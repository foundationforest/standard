// The facts proof, end to end: keys/'s test person, a stamp whose facts a verifier made from a list,
// proofs that show some of those facts to one reader from one profile, and every way a proof must
// fail.
//
// They need the setup's files, committed in facts/setup/: `npm run fetch` checks their hashes first.
// A missing file fails; nothing skips.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { after, test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { poseidon2 } from 'poseidon-lite/poseidon2'
import { groth16 } from 'snarkjs'

import { mainKey, pointOf, seedNumber } from '@foundationforest/keys'
import {
  BN254_R,
  checkFacts,
  factsInput,
  factsNumber,
  factsProofFromJson,
  factsProofToJson,
  madeForOf,
  newFact,
  proveFacts,
  signStamp,
  stampNumberOf,
  verifierKeyOf,
  type Fact,
  type SignedStamp,
} from '../src/index.ts'

// snarkjs keeps its BN254 curve, and the curve's worker threads, alive in a global of
// ffjavascript's: stopping them lets this file's process end, so every result is reported.
after(() => (globalThis as { curve_bn128?: { terminate(): Promise<void> } }).curve_bn128?.terminate())

const here = dirname(fileURLToPath(import.meta.url))
const artifacts = { wasm: join(here, '../facts/setup/facts.wasm'), zkey: join(here, '../facts/setup/facts.zkey') }
const keysVectors = JSON.parse(readFileSync(join(here, '../../keys/test/vectors.json'), 'utf8'))
const seed = Uint8Array.from(Buffer.from(keysVectors.seed, 'hex'))
const NAME = keysVectors.verifiers[0].name
const OTHER_NAME = keysVectors.verifiers[1].name
const theirSeed = new Uint8Array(32).fill(9)

// The verifier that checked them, another verifier, and a key that issues nothing anyone trusts.
const verifierPrivate = new Uint8Array(32).fill(1)
const otherPrivate = new Uint8Array(32).fill(2)
const strangerPrivate = new Uint8Array(32).fill(3)
const verifier = verifierKeyOf(verifierPrivate)
const otherVerifier = verifierKeyOf(otherPrivate)

// What the verifier read off a document, each fact with its own salt.
const list: Fact[] = [
  ['given name', 'Ana'],
  ['family name', 'Ruiz'],
  ['birth date', '1990-04-12'],
  ['nationality', 'ES'],
  ['nationality', 'MX'],
  ['document', 'passport'],
  ['expires', '2031-01-31'],
  ['face', 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQ'],
  ['height', '170'],
].map(([name, value]) => newFact(name!, value!))
const mine = stampNumberOf(seedNumber(seed), NAME)
const stampOf = (facts: Fact[], stampNumber = mine, key = verifierPrivate): SignedStamp =>
  signStamp(key, { stampNumber, facts: factsNumber(facts), verifierName: NAME, factList: facts })
const stamp = stampOf(list)

const LABEL = 'tutoring/seller'
const OTHER_LABEL = 'tutoring/buyer'
const profile = await mainKey(seed, LABEL)
const otherProfile = await mainKey(seed, OTHER_LABEL)
const theirProfile = await mainKey(theirSeed, LABEL)

// The reader, which knows itself by its profile's address, and when the proof is made.
const READER = (await mainKey(theirSeed, 'tutoring/buyer')).address
const TIME = 1_791_072_000_000
const show = (...at: number[]) => at.map((i) => ({ name: list[i]!.name, value: list[i]!.value }))

const made = await proveFacts({ seed, stamp, label: LABEL, show: show(0, 2, 7), time: TIME, to: READER, artifacts })
const expect = { verifier, verifierName: NAME, label: LABEL, profile: profile.address, to: READER, oldest: TIME - 600_000 }

/** The circuit's witness for these inputs, proven straight through snarkjs. */
const prove = (input: Record<string, unknown>) => groth16.fullProve(input, artifacts.wasm, artifacts.zkey)
const inputOf = (at: number[], s = stamp, time = TIME) => factsInput({ seed, stamp: s, label: LABEL, show: show(...at), time, to: READER }).input
/** What circom's witness generator says when a constraint does not hold: there is nothing to prove. */
const NO_WITNESS = /Assert Failed/

test('a valid proof: these facts, from a stamp this verifier signed for my seed, from this profile, for this reader', async () => {
  assert.equal(await checkFacts({ ...expect, proof: made }), true)
  assert.equal(await checkFacts({ ...expect, proof: made, profile: profile.publicKey }), true, 'the profile as its key')
  assert.equal(await checkFacts({ ...expect, proof: made, verifier: pointOf(verifier) }), true, 'the verifier as its point')
  assert.equal(made.profile, profile.address)
  assert.equal(made.verifier, verifier)
  assert.deepEqual(made.shown, show(0, 2, 7))
  const json = JSON.parse(JSON.stringify(factsProofToJson(made)))
  assert.equal(await checkFacts({ ...expect, proof: factsProofFromJson(json) }), true, 'from its JSON')
})

test('another reader, another time, or a time older than the reader accepts fails', async () => {
  assert.equal(await checkFacts({ ...expect, proof: made, to: profile.address }), false, 'another reader')
  assert.equal(await checkFacts({ ...expect, proof: { ...made, to: profile.address }, to: profile.address }), false, 'its to changed too')
  assert.equal(await checkFacts({ ...expect, proof: { ...made, time: TIME + 1 } }), false, 'another time')
  assert.equal(await checkFacts({ ...expect, proof: made, oldest: TIME + 1 }), false, 'older than the reader accepts')
  assert.equal(await checkFacts({ ...expect, proof: made, oldest: TIME }), true, 'exactly as old as it accepts')
  // Straight to the circuit: made for changed alone, the match number left as it was.
  await assert.rejects(prove({ ...inputOf([0]), madeFor: madeForOf(TIME + 1, READER) }), NO_WITNESS)
})

test('another profile, label, verifier or verifier name fails', async () => {
  assert.equal(await checkFacts({ ...expect, proof: made, profile: otherProfile.address }), false, 'my other profile')
  assert.equal(await checkFacts({ ...expect, proof: made, profile: theirProfile.address }), false, "someone else's profile")
  assert.equal(await checkFacts({ ...expect, proof: made, label: OTHER_LABEL }), false, 'another label')
  assert.equal(await checkFacts({ ...expect, proof: made, label: OTHER_LABEL, profile: otherProfile.address }), false, 'the other profile, whole')
  assert.equal(await checkFacts({ ...expect, proof: made, verifier: otherVerifier }), false, 'another verifier')
  assert.equal(await checkFacts({ ...expect, proof: made, verifierName: OTHER_NAME }), false, 'another name')
  // Straight to the circuit: a key of someone else's, with my stamp and this label.
  await assert.rejects(prove({ ...inputOf([0]), profileX: theirProfile.publicKey[0], profileY: theirProfile.publicKey[1] }), NO_WITNESS)
})

test('a changed fact fails, and so does a fact the stamp does not hold', async () => {
  const changed = (i: number, fact: { name: string; value: string }) => ({ ...made, shown: made.shown.map((f, j) => (j === i ? fact : f)) })
  assert.equal(await checkFacts({ ...expect, proof: changed(0, { name: 'given name', value: 'Eva' }) }), false, 'another value')
  assert.equal(await checkFacts({ ...expect, proof: changed(0, { name: 'family name', value: 'Ana' }) }), false, 'another name')
  assert.equal(await checkFacts({ ...expect, proof: { ...made, shown: [...made.shown].reverse() } }), false, 'another order')
  assert.equal(await checkFacts({ ...expect, proof: { ...made, shown: made.shown.slice(1) } }), false, 'one fewer')
  assert.equal(await checkFacts({ ...expect, proof: { ...made, shown: [...made.shown, ...show(3)] } }), false, 'one more')
  await assert.rejects(proveFacts({ seed, stamp, label: LABEL, show: [{ name: 'given name', value: 'Eva' }], time: TIME, to: READER, artifacts }), /holds no fact/)

  // Straight to the circuit. A fact of my own other stamp, with its salt and path, against this one: no witness.
  const otherStamp = stampOf([newFact('given name', 'Eva'), ...list.slice(1)])
  const theirs = factsInput({ seed, stamp: otherStamp, label: LABEL, show: [{ name: 'given name', value: 'Eva' }], time: TIME, to: READER }).input
  const at0 = <T>(own: T[], from: T[]) => [from[0]!, ...own.slice(1)]
  const own = inputOf([0])
  await assert.rejects(prove({ ...own, shown: at0(own.shown as bigint[][], theirs.shown as bigint[][]), salts: at0(own.salts as bigint[], theirs.salts as bigint[]), pathSiblings: at0(own.pathSiblings as bigint[][], theirs.pathSiblings as bigint[][]) }), NO_WITNESS)
  // A fact at another place in the list than its path says: no witness.
  await assert.rejects(prove({ ...own, pathIndices: [1, 0, 0, 0, 0, 0, 0, 0] }), NO_WITNESS)
  // A blank slot carrying a value: no witness.
  const shown = (own.shown as bigint[][]).map((s, i) => (i === 7 ? [0n, 5n] : s))
  await assert.rejects(prove({ ...own, shown }), NO_WITNESS)
})

test('a stamp the verifier did not sign, for another seed, or whose list does not make its facts, is refused before proving', async () => {
  const base = { seed, label: LABEL, show: show(0), time: TIME, to: READER, artifacts }
  const forged = { ...stampOf(list, mine, strangerPrivate), verifier }
  await assert.rejects(proveFacts({ ...base, stamp: forged }), /signature is not on this stamp/)
  await assert.rejects(prove(inputOf([0], forged)), NO_WITNESS, 'nor does the circuit take it')
  await assert.rejects(proveFacts({ ...base, seed: theirSeed, stamp }), /not for this seed at this verifier/)
  await assert.rejects(proveFacts({ ...base, stamp: { ...stamp, factList: [newFact('given name', 'Ana'), ...list.slice(1)] } }), /does not make/)
  await assert.rejects(proveFacts({ ...base, stamp, show: show(0, 1, 2, 3, 4, 5, 6, 7, 8) }), /up to 8 facts/)
})

test('the match number: one for every proof from one stamp, on one profile, for one made for; another for anything else', async () => {
  // All eight slots full, from the same stamp, profile and made for as `made`.
  const full = await proveFacts({ seed, stamp, label: LABEL, show: show(1, 3, 4, 5, 6, 8, 0, 2), time: TIME, to: READER, artifacts })
  assert.equal(await checkFacts({ ...expect, proof: full }), true, 'eight facts')
  assert.equal(full.match, made.match, 'one sending, one stamp: one match number')
  const matchOf = (input: Parameters<typeof factsInput>[0]) => factsInput(input).publicSignals.at(-1)
  const base = { seed, stamp, label: LABEL, show: show(0), time: TIME, to: READER }
  assert.equal(matchOf(base), made.match, 'whichever facts are shown')
  assert.notEqual(matchOf({ ...base, to: profile.address }), made.match, 'another reader')
  assert.notEqual(matchOf({ ...base, time: TIME + 1 }), made.match, 'another time')
  assert.notEqual(matchOf({ ...base, label: OTHER_LABEL }), made.match, 'another profile of mine')
  assert.notEqual(matchOf({ ...base, stamp: stampOf(list.map(({ name, value }) => newFact(name, value))) }), made.match, 'another stamp, the same facts')
  assert.equal(await checkFacts({ ...expect, proof: { ...made, match: made.match + 1n } }), false, 'a changed match number')
  // Straight to the circuit: the match number without the seed, as anyone who knows the facts
  // number could work it out: no witness.
  const input = inputOf([0])
  await assert.rejects(prove({ ...input, match: poseidon2([input.facts as bigint, input.madeFor as bigint]) }), NO_WITNESS)
})

test('a proof with no facts holds: the verification, for one reader', async () => {
  const none = await proveFacts({ seed, stamp, label: LABEL, show: [], time: TIME, to: READER, artifacts })
  assert.equal(await checkFacts({ ...expect, proof: none }), true)
  assert.equal(none.match, made.match)
  assert.equal(await checkFacts({ ...expect, proof: { ...none, shown: show(0) } }), false)
})

test('a public value outside the field, or a proof changed, fails', async () => {
  assert.equal(await checkFacts({ ...expect, proof: { ...made, match: made.match + BN254_R } }), false, 'the match number plus the order')
  assert.equal(await checkFacts({ ...expect, proof: made, profile: [profile.publicKey[0] + BN254_R, profile.publicKey[1]] }), false)
  assert.equal(await checkFacts({ ...expect, proof: made, verifier: 'not an address' }), false)
  assert.equal(await checkFacts({ ...expect, proof: { ...made, shown: [{ name: 'a\ud800', value: 'Ana' }] } }), false, 'no text')
  assert.equal(await checkFacts({ ...expect, proof: made, oldest: Number.NaN }), false)
  const changed = { ...made.proof, pi_a: [made.proof.pi_c[0], made.proof.pi_c[1], '1'] as typeof made.proof.pi_a }
  assert.equal(await checkFacts({ ...expect, proof: { ...made, proof: changed } }), false)
})
