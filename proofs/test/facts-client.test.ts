// The facts client without proving: the recipe that makes a stamp's facts number from its list,
// the list beside the stamp in its JSON, the made-for number, the circuit's input and what the
// client refuses before any proof is made, the JSON a proof travels in, and the verification key it
// checks with. The proofs themselves are the circuit's tests (facts.test.ts).

import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { keccak_256 } from '@noble/hashes/sha3.js'
import { poseidon2 } from 'poseidon-lite/poseidon2'
import { poseidon3 } from 'poseidon-lite/poseidon3'
import { poseidon4 } from 'poseidon-lite/poseidon4'

import { mainKey, pointOf, publicKeyOf } from '@foundationforest/keys'
import {
  BN254_P,
  BN254_R,
  FACTS_LISTED,
  FACTS_SHOWN,
  factListOf,
  factsInput,
  factsNumber,
  factsProofFromJson,
  factsProofToJson,
  fromBytes32,
  madeForOf,
  nameHashOf,
  newFact,
  proofBytes,
  scopeOf,
  seedNumber,
  signStamp,
  stampFromJson,
  stampNumberOf,
  stampSigned,
  stampToJson,
  type Fact,
  type FactsProof,
} from '../src/index.ts'
import { FACTS_KEY } from '../src/facts-key.ts'

const here = dirname(fileURLToPath(import.meta.url))
const keysVectors = JSON.parse(readFileSync(join(here, '../../keys/test/vectors.json'), 'utf8'))
const seed = Uint8Array.from(Buffer.from(keysVectors.seed, 'hex'))
const [verifierA] = keysVectors.verifiers
const S = seedNumber(seed)

/** A text's number, without the library: keccak256 of its UTF-8 bytes, big-endian, shifted right one byte. */
const hash = (text: string) => fromBytes32(keccak_256(new TextEncoder().encode(text))) >> 8n

// A list with fixed salts, whose facts number is pinned below.
const fixed: Fact[] = [
  { name: 'given name', value: 'Ana', salt: '1' },
  { name: 'birth date', value: '1990-04-12', salt: '2' },
  { name: 'nationality', value: 'ES', salt: '3' },
]

const verifierKey = new Uint8Array(32).fill(1)
const list = [newFact('given name', 'Ana'), newFact('birth date', '1990-04-12'), newFact('nationality', 'ES')]
const stamp = signStamp(verifierKey, { stampNumber: stampNumberOf(S, verifierA.name), facts: factsNumber(list), verifierName: verifierA.name, factList: list })
const LABEL = 'tutoring/seller'
const TIME = 1_791_072_000_000
const READER = 'a reader'

test("a fact's leaf is Poseidon(name's number, value's number, salt), and the facts number is the root of a tree of depth 8 over the leaves, then 0s", () => {
  let level = [...fixed.map((f) => poseidon3([hash(f.name), hash(f.value), BigInt(f.salt)])), ...Array<bigint>(256 - fixed.length).fill(0n)]
  while (level.length > 1) level = Array.from({ length: level.length / 2 }, (_, i) => poseidon2([level[2 * i]!, level[2 * i + 1]!]))
  assert.equal(factsNumber(fixed), level[0])
  assert.equal(factsNumber(fixed), 20409407384172712072551294647858174153229017436829105761531810527468884342048n, 'pinned')
  let blank = 0n
  for (let d = 0; d < 8; d++) blank = poseidon2([blank, blank])
  assert.equal(factsNumber([]), blank, 'an empty list: every leaf 0')
  assert.notEqual(factsNumber([fixed[1]!, fixed[0]!, fixed[2]!]), factsNumber(fixed), 'the order is part of it')
  assert.notEqual(factsNumber([{ ...fixed[0]!, salt: '4' }, fixed[1]!, fixed[2]!]), factsNumber(fixed), 'so is each salt')
  assert.equal(FACTS_LISTED, 256)
  assert.equal(FACTS_SHOWN, 8)
})

test('factsNumber refuses more than 256 facts, a salt out of range or in another spelling, text with a lone surrogate, and a fact in any other shape', () => {
  assert.doesNotThrow(() => factsNumber(Array(256).fill(fixed[0])))
  assert.throws(() => factsNumber(Array(257).fill(fixed[0])), /up to 256 facts/)
  const one = fixed[0]!
  for (const [what, fact] of [
    ['a salt past the field', { ...one, salt: String(BN254_R) }],
    ['a salt with a leading zero', { ...one, salt: '01' }],
    ['a salt as a number', { ...one, salt: 1 }],
    ['a negative salt', { ...one, salt: '-1' }],
    ['a name with a lone surrogate', { ...one, name: 'a\ud800' }],
    ['a value that is no text', { ...one, value: 7 }],
    ['no salt', { name: one.name, value: one.value }],
    ['a field more', { ...one, note: 'x' }],
    ['no object', 'given name'],
  ] as const) {
    assert.throws(() => factsNumber([fact as unknown as Fact]), Error, what)
  }
  assert.throws(() => factsNumber('x' as unknown as Fact[]), /array/)
})

test('newFact draws its own salt for each fact, below the field', () => {
  const salts = Array.from({ length: 20 }, () => newFact('a', 'b').salt)
  assert.equal(new Set(salts).size, salts.length)
  for (const salt of salts) assert.ok(BigInt(salt) < 2n ** 248n && BigInt(salt) < BN254_R)
  assert.throws(() => newFact('a\ud800', 'b'), /text/)
})

test('the list sits beside the stamp under factList, passes through its JSON unsigned, and factListOf refuses a list that does not make the facts', () => {
  const unlisted = signStamp(verifierKey, { stampNumber: stamp.stampNumber, facts: stamp.facts, verifierName: verifierA.name })
  assert.deepEqual(stamp.signature, unlisted.signature, 'the list is not signed: its root is')
  const json = stampToJson(stamp)
  assert.deepEqual(json.factList, list)
  const back = stampFromJson(JSON.parse(JSON.stringify(json)))
  assert.equal(stampSigned(back), true)
  assert.deepEqual(factListOf(back), list)
  assert.throws(() => factListOf(unlisted), /no list/)
  assert.throws(() => factListOf({ ...stamp, factList: [{ ...list[0]!, value: 'Eva' }, list[1]!, list[2]!] }), /does not make/)
  assert.throws(() => factListOf({ ...stamp, factList: list.slice(1) }), /does not make/)
  assert.throws(() => factListOf({ ...stamp, factList: 'x' }), /array/)
})

test('made for is the number of the canonical JSON of { time, to }, the time in whole ms', () => {
  const to = 'a "reader", ü\n'
  assert.equal(madeForOf(TIME, to), hash(`{"time":${TIME},"to":"a \\"reader\\", ü\\n"}`))
  assert.notEqual(madeForOf(TIME, to), madeForOf(TIME + 1, to))
  assert.notEqual(madeForOf(TIME, to), madeForOf(TIME, 'another reader'))
  for (const bad of [-1, 1.5, 2 ** 53, Number.NaN]) assert.throws(() => madeForOf(bad, to), /whole ms/, String(bad))
  assert.throws(() => madeForOf(TIME, 'a\ud800'), /text/)
})

test("the circuit's input: the verification's six, made for, each shown fact's name and value then blanks, and the match number", async () => {
  const show = [{ name: 'nationality', value: 'ES' }, { name: 'given name', value: 'Ana' }]
  const { input, publicSignals } = factsInput({ seed, stamp, label: LABEL, show, time: TIME, to: READER })
  const main = await mainKey(seed, LABEL)
  const madeFor = madeForOf(TIME, READER)
  const match = poseidon4([S, scopeOf(LABEL), stamp.facts, madeFor])
  const shown = [[hash('nationality'), hash('ES')], [hash('given name'), hash('Ana')], ...Array(6).fill([0n, 0n])]
  assert.deepEqual(publicSignals, [...main.publicKey, ...pointOf(stamp.verifier), scopeOf(LABEL), nameHashOf(verifierA.name), madeFor, ...shown.flat(), match])
  assert.equal(publicSignals.length, FACTS_KEY.nPublic)
  assert.equal(input.facts, stamp.facts)
  assert.deepEqual(input.pathIndices, [2, 0, 0, 0, 0, 0, 0, 0], "each shown fact's place in the list")
  assert.deepEqual(input.salts, [BigInt(list[2]!.salt), BigInt(list[0]!.salt), 0n, 0n, 0n, 0n, 0n, 0n])
  assert.equal(factsInput({ seed, stamp, label: LABEL, show: [], time: TIME, to: READER }).publicSignals.length, 24, 'no facts: every slot blank')
})

test('the client refuses what the circuit would', () => {
  const base = { seed, stamp, label: LABEL, time: TIME, to: READER }
  assert.throws(() => factsInput({ ...base, show: [{ name: 'given name', value: 'Eva' }] }), /holds no fact/, 'a value the stamp does not hold')
  assert.throws(() => factsInput({ ...base, show: [{ name: 'height', value: '170' }] }), /holds no fact/, 'a name it does not hold')
  assert.throws(() => factsInput({ ...base, show: Array(9).fill({ name: 'given name', value: 'Ana' }) }), /up to 8 facts/)
  const { factList: _, ...unlisted } = stamp
  assert.throws(() => factsInput({ ...base, stamp: unlisted, show: [] }), /no list/)
  assert.throws(() => factsInput({ ...base, stamp: { ...stamp, facts: stamp.facts + 1n }, show: [] }), /does not make/)
  assert.throws(() => factsInput({ ...base, time: -1, show: [] }), /whole ms/)
  assert.throws(() => factsInput({ ...base, seed: seed.subarray(1), show: [] }), /32 bytes/)
})

test('a facts proof as JSON: the match number in decimal text, the proof in base64url; and back', () => {
  const c = () => (BigInt('0x' + randomBytes(32).toString('hex')) % BN254_P).toString()
  const proof: FactsProof = {
    verifier: stamp.verifier,
    verifierName: verifierA.name,
    label: LABEL,
    profile: stamp.verifier,
    time: TIME,
    to: READER,
    shown: [{ name: 'nationality', value: 'ES' }],
    match: 12345n,
    proof: { pi_a: [c(), c(), '1'], pi_b: [[c(), c()], [c(), c()], ['1', '0']], pi_c: [c(), c(), '1'] },
  }
  const json = factsProofToJson(proof)
  assert.deepEqual(Object.keys(json).sort(), ['label', 'match', 'profile', 'proof', 'shown', 'time', 'to', 'verifier', 'verifierName'])
  assert.equal(json.match, '12345')
  assert.match(json.proof, /^[A-Za-z0-9_-]{342}$/)
  assert.deepEqual(Buffer.from(json.proof, 'base64url'), Buffer.from(proofBytes(proof.proof)))
  assert.deepEqual(factsProofFromJson(JSON.parse(JSON.stringify(json))), proof)
  assert.deepEqual(factsProofFromJson({ ...json, note: 'skipped' }), proof, 'another field is skipped')
  const bad: [string, unknown][] = [
    ['a verifier that is no address', { ...json, verifier: json.verifier.slice(1) }],
    ['a profile as a point', { ...json, profile: pointOf(json.profile).map(String) }],
    ['a label that is no text', { ...json, label: 7 }],
    ['a time in text', { ...json, time: String(TIME) }],
    ['a time past 2^53', { ...json, time: 2 ** 53 }],
    ['a to with a lone surrogate', { ...json, to: 'a\ud800' }],
    ['nine facts', { ...json, shown: Array(9).fill(json.shown[0]) }],
    ['a fact without its value', { ...json, shown: [{ name: 'nationality' }] }],
    ['a match past the field', { ...json, match: String(BN254_R) }],
    ['a match as a number', { ...json, match: 12345 }],
    ['a proof in base64 with padding', { ...json, proof: Buffer.from(proofBytes(proof.proof)).toString('base64') }],
    ['a proof of 255 bytes', { ...json, proof: Buffer.from(proofBytes(proof.proof).subarray(1)).toString('base64url') }],
    ['no proof', { ...json, proof: undefined }],
  ]
  for (const [what, value] of bad) assert.throws(() => factsProofFromJson(value), Error, what)
})

test("the verification key is the circuit setup's, value for value", () => {
  const committed = JSON.parse(readFileSync(join(here, '../facts/setup/verification-key.json'), 'utf8'))
  assert.deepEqual(FACTS_KEY, committed)
  assert.equal(FACTS_KEY.nPublic, 24, 'six, made for, eight names and values, the match number')
})

test("the circuit's one constant is keys/'s Base8; it mixes no prefix", () => {
  const circuit = readFileSync(join(here, '../facts/facts.circom'), 'utf8')
  const [x, y] = publicKeyOf(1n)
  assert.ok(circuit.includes(`${x},\n        ${y}\n    ];`))
  assert.ok(!/PREFIX|forest\//.test(circuit), 'no prefix and no text: the scope, the name hash and each fact carry their texts')
})
