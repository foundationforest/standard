// The note proof, end to end: keys/'s test person, a note an issuer signed for them, a proof for
// one label and the main key their seed gives for it, and every way a proof must fail.
//
// They need the setup's files, committed in setup/: `npm run fetch` checks their hashes first. A
// missing file fails; nothing skips.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { signMessage } from '@zk-kit/eddsa-poseidon'
import { poseidon2 } from 'poseidon-lite/poseidon2'
import { groth16 } from 'snarkjs'

import { addressOf, keyScalar, mainKey, pointOf, publicKeyOf, seedScalar, signWithScalar, stampOf, issuerSecret } from '../../../../keys/src/index.ts'
import {
  BN254_R,
  fieldHash,
  noteInput,
  issuerKeyOf,
  noteHash,
  noteNumberOf,
  noteSigned,
  proveNote,
  signNote,
  toBytes32,
  verifyNote,
  type SignedNote,
} from '../../client/src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
const artifacts = { wasm: join(here, '../setup/note.wasm'), zkey: join(here, '../setup/note.zkey') }
const keysVectors = JSON.parse(readFileSync(join(here, '../../../../keys/test/vectors.json'), 'utf8'))
const seed = Uint8Array.from(Buffer.from(keysVectors.seed, 'hex'))
const NAME = keysVectors.issuers[0].name
const OTHER_NAME = keysVectors.issuers[1].name

// The person, and another person with their own seed.
const mine = await seedScalar(seed)
const theirSeed = new Uint8Array(32).fill(9)
const theirs = await seedScalar(theirSeed)

// The issuer that checked them, another issuer, and a key that issues nothing anyone trusts.
const issuerPrivate = new Uint8Array(32).fill(1)
const otherPrivate = new Uint8Array(32).fill(2)
const strangerPrivate = new Uint8Array(32).fill(3)
const issuer = issuerKeyOf(issuerPrivate)
const otherIssuer = issuerKeyOf(otherPrivate)

const ATTRIBUTES = fieldHash('forest example attributes', 'issuer-a')
const noteFor = (noteNumber: bigint, key = issuerPrivate): SignedNote => signNote(key, { noteNumber, attributes: ATTRIBUTES })
const note = noteFor(noteNumberOf(mine, NAME))

const LABEL = 'tutoring/seller'
const OTHER_LABEL = 'tutoring/buyer'
const profile = await mainKey(seed, LABEL)
const otherProfile = await mainKey(seed, OTHER_LABEL)
const theirProfile = await mainKey(theirSeed, LABEL)

const valid = await proveNote({ seedScalar: mine, issuerName: NAME, note, label: LABEL, artifacts })
const good = { proof: valid.proof, issuer, issuerName: NAME, label: LABEL, profile: profile.address, stamp: valid.stamp }

/** The circuit's witness for these inputs, proven straight through snarkjs. */
const prove = (input: Record<string, unknown>) => groth16.fullProve(input, artifacts.wasm, artifacts.zkey)
const inputOf = (n: SignedNote, seedScalar = mine, label = LABEL) => noteInput({ seedScalar, issuerName: NAME, note: n, label }).input
/** What circom's witness generator says when a constraint does not hold: there is nothing to prove. */
const NO_WITNESS = /Assert Failed/

test("a valid proof: the issuer signed my note; my stamp for this label; the profile's key is keys/'s main key", async () => {
  assert.equal(noteSigned(note), true)
  assert.equal(await verifyNote(good), true)
  assert.equal(await verifyNote({ ...good, stamp: toBytes32(valid.stamp) }), true, 'the stamp as 32 bytes')
  assert.equal(await verifyNote({ ...good, profile: profile.publicKey }), true, 'the profile as its key')
  assert.equal(await verifyNote({ ...good, issuer: pointOf(issuer) }), true, 'the issuer as its point')
  assert.equal(valid.address, profile.address)
  assert.deepEqual(valid.profile, profile.publicKey)
  assert.equal(valid.stamp, stampOf((await issuerSecret(seed, NAME)).scalar, LABEL))
  assert.equal(valid.stamp.toString(), keysVectors.issuers[0].stamps[LABEL], "keys/'s pinned stamp")
  assert.deepEqual(valid.issuer, issuer)
  assert.equal(valid.publicSignals.length, 7, 'the stamp, then profileX, profileY, issuerX, issuerY, scope, issuerNameHash')
})

test('a proof for another profile fails, and so does a key the seed does not give for the label', async () => {
  // Shown on my other profile, or on someone else's: not this proof.
  assert.equal(await verifyNote({ ...good, profile: otherProfile.address }), false, 'my other profile')
  assert.equal(await verifyNote({ ...good, profile: theirProfile.address }), false, "someone else's profile")
  // Straight to the circuit: my other label's key, someone else's key, or a key of my choosing,
  // with my note and this label: no witness.
  for (const [what, key] of [
    ['my other label', otherProfile.publicKey],
    ["someone else's", theirProfile.publicKey],
    ['a key of my choosing', publicKeyOf(12345n)],
  ] as const) {
    await assert.rejects(prove({ ...inputOf(note), profileX: key[0], profileY: key[1] }), NO_WITNESS, what)
  }
  // My note lent to their seed, for their profile: their seed gives another note number.
  await assert.rejects(prove(inputOf(note, theirs)), NO_WITNESS)
})

test('a wrong issuer key or issuer name fails', async () => {
  assert.equal(await verifyNote({ ...good, issuer: otherIssuer }), false, 'another key')
  assert.equal(await verifyNote({ ...good, issuerName: OTHER_NAME }), false, 'another name')
  // A note the other issuer signed, presented under this issuer's key: no witness.
  const theirNote = noteFor(note.noteNumber, otherPrivate)
  await assert.rejects(prove({ ...inputOf(theirNote), issuerX: pointOf(issuer)[0], issuerY: pointOf(issuer)[1] }), NO_WITNESS)
  // My note, with another issuer's name: the note number the circuit computes is not the signed one.
  await assert.rejects(prove({ ...inputOf(note), issuerNameHash: fieldHash('forest/v1/issuer/', OTHER_NAME) }), NO_WITNESS)
  await assert.rejects(proveNote({ seedScalar: mine, issuerName: OTHER_NAME, note, label: LABEL, artifacts }), /not for this seed at this issuer/)
})

test('a forged signature fails, and so do a signature without the tag and attributes the issuer did not sign', async () => {
  // A key that is not the issuer's signs a note, which then claims the issuer's key.
  const forged = { ...noteFor(note.noteNumber, strangerPrivate), issuer }
  assert.equal(noteSigned(forged), false)
  await assert.rejects(proveNote({ seedScalar: mine, issuerName: NAME, note: forged, label: LABEL, artifacts }), /signature is not on this note/)
  await assert.rejects(prove(inputOf(forged)), NO_WITNESS)
  // The issuer's own signature with S changed, or with S plus the subgroup order: no witness.
  await assert.rejects(prove(inputOf({ ...note, signature: { ...note.signature, S: note.signature.S + 1n } })), NO_WITNESS)
  const l = 2736030358979909402780800718157159386076813972158567259200215660948447373041n
  await assert.rejects(prove(inputOf({ ...note, signature: { ...note.signature, S: note.signature.S + l } })), NO_WITNESS)
  // The issuer's own signature over the same fields without the tag: no witness.
  const untagged = poseidon2([note.noteNumber, note.attributes])
  await assert.rejects(prove(inputOf({ ...note, signature: signMessage(issuerPrivate, untagged) })), NO_WITNESS)
  // The signed note with other attributes: no witness.
  await assert.rejects(prove(inputOf({ ...note, attributes: note.attributes + 1n })), NO_WITNESS)
  await assert.rejects(proveNote({ seedScalar: mine, issuerName: NAME, note: { ...note, attributes: 0n }, label: LABEL, artifacts }), /signature is not on this note/)
})

test("another person's seed fails", async () => {
  await assert.rejects(proveNote({ seedScalar: theirs, issuerName: NAME, note, label: LABEL, artifacts }), /not for this seed at this issuer/)
  // My proof does not hold for their stamp either.
  const theirStamp = stampOf((await issuerSecret(theirSeed, NAME)).scalar, LABEL)
  assert.equal(await verifyNote({ ...good, stamp: theirStamp }), false)
})

test('a stamp or a label for another label fails', async () => {
  const otherStamp = stampOf((await issuerSecret(seed, NAME)).scalar, OTHER_LABEL)
  assert.equal(await verifyNote({ ...good, label: OTHER_LABEL }), false)
  assert.equal(await verifyNote({ ...good, stamp: otherStamp }), false)
  assert.equal(await verifyNote({ ...good, label: OTHER_LABEL, stamp: otherStamp }), false)
  assert.equal(await verifyNote({ ...good, label: OTHER_LABEL, stamp: otherStamp, profile: otherProfile.address }), false, 'the other profile, whole')
})

test('a public value outside the field, or a proof changed, fails', async () => {
  assert.equal(await verifyNote({ ...good, stamp: valid.stamp + BN254_R }), false)
  assert.equal(await verifyNote({ ...good, issuer: [pointOf(issuer)[0] + BN254_R, pointOf(issuer)[1]] }), false)
  assert.equal(await verifyNote({ ...good, issuer: 'not an address' }), false)
  assert.equal(await verifyNote({ ...good, profile: [profile.publicKey[0] + BN254_R, profile.publicKey[1]] }), false)
  const changed = { ...valid.proof, pi_a: [valid.proof.pi_c[0], valid.proof.pi_c[1], '1'] as typeof valid.proof.pi_a }
  assert.equal(await verifyNote({ ...good, proof: changed }), false)
})

test("an issuer may sign with keys/'s signWithScalar: circomlib's verifier, inside the proof, takes it", async () => {
  // An independent check of keys/'s signer: the circuit's EdDSA-Poseidon verifier accepts it.
  const scalar = keyScalar(fieldHash('example issuer scalar'))
  const key = publicKeyOf(scalar)
  const unsigned = { noteNumber: note.noteNumber, attributes: note.attributes }
  const scalarNote: SignedNote = { ...unsigned, issuer: addressOf(key), signature: signWithScalar(scalar, noteHash(unsigned)) }
  assert.equal(noteSigned(scalarNote), true)
  const r = await proveNote({ seedScalar: mine, issuerName: NAME, note: scalarNote, label: LABEL, artifacts })
  assert.equal(await verifyNote({ ...good, proof: r.proof, issuer: key }), true)
})
