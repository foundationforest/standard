// The person proof, end to end: keys/'s test person, a note an issuer signed for them, a proof for
// one label and one main key, and every way a proof must fail.
//
// They need the devnet setup's files, committed in devnet/: `npm run fetch` checks their hashes
// first. A missing file fails; nothing skips.

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { signMessage } from '@zk-kit/eddsa-poseidon'
import { poseidon4 } from 'poseidon-lite/poseidon4'
import { groth16 } from 'snarkjs'

import { issuerSecret, mainKey } from '../../../keys/src/index.ts'
import {
  BN254_R,
  fieldHash,
  issuerKeyOf,
  noteSigned,
  personInput,
  provePerson,
  signNote,
  stampOf,
  toBytes32,
  verifyPerson,
  type SignedNote,
} from '../../client/src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
const artifacts = { wasm: join(here, '../devnet/person.wasm'), zkey: join(here, '../devnet/person.zkey') }
const keysVectors = JSON.parse(readFileSync(join(here, '../../../keys/test/vectors.json'), 'utf8'))
const seed = Buffer.from(keysVectors.seed, 'hex')
const NAME = keysVectors.issuers[0].name

// The person, and another person with their own seed, each with their secret for one issuer.
const mine = await issuerSecret(seed, NAME)
const theirs = await issuerSecret(new Uint8Array(32).fill(9), NAME)

// The issuer that checked them, another issuer, and a key that issues nothing anyone trusts.
const issuerPrivate = new Uint8Array(32).fill(1)
const otherPrivate = new Uint8Array(32).fill(2)
const strangerPrivate = new Uint8Array(32).fill(3)
const issuer = issuerKeyOf(issuerPrivate)
const otherIssuer = issuerKeyOf(otherPrivate)

const noteFor = (noteNumber: bigint, key = issuerPrivate): SignedNote =>
  signNote(key, {
    noteNumber,
    embedding: new Uint8Array(Float32Array.from({ length: 128 }, (_, i) => Math.sin(i)).buffer),
    model: 'example-face-model/1',
    tier: 2n,
  })
const note = noteFor(mine.noteNumber)

const LABEL = 'tutoring/seller'
const OTHER_LABEL = 'tutoring/buyer'
const profile = (await mainKey(seed, LABEL)).publicKey
const otherProfile = (await mainKey(seed, OTHER_LABEL)).publicKey

const valid = await provePerson({ secret: mine.secret, note, label: LABEL, profile, artifacts })
const good = { proof: valid.proof, issuer, label: LABEL, profile, stamp: valid.stamp, tier: 2n }

/** The circuit's witness for these inputs, proven straight through snarkjs. */
const prove = (input: Record<string, unknown>) => groth16.fullProve(input, artifacts.wasm, artifacts.zkey)
const inputOf = (n: SignedNote, secret = mine.secret) => personInput({ secret, note: n, label: LABEL, profile }).input
/** What circom's witness generator says when a constraint does not hold: there is nothing to prove. */
const NO_WITNESS = /Assert Failed/

test('a valid proof: the issuer signed a note for my note number; my stamp for this label, for this main key', async () => {
  assert.equal(noteSigned(note), true)
  assert.equal(await verifyPerson(good), true)
  assert.equal(await verifyPerson({ ...good, stamp: toBytes32(valid.stamp) }), true, 'the stamp as 32 bytes')
  // The stamp is the one a registry row sits at: the same derivation, from the same secret.
  assert.equal(valid.stamp, stampOf(mine.secret, LABEL))
  assert.deepEqual(valid.issuer, issuer)
  assert.equal(valid.tier, 2n)
})

test('a wrong issuer key fails', async () => {
  assert.equal(await verifyPerson({ ...good, issuer: otherIssuer }), false)
  // A note the other issuer signed, presented under this issuer's key: no witness.
  const theirNote = noteFor(mine.noteNumber, otherPrivate)
  await assert.rejects(prove({ ...inputOf(theirNote), issuerX: issuer[0], issuerY: issuer[1] }), NO_WITNESS)
})

test('a forged signature fails, and so do a signature without the tag and a tier the issuer did not sign', async () => {
  // A key that is not the issuer's signs a note, which then claims the issuer's key.
  const forged = { ...noteFor(mine.noteNumber, strangerPrivate), issuer }
  assert.equal(noteSigned(forged), false)
  await assert.rejects(provePerson({ secret: mine.secret, note: forged, label: LABEL, profile, artifacts }), /signature is not on this note/)
  await assert.rejects(prove(inputOf(forged)), NO_WITNESS)
  // The issuer's own signature with S changed, or with S plus the subgroup order: no witness.
  await assert.rejects(prove(inputOf({ ...note, signature: { ...note.signature, S: note.signature.S + 1n } })), NO_WITNESS)
  const l = 2736030358979909402780800718157159386076813972158567259200215660948447373041n
  await assert.rejects(prove(inputOf({ ...note, signature: { ...note.signature, S: note.signature.S + l } })), NO_WITNESS)
  // The issuer's own signature over the same fields without the tag: no witness.
  const untagged = poseidon4([note.noteNumber, fieldHash('', note.embedding), fieldHash('', note.model), note.tier])
  await assert.rejects(prove(inputOf({ ...note, signature: signMessage(issuerPrivate, untagged) })), NO_WITNESS)
  // The signed note with another tier, in the proof or in the check.
  await assert.rejects(prove(inputOf({ ...note, tier: 3n })), NO_WITNESS)
  assert.equal(await verifyPerson({ ...good, tier: 3n }), false)
})

test("another person's secret fails", async () => {
  await assert.rejects(provePerson({ secret: theirs.secret, note, label: LABEL, profile, artifacts }), /not for this secret/)
  // Their secret with my note, straight to the circuit: their note number is not the signed one.
  await assert.rejects(prove(inputOf(note, theirs.secret)), NO_WITNESS)
  // My proof does not hold for their stamp either.
  assert.equal(await verifyPerson({ ...good, stamp: stampOf(theirs.secret, LABEL) }), false)
})

test('a stamp for another label fails', async () => {
  assert.equal(await verifyPerson({ ...good, label: OTHER_LABEL }), false)
  assert.equal(await verifyPerson({ ...good, stamp: stampOf(mine.secret, OTHER_LABEL) }), false)
  assert.equal(await verifyPerson({ ...good, label: OTHER_LABEL, stamp: stampOf(mine.secret, OTHER_LABEL) }), false)
})

test('a proof replayed for another main key fails', async () => {
  assert.equal(await verifyPerson({ ...good, profile: otherProfile }), false)
})

test('a public value outside the field, or a proof changed, fails', async () => {
  assert.equal(await verifyPerson({ ...good, stamp: valid.stamp + BN254_R }), false)
  assert.equal(await verifyPerson({ ...good, tier: 2n + BN254_R }), false)
  assert.equal(await verifyPerson({ ...good, issuer: [issuer[0] + BN254_R, issuer[1]] }), false)
  const changed = { ...valid.proof, pi_a: [valid.proof.pi_c[0], valid.proof.pi_c[1], '1'] as typeof valid.proof.pi_a }
  assert.equal(await verifyPerson({ ...good, proof: changed }), false)
})

test("the program's key is this setup's: groth16-solana's converter on the committed key gives verifying_key.rs byte for byte", () => {
  const out = mkdtempSync(join(tmpdir(), 'forest-person-vk-'))
  try {
    execFileSync(process.execPath, [join(here, '../scripts/parse_vk_to_rust.cjs'), join(here, '../devnet/verification-key.json'), out])
    assert.equal(readFileSync(join(out, 'verifying_key.rs'), 'utf8'), readFileSync(join(here, '../../program/src/verifying_key.rs'), 'utf8'))
  } finally {
    rmSync(out, { recursive: true, force: true })
  }
})
