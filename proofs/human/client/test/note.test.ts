// The note: what an issuer signs, its signature, and the circuit's input, checked without proving.
// The proofs themselves are made and refused in registry/circuit's tests.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { keccak_256 } from '@noble/hashes/sha3.js'
import { signMessage } from '@zk-kit/eddsa-poseidon'
import { poseidon4 } from 'poseidon-lite/poseidon4'
import { poseidon5 } from 'poseidon-lite/poseidon5'

import { issuerSecret } from '../../../keys/src/index.ts'
import {
  BN254_R,
  NOTE_TAG,
  fromBytes32,
  issuerKeyOf,
  stampOf,
  messageOf,
  noteFromJson,
  noteHash,
  noteNumberOf,
  noteSigned,
  noteToJson,
  personInput,
  scopeOf,
  signNote,
  type Note,
} from '../src/index.ts'
import { PERSON_KEY } from '../src/person-key.ts'

const here = dirname(fileURLToPath(import.meta.url))
const keysVectors = JSON.parse(readFileSync(join(here, '../../../keys/test/vectors.json'), 'utf8'))
const seed = Buffer.from(keysVectors.seed, 'hex')
const [issuerA] = keysVectors.issuers
const secret = (await issuerSecret(seed, issuerA.name)).secret

const issuerKey = new Uint8Array(32).fill(1)
const note: Note = {
  noteNumber: noteNumberOf(secret),
  embedding: new Uint8Array(Float32Array.from([0.25, -0.5, 0.125]).buffer),
  model: 'example-face-model/1',
  tier: 2n,
}
const signed = signNote(issuerKey, note)
const profile = new Uint8Array(32).fill(7)

test("the verification key is the circuit's committed one, value for value", () => {
  const committed = JSON.parse(readFileSync(join(here, '../../circuit/devnet/verification-key.json'), 'utf8'))
  assert.deepEqual(PERSON_KEY, committed)
  assert.equal(PERSON_KEY.nPublic, 6)
})

test("the note number is keys/'s, from the same 32 bytes", async () => {
  for (const issuer of keysVectors.issuers) {
    const s = await issuerSecret(seed, issuer.name)
    assert.equal(noteNumberOf(s.secret), s.noteNumber)
    assert.equal(noteNumberOf(s.secret).toString(), issuer.noteNumber)
  }
  assert.throws(() => noteNumberOf(secret.subarray(1)), /32 bytes/)
})

const hash = (bytes: Uint8Array) => fromBytes32(keccak_256(bytes)) >> 8n
const fields = (n: Note) => [n.noteNumber, hash(n.embedding), hash(new TextEncoder().encode(n.model)), n.tier]

test('the tag is keccak256("forest/v1/note") >> 8, the constant the circuit has', () => {
  assert.equal(NOTE_TAG, hash(new TextEncoder().encode('forest/v1/note')))
  const circuit = readFileSync(join(here, '../../circuit/person.circom'), 'utf8')
  assert.ok(circuit.includes(`var NOTE_TAG = ${NOTE_TAG};`), 'person.circom carries the same tag')
})

test('an issuer signs Poseidon(tag, note number, keccak256(embedding) >> 8, keccak256(model) >> 8, tier)', () => {
  assert.equal(noteHash(note), poseidon5([NOTE_TAG, ...fields(note)]))
  assert.throws(() => noteHash({ ...note, tier: BN254_R }), /field elements/)
  assert.throws(() => noteHash({ ...note, noteNumber: -1n }), /field elements/)
})

test('a signed note checks; any change to it, its issuer or its signature does not', () => {
  assert.equal(noteSigned(signed), true)
  assert.deepEqual(signed.issuer, issuerKeyOf(issuerKey))
  const other = issuerKeyOf(new Uint8Array(32).fill(2))
  const cases: [string, typeof signed][] = [
    ['another note number', { ...signed, noteNumber: noteNumberOf(new Uint8Array(32).fill(9)) }],
    ['another embedding', { ...signed, embedding: new Uint8Array(signed.embedding.length) }],
    ['another model', { ...signed, model: 'example-face-model/2' }],
    ['another tier', { ...signed, tier: 3n }],
    ['another issuer', { ...signed, issuer: other }],
    ['another S', { ...signed, signature: { ...signed.signature, S: signed.signature.S + 1n } }],
    ['S out of range', { ...signed, signature: { ...signed.signature, S: BN254_R } }],
    ['R8 off the curve', { ...signed, signature: { ...signed.signature, R8: [1n, 1n] } }],
    ['a tier out of the field', { ...signed, tier: BN254_R + 2n }],
  ]
  for (const [what, n] of cases) assert.equal(noteSigned(n), false, what)
  // The issuer's signature over the same fields without the tag is no note.
  const untagged = { ...signed, signature: signMessage(issuerKey, poseidon4(fields(note))) }
  assert.equal(noteSigned(untagged), false, 'no tag')
  assert.throws(() => signNote(new Uint8Array(31), note), /32 bytes/)
})

test('a note as JSON: every number in decimal text, the embedding base64url, keys a record can carry; and back', () => {
  const json = noteToJson(signed)
  assert.deepEqual(Object.keys(json).sort(), ['embedding', 'issuer', 'model', 'noteNumber', 'signature', 'tier'])
  for (const key of [...Object.keys(json), ...Object.keys(json.signature)]) assert.match(key, /^[a-z][a-zA-Z0-9]{0,63}$/, key)
  assert.equal(json.noteNumber, String(signed.noteNumber))
  assert.equal(json.embedding, Buffer.from(signed.embedding).toString('base64url'))
  assert.equal(json.issuer, Buffer.concat(signed.issuer.map((n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex'))).toString('hex'))
  assert.deepEqual(json.signature, { r8: signed.signature.R8.map(String), s: String(signed.signature.S) })
  const back = noteFromJson(JSON.parse(JSON.stringify(json)))
  assert.deepEqual(back, signed)
  assert.equal(noteSigned(back), true)
  const bad: [string, unknown][] = [
    ['a field nobody knows', { ...json, face: 'x' }],
    ['a number as a number', { ...json, tier: 1 }],
    ['a leading zero', { ...json, tier: '01' }],
    ['past the field', { ...json, noteNumber: String(BN254_R) }],
    ['the embedding in base64 with padding', { ...json, embedding: Buffer.from(signed.embedding).toString('base64') + '=' }],
    ['an issuer in upper case', { ...json, issuer: json.issuer.toUpperCase() }],
    ['the services form, R8 and S', { ...json, signature: { R8: json.signature.r8, S: json.signature.s } }],
    ['a signature field more', { ...json, signature: { ...json.signature, extra: '1' } }],
  ]
  for (const [what, value] of bad) assert.throws(() => noteFromJson(value), Error, what)
})

test("the circuit's input: the stamp is the one a row sits at, and the public signals are in order", () => {
  const { input, publicSignals } = personInput({ secret, note: signed, label: 'tutoring/seller', profile })
  assert.equal(publicSignals[0], stampOf(secret, 'tutoring/seller'))
  assert.deepEqual(publicSignals.slice(1), [signed.issuer[0], signed.issuer[1], scopeOf('tutoring/seller'), messageOf(profile), 2n])
  assert.equal(input.secret, BigInt(issuerA.scalar))
  assert.notEqual(personInput({ secret, note: signed, label: 'tutoring/buyer', profile }).publicSignals[0], publicSignals[0])
})
