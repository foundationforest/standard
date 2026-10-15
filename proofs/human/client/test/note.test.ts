// The note: what an issuer signs, its signature, its JSON, and the circuit's input, checked without
// proving. The proofs themselves are made and refused in the circuit's tests (../../circuit/test/).

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { keccak_256 } from '@noble/hashes/sha3.js'
import { signMessage } from '@zk-kit/eddsa-poseidon'
import { poseidon4 } from 'poseidon-lite/poseidon4'
import { poseidon5 } from 'poseidon-lite/poseidon5'

import { issuerSecret, mainKey, seedScalar, stampOf } from '../../../../keys/src/index.ts'
import {
  BN254_R,
  NOTE_TAG,
  fromBytes32,
  humanInput,
  isMonth,
  issuerKeyOf,
  nameHashOf,
  noteFromJson,
  noteHash,
  noteNumberOf,
  noteSigned,
  noteToJson,
  scopeOf,
  signNote,
  type Note,
} from '../src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
const keysVectors = JSON.parse(readFileSync(join(here, '../../../../keys/test/vectors.json'), 'utf8'))
const seed = Uint8Array.from(Buffer.from(keysVectors.seed, 'hex'))
const [issuerA] = keysVectors.issuers
const S = await seedScalar(seed)

const issuerKey = new Uint8Array(32).fill(1)
const note: Note = {
  noteNumber: noteNumberOf(S, issuerA.name),
  embedding: new Uint8Array(Float32Array.from([0.25, -0.5, 0.125]).buffer),
  model: 'example-face-model/1',
  month: 202610,
}
const signed = signNote(issuerKey, note)

test("the note number is keys/'s, from the seed scalar and the issuer's name", async () => {
  for (const issuer of keysVectors.issuers) {
    const s = await issuerSecret(seed, issuer.name)
    assert.equal(noteNumberOf(S, issuer.name), s.noteNumber)
    assert.equal(noteNumberOf(S, issuer.name).toString(), issuer.noteNumber)
  }
  assert.throws(() => noteNumberOf(BN254_R, issuerA.name), /field element/)
})

const hash = (bytes: Uint8Array) => fromBytes32(keccak_256(bytes)) >> 8n
const fields = (n: Note) => [n.noteNumber, hash(n.embedding), hash(new TextEncoder().encode(n.model)), BigInt(n.month)]

test('the tag is keccak256("forest/v1/note") >> 8, the constant the circuit has', () => {
  assert.equal(NOTE_TAG, hash(new TextEncoder().encode('forest/v1/note')))
  const circuit = readFileSync(join(here, '../../circuit/human.circom'), 'utf8')
  assert.ok(circuit.includes(`var NOTE_TAG = ${NOTE_TAG};`), 'human.circom carries the same tag')
})

test('an issuer signs Poseidon(tag, note number, keccak256(embedding) >> 8, keccak256(model) >> 8, month)', () => {
  assert.equal(noteHash(note), poseidon5([NOTE_TAG, ...fields(note)]))
  assert.throws(() => noteHash({ ...note, noteNumber: BN254_R }), /field element/)
  assert.throws(() => noteHash({ ...note, noteNumber: -1n }), /field element/)
  assert.throws(() => noteHash({ ...note, month: 202613 }), /YYYYMM/)
})

test('a month is YYYYMM, and nothing else', () => {
  for (const m of [202610, 100001, 999912, 202601]) assert.equal(isMonth(m), true, String(m))
  for (const m of [202600, 202613, 99912, 1000001, 202610.5, '202610', 202610n, -202610]) assert.equal(isMonth(m), false, String(m))
})

test('a signed note checks; any change to it, its issuer or its signature does not', () => {
  assert.equal(noteSigned(signed), true)
  assert.deepEqual(signed.issuer, issuerKeyOf(issuerKey))
  const other = issuerKeyOf(new Uint8Array(32).fill(2))
  const cases: [string, typeof signed][] = [
    ['another note number', { ...signed, noteNumber: noteNumberOf(S, 'issuer-b.example') }],
    ['another embedding', { ...signed, embedding: new Uint8Array(signed.embedding.length) }],
    ['another model', { ...signed, model: 'example-face-model/2' }],
    ['another month', { ...signed, month: 202611 }],
    ['another issuer', { ...signed, issuer: other }],
    ['another S', { ...signed, signature: { ...signed.signature, S: signed.signature.S + 1n } }],
    ['S out of range', { ...signed, signature: { ...signed.signature, S: BN254_R } }],
    ['R8 off the curve', { ...signed, signature: { ...signed.signature, R8: [1n, 1n] } }],
    ['a month that is no month', { ...signed, month: 202600 }],
  ]
  for (const [what, n] of cases) assert.equal(noteSigned(n), false, what)
  // The issuer's signature over the same fields without the tag is no note.
  const untagged = { ...signed, signature: signMessage(issuerKey, poseidon4(fields(note))) }
  assert.equal(noteSigned(untagged), false, 'no tag')
  assert.throws(() => signNote(new Uint8Array(31), note), /32 bytes/)
})

test('a note as JSON: big numbers in decimal text, the month a number, the embedding base64url; and back', () => {
  const json = noteToJson(signed)
  assert.deepEqual(Object.keys(json).sort(), ['embedding', 'issuer', 'model', 'month', 'noteNumber', 'signature'])
  for (const key of [...Object.keys(json), ...Object.keys(json.signature)]) assert.match(key, /^[a-z][a-zA-Z0-9]{0,63}$/, key)
  assert.equal(json.noteNumber, String(signed.noteNumber))
  assert.equal(json.month, 202610)
  assert.equal(json.embedding, Buffer.from(signed.embedding).toString('base64url'))
  assert.equal(json.issuer, Buffer.concat(signed.issuer.map((n) => Buffer.from(n.toString(16).padStart(64, '0'), 'hex'))).toString('hex'))
  assert.deepEqual(json.signature, { r8: signed.signature.R8.map(String), s: String(signed.signature.S) })
  const back = noteFromJson(JSON.parse(JSON.stringify(json)))
  assert.deepEqual(back, signed)
  assert.equal(noteSigned(back), true)
  const bad: [string, unknown][] = [
    ['a field nobody knows', { ...json, face: 'x' }],
    ['the tier a note once had', { ...json, tier: '2' }],
    ['a month as text', { ...json, month: '202610' }],
    ['a month that is no month', { ...json, month: 202613 }],
    ['a leading zero', { ...json, noteNumber: '0' + json.noteNumber }],
    ['past the field', { ...json, noteNumber: String(BN254_R) }],
    ['the embedding in base64 with padding', { ...json, embedding: Buffer.from(signed.embedding).toString('base64') + '=' }],
    ['an issuer in upper case', { ...json, issuer: json.issuer.toUpperCase() }],
    ['the services form, R8 and S', { ...json, signature: { R8: json.signature.r8, S: json.signature.s } }],
    ['a signature field more', { ...json, signature: { ...json.signature, extra: '1' } }],
  ]
  for (const [what, value] of bad) assert.throws(() => noteFromJson(value), Error, what)
})

test("the circuit's input: keys/'s stamp and main key, and the public signals in order", async () => {
  const label = 'tutoring/seller'
  const { input, publicSignals } = humanInput({ seedScalar: S, issuerName: issuerA.name, note: signed, label })
  const main = await mainKey(seed, label)
  const a = await issuerSecret(seed, issuerA.name)
  assert.deepEqual(publicSignals, [
    stampOf(a.scalar, label),
    main.publicKey[0],
    main.publicKey[1],
    signed.issuer[0],
    signed.issuer[1],
    scopeOf(label),
    nameHashOf(issuerA.name),
    202610n,
  ])
  assert.equal(publicSignals[0].toString(), issuerA.stamps[label], "keys/'s pinned stamp")
  assert.equal(input.seedScalar, BigInt(keysVectors.seedScalar.scalar))
  const other = humanInput({ seedScalar: S, issuerName: issuerA.name, note: signed, label: 'tutoring/buyer' }).publicSignals
  assert.notEqual(other[0], publicSignals[0], 'another label, another stamp')
  assert.notEqual(other[1], publicSignals[1], 'and another key')
  assert.throws(() => humanInput({ seedScalar: BN254_R, issuerName: issuerA.name, note: signed, label }), /field element/)
})
