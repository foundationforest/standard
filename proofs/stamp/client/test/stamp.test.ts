// The stamp: what a verifier signs, its signature, its JSON, and the circuit's input, checked
// without proving. The proofs themselves are made and refused in the circuit's tests
// (../../circuit/test/).

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { keccak_256 } from '@noble/hashes/sha3.js'
import { signMessage } from '@zk-kit/eddsa-poseidon'
import { poseidon2 } from 'poseidon-lite/poseidon2'
import { poseidon3 } from 'poseidon-lite/poseidon3'

import { mainKey, pointOf, seedScalar, tagOf, verifierSecret } from '@foundationforest/keys'
import {
  BN254_R,
  STAMP_PREFIX,
  fromBytes32,
  fieldHash,
  stampInput,
  verifierKeyOf,
  nameHashOf,
  stampFromJson,
  stampHash,
  stampNumberOf,
  stampSigned,
  stampToJson,
  scopeOf,
  signStamp,
  type Stamp,
} from '../src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
const keysVectors = JSON.parse(readFileSync(join(here, '../../../../keys/test/vectors.json'), 'utf8'))
const seed = Uint8Array.from(Buffer.from(keysVectors.seed, 'hex'))
const [verifierA] = keysVectors.verifiers
const S = await seedScalar(seed)

const verifierKey = new Uint8Array(32).fill(1)
const stamp: Stamp = {
  stampNumber: stampNumberOf(S, verifierA.name),
  facts: fieldHash('forest example attributes', 'issuer-a'),
}
const signed = signStamp(verifierKey, stamp)

test("the stamp number is keys/'s, from the seed scalar and the verifier's name", async () => {
  for (const verifier of keysVectors.verifiers) {
    const s = await verifierSecret(seed, verifier.name)
    assert.equal(stampNumberOf(S, verifier.name), s.stampNumber)
    assert.equal(stampNumberOf(S, verifier.name).toString(), verifier.stampNumber)
  }
  assert.throws(() => stampNumberOf(BN254_R, verifierA.name), /field element/)
})

const hash = (bytes: Uint8Array) => fromBytes32(keccak_256(bytes)) >> 8n

test('the prefix is keccak256("forest/v1/note") >> 8, the constant the circuit has', () => {
  assert.equal(STAMP_PREFIX, hash(new TextEncoder().encode('forest/v1/note')))
  const circuit = readFileSync(join(here, '../../circuit/note.circom'), 'utf8')
  // note.circom keeps its bytes, the name of its constant among them: NOTE_TAG is the prefix.
  assert.ok(circuit.includes(`var NOTE_TAG = ${STAMP_PREFIX};`), 'note.circom carries the same prefix')
})

test('a verifier signs Poseidon(prefix, stamp number, facts)', () => {
  assert.equal(stampHash(stamp), poseidon3([STAMP_PREFIX, stamp.stampNumber, stamp.facts]))
  assert.throws(() => stampHash({ ...stamp, stampNumber: BN254_R }), /field element/)
  assert.throws(() => stampHash({ ...stamp, stampNumber: -1n }), /field element/)
  assert.throws(() => stampHash({ ...stamp, facts: BN254_R }), /field element/)
  assert.throws(() => stampHash({ ...stamp, facts: -1n }), /field element/)
})

test('a signed stamp checks; any change to it, its verifier or its signature does not', () => {
  assert.equal(stampSigned(signed), true)
  assert.deepEqual(signed.verifier, verifierKeyOf(verifierKey))
  const other = verifierKeyOf(new Uint8Array(32).fill(2))
  const cases: [string, typeof signed][] = [
    ['another stamp number', { ...signed, stampNumber: stampNumberOf(S, 'issuer-b.example') }],
    ['other facts', { ...signed, facts: signed.facts + 1n }],
    ['another verifier', { ...signed, verifier: other }],
    ['another S', { ...signed, signature: { ...signed.signature, S: signed.signature.S + 1n } }],
    ['S out of range', { ...signed, signature: { ...signed.signature, S: BN254_R } }],
    ['R8 off the curve', { ...signed, signature: { ...signed.signature, R8: [1n, 1n] } }],
    ['facts past the field', { ...signed, facts: BN254_R }],
  ]
  for (const [what, n] of cases) assert.equal(stampSigned(n), false, what)
  // The verifier's signature over the same fields without the prefix is no stamp.
  const unprefixed = { ...signed, signature: signMessage(verifierKey, poseidon2([stamp.stampNumber, stamp.facts])) }
  assert.equal(stampSigned(unprefixed), false, 'no prefix')
  assert.throws(() => signStamp(new Uint8Array(31), stamp), /32 bytes/)
})

test('a stamp as JSON: big numbers in decimal text, the verifier key as its address; and back', () => {
  const json = stampToJson(signed)
  assert.deepEqual(Object.keys(json).sort(), ['facts', 'signature', 'stampNumber', 'verifier'])
  for (const key of [...Object.keys(json), ...Object.keys(json.signature)]) assert.match(key, /^[a-z][a-zA-Z0-9]{0,63}$/, key)
  assert.equal(json.stampNumber, String(signed.stampNumber))
  assert.equal(json.facts, String(signed.facts))
  assert.equal(json.verifier, verifierKeyOf(verifierKey))
  assert.match(json.verifier, /^[1-9A-HJ-NP-Za-km-z]{43,44}$/)
  assert.deepEqual(json.signature, { r8: signed.signature.R8.map(String), s: String(signed.signature.S) })
  const back = stampFromJson(JSON.parse(JSON.stringify(json)))
  assert.deepEqual(back, signed)
  assert.equal(stampSigned(back), true)
  const bad: [string, unknown][] = [
    ['no facts', { ...json, facts: undefined }],
    ['facts as a number', { ...json, facts: Number(1) }],
    ['a leading zero', { ...json, stampNumber: '0' + json.stampNumber }],
    ['past the field', { ...json, stampNumber: String(BN254_R) }],
    ['facts past the field', { ...json, facts: String(BN254_R) }],
    ['the verifier as x then y in hex', { ...json, verifier: pointOf(json.verifier).map((n) => n.toString(16).padStart(64, '0')).join('') }],
    ['a verifier that is no address', { ...json, verifier: json.verifier.slice(1) }],
    ['the verifier as a point', { ...json, verifier: pointOf(json.verifier).map(String) }],
    ['the services form, R8 and S', { ...json, signature: { R8: json.signature.r8, S: json.signature.s } }],
    ['a signature field more', { ...json, signature: { ...json.signature, extra: '1' } }],
  ]
  for (const [what, value] of bad) assert.throws(() => stampFromJson(value), Error, what)
})

test("fields a verifier adds beside the stamp pass through signing and JSON unchanged, and are not signed", () => {
  const added = { embedding: 'AAAAPgAAAL8AAAA-', model: 'example-face-model/1', tier: '2', nested: { at: [1, 'x'] } }
  const withAdded = signStamp(verifierKey, { ...stamp, ...added })
  assert.deepEqual(withAdded.signature, signed.signature, 'the same signature: only the stamp number and facts are signed')
  const json = stampToJson(withAdded)
  for (const [key, value] of Object.entries(added)) assert.deepEqual(json[key], value, key)
  const back = stampFromJson(JSON.parse(JSON.stringify(json)))
  assert.deepEqual(back, withAdded)
  assert.equal(stampSigned(back), true)
  assert.deepEqual(stampToJson(back), json)
  assert.equal(stampSigned({ ...back, model: 'another' }), true, 'an added field is the verifier’s, not the stamp’s')
})

test("the circuit's input: keys/'s tag and main key, and the public signals in order", async () => {
  const label = 'tutoring/seller'
  const { input, publicSignals } = stampInput({ seedScalar: S, verifierName: verifierA.name, stamp: signed, label })
  const main = await mainKey(seed, label)
  const a = await verifierSecret(seed, verifierA.name)
  assert.deepEqual(publicSignals, [
    tagOf(a.scalar, label),
    main.publicKey[0],
    main.publicKey[1],
    ...pointOf(signed.verifier),
    scopeOf(label),
    nameHashOf(verifierA.name),
  ])
  assert.equal(publicSignals[0].toString(), verifierA.tags[label], "keys/'s pinned tag")
  assert.equal(input.seedScalar, BigInt(keysVectors.seedScalar.scalar))
  const other = stampInput({ seedScalar: S, verifierName: verifierA.name, stamp: signed, label: 'tutoring/buyer' }).publicSignals
  assert.notEqual(other[0], publicSignals[0], 'another label, another tag')
  assert.notEqual(other[1], publicSignals[1], 'and another key')
  assert.throws(() => stampInput({ seedScalar: BN254_R, verifierName: verifierA.name, stamp: signed, label }), /field element/)
  assert.throws(() => stampInput({ seedScalar: S, verifierName: verifierA.name, stamp: { ...signed, facts: BN254_R }, label }), /field element/)
  // The circuit's signal for the facts keeps its name, attributes: note.circom keeps its bytes.
  assert.equal(input.attributes, signed.facts, 'the facts go in as the verifier signed them')
})
