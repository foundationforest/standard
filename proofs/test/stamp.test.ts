// The stamp: what a verifier signs, its signature and its JSON, checked without proving. The
// verifications made from it are verification.test.ts's.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { keccak_256 } from '@noble/hashes/sha3.js'
import { verifySignature } from '@zk-kit/eddsa-poseidon'
import { poseidon2 } from 'poseidon-lite/poseidon2'
import { poseidon3 } from 'poseidon-lite/poseidon3'

import { pointOf, serviceKey, signWithScalar } from '@foundationforest/keys'
import {
  BN254_R,
  fromBytes32,
  fieldHash,
  seedNumber,
  verifierKeyOf,
  stampFromJson,
  stampHash,
  stampNumberOf,
  stampSigned,
  stampToJson,
  signStamp,
  type Stamp,
} from '../src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
const keysVectors = JSON.parse(readFileSync(join(here, '../../keys/test/vectors.json'), 'utf8'))
const seed = Uint8Array.from(Buffer.from(keysVectors.seed, 'hex'))
const [verifierA, verifierB] = keysVectors.verifiers
const S = seedNumber(seed)

const verifierKey = new Uint8Array(32).fill(1)
const stamp: Stamp = {
  stampNumber: stampNumberOf(S, verifierA.name),
  facts: fieldHash('forest example facts', 'verifier-a'),
  verifierName: verifierA.name,
}
const signed = signStamp(verifierKey, stamp)

test("the stamp number is keys/'s, from the seed's number and the verifier's name", () => {
  for (const verifier of keysVectors.verifiers) assert.equal(stampNumberOf(S, verifier.name).toString(), verifier.stampNumber)
  assert.throws(() => stampNumberOf(BN254_R, verifierA.name), /field element/)
})

const hash = (text: string) => fromBytes32(keccak_256(new TextEncoder().encode(text))) >> 8n

test("a verifier signs Poseidon(its name hash, stamp number, facts), the name hash keccak256 of forest/verifier/ and its name, shifted right one byte", () => {
  assert.equal(stampHash(stamp), poseidon3([hash('forest/verifier/' + verifierA.name), stamp.stampNumber, stamp.facts]))
  assert.equal(stampHash(stamp), poseidon3([BigInt(verifierA.nameHash), stamp.stampNumber, stamp.facts]))
  assert.notEqual(stampHash({ ...stamp, verifierName: verifierB.name }), stampHash(stamp), 'another name, another stamp')
  assert.throws(() => stampHash({ ...stamp, verifierName: 'a\ud800' }), /verifier name must be text/)
  assert.throws(() => stampHash({ ...stamp, stampNumber: BN254_R }), /field element/)
  assert.throws(() => stampHash({ ...stamp, stampNumber: -1n }), /field element/)
  assert.throws(() => stampHash({ ...stamp, facts: BN254_R }), /field element/)
  assert.throws(() => stampHash({ ...stamp, facts: -1n }), /field element/)
})

test("a signed stamp checks, with zk-kit's check too; any change to it, its verifier or its signature does not", () => {
  assert.equal(stampSigned(signed), true)
  assert.equal(verifySignature(stampHash(stamp), signed.signature, pointOf(signed.verifier)), true, "zk-kit's own check")
  assert.deepEqual(signed.verifier, verifierKeyOf(verifierKey))
  assert.equal(signed.verifier, serviceKey(verifierKey).address, "a verifier's key is a service key")
  const other = verifierKeyOf(new Uint8Array(32).fill(2))
  const cases: [string, typeof signed][] = [
    ['another stamp number', { ...signed, stampNumber: stampNumberOf(S, verifierB.name) }],
    ['another name', { ...signed, verifierName: verifierB.name }],
    ['other facts', { ...signed, facts: signed.facts + 1n }],
    ['another verifier', { ...signed, verifier: other }],
    ['another S', { ...signed, signature: { ...signed.signature, S: signed.signature.S + 1n } }],
    ['S out of range', { ...signed, signature: { ...signed.signature, S: BN254_R } }],
    ['R8 off the curve', { ...signed, signature: { ...signed.signature, R8: [1n, 1n] } }],
    ['facts past the field', { ...signed, facts: BN254_R }],
  ]
  for (const [what, n] of cases) assert.equal(stampSigned(n), false, what)
  // The verifier's signature over the same fields without its name hash is no stamp.
  const nameless = { ...signed, signature: signWithScalar(serviceKey(verifierKey).scalar, poseidon2([stamp.stampNumber, stamp.facts])) }
  assert.equal(stampSigned(nameless), false, 'no name hash')
  assert.throws(() => signStamp(new Uint8Array(31), stamp), /32 bytes/)
})

test("a stamp as JSON: big numbers in decimal text, the verifier key as its address, the verifier's name as text; and back", () => {
  const json = stampToJson(signed)
  assert.deepEqual(Object.keys(json).sort(), ['facts', 'signature', 'stampNumber', 'verifier', 'verifierName'])
  for (const key of [...Object.keys(json), ...Object.keys(json.signature)]) assert.match(key, /^[a-z][a-zA-Z0-9]{0,63}$/, key)
  assert.equal(json.stampNumber, String(signed.stampNumber))
  assert.equal(json.facts, String(signed.facts))
  assert.equal(json.verifier, verifierKeyOf(verifierKey))
  assert.match(json.verifier, /^[1-9A-HJ-NP-Za-km-z]{43,44}$/)
  assert.equal(json.verifierName, verifierA.name)
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
    ['no verifier name', { ...json, verifierName: undefined }],
    ['a verifier name that is no text', { ...json, verifierName: 7 }],
    ['a verifier name with a lone surrogate', { ...json, verifierName: 'a\ud800' }],
    ['the verifier as a point', { ...json, verifier: pointOf(json.verifier).map(String) }],
    ['the services form, R8 and S', { ...json, signature: { R8: json.signature.r8, S: json.signature.s } }],
    ['a signature field more', { ...json, signature: { ...json.signature, extra: '1' } }],
  ]
  for (const [what, value] of bad) assert.throws(() => stampFromJson(value), Error, what)
})

test("fields a verifier adds beside the stamp pass through signing and JSON unchanged, and are not signed", () => {
  const added = { embedding: 'AAAAPgAAAL8AAAA-', model: 'example-face-model/1', tier: '2', nested: { at: [1, 'x'] } }
  const withAdded = signStamp(verifierKey, { ...stamp, ...added })
  assert.deepEqual(withAdded.signature, signed.signature, 'the same signature: only the name hash, the stamp number and the facts are signed')
  const json = stampToJson(withAdded)
  for (const [key, value] of Object.entries(added)) assert.deepEqual(json[key], value, key)
  const back = stampFromJson(JSON.parse(JSON.stringify(json)))
  assert.deepEqual(back, withAdded)
  assert.equal(stampSigned(back), true)
  assert.deepEqual(stampToJson(back), json)
  assert.equal(stampSigned({ ...back, model: 'another' }), true, 'an added field is the verifier’s, not the stamp’s')
})
