// The stamp client without proving: the verification key it checks with, the constants the circuit
// shares with keys/, the hashes that turn text into numbers, and the 256 bytes a proof is carried
// in. The proofs themselves are the circuit's tests (../../circuit/test/).

import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { keccak_256 } from '@noble/hashes/sha3.js'

import { PREFIX, publicKeyOf } from '@foundationforest/keys'
import {
  BN254_P,
  BN254_R,
  fieldHash,
  fromBytes32,
  nameHashOf,
  proofBytes,
  proofFromBytes,
  scopeOf,
  toBytes32,
  type SnarkjsProof,
} from '../src/index.ts'
import { STAMP_KEY } from '../src/stamp-key.ts'

const here = dirname(fileURLToPath(import.meta.url))
const circuit = readFileSync(join(here, '../../circuit/note.circom'), 'utf8')
const hash = (text: string) => fromBytes32(keccak_256(new TextEncoder().encode(text))) >> 8n

test("the verification key is the circuit's committed one, value for value", () => {
  const committed = JSON.parse(readFileSync(join(here, '../../circuit/setup/verification-key.json'), 'utf8'))
  assert.deepEqual(STAMP_KEY, committed)
  assert.equal(STAMP_KEY.nPublic, 7)
})

test("the circuit's constants are keys/'s: the verifier and profile prefixes, and Base8", () => {
  // note.circom keeps its bytes, the names of its constants among them: ISSUER_TAG and PROFILE_TAG
  // are the prefixes.
  assert.ok(circuit.includes(`var ISSUER_TAG = ${PREFIX.verifier};`), 'the verifier prefix')
  assert.ok(circuit.includes(`var PROFILE_TAG = ${PREFIX.profile};`), 'the profile prefix')
  const [x, y] = publicKeyOf(1n)
  assert.ok(circuit.includes(`${x},\n        ${y}\n    ];`), 'Base8, the point a scalar of 1 gives')
  assert.equal(PREFIX.verifier, hash('forest/v1/issuer'))
  assert.equal(PREFIX.profile, hash('forest/v1/profile'))
})

test('a label gives a scope and a name a name hash, each a field element, and the namespaces never collide', () => {
  for (const text of ['tutoring/seller', '', 'ünïcødé/ラベル', 'x'.repeat(1000)]) {
    const scope = scopeOf(text)
    const name = nameHashOf(text)
    assert.equal(scope, hash('forest/v1/label/' + text))
    assert.equal(name, hash('forest/v1/issuer/' + text))
    assert.notEqual(scope, name)
    for (const n of [scope, name]) assert.ok(n >= 0n && n < BN254_R && n < 2n ** 248n)
  }
  assert.equal(fieldHash('', 'forest/v1/note'), hash('forest/v1/note'))
  assert.throws(() => scopeOf('a\ud800'), /label must be text/)
  assert.throws(() => nameHashOf(7 as unknown as string), /verifier name must be text/)
})

test('a number as 32 big-endian bytes, and back', () => {
  for (const n of [0n, 1n, BN254_R - 1n, 2n ** 256n - 1n]) assert.equal(fromBytes32(toBytes32(n)), n)
  assert.deepEqual(toBytes32(258n).subarray(30), Uint8Array.from([1, 2]))
  assert.throws(() => toBytes32(2n ** 256n), /256-bit/)
  assert.throws(() => toBytes32(-1n), /256-bit/)
  assert.throws(() => fromBytes32(new Uint8Array(31)), /32 bytes/)
})

test('the 256 bytes of a proof: eight coordinates, each G2 pair imaginary part first, and back', () => {
  const c = () => (BigInt('0x' + randomBytes(32).toString('hex')) % BN254_P).toString()
  const proof: SnarkjsProof = { pi_a: [c(), c(), '1'], pi_b: [[c(), c()], [c(), c()], ['1', '0']], pi_c: [c(), c(), '1'] }
  const bytes = proofBytes(proof)
  const order = [proof.pi_a[0], proof.pi_a[1], proof.pi_b[0][1], proof.pi_b[0][0], proof.pi_b[1][1], proof.pi_b[1][0], proof.pi_c[0], proof.pi_c[1]]
  assert.deepEqual(Buffer.from(bytes), Buffer.concat(order.map((s) => toBytes32(BigInt(s)))))
  assert.deepEqual(proofFromBytes(bytes), proof)
  assert.throws(() => proofFromBytes(bytes.subarray(1)), /256 bytes/)
  const plusModulus = bytes.slice()
  plusModulus.set(toBytes32(fromBytes32(bytes.subarray(0, 32)) + BN254_P), 0)
  assert.throws(() => proofFromBytes(plusModulus), /below the base field modulus/)
  assert.throws(() => proofBytes({ ...proof, pi_a: [proof.pi_a[0], proof.pi_a[1], '2'] }), /last coordinate 1/)
  assert.throws(() => proofBytes({ ...proof, pi_c: [String(BN254_P), proof.pi_c[1], '1'] }), /below the base field modulus/)
})
