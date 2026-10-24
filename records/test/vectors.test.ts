// The spec's pinned vectors: recomputed here, and each step checked with a second implementation:
// node:crypto (OpenSSL) for SHA-256, and zk-kit's EdDSA-Poseidon for Baby Jubjub, which reads the
// key from the address and the signature from its 64 bytes on its own. The keys are keys/'s, and
// keys/'s own tests recompute them.

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { unpackPublicKey, unpackSignature, verifySignature } from '@zk-kit/eddsa-poseidon'
import { b64u, base58, hex } from '../src/bytes.ts'
import { checkBlobRequest, checkPull, decodeMessage } from '../src/message.ts'
import { openMessage } from '../src/private.ts'
import { decodeRecord } from '../src/record.ts'
import { KEYS } from './fixtures.ts'
import { vectors } from './vectors.ts'

const pinned = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'))
const RECORDS = ['hosts', 'profileRecord', 'offer', 'deleted'] as const

/** A packed point's 32 bytes, little-endian, as the number zk-kit takes. */
const littleEndian = (bytes: Uint8Array) => bytes.reduceRight((n, b) => (n << 8n) | BigInt(b), 0n)
/** The number a signature signs: SHA-256 of the signed bytes, big-endian, shifted right one byte. */
const signed = (input: Uint8Array) => BigInt('0x' + createHash('sha256').update(input).digest('hex')) >> 8n
/** Does zk-kit say `address`'s key signed `input`? */
const zkChecks = (input: Uint8Array, address: string, sig: string) => {
  const key = unpackPublicKey(littleEndian(base58.decode(address)))
  return verifySignature(signed(input), unpackSignature(Buffer.from(b64u.decode(sig))), key)
}
const startsWith = (input: Uint8Array, text: string) => assert.deepEqual([...input.subarray(0, 1 + text.length)], [0xff, ...Buffer.from(text)])

test('the vectors are what this implementation computes', async () => {
  assert.deepEqual(await vectors(), pinned)
})

test("the profile is keys/'s pinned one, and its profile record gives its pinned inbox key", () => {
  assert.equal(pinned.profile, KEYS.mainKeys[0].address)
  assert.equal(decodeRecord(pinned.profileRecord.wire).record.body!.inboxKey, KEYS.mainKeys[0].inbox.encryptTo)
})

test('each record checks with a second EdDSA-Poseidon and a second SHA-256', () => {
  for (const name of RECORDS) {
    const v = pinned[name] as { wire: string; signingInputHex: string; id: string }
    const { record, id } = decodeRecord(v.wire)
    assert.equal(id, v.id)
    const input = hex.decode(v.signingInputHex)
    startsWith(input, 'forest/v1/record\n')
    assert.equal(createHash('sha256').update(input).digest('hex'), v.id)
    assert.ok(zkChecks(input, record.profile, record.sig), name)
  }
})

test("the message checks with a second EdDSA-Poseidon and a second SHA-256, is from keys/'s tutoring/buyer, and opens with tutoring/seller's pinned inbox key", async () => {
  const v = pinned.message as { wire: string; signingInputHex: string; id: string }
  const { message, id } = decodeMessage(v.wire)
  assert.equal(id, v.id)
  const input = hex.decode(v.signingInputHex)
  startsWith(input, 'forest/v1/message\n')
  assert.equal(createHash('sha256').update(input).digest('hex'), v.id)
  assert.deepEqual([message.from, message.to], [KEYS.mainKeys[1].address, KEYS.mainKeys[0].address])
  assert.ok(zkChecks(input, message.from, message.sig))
  assert.deepEqual((await openMessage(v.wire, KEYS.mainKeys[0].inbox.identity)).body, { text: 'Is Tuesday at six free?' })
})

test('each blob request checks with a second SHA-256 and EdDSA-Poseidon: a put and a delete, each by the main key', () => {
  const letters = createHash('sha256').update('abcdefghijklmnopqrstuvwxyz').digest('hex')
  for (const [name, action] of [['blobPut', 'put'], ['blobDelete', 'delete']] as const) {
    const v = pinned[name] as { wire: string; signingInputHex: string }
    const request = checkBlobRequest(v.wire, JSON.parse(v.wire).time)
    const input = hex.decode(v.signingInputHex)
    startsWith(input, 'forest/v1/blob\n')
    assert.deepEqual([request.action, request.profile, request.sha256], [action, KEYS.mainKeys[0].address, letters])
    assert.ok(zkChecks(input, pinned.profile, request.sig), name)
  }
  assert.deepEqual(JSON.parse(pinned.blobPut.wire).mimeType, 'text/plain')
  assert.deepEqual(JSON.parse(pinned.blobPut.wire).size, 26)
})

test('the pull checks with a second EdDSA-Poseidon, by the profile it pulls', () => {
  const v = pinned.pull as { wire: string; signingInputHex: string }
  const pull = checkPull(v.wire, JSON.parse(v.wire).time)
  const input = hex.decode(v.signingInputHex)
  startsWith(input, 'forest/v1/pull\n')
  assert.equal(pull.profile, KEYS.mainKeys[0].address)
  assert.ok(zkChecks(input, pull.profile, pull.sig))
})
