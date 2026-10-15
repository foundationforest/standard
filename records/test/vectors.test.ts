// The spec's pinned vectors: recomputed here, and each step checked with a second implementation:
// node:crypto (OpenSSL) for SHA-256, and zk-kit's EdDSA-Poseidon for Baby Jubjub, which reads the
// key from the address and the signature from its 64 bytes on its own. The keys are keys/'s, and
// keys/'s own tests recompute them.

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { derivePublicKey, packPublicKey, unpackPublicKey, unpackSignature, verifySignature } from '@zk-kit/eddsa-poseidon'
import { b64u, base58, hex } from '../src/bytes.ts'
import { checkBlobRequest, checkPull, decodeMessage } from '../src/message.ts'
import { openMessage } from '../src/private.ts'
import { decodeRecord } from '../src/record.ts'
import { KEYS } from './fixtures.ts'
import { vectors } from './vectors.ts'

const pinned = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'))
const RECORDS = ['hosts', 'profileCard', 'offer', 'permissions', 'written', 'deleted', 'past'] as const

/** A packed point's 32 bytes, little-endian, as the number zk-kit takes. */
const littleEndian = (bytes: Uint8Array) => bytes.reduceRight((n, b) => (n << 8n) | BigInt(b), 0n)
/** The number a signature signs: SHA-256 of the signed bytes, big-endian, shifted right one byte. */
const signed = (input: Uint8Array) => BigInt('0x' + createHash('sha256').update(input).digest('hex')) >> 8n
/** Does zk-kit say `address`'s key signed `input`? */
const zkVerifies = (input: Uint8Array, address: string, sig: string) => {
  const key = unpackPublicKey(littleEndian(base58.decode(address)))
  return verifySignature(signed(input), unpackSignature(Buffer.from(b64u.decode(sig))), key)
}
const startsWith = (input: Uint8Array, text: string) => assert.deepEqual([...input.subarray(0, 1 + text.length)], [0xff, ...Buffer.from(text)])

test('the vectors are what this implementation computes', async () => {
  assert.deepEqual(await vectors(), pinned)
})

test("the keys are keys/'s pinned ones; the write key and the read key, recomputed with zk-kit from their 32 bytes", () => {
  assert.equal(pinned.profile, KEYS.mainKeys[0].address)
  assert.equal(decodeRecord(pinned.profileCard.wire).record.body!.inboxKey, KEYS.mainKeys[0].inbox.recipient)
  const address = (byte: number) => {
    let n = packPublicKey(derivePublicKey(new Uint8Array(32).fill(byte)))
    const bytes = new Uint8Array(32)
    for (let i = 0; i < 32; i++, n >>= 8n) bytes[i] = Number(n & 0xffn)
    return base58.encode(bytes)
  }
  assert.deepEqual([address(0x2a), address(0x2b)], [pinned.writeKey, pinned.readKey])
  assert.deepEqual([pinned.writeKey, pinned.readKey], [KEYS.accessKeys.write.address, KEYS.accessKeys.read.address])
  assert.deepEqual(decodeRecord(pinned.permissions.wire).record.body, {
    access: [
      { key: pinned.writeKey, scope: 'write', paths: ['offer', 'inbox'] },
      { key: pinned.readKey, recipient: KEYS.accessKeys.read.recipient, scope: 'read', paths: ['inbox'] },
    ],
  })
})

test('the past permissions record keeps the write key, now past, and the read key as it was', () => {
  assert.deepEqual(decodeRecord(pinned.past.wire).record.body!.access, [
    { key: pinned.writeKey, was: 'write', paths: ['offer', 'inbox'] },
    { key: pinned.readKey, recipient: KEYS.accessKeys.read.recipient, scope: 'read', paths: ['inbox'] },
  ])
})

test('each record checks with a second EdDSA-Poseidon and a second SHA-256', () => {
  for (const name of RECORDS) {
    const v = pinned[name] as { wire: string; signingInputHex: string; id: string }
    const { record, id } = decodeRecord(v.wire)
    assert.equal(id, v.id)
    const input = hex.decode(v.signingInputHex)
    startsWith(input, 'forest/v1/record\n')
    assert.equal(createHash('sha256').update(input).digest('hex'), v.id)
    assert.ok(zkVerifies(input, record.by ?? record.profile, record.sig), name)
  }
  assert.equal(decodeRecord(pinned.written.wire).record.by, pinned.writeKey, 'the write key signed what it wrote')
})

test("the message checks with a second EdDSA-Poseidon and a second SHA-256, is from keys/'s tutoring/buyer, and opens with tutoring/seller's pinned inbox key", async () => {
  const v = pinned.message as { wire: string; signingInputHex: string; id: string }
  const { message, id } = decodeMessage(v.wire)
  assert.equal(id, v.id)
  const input = hex.decode(v.signingInputHex)
  startsWith(input, 'forest/v1/message\n')
  assert.equal(createHash('sha256').update(input).digest('hex'), v.id)
  assert.deepEqual([message.from, message.to], [KEYS.mainKeys[1].address, KEYS.mainKeys[0].address])
  assert.ok(zkVerifies(input, message.from, message.sig))
  assert.deepEqual((await openMessage(v.wire, KEYS.mainKeys[0].inbox.identity)).body, { text: 'Is Tuesday at six free?' })
})

test("the write key's message checks with a second EdDSA-Poseidon by the write key, is for keys/'s tutoring/seller on host-a, and opens with tutoring/buyer's pinned inbox key", async () => {
  const v = pinned.keyMessage as { wire: string; signingInputHex: string; id: string }
  const { message, id } = decodeMessage(v.wire)
  assert.equal(id, v.id)
  const input = hex.decode(v.signingInputHex)
  startsWith(input, 'forest/v1/message\n')
  assert.equal(createHash('sha256').update(input).digest('hex'), v.id)
  assert.deepEqual([message.from, message.key, message.host, message.to], [KEYS.mainKeys[0].address, pinned.writeKey, 'https://host-a.example', KEYS.mainKeys[1].address])
  assert.ok(zkVerifies(input, message.key!, message.sig))
  assert.ok(!zkVerifies(input, message.from, message.sig), 'the main key did not sign it')
  const opened = await openMessage(v.wire, KEYS.mainKeys[1].inbox.identity)
  assert.deepEqual([opened.body, opened.key], [{ text: 'Tuesday at six, yes.' }, pinned.writeKey])
})

test('each blob request checks with a second SHA-256 and EdDSA-Poseidon: a put by the main key, a delete by its write key', () => {
  const letters = createHash('sha256').update('abcdefghijklmnopqrstuvwxyz').digest('hex')
  for (const [name, signer, action] of [['blobPut', pinned.profile, 'put'], ['blobDelete', pinned.writeKey, 'delete']] as const) {
    const v = pinned[name] as { wire: string; signingInputHex: string }
    const request = checkBlobRequest(v.wire, JSON.parse(v.wire).time)
    const input = hex.decode(v.signingInputHex)
    startsWith(input, 'forest/v1/blob\n')
    assert.deepEqual([request.action, request.profile, request.sha256], [action, KEYS.mainKeys[0].address, letters])
    assert.equal(request.key ?? request.profile, signer)
    assert.ok(zkVerifies(input, signer, request.sig), name)
  }
  assert.deepEqual(JSON.parse(pinned.blobPut.wire).mimeType, 'text/plain')
  assert.deepEqual(JSON.parse(pinned.blobPut.wire).size, 26)
})

test('each pull checks with a second EdDSA-Poseidon: by the profile it pulls, and by its read key', () => {
  for (const [name, signer] of [['pull', pinned.profile], ['keyPull', pinned.readKey]] as const) {
    const v = pinned[name] as { wire: string; signingInputHex: string }
    const pull = checkPull(v.wire, JSON.parse(v.wire).time)
    const input = hex.decode(v.signingInputHex)
    startsWith(input, 'forest/v1/pull\n')
    assert.equal(pull.profile, KEYS.mainKeys[0].address)
    assert.equal(pull.key ?? pull.profile, signer)
    assert.ok(zkVerifies(input, signer, pull.sig), name)
  }
})
