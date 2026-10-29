// The spec's pinned vectors: recomputed here, and each step checked with a second implementation:
// node:crypto (OpenSSL) for SHA-256 and HMAC-SHA256, and zk-kit's EdDSA-Poseidon for Baby Jubjub,
// which reads the key from the address and the signature from its 64 bytes on its own. The keys and
// the pay signatures are keys/'s, and keys/'s own tests recompute them.

import assert from 'node:assert/strict'
import { createHash, createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { profilesKey } from '@foundationforest/keys'
import { stampFromJson, stampSigned } from '@foundationforest/proofs'
import { unpackPublicKey, unpackSignature, verifySignature } from '@zk-kit/eddsa-poseidon'
import { b64u, base58, hex } from '../src/bytes.ts'
import { decodeEntry } from '../src/entry.ts'
import { decodeDelete, decodeInbox } from '../src/inbox.ts'
import { openInbox, openLocked } from '../src/locked.ts'
import { checkPay } from '../src/pay.ts'
import { KEYS, SEED, access } from './fixtures.ts'
import { LABEL, LETTERS, NOTE, vectors } from './vectors.ts'

const pinned = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'))
const ENTRIES = ['profileEntry', 'offer', 'offerByKey', 'photo', 'deleted', 'note'] as const
const [seller, buyer] = KEYS.mainKeys

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
/** A keyed id by node:crypto's HMAC-SHA256. */
const keyed = (secret: string, text: string) => createHmac('sha256', Buffer.from(secret, 'hex')).update(text, 'utf8').digest('hex').slice(0, 32)

test('the vectors are what this implementation computes', async () => {
  assert.deepEqual(await vectors(), pinned)
})

test("the folder is keys/'s pinned profile's, and its profile entry gives its pinned open key, its pay addresses with keys/'s pinned signatures, which hold, and keys/'s access key", () => {
  assert.equal(pinned.profile, seller.address)
  assert.equal(pinned.accessKey, KEYS.accessKey.address)
  const body = decodeEntry(pinned.profileEntry.wire).entry.body!
  assert.equal(body.openKey, seller.opening.openKey)
  const pay = KEYS.payKeys.filter((p: { label: string }) => p.label === 'tutoring/seller')
  assert.deepEqual(body.pay, Object.fromEntries(pay.map((p: { type: string; address: string }) => [p.type, p.address])))
  assert.deepEqual(body.paySig, Object.fromEntries(pay.map((p: { type: string; paySig: string }) => [p.type, p.paySig])))
  assert.deepEqual(checkPay(body, pinned.profile), ['solana', 'evm'])
  assert.deepEqual(body.keys, [{ key: KEYS.accessKey.address, open: KEYS.accessKey.opening.openKey, can: ['read-inbox', 'write'] }])
})

test('each entry checks with a second EdDSA-Poseidon and a second SHA-256, by the main key or the access key it names', () => {
  for (const name of ENTRIES) {
    const v = pinned[name] as { wire: string; signingInputHex: string; id: string }
    const { entry, id } = decodeEntry(v.wire)
    assert.equal(id, v.id)
    const input = hex.decode(v.signingInputHex)
    startsWith(input, 'forest/v1/entry\n')
    assert.equal(createHash('sha256').update(input).digest('hex'), v.id)
    assert.equal(entry.key, name === 'offerByKey' ? KEYS.accessKey.address : undefined, name)
    assert.ok(zkChecks(input, entry.key ?? entry.profile, entry.sig), name)
  }
  const photo = decodeEntry(pinned.photo.wire).entry.body!
  assert.deepEqual(photo.files, [{ sha256: createHash('sha256').update(LETTERS).digest('hex'), type: 'text/plain', size: 26 }])
})

test("the inbox entry's id is SHA-256 of its text; its message, locked inside, opens with tutoring/seller's open key and the access key's, and checks with a second EdDSA-Poseidon, its signature naming the folder", async () => {
  const v = pinned.inbox
  const { entry, id } = decodeInbox(v.wire)
  assert.equal(id, v.id)
  assert.equal(createHash('sha256').update(v.wire).digest('hex'), v.id)
  assert.deepEqual(Object.keys(JSON.parse(v.wire)).sort(), ['body', 'time', 'to', 'v'], 'nothing outside names the sender')
  for (const identity of [seller.opening.identity, KEYS.accessKey.opening.identity]) {
    const opened = await openInbox(entry, identity)
    assert.equal(JSON.stringify(opened.message), v.message.wire)
  }
  await assert.rejects(openInbox(entry, buyer.opening.identity), 'not the sender’s own')
  const message = JSON.parse(v.message.wire)
  assert.deepEqual([message.from, message.host, message.body], [buyer.address, 'https://host-b.example', { text: 'Is Tuesday at six free?' }])
  const input = hex.decode(v.message.signingInputHex)
  startsWith(input, 'forest/v1/message\n')
  assert.equal(JSON.parse(Buffer.from(input.subarray(19)).toString()).to, seller.address, 'the signed text names the folder')
  assert.ok(zkChecks(input, message.from, message.sig))
})

test('the inbox delete checks with a second EdDSA-Poseidon, by the access key, for that entry', () => {
  const v = pinned.inboxDelete
  const request = decodeDelete(v.wire)
  const input = hex.decode(v.signingInputHex)
  startsWith(input, 'forest/v1/inbox/delete\n')
  assert.deepEqual([request.to, request.id, request.key], [seller.address, pinned.inbox.id, access.address])
  assert.ok(zkChecks(input, request.key!, request.sig))
})

test("the note sits at its path keyed by tutoring/seller's secret, a second HMAC-SHA256's, and opens with its open key alone", async () => {
  const { entry } = decodeEntry(pinned.note.wire)
  assert.equal(entry.path, `key/${keyed(seller.secret, KEYS.accessKey.address)}`)
  assert.deepEqual(await openLocked(entry.body!, seller.opening.identity), NOTE)
  await assert.rejects(openLocked(entry.body!, KEYS.accessKey.opening.identity))
})

test("the Profiles folder is keys/'s pinned Profiles folder key's: its profile entry holds only hosts, and its label and stamp entries sit at paths keyed by its secret and open with its open key", async () => {
  const v = pinned.profilesFolder
  assert.equal(v.profile, KEYS.profilesKey.address)
  assert.equal((await profilesKey(SEED)).address, v.profile)
  for (const name of ['profileEntry', 'label', 'stamp'] as const) {
    const { entry, id } = decodeEntry(v[name].wire)
    assert.equal(id, v[name].id)
    assert.equal(createHash('sha256').update(hex.decode(v[name].signingInputHex)).digest('hex'), id)
    assert.ok(zkChecks(hex.decode(v[name].signingInputHex), v.profile, entry.sig), name)
  }
  assert.deepEqual(decodeEntry(v.profileEntry.wire).entry.body, { hosts: ['https://host-a.example'] })
  const label = decodeEntry(v.label.wire).entry
  assert.equal(label.path, `label/${keyed(KEYS.profilesKey.secret, 'tutoring/seller')}`)
  assert.deepEqual(await openLocked(label.body!, KEYS.profilesKey.opening.identity), LABEL)
  await assert.rejects(openLocked(label.body!, seller.opening.identity))
  // The stamp, kept as text: its path keyed by that text, the stamp its verifier signed, and the
  // fraction the verifier added, which no entry's body could spell, there whole.
  const stamp = decodeEntry(v.stamp.wire).entry
  assert.equal(stamp.path, `stamp/${keyed(KEYS.profilesKey.secret, v.stamp.text)}`)
  assert.deepEqual(await openLocked(stamp.body!, KEYS.profilesKey.opening.identity), { stamp: v.stamp.text })
  const signed = stampFromJson(JSON.parse(v.stamp.text))
  assert.equal(stampSigned(signed), true)
  assert.equal(signed.score, 0.97)
})
