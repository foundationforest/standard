// The spec's pinned vectors: recomputed here, and each step checked with a second implementation:
// node:crypto (OpenSSL) for SHA-256, and zk-kit's EdDSA-Poseidon for Baby Jubjub, which reads the key
// from the address and the signature from its 64 bytes on its own. The keys and the pay addresses
// are keys/'s, and keys/'s own tests recompute them.

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { mainKey } from '@foundationforest/keys'
import { stampFromJson, stampSigned } from '@foundationforest/proofs'
import { unpackPublicKey, unpackSignature, verifySignature } from '@zk-kit/eddsa-poseidon'
import { b64u, base58, hex } from '../src/bytes.ts'
import { decodeEntry } from '../src/entry.ts'
import { decodeInbox } from '../src/inbox.ts'
import { openInbox, openLocked } from '../src/locked.ts'
import { KEYS, SEED } from './fixtures.ts'
import { IDS, LABEL, LETTERS, NOTE, vectors } from './vectors.ts'

const pinned = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'))
const ENTRIES = ['profileEntry', 'offer', 'offerByKey', 'photo', 'deleted', 'note'] as const
const [seller, buyer, profilesFolder] = KEYS.mainKeys

/** A packed point's 32 bytes, little-endian, as the number zk-kit takes. */
const littleEndian = (bytes: Uint8Array) => bytes.reduceRight((n, b) => (n << 8n) | BigInt(b), 0n)
/** The number a signature signs: SHA-256 of the signed bytes, big-endian, shifted right one byte. */
const signed = (input: Uint8Array) => BigInt('0x' + createHash('sha256').update(input).digest('hex')) >> 8n
/** Does zk-kit say `address`'s key signed `input`? */
const zkChecks = (input: Uint8Array, address: string, sig: string) => {
  const key = unpackPublicKey(littleEndian(base58.decode(address)))
  return verifySignature(signed(input), unpackSignature(Buffer.from(b64u.decode(sig))), key)
}
/** The signed bytes are exactly the canonical text of the value without its sig: no prefix, no words. */
const isWireWithoutSig = (input: Uint8Array, wire: string) => {
  const { sig: _sig, ...rest } = JSON.parse(wire)
  const text = Buffer.from(input).toString('utf8')
  assert.deepEqual(JSON.parse(text), rest)
  assert.equal(text, wire.replace(/,"sig":"[A-Za-z0-9_-]{86}"/, ''), 'sig is the last key, so the rest is the wire text without it')
}

test('the vectors are what this implementation computes', async () => {
  assert.deepEqual(await vectors(), pinned)
})

test("the folder is keys/'s pinned profile's, and its profile entry gives its pinned open key, its pay addresses, unsigned, and keys/'s access key", () => {
  assert.equal(pinned.profile, seller.address)
  assert.equal(pinned.accessKey, KEYS.accessKey.address)
  const body = decodeEntry(pinned.profileEntry.wire).entry.body!
  assert.equal(body.openKey, seller.opening.openKey)
  const pay = KEYS.payKeys.filter((p: { label: string }) => p.label === 'tutoring/seller')
  assert.deepEqual(body.pay, Object.fromEntries(pay.map((p: { chain: string; address: string }) => [p.chain, p.address])))
  assert.deepEqual(body.keys, [{ key: KEYS.accessKey.address, open: KEYS.accessKey.opening.openKey, can: ['read-inbox', 'write'] }])
})

test('each entry checks with a second EdDSA-Poseidon and a second SHA-256, by the main key or the access key it names, over its canonical text alone', () => {
  for (const name of ENTRIES) {
    const v = pinned[name] as { wire: string; signingInputHex: string; id: string }
    const { entry, id } = decodeEntry(v.wire)
    assert.equal(id, v.id)
    const input = hex.decode(v.signingInputHex)
    isWireWithoutSig(input, v.wire)
    assert.equal(createHash('sha256').update(input).digest('hex'), v.id)
    assert.equal(entry.key, name === 'offerByKey' ? KEYS.accessKey.address : undefined, name)
    assert.ok(zkChecks(input, entry.key ?? entry.profile, entry.sig), name)
  }
  const photo = decodeEntry(pinned.photo.wire).entry.body!
  assert.deepEqual(photo.files, [{ sha256: createHash('sha256').update(LETTERS).digest('hex'), type: 'text/plain', size: 26 }])
})

test("the inbox entry's id is SHA-256 of its text; its message, locked inside, opens with tutoring/seller's open key and the access key's, and checks with a second EdDSA-Poseidon, its folder among its signed fields", async () => {
  const v = pinned.inbox
  const { entry, id } = decodeInbox(v.wire)
  assert.equal(id, v.id)
  assert.equal(createHash('sha256').update(v.wire).digest('hex'), v.id)
  assert.deepEqual(Object.keys(JSON.parse(v.wire)).sort(), ['private', 'to', 'v'], 'nothing outside names the sender, nor a time')
  for (const identity of [seller.opening.identity, KEYS.accessKey.opening.identity]) {
    const opened = await openInbox(entry, identity)
    assert.equal(JSON.stringify(opened.message), v.message.wire)
  }
  await assert.rejects(openInbox(entry, buyer.opening.identity), 'not the sender’s own')
  const message = JSON.parse(v.message.wire)
  assert.deepEqual([message.from, message.to, message.host, message.body], [buyer.address, seller.address, 'https://host-b.example', { text: 'Is Tuesday at six free?' }])
  const input = hex.decode(v.message.signingInputHex)
  isWireWithoutSig(input, v.message.wire)
  assert.ok(zkChecks(input, message.from, message.sig))
})

test("the note sits at a random path and names, inside, the key it is about; it opens with tutoring/seller's open key alone", async () => {
  const { entry } = decodeEntry(pinned.note.wire)
  assert.equal(entry.path, `key/${IDS.note}`)
  assert.ok(!entry.path.includes(KEYS.accessKey.address))
  assert.deepEqual(await openLocked(entry.body!, seller.opening.identity), NOTE)
  assert.equal(NOTE.key, KEYS.accessKey.address)
  await assert.rejects(openLocked(entry.body!, KEYS.accessKey.opening.identity))
})

test("the Profiles folder is keys/'s pinned empty label's: its profile entry holds only hosts, and its label and stamp entries sit at random paths and open with its open key", async () => {
  const v = pinned.profilesFolder
  assert.equal(profilesFolder.label, '')
  assert.equal(v.profile, profilesFolder.address)
  assert.equal((await mainKey(SEED, '')).address, v.profile)
  for (const name of ['profileEntry', 'label', 'stamp'] as const) {
    const { entry, id } = decodeEntry(v[name].wire)
    assert.equal(id, v[name].id)
    assert.equal(createHash('sha256').update(hex.decode(v[name].signingInputHex)).digest('hex'), id)
    assert.ok(zkChecks(hex.decode(v[name].signingInputHex), v.profile, entry.sig), name)
  }
  assert.deepEqual(decodeEntry(v.profileEntry.wire).entry.body, { hosts: ['https://host-a.example'] })
  const label = decodeEntry(v.label.wire).entry
  assert.equal(label.path, `label/${IDS.label}`)
  assert.deepEqual(await openLocked(label.body!, profilesFolder.opening.identity), LABEL)
  await assert.rejects(openLocked(label.body!, seller.opening.identity))
  // The stamp, kept as text: the stamp its verifier signed, naming the verifier, and the fraction
  // the verifier added, which no entry's body could spell, there whole.
  const stamp = decodeEntry(v.stamp.wire).entry
  assert.equal(stamp.path, `stamp/${IDS.stamp}`)
  assert.deepEqual(await openLocked(stamp.body!, profilesFolder.opening.identity), { stamp: v.stamp.text })
  const back = stampFromJson(JSON.parse(v.stamp.text))
  assert.equal(stampSigned(back), true)
  assert.equal(back.verifierName, 'verifier-a.example')
  assert.equal(back.score, 0.97)
})
