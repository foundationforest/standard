// The signers vectors: recomputed here, and each step checked with a second implementation:
// node:crypto (OpenSSL) for Ed25519 and HMAC-SHA256, and zk-kit's EdDSA-Poseidon for the record's
// signature by the profile's main key, from the address and the 64 bytes on its own.

import assert from 'node:assert/strict'
import { createHash, createHmac, createPrivateKey, createPublicKey, verify } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { unpackPublicKey, unpackSignature, verifySignature } from '@zk-kit/eddsa-poseidon'
import { b64u, base58, decodeRecord, hex } from '@foundationforest/records'
import { openPrivate } from '@foundationforest/records/private'
import { KEYS } from './fixtures.ts'
import { CHALLENGE, CONNECTOR, PERMISSION, REQUEST, vectors } from './vectors.ts'

const pinned = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'))
const bytesOf = (text: string) => new Uint8Array([0xff, ...new TextEncoder().encode(text)])

test('the vectors are what this implementation computes', async () => {
  assert.deepEqual(await vectors(), pinned)
})

test('the connection: Node’s Ed25519 gives the same id from the key, and checks the login and the registration over the bytes written out by hand', () => {
  const { connection, key } = pinned.connection
  const privateKey = createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d: key, x: connection }, format: 'jwk' })
  assert.equal(createPublicKey(privateKey).export({ format: 'jwk' }).x, connection)
  assert.deepEqual(b64u.decode(key), new Uint8Array(32).fill(0x2b))
  const publicKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: connection }, format: 'jwk' })
  const login = bytesOf(`forest/v1/login\n${REQUEST}`)
  assert.equal(pinned.login.signingInputHex, hex.encode(login))
  assert.equal(verify(null, login, publicKey, b64u.decode(pinned.login.sig)), true)
  const register = bytesOf(`forest/v1/register\n${CONNECTOR}\n${CHALLENGE}`)
  assert.equal(pinned.register.signingInputHex, hex.encode(register))
  assert.equal(verify(null, register, publicKey, b64u.decode(pinned.register.sig)), true)
})

test("the permission opens with tutoring/seller's pinned inbox key, encrypted to it alone, at a path whose id is HMAC-SHA256 under keys/'s pinned permission key, by node:crypto; the main key's signature holds by zk-kit's check", async () => {
  const { record, id } = decodeRecord(pinned.permission.wire)
  assert.equal(id, pinned.permission.id)
  assert.equal(record.profile, KEYS.mainKeys[0].address)
  assert.deepEqual(await openPrivate(record.body!, KEYS.mainKeys[0].inbox.identity), PERMISSION)
  const { connector, connection } = PERMISSION.who
  const byHand = createHmac('sha256', hex.decode(KEYS.mainKeys[0].permissionKey)).update(JSON.stringify({ connection, connector })).digest('hex').slice(0, 32)
  assert.equal(record.path, `permission/${byHand}`)
  const input = hex.decode(pinned.permission.signingInputHex)
  assert.equal(createHash('sha256').update(input).digest('hex'), id)
  const littleEndian = (bytes: Uint8Array) => bytes.reduceRight((n, b) => (n << 8n) | BigInt(b), 0n)
  const signed = BigInt('0x' + createHash('sha256').update(input).digest('hex')) >> 8n
  assert.equal(verifySignature(signed, unpackSignature(Buffer.from(b64u.decode(record.sig))), unpackPublicKey(littleEndian(base58.decode(record.profile)))), true)
})
