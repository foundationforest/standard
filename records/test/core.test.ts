// Keys, canonical text, records: the pieces every other part stands on.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { BN254_R, packPoint, packSignature, signBytes } from '@foundationforest/keys'
import { b64u, base58 } from '../src/bytes.ts'
import { canonical, parseCanonical } from '../src/canonical.ts'
import { keyFromScalar, publicKeyFromAddress } from '../src/keys.ts'
import { RecordError, checkRecord, decodeRecord, encodeRecord, recordId, signRecord, signingInput, unsignedOf } from '../src/record.ts'
import { ownerRecord } from '../src/write.ts'
import { KEYS, T0, alice, aliceBuyer, offerBody, profileBody, sizedRecord, stranger } from './fixtures.ts'

/** The packed bytes of y, with x's sign bit as given, in base58: an address whatever point it names, or none. */
const packedY = (y: bigint, negative = false) => {
  const bytes = new Uint8Array(32)
  for (let i = 0, v = y; i < 32; i++, v >>= 8n) bytes[i] = Number(v & 0xffn)
  if (negative) bytes[31]! |= 0x80
  return base58.encode(bytes)
}

describe('keys', () => {
  test("main keys are keys/'s: its pinned profiles sign here, and a name is the packed key in base58", () => {
    assert.equal(alice.address, KEYS.mainKeys[0].address)
    assert.equal(aliceBuyer.address, KEYS.mainKeys[1].address)
    assert.equal(alice.address, base58.encode(packPoint(alice.publicKey)), 'the name is the packed key in base58')
    assert.deepEqual(keyFromScalar(alice.scalar), { scalar: alice.scalar, publicKey: alice.publicKey, address: alice.address })
  })

  test('an address has one spelling and names a usable key', () => {
    assert.deepEqual(publicKeyFromAddress(alice.address), alice.publicKey)
    assert.equal(publicKeyFromAddress(alice.address + '1'), null)
    assert.equal(publicKeyFromAddress('1' + alice.address), null, 'a leading 1 is a leading zero byte: 33 bytes')
    assert.equal(publicKeyFromAddress(alice.address.replace(/.$/, '0')), null, 'not base58')
    assert.equal(publicKeyFromAddress(`did:key:z${alice.address}`), null)
    // The identity point, a point of order 2 and of order 4, and y past the field are refused as names.
    assert.equal(publicKeyFromAddress(packedY(1n)), null, 'the identity')
    assert.equal(publicKeyFromAddress(packedY(BN254_R - 1n)), null, 'order 2: (0, -1)')
    assert.equal(publicKeyFromAddress(packedY(0n)), null, 'order 4: (±sqrt(1/a), 0)')
    assert.equal(publicKeyFromAddress(packedY(BN254_R + 1n)), null, 'y past the field: the identity in a second spelling')
    assert.equal(publicKeyFromAddress(packedY(1n, true)), null, 'x = 0 with the sign bit set')
  })
})

describe('canonical text', () => {
  test('sorts keys, no whitespace, round-trips', () => {
    const text = canonical({ b: 1, a: [true, null, 'x'], c: { z: 'é', y: 2 } })
    assert.equal(text, '{"a":[true,null,"x"],"b":1,"c":{"y":2,"z":"é"}}')
    assert.deepEqual(parseCanonical(text), { a: [true, null, 'x'], b: 1, c: { y: 2, z: 'é' } })
  })

  test('refuses what could read two ways', () => {
    for (const text of [
      '{"a":1,"a":2}', // duplicate key
      '{"b":1,"a":2}', // key order
      '{"a": 1}', // whitespace
      '{"a":1.0}', // another number spelling
      '{"a":"\\u0041"}', // another escape
    ]) {
      assert.throws(() => parseCanonical(text), /canonical|JSON/, text)
    }
    assert.throws(() => canonical({ a: 1.5 }), /whole/)
    assert.throws(() => canonical({ a: 2 ** 53 }), /whole/)
    assert.throws(() => canonical({ a: '\ud800' }), /surrogate/)
    assert.throws(() => canonical({ __proto__x: 1 }), /key/)
    assert.throws(() => canonical({ Ab: 1 }), /key/)
    assert.throws(() => canonical(JSON.parse('{"__proto__":1}')), /key/)
    let deep: unknown = 'x'
    for (let i = 0; i < 20; i++) deep = { a: deep }
    assert.throws(() => canonical(deep), /deep/)
  })
})

describe('records', () => {
  const record = ownerRecord(alice, 'offer/maths', offerBody('30'), T0)

  test('an owner record checks, and its id is the hash of what was signed', () => {
    const { id } = checkRecord(record)
    assert.equal(id, recordId(unsignedOf(record)))
    const wire = encodeRecord(record)
    assert.equal(decodeRecord(wire).id, id)
    assert.ok(wire.startsWith('{"body":'))
  })

  test('any change to any field breaks the signature', () => {
    const changes: Array<{ [key: string]: unknown }> = [{ path: 'offer/other' }, { time: T0 + 1 }, { profile: aliceBuyer.address }, { body: offerBody('3') }, { body: null }]
    for (const change of changes) {
      assert.throws(() => checkRecord({ ...record, ...change }), (err: RecordError) => err.code === 'signature', JSON.stringify(change))
    }
  })

  test('a key cannot sign as another profile: a record signed by a key that is not the main key is refused [signature]', () => {
    assert.throws(() => signRecord({ v: 1, profile: aliceBuyer.address, path: 'profile', time: T0, body: profileBody('x') }, alice), /not the one named to sign/)
    assert.throws(() => signRecord({ v: 1, profile: alice.address, path: 'profile', time: T0, body: profileBody('x') }, stranger), /not the one named to sign/)
    // Another key's signature under Alice's name, made by hand past signRecord's check: the record fails.
    const unsigned = { v: 1 as const, profile: alice.address, path: 'offer/x', time: T0, body: offerBody('1') }
    const posing = { ...unsigned, sig: b64u.encode(packSignature(signBytes(stranger.scalar, signingInput(unsigned)))) }
    assert.throws(() => checkRecord(posing), (err: RecordError) => err.code === 'signature')
    // Naming the other key beside the record is no way in: there is no field for it.
    assert.throws(() => checkRecord({ ...posing, by: stranger.address }), (err: RecordError) => err.code === 'shape')
  })

  test('shape rules: unknown fields, paths, the control record', () => {
    const base = { v: 1 as const, profile: alice.address, path: 'profile', time: T0, body: profileBody('maths') }
    const code = (c: string) => (err: RecordError) => err.code === c
    assert.throws(() => signRecord({ ...base, extra: 1 } as never, alice), code('shape'))
    assert.throws(() => signRecord({ ...base, grant: 'a'.repeat(64) } as never, alice), code('shape'), 'grants are gone')
    assert.throws(() => signRecord({ ...base, v: 2 } as never, alice), code('version'))
    assert.throws(() => signRecord({ ...base, path: 'Offer/x' }, alice), code('path'))
    assert.throws(() => signRecord({ ...base, path: 'offer/../x' }, alice), code('path'))
    assert.throws(() => signRecord({ ...base, path: 'a/b/c/d/e' }, alice), code('path'))
    assert.throws(() => signRecord({ ...base, path: 'hosts/x' }, alice), code('path'))
    assert.throws(() => signRecord({ ...base, time: -1 }, alice), code('time'))
    assert.throws(() => signRecord({ ...base, body: [] as never }, alice), code('body'))
    assert.throws(() => signRecord({ ...base, by: alice.address } as never, alice), code('shape'), 'no by: only the main key signs')
    assert.ok(checkRecord(ownerRecord(alice, 'permissions', { anything: ['at', 1] }, T0)), 'permissions is a content path like any other')
    assert.ok(checkRecord(ownerRecord(alice, 'permissions/x', null, T0)))
  })

  test('a hosts body is exact: a field nobody knows refuses the record', () => {
    const hosts = (body: unknown) => () => ownerRecord(alice, 'hosts', body as never, T0)
    assert.throws(hosts({ urls: [] }), /1 to 8/)
    assert.throws(hosts({ urls: ['http://example.com'] }), /origin/)
    assert.throws(hosts({ urls: ['https://a.example/path'] }), /origin/)
    assert.throws(hosts({ urls: ['https://a.example', 'https://a.example'] }), /repeat/)
    assert.throws(hosts({ urls: ['https://a.example'], keep: 30 }), /unknown hosts field keep/)
    assert.ok(checkRecord(ownerRecord(alice, 'hosts', { urls: ['https://a.example', 'http://127.0.0.1:8080'] }, T0)))
    assert.ok(checkRecord(ownerRecord(alice, 'hosts', null, T0)), 'a delete leaves no hosts')
  })

  test('no size is a rule: how large a record to take is each host’s own choice (host.test.ts), and each reader’s', () => {
    const big = ownerRecord(alice, 'profile', { about: 'x'.repeat(200_000) }, T0)
    assert.ok(decodeRecord(encodeRecord(big)).id)
    assert.ok(checkRecord(sizedRecord(alice, 'stamp/a', 100_000, 1)).id)
  })
})
