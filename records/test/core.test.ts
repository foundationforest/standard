// Keys, canonical text, records: the pieces every other part stands on.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { BN254_R, accessKey as makeAccessKey, packPoint, packSignature, signBytes } from '@foundationforest/keys'
import { b64u, base58 } from '../src/bytes.ts'
import { canonical, parseCanonical } from '../src/canonical.ts'
import { keyFromScalar, publicKeyFromAddress } from '../src/keys.ts'
import { RecordError, checkRecord, decodeRecord, encodeRecord, recordId, signRecord, signingInput, unsignedOf } from '../src/record.ts'
import { accessRecord, ownerRecord, permissionsRecord } from '../src/write.ts'
import { KEYS, T0, accessKey, alice, aliceBuyer, allow, offerBody, pastKey, profileBody, reader, sizedRecord, stranger } from './fixtures.ts'

/** The packed bytes of y, with x's sign bit as given, in base58: an address whatever point it names, or none. */
const packedY = (y: bigint, negative = false) => {
  const bytes = new Uint8Array(32)
  for (let i = 0, v = y; i < 32; i++, v >>= 8n) bytes[i] = Number(v & 0xffn)
  if (negative) bytes[31]! |= 0x80
  return base58.encode(bytes)
}

describe('keys', () => {
  test("main keys and access keys are keys/'s: its pinned profiles sign here, and a name is the packed key in base58", () => {
    assert.equal(alice.address, KEYS.mainKeys[0].address)
    assert.equal(aliceBuyer.address, KEYS.mainKeys[1].address)
    assert.equal(alice.address, base58.encode(packPoint(alice.publicKey)), 'the name is the packed key in base58')
    assert.deepEqual(keyFromScalar(alice.scalar), { scalar: alice.scalar, publicKey: alice.publicKey, address: alice.address })
    assert.equal(accessKey.address, KEYS.accessKeys.write.address)
    assert.equal(reader.address, KEYS.accessKeys.read.address)
    assert.equal(reader.sealTo, KEYS.accessKeys.read.sealTo)
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

  test('an owner record verifies, and its id is the hash of what was signed', () => {
    const { id } = checkRecord(record)
    assert.equal(id, recordId(unsignedOf(record)))
    const wire = encodeRecord(record)
    assert.equal(decodeRecord(wire).id, id)
    assert.ok(wire.startsWith('{"body":'))
  })

  test('a record by an access key verifies with that key, and names it in by', () => {
    const written = accessRecord(accessKey, alice.address, 'offer/physics', offerBody('40'), T0)
    assert.equal(checkRecord(written).record.by, accessKey.address)
    const { by: _by, ...asOwner } = written
    assert.throws(() => checkRecord(asOwner), (err: RecordError) => err.code === 'signature', 'without by it is not the owner’s')
  })

  test('any change to any field breaks the signature', () => {
    const changes: Array<{ [key: string]: unknown }> = [{ path: 'offer/other' }, { time: T0 + 1 }, { profile: aliceBuyer.address }, { body: offerBody('3') }, { body: null }, { by: accessKey.address }]
    for (const change of changes) {
      assert.throws(() => checkRecord({ ...record, ...change }), (err: RecordError) => err.code === 'signature', JSON.stringify(change))
    }
  })

  test('a key cannot sign as another profile, or as an access key it is not', () => {
    assert.throws(() => signRecord({ v: 1, profile: aliceBuyer.address, path: 'profile', time: T0, body: profileBody('x') }, alice), /not the one named to sign/)
    assert.throws(() => signRecord({ v: 1, profile: alice.address, path: 'profile', time: T0, body: profileBody('x'), by: accessKey.address }, alice), /not the one named to sign/)
    // Another key's signature under Alice's name, made by hand past signRecord's check: the record fails.
    const unsigned = { v: 1 as const, profile: alice.address, path: 'offer/x', time: T0, body: offerBody('1') }
    const posing = { ...unsigned, sig: b64u.encode(packSignature(signBytes(accessKey.scalar, signingInput(unsigned)))) }
    assert.throws(() => checkRecord(posing), (err: RecordError) => err.code === 'signature')
  })

  test('shape rules: unknown fields, paths, control records, access keys', () => {
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
    assert.throws(() => signRecord({ ...base, by: alice.address }, alice), code('shape'), 'the owner signs without by')
    assert.throws(() => accessRecord(accessKey, alice.address, 'permissions', { access: [] }, T0), code('control'), 'only the owner writes control records')
    assert.throws(() => accessRecord(accessKey, alice.address, 'hosts', null, T0), code('control'))
  })

  test('hosts and permissions bodies are exact: a field nobody knows refuses the record', () => {
    const hosts = (body: unknown) => () => ownerRecord(alice, 'hosts', body as never, T0)
    assert.throws(hosts({ urls: [] }), /1 to 8/)
    assert.throws(hosts({ urls: ['http://example.com'] }), /origin/)
    assert.throws(hosts({ urls: ['https://a.example/path'] }), /origin/)
    assert.throws(hosts({ urls: ['https://a.example', 'https://a.example'] }), /repeat/)
    assert.throws(hosts({ urls: ['https://a.example'], keep: 30 }), /unknown hosts field keep/)
    assert.ok(checkRecord(ownerRecord(alice, 'hosts', { urls: ['https://a.example', 'http://127.0.0.1:8080'] }, T0)))

    const perms = (access: unknown[]) => () => permissionsRecord(alice, access as never, T0)
    const sealTo = reader.sealTo
    assert.throws(perms([{ ...allow(accessKey, ['offer']), pay: 5 }]), /unknown access field pay/)
    assert.throws(perms([{ ...allow(accessKey, ['offer']), until: T0 }]), /only a past key does/, 'no date on a key that acts')
    assert.throws(perms([allow(accessKey, ['hosts'])]), /content path/)
    assert.throws(perms([allow(accessKey, ['permissions'])]), /content path/)
    assert.throws(perms([{ key: `did:key:z${accessKey.address}`, scope: 'write', paths: ['offer'] }]), /usable/)
    assert.throws(perms([{ key: accessKey.address, paths: ['offer'] }]), /scope is one of/)
    assert.throws(perms([{ key: accessKey.address, scope: 'admin' }]), /scope is one of/)
    assert.throws(perms([{ key: accessKey.address, scope: 'message' }]), /scope is one of write, read;/, 'no message scope: a write key sends')
    assert.throws(perms([{ key: accessKey.address, scope: 'pay' }]), /scope is one of write, read;/, 'there is no pay scope')
    assert.throws(perms([{ key: reader.address, scope: 'read' }]), /read key gives sealTo/, 'a read key gives both halves')
    assert.throws(perms([{ key: sealTo, sealTo, scope: 'read' }]), /usable/, 'its key is an address')
    assert.throws(perms([{ key: reader.address, sealTo: alice.address, scope: 'read' }]), /read key gives sealTo/)
    assert.throws(perms([{ key: accessKey.address, sealTo, scope: 'write' }]), /only a read key gives sealTo/)
    assert.throws(perms([{ key: accessKey.address, scope: 'past' }]), /scope is one of/, 'a past key has was, not a scope')
    for (const was of ['read', 'message', 'pay', 'past']) assert.throws(perms([{ key: accessKey.address, was }]), /a past key has was, write, in its place/, `was ${was}`)
    assert.throws(perms([{ key: accessKey.address, scope: 'write', was: 'write' }]), /a past key has was/, 'one or the other')
    assert.throws(perms([{ key: accessKey.address, was: 'write' }]), /a past key gives until/, 'a past key gives the time it was removed')
    for (const until of ['1', null]) assert.throws(perms([{ key: accessKey.address, was: 'write', until }]), /a past key gives until/, `until ${until}`)
    assert.ok(checkRecord(permissionsRecord(alice, [allow(reader, ['note', 'inbox'], 'read')], T0)), 'a read key may list paths')
    assert.ok(checkRecord(permissionsRecord(alice, [allow(accessKey), pastKey(stranger, T0, ['offer']), allow(reader, undefined, 'read')], T0)), 'paths are optional')
    assert.throws(perms([allow(accessKey), pastKey(accessKey, T0, ['offer'])]), /listed twice/, 'one key, one entry')
    assert.throws(perms([allow(reader, undefined, 'read'), allow(reader, ['note'], 'read')]), /listed twice/)
    assert.throws(perms([allow(reader, undefined, 'read'), { key: stranger.address, sealTo, scope: 'read' }]), /listed twice/, 'one sealTo, one entry')
    const many = Array.from({ length: 100 }, (_, i) => ({ key: makeAccessKey(new Uint8Array(32).fill(i + 1)).address, was: 'write' as const, until: T0 }))
    assert.ok(checkRecord(permissionsRecord(alice, many, T0)), 'no cap on how many keys it lists')
    assert.throws(() => ownerRecord(alice, 'permissions', { access: [], more: 1 }, T0), /unknown permissions field/)
    assert.throws(() => ownerRecord(alice, 'permissions', { access: [], notes: 'YWdlLWVuY3J5cHRpb24' }, T0), /unknown permissions field notes/, 'no notes in v1')
    assert.ok(checkRecord(permissionsRecord(alice, [allow(accessKey, ['offer', 'review', 'inbox'])], T0)))
    assert.ok(checkRecord(permissionsRecord(alice, null, T0)), 'a delete removes every access key')
  })

  test('no size is a rule: how large a record to take is each host’s own choice (host.test.ts), and each reader’s', () => {
    const big = ownerRecord(alice, 'profile', { about: 'x'.repeat(200_000) }, T0)
    assert.ok(decodeRecord(encodeRecord(big)).id)
    assert.ok(checkRecord(sizedRecord(alice, 'note/a', 100_000, 1)).id)
  })
})
