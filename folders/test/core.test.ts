// Keys, canonical text, entries, profile entries, files: the pieces every other part stands on.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { BN254_R, accessKey, packPoint, packSignature, signBytes } from '@foundationforest/keys'
import { b64u, base58 } from '../src/bytes.ts'
import { canonical, parseCanonical } from '../src/canonical.ts'
import { keyFromScalar, publicKeyFromAddress } from '../src/keys.ts'
import { checkEntry, decodeEntry, encodeEntry, entryId, signEntry, signingInput, unsignedOf } from '../src/entry.ts'
import type { FolderError } from '../src/fail.ts'
import { fileOf } from '../src/files.ts'
import { canDo, checkProfileBody, hostsOf, inboxLockKeysOf, keysOf, lockKeysOf, openKeyOf } from '../src/profile.ts'
import { entry } from '../src/write.ts'
import { KEYS, T0, access, aliceOpening, alice, aliceBuyer, asAccess, listed, offerBody, profileBody, sizedEntry, stranger } from './fixtures.ts'

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

const code = (c: string) => (err: FolderError) => err.code === c
/** A second access key, from 32 bytes of 0x2c. */
const other = await accessKey(new Uint8Array(64).fill(0x2c))

describe('entries', () => {
  const offer = entry(alice, 'offer/maths', offerBody('30'), T0)

  test('a main-key entry checks, carries no key, and its id is the hash of what was signed', () => {
    const { id } = checkEntry(offer)
    assert.equal('key' in offer, false)
    assert.equal(id, entryId(unsignedOf(offer)))
    const wire = encodeEntry(offer)
    assert.equal(decodeEntry(wire).id, id)
    assert.ok(wire.startsWith('{"body":'))
  })

  test('an access key’s entry names it in key, and its signature is that key’s', () => {
    const byKey = entry(asAccess, 'offer/physics', offerBody('35'), T0)
    assert.equal(byKey.key, access.address)
    assert.equal(byKey.profile, alice.address)
    assert.ok(checkEntry(byKey))
    // The same entry with key taken away is the main key's to sign: refused [signature].
    const { key: _key, ...asMain } = byKey
    assert.throws(() => checkEntry(asMain), code('signature'))
    assert.throws(() => checkEntry({ ...byKey, key: stranger.address }), code('signature'), 'another key named')
  })

  test('any change to any field breaks the signature', () => {
    const changes: Array<{ [key: string]: unknown }> = [{ path: 'offer/other' }, { time: T0 + 1 }, { profile: aliceBuyer.address }, { body: offerBody('3') }, { body: null }, { key: access.address }]
    for (const change of changes) assert.throws(() => checkEntry({ ...offer, ...change }), code('signature'), JSON.stringify(change))
  })

  test('a key signs only as itself: signEntry refuses another, and a forged signature is refused [signature]', () => {
    assert.throws(() => signEntry({ v: 1, profile: aliceBuyer.address, path: 'offer/x', time: T0, body: offerBody('x') }, alice), /not the one named to sign/)
    assert.throws(() => signEntry({ v: 1, profile: alice.address, path: 'offer/x', time: T0, body: offerBody('x'), key: access.address }, alice), /not the one named to sign/)
    const unsigned = { v: 1 as const, profile: alice.address, path: 'offer/x', time: T0, body: offerBody('1') }
    const posing = { ...unsigned, sig: b64u.encode(packSignature(signBytes(stranger.scalar, signingInput(unsigned)))) }
    assert.throws(() => checkEntry(posing), code('signature'))
  })

  test('no access key writes the profile entry [unlisted], and key is never the main key’s own address [key]', () => {
    assert.throws(() => entry(asAccess, 'profile', profileBody('x'), T0), code('unlisted'))
    assert.throws(() => signEntry({ v: 1, profile: alice.address, path: 'offer/x', time: T0, body: null, key: alice.address }, alice), code('key'))
  })

  test('shape rules: unknown fields, paths, the profile path', () => {
    const base = { v: 1 as const, profile: alice.address, path: 'offer/x', time: T0, body: offerBody('maths') }
    assert.throws(() => signEntry({ ...base, extra: 1 } as never, alice), code('shape'))
    assert.throws(() => signEntry({ ...base, v: 2 } as never, alice), code('version'))
    assert.throws(() => signEntry({ ...base, path: 'Offer/x' }, alice), code('path'))
    assert.throws(() => signEntry({ ...base, path: 'offer/../x' }, alice), code('path'))
    assert.throws(() => signEntry({ ...base, path: 'a/b/c/d/e' }, alice), code('path'))
    assert.throws(() => signEntry({ ...base, path: 'profile/x' }, alice), code('path'), 'profile is a single path')
    assert.throws(() => signEntry({ ...base, time: -1 }, alice), code('time'))
    assert.throws(() => signEntry({ ...base, body: [] as never }, alice), code('body'))
    assert.throws(() => signEntry({ ...base, key: 'x' }, alice), code('key'))
    assert.ok(checkEntry(entry(alice, 'key/0123456789abcdef0123456789abcdef', { private: 'YWdl' }, T0)), 'a note is a path like any other')
    assert.ok(checkEntry(entry(alice, 'offer/x', null, T0)))
  })

  test('no size is a rule: how large an entry to take is each host’s own choice, and each reader’s', () => {
    const big = entry(alice, 'offer/big', { about: 'x'.repeat(200_000) }, T0)
    assert.ok(decodeEntry(encodeEntry(big)).id)
    assert.ok(checkEntry(sizedEntry(alice, 'stamp/a', 100_000, 1)).id)
  })
})

describe('the profile entry', () => {
  const check = (body: unknown) => () => checkProfileBody(body as never)
  test('hosts: 1 to 8 distinct origins, required', () => {
    assert.throws(check({ market: 'tutoring', role: 'seller' }), /hosts is 1 to 8/)
    assert.throws(check({ hosts: [] }), /hosts is 1 to 8/)
    assert.throws(check({ hosts: Array.from({ length: 9 }, (_, i) => `https://h${i}.example`) }), /hosts is 1 to 8/)
    assert.throws(check({ hosts: ['http://example.com'] }), /origin/)
    assert.throws(check({ hosts: ['https://a.example/path'] }), /origin/)
    assert.throws(check({ hosts: ['https://a.example', 'https://a.example'] }), /repeat/)
    check({ hosts: ['https://a.example', 'http://127.0.0.1:8080'] })()
    assert.throws(() => entry(alice, 'profile', { market: 'tutoring', role: 'seller' }, T0), code('profile'), 'a profile entry with no hosts is refused')
    assert.ok(checkEntry(entry(alice, 'profile', null, T0)), 'a delete leaves no hosts')
    assert.deepEqual(hostsOf(profileBody('x', { hosts: ['https://b.example'] })), ['https://b.example'])
    assert.deepEqual(hostsOf(null), [])
  })

  test('openKey: an open key, or none', () => {
    assert.throws(check({ hosts: ['https://a.example'], openKey: 'age1pq1' + 'q'.repeat(60) }), /openKey/)
    assert.throws(check({ hosts: ['https://a.example'], openKey: alice.address }), /openKey/)
    assert.equal(openKeyOf(profileBody('x')), aliceOpening.openKey)
    assert.equal(openKeyOf(profileBody('x', { openKey: null })), null)
  })

  test('keys: each listed once, with what it can do, and its open key whenever it can read', () => {
    const hosts = ['https://a.example']
    check({ hosts, keys: [listed(['write']), listed(['read', 'message'], other)] })()
    assert.throws(check({ hosts, keys: {} }), /keys is a list/)
    assert.throws(check({ hosts, keys: [{ key: 'x', can: [] }] }), /address/)
    assert.throws(check({ hosts, keys: [listed(['write']), listed(['message'])] }), /listed once/)
    assert.throws(check({ hosts, keys: [{ key: access.address, can: 'write' }] }), /can is a list/)
    assert.throws(check({ hosts, keys: [{ key: access.address, can: ['read'] }] }), /gives its open key/)
    assert.throws(check({ hosts, keys: [{ key: access.address, can: ['read-inbox'] }] }), /gives its open key/)
    assert.throws(check({ hosts, keys: [{ key: access.address, open: 'x', can: ['write'] }] }), /open is an open key/)
    check({ hosts, keys: [{ key: access.address, open: access.openKey, can: ['write'] }] })()
  })

  test('a can this code does not know grants nothing, and a listed key with a field it does not know counts for nothing; neither refuses the profile entry', () => {
    const body = profileBody('x', { keys: [{ ...listed(['write', 'pay']) }, { key: stranger.address, can: ['write'], until: 5 }] })
    assert.ok(checkEntry(entry(alice, 'profile', body, T0)), 'the profile entry is taken')
    assert.deepEqual(keysOf(body).map((k) => k.key), [access.address], 'the key with a field nobody defined counts for nothing')
    assert.equal(canDo(body, access.address, 'write'), true)
    assert.equal(canDo(body, stranger.address, 'write'), false)
    assert.equal(canDo(body, access.address, 'pay' as never), true, 'kept as written, and nothing reads it')
  })

  test('what a locked entry and an inbox entry are locked to: the main key’s open key, then each listed key’s that can read, or read-inbox', () => {
    const third = { key: stranger.address, can: ['write'] }
    const body = profileBody('x', { keys: [listed(['read']), listed(['read-inbox', 'write'], other), third] })
    assert.deepEqual(lockKeysOf(body), [aliceOpening.openKey, access.openKey])
    assert.deepEqual(inboxLockKeysOf(body), [aliceOpening.openKey, other.openKey])
    assert.throws(() => lockKeysOf(profileBody('x', { openKey: null })), code('locked'))
    assert.throws(() => inboxLockKeysOf(profileBody('x', { openKey: null })), code('no_inbox'))
  })
})

describe('files', () => {
  test('a body’s files: each { sha256, type, size } and nothing else', () => {
    const name = fileOf(new Uint8Array([1, 2, 3]), 'image/png')
    assert.ok(checkEntry(entry(alice, 'photo/one', { files: [name] }, T0)))
    for (const bad of [{}, [{ ...name, width: 3 }], [{ ...name, sha256: name.sha256.toUpperCase() }], [{ ...name, type: 'Image/PNG' }], [{ ...name, size: -1 }], ['x']]) {
      assert.throws(() => entry(alice, 'photo/one', { files: bad as never }, T0), code('files'), JSON.stringify(bad))
    }
    assert.throws(() => fileOf(new Uint8Array(1), 'image'), code('files'))
  })
})
