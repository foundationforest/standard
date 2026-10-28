// A profile's permissions: who may ask the person's signers to act as it, and for what. Each is a
// private record at permission/<id> in the profile's own folder, encrypted to its own inbox key
// alone; the id is keyed by the profile's permission key, so a path names no who. What each covers
// without the person's yes is allows'.

import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { describe, test } from 'node:test'
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { inboxKey } from '@foundationforest/keys'
import { type Body, RecordError, type SignedRecord, checkRecord, nextTime, ownerRecord, viewProfile } from '@foundationforest/records'
import { makePrivate, openPrivate, readerCount } from '@foundationforest/records/private'
import type { Ask } from '../src/asks.ts'
import { ACTIONS, PERIODS, PERMISSION_PREFIX, type Permission, allows, isOwnPath, knowsPermission, permissionId, permissionRecord, readPermissions } from '../src/permissions.ts'
import { DAY, KEYS, T0, alice, aliceBuyer, bob } from './fixtures.ts'

const code = (c: string) => (err: unknown) => err instanceof RecordError && err.code === c
const [aliceInbox, aliceBuyerInbox] = await Promise.all([inboxKey(alice.secret), inboxKey(aliceBuyer.secret)])
const connector = 'https://connector.example'
const USD = ['USD']
/** An AI app's connection, through a connector: it may write, read and pay a little. */
const assistant: Permission = {
  who: { connector, connection: 'c-1', key: 'AAEC', name: 'My assistant' },
  can: ['write', 'read', 'pay'],
  limit: { amount: '25', currency: 'USD', per: 'day' },
  until: T0 + 30 * DAY,
}
/** A person, by their profile: they may write as this profile, and pay $100 a week. */
const partner: Permission = { who: { profile: bob.address }, can: ['write', 'pay'], limit: { amount: '100', currency: 'USD', per: 'week' } }
const viewOf = (...records: SignedRecord[]) => viewProfile(alice.address, records.map(checkRecord), T0)
/** Anything, encrypted to one key, as a permission's body would be. */
const encrypted = (value: unknown, key: string) => makePrivate(value as Body, [key])

describe('permissions', () => {
  test('the standard’s words: three actions, three periods of fixed length', () => {
    assert.deepEqual(ACTIONS, ['read', 'write', 'pay'])
    assert.deepEqual(PERIODS, { day: 24 * 3_600_000, week: 7 * 24 * 3_600_000, month: 30 * 24 * 3_600_000 })
    assert.equal(PERMISSION_PREFIX, 'permission/')
  })

  test('a permission sits at permission/<id> in the profile’s own folder, encrypted to its own inbox key alone', async () => {
    const record = await permissionRecord(alice, assistant, T0)
    assert.equal(record.profile, alice.address)
    assert.match(record.path, /^permission\/[0-9a-f]{32}$/)
    assert.equal(record.path, PERMISSION_PREFIX + (await permissionId(alice, assistant.who)))
    assert.equal(readerCount(record.body as { private: string }), 1, 'encrypted to the profile alone')
    assert.deepEqual(await openPrivate(record.body!, aliceInbox.identity), assistant)
    await assert.rejects(openPrivate(record.body!, aliceBuyerInbox.identity), 'the person’s other profile opens nothing in it')
  })

  test('the id: HMAC-SHA256 under the profile’s permission key of who without key and name, recomputed by hand; one who has one path per profile, and no path names a who', async () => {
    const permissionKey = nobleHkdf(sha256, alice.secret, undefined, new TextEncoder().encode('forest/v1/permission'), 32)
    assert.equal(Buffer.from(permissionKey).toString('hex'), KEYS.mainKeys[0].permissionKey, "keys/'s pinned permission key")
    const byHand = createHmac('sha256', permissionKey).update(`{"connection":"c-1","connector":"${connector}"}`).digest('hex').slice(0, 32)
    assert.equal(await permissionId(alice, assistant.who), byHand)
    for (const who of [{ connector, connection: 'c-1' }, { connector, connection: 'c-1', name: 'Another name', key: 'BBBB' }]) {
      assert.equal(await permissionId(alice, who), byHand, 'the same who, whatever it is called and whatever its key')
    }
    const ids = new Set([
      byHand,
      await permissionId(aliceBuyer, assistant.who),
      await permissionId(alice, { connector: 'https://other.example', connection: 'c-1' }),
      await permissionId(alice, { connector, connection: 'c-2' }),
      await permissionId(alice, partner.who),
      await permissionId(aliceBuyer, partner.who),
    ])
    assert.equal(ids.size, 6, 'one who on two profiles, two paths: nothing in the folders links them')
  })

  test('written on one device, read on another from the folder, then removed by a null body, which the other device sees on its next read', async () => {
    const records = [await permissionRecord(alice, assistant, T0), await permissionRecord(alice, partner, T0)]
    // Another device: only the seed, so the main key and its secret, and what the hosts serve.
    const found = await readPermissions(viewOf(...records), alice)
    assert.deepEqual(found, new Map([[await permissionId(alice, assistant.who), assistant], [await permissionId(alice, partner.who), partner]]))
    assert.deepEqual([...found.values()].map((p) => knowsPermission(p, USD)), [true, true])
    const path = records[0]!.path
    const removed = ownerRecord(alice, path, null, nextTime(T0, viewOf(...records), path))
    assert.deepEqual([...(await readPermissions(viewOf(...records, removed), alice)).values()], [partner], 'removed on one device, gone on the next read')
  })

  test('left out: a permission that does not open, one that does not check, and one at a path its who does not give', async () => {
    const id = await permissionId(alice, partner.who)
    const view = viewOf(
      await permissionRecord(alice, assistant, T0),
      ownerRecord(alice, PERMISSION_PREFIX + id, await encrypted(partner, aliceBuyerInbox.encryptTo), T0),
      ownerRecord(alice, `${PERMISSION_PREFIX}0123456789abcdef0123456789abcdef`, await encrypted(partner, aliceInbox.encryptTo), T0),
      ownerRecord(alice, PERMISSION_PREFIX + (await permissionId(alice, { profile: aliceBuyer.address })), await encrypted({ who: { profile: aliceBuyer.address }, can: 'pay' }, aliceInbox.encryptTo), T0),
      ownerRecord(alice, 'offer/x', await encrypted(partner, aliceInbox.encryptTo), T0),
    )
    assert.deepEqual([...(await readPermissions(view, alice)).entries()], [[await permissionId(alice, assistant.who), assistant]])
  })

  test('a permission that can pay with no limit sets no cap; one that can do nothing is known whole, and every ask on it asks the person', async () => {
    const { limit: _, ...uncapped } = assistant
    assert.deepEqual(await openPrivate((await permissionRecord(alice, uncapped, T0)).body!, aliceInbox.identity), uncapped)
    assert.equal(knowsPermission(uncapped, []), true, 'no limit, no currency to know')
    const sees: Permission = { who: { connector, connection: 'c-1' }, can: [] }
    assert.equal(knowsPermission(sees, USD), true)
    for (const ask of [{ ask: 'read', label: 'tutoring/seller', path: 'offer/a' }, { ask: 'write', label: 'tutoring/seller', path: 'offer/a', body: null }, { ask: 'pay', label: 'tutoring/seller', to: bob.address, amount: '1', currency: 'USD' }] as Ask[]) {
      assert.equal(allows(sees, ask, { now: T0, currencies: USD }), false, ask.ask)
    }
    assert.equal(allows(sees, { ask: 'read' }, { now: T0, currencies: USD }), true, 'a read with nothing named needs no action')
  })

  test('refused: malformed fields, before anything is encrypted', async () => {
    const bad: [string, unknown][] = [
      ['who is no object', { ...partner, who: bob.address }],
      ['a connection and a profile in one who', { ...partner, who: { connector, connection: 'c-1', profile: bob.address } }],
      ['a connector that is no origin', { ...assistant, who: { connector: 'https://connector.example/mcp', connection: 'c-1' } }],
      ['a connector over http', { ...assistant, who: { connector: 'http://connector.example', connection: 'c-1' } }],
      ['a connection with no id', { ...assistant, who: { connector, connection: '' } }],
      ['a connection with no connector', { ...assistant, who: { connection: 'c-1' } }],
      ['a key that is no base64url', { ...assistant, who: { connector, connection: 'c-1', key: 'a+b/' } }],
      ['a name that is no text', { ...assistant, who: { connector, connection: 'c-1', name: 7 } }],
      ['a profile that is no address', { ...partner, who: { profile: 'not an address' } }],
      ['can is no list', { ...partner, can: 'pay' }],
      ['an action that is no text', { ...partner, can: [1] }],
      ['limit is no object', { ...partner, limit: [] }],
      ['an amount as a number', { ...assistant, limit: { amount: 25, currency: 'USD', per: 'day' } }],
      ['an amount with seven places', { ...assistant, limit: { amount: '0.0000001', currency: 'USD', per: 'day' } }],
      ['a negative amount', { ...assistant, limit: { amount: '-1', currency: 'USD', per: 'day' } }],
      ['an amount with a leading zero', { ...assistant, limit: { amount: '025', currency: 'USD', per: 'day' } }],
      ['a currency that is no text', { ...assistant, limit: { amount: '1', currency: 1, per: 'day' } }],
      ['an empty currency', { ...assistant, limit: { amount: '1', currency: '', per: 'day' } }],
      ['no period', { ...assistant, limit: { amount: '1', currency: 'USD' } }],
      ['until before 1970', { ...assistant, until: -1 }],
      ['until as text', { ...assistant, until: String(T0) }],
      ['a permission that is no object', 'write'],
    ]
    for (const [why, permission] of bad) await assert.rejects(permissionRecord(alice, permission as Permission, T0), code('permission'), why)
    await permissionRecord(alice, { ...assistant, limit: { amount: '0.000001', currency: 'USD', per: 'week' } }, T0)
  })

  test('unknown fields and values are kept, and an app acts on no permission it does not know whole', async () => {
    const unknown: [string, unknown][] = [
      ['a field on the permission', { ...assistant, spend: 'any' }],
      ['a field on who', { ...assistant, who: { ...assistant.who, device: 'phone' } }],
      ['a field on the limit', { ...assistant, limit: { amount: '25', currency: 'USD', per: 'day', from: 'card' } }],
      ['an action outside the three', { ...partner, can: ['write', 'review'] }],
      ['an action the standard once had', { ...partner, can: ['post'] }],
      ['a period', { ...assistant, limit: { amount: '25', currency: 'USD', per: 'year' } }],
      ['an inherited name as a period', { ...assistant, limit: { amount: '25', currency: 'USD', per: 'toString' } }],
      ['a kind of who', { ...partner, who: { group: 'family' } }],
      ['limits, a list', { ...partner, limits: [{ amount: '25', currency: 'USD', per: 'day' }] }],
    ]
    for (const [why, permission] of unknown) {
      const record = await permissionRecord(alice, permission as Permission, T0)
      assert.deepEqual(await openPrivate(record.body!, aliceInbox.identity), permission, `${why}: kept`)
      assert.equal(knowsPermission(permission as Permission, USD), false, why)
    }
  })

  test('a limit’s currency is any code: an app knows a permission whole only in a currency it pays in', async () => {
    const euros: Permission = { ...assistant, limit: { amount: '20', currency: 'EUR', per: 'day' } }
    await permissionRecord(alice, euros, T0)
    assert.equal(knowsPermission(euros, USD), false)
    assert.equal(knowsPermission(euros, ['USD', 'EUR']), true)
  })
})

describe('what a permission allows without the person’s yes', () => {
  const now = T0
  const label = 'tutoring/seller'
  const pay = (amount: string, currency = 'USD'): Ask => ({ ask: 'pay', label, to: bob.address, amount, currency })

  test('read and write as `can` says; a message is a write', () => {
    const reads: Permission = { ...assistant, can: ['read'] }
    assert.equal(allows(reads, { ask: 'read', label, path: 'offer/a' }, { now, currencies: USD }), true)
    assert.equal(allows(reads, { ask: 'read', label, inbox: true }, { now, currencies: USD }), true)
    assert.equal(allows(reads, { ask: 'write', label, path: 'offer/a', body: { about: 'x' } }, { now, currencies: USD }), false)
    assert.equal(allows(assistant, { ask: 'write', label, path: 'offer/a', body: null }, { now, currencies: USD }), true, 'a delete is a write')
    assert.equal(allows(assistant, { ask: 'write', label, to: bob.address, body: { text: 'hi' } }, { now, currencies: USD }), true)
    assert.equal(allows(reads, { ask: 'write', label, to: bob.address, body: { text: 'hi' } }, { now, currencies: USD }), false)
  })

  test('write never covers the profile record, the hosts record or a permission: those always ask the person', () => {
    for (const path of ['profile', 'hosts', 'permission/0123456789abcdef0123456789abcdef', 'permission/x']) {
      assert.equal(isOwnPath(path), true, path)
      assert.equal(allows(assistant, { ask: 'write', label, path, body: null }, { now, currencies: USD }), false, path)
    }
    for (const path of ['offer/a', 'review/1', 'profiles', 'hosts2']) assert.equal(isOwnPath(path), false, path)
  })

  test('pay within the limit, counted in its currency over its period; another currency is outside it; no limit, no cap', () => {
    assert.equal(allows(assistant, pay('25'), { now, currencies: USD }), true)
    assert.equal(allows(assistant, pay('25.000001'), { now, currencies: USD }), false)
    assert.equal(allows(assistant, pay('5'), { now, currencies: USD, spent: '20' }), true)
    assert.equal(allows(assistant, pay('5.5'), { now, currencies: USD, spent: '20' }), false)
    assert.equal(allows(assistant, pay('1', 'EUR'), { now, currencies: ['USD', 'EUR'] }), false, 'a payment in another currency than the limit’s')
    const { limit: _, ...uncapped } = assistant
    assert.equal(allows(uncapped, pay('1000000', 'EUR'), { now, currencies: USD }), true)
    assert.equal(allows({ ...assistant, can: ['read'] }, pay('1'), { now, currencies: USD }), false)
  })

  test('nothing once it has ended, and nothing on a permission an app does not know whole', () => {
    assert.equal(allows(assistant, pay('1'), { now: assistant.until!, currencies: USD }), true)
    assert.equal(allows(assistant, pay('1'), { now: assistant.until! + 1, currencies: USD }), false)
    assert.equal(allows(assistant, { ask: 'read' }, { now: assistant.until! + 1, currencies: USD }), false)
    assert.equal(allows({ ...assistant, can: ['read', 'post'] }, { ask: 'read', label, path: 'offer/a' }, { now, currencies: USD }), false)
    assert.equal(allows(assistant, pay('1'), { now, currencies: [] }), false, 'a limit in a currency the app does not pay in')
  })
})
