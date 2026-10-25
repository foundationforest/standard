// A profile's rules: who may ask the person's signers to act as it, and for what. Each is a private
// record at rule/<id> in the profile's own folder, encrypted to its own inbox key alone; the id is
// keyed by the profile's rule key, so a path names no who.

import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { describe, test } from 'node:test'
import { hkdf as nobleHkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { inboxKey } from '@foundationforest/keys'
import { publish, readProfile } from '../src/client.ts'
import { ACTIONS, CURRENCIES, PERIODS, RULE_PREFIX, type Rule, knowsRule, makePrivate, openPrivate, readRules, readerCount, ruleId, ruleRecord } from '../src/private.ts'
import { type Body, RecordError, type SignedRecord, checkRecord } from '../src/record.ts'
import { viewProfile } from '../src/view.ts'
import { hostsRecord, nextTime, ownerRecord } from '../src/write.ts'
import { KEYS, T0, alice, aliceBuyer, bob } from './fixtures.ts'
import { startHost } from './helpers.ts'

const code = (c: string) => (err: unknown) => err instanceof RecordError && err.code === c
const [aliceInbox, aliceBuyerInbox] = await Promise.all([inboxKey(alice.secret), inboxKey(aliceBuyer.secret)])
const connector = 'https://connector.example'
/** An AI app's connection, through a connector: it may post, read and pay a little. */
const assistant: Rule = {
  who: { connector, connection: 'c-1', key: 'AAEC', name: 'My assistant' },
  can: ['post', 'read', 'pay'],
  limit: { amount: '25', currency: 'USD', per: 'day' },
  until: T0 + 30 * 86_400_000,
}
/** A person, by their profile: they may message as this profile, and pay $100 a week. */
const partner: Rule = { who: { profile: bob.address }, can: ['message', 'pay'], limit: { amount: '100', currency: 'USD', per: 'week' } }
const viewOf = (...records: SignedRecord[]) => viewProfile(alice.address, records.map(checkRecord), T0)
/** Anything, encrypted to one key, as a rule's body would be. */
const encrypted = (value: unknown, key: string) => makePrivate(value as Body, [key])

describe('rules', () => {
  test('the standard’s words: four actions, one currency, three periods of fixed length', () => {
    assert.deepEqual(ACTIONS, ['post', 'message', 'read', 'pay'])
    assert.deepEqual(CURRENCIES, ['USD'])
    assert.deepEqual(PERIODS, { day: 24 * 3_600_000, week: 7 * 24 * 3_600_000, month: 30 * 24 * 3_600_000 })
    assert.equal(RULE_PREFIX, 'rule/')
  })

  test('a rule sits at rule/<id> in the profile’s own folder, encrypted to its own inbox key alone', async () => {
    const record = await ruleRecord(alice, assistant, T0)
    assert.equal(record.profile, alice.address)
    assert.match(record.path, /^rule\/[0-9a-f]{32}$/)
    assert.equal(record.path, RULE_PREFIX + (await ruleId(alice, assistant.who)))
    assert.equal(readerCount(record.body as { private: string }), 1, 'encrypted to the profile alone')
    assert.deepEqual(await openPrivate(record.body!, aliceInbox.identity), assistant)
    await assert.rejects(openPrivate(record.body!, aliceBuyerInbox.identity), 'the person’s other profile opens nothing in it')
  })

  test('the id: HMAC-SHA256 under the profile’s rule key of who without key and name, recomputed by hand; one who has one path per profile, and no path names a who', async () => {
    const ruleKey = nobleHkdf(sha256, alice.secret, undefined, new TextEncoder().encode('forest/v1/rule'), 32)
    assert.equal(Buffer.from(ruleKey).toString('hex'), KEYS.mainKeys[0].ruleKey, "keys/'s pinned rule key")
    const byHand = createHmac('sha256', ruleKey).update(`{"connection":"c-1","connector":"${connector}"}`).digest('hex').slice(0, 32)
    assert.equal(await ruleId(alice, assistant.who), byHand)
    for (const who of [{ connector, connection: 'c-1' }, { connector, connection: 'c-1', name: 'Another name', key: 'BBBB' }]) {
      assert.equal(await ruleId(alice, who), byHand, 'the same who, whatever it is called and whatever its key')
    }
    const ids = new Set([
      byHand,
      await ruleId(aliceBuyer, assistant.who),
      await ruleId(alice, { connector: 'https://other.example', connection: 'c-1' }),
      await ruleId(alice, { connector, connection: 'c-2' }),
      await ruleId(alice, partner.who),
      await ruleId(aliceBuyer, partner.who),
    ])
    assert.equal(ids.size, 6, 'one who on two profiles, two paths: nothing in the folders links them')
  })

  test('through a host: written, read by another of the person’s devices, then removed by a null body, which that device sees on its next read', async () => {
    const host = await startHost({ now: () => T0 })
    try {
      const rules = [await ruleRecord(alice, assistant, T0), await ruleRecord(alice, partner, T0)]
      await publish([host.url], [hostsRecord(alice, [host.url], T0), ...rules])
      // Another device: only the seed, so the main key and its secret.
      const read = async () => readRules(await readProfile([host.url], alice.address, T0, { post: true }), alice)
      const found = await read()
      assert.deepEqual(found, new Map([[await ruleId(alice, assistant.who), assistant], [await ruleId(alice, partner.who), partner]]))
      assert.deepEqual([...found.values()].map(knowsRule), [true, true])
      const view = await readProfile([host.url], alice.address, T0, { post: true })
      const path = rules[0]!.path
      await publish([host.url], [ownerRecord(alice, path, null, nextTime(T0, view, path))])
      assert.deepEqual([...(await read()).values()], [partner], 'removed on one device, gone on the next read')
    } finally {
      await host.close()
    }
  })

  test('left out: a rule that does not open, one that does not check, and one at a path its who does not give', async () => {
    const id = await ruleId(alice, partner.who)
    const view = viewOf(
      await ruleRecord(alice, assistant, T0),
      ownerRecord(alice, RULE_PREFIX + id, await encrypted(partner, aliceBuyerInbox.encryptTo), T0),
      ownerRecord(alice, `${RULE_PREFIX}0123456789abcdef0123456789abcdef`, await encrypted(partner, aliceInbox.encryptTo), T0),
      ownerRecord(alice, RULE_PREFIX + (await ruleId(alice, { profile: aliceBuyer.address })), await encrypted({ who: { profile: aliceBuyer.address }, can: 'pay' }, aliceInbox.encryptTo), T0),
      ownerRecord(alice, 'offer/x', await encrypted(partner, aliceInbox.encryptTo), T0),
    )
    assert.deepEqual([...(await readRules(view, alice)).entries()], [[await ruleId(alice, assistant.who), assistant]])
  })

  test('a rule that can pay with no limit sets no cap, and a signer knows it whole', async () => {
    const { limit: _, ...uncapped } = assistant
    const record = await ruleRecord(alice, uncapped, T0)
    assert.deepEqual(await openPrivate(record.body!, aliceInbox.identity), uncapped)
    assert.equal(knowsRule(uncapped), true)
    assert.equal(knowsRule({ who: { profile: bob.address }, can: [] }), true)
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
      ['no period', { ...assistant, limit: { amount: '1', currency: 'USD' } }],
      ['until before 1970', { ...assistant, until: -1 }],
      ['until as text', { ...assistant, until: String(T0) }],
      ['a rule that is no object', 'post'],
    ]
    for (const [why, rule] of bad) await assert.rejects(ruleRecord(alice, rule as Rule, T0), code('rule'), why)
    await ruleRecord(alice, { ...assistant, limit: { amount: '0.000001', currency: 'USD', per: 'week' } }, T0)
  })

  test('unknown fields and values are kept, and a signer acts on no rule it does not know whole', async () => {
    const unknown: [string, unknown][] = [
      ['a field on the rule', { ...assistant, spend: 'any' }],
      ['a field on who', { ...assistant, who: { ...assistant.who, device: 'phone' } }],
      ['a field on the limit', { ...assistant, limit: { amount: '25', currency: 'USD', per: 'day', from: 'card' } }],
      ['an action outside the four', { ...partner, can: ['message', 'review'] }],
      ['a currency', { ...assistant, limit: { amount: '25', currency: 'EUR', per: 'day' } }],
      ['a period', { ...assistant, limit: { amount: '25', currency: 'USD', per: 'year' } }],
      ['an inherited name as a period', { ...assistant, limit: { amount: '25', currency: 'USD', per: 'toString' } }],
      ['a kind of who', { ...partner, who: { group: 'family' } }],
      ['limits, a list', { ...partner, limits: [{ amount: '25', currency: 'USD', per: 'day' }] }],
    ]
    for (const [why, rule] of unknown) {
      const record = await ruleRecord(alice, rule as Rule, T0)
      assert.deepEqual(await openPrivate(record.body!, aliceInbox.identity), rule, `${why}: kept`)
      assert.equal(knowsRule(rule as Rule), false, why)
    }
  })
})
