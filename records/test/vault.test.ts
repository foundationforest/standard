// The vault: what a person's devices keep, encrypted on a host in a folder of its own; and a new
// device that has nothing but the seed and one host's address getting all of it back.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { inboxKey, mainKey, seedScalar, vaultKey } from '@foundationforest/keys'
import { fieldHash, signStamp, stampNumberOf, stampToJson } from '@foundationforest/stamp'
import { publish, readProfile } from '../src/client.ts'
import { ACTIONS, CURRENCIES, PERIODS, type Permission, type Vault, VAULT_PATH, checkVault, knowsPermission, openVault, readVault, readerCount, vaultRecord } from '../src/private.ts'
import { RecordError } from '../src/record.ts'
import { hostsRecord, ownerRecord } from '../src/write.ts'
import { KEYS, MINUTE, SEED, T0, bob, offerBody, profileBody } from './fixtures.ts'
import { startHost } from './helpers.ts'

const vault = await vaultKey(SEED)
const vaultInbox = await inboxKey(vault.secret)
const code = (c: string) => (err: unknown) => err instanceof RecordError && err.code === c
// A stamp an example verifier signed for keys/'s test person, as proofs/stamp/client's stampToJson
// writes it.
const stamp = stampToJson(
  signStamp(new Uint8Array(32).fill(0x31), {
    stampNumber: stampNumberOf(await seedScalar(SEED), 'issuer-a.example'),
    facts: fieldHash('forest example attributes', 'issuer-a'),
  }),
)

describe('the vault', () => {
  test('its folder is the vault key’s, no profile’s; only the vault’s inbox key opens it', async () => {
    assert.equal(vault.address, KEYS.vault.address)
    for (const p of KEYS.mainKeys) assert.notEqual(vault.address, p.address)
    const record = await vaultRecord(vault, vaultInbox.encryptTo, { settings: { theme: 'dark' } }, T0)
    assert.equal(record.path, VAULT_PATH)
    assert.equal(record.profile, vault.address)
    assert.equal(readerCount(record.body as { private: string }), 1, 'encrypted to the vault alone')
    assert.deepEqual(await openVault(record.body!, vaultInbox.identity), { settings: { theme: 'dark' } })
    const seller = await inboxKey((await mainKey(SEED, 'tutoring/seller')).secret)
    await assert.rejects(openVault(record.body!, seller.identity), 'a profile’s inbox key opens nothing in it')
  })

  test('every field may be missing, and an app keeps the fields it does not know, at the top and in settings', async () => {
    const contents = { tickets: [{ for: 'later' }], settings: { theme: 'dark', anotherApp: { a: 1 } } }
    const record = await vaultRecord(vault, vaultInbox.encryptTo, contents as Vault, T0)
    assert.deepEqual(await openVault(record.body!, vaultInbox.identity), contents)
    checkVault({})
  })

  test('a bad entry is refused, before it is encrypted and after it is opened', async () => {
    checkVault({ profiles: [{ label: 'tutoring/seller', hosts: ['https://a.example'] }], stamps: [{ verifier: 'issuer-a.example', stamp }], settings: {} })
    const bad: [string, unknown][] = [
      ['an array', []],
      ['profiles is a list', { profiles: {} }],
      ['a label twice', { profiles: [{ label: 'a', hosts: ['https://a.example'] }, { label: 'a', hosts: ['https://b.example'] }] }],
      ['no hosts', { profiles: [{ label: 'a', hosts: [] }] }],
      ['a host that is no origin', { profiles: [{ label: 'a', hosts: ['https://a.example/path'] }] }],
      ['a host twice', { profiles: [{ label: 'a', hosts: ['https://a.example', 'https://a.example'] }] }],
      ['a profile field nobody knows', { profiles: [{ label: 'a', hosts: ['https://a.example'], since: 1 }] }],
      ['a verifier stamp with no verifier', { stamps: [{ verifier: '', stamp }] }],
      ['a stamp that is no object', { stamps: [{ verifier: 'issuer-a.example', stamp: 'x' }] }],
      ['settings is an object', { settings: [] }],
    ]
    for (const [why, v] of bad) assert.throws(() => checkVault(v), code('vault'), why)
    await assert.rejects(vaultRecord(vault, vaultInbox.encryptTo, { settings: [] } as never, T0), code('vault'))
  })

  test('a full restore: a new device with only the seed and one host gets every profile, stamp and setting back', async () => {
    const now = () => T0 + MINUTE
    const [a, b, c] = await Promise.all([startHost({ now }), startHost({ now }), startHost({ now })])
    try {
      // The person: two profiles, each on a host of its own.
      const seller = await mainKey(SEED, 'tutoring/seller')
      const buyer = await mainKey(SEED, 'tutoring/buyer')
      const sellerInbox = await inboxKey(seller.secret)
      const sellerProfile = { ...profileBody('maths'), inboxKey: sellerInbox.encryptTo, inbox: { senders: 'anyone' } }
      await publish([a.url], [hostsRecord(seller, [a.url], T0), ownerRecord(seller, 'profile', sellerProfile, T0), ownerRecord(seller, 'offer/maths', offerBody('30'), T0)])
      await publish([b.url], [hostsRecord(buyer, [b.url], T0), ownerRecord(buyer, 'profile', { ...profileBody('maths'), role: 'buyer' }, T0)])

      // The first device keeps the rest in the vault, on a third host.
      const kept: Vault = {
        profiles: [{ label: 'tutoring/seller', hosts: [a.url] }, { label: 'tutoring/buyer', hosts: [b.url] }],
        stamps: [{ verifier: 'issuer-a.example', stamp }],
        bookmarks: [{ url: 'https://shop.example', since: T0 }],
        settings: { indexes: ['https://index.example'], theme: 'dark' },
      }
      await publish([c.url], [hostsRecord(vault, [c.url], T0), await vaultRecord(vault, vaultInbox.encryptTo, kept, T0)])
      const disk = c.dump().join('\n')
      for (const secret of ['tutoring/seller', 'issuer-a.example', 'index.example', stamp.stampNumber]) assert.ok(!disk.includes(secret), `the host holds no ${secret}`)

      // The new device: the seed, and one host's address. Nothing else.
      const v2 = await vaultKey(SEED)
      const found = await readVault([c.url], { address: v2.address, identity: (await inboxKey(v2.secret)).identity }, now())
      assert.ok(found)
      assert.deepEqual(found.vault, kept)
      assert.deepEqual(found.hosts, [c.url])
      assert.equal(found.time, T0)
      for (const p of found.vault.profiles!) {
        const view = await readProfile(p.hosts, (await mainKey(SEED, p.label)).address, now(), { post: true })
        assert.deepEqual(view.current.get('profile')?.record.body?.subjects, ['maths'], p.label)
      }
      assert.ok((await readProfile([a.url], seller.address, now())).current.has('offer/maths'), 'the offers come back from their hosts')
      assert.deepEqual(found.vault.stamps, [{ verifier: 'issuer-a.example', stamp }])
      assert.deepEqual(found.vault.bookmarks, [{ url: 'https://shop.example', since: T0 }], 'a field an app added comes back as it was')

      // A later write, from either device, after the one read: the newer vault counts.
      const later = { ...found.vault, settings: { ...found.vault.settings, theme: 'light' } }
      await publish([c.url], [await vaultRecord(v2, vaultInbox.encryptTo, later, Math.max(now(), found.time + 1))])
      assert.deepEqual((await readVault([c.url], { address: v2.address, identity: vaultInbox.identity }, now()))?.vault.settings, { indexes: ['https://index.example'], theme: 'light' })

      // A host with no vault: nothing found.
      assert.equal(await readVault([b.url], { address: v2.address, identity: vaultInbox.identity }, now()), null)
    } finally {
      await Promise.all([a.close(), b.close(), c.close()])
    }
  })

  test('a host that fails is never taken for one with no vault: the read throws, and a vault found says which failed', async () => {
    const now = () => T0 + MINUTE
    const [up, down] = await Promise.all([startHost({ now }), startHost({ now })])
    await down.close()
    try {
      const reader = { address: vault.address, identity: vaultInbox.identity }
      await assert.rejects(readVault([up.url, down.url], reader, now()), code('host'))
      await publish([up.url], [hostsRecord(vault, [up.url], T0), await vaultRecord(vault, vaultInbox.encryptTo, { settings: { theme: 'dark' } }, T0)])
      const found = await readVault([up.url, down.url], reader, now())
      assert.deepEqual(found?.vault.settings, { theme: 'dark' })
      assert.deepEqual(found?.failed.map((f) => f.host), [down.url])
    } finally {
      await up.close()
    }
  })
})

describe('permissions', () => {
  const connector = 'https://connector.example'
  /** An AI app's connection, through a connector: it may post and read for one profile, and pay a little. */
  const assistant: Permission = {
    who: { connector, connection: 'c-1', name: 'My assistant' },
    profiles: ['tutoring/seller'],
    can: ['post', 'read', 'pay'],
    limits: [{ amount: '25', currency: 'USD', per: 'day' }],
    until: T0 + 30 * 86_400_000,
  }
  /** A person, by their profile: they may message for the person, and pay $25 a day on one profile, $100 a day across all. */
  const partner: Permission = {
    who: { profile: bob.address },
    profiles: 'all',
    can: ['message', 'pay'],
    limits: [
      { amount: '25', currency: 'USD', per: 'day', profile: 'tutoring/seller' },
      { amount: '100', currency: 'USD', per: 'day' },
    ],
  }
  const vaultOf = (...permissions: unknown[]) => ({ permissions }) as Vault

  test('the standard’s words: four actions, one currency, three periods of fixed length', () => {
    assert.deepEqual(ACTIONS, ['post', 'message', 'read', 'pay'])
    assert.deepEqual(CURRENCIES, ['USD'])
    assert.deepEqual(PERIODS, { day: 24 * 3_600_000, week: 7 * 24 * 3_600_000, month: 30 * 24 * 3_600_000 })
  })

  test('a connection and a profile, each with limits, go in the vault and come back as they were', async () => {
    const contents = vaultOf(assistant, partner)
    checkVault(contents)
    const record = await vaultRecord(vault, vaultInbox.encryptTo, contents, T0)
    assert.deepEqual(await openVault(record.body!, vaultInbox.identity), contents)
    assert.deepEqual([knowsPermission(assistant), knowsPermission(partner)], [true, true])
    // The same connection id through two connectors is two connections.
    checkVault(vaultOf(assistant, { ...assistant, who: { connector: 'https://other.example', connection: 'c-1' } }))
  })

  test('an entry that can pay with no limit sets no cap: it goes in the vault, and a signer knows it whole', () => {
    const { limits: _, ...uncapped } = assistant
    for (const p of [uncapped, { ...assistant, limits: [] }]) {
      checkVault(vaultOf(p))
      assert.equal(knowsPermission(p), true)
    }
  })

  test('refused: a limit on a profile the entry does not cover, one who twice, and malformed fields', () => {
    const bad: [string, unknown[]][] = [
      ['a limit on a profile the entry does not cover', [{ ...assistant, limits: [{ amount: '5', currency: 'USD', per: 'day', profile: 'tutoring/buyer' }] }]],
      ['one connection twice, by another name', [assistant, { ...assistant, who: { connector, connection: 'c-1', name: 'Another name' } }]],
      ['one profile twice', [partner, { ...partner, can: ['read'] }]],
      ['who is no object', [{ ...partner, who: bob.address }]],
      ['a connection and a profile in one who', [{ ...partner, who: { connector, connection: 'c-1', profile: bob.address } }]],
      ['a connector that is no origin', [{ ...assistant, who: { connector: 'https://connector.example/mcp', connection: 'c-1' } }]],
      ['a connector over http', [{ ...assistant, who: { connector: 'http://connector.example', connection: 'c-1' } }]],
      ['a connection with no id', [{ ...assistant, who: { connector, connection: '' } }]],
      ['a connection with no connector', [{ ...assistant, who: { connection: 'c-1' } }]],
      ['a name that is no text', [{ ...assistant, who: { connector, connection: 'c-1', name: 7 } }]],
      ['a profile that is no address', [{ ...partner, who: { profile: 'not an address' } }]],
      ['profiles is neither all nor a list', [{ ...partner, profiles: 'some' }]],
      ['a label that is no text', [{ ...partner, profiles: [7] }]],
      ['can is no list', [{ ...partner, can: 'pay' }]],
      ['an action that is no text', [{ ...partner, can: [1] }]],
      ['limits is no list', [{ ...partner, limits: {} }]],
      ['an amount as a number', [{ ...assistant, limits: [{ amount: 25, currency: 'USD', per: 'day' }] }]],
      ['an amount with seven places', [{ ...assistant, limits: [{ amount: '0.0000001', currency: 'USD', per: 'day' }] }]],
      ['a negative amount', [{ ...assistant, limits: [{ amount: '-1', currency: 'USD', per: 'day' }] }]],
      ['an amount with a leading zero', [{ ...assistant, limits: [{ amount: '025', currency: 'USD', per: 'day' }] }]],
      ['a currency that is no text', [{ ...assistant, limits: [{ amount: '1', currency: 1, per: 'day' }] }]],
      ['no period', [{ ...assistant, limits: [{ amount: '1', currency: 'USD' }] }]],
      ['until before 1970', [{ ...assistant, until: -1 }]],
      ['until as text', [{ ...assistant, until: String(T0) }]],
      ['a permission that is no object', ['post']],
    ]
    for (const [why, permissions] of bad) assert.throws(() => checkVault(vaultOf(...permissions)), code('vault'), why)
    assert.throws(() => checkVault({ permissions: {} }), code('vault'), 'permissions is a list')
    checkVault(vaultOf({ ...assistant, limits: [{ amount: '0.000001', currency: 'USD', per: 'week' }] }))
    checkVault(vaultOf({ who: { profile: bob.address }, profiles: [], can: [] }))
  })

  test('unknown fields and values are kept, and a signer acts on no entry it does not know whole', async () => {
    const unknown: [string, unknown][] = [
      ['a field on the entry', { ...assistant, spend: 'any' }],
      ['a field on who', { ...assistant, who: { ...assistant.who, device: 'phone' } }],
      ['a field on a limit', { ...assistant, limits: [{ amount: '25', currency: 'USD', per: 'day', from: 'card' }] }],
      ['an action outside the four', { ...partner, can: ['message', 'review'] }],
      ['a currency', { ...assistant, limits: [{ amount: '25', currency: 'EUR', per: 'day' }] }],
      ['a period', { ...assistant, limits: [{ amount: '25', currency: 'USD', per: 'year' }] }],
      ['an inherited name as a period', { ...assistant, limits: [{ amount: '25', currency: 'USD', per: 'toString' }] }],
      ['a kind of who', { ...partner, who: { group: 'family' } }],
    ]
    for (const [why, p] of unknown) {
      const contents = vaultOf(p)
      checkVault(contents)
      const back = await openVault((await vaultRecord(vault, vaultInbox.encryptTo, contents, T0)).body!, vaultInbox.identity)
      assert.deepEqual(back, contents, `${why}: kept`)
      assert.equal(knowsPermission(p as Permission), false, why)
    }
    // Two entries of a kind of who this code does not know are never taken for one who twice.
    checkVault(vaultOf({ ...partner, who: { group: 'family' } }, { ...partner, who: { group: 'family' } }))
  })
})
