// The vault: what a person's devices keep, sealed on a host in a folder of its own; and a new device
// that has nothing but the seed and one host's address getting all of it back.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { inboxKey, mainKey, seedScalar, vaultKey } from '../../keys/src/index.ts'
import { noteNumberOf, noteToJson, signNote } from '../../proofs/human/client/src/index.ts'
import { publish, readProfile } from '../src/client.ts'
import { type Vault, VAULT_PATH, checkVault, openVault, readVault, readerCount, vaultRecord } from '../src/private.ts'
import { RecordError } from '../src/record.ts'
import { hostsRecord, ownerRecord } from '../src/write.ts'
import { KEYS, MINUTE, SEED, T0, offerBody, profileBody } from './fixtures.ts'
import { startHost } from './helpers.ts'

const vault = await vaultKey(SEED)
const vaultInbox = await inboxKey(vault.secret)
const code = (c: string) => (err: unknown) => err instanceof RecordError && err.code === c
// A note an example issuer signed for keys/'s test person, as proofs/human/client's noteToJson writes it.
const note = noteToJson(
  signNote(new Uint8Array(32).fill(0x31), {
    noteNumber: noteNumberOf(await seedScalar(SEED), 'issuer-a.example'),
    embedding: Uint8Array.from({ length: 16 }, (_, i) => i + 1),
    model: 'example-face-model/1',
    month: 202609,
  }),
)

describe('the vault', () => {
  test('its folder is the vault key’s, no profile’s; only the vault’s inbox key opens it', async () => {
    assert.equal(vault.address, KEYS.vault.address)
    for (const p of KEYS.mainKeys) assert.notEqual(vault.address, p.address)
    const record = await vaultRecord(vault, vaultInbox.recipient, { settings: { theme: 'dark' } }, T0)
    assert.equal(record.path, VAULT_PATH)
    assert.equal(record.profile, vault.address)
    assert.equal(readerCount(record.body as { private: string }), 1, 'sealed to the vault alone')
    assert.deepEqual(await openVault(record.body!, vaultInbox.identity), { settings: { theme: 'dark' } })
    const seller = await inboxKey((await mainKey(SEED, 'tutoring/seller')).secret)
    await assert.rejects(openVault(record.body!, seller.identity), 'a profile’s inbox key opens nothing in it')
  })

  test('every field may be missing, and an app keeps the fields it does not know, at the top and in settings', async () => {
    const contents = { tickets: [{ for: 'later' }], settings: { theme: 'dark', anotherApp: { a: 1 } } }
    const record = await vaultRecord(vault, vaultInbox.recipient, contents as Vault, T0)
    assert.deepEqual(await openVault(record.body!, vaultInbox.identity), contents)
    checkVault({})
  })

  test('a bad entry is refused, before it is sealed and after it is opened', async () => {
    checkVault({ profiles: [{ label: 'tutoring/seller', hosts: ['https://a.example'] }], issuerNotes: [{ issuer: 'issuer-a.example', note }], settings: {} })
    const bad: [string, unknown][] = [
      ['an array', []],
      ['profiles is a list', { profiles: {} }],
      ['a label twice', { profiles: [{ label: 'a', hosts: ['https://a.example'] }, { label: 'a', hosts: ['https://b.example'] }] }],
      ['no hosts', { profiles: [{ label: 'a', hosts: [] }] }],
      ['a host that is no origin', { profiles: [{ label: 'a', hosts: ['https://a.example/path'] }] }],
      ['a host twice', { profiles: [{ label: 'a', hosts: ['https://a.example', 'https://a.example'] }] }],
      ['a profile field nobody knows', { profiles: [{ label: 'a', hosts: ['https://a.example'], since: 1 }] }],
      ['an issuer note with no issuer', { issuerNotes: [{ issuer: '', note }] }],
      ['a note that is no object', { issuerNotes: [{ issuer: 'issuer-a.example', note: 'x' }] }],
      ['settings is an object', { settings: [] }],
    ]
    for (const [why, v] of bad) assert.throws(() => checkVault(v), code('vault'), why)
    await assert.rejects(vaultRecord(vault, vaultInbox.recipient, { settings: [] } as never, T0), code('vault'))
  })

  test('a full restore: a new device with only the seed and one host gets every profile, note and setting back', async () => {
    const now = () => T0 + MINUTE
    const [a, b, c] = await Promise.all([startHost({ now }), startHost({ now }), startHost({ now })])
    try {
      // The person: two profiles, each on a host of its own.
      const seller = await mainKey(SEED, 'tutoring/seller')
      const buyer = await mainKey(SEED, 'tutoring/buyer')
      const sellerInbox = await inboxKey(seller.secret)
      const sellerCard = { ...profileBody('maths'), inboxKey: sellerInbox.recipient, inbox: { senders: 'anyone' } }
      await publish([a.url], [hostsRecord(seller, [a.url], T0), ownerRecord(seller, 'profile', sellerCard, T0), ownerRecord(seller, 'offer/maths', offerBody('30'), T0)])
      await publish([b.url], [hostsRecord(buyer, [b.url], T0), ownerRecord(buyer, 'profile', { ...profileBody('maths'), role: 'buyer' }, T0)])

      // The first device keeps the rest in the vault, on a third host.
      const kept: Vault = {
        profiles: [{ label: 'tutoring/seller', hosts: [a.url] }, { label: 'tutoring/buyer', hosts: [b.url] }],
        issuerNotes: [{ issuer: 'issuer-a.example', note }],
        bookmarks: [{ url: 'https://shop.example', since: T0 }],
        settings: { indexes: ['https://index.example'], theme: 'dark' },
      }
      await publish([c.url], [hostsRecord(vault, [c.url], T0), await vaultRecord(vault, vaultInbox.recipient, kept, T0)])
      const disk = c.dump().join('\n')
      for (const secret of ['tutoring/seller', 'issuer-a.example', 'index.example', note.noteNumber]) assert.ok(!disk.includes(secret), `the host holds no ${secret}`)

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
      assert.deepEqual(found.vault.issuerNotes, [{ issuer: 'issuer-a.example', note }])
      assert.deepEqual(found.vault.bookmarks, [{ url: 'https://shop.example', since: T0 }], 'a field an app added comes back as it was')

      // A later write, from either device, after the one read: the newer vault counts.
      const later = { ...found.vault, settings: { ...found.vault.settings, theme: 'light' } }
      await publish([c.url], [await vaultRecord(v2, vaultInbox.recipient, later, Math.max(now(), found.time + 1))])
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
      await publish([up.url], [hostsRecord(vault, [up.url], T0), await vaultRecord(vault, vaultInbox.recipient, { settings: { theme: 'dark' } }, T0)])
      const found = await readVault([up.url, down.url], reader, now())
      assert.deepEqual(found?.vault.settings, { theme: 'dark' })
      assert.deepEqual(found?.failed.map((f) => f.host), [down.url])
    } finally {
      await up.close()
    }
  })
})
