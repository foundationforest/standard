// The vault: what a person's devices keep, sealed on a host in a folder of its own; and a new device
// that has nothing but the seed and one host's address getting all of it back.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { inboxKey, mainKey, vaultKey } from '../../keys/src/index.ts'
import { b64u } from '../src/bytes.ts'
import { deliver, publish, pull, readProfile } from '../src/client.ts'
import type { Grant } from '../src/grant.ts'
import { keyFromPrivate } from '../src/keys.ts'
import { pullRequest } from '../src/message.ts'
import { type Vault, VAULT_PATH, checkVault, message, openMessage, openVault, readVault, readerCount, vaultRecord } from '../src/private.ts'
import { RecordError } from '../src/record.ts'
import { accessRecord, hostsRecord, ownerRecord, permissionsRecord } from '../src/write.ts'
import { KEYS, MINUTE, OTHER_SEED, SEED, T0, allow, offerBody, profileBody } from './fixtures.ts'
import { startHost } from './helpers.ts'

const vault = await vaultKey(SEED)
const vaultInbox = await inboxKey(vault.privateKey)
const code = (c: string) => (err: unknown) => err instanceof RecordError && err.code === c
// A note an issuer signed for keys/'s test person, as registry/client's noteToJson writes it.
const note = {
  noteNumber: '10260738844603664161504988713473359584613684870648444840530706110060385700206',
  embedding: 'AQIDBAUGBwgJCgsMDQ4PEA',
  model: 'example-face-model/1',
  tier: '2',
  issuer: '234056d968baf183fe8d237d496d1c04188220cd33e8f8d14df9b84479736b202624393fad9b71c04b3b14d8ac45202dbb4eaff4c2d1350c9453fc08d18651fe',
  signature: {
    r8: ['1887297951236748735644679285430488782884537737395364719081815995454691304498', '2188413712111497275011097715999260490321570164156875446143380653326994485119'],
    s: '1675168220040714342887697386536425370133279355717535327616772797024250766384',
  },
}

describe('the vault', () => {
  test('its folder is the vault key’s, no profile’s; only the vault’s inbox key opens it', async () => {
    assert.equal(vault.address, KEYS.vault.address)
    for (const p of KEYS.mainKeys) assert.notEqual(vault.address, p.address)
    const record = await vaultRecord(vault, vaultInbox.recipient, { settings: { theme: 'dark' } }, T0)
    assert.equal(record.path, VAULT_PATH)
    assert.equal(record.profile, vault.address)
    assert.equal(readerCount(record.body as { private: string }), 1, 'sealed to the vault alone')
    assert.deepEqual(await openVault(record.body!, vaultInbox.identity), { settings: { theme: 'dark' } })
    const seller = await inboxKey((await mainKey(SEED, 'tutoring/seller')).privateKey)
    await assert.rejects(openVault(record.body!, seller.identity), 'a profile’s inbox key opens nothing in it')
  })

  test('every field may be missing, and an app keeps the fields it does not know, at the top and in settings', async () => {
    const contents = { tickets: [{ for: 'later' }], settings: { theme: 'dark', anotherApp: { a: 1 } } }
    const record = await vaultRecord(vault, vaultInbox.recipient, contents as Vault, T0)
    assert.deepEqual(await openVault(record.body!, vaultInbox.identity), contents)
    checkVault({})
  })

  test('a bad entry is refused, before it is sealed and after it is opened', async () => {
    const grant: Grant = { key: b64u.encode(new Uint8Array(32).fill(5)), folder: KEYS.mainKeys[0].address, scope: 'write', paths: ['offer'], from: KEYS.mainKeys[0].address, since: T0 }
    checkVault({ profiles: [{ label: 'tutoring/seller', hosts: ['https://a.example'] }], grants: [grant], issuerNotes: [{ issuer: 'issuer-a.example', note }] })
    const bad: [string, unknown][] = [
      ['an array', []],
      ['profiles is a list', { profiles: {} }],
      ['a label twice', { profiles: [{ label: 'a', hosts: ['https://a.example'] }, { label: 'a', hosts: ['https://b.example'] }] }],
      ['no hosts', { profiles: [{ label: 'a', hosts: [] }] }],
      ['a host that is no origin', { profiles: [{ label: 'a', hosts: ['https://a.example/path'] }] }],
      ['a host twice', { profiles: [{ label: 'a', hosts: ['https://a.example', 'https://a.example'] }] }],
      ['a profile field nobody knows', { profiles: [{ label: 'a', hosts: ['https://a.example'], since: 1 }] }],
      ['a grant that is no grant', { grants: [{ ...grant, scope: 'admin' }] }],
      ['an issuer note with no issuer', { issuerNotes: [{ issuer: '', note }] }],
      ['a note that is no object', { issuerNotes: [{ issuer: 'issuer-a.example', note: 'x' }] }],
      ['settings is an object', { settings: [] }],
    ]
    for (const [why, v] of bad) assert.throws(() => checkVault(v), (e: unknown) => code('vault')(e) || code('grant')(e), why)
    await assert.rejects(vaultRecord(vault, vaultInbox.recipient, { settings: [] } as never, T0), code('vault'))
  })

  test('a full restore: a new device with only the seed and one host gets every profile, grant, note and setting back', async () => {
    const now = () => T0 + MINUTE
    const [a, b, c] = await Promise.all([startHost({ now }), startHost({ now }), startHost({ now })])
    try {
      // The person: two profiles, each on a host of its own.
      const seller = await mainKey(SEED, 'tutoring/seller')
      const buyer = await mainKey(SEED, 'tutoring/buyer')
      const sellerInbox = await inboxKey(seller.privateKey)
      const sellerCard = { ...profileBody('Ana'), inboxKey: sellerInbox.recipient, inbox: { senders: 'anyone' } }
      await publish([a.url], [hostsRecord(seller, [a.url], T0), ownerRecord(seller, 'profile', sellerCard, T0), ownerRecord(seller, 'offer/maths', offerBody('30'), T0)])
      await publish([b.url], [hostsRecord(buyer, [b.url], T0), ownerRecord(buyer, 'profile', { ...profileBody('Ana'), role: 'buyer' }, T0)])

      // Someone else hands the seller an access key to their folder: a grant, in the seller's inbox.
      const carla = await mainKey(OTHER_SEED, 'tutoring/seller')
      const helper = keyFromPrivate(new Uint8Array(32).fill(61))
      await publish([a.url], [hostsRecord(carla, [a.url], T0), permissionsRecord(carla, [allow(helper, ['offer'])], T0)])
      const handed: Grant = { key: b64u.encode(helper.privateKey), folder: carla.address, scope: 'write', paths: ['offer'], from: carla.address, since: T0, note: 'Carla’s offers' }
      await deliver([a.url], [await message(carla, seller.address, { grant: handed }, T0, sellerCard)])

      // The first device pulls it, and keeps it in the vault with everything else, on a third host.
      const page = await pull(a.url, pullRequest(seller, 0, now()))
      const received = (await openMessage(page.messages[0]!.message, sellerInbox.identity)).body.grant as Grant
      const kept: Vault = {
        profiles: [{ label: 'tutoring/seller', hosts: [a.url] }, { label: 'tutoring/buyer', hosts: [b.url] }],
        grants: [received],
        issuerNotes: [{ issuer: 'issuer-a.example', note }],
        bookmarks: [{ url: 'https://shop.example', since: T0 }],
        settings: { indexes: ['https://index.example'], theme: 'dark' },
      }
      await publish([c.url], [hostsRecord(vault, [c.url], T0), await vaultRecord(vault, vaultInbox.recipient, kept, T0)])
      const disk = c.dump().join('\n')
      for (const secret of [received.key, 'tutoring/seller', 'issuer-a.example', 'index.example']) assert.ok(!disk.includes(secret), `the host holds no ${secret}`)

      // The new device: the seed, and one host's address. Nothing else.
      const v2 = await vaultKey(SEED)
      const found = await readVault([c.url], { address: v2.address, identity: (await inboxKey(v2.privateKey)).identity }, now())
      assert.ok(found)
      assert.deepEqual(found.vault, kept)
      assert.deepEqual(found.hosts, [c.url])
      assert.equal(found.time, T0)
      for (const p of found.vault.profiles!) {
        const view = await readProfile(p.hosts, (await mainKey(SEED, p.label)).address, now(), { post: true })
        assert.equal(view.current.get('profile')?.record.body?.name, 'Ana', p.label)
      }
      assert.ok((await readProfile([a.url], seller.address, now())).current.has('offer/maths'), 'the offers come back from their hosts')
      // The grant still signs: the helper key writes an offer into Carla's folder, as before.
      const key = keyFromPrivate(b64u.decode(found.vault.grants![0]!.key))
      const results = await publish([a.url], [accessRecord(key, carla.address, 'offer/from-a-new-device', offerBody('9'), T0 + 1)])
      assert.equal(results[0]!.results[0]!.ok, true)
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
})
