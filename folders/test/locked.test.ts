// Locked entries: a body only chosen keys open, the main key's opening half among them. Hosts
// check and store them like any entry, and read none. Notes about access keys and the Profiles
// folder's entries are locked entries at random paths.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { accessKey, mainKey, openingHalf } from '@foundationforest/keys'
import { stampFromJson, stampToJson } from '@foundationforest/proofs'
import { bech32 } from '@scure/base'
import { canonical } from '../src/canonical.ts'
import { readAll, readFolder, write } from '../src/client.ts'
import { isLocked, lock, lockCount, openLocked } from '../src/locked.ts'
import { lockKeysOf } from '../src/profile.ts'
import { entry } from '../src/write.ts'
import { KEYS, SEED, T0, access, alice, aliceBuyerOpening, aliceOpening, asAccess, bobOpening, listed, profileBody } from './fixtures.ts'
import { startHost } from './helpers.ts'

const strangerOpening = await openingHalf(new Uint8Array(32).fill(3))

describe('keys an envelope is locked to', () => {
  test("keys/'s opening half, one per key: age's post-quantum hybrid, the pinned one", async () => {
    assert.equal(aliceOpening.identity, KEYS.mainKeys[0].opening.identity)
    assert.equal(aliceOpening.openKey, KEYS.mainKeys[0].opening.openKey)
    assert.equal(access.openKey, KEYS.accessKey.opening.openKey)
    assert.notEqual(aliceOpening.openKey, aliceBuyerOpening.openKey)
    assert.match(aliceOpening.openKey, /^age1pq1[02-9ac-hj-np-z]{1952}$/)
    assert.match(aliceOpening.identity, /^AGE-SECRET-KEY-PQ-1[02-9AC-HJ-NP-Z]+$/)
  })

  test('an envelope is made only for hybrid keys', async () => {
    const x25519 = 'age1stfaf43jlmcuwa5z5e69td3djjluwqvv9afe0nydnv2myuczqgmq9vd6u4' // a valid age X25519 key
    await assert.rejects(lock({ text: 'x' }, []), /at least one/)
    await assert.rejects(lock({ text: 'x' }, [x25519]), /hybrid key/)
    await assert.rejects(lock({ text: 'x' }, [aliceOpening.openKey, x25519]), /hybrid key/)
    await assert.rejects(lock({ text: 'x' }, [alice.address]), /hybrid key/)
    await assert.rejects(lock({ text: 'x' }, ['age1pq1' + 'q'.repeat(60)]), /checksum/)
  })
})

describe('locked entries', () => {
  test('locked to the main key and to each listed key that can read: each opens it; the host, a stranger, a key that only writes and the person’s other profile cannot', async () => {
    const host = await startHost({ now: () => T0 })
    try {
      const writer = await accessKey(new Uint8Array(64).fill(0x2d))
      const body = profileBody('maths', { hosts: [host.url], keys: [listed(['read']), listed(['write'], writer)] })
      const secret = { text: 'My phone is +00 555 0100; call after six.', createdAt: '2026-10-02T12:00:00Z' }
      assert.deepEqual(lockKeysOf(body), [aliceOpening.openKey, access.openKey])
      await write([host.url], [entry(alice, 'profile', body, T0), entry(alice, 'contact/1', await lock(secret, lockKeysOf(body)), T0)])

      // What the host holds: no plaintext, and not the keys it is locked to.
      assert.ok(!host.dump().join('\n').includes('555 0100'))
      const onHost = (await readFolder([host.url], alice.address, T0)).current.get('contact/1')!.entry.body!
      assert.ok(isLocked(onHost))
      assert.deepEqual(await openLocked(onHost, aliceOpening.identity), secret)
      assert.deepEqual(await openLocked(onHost, access.identity), secret)
      for (const other of [writer.identity, aliceBuyerOpening.identity, strangerOpening.identity]) await assert.rejects(openLocked(onHost, other))
      // What anyone can see: that it exists, its size, and how many keys it was locked to.
      assert.equal(lockCount(onHost as { private: string }), 2)
    } finally {
      await host.close()
    }
  })

  test('an access key that can write locks what it writes too, to the keys the profile entry gives', async () => {
    const body = profileBody('maths', { keys: [listed(['read', 'write'])] })
    const written = entry(asAccess, 'draft/1', await lock({ text: 'from the AI' }, lockKeysOf(body)), T0)
    assert.equal(written.key, access.address)
    assert.deepEqual(await openLocked(written.body!, aliceOpening.identity), { text: 'from the AI' }, 'the person opens what the key wrote')
  })

  test('a key removed reads no new version; the old one, while a host keeps it, it still can', async () => {
    const host = await startHost({ now: () => T0 })
    try {
      const v1 = entry(alice, 'contact/door', await lock({ text: 'first' }, [bobOpening.openKey, aliceOpening.openKey]), T0 + 1)
      const v2 = entry(alice, 'contact/door', await lock({ text: 'second' }, [aliceOpening.openKey]), T0 + 2)
      await write([host.url], [v1, v2])

      const current = host.view(alice.address).current.get('contact/door')!.entry.body as { private: string }
      assert.equal(lockCount(current), 1)
      assert.deepEqual(await openLocked(current, aliceOpening.identity), { text: 'second' })
      await assert.rejects(openLocked(current, bobOpening.identity), 'Bob cannot open the new version')
      // Removal reaches what comes next, not what a key already had: while a host keeps the old
      // version, Bob can open it there.
      const old = (await readAll(host.url, { profile: alice.address })).entries.find((c) => c.entry.time === T0 + 1)!
      assert.deepEqual(await openLocked(old.entry.body!, bobOpening.identity), { text: 'first' })
    } finally {
      await host.close()
    }
  })

  test('its keys are anonymous: each stanza holds only its encapsulation, no piece of a key is in the file, and two envelopes to the same keys share nothing but the count', async () => {
    const keys = [aliceOpening, bobOpening]
    const stanzas = (body: { private: string }) => {
      const header = Buffer.from(body.private, 'base64url').toString('latin1').split('\n---')[0]!
      return header.split('\n-> ').slice(1).map((s) => s.split('\n')[0]!.split(' '))
    }
    const one = await lock({ text: 'x' }, keys.map((r) => r.openKey))
    const two = await lock({ text: 'x' }, keys.map((r) => r.openKey))
    for (const body of [one, two]) {
      assert.deepEqual(stanzas(body).map((s) => [s[0], s.length - 1]), [['mlkem768x25519', 1], ['mlkem768x25519', 1]], 'one argument each')
      const file = Buffer.from(body.private, 'base64url')
      for (const r of keys) {
        // The open key, its ML-KEM-768 half and its X25519 half: no 16 bytes of it are in the file.
        const key = bech32.fromWords(bech32.decode(r.openKey as `${string}1${string}`, false).words)
        assert.equal(key.length, 1216)
        for (let i = 0; i + 16 <= key.length; i++) assert.ok(!file.includes(Buffer.from(key.subarray(i, i + 16))), `bytes ${i} to ${i + 16} of a key`)
      }
    }
    const args = (body: { private: string }) => stanzas(body).map((s) => s[1])
    assert.ok(args(one).every((a) => !args(two).includes(a)), 'fresh encapsulations each time')
    assert.equal(lockCount(one), 2, 'what shows: how many')
  })

  test('an envelope’s stanzas say mlkem768x25519, to anyone', async () => {
    const body = await lock({ text: 'x' }, [aliceOpening.openKey])
    const header = Buffer.from(body.private, 'base64url').toString('latin1').split('\n---')[0]!
    assert.match(header, /^age-encryption\.org\/v1\n-> mlkem768x25519 /)
  })

  test('each key adds about 2 KB, so the largest entry a host takes bounds how many keys an envelope holds', async () => {
    const keys = await Promise.all(Array.from({ length: 3 }, (_, i) => openingHalf(new Uint8Array(32).fill(i + 1))))
    const size = async (n: number) => canonical({ ...entry(alice, 'contact/many', null, T0), body: await lock({ text: 'x' }, keys.slice(0, n).map((r) => r.openKey)) }).length
    const [one, two, three] = [await size(1), await size(2), await size(3)]
    assert.ok(two - one > 2000 && two - one < 2200, `${two - one} bytes a key`)
    assert.equal(three - two, two - one, 'the same for each')
  })
})

/** A random id, as an app makes one: 16 random bytes in hex. */
const randomId = () => Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('hex')

describe('notes and the Profiles folder: locked entries at random paths', () => {
  test('a note about an access key is locked to the main key alone and names its key inside: the key it is about cannot open it, nor find it; the app lists and opens', async () => {
    const host = await startHost({ now: () => T0 })
    try {
      const body = profileBody('maths', { hosts: [host.url], keys: [listed(['read', 'write'])] })
      const about = { key: access.address, holder: 'my tutoring AI', since: T0 }
      const note = entry(alice, `key/${randomId()}`, await lock(about, [aliceOpening.openKey]), T0)
      await write([host.url], [entry(alice, 'profile', body, T0), note])
      assert.match(note.path, /^key\/[0-9a-f]{32}$/)
      assert.ok(!note.path.includes(access.address.slice(0, 8)), 'the path names nothing')
      await assert.rejects(openLocked(note.body!, access.identity), 'a key that can read opens no note: a note is locked to the main key alone')
      // The app finds the note about a key by listing key/ and opening each.
      const folder = await readFolder([host.url], alice.address, T0)
      const notes = await Promise.all([...folder.current].filter(([path]) => path.startsWith('key/')).map(async ([, c]) => openLocked(c.entry.body!, aliceOpening.identity)))
      assert.deepEqual(notes.filter((n) => n.key === access.address), [about])
    } finally {
      await host.close()
    }
  })

  test("the Profiles folder: the empty label's folder, its profile entry holding only hosts; every entry in it is locked to its own opening half, at random paths", async () => {
    const profiles = await mainKey(SEED, '')
    const opening = await openingHalf(profiles.secret)
    assert.equal(profiles.address, KEYS.mainKeys[2].address)
    const host = await startHost({ now: () => T0 })
    try {
      // A stamp whose verifier added fields an entry's narrowed JSON cannot spell, a fraction and a
      // key with `_`: kept as text, it fits whole.
      const added = { stampNumber: '7', facts: '9', verifier: KEYS.serviceKey.address, verifierName: 'verifier-a.example', signature: { r8: ['1', '2'], s: '3' }, score: 0.97, checked_at: '2026-10-01' }
      assert.throws(() => canonical(added), /whole|key/, 'not as JSON in a body')
      const text = JSON.stringify(stampToJson(stampFromJson(added)))
      const stamp = { stamp: text }
      const label = { label: 'tutoring/seller', time: T0 }
      await write([host.url], [
        entry(profiles, 'profile', { hosts: [host.url] }, T0),
        entry(profiles, `label/${randomId()}`, await lock(label, [opening.openKey]), T0),
        entry(profiles, `stamp/${randomId()}`, await lock(stamp, [opening.openKey]), T0),
      ])
      // A new device: the seed gives the Profiles folder's key, its folder gives every label, and
      // each label its folder.
      const again = await mainKey(SEED, '')
      const folder = await readFolder([host.url], again.address, T0)
      assert.deepEqual(folder.hosts, [host.url])
      assert.equal(folder.current.get('profile')!.entry.body!.openKey, undefined, 'no openKey: it takes no inbox entries')
      const { identity } = await openingHalf(again.secret)
      const opened = await Promise.all([...folder.current].filter(([path]) => path !== 'profile').map(async ([path, c]) => [path.split('/')[0], await openLocked(c.entry.body!, identity)] as const))
      assert.deepEqual(Object.fromEntries(opened), { label, stamp })
      const back = stampFromJson(JSON.parse(opened.find(([kind]) => kind === 'stamp')![1].stamp as string))
      assert.deepEqual([back.score, back.checked_at], [0.97, '2026-10-01'], 'what the verifier added comes back as it wrote it')
      // Nothing in it names a label: not the paths, not what the host holds.
      assert.ok(!host.dump().join('\n').includes('tutoring'))
      const labelEntry = [...folder.current].find(([path]) => path.startsWith('label/'))![1]
      for (const other of [aliceOpening.identity, access.identity]) await assert.rejects(openLocked(labelEntry.entry.body!, other), 'only its own opening half opens it')
    } finally {
      await host.close()
    }
  })
})
