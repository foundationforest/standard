// Private records: a body only chosen keys open, the owner's inbox key among them. Hosts check and
// store them like any record, and read none.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { inboxKey } from '@foundationforest/keys'
import { bech32 } from '@scure/base'
import { canonical } from '../src/canonical.ts'
import { publish, readAll, readProfile } from '../src/client.ts'
import { DAY, DEFAULT_MAX_LINE_BYTES } from '../src/host.ts'
import { isPrivate, makePrivate, openPrivate, readerCount } from '../src/private.ts'
import { hostsRecord, ownerRecord } from '../src/write.ts'
import { KEYS, T0, alice, aliceBuyer, bob } from './fixtures.ts'
import { startHost } from './helpers.ts'

const [aliceInbox, aliceBuyerInbox, bobInbox] = await Promise.all([inboxKey(alice.secret), inboxKey(aliceBuyer.secret), inboxKey(bob.secret)])
const strangerInbox = await inboxKey(new Uint8Array(32).fill(3))

describe('keys an envelope is sealed to', () => {
  test("keys/'s inbox key, one per profile: age's post-quantum hybrid, the pinned one", async () => {
    assert.equal(aliceInbox.identity, KEYS.mainKeys[0].inbox.identity)
    assert.equal(aliceInbox.sealTo, KEYS.mainKeys[0].inbox.sealTo)
    assert.notEqual(aliceInbox.sealTo, aliceBuyerInbox.sealTo)
    assert.match(aliceInbox.sealTo, /^age1pq1[02-9ac-hj-np-z]{1952}$/)
    assert.match(aliceInbox.identity, /^AGE-SECRET-KEY-PQ-1[02-9AC-HJ-NP-Z]+$/)
  })

  test('an envelope is made only for hybrid keys', async () => {
    const x25519 = 'age1stfaf43jlmcuwa5z5e69td3djjluwqvv9afe0nydnv2myuczqgmq9vd6u4' // a valid age X25519 key
    await assert.rejects(makePrivate({ text: 'x' }, []), /at least one/)
    await assert.rejects(makePrivate({ text: 'x' }, [x25519]), /hybrid key/)
    await assert.rejects(makePrivate({ text: 'x' }, [aliceInbox.sealTo, x25519]), /hybrid key/)
    await assert.rejects(makePrivate({ text: 'x' }, [alice.address]), /hybrid key/)
    await assert.rejects(makePrivate({ text: 'x' }, ['age1pq1' + 'q'.repeat(60)]), /checksum/)
  })
})

describe('private records', () => {
  test('sharing: sealed to the owner’s inbox key and Bob’s, each opens it; the host, a stranger and the owner’s other profile cannot', async () => {
    const host = await startHost({ now: () => T0 })
    try {
      const secret = { text: 'My phone is +00 555 0100; call after six.', createdAt: '2026-10-02T12:00:00Z' }
      await publish([host.url], [hostsRecord(alice, [host.url], T0), ownerRecord(alice, 'note/1', await makePrivate(secret, [bobInbox.sealTo, aliceInbox.sealTo]), T0)])

      // What the host holds: no plaintext, and not the keys it is sealed to.
      assert.ok(!host.dump().join('\n').includes('555 0100'))
      assert.ok(!host.dump().join('\n').includes(bobInbox.sealTo))
      const onHost = (await readProfile([host.url], alice.address, T0)).current.get('note/1')!.record.body!
      assert.ok(isPrivate(onHost))

      assert.deepEqual(await openPrivate(onHost, bobInbox.identity), secret)
      assert.deepEqual(await openPrivate(onHost, aliceInbox.identity), secret)
      await assert.rejects(openPrivate(onHost, aliceBuyerInbox.identity))
      await assert.rejects(openPrivate(onHost, strangerInbox.identity))
      // What anyone can see: that it exists, its size, and how many keys it was sealed to.
      assert.equal(readerCount(onHost as { private: string }), 2)
    } finally {
      await host.close()
    }
  })

  test('a reader is removed in the next version: they cannot open it; the old one stays on hosts until keep days pass', async () => {
    const host = await startHost({ now: () => T0 })
    try {
      const v1 = ownerRecord(alice, 'note/door', await makePrivate({ text: 'first' }, [bobInbox.sealTo, aliceInbox.sealTo]), T0 + 1)
      const v2 = ownerRecord(alice, 'note/door', await makePrivate({ text: 'second' }, [aliceInbox.sealTo]), T0 + 2)
      await publish([host.url], [v1, v2])

      const current = host.view(alice.address).current.get('note/door')!.record.body as { private: string }
      assert.equal(readerCount(current), 1)
      assert.deepEqual(await openPrivate(current, aliceInbox.identity), { text: 'second' })
      await assert.rejects(openPrivate(current, bobInbox.identity), 'Bob cannot open the new version')

      // Removal reaches what comes next, not what a reader already had: the old version is still
      // on the host for its keep days, and Bob can open it there.
      const notes = async () => (await readAll(host.url, { profile: alice.address })).records.filter((c) => c.record.path === 'note/door')
      const old = (await notes()).find((c) => c.record.time === T0 + 1)!
      assert.deepEqual(await openPrivate(old.record.body!, bobInbox.identity), { text: 'first' })
      await host.prune(T0 + 31 * DAY)
      assert.deepEqual((await notes()).map((c) => c.record.time), [T0 + 2])
    } finally {
      await host.close()
    }
  })

  test('its readers are anonymous: each stanza holds only its encapsulation, no piece of a reader’s key is in the file, and two envelopes to the same readers share nothing but the count', async () => {
    const readers = [aliceInbox, bobInbox]
    const stanzas = (body: { private: string }) => {
      const header = Buffer.from(body.private, 'base64url').toString('latin1').split('\n---')[0]!
      return header.split('\n-> ').slice(1).map((s) => s.split('\n')[0]!.split(' '))
    }
    const one = await makePrivate({ text: 'x' }, readers.map((r) => r.sealTo))
    const two = await makePrivate({ text: 'x' }, readers.map((r) => r.sealTo))
    for (const body of [one, two]) {
      assert.deepEqual(stanzas(body).map((s) => [s[0], s.length - 1]), [['mlkem768x25519', 1], ['mlkem768x25519', 1]], 'one argument each')
      const file = Buffer.from(body.private, 'base64url')
      for (const r of readers) {
        // The key others seal to, its ML-KEM-768 half and its X25519 half: no 16 bytes of it are in the file.
        const key = bech32.fromWords(bech32.decode(r.sealTo as `${string}1${string}`, false).words)
        assert.equal(key.length, 1216)
        for (let i = 0; i + 16 <= key.length; i++) assert.ok(!file.includes(Buffer.from(key.subarray(i, i + 16))), `bytes ${i} to ${i + 16} of a reader's key`)
      }
    }
    const args = (body: { private: string }) => stanzas(body).map((s) => s[1])
    assert.ok(args(one).every((a) => !args(two).includes(a)), 'fresh encapsulations each time')
    assert.equal(readerCount(one), 2, 'what shows: how many')
  })

  test('an envelope’s stanzas say mlkem768x25519, to anyone', async () => {
    const body = await makePrivate({ text: 'x' }, [aliceInbox.sealTo])
    const header = Buffer.from(body.private, 'base64url').toString('latin1').split('\n---')[0]!
    assert.match(header, /^age-encryption\.org\/v1\n-> mlkem768x25519 /)
  })

  test('each key adds about 2 KB, so a record the reference host takes, 65,536 bytes, is made for about 30', async () => {
    const readers = await Promise.all(Array.from({ length: 32 }, (_, i) => inboxKey(new Uint8Array(32).fill(i + 1))))
    const size = async (n: number) => canonical({ ...ownerRecord(alice, 'note/many', null, T0), body: await makePrivate({ text: 'x' }, readers.slice(0, n).map((r) => r.sealTo)) }).length
    const [one, two] = [await size(1), await size(2)]
    assert.ok(two - one > 2000 && two - one < 2200, `${two - one} bytes a reader`)
    assert.ok((await size(30)) <= DEFAULT_MAX_LINE_BYTES)
    assert.ok((await size(32)) > DEFAULT_MAX_LINE_BYTES)
  })
})
