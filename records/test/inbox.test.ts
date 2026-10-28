// The inbox: a profile record declares one, anyone may deliver an encrypted message to it on the
// profile's hosts, encrypted to its inbox key, and only the profile's main key pulls it. Here, the
// client's side, against the minimal host (host.ts); each check a host runs on a delivery and a pull
// is the host check's (check.test.ts).

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { inboxKey } from '@foundationforest/keys'
import { canonical } from '../src/canonical.ts'
import { deliver, publish, pull, readAll, readProfile } from '../src/client.ts'
import type { Key } from '../src/keys.ts'
import { type Sender, checkMessage, encodeMessage, inboxKeyOf, inboxOf, messageSigningInput, pullRequest, readMessage, signMessage } from '../src/message.ts'
import { makePrivate, message, openMessage } from '../src/private.ts'
import { type Body, RecordError, signAs } from '../src/record.ts'
import { hostsRecord, ownerRecord } from '../src/write.ts'
import { T0, alice, aliceBuyer, bob, profileBody, stranger } from './fixtures.ts'
import { startHost } from './helpers.ts'
import type { TestHost } from './host.ts'

const [aliceInbox, aliceBuyerInbox, bobInbox] = await Promise.all([inboxKey(alice.secret), inboxKey(aliceBuyer.secret), inboxKey(bob.secret)])

const profileWith = (inbox?: Body | string, subject = 'maths') => ({ ...profileBody(subject), inboxKey: aliceInbox.encryptTo, ...(inbox !== undefined && { inbox }) })
/** An inbox with no limit of its own: anyone may write to it. */
const OPEN = {}

/** A host, at T0, holding Alice's profile record with this inbox. */
async function hostWith(inbox: Body | string | undefined): Promise<TestHost> {
  const h = await startHost({ now: () => T0 })
  await publish([h.url], [ownerRecord(alice, 'profile', profileWith(inbox), T0)])
  return h
}
const stamp = (from: Sender = bob, text = 'Is Tuesday at six free?', time = T0) => message(from, alice.address, { text, createdAt: '2026-10-02T12:00:00Z' }, time, profileWith(OPEN))
const pulled = async (h: TestHost, after = 0, time = T0, owner: Key = alice) => pull(h.url, pullRequest(owner, after, time))
const code = (c: string) => (err: unknown) => err instanceof RecordError && err.code === c

describe('messages', () => {
  test('a message is encrypted to the profile record’s inbox key and signed by from; only that key opens it', async () => {
    const m = await stamp()
    assert.deepEqual(Object.keys(m.body), ['private'])
    assert.equal(m.from, bob.address)
    const opened = await openMessage(m, aliceInbox.identity)
    assert.deepEqual([opened.from, opened.to, opened.time, opened.body.text], [bob.address, alice.address, T0, 'Is Tuesday at six free?'])
    assert.equal(opened.id, readMessage(encodeMessage(m)).id)
    assert.match(opened.id, /^[0-9a-f]{64}$/, 'lowercase hex, as a record’s id')
    await assert.rejects(openMessage(m, aliceBuyerInbox.identity), 'the same person’s other profile cannot open it')
  })

  test('a body is { private } and nothing else; the key must be from’s', async () => {
    const encrypted = await makePrivate({ text: 'hi' }, [aliceInbox.encryptTo])
    assert.throws(() => signMessage(bob, alice.address, { text: 'hi' } as never, T0), /body/)
    assert.throws(() => signMessage(bob, alice.address, { ...encrypted, extra: 'x' } as never, T0), /body/)
    assert.throws(() => signMessage(bob, 'not an address', encrypted, T0), /to is not/)
    assert.throws(() => signMessage({ ...bob, address: alice.address }, alice.address, encrypted, T0), /not the one named to sign/)
    const m = signMessage(bob, alice.address, encrypted, T0)
    for (const [text, code] of [
      [JSON.stringify(m, null, 1), 'canonical'],
      [canonical({ ...m, path: 'x' }), 'shape'],
      [canonical({ ...m, v: 2 }), 'version'],
      [canonical({ ...m, time: -1 }), 'time'],
    ] as const) assert.throws(() => readMessage(text), (err: RecordError) => err.code === code, code)
  })

  test('the profile record’s inbox: none, or one with a size or none; any field this code does not know is unsupported', () => {
    assert.equal(inboxOf(null), null)
    assert.equal(inboxOf(profileWith()), null)
    assert.equal(inboxOf({ private: 'abc' }), null, 'a private profile record declares nothing a host can read')
    assert.deepEqual(inboxOf(profileWith(OPEN)), {})
    assert.deepEqual(inboxOf(profileWith({ maxBytes: 4000 })), { maxBytes: 4000 })
    for (const inbox of ['anyone', [], { senders: 'anyone' }, { senders: { verifier: alice.address } }, { maxBytes: -1 }, { maxBytes: 1.5 }, { maxBytes: '4000' }, { once: true }, { deposit: '5' }, { readers: [aliceBuyerInbox.encryptTo] }]) {
      assert.equal(inboxOf(profileWith(inbox as unknown as Body)), 'unsupported', JSON.stringify(inbox))
    }
  })
})

describe('encrypting', () => {
  test('a message is encrypted to the inbox key the profile record gives, and nothing else', async () => {
    assert.equal(inboxKeyOf(profileWith(OPEN)), aliceInbox.encryptTo)
    const m = await message(bob, alice.address, { text: 'hi' }, T0, profileWith(OPEN))
    assert.equal((await openMessage(m, aliceInbox.identity)).body.text, 'hi')
    await assert.rejects(openMessage(m, aliceBuyerInbox.identity))
  })

  test('a sender encrypts to nobody when the profile record gives no inbox key, no inbox, or an inbox this code cannot read: a field it does not know could name more keys', async () => {
    const { inboxKey: _, ...noKey } = profileWith(OPEN)
    for (const c of [profileWith(), noKey, profileWith({ encryptTo: 'x' }), profileWith({ readers: [aliceBuyerInbox.encryptTo] })]) assert.throws(() => inboxKeyOf(c), code('no_inbox'), JSON.stringify(c.inbox))
    await assert.rejects(message(bob, alice.address, { text: 'hi' }, T0, profileWith()), code('no_inbox'))
  })
})

describe('deliver and pull', () => {
  test('a sender reads the profile record, encrypts to its inbox key, delivers to each host; the main key pulls from each and opens; no host reads it, and no record lists it', async () => {
    const h1 = await startHost({ now: () => T0 })
    const h2 = await startHost({ now: () => T0 })
    try {
      await publish([h1.url, h2.url], [hostsRecord(alice, [h1.url, h2.url], T0), ownerRecord(alice, 'profile', profileWith(OPEN), T0)])
      // Bob's app knows one host; the hosts record gives the rest, and the profile record the inbox key.
      const view = await readProfile([h1.url], alice.address, T0)
      const m = await message(bob, alice.address, { text: 'Is Tuesday at six free?' }, T0, view.current.get('profile')!.record.body!)
      const outcomes = await deliver(view.hosts, [m])
      assert.deepEqual(outcomes.map((o) => o.results.map((r) => r.error ?? 'ok')), [['ok'], ['ok']])

      for (const h of [h1, h2]) {
        const page = await pulled(h)
        assert.deepEqual(page.refused, [])
        assert.equal(page.messages.length, 1)
        assert.equal((await openMessage(page.messages[0]!.message, aliceInbox.identity)).body.text, 'Is Tuesday at six free?')
        assert.ok(!h.dump().join('\n').includes('Tuesday'))
        const records = await readAll(h.url)
        assert.deepEqual([records.records.length, records.refused.length], [2, 0], 'a message is not a record')
      }
    } finally {
      await h1.close()
      await h2.close()
    }
  })

})

describe('naming a host', () => {
  test('a message may name host, one of from’s hosts, where the recipient’s app finds the sender’s folder; no other key signs, and no field names one', async () => {
    const encrypted = await makePrivate({ text: 'hi' }, [bobInbox.encryptTo])
    const own = signMessage({ from: alice, host: 'https://host-a.example' }, bob.address, encrypted, T0)
    assert.deepEqual([own.from, own.host], [alice.address, 'https://host-a.example'])
    assert.ok(checkMessage(readMessage(encodeMessage(own))))
    const { host: _h, ...noHost } = own
    assert.equal(checkMessage(readMessage(canonical(noHost))), false, 'no host is a shape that holds, and from did not sign this')
    for (const [why, value, c] of [
      ['a key beside from', { ...own, key: stranger.address }, 'shape'],
      ['host with a path', { ...own, host: 'https://a.example/inbox' }, 'shape'],
      ['host over http', { ...own, host: 'http://a.example' }, 'shape'],
    ] as const) assert.throws(() => readMessage(canonical(value)), code(c), why)
    // A message signed by a key that is not from's: refused [signature].
    const unsigned = { v: 1 as const, to: bob.address, from: alice.address, time: T0, body: encrypted }
    assert.equal(checkMessage(readMessage(canonical({ ...unsigned, sig: signAs(stranger, stranger.address, messageSigningInput(unsigned)) }))), false)
  })

})

describe('pulling', () => {
  test('a pull answers that profile’s messages after the cursor, in arrival order, paged as the host chooses', async () => {
    const h = await hostWith(OPEN)
    h.page = 2
    try {
      const buyerProfile = { ...profileWith(OPEN, 'algebra'), inboxKey: aliceBuyerInbox.encryptTo }
      await publish([h.url], [ownerRecord(aliceBuyer, 'profile', buyerProfile, T0)])
      const toBuyer = await message(bob, aliceBuyer.address, { text: 'for the buyer' }, T0, buyerProfile)
      const texts = ['one', 'two', 'three', 'four', 'five']
      for (const [i, text] of texts.entries()) await deliver([h.url], i === 2 ? [toBuyer, await stamp(bob, text)] : [await stamp(i % 2 ? stranger : bob, text)])
      const got: string[] = []
      let cursor = 0
      for (let pages = 0; ; pages++) {
        const page = await pulled(h, cursor)
        assert.ok(page.messages.length <= 2)
        for (const c of page.messages) got.push((await openMessage(c.message, aliceInbox.identity)).body.text as string)
        if (page.cursor === cursor) {
          assert.equal(pages, 3)
          break
        }
        cursor = page.cursor
      }
      assert.deepEqual(got, texts)
      assert.deepEqual((await pulled(h, cursor)).messages, [], 'nothing new since the cursor')
      assert.equal((await pulled(h, 0, T0, aliceBuyer)).messages.length, 1)
    } finally {
      await h.close()
    }
  })

  test('a host that slips in a forged message, or one to someone else: the reader refuses each', async () => {
    const h = await hostWith(OPEN)
    try {
      const m = await stamp()
      await deliver([h.url], [m])
      const toBob = await message(alice, bob.address, { text: 'x' }, T0, profileWith(OPEN))
      const serve = h.pull.bind(h)
      h.pull = (text, now) => {
        const out = serve(text, now)
        return { lines: [...out.lines, encodeMessage({ ...m, time: T0 + 1 }), encodeMessage(toBob)], cursor: out.cursor }
      }
      const page = await pulled(h)
      assert.equal(page.messages.length, 1)
      assert.deepEqual(page.refused.map((r) => r.reason), ['signature', 'to'])
    } finally {
      await h.close()
    }
  })
})
