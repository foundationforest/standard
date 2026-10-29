// The inbox: anyone leaves an inbox entry in a folder whose profile entry has openKey; the message
// inside is locked to openKey and to every key listed with read-inbox, and signed by the sender's
// main key or a key its profile entry lists with message, the folder it is to among its signed
// fields. Anyone lists an inbox; only the envelopes protect it. Here, the client's side, against the minimal host (host.ts); each check a host runs
// is the host check's (check.test.ts).

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { accessKey } from '@foundationforest/keys'
import { leave, readAll, readFolder, readInbox, write } from '../src/client.ts'
import { FolderError } from '../src/fail.ts'
import { checkMessage, decodeInbox, encodeInbox, inboxId, messageSigningInput, senderCounts, signMessage } from '../src/inbox.ts'
import { inboxEntry, lock, openInbox, openLocked } from '../src/locked.ts'
import { signAs } from '../src/entry.ts'
import { entry } from '../src/write.ts'
import { T0, access, alice, aliceBuyer, aliceBuyerOpening, aliceOpening, bob, bobOpening, listed, profileBody, stranger } from './fixtures.ts'
import { startHost } from './helpers.ts'

const code = (c: string) => (err: unknown) => err instanceof FolderError && err.code === c
/** Alice's profile entry body: her open key, and her access key able to read her inbox. */
const alicesProfile = profileBody('maths', { keys: [listed(['read-inbox', 'write'])] })
/** Bob's profile entry body, listing a key of his own that can message as him. */
const bobsKey = await accessKey(new Uint8Array(64).fill(0x2e))
const bobsProfile = { market: 'tutoring', role: 'buyer', hosts: ['https://host-b.example'], openKey: bobOpening.openKey, keys: [listed(['message'], bobsKey)] }
const toAlice = (text: string, from: Parameters<typeof inboxEntry>[0] = bob, time = T0) => inboxEntry(from, alice.address, { text }, time, alicesProfile, 'https://host-b.example')

describe('messages', () => {
  test('an inbox entry names only the folder it is to, and no time; its message, locked inside, names its sender and its folder and is signed by it', async () => {
    const e = await toAlice('Is Tuesday at six free?')
    assert.deepEqual(Object.keys(e).sort(), ['private', 'to', 'v'])
    assert.ok(!encodeInbox(e).includes(bob.address), 'the sender is locked inside')
    const opened = await openInbox(e, aliceOpening.identity)
    assert.deepEqual([opened.to, opened.message.from, opened.message.to, opened.message.host, opened.message.time, opened.message.body.text], [alice.address, bob.address, alice.address, 'https://host-b.example', T0, 'Is Tuesday at six free?'])
    assert.equal(opened.id, inboxId(e))
    assert.match(opened.id, /^[0-9a-f]{64}$/, 'lowercase hex, as an entry’s id')
    assert.equal(opened.id, decodeInbox(encodeInbox(e)).id)
  })

  test('it is locked to the main key and to each key listed with read-inbox: each opens it; the person’s other profile and a key that only writes do not', async () => {
    const writer = await accessKey(new Uint8Array(64).fill(0x2f))
    const body = profileBody('maths', { keys: [listed(['read-inbox']), listed(['write', 'read'], writer)] })
    const e = await inboxEntry(bob, alice.address, { text: 'hi' }, T0, body)
    for (const identity of [aliceOpening.identity, access.identity]) assert.equal((await openInbox(e, identity)).message.body.text, 'hi')
    for (const identity of [aliceBuyerOpening.identity, writer.identity]) await assert.rejects(openInbox(e, identity))
  })

  test('a folder whose profile entry has no openKey takes no inbox entries: a sender locks nothing to it', async () => {
    await assert.rejects(inboxEntry(bob, alice.address, { text: 'hi' }, T0, profileBody('maths', { openKey: null })), code('no_inbox'))
    await assert.rejects(inboxEntry(bob, alice.address, { text: 'hi' }, T0, null), code('no_inbox'))
  })

  test('a message names its folder among its signed fields: moved to another inbox, it is no longer its sender’s', async () => {
    const e = await toAlice('for Alice only')
    const { message } = await openInbox(e, aliceOpening.identity)
    assert.equal(message.to, alice.address)
    assert.equal(checkMessage(message), true)
    assert.equal(checkMessage({ ...message, to: aliceBuyer.address }), false, 'to is signed')
    // Alice locks Bob's message to her other profile, as if Bob had written there: refused [to].
    const moved = { v: 1 as const, to: aliceBuyer.address, ...(await lock(message, [aliceBuyerOpening.openKey])) }
    await assert.rejects(openInbox(moved, aliceBuyerOpening.identity), code('to'))
    // And with its to changed to match: its signature no longer holds [signature].
    const rewritten = { v: 1 as const, to: aliceBuyer.address, ...(await lock({ ...message, to: aliceBuyer.address }, [aliceBuyerOpening.openKey])) }
    await assert.rejects(openInbox(rewritten, aliceBuyerOpening.identity), code('signature'))
  })

  test('a message is exact: its fields, a body that is an object, host an origin, key an access key; the key must be the one named', async () => {
    assert.throws(() => signMessage(bob, alice.address, 'hi' as never, T0), code('body'))
    assert.throws(() => signMessage(bob, 'not an address', { text: 'hi' }, T0), code('key'))
    assert.throws(() => signMessage(bob, alice.address, { text: 'hi' }, T0, 'https://a.example/inbox'), code('shape'))
    assert.throws(() => signMessage(bob, alice.address, { text: 'hi' }, T0, 'http://a.example'), code('shape'))
    assert.throws(() => signMessage({ ...bob, address: alice.address }, alice.address, { text: 'hi' }, T0), /not the one named to sign/)
    const m = signMessage(bob, alice.address, { text: 'hi' }, T0)
    const locked = async (value: object) => ({ v: 1 as const, to: alice.address, ...(await lock(value as never, [aliceOpening.openKey])) })
    await assert.rejects(openInbox(await locked({ ...m, path: 'x' }), aliceOpening.identity), code('shape'))
    await assert.rejects(openInbox(await locked({ ...m, key: bob.address }), aliceOpening.identity), code('key'), 'key is never from’s own main key')
    const unsigned = { from: bob.address, to: alice.address, time: T0, body: { text: 'hi' } }
    const posing = { ...unsigned, sig: signAs(stranger, stranger.address, messageSigningInput(unsigned)) }
    await assert.rejects(openInbox(await locked(posing), aliceOpening.identity), code('signature'), 'a key that is not from’s, unnamed')
  })

  test('an access key messages as its profile only while that profile’s entry lists it with message: the recipient’s app checks', async () => {
    const e = await toAlice('from Bob’s assistant', { profile: bob.address, key: bobsKey })
    const { message } = await openInbox(e, aliceOpening.identity)
    assert.deepEqual([message.from, message.key], [bob.address, bobsKey.address])
    assert.equal(senderCounts(message, bobsProfile), true)
    assert.equal(senderCounts(message, { ...bobsProfile, keys: [listed(['write'], bobsKey)] }), false, 'listed, but not with message')
    assert.equal(senderCounts(message, { ...bobsProfile, keys: [] }), false, 'removed')
    assert.equal(senderCounts(message, null), false, 'no profile entry')
    const fromMain = (await openInbox(await toAlice('from Bob himself'), aliceOpening.identity)).message
    assert.equal(senderCounts(fromMain, null), true, 'the main key needs no listing')
  })
})

describe('leave and list', () => {
  test('a sender reads the profile entry, locks to its keys, leaves the entry with each host; anyone lists it; the main key and a read-inbox key open it; no host reads it, and no folder lists it', async () => {
    const h1 = await startHost({ now: () => T0 })
    const h2 = await startHost({ now: () => T0 })
    try {
      const body = { ...alicesProfile, hosts: [h1.url, h2.url] }
      await write([h1.url, h2.url], [entry(alice, 'profile', body, T0)])
      // Bob's app knows one host; the profile entry gives the rest, and the keys to lock to.
      const folder = await readFolder([h1.url], alice.address, T0)
      const e = await inboxEntry(bob, alice.address, { text: 'Is Tuesday at six free?' }, T0, folder.current.get('profile')!.entry.body!)
      assert.deepEqual((await leave(folder.hosts, [e])).map((o) => o.results.map((r) => r.error ?? 'ok')), [['ok'], ['ok']])
      for (const h of [h1, h2]) {
        const page = await readInbox(h.url, alice.address)
        assert.deepEqual(page.refused, [])
        assert.equal(page.entries.length, 1)
        for (const identity of [aliceOpening.identity, access.identity]) assert.equal((await openInbox(page.entries[0]!.entry, identity)).message.body.text, 'Is Tuesday at six free?')
        assert.ok(!h.dump().join('\n').includes('Tuesday'))
        assert.ok(!h.dump().join('\n').includes(bob.address), 'nor who wrote')
        assert.equal((await readAll(h.url)).entries.length, 1, 'an inbox entry is not an entry of a folder')
      }
    } finally {
      await h1.close()
      await h2.close()
    }
  })

  test('an inbox lists after the cursor, in arrival order, paged as the host chooses, one folder’s', async () => {
    const h = await startHost({ now: () => T0 })
    h.page = 2
    try {
      const buyerProfile = { market: 'tutoring', role: 'buyer', hosts: [h.url], openKey: aliceBuyerOpening.openKey }
      await write([h.url], [entry(alice, 'profile', { ...alicesProfile, hosts: [h.url] }, T0), entry(aliceBuyer, 'profile', buyerProfile, T0)])
      const texts = ['one', 'two', 'three', 'four', 'five']
      for (const [i, text] of texts.entries()) {
        const forBuyer = await inboxEntry(bob, aliceBuyer.address, { text: 'for the buyer' }, T0 + i, buyerProfile)
        await leave([h.url], i === 2 ? [forBuyer, await toAlice(text, bob, T0 + i)] : [await toAlice(text, i % 2 ? { profile: bob.address, key: bobsKey } : bob, T0 + i)])
      }
      const got: string[] = []
      let cursor = 0
      for (let pages = 0; ; pages++) {
        const page = await readInbox(h.url, alice.address, { after: cursor })
        assert.ok(page.entries.length <= 2)
        for (const c of page.entries) got.push((await openInbox(c.entry, aliceOpening.identity)).message.body.text as string)
        if (page.cursor === cursor) {
          assert.equal(pages, 3)
          break
        }
        cursor = page.cursor
      }
      assert.deepEqual(got, texts)
      assert.deepEqual((await readInbox(h.url, alice.address, { after: cursor })).entries, [], 'nothing new since the cursor')
      assert.equal((await readInbox(h.url, aliceBuyer.address)).entries.length, 1)
    } finally {
      await h.close()
    }
  })

  test('a host that slips in an inbox entry for another folder, or one not canonical: the reader refuses each', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      await write([h.url], [entry(alice, 'profile', { ...alicesProfile, hosts: [h.url] }, T0)])
      const e = await toAlice('real')
      await leave([h.url], [e])
      const toBob = await inboxEntry(alice, bob.address, { text: 'x' }, T0, bobsProfile)
      const serve = h.readInbox.bind(h)
      h.readInbox = (to, after) => {
        const out = serve(to, after)
        return { lines: [...out.lines, encodeInbox(toBob), JSON.stringify(e, null, 1).replaceAll('\n', '')], cursor: out.cursor }
      }
      const page = await readInbox(h.url, alice.address)
      assert.equal(page.entries.length, 1)
      assert.deepEqual(page.refused.map((r) => r.reason), ['to', 'canonical'])
      assert.deepEqual(await openLocked({ private: page.entries[0]!.entry.private }, aliceOpening.identity).then((m) => m.body), { text: 'real' })
    } finally {
      await h.close()
    }
  })
})
