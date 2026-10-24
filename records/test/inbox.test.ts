// The inbox: a profile record declares one, anyone may deliver a sealed message to it on the
// profile's hosts, sealed to its inbox key, and only the profile's main key pulls it. Each check a
// host runs on a delivery is tried here, in the standard's order, and so is each way to pull what is
// not yours. The issuer rule runs proofs/note/client's own verifier on the example profile record's
// note proof.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, test } from 'node:test'
import { inboxKey, pointOf } from '@foundationforest/keys'
import { verifyNote } from '@foundationforest/note'
import { canonical } from '../src/canonical.ts'
import { deliver, publish, pull, readAll, readProfile } from '../src/client.ts'
import { DEFAULT_MAX_LINE_BYTES, type Host, type HostOptions } from '../src/host.ts'
import type { Key } from '../src/keys.ts'
import { type Sender, type SignedMessage, encodeMessage, inboxKeyOf, inboxOf, messageSigningInput, pullRequest, pullSigningInput, readMessage, signMessage, verifyMessage } from '../src/message.ts'
import { makePrivate, message, openMessage } from '../src/private.ts'
import type { NoteCheck } from '../src/proofs.ts'
import { type Body, RecordError, signAs } from '../src/record.ts'
import { hostsRecord, ownerRecord } from '../src/write.ts'
import { DAY, MINUTE, T0, alice, aliceBuyer, bob, profileBody, stranger } from './fixtures.ts'
import { Clock, startHost } from './helpers.ts'

const [aliceInbox, aliceBuyerInbox, bobInbox] = await Promise.all([inboxKey(alice.secret), inboxKey(aliceBuyer.secret), inboxKey(bob.secret)])
/** The example profile record (schemas/examples/profile.json) is Alice's: its note proof is from an example issuer, for her key. */
const EXAMPLE = JSON.parse(readFileSync(new URL('../schemas/examples/profile.json', import.meta.url), 'utf8'))
const NOTE_PROOF = EXAMPLE.proofs.find((p: { circuit: string }) => p.circuit === 'note')
/** That issuer, named by its key's address. */
const ISSUER: string = NOTE_PROOF.issuer

const profileWith = (inbox?: Body | string, subject = 'maths') => ({ ...profileBody(subject), inboxKey: aliceInbox.sealTo, ...(inbox !== undefined && { inbox }) })
const ANYONE = { senders: 'anyone' }

/** A host, at T0 unless given a clock, holding Alice's profile record with this inbox. */
async function hostWith(inbox: Body | string | undefined, options: HostOptions = {}): Promise<Host> {
  const h = await startHost({ now: () => T0, ...options })
  await publish([h.url], [ownerRecord(alice, 'profile', profileWith(inbox), T0)])
  return h
}
const note = (from: Sender = bob, text = 'Is Tuesday at six free?', time = T0) => message(from, alice.address, { text, createdAt: '2026-10-02T12:00:00Z' }, time, profileWith(ANYONE))
const errors = async (h: Host, messages: SignedMessage[]) => (await deliver([h.url], messages))[0]!.results.map((r) => r.error ?? 'ok')
const pulled = async (h: Host, after = 0, time = T0, owner: Key = alice) => pull(h.url, pullRequest(owner, after, time))
const refusal = async (promise: Promise<unknown>) => promise.then(() => 'ok', (err: unknown) => (err instanceof RecordError ? err.code : String(err)))
const code = (c: string) => (err: unknown) => err instanceof RecordError && err.code === c

/** How a host reads a sender's records: from the host the message names, each checked. */
const readSender = async (url: string, profile: string) => (await readAll(url, { profile })).records
const bobProfile = { ...profileBody('maths'), role: 'buyer', inboxKey: bobInbox.sealTo, inbox: ANYONE }
const toBob = (sender: Sender, text = 'Tuesday works.') => message(sender, bob.address, { text }, T0, bobProfile)

/** Alice's folder on her own host, with her profile record; Bob's inbox on another host, which reads senders' records. */
async function twoHosts(options: HostOptions = {}, aliceProfile: Body = profileWith(ANYONE)) {
  const home = await startHost({ now: () => T0, readSender })
  const inbox = await startHost({ now: () => T0, readSender, ...options })
  await publish([home.url], [hostsRecord(alice, [home.url], T0), ownerRecord(alice, 'profile', aliceProfile, T0)])
  await publish([inbox.url], [ownerRecord(bob, 'profile', bobProfile, T0)])
  return {
    home,
    inbox,
    close: async () => {
      await home.close()
      await inbox.close()
    },
  }
}

describe('messages', () => {
  test('a message is sealed to the profile record’s inbox key and signed by from; only that key opens it', async () => {
    const m = await note()
    assert.deepEqual(Object.keys(m.body), ['private'])
    assert.equal(m.from, bob.address)
    const opened = await openMessage(m, aliceInbox.identity)
    assert.deepEqual([opened.from, opened.to, opened.time, opened.body.text], [bob.address, alice.address, T0, 'Is Tuesday at six free?'])
    assert.equal(opened.id, readMessage(encodeMessage(m)).id)
    assert.match(opened.id, /^[0-9a-f]{64}$/, 'lowercase hex, as a record’s id')
    await assert.rejects(openMessage(m, aliceBuyerInbox.identity), 'the same person’s other profile cannot open it')
  })

  test('a body is { private } and nothing else; the key must be from’s', async () => {
    const sealed = await makePrivate({ text: 'hi' }, [aliceInbox.sealTo])
    assert.throws(() => signMessage(bob, alice.address, { text: 'hi' } as never, T0), /body/)
    assert.throws(() => signMessage(bob, alice.address, { ...sealed, extra: 'x' } as never, T0), /body/)
    assert.throws(() => signMessage(bob, 'not an address', sealed, T0), /to is not/)
    assert.throws(() => signMessage({ ...bob, address: alice.address }, alice.address, sealed, T0), /not the one named to sign/)
    const m = signMessage(bob, alice.address, sealed, T0)
    for (const [text, code] of [
      [JSON.stringify(m, null, 1), 'canonical'],
      [canonical({ ...m, path: 'x' }), 'shape'],
      [canonical({ ...m, v: 2 }), 'version'],
      [canonical({ ...m, time: -1 }), 'time'],
    ] as const) assert.throws(() => readMessage(text), (err: RecordError) => err.code === code, code)
  })

  test('the profile record’s inbox: none, open to anyone, an issuer’s rule; anything this code does not know is unsupported', () => {
    assert.equal(inboxOf(null), null)
    assert.equal(inboxOf(profileWith()), null)
    assert.equal(inboxOf({ private: 'abc' }), null, 'a private profile record declares nothing a host can read')
    assert.deepEqual(inboxOf(profileWith(ANYONE)), { senders: 'anyone' })
    assert.deepEqual(inboxOf(profileWith({ senders: { issuer: ISSUER }, once: true, maxBytes: 4000 })), { senders: { issuer: ISSUER }, once: true, maxBytes: 4000 })
    for (const inbox of ['anyone', {}, { senders: 'everyone' }, { senders: { deposit: '5' } }, { senders: { issuer: 'x' } }, { senders: { issuer: pointOf(ISSUER).map((n) => n.toString(16).padStart(64, '0')).join('') } }, { senders: { issuer: pointOf(ISSUER).map(String) } }, { senders: { issuer: ISSUER.slice(1) } }, { senders: { issuer: ISSUER + '1' } }, { senders: { issuer: ISSUER, label: 'x' } }, { ...ANYONE, once: false }, { ...ANYONE, maxBytes: -1 }, { ...ANYONE, deposit: '5' }, { ...ANYONE, readers: [aliceBuyerInbox.sealTo] }]) {
      assert.equal(inboxOf(profileWith(inbox as Body)), 'unsupported', JSON.stringify(inbox))
    }
  })
})

describe('sealing', () => {
  test('a message is sealed to the inbox key the profile record gives, and nothing else', async () => {
    assert.equal(inboxKeyOf(profileWith(ANYONE)), aliceInbox.sealTo)
    const m = await message(bob, alice.address, { text: 'hi' }, T0, profileWith(ANYONE))
    assert.equal((await openMessage(m, aliceInbox.identity)).body.text, 'hi')
    await assert.rejects(openMessage(m, aliceBuyerInbox.identity))
  })

  test('a sender seals to nobody when the profile record gives no inbox key, no inbox, or an inbox this code cannot read: a field it does not know could name more keys', async () => {
    const { inboxKey: _, ...noKey } = profileWith(ANYONE)
    for (const c of [profileWith(), noKey, profileWith({ ...ANYONE, sealTo: 'x' }), profileWith({ ...ANYONE, readers: [aliceBuyerInbox.sealTo] })]) assert.throws(() => inboxKeyOf(c), code('no_inbox'), JSON.stringify(c.inbox))
    await assert.rejects(message(bob, alice.address, { text: 'hi' }, T0, profileWith()), code('no_inbox'))
  })
})

describe('deliver and pull', () => {
  test('a sender reads the profile record, seals to its inbox key, delivers to each host; the main key pulls from each and opens; no host reads it, and no record lists it', async () => {
    const h1 = await startHost({ now: () => T0 })
    const h2 = await startHost({ now: () => T0 })
    try {
      await publish([h1.url, h2.url], [hostsRecord(alice, [h1.url, h2.url], T0), ownerRecord(alice, 'profile', profileWith(ANYONE), T0)])
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

  test('a host checks a delivery in order: shape, future, duplicate, no inbox, signature', async () => {
    const h = await hostWith(ANYONE)
    try {
      const m = await note()
      const forged = { ...(await note(stranger)), from: bob.address } // stranger signed, claims to be Bob
      const results = await h.deliver([
        'not json',
        canonical({ ...m, path: 'x' }),
        encodeMessage({ ...m, body: { private: m.body.private, text: 'x' } } as never),
        encodeMessage(await note(bob, 'later', T0 + 10 * MINUTE + 1)),
        encodeMessage(m),
        encodeMessage(m),
        encodeMessage({ ...m, to: bob.address }),
        encodeMessage(forged),
        encodeMessage({ ...m, time: T0 - 1 }),
      ])
      assert.deepEqual(results.map((r) => r.error ?? 'ok'), ['canonical', 'shape', 'body', 'future', 'ok', 'duplicate', 'no_inbox', 'signature', 'signature'])
      assert.deepEqual(await errors(h, [m]), ['duplicate'], 'in a later request too')
      // Cheap checks first: a forged message to a profile with no inbox is refused before its signature is checked.
      assert.deepEqual(await errors(h, [{ ...forged, to: aliceBuyer.address }]), ['no_inbox'])
    } finally {
      await h.close()
    }
  })

  test('size is the host’s own choice, checked first: 65,536 bytes here unless its operator says otherwise', async () => {
    const big = signMessage(bob, alice.address, { private: 'A'.repeat(DEFAULT_MAX_LINE_BYTES) }, T0)
    const h = await hostWith(ANYONE)
    const roomy = await hostWith(ANYONE, { maxLineBytes: 2 * DEFAULT_MAX_LINE_BYTES })
    try {
      assert.deepEqual(await errors(h, [big]), ['size'])
      assert.deepEqual(await h.deliver(['x'.repeat(DEFAULT_MAX_LINE_BYTES + 1)]).then((r) => r.map((x) => x.error)), ['size'], 'before its shape')
      assert.deepEqual(await errors(roomy, [big]), ['ok'])
    } finally {
      await h.close()
      await roomy.close()
    }
  })

  test('a message from the profile it is to skips the inbox’s rules: its issuer rule, an inbox the host cannot read, once and maxBytes', async () => {
    const toSelf = async (text: string) => signMessage(alice, alice.address, await makePrivate({ text }, [aliceInbox.sealTo]), T0)
    for (const inbox of [{ senders: { issuer: ISSUER }, once: true, maxBytes: 100 }, { ...ANYONE, deposit: '5' }] as Body[]) {
      const h = await hostWith(inbox)
      try {
        assert.deepEqual(await errors(h, [await toSelf('From my phone'), await toSelf('From my laptop')]), ['ok', 'ok'], JSON.stringify(inbox))
        assert.deepEqual(await errors(h, [await note(bob)]), ['rule_unsupported'], 'anyone else still meets them')
      } finally {
        await h.close()
      }
    }
    const h = await hostWith(undefined)
    try {
      assert.deepEqual(await errors(h, [await toSelf('hi')]), ['no_inbox'], 'with no inbox there is still none')
    } finally {
      await h.close()
    }
  })

  test('no inbox field, no inbox: a profile record without one, none, a deleted one, and one on another host', async () => {
    const h = await hostWith(undefined)
    const other = await startHost({ now: () => T0 })
    try {
      assert.deepEqual(await errors(h, [await note()]), ['no_inbox'])
      await publish([other.url], [ownerRecord(alice, 'profile', profileWith(ANYONE), T0 + 1)])
      assert.deepEqual(await errors(h, [await note()]), ['no_inbox'], 'only the profile record on this host counts')
      await publish([h.url], [ownerRecord(alice, 'profile', profileWith(ANYONE), T0 + 1)])
      assert.deepEqual(await errors(h, [await note()]), ['ok'])
      await publish([h.url], [ownerRecord(alice, 'profile', null, T0 + 2)])
      assert.deepEqual(await errors(h, [await note()]), ['no_inbox'], 'a deleted profile record')
      assert.deepEqual(await errors(h, [await message(bob, bob.address, { text: 'x' }, T0, profileWith(ANYONE))]), ['no_inbox'], 'a profile this host has never seen')
    } finally {
      await h.close()
      await other.close()
    }
  })

  test('the issuer rule: from’s profile record, read from the host the message names, carries a note proof from that issuer that holds for from, under any label; a host that checks none answers rule_unsupported; a check that fails is lookup, never sender', async () => {
    assert.equal(NOTE_PROOF.label, 'tutoring/seller', 'the example profile record is Alice’s')
    const checked: string[] = []
    const counted = async (input: NoteCheck) => (checked.push(input.profile), verifyNote(input))
    const { home, inbox, close } = await twoHosts({ verifyNote: counted }, { ...profileWith(ANYONE), proofs: [NOTE_PROOF] })
    const none = await startHost({ now: () => T0, readSender })
    let down = true
    const flaky = await startHost({
      now: () => T0,
      readSender,
      verifyNote: async (input) => {
        if (down) throw new Error('verifier unreachable')
        return verifyNote(input)
      },
    })
    try {
      const ruled = (issuer: string, time = T0 + 1) => ownerRecord(bob, 'profile', { ...bobProfile, inbox: { senders: { issuer } } }, time)
      for (const h of [inbox, none, flaky]) await publish([h.url], [ruled(ISSUER)])
      // Alice's other profile carries her proof too, copied: it holds only for the key it was made for.
      await publish([home.url], [hostsRecord(aliceBuyer, [home.url], T0), ownerRecord(aliceBuyer, 'profile', { ...profileBody('x'), role: 'buyer', proofs: [NOTE_PROOF] }, T0)])
      const fromHome = (from: Key) => ({ from, host: home.url })
      assert.deepEqual(
        await errors(inbox, [await toBob(fromHome(alice)), await toBob(alice, 'naming no host'), await toBob(fromHome(aliceBuyer), 'a proof made for another key'), await toBob(fromHome(stranger), 'no records there')]),
        ['ok', 'sender', 'sender', 'sender'],
      )
      assert.deepEqual(checked, [alice.address, aliceBuyer.address], 'each proof checked for the profile whose profile record carries it')
      await publish([inbox.url], [ruled(stranger.address, T0 + 2)])
      assert.deepEqual(await errors(inbox, [await toBob(fromHome(alice), 'another issuer')]), ['sender'])

      assert.deepEqual(await errors(none, [await toBob(fromHome(alice))]), ['rule_unsupported'])
      const m = await toBob(fromHome(alice))
      const [outcome] = await deliver([flaky.url], [m])
      assert.equal(outcome!.results[0]!.error, 'lookup')
      assert.match(outcome!.results[0]!.message!, /verifier unreachable/)
      down = false
      assert.deepEqual(await errors(flaky, [m]), ['ok'], 'the same message, again: nothing was kept the first time')
      // A host that checks no note proof still takes an inbox open to anyone.
      await publish([none.url], [ownerRecord(bob, 'profile', bobProfile, T0 + 2)])
      assert.deepEqual(await errors(none, [await toBob(aliceBuyer)]), ['ok'])
    } finally {
      await close()
      await none.close()
      await flaky.close()
    }
  })

  test('an inbox the host cannot read is refused as rule_unsupported, never taken as open to anyone', async () => {
    for (const inbox of [{ senders: { deposit: '5' } }, { ...ANYONE, deposit: '5' }, { ...ANYONE, once: 'yes' }, 'anyone']) {
      const h = await hostWith(inbox as Body, { readSender, verifyNote: async () => true })
      try {
        assert.deepEqual(await errors(h, [await note()]), ['rule_unsupported'], JSON.stringify(inbox))
      } finally {
        await h.close()
      }
    }
  })

  test('once: a second message from the same sender is refused, ever; a refused first does not use it up; the pair is kept only while the inbox says once', async () => {
    const clock = new Clock(T0)
    const h = await startHost({ now: clock.now })
    try {
      await publish([h.url], [ownerRecord(alice, 'profile', profileWith({ ...ANYONE, once: true, maxBytes: 4000 }), T0)])
      assert.deepEqual(await errors(h, [await note(bob, 'x'.repeat(3000))]), ['too_big'])
      assert.deepEqual(await errors(h, [await note(bob), await note(bob, 'And Wednesday?')]), ['ok', 'once'])
      assert.deepEqual(await errors(h, [await note(aliceBuyer)]), ['ok'], 'another sender')
      await h.prune(T0 + 31 * DAY)
      assert.equal((await pulled(h)).messages.length, 0, 'the messages went after keep days')
      assert.deepEqual(await errors(h, [await note(bob, 'Still there?')]), ['once'], 'the pair did not')

      // While the inbox is open, no pair is kept: turning once on later gives each sender one more.
      await publish([h.url], [ownerRecord(alice, 'profile', profileWith(ANYONE), T0 + 1)])
      assert.deepEqual(await errors(h, [await note(stranger)]), ['ok'])
      await publish([h.url], [ownerRecord(alice, 'profile', profileWith({ ...ANYONE, once: true }), T0 + 2)])
      assert.deepEqual(await errors(h, [await note(stranger, 'Hello again'), await note(stranger, 'And again')]), ['ok', 'once'])
    } finally {
      await h.close()
    }
  })

  test('maxBytes counts the message’s canonical text, in bytes: too_big', async () => {
    const m = await note()
    const bytes = Buffer.byteLength(encodeMessage(m))
    for (const [maxBytes, result] of [[bytes, 'ok'], [bytes - 1, 'too_big']] as const) {
      const h = await hostWith({ ...ANYONE, maxBytes })
      try {
        assert.deepEqual(await errors(h, [m]), [result], String(maxBytes))
      } finally {
        await h.close()
      }
    }
  })

  test('a host’s own choice comes last, and sees what it holds for the profile it is to', async () => {
    const seen: number[] = []
    const h = await hostWith(ANYONE, {
      messageChoice: (_m, stored) => {
        seen.push(stored.messages)
        return stored.messages < 2 ? null : 'two messages a profile here'
      },
    })
    try {
      const forged = { ...(await note(stranger)), from: bob.address }
      assert.deepEqual(await errors(h, [await note(bob), forged, await note(aliceBuyer), await note(stranger)]), ['ok', 'signature', 'ok', 'refused'])
      assert.deepEqual(seen, [0, 1, 2], 'never asked about a forged one')
    } finally {
      await h.close()
    }
  })

  test('a host chooses its batch: 100 here unless told otherwise; a client sends a bigger request in halves', async () => {
    const h = await hostWith(ANYONE, { maxBatch: 2 })
    const reference = await hostWith(ANYONE)
    try {
      const five = await Promise.all([1, 2, 3, 4, 5].map((i) => note(bob, `note ${i}`)))
      assert.deepEqual(await h.deliver(five.map(encodeMessage)), [{ i: 0, ok: false, error: 'batch', message: 'at most 2 messages a request' }])
      const [outcome] = await deliver([h.url], five)
      assert.deepEqual(outcome!.results.map((r) => [r.i, r.error ?? 'ok']), five.map((_, i) => [i, 'ok']))
      assert.equal((await reference.deliver(Array(101).fill('x')))[0]!.error, 'batch')
    } finally {
      await h.close()
      await reference.close()
    }
  })
})

describe('naming a host', () => {
  test('a message may name host, one of from’s hosts, where an inbox with an issuer’s rule reads from’s profile record; no other key signs, and no field names one', async () => {
    const sealed = await makePrivate({ text: 'hi' }, [bobInbox.sealTo])
    const own = signMessage({ from: alice, host: 'https://host-a.example' }, bob.address, sealed, T0)
    assert.deepEqual([own.from, own.host], [alice.address, 'https://host-a.example'])
    assert.ok(verifyMessage(readMessage(encodeMessage(own))))
    const { host: _h, ...noHost } = own
    assert.equal(verifyMessage(readMessage(canonical(noHost))), false, 'no host is a shape that holds, and from did not sign this')
    for (const [why, value, c] of [
      ['a key beside from', { ...own, key: stranger.address }, 'shape'],
      ['host with a path', { ...own, host: 'https://a.example/inbox' }, 'shape'],
      ['host over http', { ...own, host: 'http://a.example' }, 'shape'],
    ] as const) assert.throws(() => readMessage(canonical(value)), code(c), why)
    // A message signed by a key that is not from's: refused [signature].
    const unsigned = { v: 1 as const, to: bob.address, from: alice.address, time: T0, body: sealed }
    assert.equal(verifyMessage(readMessage(canonical({ ...unsigned, sig: signAs(stranger, stranger.address, messageSigningInput(unsigned)) }))), false)
  })

  test('within one request a host reads a sender’s records once; the next request reads them again', async () => {
    let reads = 0
    const counted = async (url: string, profile: string) => (reads++, readSender(url, profile))
    const { home, inbox, close } = await twoHosts({ readSender: counted, verifyNote }, { ...profileWith(ANYONE), proofs: [NOTE_PROOF] })
    try {
      await publish([inbox.url], [ownerRecord(bob, 'profile', { ...bobProfile, inbox: { senders: { issuer: ISSUER } } }, T0 + 1)])
      const fromHome = { from: alice, host: home.url }
      assert.deepEqual(await errors(inbox, [await toBob(fromHome, 'one'), await toBob(fromHome, 'two')]), ['ok', 'ok'])
      assert.equal(reads, 1)
      assert.deepEqual(await errors(inbox, [await toBob(fromHome, 'three')]), ['ok'])
      assert.equal(reads, 2)
    } finally {
      await close()
    }
  })
})

describe('pulling', () => {
  test('only the main key pulls: another profile’s key, a key that is no profile’s, or a changed request is refused as signature', async () => {
    const h = await hostWith(ANYONE)
    try {
      await deliver([h.url], [await note()])
      const mine = pullRequest(alice, 0, T0)
      assert.equal((await pull(h.url, mine)).messages.length, 1)
      assert.equal(await refusal(pull(h.url, { ...pullRequest(bob, 0, T0), profile: alice.address })), 'signature')
      const unsigned = { v: 1 as const, profile: alice.address, after: 0, time: T0 }
      assert.equal(await refusal(pull(h.url, { ...unsigned, sig: signAs(stranger, stranger.address, pullSigningInput(unsigned)) })), 'signature', 'a key that is not the main key')
      assert.equal(await refusal(pull(h.url, { ...mine, key: stranger.address } as never)), 'shape', 'no field names another key')
      assert.equal(await refusal(pull(h.url, { ...pullRequest(aliceBuyer, 0, T0), profile: alice.address })), 'signature', 'the same person’s other profile')
      assert.equal(await refusal(pull(h.url, { ...mine, after: 1 })), 'signature')
      // Bob's own pull is fine, and finds nothing: messages go to the profile they are to only.
      assert.equal((await pull(h.url, pullRequest(bob, 0, T0))).messages.length, 0)
    } finally {
      await h.close()
    }
  })

  test('a pull is signed within ten minutes of the host’s clock, either way: stale', async () => {
    const h = await hostWith(ANYONE)
    try {
      for (const [time, result] of [[T0 - 10 * MINUTE, 'ok'], [T0 + 10 * MINUTE, 'ok'], [T0 - 10 * MINUTE - 1, 'stale'], [T0 + 10 * MINUTE + 1, 'stale']] as const) {
        assert.equal(await refusal(pulled(h, 0, time)), result, String(time - T0))
      }
    } finally {
      await h.close()
    }
  })

  test('a pull answers that profile’s messages after the cursor, in arrival order, paged as the host chooses', async () => {
    const h = await hostWith(ANYONE, { maxPageRecords: 2 })
    try {
      const buyerProfile = { ...profileWith(ANYONE, 'algebra'), inboxKey: aliceBuyerInbox.sealTo }
      await publish([h.url], [ownerRecord(aliceBuyer, 'profile', buyerProfile, T0)])
      const toBuyer = await message(bob, aliceBuyer.address, { text: 'for the buyer' }, T0, buyerProfile)
      const texts = ['one', 'two', 'three', 'four', 'five']
      for (const [i, text] of texts.entries()) await deliver([h.url], i === 2 ? [toBuyer, await note(bob, text)] : [await note(i % 2 ? stranger : bob, text)])
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

  test('a pull is a POST, so no URL carries it; GET is 405, and a pull that is not canonical is refused', async () => {
    const h = await hostWith(ANYONE)
    try {
      assert.equal((await fetch(`${h.url}/v1/inbox/pull`)).status, 405)
      assert.equal((await fetch(`${h.url}/v1/inbox`)).status, 405)
      const res = await fetch(`${h.url}/v1/inbox/pull`, { method: 'POST', body: JSON.stringify(pullRequest(alice, 0, T0), null, 1) })
      assert.deepEqual([res.status, ((await res.json()) as { error: string }).error], [400, 'canonical'])
    } finally {
      await h.close()
    }
  })

  test('a host that slips in a forged message, or one to someone else: the reader refuses each', async () => {
    const h = await hostWith(ANYONE)
    try {
      const m = await note()
      await deliver([h.url], [m])
      const toBob = await message(alice, bob.address, { text: 'x' }, T0, profileWith(ANYONE))
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
