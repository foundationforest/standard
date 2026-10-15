// Trying hard to break each promise. Every test names the promise and says what was tried; a test
// that shows an attack succeeding says so in its name (FINDING), and README.md lists it as a limit.
// Other attack tests live next to the code they attack: host.test.ts, view.test.ts, private.test.ts.

import assert from 'node:assert/strict'
import { after, before, describe, test } from 'node:test'
import { sha256 } from '@noble/hashes/sha2.js'
import { Base8, addPoint, mulPointEscalar } from '@zk-kit/baby-jubjub'
import { verifySignature as zkVerify } from '@zk-kit/eddsa-poseidon'
import { poseidon5 } from 'poseidon-lite/poseidon5'
import { BN254_R, SUBGROUP_ORDER, accessKey as makeAccessKey, bytesMessage, inboxKey, packSignature, unpackSignature, verifyWithPublicKey } from '../../keys/src/index.ts'
import { b64u, base58, concat, hex, utf8 } from '../src/bytes.ts'
import { deliver, publish, readAll, readProfile } from '../src/client.ts'
import type { Host } from '../src/host.ts'
import { MESSAGE_PREFIX, PULL_PREFIX } from '../src/message.ts'
import { message } from '../src/private.ts'
import { SIGN_PREFIX, checkRecord, encodeRecord, signingInput, unsignedOf, verifySignature } from '../src/record.ts'
import { viewProfile } from '../src/view.ts'
import { accessRecord, hostsRecord, ownerRecord, permissionsRecord } from '../src/write.ts'
import { DAY, MINUTE, SEED, T0, accessKey, alice, aliceBuyer, allow, bob, offerBody, pastKey, profileBody } from './fixtures.ts'
import { startHost } from './helpers.ts'

const L = SUBGROUP_ORDER
const le = (n: bigint, len = 32) => Uint8Array.from({ length: len }, (_, i) => Number((n >> BigInt(8 * i)) & 255n))
const fromLe = (b: Uint8Array) => b.reduceRight((acc, byte) => (acc << 8n) + BigInt(byte), 0n)
/** The point of order 2 on Baby Jubjub: on the curve, in no key's subgroup. */
const ORDER_2: [bigint, bigint] = [0n, BN254_R - 1n]

describe('nobody forges; a signature means one thing everywhere', () => {
  const record = ownerRecord(alice, 'offer/a', offerBody('30'), T0)
  const message = signingInput(unsignedOf(record))
  const sig = b64u.decode(record.sig)

  test("a valid signature: ours and zk-kit's agree", () => {
    assert.equal(verifySignature(sig, message, alice.address), true)
    assert.equal(zkVerify(bytesMessage(message), unpackSignature(sig)!, alice.publicKey), true)
  })

  test('a second spelling of the same signature (S + l) is refused, and could not make a new id anyway', () => {
    const S = fromLe(sig.subarray(32))
    const malleated = concat(sig.subarray(0, 32), le(S + L))
    assert.equal(verifySignature(malleated, message, alice.address), false)
    assert.equal(zkVerify(bytesMessage(message), { R8: unpackSignature(sig)!.R8, S: S + L }, alice.publicKey), false)
    assert.throws(() => checkRecord({ ...record, sig: b64u.encode(malleated) }), /signature/)
  })

  test("a small-order key: (R8 = identity, S = 0) verifies any message for it under zk-kit's check; Forest refuses the key outright", (t) => {
    const universal = { R8: [0n, 1n] as [bigint, bigint], S: 0n }
    assert.equal(verifyWithPublicKey(ORDER_2, bytesMessage(message), universal), false)
    assert.equal(verifySignature(packSignature(universal), message, ORDER_2), false)
    t.diagnostic(`zk-kit's verifySignature accepts the universal signature for the key of order 2: ${zkVerify(bytesMessage(message), universal, ORDER_2)}`)
    // A permissions record naming a small-order access key cannot even be written.
    const packed = le(ORDER_2[1])
    assert.throws(() => permissionsRecord(alice, [{ key: base58.encode(packed), scope: 'write', paths: ['offer'] }], T0), /usable/)
  })

  test("a mixed-order key (the owner's key plus the point of order 2): zk-kit's check takes the owner's signatures for it; Forest refuses it", () => {
    // (x, y) + (0, -1) = (-x, -y). Signed with Alice's scalar but the mixed key in the hash, the
    // equation still holds, because 8 times the order-2 point is the identity.
    const mixed = addPoint(alice.publicKey, ORDER_2) as [bigint, bigint]
    assert.deepEqual(mixed, [BN254_R - alice.publicKey[0], BN254_R - alice.publicKey[1]])
    const m = bytesMessage(utf8('a message'))
    const r = 12345n
    const R8 = mulPointEscalar(Base8, r) as [bigint, bigint]
    const hm = poseidon5([R8[0], R8[1], mixed[0], mixed[1], m])
    const forged = { R8, S: (r + 8n * hm * alice.scalar) % L }
    assert.equal(zkVerify(m, forged, mixed), true, 'zk-kit takes it: it checks only that a key is on the curve')
    assert.equal(verifyWithPublicKey(mixed, m, forged), false, 'Forest takes no key outside the subgroup')
  })

  test('the signed bytes of a record, a message, a pull and an index root each start with their own text', () => {
    const texts = [SIGN_PREFIX, MESSAGE_PREFIX, PULL_PREFIX, concat(Uint8Array.of(0xff), utf8('forest/v1/reputation\n'))]
    for (const [i, a] of texts.entries()) {
      for (const [j, b] of texts.entries()) if (i !== j) assert.notDeepEqual(a.subarray(0, Math.min(a.length, b.length)), b.subarray(0, Math.min(a.length, b.length)), 'no text begins another')
    }
  })

  test('replaying a record into another profile, path or time fails; the same record twice is one record', () => {
    for (const change of [{ profile: bob.address }, { path: 'offer/b' }, { time: T0 + 1 }]) {
      assert.throws(() => checkRecord({ ...record, ...change }), /signature/)
    }
    assert.equal(checkRecord(record).id, checkRecord(JSON.parse(encodeRecord(record))).id)
  })
})

describe('a stolen access key', () => {
  const permissions = permissionsRecord(alice, [allow(accessKey, ['offer'])], T0)
  const mine = ownerRecord(alice, 'offer/maths', offerBody('30'), T0)
  const view = (...records: Parameters<typeof checkRecord>[0][]) => viewProfile(alice.address, records.map((r) => checkRecord(r)), T0 + DAY)

  test('cannot rewrite or delete what the owner wrote, cannot touch hosts or permissions, cannot write outside its paths', () => {
    const overwrite = accessRecord(accessKey, alice.address, 'offer/maths', offerBody('1'), T0 + DAY)
    const card = accessRecord(accessKey, alice.address, 'profile', profileBody('forgery'), T0 + DAY)
    const v = view(permissions, mine, overwrite, card)
    assert.equal(v.current.get('offer/maths')!.id, checkRecord(mine).id)
    assert.equal(v.current.has('profile'), false)
    assert.throws(() => accessRecord(accessKey, alice.address, 'hosts', { urls: ['https://evil.example'] }, T0 + DAY), /only the owner/)
  })

  test('with no paths, it still cannot write the card', () => {
    const anywhere = permissionsRecord(alice, [allow(accessKey)], T0)
    const card = accessRecord(accessKey, alice.address, 'profile', profileBody('forgery'), T0 + DAY)
    const v = view(anywhere, card)
    assert.equal(v.current.has('profile'), false)
  })

  test('once its entry is deleted, nothing it signed counts, however it is dated, on any host or none', () => {
    const removed = permissionsRecord(alice, [], T0 + MINUTE)
    const before = accessRecord(accessKey, alice.address, 'offer/before', offerBody('1'), T0)
    const after = accessRecord(accessKey, alice.address, 'offer/after', offerBody('1'), T0 + 2 * MINUTE)
    const v = view(removed, before, after)
    assert.deepEqual([v.current.has('offer/before'), v.current.has('offer/after')], [false, false])
  })

  test('FINDING: once past, a stolen key can still write to a host that skips the check, and that host’s readers count it', () => {
    // An honest host refuses it (host.test.ts). A reader counts every record a past key wrote,
    // since it is still listed and no date is checked, so whoever holds a host that takes one can
    // show it. The owner's record wins at that path, so the owner deletes it there.
    const past = permissionsRecord(alice, [pastKey(accessKey, ['offer'])], T0 + MINUTE)
    const sneaked = accessRecord(accessKey, alice.address, 'offer/new', offerBody('1'), T0 + 2 * MINUTE)
    const later = T0 + 365 * DAY
    assert.equal(viewProfile(alice.address, [past, sneaked].map((r) => checkRecord(r)), later).current.has('offer/new'), true)
    const deleted = ownerRecord(alice, 'offer/new', null, T0 + 3 * MINUTE)
    assert.equal(viewProfile(alice.address, [past, sneaked, deleted].map((r) => checkRecord(r)), later).current.get('offer/new')!.record.body, null)
  })
})

describe('a stolen write key that sends', () => {
  test('once past, it cannot send through a host that serves the sender’s old permissions record: the sender’s hosts record does not name that host', async () => {
    const readSender = async (url: string, profile: string) => (await readAll(url, { profile })).records
    const home = await startHost({ now: () => T0 })
    const thief = await startHost({ now: () => T0 }) // keeps copies of Alice's old records: they are public
    const inbox = await startHost({ now: () => T0, readSender })
    try {
      const listed = permissionsRecord(alice, [allow(accessKey, ['inbox'])], T0)
      await publish([home.url], [hostsRecord(alice, [home.url], T0), listed, permissionsRecord(alice, [pastKey(accessKey, ['inbox'])], T0 + 1)])
      await publish([thief.url], [hostsRecord(alice, [home.url], T0), listed])
      const bobInbox = await inboxKey(bob.secret)
      const bobCard = { ...profileBody('chemistry'), inboxKey: bobInbox.recipient, inbox: { senders: 'anyone' } }
      await publish([inbox.url], [ownerRecord(bob, 'profile', bobCard, T0)])
      const send = (host: string) => message({ key: accessKey, from: alice.address, host }, bob.address, { text: 'Send me the money.' }, T0 + 2, bobCard)
      const results = async (host: string) => (await deliver([inbox.url], [await send(host)]))[0]!.results[0]!.error
      assert.equal(await results(thief.url), 'permission', 'the old record, from a host she does not name')
      assert.equal(await results(home.url), 'permission', 'her current record says past')
    } finally {
      await home.close()
      await thief.close()
      await inbox.close()
    }
  })
})

describe('over real hosts', () => {
  let h1: Host
  let h2: Host
  before(async () => {
    h1 = await startHost({ now: () => T0 + 10 * MINUTE })
    h2 = await startHost({ now: () => T0 + 10 * MINUTE })
    const urls = [h1.url, h2.url]
    await publish(urls, [hostsRecord(alice, urls, T0), ownerRecord(alice, 'profile', profileBody('maths'), T0), ownerRecord(alice, 'offer/a', offerBody('1'), T0)])
  })
  after(async () => {
    await h1.close()
    await h2.close()
  })

  test('a deleted offer cannot be brought back by a host that still has the old version', async () => {
    await publish([h1.url], [ownerRecord(alice, 'offer/a', null, T0 + 1)]) // only host 1 hears the delete
    const v = await readProfile([h2.url, h1.url], alice.address, T0 + 10 * MINUTE)
    assert.equal(v.current.get('offer/a')!.record.body, null)
  })

  test('a host holds no key: its whole database holds no secret of the person', async () => {
    const inbox = await inboxKey(alice.secret)
    const disk = [...h1.dump(), ...h2.dump()].join('\n')
    for (const secret of [alice.secret, SEED, le(alice.scalar), le(alice.scalar).reverse()]) {
      for (const form of [hex.encode(secret), b64u.encode(secret), Buffer.from(secret).toString('base64'), base58.encode(secret)]) assert.ok(!disk.includes(form))
    }
    assert.ok(!disk.includes(alice.scalar.toString()), 'nor the main key’s scalar')
    assert.ok(!disk.includes(inbox.identity))
  })

  test('a hosts record signed by someone else, naming other hosts, is refused by hosts and readers', async () => {
    const fake = { ...hostsRecord(bob, ['https://evil.example'], T0 + 5), profile: alice.address }
    assert.throws(() => checkRecord(fake), /signature/)
    assert.equal((await h1.accept([encodeRecord(fake)]))[0]!.error, 'signature')
  })

  test('two readers reading different hosts compute the same view', async () => {
    await publish([h2.url], [ownerRecord(alice, 'offer/a', null, T0 + 1)]) // now both hosts hold everything
    const summary = (v: { current: Map<string, { id: string }> }) => [...v.current].map(([p, c]) => `${p}=${c.id}`).sort().join()
    const one = viewProfile(alice.address, (await readAll(h1.url, { profile: alice.address })).records, T0 + 10 * MINUTE)
    const two = viewProfile(alice.address, (await readAll(h2.url, { profile: alice.address })).records, T0 + 10 * MINUTE)
    assert.equal(summary(one), summary(two))
  })
})

describe('linking two profiles of one person', () => {
  test('addresses, inbox keys and access keys: nothing public repeats across the two profiles', async () => {
    const [inbox0, inbox1] = await Promise.all([inboxKey(alice.secret), inboxKey(aliceBuyer.secret)])
    const accessFor = (n: number) => ({ key: makeAccessKey(sha256(utf8(`access ${n}`))).address, scope: 'write' as const, paths: ['offer'] })
    const one = [
      hostsRecord(alice, ['https://big-host.example'], T0),
      ownerRecord(alice, 'profile', { ...profileBody('statistics'), inboxKey: inbox0.recipient }, T0),
      permissionsRecord(alice, [accessFor(1)], T0),
    ]
    const two = [
      hostsRecord(aliceBuyer, ['https://big-host.example'], T0),
      ownerRecord(aliceBuyer, 'profile', { ...profileBody('geometry'), role: 'buyer', inboxKey: inbox1.recipient }, T0),
      permissionsRecord(aliceBuyer, [accessFor(2)], T0),
    ]
    const tokens = (records: object[]) => {
      const out = new Set<string>()
      const walk = (v: unknown) => {
        if (typeof v === 'string' && v.length >= 16) out.add(v)
        else if (v && typeof v === 'object') for (const x of Object.values(v)) walk(x)
      }
      for (const r of records) walk(r)
      return out
    }
    const shared = [...tokens(one)].filter((t) => tokens(two).has(t))
    // What repeats is only what the person chose to repeat: here the host.
    assert.deepEqual(shared, ['https://big-host.example'])
  })

  test('FINDING: written in the same moment, two profiles sit side by side in a host’s listing', async () => {
    const host = await startHost({ now: () => T0 })
    try {
      await publish([host.url], [ownerRecord(alice, 'profile', profileBody('maths'), T0)])
      await publish([host.url], [ownerRecord(bob, 'profile', profileBody('physics'), T0)])
      // One app writes both of a person's profiles at once:
      await publish([host.url], [ownerRecord(alice, 'offer/x', offerBody('1'), T0 + 1), ownerRecord(aliceBuyer, 'offer/y', offerBody('1'), T0 + 1)])
      const listing = (await readAll(host.url)).records.map((c) => c.record.profile)
      assert.deepEqual(listing.slice(-2), [alice.address, aliceBuyer.address], 'adjacent, same millisecond: an observer can guess they are one person')
    } finally {
      await host.close()
    }
  })

  test('FINDING: one access key listed by two profiles links them in public', () => {
    const intoSeller = accessRecord(accessKey, alice.address, 'offer/x', offerBody('1'), T0)
    const intoBuyer = accessRecord(accessKey, aliceBuyer.address, 'offer/y', offerBody('1'), T0)
    assert.equal(intoSeller.by, intoBuyer.by, 'anyone reading both sees the same by: give each folder its own access keys')
  })
})
