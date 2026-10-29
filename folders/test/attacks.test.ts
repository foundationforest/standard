// Trying hard to break each promise. Every test names the promise and says what was tried; a test
// that shows an attack succeeding says so in its name (FINDING), and README.md lists it as a limit.
// Other attack tests live next to the code they attack: host.test.ts, view.test.ts, locked.test.ts,
// inbox.test.ts, and what a host must refuse is the host check's (check.test.ts).

import assert from 'node:assert/strict'
import { after, before, describe, test } from 'node:test'
import { sha256 } from '@noble/hashes/sha2.js'
import { Base8, addPoint, mulPointEscalar } from '@zk-kit/baby-jubjub'
import { verifySignature as zkVerify } from '@zk-kit/eddsa-poseidon'
import { poseidon5 } from 'poseidon-lite/poseidon5'
import { BN254_R, SUBGROUP_ORDER, bytesMessage, checkWithPublicKey, packSignature, unpackSignature } from '@foundationforest/keys'
import { b64u, base58, concat, hex, utf8 } from '../src/bytes.ts'
import { canonical } from '../src/canonical.ts'
import { readAll, readFolder, write } from '../src/client.ts'
import { SIGN_PREFIX, checkEntry, checkSignature, encodeEntry, signAs, signingInput, unsignedOf } from '../src/entry.ts'
import { DELETE_PREFIX, MESSAGE_PREFIX, checkMessage, decodeDelete, deleteSigningInput, messageSigningInput } from '../src/inbox.ts'
import { viewFolder } from '../src/view.ts'
import { entry } from '../src/write.ts'
import { MINUTE, SEED, T0, access, aliceBuyerOpening, aliceOpening, alice, aliceBuyer, asAccess, bob, listed, offerBody, profileBody, stranger } from './fixtures.ts'
import { startHost } from './helpers.ts'
import type { TestHost } from './host.ts'

const L = SUBGROUP_ORDER
const le = (n: bigint, len = 32) => Uint8Array.from({ length: len }, (_, i) => Number((n >> BigInt(8 * i)) & 255n))
const fromLe = (b: Uint8Array) => b.reduceRight((acc, byte) => (acc << 8n) + BigInt(byte), 0n)
/** The point of order 2 on Baby Jubjub: on the curve, in no key's subgroup. */
const ORDER_2: [bigint, bigint] = [0n, BN254_R - 1n]

describe('nobody forges; a signature means one thing everywhere', () => {
  const offer = entry(alice, 'offer/a', offerBody('30'), T0)
  const message = signingInput(unsignedOf(offer))
  const sig = b64u.decode(offer.sig)

  test("a valid signature: ours and zk-kit's agree", () => {
    assert.equal(checkSignature(sig, message, alice.address), true)
    assert.equal(zkVerify(bytesMessage(message), unpackSignature(sig)!, alice.publicKey), true)
  })

  test('a second spelling of the same signature (S + l) is refused, and could not make a new id anyway', () => {
    const S = fromLe(sig.subarray(32))
    const malleated = concat(sig.subarray(0, 32), le(S + L))
    assert.equal(checkSignature(malleated, message, alice.address), false)
    assert.equal(zkVerify(bytesMessage(message), { R8: unpackSignature(sig)!.R8, S: S + L }, alice.publicKey), false)
    assert.throws(() => checkEntry({ ...offer, sig: b64u.encode(malleated) }), /signature/)
  })

  test("a small-order key: (R8 = identity, S = 0) passes zk-kit's check for any message; Forest refuses the key outright", (t) => {
    const universal = { R8: [0n, 1n] as [bigint, bigint], S: 0n }
    assert.equal(checkWithPublicKey(ORDER_2, bytesMessage(message), universal), false)
    assert.equal(checkSignature(packSignature(universal), message, ORDER_2), false)
    t.diagnostic(`zk-kit's verifySignature accepts the universal signature for the key of order 2: ${zkVerify(bytesMessage(message), universal, ORDER_2)}`)
    // An entry for a small-order key cannot even be read: its profile is no usable address, nor its
    // key.
    const packed = base58.encode(le(ORDER_2[1]))
    assert.throws(() => checkEntry({ ...offer, profile: packed, sig: b64u.encode(packSignature(universal)) }), /usable/)
    assert.throws(() => checkEntry({ ...offer, key: packed, sig: b64u.encode(packSignature(universal)) }), /access key/)
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
    assert.equal(checkWithPublicKey(mixed, m, forged), false, 'Forest takes no key outside the subgroup')
  })

  test('the signed bytes of an entry, a message, an inbox delete, a pay signature and an index root each start with their own text', () => {
    const texts = [SIGN_PREFIX, MESSAGE_PREFIX, DELETE_PREFIX, concat(Uint8Array.of(0xff), utf8('forest/v1/pay\n')), concat(Uint8Array.of(0xff), utf8('forest/v1/reputation\n'))]
    for (const [i, a] of texts.entries()) {
      for (const [j, b] of texts.entries()) if (i !== j) assert.notDeepEqual(a.subarray(0, Math.min(a.length, b.length)), b.subarray(0, Math.min(a.length, b.length)), 'no text begins another')
    }
  })

  test('replaying an entry into another folder, path or time fails; the same entry twice is one entry', () => {
    for (const change of [{ profile: bob.address }, { path: 'offer/b' }, { time: T0 + 1 }]) {
      assert.throws(() => checkEntry({ ...offer, ...change }), /signature/)
    }
    assert.equal(checkEntry(offer).id, checkEntry(JSON.parse(encodeEntry(offer))).id)
    // An access key's entry for Alice, replayed as Bob's: the key is not Bob's to list, and the
    // signature names Alice.
    const byKey = entry(asAccess, 'offer/a', offerBody('30'), T0)
    assert.throws(() => checkEntry({ ...byKey, profile: bob.address }), /signature/)
  })
})

describe('a key that is not the main key, nor the key named', () => {
  const posing = <T extends object>(unsigned: T, input: (u: T) => Uint8Array) => ({ ...unsigned, sig: signAs(stranger, stranger.address, input(unsigned)) })

  test('signs nothing for the profile: its entry, message and inbox delete are each refused [signature]', () => {
    const signature = (run: () => unknown) => assert.throws(run, (err: { code?: string }) => err.code === 'signature')
    signature(() => checkEntry(posing({ v: 1 as const, profile: alice.address, path: 'offer/x', time: T0, body: offerBody('1') }, signingInput)))
    signature(() => checkEntry(posing({ v: 1 as const, profile: alice.address, path: 'offer/x', time: T0, body: offerBody('1'), key: access.address }, signingInput)))
    const sent = { from: alice.address, time: T0, body: { text: 'hi' } }
    assert.equal(checkMessage({ ...sent, sig: signAs(stranger, stranger.address, messageSigningInput(sent, bob.address)) }, bob.address), false)
    signature(() => decodeDelete(canonical(posing({ v: 1 as const, to: alice.address, id: '0'.repeat(64) }, deleteSigningInput))))
    signature(() => decodeDelete(canonical(posing({ v: 1 as const, to: alice.address, id: '0'.repeat(64), key: access.address }, deleteSigningInput))))
  })

  test('an access key never writes the profile entry, so it can never list itself, add a host, or raise what it can do', () => {
    const v = (entries: ReturnType<typeof entry>[]) => viewFolder(alice.address, entries.map((e) => checkEntry(e)), T0 + MINUTE)
    const profile = entry(alice, 'profile', profileBody('maths', { keys: [listed(['write'])] }), T0)
    const unsigned = { v: 1 as const, profile: alice.address, path: 'profile', time: T0 + 1, body: profileBody('maths', { hosts: ['https://evil.example'], keys: [listed(['write', 'read-inbox'])] }), key: access.address }
    const forged = { ...unsigned, sig: signAs(access, access.address, signingInput(unsigned)) }
    assert.throws(() => checkEntry(forged), (err: { code?: string }) => err.code === 'unlisted')
    // A reader that skips the check still does not count it.
    const view = viewFolder(alice.address, [checkEntry(profile), { entry: forged, id: 'f'.repeat(64) }], T0 + MINUTE)
    assert.deepEqual(view.hosts, ['https://host-a.example'])
    assert.equal(view.ignored.get('f'.repeat(64)), 'unlisted')
    assert.deepEqual(v([profile]).keys[0]!.can, ['write'])
  })
})

describe('over real hosts', () => {
  let h1: TestHost
  let h2: TestHost
  before(async () => {
    h1 = await startHost({ now: () => T0 + 10 * MINUTE })
    h2 = await startHost({ now: () => T0 + 10 * MINUTE })
    const urls = [h1.url, h2.url]
    await write(urls, [entry(alice, 'profile', profileBody('maths', { hosts: urls }), T0), entry(alice, 'offer/a', offerBody('1'), T0)])
  })
  after(async () => {
    await h1.close()
    await h2.close()
  })

  test('a deleted offer cannot be brought back by a host that still has the old version', async () => {
    await write([h1.url], [entry(alice, 'offer/a', null, T0 + 1)]) // only host 1 hears the delete
    const v = await readFolder([h2.url, h1.url], alice.address, T0 + 10 * MINUTE)
    assert.equal(v.current.get('offer/a')!.entry.body, null)
  })

  test('a host holds no key: all it holds has no secret of the person', async () => {
    const disk = [...h1.dump(), ...h2.dump()].join('\n')
    for (const secret of [alice.secret, SEED, le(alice.scalar), le(alice.scalar).reverse()]) {
      for (const form of [hex.encode(secret), b64u.encode(secret), Buffer.from(secret).toString('base64'), base58.encode(secret)]) assert.ok(!disk.includes(form))
    }
    assert.ok(!disk.includes(alice.scalar.toString()), 'nor the main key’s scalar')
    assert.ok(!disk.includes(aliceOpening.identity))
  })

  test('a profile entry signed by someone else, naming other hosts, is refused by hosts and readers', async () => {
    const fake = { ...entry(bob, 'profile', profileBody('maths', { hosts: ['https://evil.example'] }), T0 + 5), profile: alice.address }
    assert.throws(() => checkEntry(fake), /signature/)
    assert.equal((await h1.accept([encodeEntry(fake)]))[0]!.error, 'signature')
  })

  test('two readers reading different hosts compute the same view', async () => {
    await write([h2.url], [entry(alice, 'offer/a', null, T0 + 1)]) // now both hosts hold everything
    const summary = (v: { current: Map<string, { id: string }> }) => [...v.current].map(([p, c]) => `${p}=${c.id}`).sort().join()
    const one = viewFolder(alice.address, (await readAll(h1.url, { profile: alice.address })).entries, T0 + 10 * MINUTE)
    const two = viewFolder(alice.address, (await readAll(h2.url, { profile: alice.address })).entries, T0 + 10 * MINUTE)
    assert.equal(summary(one), summary(two))
  })
})

describe('linking two profiles of one person', () => {
  test('addresses and open keys: nothing public repeats across the two profiles', async () => {
    const one = [entry(alice, 'profile', profileBody('statistics', { hosts: ['https://big-host.example'] }), T0)]
    const two = [entry(aliceBuyer, 'profile', { ...profileBody('geometry', { hosts: ['https://big-host.example'], openKey: aliceBuyerOpening.openKey }), role: 'buyer' }, T0)]
    const tokens = (entries: object[]) => {
      const out = new Set<string>()
      const walk = (v: unknown) => {
        if (typeof v === 'string' && v.length >= 16) out.add(v)
        else if (v && typeof v === 'object') for (const x of Object.values(v)) walk(x)
      }
      for (const r of entries) walk(r)
      return out
    }
    const shared = [...tokens(one)].filter((t) => tokens(two).has(t))
    // What repeats is only what the person chose to repeat: here the host.
    assert.deepEqual(shared, ['https://big-host.example'])
  })

  test('FINDING: written in the same moment, two profiles sit side by side in a host’s listing', async () => {
    const host = await startHost({ now: () => T0 })
    try {
      await write([host.url], [entry(alice, 'profile', profileBody('maths'), T0)])
      await write([host.url], [entry(bob, 'profile', profileBody('physics'), T0)])
      // One app writes both of a person's profiles at once:
      await write([host.url], [entry(alice, 'offer/x', offerBody('1'), T0 + 1), entry(aliceBuyer, 'offer/y', offerBody('1'), T0 + 1)])
      const listing = (await readAll(host.url)).entries.map((c) => c.entry.profile)
      assert.deepEqual(listing.slice(-2), [alice.address, aliceBuyer.address], 'adjacent, same millisecond: an observer can guess they are one person')
    } finally {
      await host.close()
    }
  })
})
