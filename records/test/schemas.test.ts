// The three record schemas (schemas/*.json), checked with a standard JSON Schema validator: the
// examples and the bodies the other tests publish fit them; each rule still refuses what it
// refused; an offer's and a review's other fields are the market's, so none is refused; every
// example is a body a record can carry. The example card's proofs are checked with their own
// verifiers (proofs/human/client, proofs/reputation/client), for the card's own address.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, test } from 'node:test'
import { Ajv2020 } from 'ajv/dist/2020.js'
import formats from 'ajv-formats'
import { accessKey as makeAccessKey, inboxKey, payKey, readKey } from '../../keys/src/index.ts'
import { verifyHuman } from '../../proofs/human/client/src/index.ts'
import { verifyReputation } from '../../proofs/reputation/client/src/index.ts'
import { checkValue } from '../src/canonical.ts'
import { inboxOf } from '../src/message.ts'
import { humanCheck, proofsOf, reputationCheck } from '../src/proofs.ts'
import { checkRecord, decodeRecord, encodeRecord } from '../src/record.ts'
import { ownerRecord } from '../src/write.ts'
import { SEED, T0, alice, aliceBuyer, offerBody, profileBody, reviewBody } from './fixtures.ts'

const read = (path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'))
const KINDS = ['profile', 'offer', 'review'] as const
type Kind = (typeof KINDS)[number]
const PATHS: { [kind in Kind]: string } = { profile: 'profile', offer: 'offer/x', review: 'review/x' }

const ajv = new Ajv2020({ strict: true, allErrors: true })
formats.default(ajv)
const validators = Object.fromEntries(KINDS.map((kind) => [kind, ajv.compile(read(`../schemas/${kind}.json`))]))
const fits = (kind: Kind, body: unknown) => validators[kind]!(body) === true
const example = (kind: Kind): { [key: string]: any } => read(`../schemas/examples/${kind}.json`)

/** The example with one field set (or removed, with undefined) at a path of keys. */
function edit(kind: Kind, path: Array<string | number>, value: unknown): { [key: string]: any } {
  const body = example(kind)
  let at: any = body
  for (const key of path.slice(0, -1)) at = at[key] ??= {}
  const last = path[path.length - 1]!
  if (value === undefined) delete at[last]
  else at[last] = value
  return body
}

/** Where each kind of proof sits in the example card. */
const at = (circuit: string) => example('profile').proofs.findIndex((p: { circuit: string }) => p.circuit === circuit)

describe('schemas', () => {
  test('each example fits its schema, and so do the bodies the other tests publish', () => {
    for (const kind of KINDS) assert.ok(fits(kind, example(kind)), `${kind}: ${ajv.errorsText(validators[kind]!.errors)}`)
    assert.ok(fits('profile', profileBody('maths')))
    assert.ok(fits('offer', offerBody('30')))
    assert.ok(fits('review', reviewBody(alice.address)))
    assert.ok(fits('offer', JSON.parse(read('./vectors.json').offer.wire).body), 'the offer the test vectors pin')
  })

  test('every example is a body a record carries: it signs, travels and checks', () => {
    for (const kind of KINDS) {
      const body = example(kind)
      checkValue(example(kind))
      assert.deepEqual(decodeRecord(encodeRecord(ownerRecord(alice, PATHS[kind], body, T0))).record.body, body)
    }
  })

  test('records stay open: a market adds fields, flat beside the standard’s, and a field nobody defined is not refused', () => {
    for (const kind of KINDS) assert.ok(fits(kind, { ...example(kind), anythingElse: 1 }), kind)
  })

  test('the required fields: a card’s market and role; nothing in an offer or a review', () => {
    for (const field of ['market', 'role']) assert.ok(!fits('profile', edit('profile', [field], undefined)), field)
    assert.ok(fits('profile', { market: 'tutoring', role: 'seller' }), 'a card can be its market and role alone')
    assert.ok(fits('offer', {}), 'an offer can be empty')
    assert.ok(fits('review', {}), 'a review too')
  })

  test('a role is any text: which roles exist is the market’s', () => {
    for (const role of ['seller', 'buyer', 'peer', 'driver', 'x']) assert.ok(fits('profile', edit('profile', ['role'], role)), role)
    for (const role of [7, null, 'x'.repeat(65)]) assert.ok(!fits('profile', edit('profile', ['role'], role)), String(role))
  })

  test('an offer’s and a review’s fields beside media are the market’s: the standard refuses none of them', () => {
    // Fields the standard once shaped, in shapes it once refused: each is now the market's to judge.
    const once = { description: 7, price: { amount: 25, per: 'week' }, terms: { timer: { days: 0, to: 'arbiter' } }, location: { lat: 38.72 }, createdAt: 'yesterday', expires: 1 }
    assert.ok(fits('offer', { ...example('offer'), ...once }))
    assert.ok(fits('review', { ...example('review'), subject: 'did:web:example.com', score: 9, offer: 'Maths', evidence: 'x', text: 1, createdAt: 'yesterday' }))
    for (const kind of ['offer', 'review'] as const) {
      assert.deepEqual(Object.keys(read(`../schemas/${kind}.json`).properties), ['media'], `${kind}: the standard names media alone`)
      assert.equal(read(`../schemas/${kind}.json`).required, undefined, `${kind}: and requires nothing`)
    }
  })

  test('blobs are SHA-256 references with their types and sizes; which types and how large is each host’s own choice, not the shape’s', () => {
    for (const type of ['image/png', 'image/gif', 'image/svg+xml', 'application/vnd.oasis.opendocument.text']) {
      assert.ok(fits('offer', edit('offer', ['media'], [{ sha256: 'b'.repeat(64), mimeType: type, size: 1 }])), type)
      assert.ok(fits('review', edit('review', ['media'], [{ sha256: 'b'.repeat(64), mimeType: type, size: 1 }])), type)
    }
    for (const type of ['Image/PNG', 'image', 'image/', '/png', 'image/png; charset=x', 'image/p ng', '', 'a/' + 'b'.repeat(254)]) {
      assert.ok(!fits('offer', edit('offer', ['media', 0, 'mimeType'], type)), type)
    }
    assert.ok(fits('offer', edit('offer', ['media', 0, 'size'], 1_000_001)))
    assert.ok(!fits('offer', edit('offer', ['media', 0, 'size'], -1)))
    assert.ok(!fits('offer', edit('offer', ['media', 0, 'sha256'], 'A'.repeat(64))))
    assert.ok(!fits('offer', edit('offer', ['media', 0, 'ref'], 'bafkrei…')), 'a reference is nothing but its hash, type and size')
    const clip = { sha256: 'b'.repeat(64), mimeType: 'video/mp4', size: 50_000_000 }
    assert.ok(fits('review', edit('review', ['media'], Array(10).fill(clip))))
    assert.ok(!fits('review', edit('review', ['media'], Array(11).fill(clip))))
    assert.ok(fits('review', edit('review', ['media'], [{ ...clip, size: 50_000_001 }])))
    assert.ok(fits('offer', edit('offer', ['media'], [{ ...clip, size: 50_000_001 }])))
    assert.ok(fits('offer', edit('offer', ['media'], Array(10).fill(clip))), 'an offer carries the same media as a review')
    assert.ok(!fits('offer', edit('offer', ['media'], Array(11).fill(clip))))
  })

  test('a profile’s pay address is keys/’s payKey for its label: an ed25519 key on Solana, in base58', async () => {
    assert.equal(example('profile').pay, (await payKey(SEED, 'tutoring/seller')).address)
    assert.ok(fits('profile', edit('profile', ['pay'], undefined)), 'optional')
    for (const bad of ['x', alice.address.replace(/^./, '0'), 'I'.repeat(44), 'a'.repeat(45), 7]) assert.ok(!fits('profile', edit('profile', ['pay'], bad)), String(bad))
  })

  test('a profile’s inboxKey is its inbox key, an age post-quantum hybrid recipient', async () => {
    const own = (await inboxKey(alice.secret)).recipient
    assert.equal(example('profile').inboxKey, own, 'the example card’s')
    assert.ok(fits('profile', edit('profile', ['inboxKey'], undefined)), 'optional')
    for (const bad of ['age1pq1' + 'q'.repeat(60), alice.address, 'AGE1' + 'Q'.repeat(58), 'age1' + 'b'.repeat(58)]) assert.ok(!fits('profile', edit('profile', ['inboxKey'], bad)), bad)
  })

  test('a profile’s inbox: open to anyone or to an issuer’s human proofs, once, a size, readers; nothing else', async () => {
    const reader = (await readKey(new Uint8Array(32).fill(5))).recipient
    const issuer = example('profile').proofs[at('human')].issuer
    for (const inbox of [{ senders: 'anyone' }, { senders: { issuer } }, { senders: 'anyone', once: true, maxBytes: 4000 }, { senders: 'anyone', readers: [reader] }, { senders: 'anyone', readers: [] }]) {
      assert.ok(fits('profile', edit('profile', ['inbox'], inbox)), JSON.stringify(inbox))
      assert.ok(inboxOf(edit('profile', ['inbox'], inbox)) !== 'unsupported', 'and a host reads it')
    }
    assert.ok(fits('profile', edit('profile', ['inbox'], undefined)), 'optional: no field, no inbox')
    for (const inbox of [{}, 'anyone', { senders: 'everyone' }, { senders: { issuer: 'x' } }, { senders: { issuer: alice.address } }, { senders: { issuer: issuer.toUpperCase() } }, { senders: { issuer: issuer.slice(2) } }, { senders: { issuer, label: 'x' } }, { senders: { deposit: '5' } }, { senders: 'anyone', once: false }, { senders: 'anyone', maxBytes: -1 }, { senders: 'anyone', deposit: '5' }, { senders: 'anyone', readers: reader }, { senders: 'anyone', readers: [alice.address] }, { senders: 'anyone', readers: [reader.toUpperCase()] }]) {
      assert.ok(!fits('profile', edit('profile', ['inbox'], inbox)), JSON.stringify(inbox))
      assert.equal(inboxOf(edit('profile', ['inbox'], inbox)), 'unsupported', 'and a host refuses deliveries to it')
    }
  })

  test('a profile’s proofs: up to four; another circuit’s fields are its own', () => {
    const one = example('profile').proofs[at('reputation')]
    const proofs = (...items: unknown[]) => edit('profile', ['proofs'], items)
    assert.ok(fits('profile', edit('profile', ['proofs'], undefined)), 'optional')
    assert.ok(fits('profile', proofs(one, one, one, one)))
    assert.ok(!fits('profile', proofs(one, one, one, one, one)))
    const later = { circuit: 'kyc-age', over: 18, anything: { at: ['all'] } }
    assert.ok(fits('profile', proofs(later, one)), 'a circuit nobody defined yet is not refused, so an older app ignores it')
    assert.ok(checkRecord(ownerRecord(alice, 'profile', proofs(later, one), T0)), 'and a record carries it')
    assert.deepEqual(proofsOf(proofs(later, one, 'x', null)).map((p) => p.circuit), ['kyc-age', 'reputation'], 'what proofsOf hands on')
    for (const circuit of [undefined, '', 'Reputation', '1x', 'x_y', 'x'.repeat(33), 7]) {
      assert.ok(!fits('profile', proofs({ ...later, circuit })), String(circuit))
    }
  })

  test('the example’s reputation proof holds for the card’s address, as verifyReputation takes it; each field keeps its shape', async () => {
    const i = at('reputation')
    const shown = example('profile').proofs[i]
    const set = (field: string, value: unknown) => edit('profile', ['proofs', i, field], value)
    assert.equal(shown.index, makeAccessKey(new Uint8Array(32).fill(0x2c)).address, 'the example index’s key (scripts/example-card.ts)')
    const check = reputationCheck(shown, alice.address)!
    assert.equal(await verifyReputation(check), true)
    assert.equal(await verifyReputation({ ...check, profile: aliceBuyer.address }), false, 'nor on another profile')
    assert.equal(await verifyReputation({ ...check, score: check.score + 1n }), false, 'nor with another score')
    assert.equal(reputationCheck({ ...shown, root: 'x' }, alice.address), null)

    assert.ok(fits('profile', set('label', 'online-tutors/seller')), 'a label, when the proof shows one market')
    for (const field of ['index', 'root', 'time', 'signature', 'score', 'proof']) assert.ok(!fits('profile', set(field, undefined)), field)
    assert.ok(!fits('profile', set('extra', 1)), 'a reputation proof carries nothing its verifier does not take')
    const bad: { [field: string]: unknown[] } = {
      index: ['x', alice.address.replace(/^./, '0'), 'I'.repeat(44)],
      root: [shown.root.toUpperCase(), shown.root.slice(1), '0x' + shown.root.slice(2), BigInt('0x' + shown.root).toString()],
      time: [-1, 1.5, 2 ** 53, '1790812800000'],
      signature: [shown.signature.slice(1), shown.signature + 'A', shown.signature.replace(/^./, '+'), shown.signature + '=='],
      score: [-1, 2 ** 32, 8.7, '87'],
      label: ['', 'x'.repeat(129), 1],
      proof: [shown.proof.slice(1), shown.proof + 'A', shown.proof.replace(/^./, '/')],
    }
    for (const [field, values] of Object.entries(bad)) {
      for (const value of values) assert.ok(!fits('profile', set(field, value)), `${field} ${JSON.stringify(value)}`)
    }
    assert.ok(fits('profile', set('score', 2 ** 32 - 1)), 'the largest score')
    assert.ok(fits('profile', set('time', 2 ** 53 - 1)), 'the latest time')
  })

  test('the example’s human proof holds for the card’s address, as verifyHuman takes it; each field keeps its shape', async () => {
    const i = at('human')
    const shown = example('profile').proofs[i]
    const set = (field: string, value: unknown) => edit('profile', ['proofs', i, field], value)
    assert.equal(`${example('profile').market}/${example('profile').role}`, shown.label, 'the profile’s own label')
    const check = humanCheck(shown, alice.address)!
    assert.equal(await verifyHuman(check), true)
    for (const [why, changed] of [
      ['another profile', { profile: aliceBuyer.address }],
      ['another issuer name', { issuerName: 'issuer-b.example' }],
      ['another label', { label: 'tutoring/buyer' }],
    ] as const) {
      assert.equal(await verifyHuman({ ...check, ...changed }), false, why)
    }
    assert.equal(humanCheck({ ...shown, stamp: shown.stamp.toUpperCase() }, alice.address), null)

    for (const field of ['issuer', 'issuerName', 'label', 'stamp', 'proof']) assert.ok(!fits('profile', set(field, undefined)), field)
    assert.ok(!fits('profile', set('extra', 1)), 'nothing verifyHuman does not take')
    assert.ok(!fits('profile', set('month', 202609)), 'the month a proof once showed, too')
    const bad: { [field: string]: unknown[] } = {
      issuer: [shown.issuer.toUpperCase(), shown.issuer.slice(1), shown.issuer + '0', alice.address],
      issuerName: ['', 'x'.repeat(257), 1],
      label: ['', 'x'.repeat(129), 1],
      stamp: [shown.stamp.toUpperCase(), shown.stamp.slice(1), shown.stamp + '0', '0x' + shown.stamp.slice(2)],
      proof: [shown.proof.slice(1), shown.proof + 'A', shown.proof.replace(/^./, '+')],
    }
    for (const [field, values] of Object.entries(bad)) {
      for (const value of values) assert.ok(!fits('profile', set(field, value)), `${field} ${JSON.stringify(value)}`)
    }
  })
})
