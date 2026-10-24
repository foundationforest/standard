// The profile record's schema (schemas/profile.json), checked with a standard JSON Schema validator:
// the example and the bodies the other tests publish fit it; each of its rules still refuses what it
// refused; the example is a body a record can carry. An offer's and a review's body is the market's,
// so the standard has no schema for them. The example's proofs are checked with their own verifiers
// (proofs/note/client, proofs/reputation/client), for the profile's own address.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, test } from 'node:test'
import { Ajv2020 } from 'ajv/dist/2020.js'
import formats from 'ajv-formats'
import { inboxKey, isEvmAddress, payAddresses, pointOf, serviceKey } from '@foundationforest/keys'
import { verifyNote } from '@foundationforest/note'
import { verifyReputation } from '@foundationforest/reputation'
import { checkValue } from '../src/canonical.ts'
import { inboxOf } from '../src/message.ts'
import { noteCheck, proofsOf, reputationCheck } from '../src/proofs.ts'
import { checkRecord, decodeRecord, encodeRecord } from '../src/record.ts'
import { ownerRecord } from '../src/write.ts'
import { SEED, T0, alice, aliceBuyer, profileBody } from './fixtures.ts'

const read = (path: string) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'))
const KINDS = ['profile'] as const
type Kind = (typeof KINDS)[number]
const PATHS: { [kind in Kind]: string } = { profile: 'profile' }

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

/** Where each kind of proof sits in the example profile record. */
const at = (circuit: string) => example('profile').proofs.findIndex((p: { circuit: string }) => p.circuit === circuit)

describe('schemas', () => {
  test('the example fits its schema, and so do the bodies the other tests publish', () => {
    for (const kind of KINDS) assert.ok(fits(kind, example(kind)), `${kind}: ${ajv.errorsText(validators[kind]!.errors)}`)
    assert.ok(fits('profile', profileBody('maths')))
    assert.ok(fits('profile', JSON.parse(read('./vectors.json').profileRecord.wire).body), 'the profile record the test vectors pin')
  })

  test('the example is a body a record carries: it signs, travels and checks', () => {
    for (const kind of KINDS) {
      const body = example(kind)
      checkValue(example(kind))
      assert.deepEqual(decodeRecord(encodeRecord(ownerRecord(alice, PATHS[kind], body, T0))).record.body, body)
    }
  })

  test('records stay open: a market adds fields, flat beside the standard’s, and a field nobody defined is not refused', () => {
    for (const kind of KINDS) assert.ok(fits(kind, { ...example(kind), anythingElse: 1 }), kind)
  })

  test('the required fields: a profile record’s market and role', () => {
    for (const field of ['market', 'role']) assert.ok(!fits('profile', edit('profile', [field], undefined)), field)
    assert.ok(fits('profile', { market: 'tutoring', role: 'seller' }), 'a profile record can be its market and role alone')
  })

  test('a role is any text: which roles exist is the market’s', () => {
    for (const role of ['seller', 'buyer', 'peer', 'driver', 'x']) assert.ok(fits('profile', edit('profile', ['role'], role)), role)
    for (const role of [7, null, 'x'.repeat(65)]) assert.ok(!fits('profile', edit('profile', ['role'], role)), String(role))
  })

  test('a profile’s pay is keys/’s payAddresses for its label: its Solana address in base58 and its EVM address in EIP-55, both there', async () => {
    const pay = example('profile').pay
    assert.deepEqual(pay, await payAddresses(SEED, 'tutoring/seller'))
    assert.equal(isEvmAddress(pay.evm), true)
    assert.ok(fits('profile', edit('profile', ['pay'], undefined)), 'optional')
    assert.ok(fits('profile', edit('profile', ['pay', 'bitcoin'], 'bc1q…')), 'a type a reader does not know is ignored, not refused')
    assert.ok(!fits('profile', edit('profile', ['pay'], pay.solana)), 'no longer one address')
    for (const type of ['solana', 'evm']) assert.ok(!fits('profile', edit('profile', ['pay', type], undefined)), `both types: no ${type}`)
    for (const bad of ['x', alice.address.replace(/^./, '0'), 'I'.repeat(44), 'a'.repeat(45), 7]) assert.ok(!fits('profile', edit('profile', ['pay', 'solana'], bad)), String(bad))
    for (const bad of [pay.evm.slice(2), pay.evm.slice(0, -1), pay.evm + '0', '0x' + 'g'.repeat(40), 7]) assert.ok(!fits('profile', edit('profile', ['pay', 'evm'], bad)), String(bad))
    assert.equal(isEvmAddress(pay.evm.toLowerCase()), false, 'the schema takes any case; the one spelling is keys/’s isEvmAddress')
  })

  test('a profile’s inboxKey is its inbox key, an age post-quantum hybrid key', async () => {
    const own = (await inboxKey(alice.secret)).sealTo
    assert.equal(example('profile').inboxKey, own, 'the example profile record’s')
    assert.ok(fits('profile', edit('profile', ['inboxKey'], undefined)), 'optional')
    for (const bad of ['age1pq1' + 'q'.repeat(60), alice.address, 'AGE1' + 'Q'.repeat(58), 'age1' + 'b'.repeat(58)]) assert.ok(!fits('profile', edit('profile', ['inboxKey'], bad)), bad)
  })

  test('a profile’s inbox: open to anyone or to an issuer’s note proofs, once, a size; nothing else', async () => {
    const reader = (await inboxKey(new Uint8Array(32).fill(5))).sealTo
    const issuer = example('profile').proofs[at('note')].issuer
    for (const inbox of [{ senders: 'anyone' }, { senders: { issuer } }, { senders: 'anyone', once: true, maxBytes: 4000 }]) {
      assert.ok(fits('profile', edit('profile', ['inbox'], inbox)), JSON.stringify(inbox))
      assert.ok(inboxOf(edit('profile', ['inbox'], inbox)) !== 'unsupported', 'and a host reads it')
    }
    assert.ok(fits('profile', edit('profile', ['inbox'], undefined)), 'optional: no field, no inbox')
    for (const inbox of [{}, 'anyone', { senders: 'everyone' }, { senders: { issuer: 'x' } }, { senders: { issuer: pointOf(issuer).map((n) => n.toString(16).padStart(64, '0')).join('') } }, { senders: { issuer: issuer + '0' } }, { senders: { issuer: pointOf(issuer).map(String) } }, { senders: { issuer, label: 'x' } }, { senders: { deposit: '5' } }, { senders: 'anyone', once: false }, { senders: 'anyone', maxBytes: -1 }, { senders: 'anyone', deposit: '5' }, { senders: 'anyone', readers: [reader] }, { senders: 'anyone', readers: [] }]) {
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

  test('the example’s reputation proof holds for the profile’s address, as verifyReputation takes it; each field keeps its shape', async () => {
    const i = at('reputation')
    const shown = example('profile').proofs[i]
    const set = (field: string, value: unknown) => edit('profile', ['proofs', i, field], value)
    assert.equal(shown.index, serviceKey(new Uint8Array(32).fill(0x2c)).address, 'the example index’s key (scripts/example-profile.ts)')
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

  test('the example’s note proof holds for the profile’s address, as verifyNote takes it; each field keeps its shape', async () => {
    const i = at('note')
    const shown = example('profile').proofs[i]
    const set = (field: string, value: unknown) => edit('profile', ['proofs', i, field], value)
    assert.equal(`${example('profile').market}/${example('profile').role}`, shown.label, 'the profile’s own label')
    const check = noteCheck(shown, alice.address)!
    assert.equal(await verifyNote(check), true)
    for (const [why, changed] of [
      ['another profile', { profile: aliceBuyer.address }],
      ['another issuer name', { issuerName: 'issuer-b.example' }],
      ['another label', { label: 'tutoring/buyer' }],
    ] as const) {
      assert.equal(await verifyNote({ ...check, ...changed }), false, why)
    }
    assert.equal(noteCheck({ ...shown, stamp: shown.stamp.toUpperCase() }, alice.address), null)
    assert.equal(noteCheck({ ...shown, issuer: shown.issuer.slice(1) }, alice.address), null, 'an issuer that is no address')

    for (const field of ['issuer', 'issuerName', 'label', 'stamp', 'proof']) assert.ok(!fits('profile', set(field, undefined)), field)
    assert.ok(!fits('profile', set('extra', 1)), 'nothing verifyNote does not take')
    assert.ok(!fits('profile', set('month', 202609)), 'the month a proof once showed, too')
    const bad: { [field: string]: unknown[] } = {
      issuer: [pointOf(shown.issuer).map((n) => n.toString(16).padStart(64, '0')).join(''), shown.issuer + '0', 'x', 7, pointOf(shown.issuer).map(String)],
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
