// The profile entry's schema (schemas/profile.json), checked with a standard JSON Schema validator:
// the example and the bodies the other tests write fit it; each of its rules still refuses what it
// refused; the example is a body a profile entry can carry. An offer's and a review's body is the
// market's, so the standard has no schema for them. The example's proofs are checked with their own
// proof checks (proofs/verification/client, proofs/reputation/client), and its pay signatures with
// checkPay, for the profile's own address.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, test } from 'node:test'
import { Ajv2020 } from 'ajv/dist/2020.js'
import formats from 'ajv-formats'
import { isEvmAddress, payAddresses, pointOf, profilesKey, serviceKey } from '@foundationforest/keys'
import { checkVerification } from '@foundationforest/verification'
import { checkReputation } from '@foundationforest/reputation'
import { checkValue } from '../src/canonical.ts'
import { checkProfileBody } from '../src/profile.ts'
import { checkPay } from '../src/pay.ts'
import { proofsOf, reputationCheck, verificationCheck } from '../src/proofs.ts'
import { checkEntry, decodeEntry, encodeEntry } from '../src/entry.ts'
import { entry } from '../src/write.ts'
import { KEYS, SEED, T0, access, aliceOpening, alice, aliceBuyer, listed, profileBody } from './fixtures.ts'

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

/** Where each kind of proof sits in the example profile entry. */
const at = (circuit: string) => example('profile').proofs.findIndex((p: { circuit: string }) => p.circuit === circuit)

describe('schemas', () => {
  test('the example fits its schema, and so do the bodies the other tests write', () => {
    for (const kind of KINDS) assert.ok(fits(kind, example(kind)), `${kind}: ${ajv.errorsText(validators[kind]!.errors)}`)
    assert.ok(fits('profile', profileBody('maths', { keys: [listed(['read-inbox', 'write'])] })))
    const pinned = read('./vectors.json')
    assert.ok(fits('profile', JSON.parse(pinned.profileEntry.wire).body), 'the profile entry the test vectors pin')
    assert.ok(fits('profile', JSON.parse(pinned.profilesFolder.profileEntry.wire).body), 'and the Profiles folder’s')
  })

  test('the example is a body a profile entry carries: it signs, travels and checks, and a host reads its fields', () => {
    for (const kind of KINDS) {
      const body = example(kind)
      checkValue(example(kind))
      checkProfileBody(body)
      assert.deepEqual(decodeEntry(encodeEntry(entry(alice, PATHS[kind], body, T0))).entry.body, body)
    }
  })

  test('entries stay open: a market adds fields, flat beside the standard’s, and a field nobody defined is not refused', () => {
    for (const kind of KINDS) assert.ok(fits(kind, { ...example(kind), anythingElse: 1 }), kind)
  })

  test('the required fields: hosts, and market and role together; the Profiles folder’s holds only hosts', async () => {
    assert.ok(!fits('profile', edit('profile', ['hosts'], undefined)), 'hosts')
    for (const field of ['market', 'role']) assert.ok(!fits('profile', edit('profile', [field], undefined)), `${field} without the other`)
    assert.ok(fits('profile', { market: 'tutoring', role: 'seller', hosts: ['https://host-a.example'] }), 'a profile entry can be its market, role and hosts alone')
    assert.ok(fits('profile', { hosts: ['https://host-a.example'] }), 'the Profiles folder’s, with no market')
    assert.equal(read('./vectors.json').profilesFolder.profile, (await profilesKey(SEED)).address)
  })

  test('hosts: 1 to 8 distinct origins', () => {
    for (const hosts of [['https://a.example', 'https://b.example:8443'], ['http://127.0.0.1:8080']]) assert.ok(fits('profile', edit('profile', ['hosts'], hosts)), hosts.join())
    for (const hosts of [[], ['https://a.example', 'https://a.example'], ['http://a.example'], ['https://a.example/x'], ['HTTPS://A.EXAMPLE'], Array.from({ length: 9 }, (_, i) => `https://h${i}.example`)]) {
      assert.ok(!fits('profile', edit('profile', ['hosts'], hosts)), hosts.join())
    }
  })

  test('a role is any text: which roles exist is the market’s', () => {
    for (const role of ['seller', 'buyer', 'peer', 'driver', 'x']) assert.ok(fits('profile', edit('profile', ['role'], role)), role)
    for (const role of [7, null, 'x'.repeat(65)]) assert.ok(!fits('profile', edit('profile', ['role'], role)), String(role))
  })

  test('a profile’s pay is keys/’s payAddresses for its label, any of its types: its Solana address in base58, its EVM address in EIP-55', async () => {
    const pay = example('profile').pay
    assert.deepEqual(pay, await payAddresses(SEED, 'tutoring/seller'))
    assert.equal(isEvmAddress(pay.evm), true)
    assert.ok(fits('profile', edit('profile', ['pay'], undefined)), 'optional')
    assert.ok(!fits('profile', edit('profile', ['paySig'], undefined)), 'but with it, paySig')
    assert.ok(fits('profile', edit('profile', ['pay', 'bitcoin'], 'bc1q…')), 'a type a reader does not know is ignored, not refused')
    assert.ok(!fits('profile', edit('profile', ['pay'], pay.solana)), 'not one address: an object of them')
    for (const type of ['solana', 'evm']) assert.ok(fits('profile', edit('profile', ['pay', type], undefined)), `one type is enough: no ${type}`)
    for (const bad of ['x', alice.address.replace(/^./, '0'), 'I'.repeat(44), 'a'.repeat(45), 7]) assert.ok(!fits('profile', edit('profile', ['pay', 'solana'], bad)), String(bad))
    for (const bad of [pay.evm.slice(2), pay.evm.slice(0, -1), pay.evm + '0', '0x' + 'g'.repeat(40), 7]) assert.ok(!fits('profile', edit('profile', ['pay', 'evm'], bad)), String(bad))
    assert.equal(isEvmAddress(pay.evm.toLowerCase()), false, 'the schema takes any case; the one spelling is keys/’s isEvmAddress')
  })

  test('a profile’s paySig: each pay key signed the profile’s address, keys/’s pinned signatures; checkPay counts only the types whose signature holds', () => {
    const body = example('profile')
    const pinned = Object.fromEntries(KEYS.payKeys.filter((p: { label: string }) => p.label === 'tutoring/seller').map((p: { type: string; paySig: string }) => [p.type, p.paySig]))
    assert.deepEqual(body.paySig, pinned)
    assert.deepEqual(checkPay(body, alice.address), ['solana', 'evm'])
    assert.deepEqual(checkPay(body, aliceBuyer.address), [], 'copied onto another profile, no address counts')
    const other = KEYS.payKeys.find((p: { label: string; type: string }) => p.label === 'tutoring/buyer' && p.type === 'evm')
    assert.deepEqual(checkPay(edit('profile', ['pay', 'evm'], other.address), alice.address), ['solana'], 'an address that is not its own')
    assert.deepEqual(checkPay(edit('profile', ['paySig', 'solana'], body.paySig.evm.slice(0, 86)), alice.address), ['evm'])
    assert.deepEqual(checkPay(edit('profile', ['paySig'], undefined), alice.address), [], 'no paySig, no address')
    for (const type of ['solana', 'evm']) assert.ok(!fits('profile', edit('profile', ['paySig', type], undefined)), `a type pay lists, with no signature: ${type}`)
    for (const type of ['solana', 'evm'] as const) {
      // A profile entry that lists one type, with its signature alone.
      const other = type === 'solana' ? 'evm' : 'solana'
      const one: { [key: string]: any } = { ...body, pay: { [type]: body.pay[type] }, paySig: { [type]: body.paySig[type] } }
      assert.ok(fits('profile', one), `${type} alone`)
      assert.deepEqual(checkPay(one, alice.address), [type])
      assert.ok(fits('profile', { ...one, paySig: { ...one.paySig, [other]: body.paySig[other] } }), 'a signature for a type pay does not list is ignored')
      assert.deepEqual(checkPay({ ...one, paySig: body.paySig }, alice.address), [type], 'and not counted')
    }
    for (const bad of [body.paySig.solana.slice(1), body.paySig.solana + 'A', body.paySig.solana.replace(/^./, '+'), 7]) assert.ok(!fits('profile', edit('profile', ['paySig', 'solana'], bad)), String(bad))
    for (const bad of [body.paySig.evm.slice(1), body.paySig.evm + 'A', body.paySig.evm.replace(/^./, '/'), 7]) assert.ok(!fits('profile', edit('profile', ['paySig', 'evm'], bad)), String(bad))
  })

  test('a profile’s openKey is its main key’s opening half, an age post-quantum hybrid key', async () => {
    assert.equal(example('profile').openKey, aliceOpening.openKey, 'the example profile entry’s')
    assert.ok(fits('profile', edit('profile', ['openKey'], undefined)), 'optional: without it, the folder takes no inbox entries')
    for (const bad of ['age1pq1' + 'q'.repeat(60), alice.address, 'AGE1' + 'Q'.repeat(58), 'age1' + 'b'.repeat(58)]) assert.ok(!fits('profile', edit('profile', ['openKey'], bad)), bad)
  })

  test('a profile’s keys: each its address, what it can do, and its open key when it can read', () => {
    assert.deepEqual(example('profile').keys, [{ key: access.address, open: access.openKey, can: ['read', 'write'] }], 'keys/’s access key')
    assert.ok(fits('profile', edit('profile', ['keys'], undefined)), 'optional')
    for (const can of [['write'], ['message'], [], ['write', 'pay']]) assert.ok(fits('profile', edit('profile', ['keys'], [{ key: access.address, can }])), can.join())
    for (const can of [['read'], ['read-inbox', 'write']]) {
      assert.ok(!fits('profile', edit('profile', ['keys'], [{ key: access.address, can }])), `${can.join()}, with no open key`)
      assert.ok(fits('profile', edit('profile', ['keys'], [listed(can)])), `${can.join()}, with its open key`)
    }
    for (const bad of [{ key: 'x', can: [] }, { can: [] }, { key: access.address }, { key: access.address, can: 'write' }, { key: access.address, open: 'x', can: ['write'] }]) {
      assert.ok(!fits('profile', edit('profile', ['keys'], [bad])), JSON.stringify(bad))
    }
    assert.ok(fits('profile', edit('profile', ['keys'], [{ key: access.address, can: ['write'], until: 5 }])), 'a field nobody defined: not refused, and the key counts for nothing')
  })

  test('a profile entry may carry files too, each exactly { sha256, type, size }', () => {
    const file = { sha256: 'a'.repeat(64), type: 'image/jpeg', size: 2000 }
    assert.ok(fits('profile', edit('profile', ['files'], [file])))
    for (const bad of [[{ ...file, sha256: 'A'.repeat(64) }], [{ ...file, type: 'Image/JPEG' }], [{ ...file, size: -1 }], [{ ...file, width: 3 }], file]) assert.ok(!fits('profile', edit('profile', ['files'], bad)), JSON.stringify(bad))
  })

  test('a profile’s proofs: up to four; another circuit’s fields are its own', () => {
    const one = example('profile').proofs[at('reputation')]
    const proofs = (...items: unknown[]) => edit('profile', ['proofs'], items)
    assert.ok(fits('profile', edit('profile', ['proofs'], undefined)), 'optional')
    assert.ok(fits('profile', proofs(one, one, one, one)))
    assert.ok(!fits('profile', proofs(one, one, one, one, one)))
    const later = { circuit: 'kyc-age', over: 18, anything: { at: ['all'] } }
    assert.ok(fits('profile', proofs(later, one)), 'a circuit nobody defined yet is not refused, so an older app ignores it')
    assert.ok(checkEntry(entry(alice, 'profile', proofs(later, one), T0)), 'and a profile entry carries it')
    assert.deepEqual(proofsOf(proofs(later, one, 'x', null)).map((p) => p.circuit), ['kyc-age', 'reputation'], 'what proofsOf hands on')
    for (const circuit of [undefined, '', 'Reputation', '1x', 'x_y', 'x'.repeat(33), 7]) {
      assert.ok(!fits('profile', proofs({ ...later, circuit })), String(circuit))
    }
  })

  test('the example’s reputation proof holds for the profile’s address, as checkReputation takes it; each field keeps its shape', async () => {
    const i = at('reputation')
    const shown = example('profile').proofs[i]
    const set = (field: string, value: unknown) => edit('profile', ['proofs', i, field], value)
    assert.equal(shown.index, serviceKey(new Uint8Array(32).fill(0x2c)).address, 'the example index’s key (scripts/example-profile.ts)')
    const check = reputationCheck(shown, alice.address)!
    assert.equal(await checkReputation(check), true)
    assert.equal(await checkReputation({ ...check, profile: aliceBuyer.address }), false, 'nor on another profile')
    assert.equal(await checkReputation({ ...check, score: check.score + 1n }), false, 'nor with another score')
    assert.equal(reputationCheck({ ...shown, root: 'x' }, alice.address), null)

    assert.ok(!fits('profile', set('label', 'tutoring/buyer')), 'the label a proof once showed, too')
    for (const field of ['index', 'root', 'time', 'signature', 'score', 'proof']) assert.ok(!fits('profile', set(field, undefined)), field)
    assert.ok(!fits('profile', set('extra', 1)), 'a reputation proof carries nothing its proof check does not take')
    const bad: { [field: string]: unknown[] } = {
      index: ['x', alice.address.replace(/^./, '0'), 'I'.repeat(44)],
      root: [shown.root.toUpperCase(), shown.root.slice(1), '0x' + shown.root.slice(2), BigInt('0x' + shown.root).toString()],
      time: [-1, 1.5, 2 ** 53, '1790812800000'],
      signature: [shown.signature.slice(1), shown.signature + 'A', shown.signature.replace(/^./, '+'), shown.signature + '=='],
      score: [-1, 2 ** 32, 8.7, '87'],
      proof: [shown.proof.slice(1), shown.proof + 'A', shown.proof.replace(/^./, '/')],
    }
    for (const [field, values] of Object.entries(bad)) {
      for (const value of values) assert.ok(!fits('profile', set(field, value)), `${field} ${JSON.stringify(value)}`)
    }
    assert.ok(fits('profile', set('score', 2 ** 32 - 1)), 'the largest score')
    assert.ok(fits('profile', set('time', 2 ** 53 - 1)), 'the latest time')
  })

  test('the example’s verification holds for the profile’s address, as checkVerification takes it; each field keeps its shape', async () => {
    const i = at('verification')
    const shown = example('profile').proofs[i]
    const set = (field: string, value: unknown) => edit('profile', ['proofs', i, field], value)
    assert.equal(`${example('profile').market}/${example('profile').role}`, shown.label, 'the profile’s own label')
    const check = verificationCheck(shown, alice.address)!
    assert.equal(await checkVerification(check), true)
    for (const [why, changed] of [
      ['another profile', { profile: aliceBuyer.address }],
      ['another verifier name', { verifierName: 'issuer-b.example' }],
      ['another label', { label: 'tutoring/buyer' }],
    ] as const) {
      assert.equal(await checkVerification({ ...check, ...changed }), false, why)
    }
    assert.equal(verificationCheck({ ...shown, proof: shown.proof.slice(1) }, alice.address), null)
    assert.equal(verificationCheck({ ...shown, verifier: shown.verifier.slice(1) }, alice.address), null, 'a verifier that is no address')

    for (const field of ['verifier', 'verifierName', 'label', 'proof']) assert.ok(!fits('profile', set(field, undefined)), field)
    assert.ok(!fits('profile', set('extra', 1)), 'nothing checkVerification does not take')
    assert.ok(!fits('profile', set('month', 202609)), 'the month a proof once showed, too')
    const bad: { [field: string]: unknown[] } = {
      verifier: [pointOf(shown.verifier).map((n) => n.toString(16).padStart(64, '0')).join(''), shown.verifier + '0', 'x', 7, pointOf(shown.verifier).map(String)],
      verifierName: ['', 'x'.repeat(257), 1],
      label: ['', 'x'.repeat(129), 1],
      proof: [shown.proof.slice(1), shown.proof + 'A', shown.proof.replace(/^./, '+')],
    }
    for (const [field, values] of Object.entries(bad)) {
      for (const value of values) assert.ok(!fits('profile', set(field, value)), `${field} ${JSON.stringify(value)}`)
    }
  })
})
