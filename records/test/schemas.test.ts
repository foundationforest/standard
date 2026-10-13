// The three record schemas (schemas/*.json), checked with a standard JSON Schema validator: the
// examples and the bodies the other tests publish fit them; each rule still refuses what it
// refused; every example is a body a record can carry.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { describe, test } from 'node:test'
import { Ajv2020 } from 'ajv/dist/2020.js'
import formats from 'ajv-formats'
import { checkValue } from '../src/canonical.ts'
import { inboxKey } from '../../keys/src/index.ts'
import { inboxOf } from '../src/message.ts'
import { checkRecord, decodeRecord, encodeRecord } from '../src/record.ts'
import { ownerRecord } from '../src/write.ts'
import { T0, alice, offerBody, profileBody, reviewBody } from './fixtures.ts'

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

describe('schemas', () => {
  test('each example fits its schema, and so do the bodies the other tests publish', () => {
    for (const kind of KINDS) assert.ok(fits(kind, example(kind)), `${kind}: ${ajv.errorsText(validators[kind]!.errors)}`)
    assert.ok(fits('profile', profileBody('Ana')))
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

  test('records stay open: a market adds fields, and a field nobody defined is not refused', () => {
    assert.ok(fits('offer', example('offer'))) // subjects and languages come from the online-tutors market
    assert.ok(fits('review', example('review'))) // sessions, too
    for (const kind of KINDS) assert.ok(fits(kind, { ...example(kind), anythingElse: 1 }), kind)
  })

  test('the required fields', () => {
    for (const field of ['market', 'role', 'createdAt']) assert.ok(!fits('profile', edit('profile', [field], undefined)), field)
    assert.ok(fits('profile', edit('profile', ['name'], undefined)), 'a card without a name is shown by its market and role')
    for (const field of ['direction', 'description', 'createdAt']) assert.ok(!fits('offer', edit('offer', [field], undefined)), field)
    for (const field of ['subject', 'createdAt']) assert.ok(!fits('review', edit('review', [field], undefined)), field)
    assert.ok(fits('review', { subject: alice.address, createdAt: '2026-10-02T12:00:00Z' }), 'a review can be as thin as pointing at a person')
    assert.ok(!fits('offer', edit('offer', ['createdAt'], 'yesterday')))
  })

  test('decimals are text: an amount, a rating or a degree as a number is refused', () => {
    assert.ok(!fits('offer', edit('offer', ['price', 'amount'], 25)))
    assert.ok(!fits('review', edit('review', ['ratings', 'overall'], 9)))
    const located = edit('offer', ['location'], { lat: '38.72', lon: '-9.14', precisionKm: 1, area: 'Lisbon' })
    assert.ok(fits('offer', located))
    assert.ok(!fits('offer', { ...located, location: { ...located.location, lat: 38.72 } }))
  })

  test('blobs are SHA-256 references with their types and sizes; which types and how large is each host’s own choice, not the shape’s', () => {
    for (const type of ['image/png', 'image/gif', 'image/svg+xml', 'application/vnd.oasis.opendocument.text']) {
      assert.ok(fits('profile', edit('profile', ['photo', 'mimeType'], type)), type)
      assert.ok(fits('offer', edit('offer', ['media'], [{ sha256: 'b'.repeat(64), mimeType: type, size: 1 }])), type)
      assert.ok(fits('review', edit('review', ['media'], [{ sha256: 'b'.repeat(64), mimeType: type, size: 1 }])), type)
    }
    for (const type of ['Image/PNG', 'image', 'image/', '/png', 'image/png; charset=x', 'image/p ng', '', 'a/' + 'b'.repeat(254)]) {
      assert.ok(!fits('profile', edit('profile', ['photo', 'mimeType'], type)), type)
    }
    assert.ok(fits('profile', edit('profile', ['photo', 'size'], 1_000_001)))
    assert.ok(!fits('profile', edit('profile', ['photo', 'size'], -1)))
    assert.ok(!fits('profile', edit('profile', ['photo', 'sha256'], 'A'.repeat(64))))
    assert.ok(!fits('profile', edit('profile', ['photo', 'ref'], 'bafkrei…')), 'a reference is nothing but its hash, type and size')
    const clip = { sha256: 'b'.repeat(64), mimeType: 'video/mp4', size: 50_000_000 }
    assert.ok(fits('review', edit('review', ['media'], Array(10).fill(clip))))
    assert.ok(!fits('review', edit('review', ['media'], Array(11).fill(clip))))
    assert.ok(fits('review', edit('review', ['media'], [{ ...clip, size: 50_000_001 }])))
    assert.ok(fits('offer', edit('offer', ['media'], [{ ...clip, size: 50_000_001 }])))
    assert.ok(fits('offer', edit('offer', ['media'], Array(10).fill(clip))), 'an offer carries the same media as a review')
    assert.ok(!fits('offer', edit('offer', ['media'], Array(11).fill(clip))))
  })

  test('an offer’s price, terms and timer keep their choices and bounds', () => {
    assert.ok(!fits('offer', edit('offer', ['direction'], 'sell')))
    assert.ok(!fits('offer', edit('offer', ['price', 'per'], 'week')))
    assert.ok(!fits('offer', edit('offer', ['price', 'per'], undefined)))
    assert.ok(fits('offer', edit('offer', ['terms'], {})), 'no terms: no arbiter and no timer')
    for (const [days, ok] of [[1, true], [65535, true], [0, false], [65536, false]] as const) {
      assert.equal(fits('offer', edit('offer', ['terms', 'timer'], { days, to: 'seller' })), ok, `days ${days}`)
    }
    assert.ok(!fits('offer', edit('offer', ['terms', 'timer'], { days: 3, to: 'arbiter' })))
    assert.ok(!fits('offer', edit('offer', ['location'], { lat: '0', lon: '0', precisionKm: 20001, area: 'x' })))
  })

  test('degrees accept exactly what the old rule accepted: at most 4 decimals, within ±90 and ±180', () => {
    // The old rule: /^-?[0-9]{1,3}(\.[0-9]{1,4})?$/, the value within bounds, and the lexicon's
    // maxLength (8 for lat, 9 for lon). Every spelling below is judged both ways.
    const OLD = /^-?[0-9]{1,3}(\.[0-9]{1,4})?$/
    const whole = ['0', '00', '000', '5', '05', '005', '9', '09', '10', '45', '89', '089', '90', '090', '91', '099', '100', '179', '0179', '180', '181', '199', '200', '999', '1000']
    const fraction = ['', '.', '.0', '.00', '.0000', '.00000', '.5', '.0001', '.9999', '.12345', 'e1']
    let judged = 0
    for (const sign of ['', '-', '+']) {
      for (const w of whole) {
        for (const f of fraction) {
          const v = sign + w + f
          for (const [key, bound, maxLength] of [['lat', 90, 8], ['lon', 180, 9]] as const) {
            const old = OLD.test(v) && Math.abs(Number(v)) <= bound && v.length <= maxLength
            const place = { lat: '0', lon: '0', precisionKm: 0, area: 'here', [key]: v }
            assert.equal(fits('offer', edit('offer', ['location'], place)), old, `${key} ${JSON.stringify(v)}`)
            judged++
          }
        }
      }
    }
    assert.equal(judged, 3 * whole.length * fraction.length * 2)
  })

  test('a review names a profile by its address, and its ratings run from 1 to 10 with one decimal', () => {
    for (const subject of ['did:key:z6MkpSx7aRn6kR1oSMgun7YdDD3ZXPepph8UcWYp1Jp4vhJL', 'did:web:example.com', alice.address.replace(/^./, '0')]) {
      assert.ok(!fits('review', edit('review', ['subject'], subject)), subject)
    }
    for (const rating of ['1', '1.0', '5.5', '9.9', '10', '10.0']) assert.ok(fits('review', edit('review', ['ratings', 'overall'], rating)), rating)
    for (const rating of ['0', '0.5', '10.5', '11', '9.55', '8.', '.5', '07', ' 8']) assert.ok(!fits('review', edit('review', ['ratings', 'overall'], rating)), rating)
    assert.ok(fits('review', edit('review', ['ratings', 'punctuality'], '7.5')), 'any name may be used')
    assert.ok(!fits('review', edit('review', ['ratings', 'punctuality'], '11')), 'and every rating is checked')
  })

  test('a profile’s inboxKey is its inbox key, an age post-quantum hybrid recipient', async () => {
    assert.ok(fits('profile', edit('profile', ['inboxKey'], (await inboxKey(alice.privateKey)).recipient)))
    assert.ok(fits('profile', edit('profile', ['inboxKey'], undefined)), 'optional')
    for (const bad of ['age1pq1' + 'q'.repeat(60), alice.address, 'AGE1' + 'Q'.repeat(58), 'age1' + 'b'.repeat(58)]) assert.ok(!fits('profile', edit('profile', ['inboxKey'], bad)), bad)
  })

  test('a profile’s inbox: open to anyone or to an issuer’s rows, once, a size, readers; nothing else', async () => {
    const reader = (await inboxKey(new Uint8Array(32).fill(5))).recipient
    const issuer = '1f94c72d4e5d0f9f6d4ea3b1135b4af2eaec6d14ebe63a96a2f136236887c09611bfedb43d85cb0ead1845d088ba92eb5c96715cde3ccf90607eb007285c2ea6'
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

  test('a profile’s proofs: up to four; a reputation proof is exactly what its verifier takes; another circuit’s fields are its own', () => {
    const one = example('profile').proofs[0]
    const proofs = (...items: unknown[]) => edit('profile', ['proofs'], items)
    const set = (field: string, value: unknown) => edit('profile', ['proofs', 0, field], value)
    assert.ok(fits('profile', edit('profile', ['proofs'], undefined)), 'optional')
    assert.ok(fits('profile', proofs(one, one, one, one)))
    assert.ok(!fits('profile', proofs(one, one, one, one, one)))
    assert.ok(fits('profile', set('label', 'online-tutors/seller')), 'a label, when the proof shows one market')

    const later = { circuit: 'kyc-age', over: 18, anything: { at: ['all'] } }
    assert.ok(fits('profile', proofs(later, one)), 'a circuit nobody defined yet is not refused, so an older app ignores it')
    assert.ok(checkRecord(ownerRecord(alice, 'profile', proofs(later, one), T0)), 'and a record carries it')
    for (const circuit of [undefined, '', 'Reputation', '1x', 'x_y', 'x'.repeat(33), 7]) {
      assert.ok(!fits('profile', proofs({ ...later, circuit })), String(circuit))
    }

    for (const field of ['index', 'root', 'time', 'signature', 'score', 'proof']) assert.ok(!fits('profile', set(field, undefined)), field)
    assert.ok(!fits('profile', set('extra', 1)), 'a reputation proof carries nothing its verifier does not take')
    const bad: { [field: string]: unknown[] } = {
      index: ['x', alice.address.replace(/^./, '0'), 'I'.repeat(44)],
      root: [one.root.toUpperCase(), one.root.slice(1), '0x' + one.root.slice(2), BigInt('0x' + one.root).toString()],
      time: [-1, 1.5, 2 ** 53, '1790812800000'],
      signature: [one.signature.slice(1), one.signature + 'A', one.signature.replace(/^./, '+'), one.signature + '=='],
      score: [-1, 2 ** 32, 8.7, '87'],
      label: ['', 'x'.repeat(129), 1],
      proof: [one.proof.slice(1), one.proof + 'A', one.proof.replace(/^./, '/')],
    }
    for (const [field, values] of Object.entries(bad)) {
      for (const value of values) assert.ok(!fits('profile', set(field, value)), `${field} ${JSON.stringify(value)}`)
    }
    assert.ok(fits('profile', set('score', 2 ** 32 - 1)), 'the largest score')
    assert.ok(fits('profile', set('time', 2 ** 53 - 1)), 'the latest time')
  })

  test('a profile’s person proof: exactly what verifyTier takes, and the example is a proof the registry program took', () => {
    const at = example('profile').proofs.findIndex((p: { circuit: string }) => p.circuit === 'person')
    const shown = example('profile').proofs[at]
    const set = (field: string, value: unknown) => edit('profile', ['proofs', at, field], value)

    // The registry's fixture (registry/client checks verifyTier takes this entry against its row).
    const fixtures = read('../../registry/program/tests-litesvm/fixtures/proofs.json')
    const taken = fixtures.proofs.find((p: { name: string }) => p.name === 'alice-tutoring-A')
    const { a, b, c } = taken.uncompressed
    assert.deepEqual(shown, {
      circuit: 'person',
      issuer: taken.issuerKey,
      label: taken.label,
      stamp: taken.stamp,
      tier: BigInt('0x' + taken.tier).toString(),
      proof: Buffer.from(a + b + c, 'hex').toString('base64url'),
    })
    assert.equal(`${example('profile').market}/${example('profile').role}`, shown.label, 'the profile’s own label')

    for (const field of ['issuer', 'label', 'stamp', 'tier', 'proof']) assert.ok(!fits('profile', set(field, undefined)), field)
    assert.ok(!fits('profile', set('extra', 1)), 'nothing verifyTier does not take')
    const bad: { [field: string]: unknown[] } = {
      issuer: [shown.issuer.toUpperCase(), shown.issuer.slice(1), shown.issuer + '0', taken.profile],
      label: ['', 'x'.repeat(129), 1],
      stamp: [shown.stamp.toUpperCase(), shown.stamp.slice(1), shown.stamp + '0', '0x' + shown.stamp.slice(2)],
      tier: [2, '02', '-1', '1.0', '', ' 2', '1'.repeat(78)],
      proof: [shown.proof.slice(1), shown.proof + 'A', shown.proof.replace(/^./, '+')],
    }
    for (const [field, values] of Object.entries(bad)) {
      for (const value of values) assert.ok(!fits('profile', set(field, value)), `${field} ${JSON.stringify(value)}`)
    }
    for (const tier of ['0', '1', '9'.repeat(77)]) assert.ok(fits('profile', set('tier', tier)), tier)
  })

  test('a deal id is an escrow address or 32 bytes of lowercase hex', () => {
    assert.ok(fits('review', edit('review', ['dealId'], 'a1'.repeat(32))))
    assert.ok(fits('review', edit('review', ['dealId'], alice.address)))
    for (const id of ['A1'.repeat(32), 'a1'.repeat(31), 'xyz', '0OIl' + 'a'.repeat(40)]) assert.ok(!fits('review', edit('review', ['dealId'], id)), id)
  })
})
