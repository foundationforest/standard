// The view: versions, deletes, and only the main key's records. All pure, no network.

import assert from 'node:assert/strict'
import { randomInt } from 'node:crypto'
import { describe, test } from 'node:test'
import { type Checked, RecordError, type SignedRecord, checkRecord, signAs, signingInput } from '../src/record.ts'
import { liveContent, viewProfile } from '../src/view.ts'
import { hostsRecord, nextTime, ownerRecord } from '../src/write.ts'
import { MINUTE, T0, alice, bob, offerBody, profileBody, stranger } from './fixtures.ts'

const checked = (...records: SignedRecord[]): Checked[] => records.map((r) => checkRecord(r))
const view = (records: SignedRecord[], now = T0 + MINUTE) => viewProfile(alice.address, checked(...records), now)
const idOf = (r: SignedRecord) => checkRecord(r).id

describe('versions', () => {
  test('the newest time wins, whatever order the records come in', () => {
    const v1 = ownerRecord(alice, 'offer/maths', offerBody('30'), T0)
    const v2 = ownerRecord(alice, 'offer/maths', offerBody('35'), T0 + 1000)
    assert.equal(view([v2, v1]).current.get('offer/maths')!.id, idOf(v2))
    assert.equal(view([v1, v2]).ignored.get(idOf(v1)), 'older')
  })

  test('a null body deletes; the live content drops the path', () => {
    const v1 = ownerRecord(alice, 'offer/maths', offerBody('30'), T0)
    const gone = ownerRecord(alice, 'offer/maths', null, T0 + 1000)
    const v = view([v1, gone])
    assert.equal(v.current.get('offer/maths')!.record.body, null)
    assert.equal(liveContent(v).has('offer/maths'), false)
  })

  test('an edit never loses to its own older version, whatever the app’s clock says', () => {
    const v1 = ownerRecord(alice, 'profile', profileBody('maths'), T0 + 5 * MINUTE)
    const slowClock = T0 // a phone whose clock is five minutes slow
    const v2 = ownerRecord(alice, 'profile', profileBody('physics'), nextTime(slowClock, view([v1], T0 + 6 * MINUTE), 'profile'))
    assert.equal(view([v1, v2], T0 + 6 * MINUTE).current.get('profile')!.id, idOf(v2))
  })

  test('records dated more than ten minutes ahead are held back until their time', () => {
    const ahead = ownerRecord(alice, 'profile', profileBody('future'), T0 + 11 * MINUTE)
    assert.equal(view([ahead], T0).current.size, 0)
    assert.equal(view([ahead], T0).ignored.get(idOf(ahead)), 'future')
    assert.equal(view([ahead], T0 + 11 * MINUTE).current.size, 1)
  })

  test('the hosts record is the owner’s newest; a delete leaves no hosts', () => {
    const one = hostsRecord(alice, ['https://a.example'], T0)
    const two = hostsRecord(alice, ['https://b.example', 'https://c.example'], T0 + 1)
    assert.deepEqual(view([two, one]).hosts, ['https://b.example', 'https://c.example'])
    assert.deepEqual(view([one, two, hostsRecord(alice, null, T0 + 2)]).hosts, [])
    assert.deepEqual(view([]).hosts, [])
  })

  test('any set of records, in any order, with duplicates, gives the same view', () => {
    const records = [
      hostsRecord(alice, ['https://a.example'], T0),
      ownerRecord(alice, 'profile', profileBody('maths'), T0),
      ownerRecord(alice, 'profile', profileBody('physics'), T0), // same time: the larger id wins
      ownerRecord(alice, 'offer/a', offerBody('1'), T0),
      ownerRecord(alice, 'offer/a', null, T0 + 1),
      ownerRecord(alice, 'offer/b', offerBody('2'), T0 + 2),
      ownerRecord(alice, 'offer/b', offerBody('3'), T0 + 3),
      ownerRecord(bob, 'offer/c', offerBody('4'), T0 + 3), // another profile's
    ]
    const summary = (list: Checked[]) => [...viewProfile(alice.address, list, T0 + MINUTE).current].map(([p, c]) => `${p}:${c.id}`).sort().join()
    const expected = summary(checked(...records))
    for (let round = 0; round < 50; round++) {
      const shuffled = checked(...records, ...records.slice(0, randomInt(records.length)))
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = randomInt(i + 1)
        ;[shuffled[i], shuffled[j]] = [shuffled[j]!, shuffled[i]!]
      }
      assert.equal(summary(shuffled), expected)
    }
  })
})

describe('one key', () => {
  test('a record signed by a key that is not the main key is refused [signature]; a view counts only the profile’s own records', () => {
    const unsigned = { v: 1 as const, profile: alice.address, path: 'offer/x', time: T0, body: offerBody('1') }
    const posing = { ...unsigned, sig: signAs(stranger, stranger.address, signingInput(unsigned)) }
    assert.throws(() => checkRecord(posing), (err: RecordError) => err.code === 'signature')
    const bobs = ownerRecord(bob, 'offer/x', offerBody('1'), T0)
    assert.equal(view([bobs]).current.size, 0, 'Bob’s record is in Bob’s folder')
  })

  test('a rule is a content path like any other: the newest record there is current, and a delete deletes it', () => {
    const path = 'rule/0123456789abcdef0123456789abcdef'
    const one = ownerRecord(alice, path, { anything: 'what a rule says is private: any body here' }, T0)
    const two = ownerRecord(alice, path, null, T0 + 1)
    assert.equal(view([one]).current.get(path)!.id, idOf(one))
    assert.equal(liveContent(view([one, two])).has(path), false)
    assert.deepEqual([...view([two, one]).ignored], [[idOf(one), 'older']])
  })
})
