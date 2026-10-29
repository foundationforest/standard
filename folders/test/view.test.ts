// The view: versions, deletes, and which entries count: the main key's, and an access key's while
// the current profile entry lists it with write. All pure, no network.

import assert from 'node:assert/strict'
import { randomInt } from 'node:crypto'
import { describe, test } from 'node:test'
import { type Checked, type SignedEntry, checkEntry, signAs, signingInput } from '../src/entry.ts'
import { liveContent, viewFolder } from '../src/view.ts'
import { entry, nextTime } from '../src/write.ts'
import { MINUTE, T0, access, alice, asAccess, bob, listed, offerBody, profileBody, stranger } from './fixtures.ts'

const checked = (...entries: SignedEntry[]): Checked[] => entries.map((e) => checkEntry(e))
const view = (entries: SignedEntry[], now = T0 + MINUTE) => viewFolder(alice.address, checked(...entries), now)
const idOf = (e: SignedEntry) => checkEntry(e).id
/** Alice's profile entry, listing her access key with what it can do, or listing none. */
const profileWith = (can: string[] | null, time = T0) => entry(alice, 'profile', profileBody('maths', can ? { keys: [listed(can)] } : {}), time)

describe('versions', () => {
  test('the newest time wins, whatever order the entries come in', () => {
    const v1 = entry(alice, 'offer/maths', offerBody('30'), T0)
    const v2 = entry(alice, 'offer/maths', offerBody('35'), T0 + 1000)
    assert.equal(view([v2, v1]).current.get('offer/maths')!.id, idOf(v2))
    assert.equal(view([v1, v2]).ignored.get(idOf(v1)), 'older')
  })

  test('a null body deletes; the live content drops the path', () => {
    const v1 = entry(alice, 'offer/maths', offerBody('30'), T0)
    const gone = entry(alice, 'offer/maths', null, T0 + 1000)
    const v = view([v1, gone])
    assert.equal(v.current.get('offer/maths')!.entry.body, null)
    assert.equal(liveContent(v).has('offer/maths'), false)
  })

  test('an edit never loses to its own older version, whatever the app’s clock says', () => {
    const v1 = entry(alice, 'profile', profileBody('maths'), T0 + 5 * MINUTE)
    const slowClock = T0 // a phone whose clock is five minutes slow
    const v2 = entry(alice, 'profile', profileBody('physics'), nextTime(slowClock, view([v1], T0 + 6 * MINUTE), 'profile'))
    assert.equal(view([v1, v2], T0 + 6 * MINUTE).current.get('profile')!.id, idOf(v2))
  })

  test('entries dated more than ten minutes ahead are held back until their time', () => {
    const ahead = entry(alice, 'profile', profileBody('future'), T0 + 11 * MINUTE)
    assert.equal(view([ahead], T0).current.size, 0)
    assert.equal(view([ahead], T0).ignored.get(idOf(ahead)), 'future')
    assert.equal(view([ahead], T0 + 11 * MINUTE).current.size, 1)
  })

  test('the hosts are the newest profile entry’s; a delete leaves none', () => {
    const one = entry(alice, 'profile', profileBody('x', { hosts: ['https://a.example'] }), T0)
    const two = entry(alice, 'profile', profileBody('x', { hosts: ['https://b.example', 'https://c.example'] }), T0 + 1)
    assert.deepEqual(view([two, one]).hosts, ['https://b.example', 'https://c.example'])
    assert.deepEqual(view([one, two, entry(alice, 'profile', null, T0 + 2)]).hosts, [])
    assert.deepEqual(view([]).hosts, [])
  })

  test('any set of entries, in any order, with duplicates, gives the same view', () => {
    const entries = [
      profileWith(['write'], T0),
      entry(alice, 'profile', profileBody('physics', { keys: [listed(['write'])] }), T0), // same time: the larger id wins
      entry(alice, 'offer/a', offerBody('1'), T0),
      entry(alice, 'offer/a', null, T0 + 1),
      entry(asAccess, 'offer/b', offerBody('2'), T0 + 2),
      entry(alice, 'offer/b', offerBody('3'), T0 + 3),
      entry(asAccess, 'offer/c', offerBody('4'), T0 + 3),
      entry({ profile: alice.address, key: stranger }, 'offer/d', offerBody('5'), T0 + 4), // a key nobody listed
      entry(bob, 'offer/c', offerBody('6'), T0 + 3), // another profile's
    ]
    const summary = (list: Checked[]) => [...viewFolder(alice.address, list, T0 + MINUTE).current].map(([p, c]) => `${p}:${c.id}`).sort().join()
    const expected = summary(checked(...entries))
    for (let round = 0; round < 50; round++) {
      const shuffled = checked(...entries, ...entries.slice(0, randomInt(entries.length)))
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = randomInt(i + 1)
        ;[shuffled[i], shuffled[j]] = [shuffled[j]!, shuffled[i]!]
      }
      assert.equal(summary(shuffled), expected)
    }
  })
})

describe('who writes', () => {
  test('a key that is not the main key, and that the profile entry does not list, signs nothing that counts', () => {
    const unsigned = { v: 1 as const, profile: alice.address, path: 'offer/x', time: T0, body: offerBody('1') }
    assert.throws(() => checkEntry({ ...unsigned, sig: signAs(stranger, stranger.address, signingInput(unsigned)) }), /signature/, 'unnamed, it is checked as the main key’s')
    const named = entry({ profile: alice.address, key: stranger }, 'offer/x', offerBody('1'), T0)
    assert.equal(view([profileWith(['write']), named]).ignored.get(idOf(named)), 'unlisted')
    assert.equal(view([entry(bob, 'offer/x', offerBody('1'), T0)]).current.size, 0, 'Bob’s entry is in Bob’s folder')
  })

  test('an access key’s entry counts while the current profile entry lists it with write, and not before, nor with only another can', () => {
    const byKey = entry(asAccess, 'offer/x', offerBody('by the key'), T0 + 1)
    assert.equal(view([byKey]).ignored.get(idOf(byKey)), 'unlisted', 'no profile entry, no listed key')
    for (const can of [['read'], ['read-inbox', 'message'], []]) assert.equal(view([profileWith(can), byKey]).ignored.get(idOf(byKey)), 'unlisted', can.join())
    const v = view([profileWith(['write']), byKey])
    assert.equal(v.current.get('offer/x')!.id, idOf(byKey))
    assert.deepEqual(v.keys.map((k) => k.key), [access.address])
  })

  test('a key removed from the list stops counting, and its entries with it: the main key’s older entry at the path is current again', () => {
    const mine = entry(alice, 'offer/x', offerBody('the main key’s'), T0)
    const byKey = entry(asAccess, 'offer/x', offerBody('by the key'), T0 + 1)
    assert.equal(view([profileWith(['write'], T0), mine, byKey]).current.get('offer/x')!.id, idOf(byKey))
    const removed = view([profileWith(['write'], T0), profileWith(null, T0 + 2), mine, byKey])
    assert.equal(removed.current.get('offer/x')!.id, idOf(mine))
    assert.equal(removed.ignored.get(idOf(byKey)), 'unlisted')
    assert.deepEqual(removed.keys, [])
    // Listed again, it counts again: nothing is kept of when it was listed.
    assert.equal(view([profileWith(null, T0), profileWith(['write'], T0 + 2), mine, byKey]).current.get('offer/x')!.id, idOf(byKey))
  })

  test('a note is a path like any other: the newest entry there is current, and a delete deletes it', () => {
    const path = 'key/0123456789abcdef0123456789abcdef'
    const one = entry(alice, path, { private: 'what a note says is locked: any body here' }, T0)
    const two = entry(alice, path, null, T0 + 1)
    assert.equal(view([one]).current.get(path)!.id, idOf(one))
    assert.equal(liveContent(view([one, two])).has(path), false)
    assert.deepEqual([...view([two, one]).ignored], [[idOf(one), 'older']])
  })
})
