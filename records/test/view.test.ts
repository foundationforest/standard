// The view: versions, deletes, the owner first, access keys and permissions. All pure, no network.

import assert from 'node:assert/strict'
import { randomInt } from 'node:crypto'
import { describe, test } from 'node:test'
import { type Checked, type SignedRecord, checkRecord } from '../src/record.ts'
import { actsOnInbox, allowsInbox, liveContent, viewProfile } from '../src/view.ts'
import { accessRecord, hostsRecord, nextTime, ownerRecord, permissionsRecord } from '../src/write.ts'
import { DAY, MINUTE, T0, accessKey, alice, allow, bob, offerBody, pastKey, profileBody, reader, stranger } from './fixtures.ts'

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
      permissionsRecord(alice, [allow(accessKey, ['offer'])], T0),
      ownerRecord(alice, 'profile', profileBody('maths'), T0),
      ownerRecord(alice, 'profile', profileBody('physics'), T0), // same time: the larger id wins
      ownerRecord(alice, 'offer/a', offerBody('1'), T0),
      ownerRecord(alice, 'offer/a', null, T0 + 1),
      accessRecord(accessKey, alice.address, 'offer/a', offerBody('9'), T0 + 2), // the owner wrote here
      accessRecord(accessKey, alice.address, 'offer/b', offerBody('2'), T0 + 2),
      accessRecord(accessKey, alice.address, 'offer/b', offerBody('3'), T0 + 3),
      accessRecord(stranger, alice.address, 'offer/c', offerBody('4'), T0 + 3),
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

describe('access keys and permissions', () => {
  const permissions = permissionsRecord(alice, [allow(accessKey, ['offer'])], T0)
  const written = accessRecord(accessKey, alice.address, 'offer/physics', offerBody('40'), T0 + MINUTE)

  test('a key the permissions record lists with scope write writes at the paths it allows', () => {
    const v = view([permissions, written], T0 + 2 * MINUTE)
    assert.equal(v.current.get('offer/physics')!.id, idOf(written))
    assert.deepEqual(v.access, [{ key: accessKey.address, scope: 'write', paths: ['offer'] }])
  })

  test('without a permissions record, or outside its paths, an access key’s record counts for nothing', () => {
    assert.equal(view([written]).ignored.get(idOf(written)), 'not-allowed')
    const review = accessRecord(accessKey, alice.address, 'review/x', { subject: bob.address }, T0 + MINUTE)
    const sneaky = accessRecord(accessKey, alice.address, 'offerx', offerBody('1'), T0 + MINUTE) // a prefix covers whole segments
    const v = view([permissions, review, sneaky], T0 + 2 * MINUTE)
    assert.equal(v.ignored.get(idOf(review)), 'not-allowed')
    assert.equal(v.ignored.get(idOf(sneaky)), 'not-allowed')
  })

  test('with no paths, a write key covers every content path but those profile covers; with paths, only those', () => {
    const anywhere = permissionsRecord(alice, [allow(accessKey)], T0)
    const at = (path: string) => accessRecord(accessKey, alice.address, path, { text: path }, T0 + MINUTE)
    const v = view([anywhere, ...['offer/x', 'review/1', 'note/a/b', 'profiles', 'grants', 'profile', 'profile/x'].map(at)], T0 + 2 * MINUTE)
    assert.deepEqual([...liveContent(v).keys()].sort(), ['grants', 'note/a/b', 'offer/x', 'profiles', 'review/1'])
    const named = view([permissionsRecord(alice, [allow(accessKey, ['profile'])], T0), at('profile'), at('offer/x')], T0 + 2 * MINUTE)
    assert.deepEqual([...liveContent(named).keys()].sort(), ['profile'], 'paths can name it; then only those')
    assert.equal(liveContent(view([permissionsRecord(alice, [allow(accessKey, [])], T0), at('offer/x')])).size, 0, 'an empty list covers nothing')
  })

  test('only a write key writes: a record a read key signed counts for nothing, at any path, though it lists no paths', () => {
    const listed = permissionsRecord(alice, [allow(reader, undefined, 'read')], T0)
    for (const path of ['offer/physics', 'review/1', 'note']) {
      const sneaked = accessRecord(reader, alice.address, path, offerBody('30'), T0 + MINUTE)
      assert.equal(view([listed, sneaked], T0 + 2 * MINUTE).ignored.get(idOf(sneaked)), 'not-allowed', path)
    }
  })

  test('which keys act on the inbox: a write key sends and a read key pulls when their paths cover inbox, or they list none', () => {
    const access = [allow(accessKey, ['offer', 'inbox']), allow(stranger, ['offer']), allow(reader, undefined, 'read'), pastKey(bob, T0, ['inbox'])]
    assert.equal(allowsInbox(access, accessKey.address, 'write'), true)
    assert.equal(allowsInbox(access, stranger.address, 'write'), false, 'its paths do not cover inbox')
    assert.equal(allowsInbox(access, reader.address, 'read'), true, 'no paths: the inbox too')
    assert.equal(allowsInbox(access, reader.address, 'write'), false, 'a read key does not send')
    assert.equal(allowsInbox(access, accessKey.address, 'read'), false, 'a write key does not pull')
    assert.equal(allowsInbox(access, bob.address, 'write'), false, 'a past key acts on nothing')
    assert.equal(actsOnInbox(allow(accessKey, ['inbox/x'])), false, 'inbox/x does not cover inbox')
    assert.equal(actsOnInbox(allow(accessKey, [])), false, 'an empty list covers nothing')
  })

  test('a key the permissions record does not list counts for nothing', () => {
    const imposter = accessRecord(stranger, alice.address, 'offer/x', offerBody('1'), T0 + MINUTE)
    assert.equal(view([permissions, imposter]).ignored.get(idOf(imposter)), 'not-allowed')
  })

  test('the owner wins: an access key cannot overwrite or delete what the owner wrote, even later', () => {
    const mine = ownerRecord(alice, 'offer/maths', offerBody('30'), T0)
    const overwrite = accessRecord(accessKey, alice.address, 'offer/maths', null, T0 + 2 * MINUTE)
    const v = view([permissions, mine, overwrite], T0 + 3 * MINUTE)
    assert.equal(v.current.get('offer/maths')!.id, idOf(mine))
    assert.equal(v.ignored.get(idOf(overwrite)), 'owner-wins')
  })

  test('the owner overrides an access key by writing at its path, at any time', () => {
    const fix = ownerRecord(alice, 'offer/physics', null, T0) // dated before the access key's record
    const v = view([permissions, written, fix], T0 + 2 * MINUTE)
    assert.equal(v.current.get('offer/physics')!.id, idOf(fix))
  })

  test('removing a write key is replacing its scope with was and adding until: what it wrote dated before its until still counts, a year later', () => {
    const past = permissionsRecord(alice, [pastKey(accessKey, T0 + 10 * MINUTE, ['offer'])], T0 + 10 * MINUTE)
    const v = view([permissions, written, past], T0 + 365 * DAY)
    assert.equal(v.current.get('offer/physics')!.id, idOf(written), 'a year later')
    const outside = accessRecord(accessKey, alice.address, 'review/1', { subject: bob.address }, T0 + MINUTE)
    assert.equal(view([past, outside]).ignored.get(idOf(outside)), 'not-allowed', 'a past key keeps its paths')
  })

  test('a past key’s record counts only if dated before its until; one dated at its until or after is ignored', () => {
    const past = permissionsRecord(alice, [pastKey(accessKey, T0 + 10 * MINUTE, ['offer'])], T0 + 10 * MINUTE)
    const before = accessRecord(accessKey, alice.address, 'offer/before', offerBody('1'), T0 + 10 * MINUTE - 1)
    const at = accessRecord(accessKey, alice.address, 'offer/at', offerBody('1'), T0 + 10 * MINUTE)
    const after = accessRecord(accessKey, alice.address, 'offer/after', offerBody('1'), T0 + 11 * MINUTE)
    const v = view([past, before, at, after], T0 + 365 * DAY)
    assert.equal(v.current.get('offer/before')!.id, idOf(before))
    assert.equal(v.ignored.get(idOf(at)), 'not-allowed', 'at its until')
    assert.equal(v.ignored.get(idOf(after)), 'not-allowed', 'after it')
    // A write key still listed with its scope counts whatever the date.
    assert.ok(view([permissions, accessRecord(accessKey, alice.address, 'offer/later', offerBody('1'), T0 + 2 * DAY)], T0 + 2 * DAY).current.has('offer/later'))
  })

  test('adding another key after a removal does not reopen the removed key’s window', () => {
    const removed = T0 + 10 * MINUTE
    const past = permissionsRecord(alice, [pastKey(accessKey, removed, ['offer'])], removed)
    const added = permissionsRecord(alice, [pastKey(accessKey, removed, ['offer']), allow(stranger, ['review'])], T0 + 20 * MINUTE)
    const between = accessRecord(accessKey, alice.address, 'offer/between', offerBody('1'), T0 + 15 * MINUTE)
    const v = view([past, added, between], T0 + 365 * DAY)
    assert.equal(v.access.length, 2, 'the record now current is the later one')
    assert.equal(v.ignored.get(idOf(between)), 'not-allowed', 'dated after its until, though before the permissions record now current')
  })

  test('deleting a key’s entry, or the permissions record, disowns what it wrote: it stops counting', () => {
    const dropped = permissionsRecord(alice, [], T0 + 10 * MINUTE)
    const v = view([permissions, written, dropped], T0 + 30 * DAY)
    assert.equal(v.current.has('offer/physics'), false)
    assert.equal(v.ignored.get(idOf(written)), 'not-allowed')
    assert.equal(view([permissions, written, permissionsRecord(alice, null, T0 + 10 * MINUTE)], T0 + DAY).current.has('offer/physics'), false)
  })

  test('narrowing its paths ends what it wrote outside them; another access key is untouched', () => {
    const other = accessRecord(stranger, alice.address, 'review/1', { subject: bob.address }, T0 + MINUTE)
    const both = permissionsRecord(alice, [allow(accessKey, ['offer', 'note']), allow(stranger, ['review'])], T0 + 1)
    const note = accessRecord(accessKey, alice.address, 'note/a', { text: 'x' }, T0 + MINUTE)
    const narrowed = permissionsRecord(alice, [allow(accessKey, ['note']), allow(stranger, ['review'])], T0 + 5 * MINUTE)
    const v = view([both, written, note, other, narrowed], T0 + 6 * MINUTE)
    assert.equal(v.current.has('offer/physics'), false)
    assert.equal(v.current.get('note/a')!.id, idOf(note))
    assert.equal(v.current.get('review/1')!.id, idOf(other))
  })

  test('an access key back in the permissions record brings its records back: the view is only what is current', () => {
    const dropped = permissionsRecord(alice, [], T0 + 10 * MINUTE)
    const back = permissionsRecord(alice, [allow(accessKey, ['offer'])], T0 + 20 * MINUTE)
    assert.equal(view([permissions, written, dropped, back], T0 + DAY).current.get('offer/physics')!.id, idOf(written))
  })

  test('only the owner’s permissions count: an access key cannot list itself, or use one profile’s permissions in another', () => {
    assert.throws(() => accessRecord(accessKey, alice.address, 'permissions', { access: [allow(accessKey, ['review'])] }, T0), /only the owner/)
    const intoBob = accessRecord(accessKey, bob.address, 'offer/x', offerBody('1'), T0 + 1)
    const v = viewProfile(bob.address, checked(permissions, intoBob), T0 + MINUTE)
    assert.equal(v.ignored.get(idOf(intoBob)), 'not-allowed')
  })
})
