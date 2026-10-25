// Keys are free, and the protocol sets no budget. A host may refuse content records by its own
// choice, from the record and what it already stores, and the first hosts record of a folder it holds
// nothing of yet, so joining can cost. It is never asked about a hosts record for a folder it holds,
// so a person can always leave or update. The choices below are one host's examples, not the
// protocol's.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { publish } from '../src/client.ts'
import type { RecordChoice } from '../src/host.ts'
import { serviceKey } from '@foundationforest/keys'
import { hostsRecord, ownerRecord } from '../src/write.ts'
import { DAY, T0, alice, offerBody, profileBody } from './fixtures.ts'
import { startHost } from './helpers.ts'

/** A fresh key from 32 bytes: a profile's, for all a host knows. */
const freshKey = (i: number) => serviceKey(new Uint8Array(32).map((_, j) => (i * 31 + j * 7 + 1) & 255))

/** One host's choice: at most three content records a profile. */
const threeEach: RecordChoice = (_record, stored) => (stored.records < 3 ? null : 'three records a profile here')

describe('host choice', () => {
  test('the protocol sets no budget: a host that chooses nothing of its own takes 200 fresh keys', async () => {
    const host = await startHost({ now: () => T0 })
    try {
      let taken = 0
      for (let i = 0; i < 200; i++) {
        const k = freshKey(i)
        const [outcome] = await publish([host.url], [ownerRecord(k, 'profile', profileBody(`bot ${i}`), T0)])
        if (outcome!.results.every((r) => r.ok)) taken++
      }
      assert.equal(taken, 200)
    } finally {
      await host.close()
    }
  })

  test('a host’s own choice refuses content; a newer hosts record always passes', async () => {
    const host = await startHost({ now: () => T0, recordChoice: threeEach })
    try {
      const results = async (records: Parameters<typeof publish>[1]) => (await publish([host.url], records))[0]!.results.map((r) => r.error ?? 'ok')
      assert.deepEqual(await results([ownerRecord(alice, 'profile', profileBody('maths'), T0), ownerRecord(alice, 'offer/a', offerBody('1'), T0), ownerRecord(alice, 'offer/b', offerBody('1'), T0)]), ['ok', 'ok', 'ok'])
      assert.deepEqual(await results([ownerRecord(alice, 'offer/c', offerBody('1'), T0), ownerRecord(alice, 'rule/0123456789abcdef0123456789abcdef', offerBody('1'), T0)]), ['refused', 'refused'], 'a rule is content too')
      // The person can always move.
      assert.deepEqual(await results([hostsRecord(alice, ['https://elsewhere.example'], T0), hostsRecord(alice, ['https://other.example'], T0 + 1)]), ['ok', 'ok'])
    } finally {
      await host.close()
    }
  })

  test('joining can cost: a host’s own choice may refuse a folder’s first hosts record, and is never asked about a later one', async () => {
    const asked: string[] = []
    // One host's choice: a folder joins only once paid, which this example keeps as a list.
    const paid = new Set<string>()
    const choice: RecordChoice = (record, stored) => {
      asked.push(`${record.path} ${stored.records}`)
      return stored.records === 0 && !paid.has(record.profile) ? 'pay to join this host' : null
    }
    const host = await startHost({ now: () => T0, recordChoice: choice })
    try {
      const results = async (records: Parameters<typeof publish>[1]) => (await publish([host.url], records))[0]!.results.map((r) => r.error ?? 'ok')
      assert.deepEqual(await results([hostsRecord(alice, [host.url], T0)]), ['refused'], 'not paid: the first hosts record is refused')
      assert.deepEqual(await results([ownerRecord(alice, 'profile', profileBody('maths'), T0)]), ['refused'], 'and so is content, by the same choice')
      paid.add(alice.address)
      assert.deepEqual(await results([hostsRecord(alice, [host.url], T0), ownerRecord(alice, 'profile', profileBody('maths'), T0)]), ['ok', 'ok'])
      paid.delete(alice.address)
      asked.length = 0
      assert.deepEqual(await results([hostsRecord(alice, ['https://elsewhere.example'], T0 + 1)]), ['ok'], 'a folder it holds can always leave')
      assert.deepEqual(asked, [], 'and the choice was not asked')
    } finally {
      await host.close()
    }
  })
})
