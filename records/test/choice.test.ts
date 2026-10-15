// Keys are free, and the protocol sets no budget. A host may refuse content records by its own
// choice, from the record and what it already stores. It is never asked about a hosts or
// permissions record, so a person can always move and always remove an access key. The choice below
// is one host's example, not the protocol's.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { publish } from '../src/client.ts'
import type { RecordChoice } from '../src/host.ts'
import { accessKey as makeKey } from '../../keys/src/index.ts'
import { accessRecord, hostsRecord, ownerRecord, permissionsRecord } from '../src/write.ts'
import { DAY, T0, accessKey, alice, allow, offerBody, profileBody } from './fixtures.ts'
import { startHost } from './helpers.ts'

const freshKey = (i: number) => makeKey(new Uint8Array(32).map((_, j) => (i * 31 + j * 7 + 1) & 255))

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

  test('a host’s own choice refuses content; a newer hosts or permissions record always passes', async () => {
    const host = await startHost({ now: () => T0, recordChoice: threeEach })
    try {
      const results = async (records: Parameters<typeof publish>[1]) => (await publish([host.url], records))[0]!.results.map((r) => r.error ?? 'ok')
      assert.deepEqual(await results([ownerRecord(alice, 'profile', profileBody('maths'), T0), ownerRecord(alice, 'offer/a', offerBody('1'), T0), ownerRecord(alice, 'offer/b', offerBody('1'), T0)]), ['ok', 'ok', 'ok'])
      assert.deepEqual(await results([ownerRecord(alice, 'offer/c', offerBody('1'), T0)]), ['refused'])
      // An access key went bad and floods: the person can always remove it, and always move.
      assert.deepEqual(await results([permissionsRecord(alice, [allow(accessKey, ['offer'])], T0)]), ['ok'])
      assert.deepEqual(await results([accessRecord(accessKey, alice.address, 'offer/w', offerBody('1'), T0)]), ['refused'])
      assert.deepEqual(await results([permissionsRecord(alice, [], T0 + 1), hostsRecord(alice, ['https://elsewhere.example'], T0)]), ['ok', 'ok'])
    } finally {
      await host.close()
    }
  })
})
