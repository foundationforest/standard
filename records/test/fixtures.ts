// Shared test fixtures: keys/'s test seed, a few keys, and ready-made bodies. Records mixes no
// key: the keys come from keys/, as an app gets them.

import { readFileSync } from 'node:fs'
import { mainKey, serviceKey } from '@foundationforest/keys'
import { hex } from '../src/bytes.ts'
import { canonical } from '../src/canonical.ts'
import type { Key } from '../src/keys.ts'
import { type Body, type SignedRecord, type UnsignedRecord, signAs, signingInput } from '../src/record.ts'

/** keys/'s pinned vectors: its test seed (bytes 00 01 … 1f), its profiles and their inbox keys. */
export const KEYS = JSON.parse(readFileSync(new URL('../../keys/test/vectors.json', import.meta.url), 'utf8'))
export const SEED = hex.decode(KEYS.seed)
/** A second person. */
export const OTHER_SEED = new Uint8Array(32).fill(7)

export const alice = await mainKey(SEED, 'tutoring/seller')
export const aliceBuyer = await mainKey(SEED, 'tutoring/buyer') // the same person, another label
export const bob = await mainKey(OTHER_SEED, 'tutoring/buyer') // someone else
/** A key that is no one's main key here: what tries to sign for a profile it is not. */
export const stranger = serviceKey(new Uint8Array(32).fill(99))

export const T0 = Date.UTC(2026, 9, 2, 12, 0, 0)
export const MINUTE = 60_000
export const DAY = 86_400_000

/** A profile record's body. `subjects`, a field a market adds, tells one version from another. */
export const profileBody = (subject: string): Body => ({
  market: 'tutoring',
  role: 'seller',
  subjects: [subject],
})

// An offer's and a review's fields are the market's, not the standard's (README.md, Folders):
// these tests need only bodies that differ, so `about` stands in for them.
export const offerBody = (about: string): Body => ({ about })
export const reviewBody = (about: string): Body => ({ about })

/** A signed owner record whose canonical text is exactly `bytes` long, `wide` of its characters two-byte (é). */
export function sizedRecord(key: Key, path: string, bytes: number, wide = 0): SignedRecord {
  const unsigned = (about: string): UnsignedRecord => ({ v: 1, profile: key.address, path, time: T0, body: { about } })
  const rest = bytes - canonical({ ...unsigned(''), sig: 'x'.repeat(86) }).length - 2 * wide
  const u = unsigned('é'.repeat(wide) + 'x'.repeat(rest))
  return { ...u, sig: signAs(key, key.address, signingInput(u)) }
}
