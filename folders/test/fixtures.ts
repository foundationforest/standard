// Shared test fixtures: keys/'s test seed, a few keys, and ready-made bodies. Folders derives no
// key: the keys come from keys/, as an app gets them.

import { readFileSync } from 'node:fs'
import { accessKey, mainKey, openingHalf, serviceKey } from '@foundationforest/keys'
import { hex } from '../src/bytes.ts'
import { canonical } from '../src/canonical.ts'
import type { Key } from '../src/keys.ts'
import { type Body, type SignedEntry, type UnsignedEntry, signAs, signingInput } from '../src/entry.ts'

/** keys/'s pinned vectors: its test seed (bytes 00 01 … 1f), its profiles, their encryption keys and its access key. */
export const KEYS = JSON.parse(readFileSync(new URL('../../keys/test/vectors.json', import.meta.url), 'utf8'))
export const SEED = hex.decode(KEYS.seed)
/** A second person. */
export const OTHER_SEED = new Uint8Array(32).fill(7)
/** A backup of keys/'s test seed, bytes 20 21 … 3f: a second seed whose Profiles folder holds SEED in its seed entry. */
export const BACKUP_SEED = Uint8Array.from({ length: 32 }, (_, i) => 0x20 + i)

export const alice = await mainKey(SEED, 'tutoring/seller')
export const aliceBuyer = await mainKey(SEED, 'tutoring/buyer') // the same person, another label
export const bob = await mainKey(OTHER_SEED, 'tutoring/buyer') // someone else
/** A key that is no one's main key here, nor listed anywhere: what tries to sign for a profile it is not. */
export const stranger = serviceKey(new Uint8Array(32).fill(99))
/** keys/'s pinned access key, from 32 bytes of 0x2b: the one Alice's profile entries list. */
export const access = await accessKey(hex.decode(KEYS.accessKey.secret))
/** Alice's access key as a writer for her folder. */
export const asAccess = { profile: alice.address, key: access }

export const [aliceOpening, aliceBuyerOpening, bobOpening] = await Promise.all([openingHalf(alice.secret), openingHalf(aliceBuyer.secret), openingHalf(bob.secret)])

export const T0 = Date.UTC(2026, 9, 2, 12, 0, 0)
export const MINUTE = 60_000
export const DAY = 86_400_000

/** A listed access key: its address, its public encryption key when it can read, and what it can do. */
export const listed = (can: string[], key = access): Body => ({ key: key.address, ...(can.some((c) => c.startsWith('read')) && { open: key.openKey }), can })

/**
 * A profile entry's body for Alice: hosts, her public encryption key, and the keys given.
 * `subjects`, a field a market adds, tells one version from another.
 */
export const profileBody = (subject: string, options: { hosts?: string[]; keys?: Body[]; openKey?: string | null } = {}): Body => ({
  market: 'tutoring',
  role: 'seller',
  hosts: options.hosts ?? ['https://host-a.example'],
  ...(options.openKey !== null && { openKey: options.openKey ?? aliceOpening.openKey }),
  ...(options.keys && { keys: options.keys }),
  subjects: [subject],
})

// A listing's and a review's fields are the market's, not the standard's (README.md, Folders):
// these tests need only bodies that differ, so `about` stands in for them.
export const listingBody = (about: string): Body => ({ about })
export const reviewBody = (about: string): Body => ({ about })

/** A main-key entry whose canonical text is exactly `bytes` long, `wide` of its characters two-byte (é). */
export function sizedEntry(key: Key, path: string, bytes: number, wide = 0): SignedEntry {
  const unsigned = (about: string): UnsignedEntry => ({ v: 1, profile: key.address, path, time: T0, body: { about } })
  const rest = bytes - canonical({ ...unsigned(''), sig: 'x'.repeat(86) }).length - 2 * wide
  const u = unsigned('é'.repeat(wide) + 'x'.repeat(rest))
  return { ...u, sig: signAs(key, key.address, signingInput(u)) }
}
