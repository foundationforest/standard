// Shared test fixtures: keys/'s test seed and a few of its profiles, as an app gets them.

import { readFileSync } from 'node:fs'
import { mainKey } from '@foundationforest/keys'
import { hex } from '@foundationforest/records'

/** keys/'s pinned vectors: its test seed (bytes 00 01 … 1f), its profiles, their inbox keys and permission keys. */
export const KEYS = JSON.parse(readFileSync(new URL('../../keys/test/vectors.json', import.meta.url), 'utf8'))
export const SEED = hex.decode(KEYS.seed)

export const alice = await mainKey(SEED, 'tutoring/seller')
export const aliceBuyer = await mainKey(SEED, 'tutoring/buyer') // the same person, another label
export const bob = await mainKey(new Uint8Array(32).fill(7), 'tutoring/buyer') // someone else

export const T0 = Date.UTC(2026, 9, 2, 12, 0, 0)
export const DAY = 86_400_000
