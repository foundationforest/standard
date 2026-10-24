// Making records: what an app does before publishing them.

import type { Key } from './keys.ts'
import { type Body, type SignedRecord, signRecord } from './record.ts'
import type { View } from './view.ts'

/**
 * The time for a new version: the clock, but always after the newest version the app knows
 * at that path, so a slow clock cannot make an edit lose to what it replaces.
 */
export function nextTime(now: number, view: View | undefined, path: string): number {
  const top = view?.current.get(path)
  return top ? Math.max(now, top.record.time + 1) : now
}

/** A record signed by the profile's main key: the only key that signs for it. */
export function ownerRecord(owner: Key, path: string, body: Body | null, time: number): SignedRecord {
  return signRecord({ v: 1, profile: owner.address, path, time, body }, owner)
}

/** Where the profile's records live. */
export function hostsRecord(owner: Key, urls: string[] | null, time: number): SignedRecord {
  return ownerRecord(owner, 'hosts', urls && { urls }, time)
}
