// Making records: what an app does before publishing them.

import type { Key } from './keys.ts'
import { type AccessKey, type Body, type SignedRecord, signRecord } from './record.ts'
import type { View } from './view.ts'

/**
 * The time for a new version: the clock, but always after the newest version the app knows
 * at that path, so a slow clock cannot make an edit lose to what it replaces.
 */
export function nextTime(now: number, view: View | undefined, path: string): number {
  const top = view?.current.get(path)
  return top ? Math.max(now, top.record.time + 1) : now
}

/** A record signed by the main key itself. */
export function ownerRecord(owner: Key, path: string, body: Body | null, time: number): SignedRecord {
  return signRecord({ v: 1, profile: owner.address, path, time, body }, owner)
}

/** A record signed by a write key, into a profile whose permissions record lists it. */
export function accessRecord(key: Key, profile: string, path: string, body: Body | null, time: number): SignedRecord {
  return signRecord({ v: 1, profile, path, time, body, by: key.address }, key)
}

/** Where the profile's records live. */
export function hostsRecord(owner: Key, urls: string[] | null, time: number): SignedRecord {
  return ownerRecord(owner, 'hosts', urls && { urls }, time)
}

/**
 * The access keys this folder lists, each with its scope. To remove a write key, replace its
 * `scope` with `was: "write"` and `until`, this record's `time`, keeping its paths, and keep the
 * entry as it is in every later record: it can no longer act, and what it wrote dated before
 * `until` still counts. Deleting its entry instead disowns what it wrote. A read key is removed by
 * deleting its entry.
 */
export function permissionsRecord(owner: Key, access: AccessKey[] | null, time: number): SignedRecord {
  return ownerRecord(owner, 'permissions', access && { access }, time)
}
