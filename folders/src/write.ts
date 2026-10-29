// Making entries: what an app does before writing them to a folder's hosts.

import type { Key } from './keys.ts'
import { type Body, type SignedEntry, type UnsignedEntry, signEntry } from './entry.ts'
import type { View } from './view.ts'

/**
 * Who writes for a profile: its main key, or an access key the profile's entry lists, with the
 * profile's address. The same goes for a message.
 */
export type Writer = Key | { profile: string; key: Key }

/** The profile a writer writes for, and the key that signs. */
export function writerOf(writer: Writer): { profile: string; key: Key; access: boolean } {
  return 'scalar' in writer ? { profile: writer.address, key: writer, access: false } : { profile: writer.profile, key: writer.key, access: true }
}

/**
 * The time for a new version: the clock, but always after the newest version the app knows
 * at that path, so a slow clock cannot make an edit lose to what it replaces.
 */
export function nextTime(now: number, view: View | undefined, path: string): number {
  const top = view?.current.get(path)
  return top ? Math.max(now, top.entry.time + 1) : now
}

/** An entry at `path`, signed by the writer: the main key, or an access key, which names itself in `key`. */
export function entry(writer: Writer, path: string, body: Body | null, time: number): SignedEntry {
  const { profile, key, access } = writerOf(writer)
  const unsigned: UnsignedEntry = { v: 1, profile, path, time, body, ...(access && { key: key.address }) }
  return signEntry(unsigned, key)
}
