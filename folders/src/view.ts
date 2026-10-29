// The view: what a folder says, from whatever entries a reader holds, at the reader's clock. A pure
// function of the set of entries: where they came from and in what order does not matter, so two
// readers holding the same entries agree.
//
// Rules:
//   1. Entries dated more than MAX_FUTURE_MS ahead of the reader's clock are held back.
//   2. The current profile entry is the newest at `profile`; only the main key writes it.
//   3. An entry counts if the main key signed it, or an access key the current profile entry lists
//      with write. A key removed from the list stops counting, and its entries with it.
//   4. At each path, the newest entry that counts is current. A host takes an entry by the same
//      rule.
//   5. Newest: the later time, then the larger id. A null body is a delete.

import { type Checked, MAX_FUTURE_MS, PROFILE_PATH } from './entry.ts'
import { type ListedKey, hostsOf, keysOf } from './profile.ts'

export type View = {
  profile: string
  /** The current version of every path, the profile entry's among them. A null body means the path is deleted. */
  current: Map<string, Checked>
  /** The hosts the current profile entry names; none if there is none, or it was deleted. */
  hosts: string[]
  /** The access keys the current profile entry lists that count. */
  keys: ListedKey[]
  /** Entries present that do not count, by id, with the reason. */
  ignored: Map<string, 'future' | 'older' | 'unlisted'>
}

/** Newer: later time, then the larger id. */
export function isNewer(a: Checked, b: Checked): boolean {
  if (a.entry.time !== b.entry.time) return a.entry.time > b.entry.time
  return a.id > b.id
}

export function viewFolder(profile: string, entries: Iterable<Checked>, now: number): View {
  const ignored: View['ignored'] = new Map()
  const held = new Map<string, Checked>()
  for (const c of entries) {
    if (c.entry.profile !== profile) continue
    if (c.entry.time > now + MAX_FUTURE_MS) ignored.set(c.id, 'future')
    else held.set(c.id, c)
  }
  let top: Checked | undefined
  for (const c of held.values()) if (c.entry.path === PROFILE_PATH && c.entry.key === undefined && (!top || isNewer(c, top))) top = c
  const keys = keysOf(top?.entry.body)
  const writers = new Set(keys.filter((k) => k.can.includes('write')).map((k) => k.key))
  const current = new Map<string, Checked>()
  for (const c of held.values()) {
    const { key, path } = c.entry
    if (key !== undefined && (path === PROFILE_PATH || !writers.has(key))) {
      ignored.set(c.id, 'unlisted')
      continue
    }
    const was = current.get(path)
    if (!was || isNewer(c, was)) {
      if (was) ignored.set(was.id, 'older')
      current.set(path, c)
    } else ignored.set(c.id, 'older')
  }
  return { profile, current, hosts: hostsOf(top?.entry.body), keys, ignored }
}

/** The live content of a view: current versions that are not deletes. */
export function liveContent(view: View): Map<string, Checked> {
  const out = new Map<string, Checked>()
  for (const [path, c] of view.current) if (c.entry.body !== null) out.set(path, c)
  return out
}
