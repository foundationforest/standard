// The view: what a profile's folder says, from whatever records a reader holds, at the reader's
// clock. A pure function of the set of records: where they came from and in what order does not
// matter, so two readers holding the same records agree.
//
// Rules:
//   1. Records dated more than MAX_FUTURE_MS ahead of the reader's clock are held back.
//   2. Every record is the profile's main key's (the record's check refuses any other), so at each
//      path the newest record is current. A host takes a record by the same rule.
//   3. Newest: the later time, then the larger id. A null body is a delete.

import { type Checked, type HostsBody, MAX_FUTURE_MS, isControlPath } from './record.ts'

export type View = {
  profile: string
  /** The current version of every path. A null body means the path is deleted. */
  current: Map<string, Checked>
  /** The current hosts record's urls; empty if there is none, or it was deleted. */
  hosts: string[]
  /** Records present that do not count, by id, with the reason. */
  ignored: Map<string, 'future' | 'older'>
}

/** Newer: later time, then the larger id. */
export function isNewer(a: Checked, b: Checked): boolean {
  if (a.record.time !== b.record.time) return a.record.time > b.record.time
  return a.id > b.id
}

export function viewProfile(profile: string, records: Iterable<Checked>, now: number): View {
  const ignored: View['ignored'] = new Map()
  const current = new Map<string, Checked>()
  for (const c of records) {
    if (c.record.profile !== profile) continue
    if (c.record.time > now + MAX_FUTURE_MS) {
      ignored.set(c.id, 'future')
      continue
    }
    const top = current.get(c.record.path)
    if (top?.id === c.id) continue
    if (!top || isNewer(c, top)) {
      if (top) ignored.set(top.id, 'older')
      current.set(c.record.path, c)
    } else ignored.set(c.id, 'older')
  }
  const hosts = (current.get('hosts')?.record.body as HostsBody | null | undefined)?.urls ?? []
  return { profile, current, hosts, ignored }
}

/** The live content of a view: current versions that are not deletes, control records left out. */
export function liveContent(view: View): Map<string, Checked> {
  const out = new Map<string, Checked>()
  for (const [path, c] of view.current) if (!isControlPath(path) && c.record.body !== null) out.set(path, c)
  return out
}
