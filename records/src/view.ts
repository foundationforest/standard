// The view: what a profile's folder says, from whatever records a reader holds, at the reader's
// clock. A pure function of the set of records: where they came from and in what order does not
// matter, so two readers holding the same records agree.
//
// Rules:
//   1. Records dated more than MAX_FUTURE_MS ahead of the reader's clock are held back.
//   2. `hosts` and `permissions` are the owner's alone (the shape check refuses an access key
//      there). The newest is current.
//   3. At a content path, if the owner ever wrote there, the owner's newest version is current and
//      no access key's record counts. Otherwise the newest access key's record the current
//      permissions record allows (allows): its key is listed with scope write, or was write and the
//      record is dated before the permissions record, and its paths cover the record's path (with
//      no paths, every content path but those `profile` covers). A read key never writes; a key
//      whose entry is gone counts for nothing. A host takes a record by the same rule.
//   4. Newest: the later time, then the larger id. A null body is a delete.

import { type AccessKey, type Checked, type HostsBody, MAX_FUTURE_MS, type PermissionsBody, type SignedRecord, isControlPath, pathCovers } from './record.ts'

/** Content prefixes an access key with no `paths` does not cover: the profile record. */
export const NOT_WITHOUT_PATHS = ['profile']
/** The path an access key's paths name to act on the inbox: a write key sends, a read key pulls. */
export const INBOX = 'inbox'

export type View = {
  profile: string
  /** The current version of every path. A null body means the path is deleted. */
  current: Map<string, Checked>
  /** The current hosts record's urls; empty if there is none, or it was deleted. */
  hosts: string[]
  /** The current permissions record's access keys; empty if there is none, or it was deleted. */
  access: AccessKey[]
  /** The current permissions record's time, 0 if there is none: a past key's records count only when dated before it. */
  permissionsTime: number
  /** Records present that do not count, by id, with the reason. */
  ignored: Map<string, 'future' | 'older' | 'owner-wins' | 'not-allowed'>
}

/** Newer: later time, then the larger id. */
export function isNewer(a: Checked, b: Checked): boolean {
  if (a.record.time !== b.record.time) return a.record.time > b.record.time
  return a.id > b.id
}

/**
 * Whether an access key's entry covers a content path: one of its paths does, or, with no paths,
 * any content path but those NOT_WITHOUT_PATHS cover.
 */
export function covers(entry: AccessKey, path: string): boolean {
  if (isControlPath(path)) return false
  return entry.paths ? entry.paths.some((p) => pathCovers(p, path)) : !NOT_WITHOUT_PATHS.some((p) => pathCovers(p, path))
}

/** Whether an access key's entry acts on the inbox: one of its paths covers `inbox`, or it has none. */
export function actsOnInbox(entry: AccessKey): boolean {
  return entry.paths ? entry.paths.some((p) => pathCovers(p, INBOX)) : true
}

/** Whether the access keys listed let `key` act on the inbox now, with this scope: a write key to send, a read key to pull. */
export function allowsInbox(access: readonly AccessKey[], key: string, scope: 'write' | 'read'): boolean {
  return access.some((k) => k.key === key && k.scope === scope && actsOnInbox(k))
}

/**
 * The access rule, the one a reader and a host both check: whether the current permissions record,
 * its access keys and its time, allows a record an access key signed. Its key is listed covering
 * the record's path, with scope write; or as past, was write, and the record is dated before the
 * permissions record.
 */
export function allows(access: readonly AccessKey[], permissionsTime: number, record: SignedRecord): boolean {
  return access.some((k) => k.key === record.by && covers(k, record.path) && (k.scope === 'write' || (k.was === 'write' && record.time < permissionsTime)))
}

export function viewProfile(profile: string, records: Iterable<Checked>, now: number): View {
  const ignored: View['ignored'] = new Map()
  const byPath = new Map<string, Map<string, Checked>>()
  for (const c of records) {
    if (c.record.profile !== profile) continue
    if (c.record.time > now + MAX_FUTURE_MS) {
      ignored.set(c.id, 'future')
      continue
    }
    let atPath = byPath.get(c.record.path)
    if (!atPath) byPath.set(c.record.path, (atPath = new Map()))
    atPath.set(c.id, c)
  }

  const newest = (list: Checked[]) => list.reduce((a, b) => (isNewer(b, a) ? b : a))
  const permissions = byPath.get('permissions')
  const permissionsRecord = permissions ? newest([...permissions.values()]).record : undefined
  const access = (permissionsRecord?.body as PermissionsBody | null | undefined)?.access ?? []
  const permissionsTime = permissionsRecord?.time ?? 0

  const current = new Map<string, Checked>()
  for (const [path, atPath] of byPath) {
    const all = [...atPath.values()]
    let candidates = all.filter((c) => c.record.by === undefined)
    if (candidates.length) {
      for (const c of all) if (c.record.by !== undefined) ignored.set(c.id, 'owner-wins')
    } else {
      candidates = all.filter((c) => allows(access, permissionsTime, c.record))
      for (const c of all) if (!candidates.includes(c)) ignored.set(c.id, 'not-allowed')
    }
    if (!candidates.length) continue
    const top = newest(candidates)
    current.set(path, top)
    for (const c of candidates) if (c !== top) ignored.set(c.id, 'older')
  }

  const hosts = (current.get('hosts')?.record.body as HostsBody | null | undefined)?.urls ?? []
  return { profile, current, hosts, access, permissionsTime, ignored }
}

/** The live content of a view: current versions that are not deletes, control records left out. */
export function liveContent(view: View): Map<string, Checked> {
  const out = new Map<string, Checked>()
  for (const [path, c] of view.current) if (!isControlPath(path) && c.record.body !== null) out.set(path, c)
  return out
}
