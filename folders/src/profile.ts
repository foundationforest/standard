// The profile entry: the entry at `profile` in a folder, written by the main key only, and the one
// body every host reads. The fields the standard reads (README.md, The profile entry):
//
//   { market?, role?, hosts, openKey?, pay?, proofs?, keys?, files? }
//
// `hosts` says where the folder lives; `openKey`, the main key's opening half, is what envelopes
// are locked to, and a folder whose profile entry has one takes inbox entries; `keys` lists the
// access keys the profile hands out, each with what it can do. A market adds its own fields beside
// these. A listed key with a field this code does not know counts for nothing, and a `can` it does
// not know grants nothing: a field it skipped could be a limit, and refusing the whole profile
// entry instead would stop a person updating it.

import type { Json } from './canonical.ts'
import { fail } from './fail.ts'
import { publicKeyFromAddress } from './keys.ts'

type Body = { [key: string]: Json }

/** A profile entry names 1 to MAX_HOSTS hosts. */
export const MAX_HOSTS = 8
/** An open key: an age post-quantum hybrid key (mlkem768x25519), what envelopes are locked to. */
export const OPEN_KEY = /^age1pq1[02-9ac-hj-np-z]{1952}$/
/** What a listed access key can do: these four, and nothing more. */
export const CAN = ['read-inbox', 'read', 'write', 'message'] as const
export type Can = (typeof CAN)[number]
/** An access key a profile entry lists: its address, its open key when it can read, and what it can do. */
export type ListedKey = { key: string; open?: string; can: string[] }

const KEY_FIELDS = new Set(['key', 'open', 'can'])
const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)
const reads = (can: unknown[]) => can.includes('read') || can.includes('read-inbox')

/** The origin form hosts are named by, or null. https only, except http on loopback for tests. */
export function normalizeOrigin(url: string): string | null {
  let u: URL
  try {
    u = new URL(url)
  } catch {
    return null
  }
  const loopback = u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname === '[::1]'
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback)) return null
  if (u.username || u.password || u.search || u.hash || (u.pathname !== '/' && u.pathname !== '')) return null
  return u.origin
}

/**
 * The fields of a profile entry's body a host reads: `hosts`, 1 to MAX_HOSTS distinct origins;
 * `openKey`, an open key; `keys`, each with a usable address listed once, `can` a list of text, and
 * `open`, an open key, whenever it can read or read-inbox. Throws FolderError with code `profile`.
 * The rest is a reader's to check (schemas/profile.json, the proof checks).
 */
export function checkProfileBody(body: Body): void {
  const hosts = body.hosts
  if (!Array.isArray(hosts) || hosts.length < 1 || hosts.length > MAX_HOSTS) fail('profile', `hosts is 1 to ${MAX_HOSTS} origins`)
  for (const url of hosts as unknown[]) if (typeof url !== 'string' || normalizeOrigin(url) !== url) fail('profile', 'each host is an origin, https (http only on loopback)')
  if (new Set(hosts as string[]).size !== hosts.length) fail('profile', 'hosts repeat')
  if ('openKey' in body && (typeof body.openKey !== 'string' || !OPEN_KEY.test(body.openKey))) fail('profile', 'openKey is an open key, age1pq1…')
  if (!('keys' in body)) return
  if (!Array.isArray(body.keys)) fail('profile', 'keys is a list')
  const seen = new Set<string>()
  for (const item of body.keys as unknown[]) {
    if (!isObject(item)) fail('profile', 'a listed key is an object')
    if (!publicKeyFromAddress(item.key)) fail('profile', 'a listed key is an address')
    if (seen.has(item.key as string)) fail('profile', 'a key is listed once')
    seen.add(item.key as string)
    if (!Array.isArray(item.can) || item.can.some((c) => typeof c !== 'string')) fail('profile', 'can is a list of what the key can do')
    if ('open' in item && (typeof item.open !== 'string' || !OPEN_KEY.test(item.open))) fail('profile', 'open is an open key, age1pq1…')
    if (reads(item.can) && !('open' in item)) fail('profile', 'a key that can read gives its open key')
  }
}

/** The hosts a profile entry's body names; none when there is no profile entry or it was deleted. */
export function hostsOf(body: Body | null | undefined): string[] {
  const hosts = body?.hosts
  return Array.isArray(hosts) ? hosts.filter((h): h is string => typeof h === 'string') : []
}

/** The main key's open key a profile entry's body gives, or null. */
export function openKeyOf(body: Body | null | undefined): string | null {
  const openKey = body?.openKey
  return typeof openKey === 'string' && OPEN_KEY.test(openKey) ? openKey : null
}

/** The access keys a profile entry's body lists that count: each whose every field this code knows. */
export function keysOf(body: Body | null | undefined): ListedKey[] {
  const keys = body?.keys
  if (!Array.isArray(keys)) return []
  return keys.filter((k): k is ListedKey => isObject(k) && Object.keys(k).every((f) => KEY_FIELDS.has(f)) && typeof k.key === 'string' && Array.isArray(k.can))
}

/** Whether a profile entry's body lists `address` as an access key that can do `can`. */
export function canDo(body: Body | null | undefined, address: string, can: Can): boolean {
  return keysOf(body).some((k) => k.key === address && k.can.includes(can))
}

/**
 * The open keys a locked entry in this folder is locked to: the main key's, then each listed key's
 * that can read. Throws FolderError `locked` when the profile entry gives no open key.
 */
export function lockKeysOf(body: Body | null | undefined): string[] {
  return opening(body, 'read', 'locked', 'the profile entry gives no open key to lock to')
}

/**
 * The open keys an inbox entry to this folder is locked to: the main key's, then each listed key's
 * that can read-inbox. Throws FolderError `no_inbox` when the profile entry gives no open key, so
 * the folder takes no inbox entries.
 */
export function inboxLockKeysOf(body: Body | null | undefined): string[] {
  return opening(body, 'read-inbox', 'no_inbox', 'the profile entry gives no open key: the folder takes no inbox entries')
}

function opening(body: Body | null | undefined, can: Can, code: string, why: string): string[] {
  const openKey = openKeyOf(body)
  if (!openKey) fail(code, why)
  const keys = keysOf(body).filter((k) => k.can.includes(can) && typeof k.open === 'string' && OPEN_KEY.test(k.open))
  return [...new Set([openKey, ...keys.map((k) => k.open!)])]
}
