// A record: one signed version of one path in one profile's folder.
//
//   { v: 1, profile, path, time, body | null, by?, sig }
//
// `sig` is EdDSA-Poseidon on Baby Jubjub, by keys/'s signBytes, over the signed bytes
// 0xff || "forest/v1/record\n" || JCS(the rest): the main key's, or the access key's named in
// `by`. It signs SHA-256 of those bytes, shifted right one byte, as a number, and is written as 64
// bytes, R8 packed then S, in base64url. A message's and a pull's signed bytes start with their own
// text, so no signature is ever two of them.

import { sha256 } from '@noble/hashes/sha2.js'
import { type Point, packSignature, publicKeyOf, signBytes, unpackSignature, verifyBytes } from '../../keys/src/curve.ts'
import { b64u, concat, hex, utf8 } from './bytes.ts'
import { type Json, canonical, checkValue, parseCanonical } from './canonical.ts'
import { type Key, publicKeyFromAddress } from './keys.ts'

export const VERSION = 1
export const SIGN_PREFIX = concat(Uint8Array.of(0xff), utf8('forest/v1/record\n'))
/** Hosts refuse, and readers hold back, records dated further ahead than this. */
export const MAX_FUTURE_MS = 10 * 60 * 1000

export type Body = { [key: string]: Json }
export type UnsignedRecord = {
  v: 1
  /** The profile's address. */
  profile: string
  path: string
  time: number
  body: Body | null
  /** Present only when an access key signed: its address. */
  by?: string
}
export type SignedRecord = UnsignedRecord & { sig: string }
/** A record that passed every check, with its id. */
export type Checked = { record: SignedRecord; id: string }

export class RecordError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.name = 'RecordError'
    this.code = code
  }
}
function fail(code: string, message: string): never {
  throw new RecordError(code, message)
}

// Paths: 1 to 4 segments of [a-z0-9][a-z0-9._-]{0,63}. `hosts` and `permissions` are the control
// paths only the owner writes. Everything else is content; indexes read profile, offer/<id> and
// review/<id>.
const SEGMENT = '[a-z0-9][a-z0-9._-]{0,63}'
export const PATH = new RegExp(`^${SEGMENT}(/${SEGMENT}){0,3}$`)
export const MAX_PATH = 256

/** A path whose first segment is a control record's: only `hosts` and `permissions` themselves are valid. */
export function isControlPath(path: string): boolean {
  const first = path.split('/')[0]
  return first === 'hosts' || first === 'permissions'
}

export function checkPath(path: unknown): asserts path is string {
  if (typeof path !== 'string' || path.length > MAX_PATH || !PATH.test(path)) fail('path', 'a path is segments of [a-z0-9][a-z0-9._-]')
  if (isControlPath(path) && path.includes('/')) fail('path', 'hosts and permissions are single paths')
}

/** Does a path prefix cover a path? Segment by segment: `offer` covers `offer/x`, not `offerx`. */
export function pathCovers(prefix: string, path: string): boolean {
  return path === prefix || path.startsWith(prefix + '/')
}

/** A private body: `{ private: <age file, base64url> }` and nothing else (private.ts opens it). */
export function isPrivate(body: Body | null): body is { private: string } {
  return body !== null && typeof body.private === 'string' && Object.keys(body).length === 1
}

const FIELDS = new Set(['v', 'profile', 'path', 'time', 'body', 'by', 'sig'])
const SIG = /^[A-Za-z0-9_-]{86}$/

/** Everything about a record but its signature. Throws RecordError. */
export function checkShape(value: unknown, signed = true): asserts value is SignedRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail('shape', 'a record is an object')
  const r = value as { [key: string]: unknown }
  for (const key of Object.keys(r)) if (!FIELDS.has(key)) fail('shape', `unknown field ${key}`)
  if (r.v !== VERSION) fail('version', 'v must be 1')
  if (!publicKeyFromAddress(r.profile)) fail('key', 'profile is not a usable address')
  checkPath(r.path)
  if (!Number.isSafeInteger(r.time) || (r.time as number) < 0) fail('time', 'time is whole milliseconds since 1970')
  if (r.body !== null) {
    if (typeof r.body !== 'object' || Array.isArray(r.body)) fail('body', 'body is an object or null')
    try {
      checkValue(r.body, 1)
    } catch (err) {
      fail('body', (err as Error).message)
    }
  }
  if ('by' in r) {
    if (!publicKeyFromAddress(r.by)) fail('key', 'by is not a usable address')
    if (r.by === r.profile) fail('shape', 'the owner signs without by')
    if (isControlPath(r.path as string)) fail('control', 'only the owner writes hosts and permissions')
  }
  if (signed) {
    if (typeof r.sig !== 'string' || !SIG.test(r.sig)) fail('shape', 'sig is 64 bytes in base64url')
  } else if ('sig' in r) fail('shape', 'an unsigned record carries no sig')
  if (isControlPath(r.path as string) && r.body !== null) checkControlBody(r.path as string, r.body as Body)
}

export function unsignedOf(record: SignedRecord): UnsignedRecord {
  const { sig: _sig, ...rest } = record
  return rest
}

export function signingInput(unsigned: UnsignedRecord): Uint8Array {
  return concat(SIGN_PREFIX, utf8(canonical(unsigned)))
}

/** The record's id: SHA-256 of what was signed, so a re-encoded signature is not a new record. */
export function recordId(unsigned: UnsignedRecord): string {
  return hex.encode(sha256(signingInput(unsigned)))
}

export function signRecord(unsigned: UnsignedRecord, signer: Key): SignedRecord {
  checkShape(unsigned, false)
  return { ...unsigned, sig: signAs(signer, unsigned.by ?? unsigned.profile, signingInput(unsigned)) }
}

/** Sign `bytes` with `signer`, which must be the key `address` names. The signature in base64url. */
export function signAs(signer: Key, address: string, bytes: Uint8Array): string {
  const named = publicKeyFromAddress(address)
  const own = publicKeyOf(signer.scalar)
  if (signer.address !== address || !named || named[0] !== own[0] || named[1] !== own[1]) fail('key', 'the key that signs is not the one named to sign')
  return b64u.encode(packSignature(signBytes(signer.scalar, bytes)))
}

/**
 * Strict: the signature's 64 bytes are R8, a point on Baby Jubjub in its one spelling, and S below
 * the subgroup order; the key is a point of the prime-order subgroup; and the signature holds for
 * SHA-256 of the signed bytes, shifted right one byte. The equation itself puts R8 in the subgroup.
 */
export function verifySignature(sig: Uint8Array, message: Uint8Array, publicKey: Point | string): boolean {
  const signature = unpackSignature(sig)
  return signature !== null && verifyBytes(publicKey, message, signature)
}

/** Shape and signature. Returns the record with its id. Throws RecordError. How large a record to take is each host's own choice, and each reader's. */
export function checkRecord(value: unknown): Checked {
  checkShape(value)
  const record = value
  const unsigned = unsignedOf(record)
  if (!verifySignature(b64u.decode(record.sig), signingInput(unsigned), record.by ?? record.profile)) fail('signature', 'the signature does not verify')
  return { record, id: recordId(unsigned) }
}

/** A record's wire form: exactly its canonical text. */
export function encodeRecord(record: SignedRecord): string {
  return canonical(record)
}

/** Read one record off the wire: the text must be canonical, then every check. */
export function decodeRecord(text: string): Checked {
  let value: Json
  try {
    value = parseCanonical(text)
  } catch (err) {
    return fail('canonical', (err as Error).message)
  }
  return checkRecord(value)
}

// ---------------------------------------------------------------------------------------------
// Control records. Only the owner writes these. A field a reader does not know refuses the whole
// record, so a later limit can never be silently ignored.

export type HostsBody = {
  /** Where this profile's records live, as https origins (http only on loopback, for tests). */
  urls: string[]
}

/**
 * What an access key is for. write: signing records where its paths allow, and messages for the
 * main key when they cover `inbox`. read: pulling the inbox when its paths cover `inbox`, and
 * opening what is encrypted to it.
 */
export type Scope = 'write' | 'read'
export const SCOPES: readonly Scope[] = ['write', 'read']

/**
 * A listed key: one that acts, with its `scope`; or a past key, a write key the owner removed,
 * with `was: "write"` in place of `scope`. A past key can no longer act: nothing that checks a
 * scope finds one. What a past write key wrote still counts, at its paths.
 */
export type AccessKey = {
  /** Its signing key's address. */
  key: string
  /** A read key's age post-quantum hybrid recipient (age1pq1…): on a read key, and only there. */
  recipient?: string
  /** What it may do; on a key that acts, and only there. */
  scope?: Scope
  /** The scope a past key had; on a past key, and only there. */
  was?: 'write'
  /**
   * Path prefixes it works under, segment by segment: where a write key writes, and which private
   * records the owner's devices encrypt to a read key; `inbox` among them lets a write key send
   * messages and a read key pull. Without it, every content path but those `profile` covers, and
   * the inbox.
   */
  paths?: string[]
}
export type PermissionsBody = {
  access: AccessKey[]
}

export const MAX_HOSTS = 8
export const MAX_ACCESS_PATHS = 16
/** An age post-quantum hybrid recipient (mlkem768x25519): an inbox key's or a read key's public half. */
export const RECIPIENT = /^age1pq1[02-9ac-hj-np-z]{1952}$/

const only = (body: object, fields: string[], code: string, what: string) => {
  for (const key of Object.keys(body)) if (!fields.includes(key)) fail(code, `unknown ${what} field ${key}`)
}

/** An access key's paths: at most MAX_ACCESS_PATHS content path prefixes. Throws RecordError with `code`. */
export function checkAccessPaths(paths: unknown, code: string): asserts paths is string[] {
  if (!Array.isArray(paths) || paths.length > MAX_ACCESS_PATHS) fail(code, `paths is at most ${MAX_ACCESS_PATHS} prefixes`)
  for (const p of paths as unknown[]) if (typeof p !== 'string' || !PATH.test(p) || isControlPath(p)) fail(code, 'an access path is a content path prefix')
}

export function checkControlBody(path: string, body: Body): void {
  if (path === 'hosts') {
    only(body, ['urls'], 'hosts', 'hosts')
    const urls = body.urls
    if (!Array.isArray(urls) || urls.length < 1 || urls.length > MAX_HOSTS) fail('hosts', `urls is 1 to ${MAX_HOSTS} origins`)
    for (const url of urls as unknown[]) if (typeof url !== 'string' || normalizeOrigin(url) !== url) fail('hosts', 'each url is an origin, https (http only on loopback)')
    if (new Set(urls as string[]).size !== (urls as string[]).length) fail('hosts', 'urls repeat')
    return
  }
  only(body, ['access'], 'permissions', 'permissions')
  const access = body.access
  if (!Array.isArray(access)) fail('permissions', 'access is a list of keys')
  const listed = new Set<unknown>()
  for (const k of access as unknown[]) {
    if (k === null || typeof k !== 'object' || Array.isArray(k)) fail('permissions', 'an access entry is an object')
    only(k, ['key', 'recipient', 'scope', 'was', 'paths'], 'permissions', 'access')
    const { key, recipient, scope, was, paths } = k as { [key: string]: unknown }
    if ('was' in (k as object) ? 'scope' in (k as object) || was !== 'write' : !SCOPES.includes(scope as Scope)) {
      fail('permissions', `scope is one of ${SCOPES.join(', ')}; a past key has was, write, in its place`)
    }
    if (!publicKeyFromAddress(key)) fail('permissions', 'an access key is a usable address')
    if (scope === 'read') {
      if (typeof recipient !== 'string' || !RECIPIENT.test(recipient)) fail('permissions', 'a read key gives its recipient, an age post-quantum hybrid recipient, age1pq1…')
    } else if ('recipient' in (k as object)) fail('permissions', 'only a read key gives a recipient')
    if ('paths' in (k as object)) checkAccessPaths(paths, 'permissions')
    for (const half of scope === 'read' ? [key, recipient] : [key]) {
      if (listed.has(half)) fail('permissions', 'a key is listed twice')
      listed.add(half)
    }
  }
}

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
