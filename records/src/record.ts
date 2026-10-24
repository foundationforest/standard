// A record: one signed version of one path in one profile's folder.
//
//   { v: 1, profile, path, time, body | null, sig }
//
// `sig` is EdDSA-Poseidon on Baby Jubjub, by keys/'s signBytes, over the signed bytes
// 0xff || "forest/v1/record\n" || JCS(the rest): the profile's main key's, and no other key's. It
// signs SHA-256 of those bytes, shifted right one byte, as a number, and is written as 64
// bytes, R8 packed then S, in base64url. A message's and a pull's signed bytes start with their own
// text, so no signature is ever two of them.

import { sha256 } from '@noble/hashes/sha2.js'
import { type Point, checkBytes, packSignature, publicKeyOf, signBytes, unpackSignature } from '@foundationforest/keys/curve'
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

// Paths: 1 to 4 segments of [a-z0-9][a-z0-9._-]{0,63}. `hosts` is the control path, whose body every
// host reads. Everything else is content; indexes read profile, offer/<id> and review/<id>.
const SEGMENT = '[a-z0-9][a-z0-9._-]{0,63}'
export const PATH = new RegExp(`^${SEGMENT}(/${SEGMENT}){0,3}$`)
export const MAX_PATH = 256

/** A path whose first segment is the control record's: only `hosts` itself is valid. */
export function isControlPath(path: string): boolean {
  return path.split('/')[0] === 'hosts'
}

export function checkPath(path: unknown): asserts path is string {
  if (typeof path !== 'string' || path.length > MAX_PATH || !PATH.test(path)) fail('path', 'a path is segments of [a-z0-9][a-z0-9._-]')
  if (isControlPath(path) && path.includes('/')) fail('path', 'hosts is a single path')
}

/** A private body: `{ private: <age file, base64url> }` and nothing else (private.ts opens it). */
export function isPrivate(body: Body | null): body is { private: string } {
  return body !== null && typeof body.private === 'string' && Object.keys(body).length === 1
}

const FIELDS = new Set(['v', 'profile', 'path', 'time', 'body', 'sig'])
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
  if (signed) {
    if (typeof r.sig !== 'string' || !SIG.test(r.sig)) fail('shape', 'sig is 64 bytes in base64url')
  } else if ('sig' in r) fail('shape', 'an unsigned record carries no sig')
  if (r.path === 'hosts' && r.body !== null) checkHostsBody(r.body as Body)
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

export function signRecord(unsigned: UnsignedRecord, key: Key): SignedRecord {
  checkShape(unsigned, false)
  return { ...unsigned, sig: signAs(key, unsigned.profile, signingInput(unsigned)) }
}

/** Sign `bytes` with `key`, which must be the key `address` names. The signature in base64url. */
export function signAs(key: Key, address: string, bytes: Uint8Array): string {
  const named = publicKeyFromAddress(address)
  const own = publicKeyOf(key.scalar)
  if (key.address !== address || !named || named[0] !== own[0] || named[1] !== own[1]) fail('key', 'the key that signs is not the one named to sign')
  return b64u.encode(packSignature(signBytes(key.scalar, bytes)))
}

/**
 * Strict: the signature's 64 bytes are R8, a point on Baby Jubjub in its one spelling, and S below
 * the subgroup order; the key is a point of the prime-order subgroup; and the signature holds for
 * SHA-256 of the signed bytes, shifted right one byte. The equation itself puts R8 in the subgroup.
 */
export function checkSignature(sig: Uint8Array, message: Uint8Array, publicKey: Point | string): boolean {
  const signature = unpackSignature(sig)
  return signature !== null && checkBytes(publicKey, message, signature)
}

/** Shape and signature. Returns the record with its id. Throws RecordError. How large a record to take is each host's own choice, and each reader's. */
export function checkRecord(value: unknown): Checked {
  checkShape(value)
  const record = value
  const unsigned = unsignedOf(record)
  if (!checkSignature(b64u.decode(record.sig), signingInput(unsigned), record.profile)) fail('signature', 'the signature does not hold')
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
// The hosts record, the control record. A field a reader does not know refuses the whole record,
// so a later limit can never be silently ignored.

export type HostsBody = {
  /** Where this profile's records live, as https origins (http only on loopback, for tests). */
  urls: string[]
}

export const MAX_HOSTS = 8
/** What an envelope is encrypted to: an age post-quantum hybrid key (mlkem768x25519), an inbox key's public half. */
export const ENCRYPT_TO = /^age1pq1[02-9ac-hj-np-z]{1952}$/

/** A hosts record's body: 1 to MAX_HOSTS distinct origins, and no other field. Throws RecordError with code `hosts`. */
export function checkHostsBody(body: Body): void {
  for (const key of Object.keys(body)) if (key !== 'urls') fail('hosts', `unknown hosts field ${key}`)
  const urls = body.urls
  if (!Array.isArray(urls) || urls.length < 1 || urls.length > MAX_HOSTS) fail('hosts', `urls is 1 to ${MAX_HOSTS} origins`)
  for (const url of urls as unknown[]) if (typeof url !== 'string' || normalizeOrigin(url) !== url) fail('hosts', 'each url is an origin, https (http only on loopback)')
  if (new Set(urls as string[]).size !== (urls as string[]).length) fail('hosts', 'urls repeat')
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
