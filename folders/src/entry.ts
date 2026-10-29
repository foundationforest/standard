// An entry: one signed version of one path in one profile's folder.
//
//   { v: 1, profile, path, time, body | null, key?, sig }
//
// `sig` is EdDSA-Poseidon on Baby Jubjub, by keys/'s signBytes, over JCS(the rest), the canonical
// text of the entry without its sig and nothing else: by the access key `key` names when there is
// one, else by the profile's main key. It signs SHA-256 of those bytes, shifted right one byte, as a
// number, and is written as 64 bytes, R8 packed then S, in base64url. A message and an index's root
// each say what they are by their own fields, so no signature is ever two of them.
//
// Whether an access key's entry counts is the view's (view.ts): only while the folder's current
// profile entry lists the key with write. No access key writes `profile`, so that is refused here.

import { sha256 } from '@noble/hashes/sha2.js'
import { type Point, checkBytes, packSignature, publicKeyOf, signBytes, unpackSignature } from '@foundationforest/keys/curve'
import { b64u, hex, utf8 } from './bytes.ts'
import { type Json, canonical, checkValue, parseCanonical } from './canonical.ts'
import { fail } from './fail.ts'
import { checkFiles } from './files.ts'
import { type Key, publicKeyFromAddress } from './keys.ts'
import { checkProfileBody } from './profile.ts'

export const VERSION = 1
/** Hosts refuse, and readers hold back, entries dated further ahead than this. */
export const MAX_FUTURE_MS = 10 * 60 * 1000
/** The path of a folder's profile entry: the one entry every host reads, written by the main key only. */
export const PROFILE_PATH = 'profile'

export type Body = { [key: string]: Json }
export type UnsignedEntry = {
  v: 1
  /** The profile's address: the folder's name. */
  profile: string
  path: string
  time: number
  body: Body | null
  /** The address of the access key that signed; absent when the main key signed. */
  key?: string
}
export type SignedEntry = UnsignedEntry & { sig: string }
/** An entry that passed every check, with its id. */
export type Checked = { entry: SignedEntry; id: string }

// Paths: 1 to 4 segments of [a-z0-9][a-z0-9._-]{0,63}. `profile` is the profile entry's, a single
// path; everything else is any shape the writer chooses.
const SEGMENT = '[a-z0-9][a-z0-9._-]{0,63}'
export const PATH = new RegExp(`^${SEGMENT}(/${SEGMENT}){0,3}$`)
export const MAX_PATH = 256

export function checkPath(path: unknown): asserts path is string {
  if (typeof path !== 'string' || path.length > MAX_PATH || !PATH.test(path)) fail('path', 'a path is segments of [a-z0-9][a-z0-9._-]')
  if (path.split('/')[0] === PROFILE_PATH && path !== PROFILE_PATH) fail('path', 'profile is a single path')
}

/** A locked body: `{ private: <age file, base64url> }` and nothing else (locked.ts opens it). */
export function isLocked(body: Body | null | undefined): body is { private: string } {
  return !!body && typeof body.private === 'string' && Object.keys(body).length === 1
}

const FIELDS = new Set(['v', 'profile', 'path', 'time', 'body', 'key', 'sig'])
const SIG = /^[A-Za-z0-9_-]{86}$/

/** Everything about an entry but its signature. Throws FolderError. */
export function checkShape(value: unknown, signed = true): asserts value is SignedEntry {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail('shape', 'an entry is an object')
  const r = value as { [key: string]: unknown }
  for (const key of Object.keys(r)) if (!FIELDS.has(key)) fail('shape', `unknown field ${key}`)
  if (r.v !== VERSION) fail('version', 'v must be 1')
  if (!publicKeyFromAddress(r.profile)) fail('key', 'profile is not a usable address')
  if ('key' in r && (!publicKeyFromAddress(r.key) || r.key === r.profile)) fail('key', 'key is an access key’s address, not the main key’s')
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
  } else if ('sig' in r) fail('shape', 'an unsigned entry carries no sig')
  if (r.path === PROFILE_PATH && 'key' in r) fail('unlisted', 'no access key writes the profile entry')
  const body = r.body as Body | null
  if (body !== null && 'files' in body) checkFiles(body.files)
  if (r.path === PROFILE_PATH && body !== null) checkProfileBody(body)
}

export function unsignedOf(entry: SignedEntry): UnsignedEntry {
  const { sig: _sig, ...rest } = entry
  return rest
}

/** What an entry's signature signs: the canonical text of the entry without its sig. */
export function signingInput(unsigned: UnsignedEntry): Uint8Array {
  return utf8(canonical(unsigned))
}

/** The entry's id: SHA-256 of what was signed, so a re-encoded signature is not a new entry. */
export function entryId(unsigned: UnsignedEntry): string {
  return hex.encode(sha256(signingInput(unsigned)))
}

/** The address whose key signs an entry: the access key it names, else the folder's main key. */
export function signedBy(entry: UnsignedEntry): string {
  return entry.key ?? entry.profile
}

export function signEntry(unsigned: UnsignedEntry, key: Key): SignedEntry {
  checkShape(unsigned, false)
  return { ...unsigned, sig: signAs(key, signedBy(unsigned), signingInput(unsigned)) }
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

/**
 * Shape and signature. Returns the entry with its id. Throws FolderError. How large an entry to
 * take is each host's own choice, and each reader's. Whether an access key's entry counts is the
 * view's (viewFolder).
 */
export function checkEntry(value: unknown): Checked {
  checkShape(value)
  const entry = value
  const unsigned = unsignedOf(entry)
  if (!checkSignature(b64u.decode(entry.sig), signingInput(unsigned), signedBy(entry))) fail('signature', 'the signature does not hold')
  return { entry, id: entryId(unsigned) }
}

/** An entry's wire form: exactly its canonical text. */
export function encodeEntry(entry: SignedEntry): string {
  return canonical(entry)
}

/** Read one entry off the wire: the text must be canonical, then every check. */
export function decodeEntry(text: string): Checked {
  let value: Json
  try {
    value = parseCanonical(text)
  } catch (err) {
    return fail('canonical', (err as Error).message)
  }
  return checkEntry(value)
}
