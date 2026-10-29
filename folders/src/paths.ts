// Keyed paths: paths that name nothing. An entry that is about something the person keeps to
// themselves, such as who holds an access key, or which profiles and stamps the person has, sits at
// `<prefix>/<id>`, its id keyed by the folder's own secret, so only the person's devices, which mix
// that secret from the seed, can tell what a path is about (README.md, Keyed paths).
//
//   id = the first 32 hex characters of HMAC-SHA256(the folder's secret, UTF-8(text))
//
// A profile's folder is keyed by the profile's secret, keys/'s mainKey(seed, label).secret; the
// Profiles folder by its own, keys/'s profilesKey(seed).secret. The ids use the secret itself, with
// no text of their own to mix it with: HMAC keyed by the secret is apart from the HKDF and the
// BLAKE-512 the secret's halves come from.

import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hex, utf8 } from './bytes.ts'
import { type Json, canonical } from './canonical.ts'

/** A keyed id: the first 32 hex characters of HMAC-SHA256, keyed by the folder's secret, of the text. */
export function keyedId(secret: Uint8Array, text: string): string {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) throw new Error('a folder’s secret is 32 bytes')
  return hex.encode(hmac(sha256, secret, utf8(text))).slice(0, 32)
}

/** Where a profile's note about one of its access keys sits: `key/<id>`, keyed by the access key's address. */
export function notePath(secret: Uint8Array, accessKey: string): string {
  return `key/${keyedId(secret, accessKey)}`
}

/** Where the Profiles folder lists one profile: `label/<id>`, keyed by its label. */
export function labelPath(secret: Uint8Array, label: string): string {
  return `label/${keyedId(secret, label)}`
}

/** Where the Profiles folder keeps one stamp: `stamp/<id>`, keyed by the stamp's canonical text. */
export function stampPath(secret: Uint8Array, stamp: { [key: string]: Json }): string {
  return `stamp/${keyedId(secret, canonical(stamp))}`
}
