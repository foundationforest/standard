// The inbox: entries anyone leaves in a folder whose profile entry has openKey. An inbox entry is
// not signed outside, and names only the folder it is to:
//
//   { v: 1, to, time, body: { private } }
//
// Its id is lowercase hex of SHA-256 of its canonical text. Locked inside it, to openKey and to
// every key the profile entry lists with read-inbox, is one message:
//
//   { from, key?, host?, time, body, sig }
//
// signed by from's main key, or by `key`, an access key from's profile entry lists with message,
// over 0xff || "forest/v1/message\n" || JCS(the message without sig, with `to` beside it): the
// signature names the folder it was left in, so a message cannot be moved to another inbox as its
// sender's. `host`, one of from's hosts, tells the recipient's app where the sender's folder is.
// The recipient's app checks the signature and the sender's profile entry, and decides what to
// show.
//
// Deleting one is signed by the folder's main key, or by a key it lists with read-inbox:
//
//   { v: 1, to, id, key?, sig }    over 0xff || "forest/v1/inbox/delete\n" || JCS(the rest)
//
// Nothing here locks or opens a body: that needs age, and is inboxEntry() and openInbox() in
// locked.ts.

import { sha256 } from '@noble/hashes/sha2.js'
import { b64u, concat, hex, utf8 } from './bytes.ts'
import { type Json, canonical, checkValue, parseCanonical } from './canonical.ts'
import { type Body, checkSignature, signAs } from './entry.ts'
import { fail } from './fail.ts'
import { publicKeyFromAddress } from './keys.ts'
import { canDo, normalizeOrigin } from './profile.ts'
import { type Writer, writerOf } from './write.ts'

export const MESSAGE_PREFIX = concat(Uint8Array.of(0xff), utf8('forest/v1/message\n'))
export const DELETE_PREFIX = concat(Uint8Array.of(0xff), utf8('forest/v1/inbox/delete\n'))

/** A locked body: an age file, base64url, that only the keys it was locked to open. */
export type LockedBody = { private: string }
export type InboxEntry = {
  v: 1
  /** The address of the profile whose folder it is left in. */
  to: string
  time: number
  body: LockedBody
}
/** An inbox entry whose shape checked, with its id. */
export type CheckedInbox = { entry: InboxEntry; id: string }

export type UnsignedMessage = {
  /** The sender's profile: its address. */
  from: string
  /** The access key that signed, which from's profile entry lists with message; absent when from's main key signed. */
  key?: string
  /** One of from's hosts: where the recipient's app finds the sender's folder. */
  host?: string
  time: number
  /** What the message says: the two apps' to agree; the main way, for a plain message, is { text }. */
  body: Body
}
export type SignedMessage = UnsignedMessage & { sig: string }

export type UnsignedDelete = {
  v: 1
  /** The folder whose inbox entry it deletes: its profile's address. */
  to: string
  /** The inbox entry's id. */
  id: string
  /** The access key that signed, which the folder's profile entry lists with read-inbox; absent when its main key signed. */
  key?: string
}
export type SignedDelete = UnsignedDelete & { sig: string }

const isObject = (value: unknown): value is { [key: string]: unknown } => value !== null && typeof value === 'object' && !Array.isArray(value)
const only = (value: object, fields: string[], what: string) => {
  for (const key of Object.keys(value)) if (!fields.includes(key)) fail('shape', `unknown ${what} field ${key}`)
}
const SIG = /^[A-Za-z0-9_-]{86}$/
const B64U = /^[A-Za-z0-9_-]+$/
const ID = /^[0-9a-f]{64}$/
const time = (value: unknown) => {
  if (!Number.isSafeInteger(value) || (value as number) < 0) fail('time', 'time is whole milliseconds since 1970')
}
const sig = (value: { [key: string]: unknown }, signed: boolean, what: string) => {
  if (signed) {
    if (typeof value.sig !== 'string' || !SIG.test(value.sig)) fail('shape', 'sig is 64 bytes in base64url')
  } else if ('sig' in value) fail('shape', `an unsigned ${what} carries no sig`)
}
const accessKey = (value: { [key: string]: unknown }, owner: unknown) => {
  if ('key' in value && (!publicKeyFromAddress(value.key) || value.key === owner)) fail('key', 'key is an access key’s address, not the main key’s')
}
const parse = (text: string): Json => {
  try {
    return parseCanonical(text)
  } catch (err) {
    return fail('canonical', (err as Error).message)
  }
}

// ---------------------------------------------------------------------------------------------
// Inbox entries

/** Everything about an inbox entry. Throws FolderError. */
export function checkInboxShape(value: unknown): asserts value is InboxEntry {
  if (!isObject(value)) fail('shape', 'an inbox entry is an object')
  only(value, ['v', 'to', 'time', 'body'], 'inbox entry')
  if (value.v !== 1) fail('version', 'v must be 1')
  if (!publicKeyFromAddress(value.to)) fail('key', 'to is not a usable address')
  time(value.time)
  const body = value.body
  if (!isObject(body) || Object.keys(body).length !== 1 || typeof body.private !== 'string' || !B64U.test(body.private)) {
    fail('body', 'an inbox entry’s body is { private: <age file, base64url> } and nothing else')
  }
}

/** An inbox entry's id: lowercase hex of SHA-256 of its canonical text. */
export function inboxId(entry: InboxEntry): string {
  return hex.encode(sha256(utf8(canonical(entry))))
}

/** An inbox entry's wire form: exactly its canonical text. */
export function encodeInbox(entry: InboxEntry): string {
  return canonical(entry)
}

/** Read one inbox entry off the wire: canonical text, shape, id. Throws FolderError. */
export function decodeInbox(text: string): CheckedInbox {
  const value = parse(text)
  checkInboxShape(value)
  return { entry: value, id: inboxId(value) }
}

// ---------------------------------------------------------------------------------------------
// Messages, locked inside inbox entries

/** Everything about a message but its signature. Throws FolderError. */
export function checkMessageShape(value: unknown, signed = true): asserts value is SignedMessage {
  if (!isObject(value)) fail('shape', 'a message is an object')
  only(value, ['from', 'key', 'host', 'time', 'body', 'sig'], 'message')
  if (!publicKeyFromAddress(value.from)) fail('key', 'from is not a usable address')
  accessKey(value, value.from)
  if ('host' in value && (typeof value.host !== 'string' || normalizeOrigin(value.host) !== value.host)) fail('shape', 'host is an origin, https (http only on loopback)')
  time(value.time)
  if (!isObject(value.body)) fail('body', 'a message’s body is an object')
  try {
    checkValue(value.body, 1)
  } catch (err) {
    fail('body', (err as Error).message)
  }
  sig(value, signed, 'message')
}

/** What a message's signature signs: its text with `to`, the folder it is left in, beside its fields. */
export function messageSigningInput(unsigned: UnsignedMessage, to: string): Uint8Array {
  return concat(MESSAGE_PREFIX, utf8(canonical({ ...unsigned, to })))
}

/** A message to `to`, signed by the writer: the sender's main key, or an access key its profile entry lists with message. */
export function signMessage(writer: Writer, to: string, body: Body, time: number, host?: string): SignedMessage {
  const { profile, key, access } = writerOf(writer)
  if (!publicKeyFromAddress(to)) fail('key', 'to is not a usable address')
  const unsigned: UnsignedMessage = { from: profile, ...(access && { key: key.address }), ...(host !== undefined && { host }), time, body }
  checkMessageShape(unsigned, false)
  return { ...unsigned, sig: signAs(key, key.address, messageSigningInput(unsigned, to)) }
}

/** Whether the message's signature holds, by `key` or by from's main key, for the folder `to`. */
export function checkMessage(message: SignedMessage, to: string): boolean {
  const { sig: s, ...unsigned } = message
  return checkSignature(b64u.decode(s), messageSigningInput(unsigned, to), message.key ?? message.from)
}

/**
 * Whether the sender's own profile entry stands behind the message: its main key signed it, or the
 * key that signed is one `senderProfile`, from's current profile entry's body, lists with message.
 * The recipient's app reads that profile entry from the sender's hosts (`host`, among others).
 */
export function senderCounts(message: SignedMessage, senderProfile: Body | null | undefined): boolean {
  return message.key === undefined || canDo(senderProfile, message.key, 'message')
}

// ---------------------------------------------------------------------------------------------
// Inbox deletes

function checkDeleteShape(value: unknown, signed = true): asserts value is SignedDelete {
  if (!isObject(value)) fail('shape', 'an inbox delete is an object')
  only(value, ['v', 'to', 'id', 'key', 'sig'], 'inbox delete')
  if (value.v !== 1) fail('version', 'v must be 1')
  if (!publicKeyFromAddress(value.to)) fail('key', 'to is not a usable address')
  if (typeof value.id !== 'string' || !ID.test(value.id)) fail('shape', 'id is an inbox entry’s id: 64 characters of lowercase hex')
  accessKey(value, value.to)
  sig(value, signed, 'inbox delete')
}

export function deleteSigningInput(unsigned: UnsignedDelete): Uint8Array {
  return concat(DELETE_PREFIX, utf8(canonical(unsigned)))
}

/** A request to delete the inbox entry `id` from the writer's folder: its main key, or an access key it lists with read-inbox. */
export function inboxDelete(writer: Writer, id: string): SignedDelete {
  const { profile, key, access } = writerOf(writer)
  const unsigned: UnsignedDelete = { v: 1, to: profile, id, ...(access && { key: key.address }) }
  checkDeleteShape(unsigned, false)
  return { ...unsigned, sig: signAs(key, key.address, deleteSigningInput(unsigned)) }
}

/** An inbox delete's wire form: exactly its canonical text. */
export function encodeDelete(request: SignedDelete): string {
  return canonical(request)
}

/**
 * An inbox delete off the wire: canonical text, shape, then the signature, by `key` or by the
 * folder's main key [signature]. Whether the folder's profile entry lists `key` with read-inbox is
 * the host's to check. Throws FolderError.
 */
export function decodeDelete(text: string): SignedDelete {
  const value = parse(text)
  checkDeleteShape(value)
  const { sig: s, ...unsigned } = value
  if (!checkSignature(b64u.decode(s), deleteSigningInput(unsigned), value.key ?? value.to)) fail('signature', 'the signature does not hold')
  return value
}
