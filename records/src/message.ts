// A message: a sealed envelope any key delivers to a profile's inbox, on that profile's hosts. It is
// not a record: no path, no versions, no newest-wins, and a host serves it only to the profile it is
// to.
//
//   { v: 1, to, from, time, body: { private }, host?, sig }
//
// `sig` is EdDSA-Poseidon on Baby Jubjub, as a record's, over 0xff || "forest/v1/message\n" ||
// JCS(the rest), by `from`. `host`, one of `from`'s hosts, says where a receiving host reads
// `from`'s profile record, for an inbox with an issuer's rule. A pull request,
// `{ v: 1, profile, after, time, sig }`, is signed the same way by the profile's main key, over
// 0xff || "forest/v1/pull\n" || JCS(the rest). A blob request,
// `{ v: 1, action, profile, sha256, mimeType?, size?, time, sig }`, puts bytes in a folder or
// deletes them, signed by the folder's main key, over 0xff || "forest/v1/blob\n" || JCS(the rest).
// Each signed text differs from a record's, so no signature is ever two of them.
//
// Nothing here seals or opens a body: that needs age, and is message() and openMessage() in
// private.ts.

import { sha256 } from '@noble/hashes/sha2.js'
import { b64u, concat, hex, utf8 } from './bytes.ts'
import { type Json, canonical, parseCanonical } from './canonical.ts'
import { type Key, publicKeyFromAddress } from './keys.ts'
import { type Body, MAX_FUTURE_MS, RecordError, SEAL_TO, normalizeOrigin, signAs, verifySignature } from './record.ts'

export const MESSAGE_PREFIX = concat(Uint8Array.of(0xff), utf8('forest/v1/message\n'))
export const PULL_PREFIX = concat(Uint8Array.of(0xff), utf8('forest/v1/pull\n'))
export const BLOB_PREFIX = concat(Uint8Array.of(0xff), utf8('forest/v1/blob\n'))

/** A sealed body: an age file, base64url, that only the inbox key of the profile it is to opens. */
export type SealedBody = { private: string }
export type UnsignedMessage = {
  v: 1
  /** The address of the profile it is to. */
  to: string
  /** The sender's address: its main key, or any key. */
  from: string
  time: number
  body: SealedBody
  /** One of from's hosts, where a receiving host reads from's profile record: needed only for an inbox with an issuer's rule. */
  host?: string
}
export type SignedMessage = UnsignedMessage & { sig: string }
/** A message whose shape checked, with its id. */
export type CheckedMessage = { message: SignedMessage; id: string }

export type UnsignedPull = {
  v: 1
  /** The profile whose inbox is pulled; its main key signs. */
  profile: string
  /** The cursor: messages that arrived after it. 0 for all. */
  after: number
  time: number
}
export type SignedPull = UnsignedPull & { sig: string }

/** A blob's name: what a stranger needs to fetch it from a folder's hosts and check it. */
export type BlobName = {
  /** SHA-256 of the bytes, lowercase hex. */
  sha256: string
  /** The bytes' media type, type/subtype in lower case, such as image/jpeg. */
  mimeType: string
  /** How many bytes. */
  size: number
}
/** Put a blob in a folder, or delete it from the folder: signed by its main key. */
export type UnsignedBlobRequest = { v: 1; profile: string; time: number } & ({ action: 'put' } & BlobName | { action: 'delete'; sha256: string })
export type SignedBlobRequest = UnsignedBlobRequest & { sig: string }

function fail(code: string, message: string): never {
  throw new RecordError(code, message)
}

const isObject = (value: unknown): value is { [key: string]: unknown } => value !== null && typeof value === 'object' && !Array.isArray(value)
const only = (value: object, fields: string[], what: string) => {
  for (const key of Object.keys(value)) if (!fields.includes(key)) fail('shape', `unknown ${what} field ${key}`)
}
const SIG = /^[A-Za-z0-9_-]{86}$/
const B64U = /^[A-Za-z0-9_-]+$/

function checkSig(value: { [key: string]: unknown }, signed: boolean) {
  if (signed) {
    if (typeof value.sig !== 'string' || !SIG.test(value.sig)) fail('shape', 'sig is 64 bytes in base64url')
  } else if ('sig' in value) fail('shape', 'an unsigned message carries no sig')
}

// ---------------------------------------------------------------------------------------------
// Messages

/** Everything about a message but its signature. Throws RecordError. */
export function checkMessageShape(value: unknown, signed = true): asserts value is SignedMessage {
  if (!isObject(value)) fail('shape', 'a message is an object')
  only(value, ['v', 'to', 'from', 'time', 'body', 'host', 'sig'], 'message')
  if (value.v !== 1) fail('version', 'v must be 1')
  if (!publicKeyFromAddress(value.to)) fail('key', 'to is not a usable address')
  if (!publicKeyFromAddress(value.from)) fail('key', 'from is not a usable address')
  if (!Number.isSafeInteger(value.time) || (value.time as number) < 0) fail('time', 'time is whole milliseconds since 1970')
  const body = value.body
  if (!isObject(body) || Object.keys(body).length !== 1 || typeof body.private !== 'string' || !B64U.test(body.private)) {
    fail('body', 'a message body is { private: <age file, base64url> } and nothing else')
  }
  if ('host' in value && (typeof value.host !== 'string' || normalizeOrigin(value.host) !== value.host)) fail('shape', 'host is an origin, https (http only on loopback)')
  checkSig(value, signed)
}

export function unsignedMessageOf(message: SignedMessage): UnsignedMessage {
  const { sig: _sig, ...rest } = message
  return rest
}

export function messageSigningInput(unsigned: UnsignedMessage): Uint8Array {
  return concat(MESSAGE_PREFIX, utf8(canonical(unsigned)))
}

/** The message's id: lowercase hex of SHA-256 of what was signed, as a record's id is. */
export function messageId(unsigned: UnsignedMessage): string {
  return hex.encode(sha256(messageSigningInput(unsigned)))
}

/** The sender's own key, naming `host`, one of its hosts, where an inbox with an issuer's rule reads its profile record. */
export type HostSender = { from: Key; host: string }
/** Who signs a message: the sender's own key (a main key, or any key), with one of its hosts or not. */
export type Sender = Key | HostSender

/** Sign a sealed body to `to`. Sealing it is message() in private.ts. */
export function signMessage(sender: Sender, to: string, body: SealedBody, time: number): SignedMessage {
  const signer = 'scalar' in sender ? sender : sender.from
  const unsigned: UnsignedMessage = 'scalar' in sender ? { v: 1, to, from: sender.address, time, body } : { v: 1, to, from: sender.from.address, time, body, host: sender.host }
  checkMessageShape(unsigned, false)
  return { ...unsigned, sig: signAs(signer, unsigned.from, messageSigningInput(unsigned)) }
}

/** A message's wire form: exactly its canonical text. */
export function encodeMessage(message: SignedMessage): string {
  return canonical(message)
}

/**
 * Read one message off the wire without checking its signature: canonical text, shape, id. A host
 * runs its cheap checks before the signature, and how large a message to take is its own choice.
 * Throws RecordError.
 */
export function readMessage(text: string): CheckedMessage {
  let value: Json
  try {
    value = parseCanonical(text)
  } catch (err) {
    return fail('canonical', (err as Error).message)
  }
  checkMessageShape(value)
  return { message: value, id: messageId(unsignedMessageOf(value)) }
}

/** Whether `from` signed the message. Strict, as a record's. */
export function verifyMessage({ message }: CheckedMessage): boolean {
  return verifySignature(b64u.decode(message.sig), messageSigningInput(unsignedMessageOf(message)), message.from)
}

/** Read one message off the wire: every check, the signature included. Throws RecordError. */
export function decodeMessage(text: string): CheckedMessage {
  const checked = readMessage(text)
  if (!verifyMessage(checked)) fail('signature', 'the signature does not verify')
  return checked
}

// ---------------------------------------------------------------------------------------------
// Pull requests

export function pullSigningInput(unsigned: UnsignedPull): Uint8Array {
  return concat(PULL_PREFIX, utf8(canonical(unsigned)))
}

function checkPullShape(value: unknown, signed = true): asserts value is SignedPull {
  if (!isObject(value)) fail('shape', 'a pull request is an object')
  only(value, ['v', 'profile', 'after', 'time', 'sig'], 'pull')
  if (value.v !== 1) fail('version', 'v must be 1')
  if (!publicKeyFromAddress(value.profile)) fail('key', 'profile is not a usable address')
  if (!Number.isSafeInteger(value.after) || (value.after as number) < 0) fail('shape', 'after is a cursor: a whole number')
  if (!Number.isSafeInteger(value.time) || (value.time as number) < 0) fail('time', 'time is whole milliseconds since 1970')
  checkSig(value, signed)
}

/** A request for the messages to a profile that arrived after the cursor, signed at `time` by its main key. */
export function pullRequest(owner: Key, after: number, time: number): SignedPull {
  const unsigned: UnsignedPull = { v: 1, profile: owner.address, after, time }
  checkPullShape(unsigned, false)
  return { ...unsigned, sig: signAs(owner, unsigned.profile, pullSigningInput(unsigned)) }
}

/**
 * A pull request off the wire, at the host's clock `now`: canonical text and shape, then its time
 * within ten minutes of `now` either way [stale], then the signature of the profile's main key
 * [signature]. Throws RecordError.
 */
export function checkPull(text: string, now: number): SignedPull {
  let value: Json
  try {
    value = parseCanonical(text)
  } catch (err) {
    return fail('canonical', (err as Error).message)
  }
  checkPullShape(value)
  if (Math.abs(value.time - now) > MAX_FUTURE_MS) fail('stale', 'a pull is signed within ten minutes of the host’s clock')
  const { sig, ...unsigned } = value
  if (!verifySignature(b64u.decode(sig), pullSigningInput(unsigned), value.profile)) fail('signature', 'the profile’s main key did not sign this pull')
  return value
}

// ---------------------------------------------------------------------------------------------
// Blob requests

const SHA256 = /^[0-9a-f]{64}$/
/** A media type, type/subtype in lower case: what a host serves back as content-type. */
export const MIME_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/

/** A blob's name, from its bytes and their media type. */
export function blobNameOf(bytes: Uint8Array, mimeType: string): BlobName {
  return { sha256: hex.encode(sha256(bytes)), mimeType, size: bytes.length }
}

export function blobSigningInput(unsigned: UnsignedBlobRequest): Uint8Array {
  return concat(BLOB_PREFIX, utf8(canonical(unsigned)))
}

function checkBlobShape(value: unknown, signed = true): asserts value is SignedBlobRequest {
  if (!isObject(value)) fail('shape', 'a blob request is an object')
  if (value.action !== 'put' && value.action !== 'delete') fail('shape', 'action is put or delete')
  const put = value.action === 'put'
  only(value, ['v', 'action', 'profile', 'sha256', ...(put ? ['mimeType', 'size'] : []), 'time', 'sig'], `${value.action} request`)
  if (value.v !== 1) fail('version', 'v must be 1')
  if (!publicKeyFromAddress(value.profile)) fail('key', 'profile is not a usable address')
  if (typeof value.sha256 !== 'string' || !SHA256.test(value.sha256)) fail('shape', 'sha256 is 64 characters of lowercase hex')
  if (put) {
    if (typeof value.mimeType !== 'string' || value.mimeType.length > 255 || !MIME_TYPE.test(value.mimeType)) fail('shape', 'mimeType is type/subtype in lower case, at most 255 characters')
    if (!Number.isSafeInteger(value.size) || (value.size as number) < 0) fail('shape', 'size is a whole number of bytes')
  }
  if (!Number.isSafeInteger(value.time) || (value.time as number) < 0) fail('time', 'time is whole milliseconds since 1970')
  checkSig(value, signed)
}

/**
 * A request to put a blob in a profile's folder, or to delete it from the folder, signed at `time`
 * by its main key. The same request goes to each of the folder's hosts.
 */
export function blobRequest(owner: Key, request: ({ action: 'put' } & BlobName) | { action: 'delete'; sha256: string }, time: number): SignedBlobRequest {
  const unsigned = { v: 1, ...request, profile: owner.address, time } as UnsignedBlobRequest
  checkBlobShape(unsigned, false)
  return { ...unsigned, sig: signAs(owner, unsigned.profile, blobSigningInput(unsigned)) }
}

/**
 * A blob request off the wire, at the host's clock `now`: canonical text and shape, then its time
 * within ten minutes of `now` either way [stale], then the signature of the profile's main key
 * [signature]. Throws RecordError.
 *
 * As with a pull, the same request sent again within those ten minutes does what it did: only the
 * hosts it was sent to see it, and a host may keep or drop bytes whatever it is sent.
 */
export function checkBlobRequest(text: string, now: number): SignedBlobRequest {
  let value: Json
  try {
    value = parseCanonical(text)
  } catch (err) {
    return fail('canonical', (err as Error).message)
  }
  checkBlobShape(value)
  if (Math.abs(value.time - now) > MAX_FUTURE_MS) fail('stale', 'a blob request is signed within ten minutes of the host’s clock')
  const { sig, ...unsigned } = value
  if (!verifySignature(b64u.decode(sig), blobSigningInput(unsigned as UnsignedBlobRequest), value.profile)) fail('signature', 'the profile’s main key did not sign this request')
  return value
}

// ---------------------------------------------------------------------------------------------
// The inbox a profile declares

export type Inbox = {
  /**
   * Who may deliver: anyone, or a profile whose profile record carries a stamp proof from this
   * issuer, under any label. The issuer is named by its key's address.
   */
  senders: 'anyone' | { issuer: string }
  /** One message from each sender, ever. */
  once?: true
  /** The largest message it takes, as canonical text in bytes. */
  maxBytes?: number
}

/**
 * The inbox a profile record's body declares: null when it declares none (no `inbox` field, or a
 * deleted or private profile record), 'unsupported' when it holds a rule, a field or a value this code does
 * not know. A host refuses deliveries to an inbox it cannot read rather than guess: a field it
 * skipped could be a limit the profile set, so a new kind of rule can be added later without an
 * old host taking what it should refuse.
 */
export function inboxOf(body: Body | null | undefined): Inbox | null | 'unsupported' {
  if (!body || !('inbox' in body)) return null
  const inbox = body.inbox
  if (!isObject(inbox) || Object.keys(inbox).some((key) => !['senders', 'once', 'maxBytes'].includes(key))) return 'unsupported'
  const { senders, once, maxBytes } = inbox
  let rule: Inbox['senders']
  if (senders === 'anyone') rule = 'anyone'
  else if (isObject(senders) && Object.keys(senders).length === 1 && publicKeyFromAddress(senders.issuer)) rule = { issuer: senders.issuer as string }
  else return 'unsupported'
  if ('once' in inbox && once !== true) return 'unsupported'
  if ('maxBytes' in inbox && (!Number.isSafeInteger(maxBytes) || (maxBytes as number) < 0)) return 'unsupported'
  return {
    senders: rule,
    ...(once === true && { once }),
    ...('maxBytes' in inbox && { maxBytes: maxBytes as number }),
  }
}

/**
 * The key a message to a profile is sealed to, from its profile record's body: its inbox key. Throws
 * when the profile record gives no inbox key, or declares no inbox this code can read: a field it
 * does not know could name more keys to seal to.
 */
export function inboxKeyOf(profileBody: Body | null | undefined): string {
  const inbox = inboxOf(profileBody)
  if (inbox === null || inbox === 'unsupported') fail('no_inbox', 'the profile record declares no inbox this code can read')
  const inboxKey = profileBody!.inboxKey
  if (typeof inboxKey !== 'string' || !SEAL_TO.test(inboxKey)) fail('no_inbox', 'the profile record gives no inbox key')
  return inboxKey
}
