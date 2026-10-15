// A message: a sealed note any key delivers to a profile's inbox, on that profile's hosts. It is not
// a record: no path, no versions, no newest-wins, and a host serves it only to its recipient.
//
//   { v: 1, to, from, time, body: { private }, key?, host?, sig }
//
// `sig` is EdDSA-Poseidon on Baby Jubjub, as a record's, over 0xff || "forest/v1/message\n" ||
// JCS(the rest), by `from`, or by `key`: a write key `from`'s permissions record lists for the inbox.
// `host`, one of `from`'s hosts, says where a receiving host reads `from`'s records: its
// permissions, for a message `key` signed, and its card, for an inbox with an issuer's rule. A pull
// request, `{ v: 1, profile, after, time, key?, sig }`, is signed the same way by the profile's main
// key, or by `key`, a read key it lists for the inbox, over 0xff || "forest/v1/pull\n" || JCS(the
// rest). Each signed text differs from a record's, so no signature is ever two of them.
//
// Nothing here seals or opens a body: that needs age, and is message() and openMessage() in
// private.ts.

import { sha256 } from '@noble/hashes/sha2.js'
import { b64u, concat, hex, utf8 } from './bytes.ts'
import { type Json, canonical, parseCanonical } from './canonical.ts'
import { type Key, publicKeyFromAddress } from './keys.ts'
import { type Body, MAX_FUTURE_MS, RECIPIENT, RecordError, normalizeOrigin, signAs, verifySignature } from './record.ts'

export const MESSAGE_PREFIX = concat(Uint8Array.of(0xff), utf8('forest/v1/message\n'))
export const PULL_PREFIX = concat(Uint8Array.of(0xff), utf8('forest/v1/pull\n'))

/** A sealed body: an age file, base64url, that only the recipient's inbox key and its readers open. */
export type SealedBody = { private: string }
export type UnsignedMessage = {
  v: 1
  /** The recipient profile's address. */
  to: string
  /** The sender's address: its main key, or any key. With `key`, a profile's main key. */
  from: string
  time: number
  body: SealedBody
  /** Present only when a write key signed for `from`: its address. */
  key?: string
  /** One of from's hosts, where a receiving host reads from's records. Always there with `key`. */
  host?: string
}
export type SignedMessage = UnsignedMessage & { sig: string }
/** A message whose shape checked, with its id. */
export type CheckedMessage = { message: SignedMessage; id: string }

export type UnsignedPull = {
  v: 1
  /** The profile whose inbox is pulled; its main key signs, or `key`. */
  profile: string
  /** The cursor: messages that arrived after it. 0 for all. */
  after: number
  time: number
  /** Present only when a read key signed: its address. */
  key?: string
}
export type SignedPull = UnsignedPull & { sig: string }

function fail(code: string, message: string): never {
  throw new RecordError(code, message)
}

const isObject = (value: unknown): value is { [key: string]: unknown } => value !== null && typeof value === 'object' && !Array.isArray(value)
const only = (value: object, fields: string[], what: string) => {
  for (const key of Object.keys(value)) if (!fields.includes(key)) fail('shape', `unknown ${what} field ${key}`)
}
const SIG = /^[A-Za-z0-9_-]{86}$/
/** An issuer's key: x then y of its point on Baby Jubjub, each 32 bytes big-endian, in lowercase hex. */
const ISSUER_KEY = /^[0-9a-f]{128}$/
const B64U = /^[A-Za-z0-9_-]+$/

function checkSig(value: { [key: string]: unknown }, signed: boolean) {
  if (signed) {
    if (typeof value.sig !== 'string' || !SIG.test(value.sig)) fail('shape', 'sig is 64 bytes in base64url')
  } else if ('sig' in value) fail('shape', 'an unsigned message carries no sig')
}

// ---------------------------------------------------------------------------------------------
// Messages

/** A message's or a pull's `key`: usable, and not the address it signs for. */
function checkKey(value: { [key: string]: unknown }, owner: unknown) {
  if (!publicKeyFromAddress(value.key)) fail('key', 'key is not a usable address')
  if (value.key === owner) fail('shape', 'the main key signs without key')
}

/** Everything about a message but its signature. Throws RecordError. */
export function checkMessageShape(value: unknown, signed = true): asserts value is SignedMessage {
  if (!isObject(value)) fail('shape', 'a message is an object')
  only(value, ['v', 'to', 'from', 'time', 'body', 'key', 'host', 'sig'], 'message')
  if (value.v !== 1) fail('version', 'v must be 1')
  if (!publicKeyFromAddress(value.to)) fail('key', 'to is not a usable address')
  if (!publicKeyFromAddress(value.from)) fail('key', 'from is not a usable address')
  if (!Number.isSafeInteger(value.time) || (value.time as number) < 0) fail('time', 'time is whole milliseconds since 1970')
  const body = value.body
  if (!isObject(body) || Object.keys(body).length !== 1 || typeof body.private !== 'string' || !B64U.test(body.private)) {
    fail('body', 'a message body is { private: <age file, base64url> } and nothing else')
  }
  if ('key' in value) {
    if (!('host' in value)) fail('shape', 'a message signed by key names host')
    checkKey(value, value.from)
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

/** A write key, signing for `from`, a profile whose permissions record lists it for the inbox, as `host`, one of its hosts, serves it. */
export type KeySender = { key: Key; from: string; host: string }
/** The sender's own key, naming `host`, one of its hosts, where an inbox with an issuer's rule reads its card. */
export type HostSender = { from: Key; host: string }
/** Who signs a message: the sender's own key (a main key, or any key), with one of its hosts or not, or a write key. */
export type Sender = Key | HostSender | KeySender

/** Sign a sealed body to `to`. Sealing it is message() in private.ts. */
export function signMessage(sender: Sender, to: string, body: SealedBody, time: number): SignedMessage {
  let signer: Key
  let unsigned: UnsignedMessage
  if ('scalar' in sender) {
    signer = sender
    unsigned = { v: 1, to, from: sender.address, time, body }
  } else if ('key' in sender) {
    signer = sender.key
    unsigned = { v: 1, to, from: sender.from, time, body, key: sender.key.address, host: sender.host }
  } else {
    signer = sender.from
    unsigned = { v: 1, to, from: sender.from.address, time, body, host: sender.host }
  }
  checkMessageShape(unsigned, false)
  return { ...unsigned, sig: signAs(signer, unsigned.key ?? unsigned.from, messageSigningInput(unsigned)) }
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

/**
 * Whether the message's signer signed it: `key` if it names one, else `from`. Strict, as a
 * record's. Whether from lists `key` is the receiving host's check, against from's own records.
 */
export function verifyMessage({ message }: CheckedMessage): boolean {
  return verifySignature(b64u.decode(message.sig), messageSigningInput(unsignedMessageOf(message)), message.key ?? message.from)
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
  only(value, ['v', 'profile', 'after', 'time', 'key', 'sig'], 'pull')
  if (value.v !== 1) fail('version', 'v must be 1')
  if (!publicKeyFromAddress(value.profile)) fail('key', 'profile is not a usable address')
  if (!Number.isSafeInteger(value.after) || (value.after as number) < 0) fail('shape', 'after is a cursor: a whole number')
  if (!Number.isSafeInteger(value.time) || (value.time as number) < 0) fail('time', 'time is whole milliseconds since 1970')
  if ('key' in value) checkKey(value, value.profile)
  checkSig(value, signed)
}

/**
 * A request for the messages to a profile that arrived after the cursor, signed at `time` by its
 * main key, or by `key`, a read key its permissions record lists for the inbox, for `profile`.
 */
export function pullRequest(owner: Key | { key: Key; profile: string }, after: number, time: number): SignedPull {
  const own = 'scalar' in owner
  const signer = own ? owner : owner.key
  const unsigned: UnsignedPull = own ? { v: 1, profile: owner.address, after, time } : { v: 1, profile: owner.profile, after, time, key: owner.key.address }
  checkPullShape(unsigned, false)
  return { ...unsigned, sig: signAs(signer, unsigned.key ?? unsigned.profile, pullSigningInput(unsigned)) }
}

/**
 * A pull request off the wire, at the host's clock `now`: canonical text and shape, then its time
 * within ten minutes of `now` either way [stale], then the signature of `key`, or else of the
 * profile's main key [signature]. Whether the profile lists `key` is the host's check, against its
 * own copy of the permissions record. Throws RecordError.
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
  if (!verifySignature(b64u.decode(sig), pullSigningInput(unsigned), value.key ?? value.profile)) fail('signature', value.key === undefined ? 'the profile’s main key did not sign this pull' : 'key did not sign this pull')
  return value
}

// ---------------------------------------------------------------------------------------------
// The inbox a profile declares

export type Inbox = {
  /**
   * Who may deliver: anyone, or a profile whose card carries a human proof from this issuer, under
   * any label. The issuer is named by its key: 128 characters of lowercase hex, x then y.
   */
  senders: 'anyone' | { issuer: string }
  /** One message from each sender, ever. */
  once?: true
  /** The largest message it takes, as canonical text in bytes. */
  maxBytes?: number
  /** Read keys' recipients: a sender seals every message to the inbox key and to each of these. */
  readers?: string[]
}

/**
 * The inbox a profile record's body declares: null when it declares none (no `inbox` field, or a
 * deleted or private card), 'unsupported' when it holds a rule, a field or a value this code does
 * not know. A host refuses deliveries to an inbox it cannot read rather than guess: a field it
 * skipped could be a limit the profile set, so a new kind of rule can be added later without an
 * old host taking what it should refuse.
 */
export function inboxOf(body: Body | null | undefined): Inbox | null | 'unsupported' {
  if (!body || !('inbox' in body)) return null
  const inbox = body.inbox
  if (!isObject(inbox) || Object.keys(inbox).some((key) => !['senders', 'once', 'maxBytes', 'readers'].includes(key))) return 'unsupported'
  const { senders, once, maxBytes, readers } = inbox
  let rule: Inbox['senders']
  if (senders === 'anyone') rule = 'anyone'
  else if (isObject(senders) && Object.keys(senders).length === 1 && typeof senders.issuer === 'string' && ISSUER_KEY.test(senders.issuer)) rule = { issuer: senders.issuer }
  else return 'unsupported'
  if ('once' in inbox && once !== true) return 'unsupported'
  if ('maxBytes' in inbox && (!Number.isSafeInteger(maxBytes) || (maxBytes as number) < 0)) return 'unsupported'
  if ('readers' in inbox && (!Array.isArray(readers) || readers.some((r) => typeof r !== 'string' || !RECIPIENT.test(r)))) return 'unsupported'
  return {
    senders: rule,
    ...(once === true && { once }),
    ...('maxBytes' in inbox && { maxBytes: maxBytes as number }),
    ...('readers' in inbox && { readers: readers as string[] }),
  }
}

/**
 * The keys a message to this card is sealed to, in one envelope: its inbox key, then its inbox's
 * readers. Throws when the card gives no inbox key, or declares no inbox this code can read: a
 * field it does not know could name more keys to seal to.
 */
export function sealedTo(card: Body | null | undefined): string[] {
  const inbox = inboxOf(card)
  if (inbox === null || inbox === 'unsupported') fail('no_inbox', 'the card declares no inbox this code can read')
  const inboxKey = card!.inboxKey
  if (typeof inboxKey !== 'string' || !RECIPIENT.test(inboxKey)) fail('no_inbox', 'the card gives no inbox key')
  return [inboxKey, ...(inbox.readers ?? [])]
}
