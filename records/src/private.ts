// Private records: a body only chosen keys open. The body on a host is
// `{ private: <age file, base64url> }`. The age file is the envelope: one random file key per
// record, encrypted once to each key, naming none of them. Each key is age's post-quantum hybrid
// (mlkem768x25519: ML-KEM-768 with X25519); its public half is `age1pq1…`. The owner's own inbox key
// is one, which keys/ mixes from the profile's secret and the profile record's `inboxKey` field
// publishes. The record around the envelope is signed as usual, so no reader can forge content for
// the others.
//
// The owner shares a record by encrypting it to other people's inbox keys besides its own. What
// this does not hide: that a private record exists, its path, time and size, and how many keys it
// was encrypted to (one stanza each), though never which: a stanza holds only its encapsulation.
// Removing a reader means a new version encrypted to the rest; a reader keeps whatever it already
// opened. No forward secrecy: a key that leaks later opens every envelope ever encrypted to it.
//
// A message's body is one of these envelopes, encrypted to the inbox key of the profile it is to.
// message() encrypts and signs one; openMessage() checks one and opens it.

import { Decrypter, Encrypter } from 'age-encryption'
import { b64u } from './bytes.ts'
import { canonical, parseCanonical } from './canonical.ts'
import { type Sender, type SignedMessage, decodeMessage, encodeMessage, inboxKeyOf, signMessage } from './message.ts'
import { type Body, isPrivate } from './record.ts'

export { isPrivate }

/** A private body: `body` in an envelope encrypted to these keys (`age1pq1…`), which only they open. */
export async function makePrivate(body: Body, readers: string[]): Promise<{ private: string }> {
  if (!readers.length) throw new Error('encrypt it to at least one key')
  const encrypter = new Encrypter()
  for (const reader of readers) {
    // age checks the rest of the key when it is added.
    if (typeof reader !== 'string' || !reader.startsWith('age1pq1')) throw new Error('a key to encrypt to is an age post-quantum hybrid key, age1pq1…')
    encrypter.addRecipient(reader)
  }
  return { private: b64u.encode(await encrypter.encrypt(canonical(body))) }
}

/** Open a private body with a key's identity. Throws if the envelope was not encrypted to it. */
export async function openPrivate(body: Body, identity: string): Promise<Body> {
  if (!isPrivate(body)) throw new Error('not a private body')
  const decrypter = new Decrypter()
  decrypter.addIdentity(identity)
  const value = parseCanonical(await decrypter.decrypt(b64u.decode(body.private), 'text'))
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('a private body holds an object')
  return value
}

/** How many keys an envelope was encrypted to: visible to anyone, hosts included. */
export function readerCount(body: { private: string }): number {
  const bytes = b64u.decode(body.private)
  const header = new TextDecoder().decode(bytes.subarray(0, Math.min(bytes.length, 64 * 1024))).split('\n---')[0] ?? ''
  return header.split('\n').filter((line) => line.startsWith('-> ')).length
}

/**
 * A message to `to`'s inbox: `body` encrypted to the inbox key `profileBody` (to's profile record
 * body) gives, and nothing else; then signed by the sender's own key.
 */
export async function message(sender: Sender, to: string, body: Body, time: number, profileBody: Body): Promise<SignedMessage> {
  return signMessage(sender, to, await makePrivate(body, [inboxKeyOf(profileBody)]), time)
}

/**
 * A message, as wire text or signed, checked, then its body opened with the identity of the inbox
 * key of the profile it is to.
 */
export async function openMessage(message: SignedMessage | string, identity: string): Promise<{ id: string; from: string; to: string; time: number; body: Body }> {
  const { message: m, id } = decodeMessage(typeof message === 'string' ? message : encodeMessage(message))
  return { id, from: m.from, to: m.to, time: m.time, body: await openPrivate(m.body, identity) }
}
