// Locked entries and inbox entries: bodies only chosen keys open. A locked body on a host is
// `{ private: <age file, base64url> }`. The age file is the envelope: one random file key per
// body, locked once to each open key, naming none of them. Each open key is age's post-quantum
// hybrid (mlkem768x25519: ML-KEM-768 with X25519), `age1pq1…`, an opening half's (keys/'s
// openingHalf). The entry around the envelope is signed as usual, so no reader can forge content
// for the others.
//
// A locked entry in a folder is locked to the main key's open key and to each listed key that can
// read (lockKeysOf); a note about an access key, to the main key's alone. The writer locks it:
// nobody can check, since an envelope names no key. What this does not hide: that a locked entry
// exists, its path, time and size, and how many keys it was locked to (one stanza each), though
// never which: a stanza holds only its encapsulation. A key removed reads no new version; it keeps
// whatever it already opened. No forward secrecy: a key that leaks later opens every envelope ever
// locked to it.
//
// An inbox entry's `private` is one of these envelopes, holding one signed message, locked to the
// open keys the folder's profile entry gives for its inbox (inboxLockKeysOf). inboxEntry() signs and
// locks one; openInbox() opens one and checks its message.

import { Decrypter, Encrypter } from 'age-encryption'
import { b64u } from './bytes.ts'
import { canonical, parseCanonical } from './canonical.ts'
import { type Body, isLocked } from './entry.ts'
import { FolderError } from './fail.ts'
import { type InboxEntry, type SignedMessage, checkMessage, checkMessageShape, decodeInbox, encodeInbox, signMessage } from './inbox.ts'
import { inboxLockKeysOf } from './profile.ts'
import type { Writer } from './write.ts'

export { isLocked }

/** A locked body: `body` in an envelope locked to these open keys (`age1pq1…`), which only their identities open. */
export async function lock(body: Body, openKeys: string[]): Promise<{ private: string }> {
  if (!openKeys.length) throw new Error('lock it to at least one key')
  const encrypter = new Encrypter()
  for (const openKey of openKeys) {
    // age checks the rest of the key when it is added.
    if (typeof openKey !== 'string' || !openKey.startsWith('age1pq1')) throw new Error('an open key is an age post-quantum hybrid key, age1pq1…')
    encrypter.addRecipient(openKey)
  }
  return { private: b64u.encode(await encrypter.encrypt(canonical(body))) }
}

/** Open a locked body with an opening half's identity. Throws if the envelope was not locked to it. */
export async function openLocked(body: Body, identity: string): Promise<Body> {
  if (!isLocked(body)) throw new Error('not a locked body')
  const decrypter = new Decrypter()
  decrypter.addIdentity(identity)
  const value = parseCanonical(await decrypter.decrypt(b64u.decode(body.private), 'text'))
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('a locked body holds an object')
  return value
}

/** How many keys an envelope was locked to: visible to anyone, hosts included. */
export function lockCount(body: { private: string }): number {
  const bytes = b64u.decode(body.private)
  const header = new TextDecoder().decode(bytes.subarray(0, Math.min(bytes.length, 64 * 1024))).split('\n---')[0] ?? ''
  return header.split('\n').filter((line) => line.startsWith('-> ')).length
}

/**
 * An inbox entry for `to`'s folder: a message, signed by the writer (the sender's main key, or an
 * access key its profile entry lists with message), locked to the open keys `toProfile`, to's
 * current profile entry's body, gives for its inbox, and nothing else. `host` is one of the
 * sender's hosts.
 */
export async function inboxEntry(writer: Writer, to: string, body: Body, time: number, toProfile: Body | null | undefined, host?: string): Promise<InboxEntry> {
  const message = signMessage(writer, to, body, time, host)
  return { v: 1, to, ...(await lock(message, inboxLockKeysOf(toProfile))) }
}

/**
 * An inbox entry, as wire text or as it is, opened with the identity of one of the keys it was
 * locked to, and its message checked: its shape, that it is to this folder, and its signature, by
 * its key or its sender's main key. Throws FolderError `to` when the message is to another folder,
 * and `signature` when its signature does not hold. Whether the sender's profile entry lists the key
 * that signed is senderCounts's.
 */
export async function openInbox(entry: InboxEntry | string, identity: string): Promise<{ id: string; to: string; message: SignedMessage }> {
  const { entry: e, id } = decodeInbox(typeof entry === 'string' ? entry : encodeInbox(entry))
  const message = await openLocked({ private: e.private }, identity)
  checkMessageShape(message)
  if (message.to !== e.to) throw new FolderError('to', 'the message is to another folder')
  if (!checkMessage(message)) throw new FolderError('signature', 'the message’s signature does not hold')
  return { id, to: e.to, message }
}
