// Private records: a body only chosen keys open. The body on a host is
// `{ private: <age file, base64url> }`. The age file is the envelope: one random file key per
// record, sealed once to each key, naming none of them. Each key is age's post-quantum hybrid
// (mlkem768x25519: ML-KEM-768 with X25519); its public half is `age1pq1…`. The owner's own inbox key
// is one, which keys/ mixes from the profile's secret and the profile record's `inboxKey` field
// publishes. The record around the envelope is signed as usual, so no reader can forge content for
// the others.
//
// What this does not hide: that a private record exists, its path, time and size, and how many
// keys it was sealed to (one stanza each). Removing a reader means a new version sealed to the
// rest; a reader keeps whatever it already opened. No forward secrecy: a key that leaks later opens
// every envelope ever sealed to it.
//
// A message's body is one of these envelopes, sealed to the inbox key of the profile it is to.
// message() seals and signs one; openMessage() checks one and opens it. The
// vault, what a new device needs and the seed cannot give back, is one private record at `vault` in
// a folder of its own, sealed to the vault's own inbox key alone (vault.ts).

import { Decrypter, Encrypter } from 'age-encryption'
import { b64u } from './bytes.ts'
import { canonical, parseCanonical } from './canonical.ts'
import { readProfile, type ReadHow } from './client.ts'
import type { Key } from './keys.ts'
import { type Sender, type SignedMessage, decodeMessage, encodeMessage, inboxKeyOf, signMessage } from './message.ts'
import { type Body, RecordError, type SignedRecord, isPrivate } from './record.ts'
import { VAULT_PATH, type Vault, checkVault } from './vault.ts'
import { ownerRecord } from './write.ts'

export { isPrivate }
export * from './vault.ts'

/** A private body: `body` in an envelope sealed to these keys (`age1pq1…`), which only they open. */
export async function makePrivate(body: Body, readers: string[]): Promise<{ private: string }> {
  if (!readers.length) throw new Error('seal it to at least one key')
  const encrypter = new Encrypter()
  for (const reader of readers) {
    // age checks the rest of the key when it is added.
    if (typeof reader !== 'string' || !reader.startsWith('age1pq1')) throw new Error('a key to seal to is an age post-quantum hybrid key, age1pq1…')
    encrypter.addRecipient(reader)
  }
  return { private: b64u.encode(await encrypter.encrypt(canonical(body))) }
}

/** Open a private body with a key's identity. Throws if the envelope was not sealed to it. */
export async function openPrivate(body: Body, identity: string): Promise<Body> {
  if (!isPrivate(body)) throw new Error('not a private body')
  const decrypter = new Decrypter()
  decrypter.addIdentity(identity)
  const value = parseCanonical(await decrypter.decrypt(b64u.decode(body.private), 'text'))
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('a private body holds an object')
  return value
}

/** How many keys an envelope was sealed to: visible to anyone, hosts included. */
export function readerCount(body: { private: string }): number {
  const bytes = b64u.decode(body.private)
  const header = new TextDecoder().decode(bytes.subarray(0, Math.min(bytes.length, 64 * 1024))).split('\n---')[0] ?? ''
  return header.split('\n').filter((line) => line.startsWith('-> ')).length
}

/**
 * A message to `to`'s inbox: `body` sealed to the inbox key `profileBody` (to's profile record body)
 * gives, and nothing else; then signed by the sender's own key.
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

/**
 * The vault record: the vault's contents, checked, sealed to the vault's own inbox key alone, at
 * `vault` in the vault's folder, signed by the vault key (keys/'s vaultKey; inboxKey of its secret
 * gives `inboxKey`, what it is sealed to). Write it after reading the current one, at a time past its time (readVault gives
 * it), to every host the vault's hosts record names.
 */
export async function vaultRecord(vault: Key, inboxKey: string, contents: Vault, time: number): Promise<SignedRecord> {
  checkVault(contents)
  return ownerRecord(vault, VAULT_PATH, await makePrivate(contents as Body, [inboxKey]), time)
}

/** The vault in a vault record's body, opened with the vault's inbox key identity, checked. */
export async function openVault(body: Body, identity: string): Promise<Vault> {
  const inside = await openPrivate(body, identity)
  checkVault(inside)
  return inside
}

/**
 * The vault, read from hosts: the folder at the vault key's `address`, on the hosts given and every
 * host its hosts record names, by POST so the address is in no URL; its current `vault` record
 * opened with the vault's inbox key `identity`. With it, the folder's hosts, the record's time, for
 * the next write, and the hosts that failed, as readProfile lists them: one may hold a newer vault.
 * Null when every host asked answered and none has it. When none has it and a host failed, it
 * throws: the vault may be there.
 */
export async function readVault(hosts: string[], vault: { address: string; identity: string }, now: number, how: ReadHow = {}): Promise<{ vault: Vault; hosts: string[]; time: number; failed: Array<{ host: string; error: string }> } | null> {
  const view = await readProfile(hosts, vault.address, now, { ...how, post: true })
  const current = view.current.get(VAULT_PATH)
  if (!current?.record.body) {
    if (!view.failed.length) return null
    throw new RecordError('host', `no vault read, and a host that may hold it failed: ${view.failed.map((f) => `${f.host} (${f.error})`).join(', ')}`)
  }
  return { vault: await openVault(current.record.body, vault.identity), hosts: view.hosts, time: current.record.time, failed: view.failed }
}
