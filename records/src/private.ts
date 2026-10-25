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
// message() encrypts and signs one; openMessage() checks one and opens it. A profile's rules are
// private records in its own folder, each encrypted to its own inbox key alone (rules.ts).

import { INFO, hkdf, inboxKey } from '@foundationforest/keys'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { Decrypter, Encrypter } from 'age-encryption'
import { b64u, hex, utf8 } from './bytes.ts'
import { type Json, canonical, parseCanonical } from './canonical.ts'
import type { Key } from './keys.ts'
import { type Sender, type SignedMessage, decodeMessage, encodeMessage, inboxKeyOf, signMessage } from './message.ts'
import { type Body, type SignedRecord, isPrivate } from './record.ts'
import { RULE_PREFIX, type Rule, type Who, checkRule } from './rules.ts'
import type { View } from './view.ts'
import { ownerRecord } from './write.ts'

export { isPrivate }
export * from './rules.ts'

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

/** A profile's main key, as keys/'s mainKey gives it: with the profile's secret, which its inbox key and rule key come from. */
export type ProfileKey = Key & { secret: Uint8Array }

/**
 * A rule's id, the last segment of its path: the first 32 hex characters of HMAC-SHA256, keyed by
 * the profile's rule key (keys/'s `hkdf(secret, INFO.rule)`), of the canonical text of `who`
 * without `key` and `name`. So one who has one rule per profile, whatever the person calls it; and
 * since only the person's signers hold the rule key, a path names no who, and one who's rules on two
 * profiles never share a path.
 */
export async function ruleId(owner: { secret: Uint8Array }, who: Who): Promise<string> {
  const { key: _key, name: _name, ...named } = who as { [field: string]: Json }
  return hex.encode(hmac(sha256, await hkdf(owner.secret, INFO.rule), utf8(canonical(named)))).slice(0, 32)
}

/**
 * A rule's record: the rule, checked, encrypted to the profile's own inbox key alone, at
 * `rule/<id>` in its folder, signed by its main key. Write it at a time past the current one's at
 * that path (nextTime). A null body at the same path removes the rule.
 */
export async function ruleRecord(owner: ProfileKey, rule: Rule, time: number): Promise<SignedRecord> {
  checkRule(rule)
  const { encryptTo } = await inboxKey(owner.secret)
  return ownerRecord(owner, RULE_PREFIX + (await ruleId(owner, rule.who)), await makePrivate(rule as unknown as Body, [encryptTo]), time)
}

/**
 * A profile's rules, by id, from its view (readProfile's, read by POST), opened with its inbox key.
 * A rule that does not open, does not check, or sits at a path its who does not give is left out: a
 * rule a signer cannot read is no rule, so it asks the person, as for any ask no rule covers. A
 * signer reads them before it acts on any ask for the profile, so a rule removed on another device
 * stops here too.
 */
export async function readRules(view: View, owner: { secret: Uint8Array }): Promise<Map<string, Rule>> {
  const { identity } = await inboxKey(owner.secret)
  const rules = new Map<string, Rule>()
  for (const [path, { record }] of view.current) {
    if (!path.startsWith(RULE_PREFIX) || record.body === null) continue
    const id = path.slice(RULE_PREFIX.length)
    try {
      const rule = await openPrivate(record.body, identity)
      checkRule(rule)
      if ((await ruleId(owner, rule.who)) === id) rules.set(id, rule)
    } catch {
      // Left out: no rule, so the signer asks.
    }
  }
  return rules
}
