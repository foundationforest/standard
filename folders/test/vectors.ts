// The spec's test vectors. The keys are keys/'s: its test seed (bytes 00 01 … 1f), its
// tutoring/seller and tutoring/buyer profiles, their opening halves and pay addresses, the empty
// label's main key, the Profiles folder's, and its access key, pinned in keys/test/vectors.json and
// not repeated here. EdDSA-Poseidon here is deterministic, and the locked bodies are pinned as made,
// in envelopes.json, so these never change unless the standard does. `node test/vectors.ts` prints
// them; vectors.test.ts checks them against test/vectors.json, each with a second implementation.

import { readFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { fieldHash, mainKey, seedNumber } from '@foundationforest/keys'
import { signStamp, stampNumberOf, stampToJson } from '@foundationforest/proofs'
import { sha256 } from '@noble/hashes/sha2.js'
import { hex } from '../src/bytes.ts'
import { canonical } from '../src/canonical.ts'
import { type SignedEntry, entryId, signingInput, unsignedOf } from '../src/entry.ts'
import { type InboxEntry, type SignedMessage, inboxId, messageSigningInput, signMessage } from '../src/inbox.ts'
import { entry } from '../src/write.ts'
import { KEYS, SEED, access, alice, aliceBuyer, aliceOpening } from './fixtures.ts'

export const TIME = 1_790_000_000_000 // 2026-09-21T13:33:20Z
/** The locked bodies, made once with lock() and pinned as made: age's encryption is random. */
export const ENVELOPES = JSON.parse(readFileSync(new URL('./envelopes.json', import.meta.url), 'utf8'))
/** The random ids of the note's and the Profiles folder's paths, made once and pinned as made. */
export const IDS = { note: 'cdfa9eef25aaa50a0a5e4ea0beee1cde', label: 'e37918782bf5499626384d7d74947220', stamp: 'a5dc56ca9647b953b2166ba16b75ea97' }

const describe = (e: SignedEntry) => ({
  wire: canonical(e),
  signingInputHex: hex.encode(signingInput(unsignedOf(e))),
  id: entryId(unsignedOf(e)),
})

const describeMessage = (message: SignedMessage) => {
  const { sig: _sig, ...unsigned } = message
  return { wire: canonical(message), signingInputHex: hex.encode(messageSigningInput(unsigned)) }
}

/** The photo vector's bytes: the 26 letters, as text/plain. */
export const LETTERS = new TextEncoder().encode('abcdefghijklmnopqrstuvwxyz')

/** The folder's profile entry: its hosts, its open key, its pay addresses, and keys/'s access key, able to read its inbox and write. */
export const profileBody = () => {
  const seller = KEYS.payKeys.filter((p: { label: string }) => p.label === 'tutoring/seller')
  return {
    market: 'tutoring',
    role: 'seller',
    hosts: ['https://host-a.example', 'https://host-b.example'],
    openKey: aliceOpening.openKey,
    pay: Object.fromEntries(seller.map((p: { chain: string; address: string }) => [p.chain, p.address])),
    keys: [{ key: access.address, open: access.openKey, can: ['read-inbox', 'write'] }],
  }
}
/** The message locked in the inbox vector: from tutoring/buyer, naming one of its hosts. */
export const MESSAGE = { text: 'Is Tuesday at six free?' }
/** The note about the access key, locked to the main key alone: it names the key it is about. */
export const NOTE = { key: access.address, holder: 'my tutoring AI', since: TIME }
/** The Profiles folder's entry for tutoring/seller, locked to its own opening half. */
export const LABEL = { label: 'tutoring/seller', time: TIME }

/**
 * The Profiles folder's stamp, as text: the example verifier's stamp for the test seed (its key from
 * the text scripts/example-profile.ts makes it from), with a field the verifier added that an
 * entry's narrowed JSON cannot spell, a fraction. Its entry holds `{ stamp: <this text> }`.
 */
export function stampText(): string {
  const verifier = 'verifier-a.example'
  const key = sha256(new TextEncoder().encode(`forest example verifier: ${verifier}`))
  const stampNumber = stampNumberOf(seedNumber(SEED), verifier)
  return JSON.stringify(stampToJson(signStamp(key, { stampNumber, facts: fieldHash('forest example facts', verifier), verifierName: verifier, score: 0.97 })))
}

/** The inbox entry's message: from tutoring/buyer to tutoring/seller, three minutes in. */
export const inboxMessage = () => signMessage(aliceBuyer, alice.address, MESSAGE, TIME + 180_000, 'https://host-b.example')

export async function vectors() {
  const profiles = await mainKey(SEED, '')
  // An offer's fields are its market's, and the standard names none (README.md, Folders): `about`
  // stands in for them.
  const offer = { about: 'One hour of maths, online.' }
  const letters = { sha256: hex.encode(sha256(LETTERS)), type: 'text/plain', size: LETTERS.length }
  const inbox: InboxEntry = { v: 1, to: alice.address, private: ENVELOPES.inbox }
  const stamp = stampText()
  return {
    about: "Forest folders vectors. The folder is keys/'s tutoring/seller profile's, from its test seed: its profile entry's openKey is that profile's main key's opening half, its pay field its pay addresses, and its keys field lists keys/'s access key, from 32 bytes of 0x2b then 32 of 0x2c, able to read-inbox and write, all pinned in keys/test/vectors.json. Every signature is EdDSA-Poseidon on Baby Jubjub over SHA-256 of the signed bytes, shifted right one byte, by the main key or the access key named; the signed bytes are the canonical text of what is signed, without its sig, and nothing else. offerByKey is the access key's; photo is an entry whose body is its file, the 26 letters a to z as text/plain. The inbox entry holds a message from keys/'s tutoring/buyer profile, from the same seed, to tutoring/seller, locked to tutoring/seller's open key and the access key's. note is the main key's note about the access key, at a random path, locked to the main key alone, naming the key it is about. profilesFolder is the seed's Profiles folder, the empty label's: its profile entry, hosts alone; its entry for tutoring/seller; and its entry for one stamp, the example verifier's, holding the stamp's JSON as text (a field the verifier added, a fraction, among it), each at a random path and locked to its own opening half. Locked bodies and random ids are made once and pinned as made, in envelopes.json and in test/vectors.ts, since age's encryption and the ids are random.",
    profile: alice.address,
    accessKey: access.address,
    profileEntry: describe(entry(alice, 'profile', profileBody(), TIME)),
    offer: describe(entry(alice, 'offer/maths', offer, TIME)),
    offerByKey: describe(entry({ profile: alice.address, key: access }, 'offer/physics', offer, TIME + 60_000)),
    photo: describe(entry(alice, 'photo/letters', { files: [letters] }, TIME + 90_000)),
    deleted: describe(entry(alice, 'offer/maths', null, TIME + 120_000)),
    inbox: { wire: canonical(inbox), id: inboxId(inbox), message: describeMessage(inboxMessage()) },
    note: describe(entry(alice, `key/${IDS.note}`, { private: ENVELOPES.note }, TIME + 240_000)),
    profilesFolder: {
      profile: profiles.address,
      profileEntry: describe(entry(profiles, 'profile', { hosts: ['https://host-a.example'] }, TIME)),
      label: describe(entry(profiles, `label/${IDS.label}`, { private: ENVELOPES.label }, TIME + 300_000)),
      stamp: { text: stamp, ...describe(entry(profiles, `stamp/${IDS.stamp}`, { private: ENVELOPES.stamp }, TIME + 360_000)) },
    },
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]!).href) console.log(JSON.stringify(await vectors(), null, 2))
