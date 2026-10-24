// A profile's keys: the main key, one per label, mixed from the seed scalar so the stamp proof can
// derive it too; the profile's secret, mixed from the seed; and its inbox key, mixed from that
// secret. See README.md, "The recipe".

import { bech32 } from '@scure/base'
import { identityToRecipient } from 'age-encryption'
import { poseidon3 } from 'poseidon-lite/poseidon3'
import { type Point, addressOf, keyScalar, publicKeyOf } from './curve.ts'
import { PREFIX, isFieldElement, scopeOf } from './field.ts'
import { INFO, SEED_LENGTH, assertBytes, assertText, hkdf } from './hkdf.ts'
import { seedScalar } from './scalar.ts'

/**
 * A profile's main key, on Baby Jubjub. Its address is the profile's name. It signs the profile's
 * records. Held in memory only.
 */
export type MainKey = {
  label: string
  /** The label as a number, `scopeOf(label)`. */
  scope: bigint
  /** The scalar that signs: the lowest 250 bits of `Poseidon(profile prefix, seed scalar, scope)`. */
  scalar: bigint
  /** `scalar · Base8`. */
  publicKey: Point
  /** The public key packed into 32 bytes, in base58: the profile's name. */
  address: string
  /** 32 bytes mixed from the seed for this label. The inbox key is mixed from them; no public key gives them. */
  secret: Uint8Array
}

/**
 * The key that opens envelopes sealed to a profile: age's post-quantum hybrid identity, ML-KEM-768
 * with X25519 (mlkem768x25519).
 */
export type InboxKey = {
  /** age's hybrid identity, `AGE-SECRET-KEY-PQ-1…`: it opens what is sealed to this profile. */
  identity: string
  /** What others seal to, `age1pq1…`. The profile's address does not give it. */
  sealTo: string
}

/** A profile's scalar from the seed scalar and its label. The stamp circuit computes the same. */
export function profileScalarOf(seed: bigint, label: string): bigint {
  if (!isFieldElement(seed)) throw new RangeError('a seed scalar is a field element')
  return keyScalar(poseidon3([PREFIX.profile, seed, scopeOf(label)]))
}

/**
 * The main key for `label`, from the seed. One Poseidon mix per label, so two labels give
 * unrelated keys, and the same seed and label always give the same key.
 */
export async function mainKey(seed: Uint8Array, label: string): Promise<MainKey> {
  assertBytes('seed', seed, SEED_LENGTH)
  assertText('label', label)
  const scalar = profileScalarOf(await seedScalar(seed), label)
  const publicKey = publicKeyOf(scalar)
  const secret = await hkdf(seed, INFO.profile(label))
  return { label, scope: scopeOf(label), scalar, publicKey, address: addressOf(publicKey), secret }
}

/**
 * An inbox key, from a profile's 32-byte secret or the vault's. The 32 mixed bytes are used
 * unchanged as age's hybrid identity (its seed, which age expands into the ML-KEM-768 and X25519
 * keys); age's own library computes what others seal to (identityToRecipient).
 */
export async function inboxKey(secret: Uint8Array): Promise<InboxKey> {
  assertBytes('secret', secret, 32)
  const bytes = await hkdf(secret, INFO.inbox)
  const identity = bech32.encodeFromBytes('AGE-SECRET-KEY-PQ-', bytes).toUpperCase()
  return { identity, sealTo: await identityToRecipient(identity) }
}
