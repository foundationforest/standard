// A profile's main key, one per label, mixed from the seed scalar so the proofs can derive it too;
// and the profile's secret, mixed from the seed, which the main key's opening half comes from. See
// README.md, "The recipe".

import { poseidon3 } from 'poseidon-lite/poseidon3'
import { type Point, addressOf, keyScalar, publicKeyOf } from './curve.ts'
import { PREFIX, isFieldElement, scopeOf } from './field.ts'
import { INFO, SEED_LENGTH, assertBytes, assertText, hkdf } from './hkdf.ts'
import { seedScalar } from './scalar.ts'

/**
 * A profile's main key, on Baby Jubjub: its signing half. Its address is the profile's name. It
 * signs the profile's entries. Held in memory only.
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
  /** 32 bytes mixed from the seed for this label. The opening half is mixed from them; no public key gives them. */
  secret: Uint8Array
}

/** A profile's scalar from the seed scalar and its label. Both circuits compute the same. */
export function profileScalarOf(seed: bigint, label: string): bigint {
  if (!isFieldElement(seed)) throw new RangeError('a seed scalar is a field element')
  return keyScalar(poseidon3([PREFIX.profile, seed, scopeOf(label)]))
}

/**
 * The main key for `label`, from the seed. One Poseidon mix per label, so two labels give
 * unrelated keys, and the same seed and label always give the same key. Its opening half is
 * `openingHalf(secret)`.
 */
export async function mainKey(seed: Uint8Array, label: string): Promise<MainKey> {
  assertBytes('seed', seed, SEED_LENGTH)
  assertText('label', label)
  const scalar = profileScalarOf(await seedScalar(seed), label)
  const publicKey = publicKeyOf(scalar)
  const secret = await hkdf(seed, INFO.profile(label))
  return { label, scope: scopeOf(label), scalar, publicKey, address: addressOf(publicKey), secret }
}
