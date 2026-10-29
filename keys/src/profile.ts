// A profile's main key, one per label: its signing half mixed from the seed's number so the proofs
// can derive it too, and its opening secret mixed from the seed with the same text. The empty label
// gives the Profiles folder's. See README.md, "The recipe".

import { poseidon2 } from 'poseidon-lite/poseidon2'
import { type Point, addressOf, keyScalar, publicKeyOf } from './curve.ts'
import { isFieldElement, scopeOf, seedNumber } from './field.ts'
import { TEXT, SEED_LENGTH, assertBytes, assertText, hkdf } from './hkdf.ts'

/**
 * A profile's main key, on Baby Jubjub: its signing half, and the secret its opening half is. Its
 * address is the profile's name. It signs the profile's entries. Held in memory only.
 */
export type MainKey = {
  label: string
  /** The label as a number, `scopeOf(label)`. */
  scope: bigint
  /** The scalar that signs: the lowest 250 bits of `Poseidon(the seed's number, scope)`. */
  scalar: bigint
  /** `scalar · Base8`. */
  publicKey: Point
  /** The public key packed into 32 bytes, in base58: the profile's name. */
  address: string
  /** The opening secret, `HKDF(seed, "forest/profile/<label>")`: the opening half, as it is (`openingHalf`). No public key gives it. */
  secret: Uint8Array
}

/** A profile's scalar from the seed's number and its label. Both circuits compute the same. */
export function profileScalarOf(seed: bigint, label: string): bigint {
  if (!isFieldElement(seed)) throw new RangeError("the seed's number is a field element")
  return keyScalar(poseidon2([seed, scopeOf(label)]))
}

/**
 * The main key for `label`, from the seed. One Poseidon mix per label, so two labels give
 * unrelated keys, and the same seed and label always give the same key. Its opening half is
 * `openingHalf(secret)`.
 */
export async function mainKey(seed: Uint8Array, label: string): Promise<MainKey> {
  assertBytes('seed', seed, SEED_LENGTH)
  assertText('label', label)
  const scalar = profileScalarOf(seedNumber(seed), label)
  const publicKey = publicKeyOf(scalar)
  const secret = await hkdf(seed, TEXT.profile(label))
  return { label, scope: scopeOf(label), scalar, publicKey, address: addressOf(publicKey), secret }
}
