// Keys, and the one way a key is written down.
//
// Records mixes no key: keys/ does (keys/README.md), and an app takes its keys from there. A
// profile's main key comes from the person's seed and signs everything for its folder: its records,
// its messages, its pulls and its blob requests. No other key signs for a profile: someone acting
// for the person asks one of the person's signers, which signs with the main key. Every key signs
// with EdDSA-Poseidon on Baby Jubjub, by keys/'s signBytes, and every address is a packed point in
// base58.

// keys/'s curve alone, not all of keys/, whose inbox keys load age: the core holds no encryption
// library (README.md, Run it).
import { type Point, addressOf, pointOf, publicKeyOf } from '@foundationforest/keys/curve'

export type { Point } from '@foundationforest/keys/curve'

/** Anything that signs: keys/'s main key or service key. Held in memory only. */
export type Key = {
  /** The scalar that signs. */
  scalar: bigint
  publicKey: Point
  /** Its address: a profile's name, or a service's key. */
  address: string
}

/** A key from its scalar. */
export function keyFromScalar(scalar: bigint): Key {
  const publicKey = publicKeyOf(scalar)
  return { scalar, publicKey, address: addressOf(publicKey) }
}

/**
 * The key an address names, or null. Strict: one spelling per key (the decoded bytes must
 * re-encode to the same text), 32 bytes, a point on Baby Jubjub in the prime-order subgroup.
 */
export function publicKeyFromAddress(address: unknown): Point | null {
  if (typeof address !== 'string' || address.length < 32 || address.length > 44) return null
  try {
    return pointOf(address)
  } catch {
    return null
  }
}
