// A service key: the signing key of an index or a verifier. It is 32 random bytes the service makes
// for itself, from no seed; its scalar is the lowest 250 bits of the bytes read big-endian, as a
// main key's is the lowest 250 bits of a Poseidon mix. It signs as a main key does, and its address
// is spelled as one is. The signing half of an access key is made the same way (access.ts).

import { type Point, addressOf, keyScalar, publicKeyOf } from './curve.ts'
import { numberOf } from './field.ts'
import { assertBytes } from './hkdf.ts'

/** A service's signing key. Held by the service only. */
export type ServiceKey = {
  /** The 32 random bytes. */
  secret: Uint8Array
  /** The scalar that signs: the lowest 250 bits of the bytes. */
  scalar: bigint
  publicKey: Point
  /** Its address: what a reader checks the service's signatures against. */
  address: string
}

/** A service key, from its 32 random bytes. */
export function serviceKey(secret: Uint8Array): ServiceKey {
  assertBytes('a service key', secret, 32)
  const scalar = keyScalar(numberOf(secret))
  const publicKey = publicKeyOf(scalar)
  return { secret, scalar, publicKey, address: addressOf(publicKey) }
}
