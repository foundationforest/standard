// A service key: the signing key of an index or a verifier. It is 32 bytes from no person's seed:
// random, or derived from the service's own secret, as our verifier's two keys are; its scalar is
// the lowest 250 bits of the bytes read big-endian, as a main key's is the lowest 250 bits of a
// number Poseidon derives. It signs as a main key does, and its address is spelled as one is. The
// signing key of an access key is made the same way (access.ts).

import { type Point, addressOf, keyScalar, publicKeyOf } from './curve.ts'
import { numberOf } from './field.ts'
import { assertBytes } from './hkdf.ts'

/** A service's signing key. Held by the service only. */
export type ServiceKey = {
  /** The 32 bytes: random, or derived from the service's own secret. */
  secret: Uint8Array
  /** The scalar that signs: the lowest 250 bits of the bytes. */
  scalar: bigint
  publicKey: Point
  /** Its address: what a reader checks the service's signatures against. */
  address: string
}

/** A service key, from its 32 bytes. */
export function serviceKey(secret: Uint8Array): ServiceKey {
  assertBytes('a service key', secret, 32)
  const scalar = keyScalar(numberOf(secret))
  const publicKey = publicKeyOf(scalar)
  return { secret, scalar, publicKey, address: addressOf(publicKey) }
}
