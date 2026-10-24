// A service key: the signing key of an index or a verifier, never a person's. It is 32 random bytes
// the service makes for itself, from no seed, and its signing key is the one zk-kit's
// EdDSA-Poseidon makes of 32 private bytes (`deriveSecretScalar`), as a verifier's stamp key is. It
// signs as a main key does, and its address is spelled as one is.

import { deriveSecretScalar } from '@zk-kit/eddsa-poseidon'
import { type Point, addressOf, publicKeyOf } from './curve.ts'
import { assertBytes } from './hkdf.ts'

/** A service's signing key. Held by the service only. */
export type ServiceKey = {
  /** The 32 random bytes. */
  secret: Uint8Array
  /** The scalar that signs. */
  scalar: bigint
  publicKey: Point
  /** Its address: what a reader checks the service's signatures against. */
  address: string
}

/** A service key, from its 32 random bytes. */
export function serviceKey(secret: Uint8Array): ServiceKey {
  assertBytes('a service key', secret, 32)
  const scalar = deriveSecretScalar(secret)
  const publicKey = publicKeyOf(scalar)
  return { secret, scalar, publicKey, address: addressOf(publicKey) }
}
