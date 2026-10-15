// Access keys: what a person hands an app, a server or an AI, never a main key. Each is 32 random
// bytes the owner's app makes, not from the seed. Their signing key is the one zk-kit's EdDSA-Poseidon
// makes of 32 private bytes (`deriveSecretScalar`), as an issuer's is. A read key's bytes also give
// an age post-quantum hybrid identity, mixed as an inbox key is (inboxKey), which no public number
// gives: its address names its signing key, which a quantum computer could break, never its
// identity.

import { deriveSecretScalar } from '@zk-kit/eddsa-poseidon'
import { type Point, addressOf, publicKeyOf } from './curve.ts'
import { assertBytes } from './hkdf.ts'
import { inboxKey } from './profile.ts'

/** A key that signs: a write key, or a read key's signing half. Held in memory only. */
export type AccessKey = {
  /** The 32 random bytes. */
  secret: Uint8Array
  /** The scalar that signs. */
  scalar: bigint
  publicKey: Point
  /** Its address, as the permissions record lists it. */
  address: string
}

/** A read key: a signing key that pulls an inbox, and an age identity that opens what is encrypted to it. */
export type ReadKey = AccessKey & {
  /** age's hybrid identity, `AGE-SECRET-KEY-PQ-1…`. */
  identity: string
  /** What the owner's devices encrypt to, `age1pq1…`, as the permissions record lists it. */
  recipient: string
}

/** A write key, or any signing access key, from its 32 random bytes. */
export function accessKey(secret: Uint8Array): AccessKey {
  assertBytes('an access key', secret, 32)
  const scalar = deriveSecretScalar(secret)
  const publicKey = publicKeyOf(scalar)
  return { secret, scalar, publicKey, address: addressOf(publicKey) }
}

/** A read key, from its 32 random bytes: its signing key, and its age identity and recipient. */
export async function readKey(secret: Uint8Array): Promise<ReadKey> {
  const key = accessKey(secret)
  return { ...key, ...(await inboxKey(secret)) }
}
