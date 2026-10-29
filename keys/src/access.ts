// An access key: two random secrets, 64 bytes, from no seed, since it is made to be handed out. The
// first 32 sign, made into a scalar as a service key's are; the last 32 open, as every opening half
// does. Nothing is derived from the one for the other. See README.md, "Access keys".

import { assertBytes } from './hkdf.ts'
import { type OpeningHalf, openingHalf } from './opening.ts'
import { type ServiceKey, serviceKey } from './service.ts'

/** An access key with both halves: its 64 bytes, the signing half's scalar, key and address, and the opening half. */
export type AccessKey = Omit<ServiceKey, 'secret'> & OpeningHalf & { secret: Uint8Array }

/** An access key from its 64 bytes, as whoever it was handed to holds it. */
export async function accessKey(secret: Uint8Array): Promise<AccessKey> {
  assertBytes('an access key', secret, 64)
  const { scalar, publicKey, address } = serviceKey(secret.subarray(0, 32))
  return { secret, scalar, publicKey, address, ...(await openingHalf(secret.subarray(32))) }
}

/** A new access key: 64 fresh random bytes, from no seed. */
export async function newAccessKey(): Promise<AccessKey> {
  return accessKey(crypto.getRandomValues(new Uint8Array(64)))
}
