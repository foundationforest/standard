// Keys whose two halves both come from one 32-byte secret: the signing half made as a service key
// is (zk-kit's deriveSecretScalar), the opening half as every opening half is. The Profiles folder
// key's secret is mixed from the seed alone; an access key's is 32 random bytes, since it is made
// to be handed out. See README.md, "The Profiles folder key" and "Access keys".

import { INFO, SEED_LENGTH, assertBytes, hkdf } from './hkdf.ts'
import { type OpeningHalf, openingHalf } from './opening.ts'
import { type ServiceKey, serviceKey } from './service.ts'

/** A key with both halves: the signing half's scalar, key and address, and the opening half. */
export type KeyPair = ServiceKey & OpeningHalf

/** A key pair from its 32-byte secret. */
async function pairOf(secret: Uint8Array): Promise<KeyPair> {
  return { ...serviceKey(secret), ...(await openingHalf(secret)) }
}

/** The Profiles folder key: the person's folder that lists their profiles and stamps, from the seed alone. */
export async function profilesKey(seed: Uint8Array): Promise<KeyPair> {
  assertBytes('seed', seed, SEED_LENGTH)
  return pairOf(await hkdf(seed, INFO.profiles))
}

/** An access key from its 32 bytes, as whoever it was handed to holds it. */
export async function accessKey(secret: Uint8Array): Promise<KeyPair> {
  assertBytes('an access key', secret, 32)
  return pairOf(secret)
}

/** A new access key: 32 fresh random bytes, from no seed. */
export async function newAccessKey(): Promise<KeyPair> {
  return accessKey(crypto.getRandomValues(new Uint8Array(32)))
}
