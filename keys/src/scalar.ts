// The seed scalar: the one number the circuits take from the seed. Every number that ties a
// person's notes and profiles together inside a proof is a Poseidon mix of it, under a prefix, so a
// proof can show two of them come from one seed without showing it, and nothing public links them.
//
// The 32 mixed bytes become a scalar the way Semaphore v4 made its secret scalar, with zk-kit's
// own `deriveSecretScalar`, unchanged.

import { deriveSecretScalar } from '@zk-kit/eddsa-poseidon'
import { INFO, SEED_LENGTH, assertBytes, hkdf } from './hkdf.ts'

/** The seed scalar: `deriveSecretScalar(hkdf(seed, "forest/v1/seed"))`, below Baby Jubjub's subgroup order. */
export async function seedScalar(seed: Uint8Array): Promise<bigint> {
  assertBytes('seed', seed, SEED_LENGTH)
  return deriveSecretScalar(await hkdf(seed, INFO.seed))
}
