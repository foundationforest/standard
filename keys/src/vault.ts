// The vault key: the main key of the person's vault, a folder of its own on a host that holds what
// a new device needs and the seed alone cannot give back (records/README.md, The vault). It is
// mixed from the seed, so a new device finds the vault with the seed and one host's address: its
// address is the folder's name. It signs as a profile's main key does, on Baby Jubjub. Its inbox key, mixed
// from the vault's secret as a profile's is from its own (inboxKey), opens what the vault holds.
// Its Poseidon mix has its own prefix and no label, so no profile's key is ever the vault's.

import { poseidon2 } from 'poseidon-lite/poseidon2'
import { addressOf, keyScalar, publicKeyOf } from './curve.ts'
import { PREFIX, isFieldElement } from './field.ts'
import { INFO, SEED_LENGTH, assertBytes, hkdf } from './hkdf.ts'
import type { MainKey } from './profile.ts'
import { seedScalar } from './scalar.ts'

/** The vault's key: a main key with no label. Held in memory only. */
export type VaultKey = Omit<MainKey, 'label' | 'scope'>

/** The vault's scalar: the lowest 250 bits of `Poseidon(vault prefix, seed scalar)`. */
export function vaultScalarOf(seed: bigint): bigint {
  if (!isFieldElement(seed)) throw new RangeError('a seed scalar is a field element')
  return keyScalar(poseidon2([PREFIX.vault, seed]))
}

/** The vault key, from the seed: the same every time, and unrelated to every profile's main key. */
export async function vaultKey(seed: Uint8Array): Promise<VaultKey> {
  assertBytes('seed', seed, SEED_LENGTH)
  const scalar = vaultScalarOf(await seedScalar(seed))
  const publicKey = publicKeyOf(scalar)
  return { scalar, publicKey, address: addressOf(publicKey), secret: await hkdf(seed, INFO.vault) }
}
