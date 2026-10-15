// A profile's payment key: an ed25519 keypair on Solana, one per label, mixed from the seed. It
// holds and moves the profile's money; the main key, on Baby Jubjub, is not a Solana account.

import { ed25519 } from '@noble/curves/ed25519.js'
import { base58 } from '@scure/base'
import { INFO, SEED_LENGTH, assertBytes, assertText, hkdf } from './hkdf.ts'

/** A profile's payment key. Held in memory only. */
export type PayKey = {
  label: string
  /** The 32-byte ed25519 private seed, the form Solana tooling accepts as a keypair seed. */
  privateKey: Uint8Array
  publicKey: Uint8Array
  /** The public key in base58: the profile's Solana address, its `pay`. */
  address: string
}

/** The payment key for `label`, from the seed: one HKDF output per label. */
export async function payKey(seed: Uint8Array, label: string): Promise<PayKey> {
  assertBytes('seed', seed, SEED_LENGTH)
  assertText('label', label)
  const privateKey = await hkdf(seed, INFO.pay(label))
  const publicKey = ed25519.getPublicKey(privateKey)
  return { label, privateKey, publicKey, address: base58.encode(publicKey) }
}
