// A profile's pay keys: one keypair for each address type, per label, mixed from the seed. Each
// holds and moves the profile's money on chains of its type; the main key, on Baby Jubjub, is no
// chain's account.
//
// - solana: an ed25519 keypair; its address is the public key in base58.
// - evm: the 32 bytes, read big-endian, are a secp256k1 private key; its address is the last 20
//   bytes of keccak256 of the uncompressed public key without its 04, written in EIP-55's
//   mixed-case checksum, the one spelling this standard takes.

import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { base58, hex } from '@scure/base'
import { INFO, SEED_LENGTH, assertBytes, assertText, hkdf } from './hkdf.ts'

/** The address types a profile has a pay key for. */
export const PAY_TYPES = ['solana', 'evm'] as const
export type PayType = (typeof PAY_TYPES)[number]

/** A profile's pay key for one address type. Held in memory only. */
export type PayKey = {
  label: string
  type: PayType
  /**
   * The 32-byte private key: for solana the ed25519 private seed, the form Solana tooling accepts
   * as a keypair seed; for evm the secp256k1 private key, big-endian.
   */
  privateKey: Uint8Array
  /** For solana the 32-byte ed25519 public key; for evm the 65-byte uncompressed secp256k1 one. */
  publicKey: Uint8Array
  /** The profile's address of this type: base58 for solana, EIP-55 for evm. */
  address: string
}

/** A profile's pay addresses, one per address type: its profile record's `pay`. */
export type PayAddresses = { [type in PayType]: string }

/**
 * The pay key for `label` and `type`, from the seed: one HKDF output per type and label. An evm
 * key's bytes are used as they are: in the 2^-128 chance they are no secp256k1 key, it throws,
 * and nothing adjusts them.
 */
export async function payKey(seed: Uint8Array, label: string, type: PayType): Promise<PayKey> {
  assertBytes('seed', seed, SEED_LENGTH)
  assertText('label', label)
  if (!PAY_TYPES.includes(type)) throw new Error(`a pay type is one of ${PAY_TYPES.join(', ')}`)
  const privateKey = await hkdf(seed, INFO.pay(type, label))
  if (type === 'solana') {
    const publicKey = ed25519.getPublicKey(privateKey)
    return { label, type, privateKey, publicKey, address: base58.encode(publicKey) }
  }
  if (!secp256k1.utils.isValidSecretKey(privateKey)) throw new Error('these bytes are no secp256k1 key')
  const publicKey = secp256k1.getPublicKey(privateKey, false)
  return { label, type, privateKey, publicKey, address: evmAddressOf(publicKey) }
}

/** The profile's pay address of each type, for `label`: what its profile record's `pay` holds. */
export async function payAddresses(seed: Uint8Array, label: string): Promise<PayAddresses> {
  const [solana, evm] = await Promise.all(PAY_TYPES.map(async (type) => (await payKey(seed, label, type)).address))
  return { solana: solana!, evm: evm! }
}

/** The EVM address of a secp256k1 public key, in any form a point takes: in EIP-55. */
export function evmAddressOf(publicKey: Uint8Array): string {
  const uncompressed = secp256k1.Point.fromBytes(publicKey).toBytes(false)
  return checksum(hex.encode(keccak_256(uncompressed.subarray(1)).subarray(12)))
}

/** Whether text is an EVM address in its one written form, EIP-55's mixed-case checksum. Any other spelling, all lower case included, is not. */
export function isEvmAddress(text: unknown): text is string {
  return typeof text === 'string' && /^0x[0-9a-fA-F]{40}$/.test(text) && checksum(text.slice(2).toLowerCase()) === text
}

/** EIP-55: a hex letter is upper case where the same place in keccak256 of the lower-case hex is 8 or more. */
function checksum(lower: string): string {
  const hash = hex.encode(keccak_256(new TextEncoder().encode(lower)))
  let out = '0x'
  for (let i = 0; i < lower.length; i++) out += parseInt(hash[i]!, 16) >= 8 ? lower[i]!.toUpperCase() : lower[i]!
  return out
}
