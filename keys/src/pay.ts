// A profile's pay keys: one keypair for each address type, per label, mixed from the seed. Each
// holds and moves the profile's money on chains of its type; the main key, on Baby Jubjub, is no
// chain's account.
//
// - solana: an ed25519 keypair; its address is the public key in base58.
// - evm: the 32 bytes, read big-endian, are a secp256k1 private key; its address is the last 20
//   bytes of keccak256 of the uncompressed public key without its 04, written in EIP-55's
//   mixed-case checksum, the one spelling this standard takes.
//
// Each pay key signs its profile's address, so a profile record lists only addresses that are its
// own: `0xff || "forest/v1/pay\n" || address`, in UTF-8. 0xff begins no Solana transaction and no
// EVM one, so the signature can never pass as either.

import { ed25519 } from '@noble/curves/ed25519.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { base58, base64urlnopad, hex } from '@scure/base'
import { INFO, SEED_LENGTH, assertBytes, assertText, hkdf, utf8 } from './hkdf.ts'

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

/** The bytes a pay key signs for a profile: `0xff || "forest/v1/pay\n" || address`, in UTF-8. */
function payBytes(profileAddress: string): Uint8Array {
  assertText('profile address', profileAddress)
  const text = utf8(`forest/v1/pay\n${profileAddress}`)
  const out = new Uint8Array(1 + text.length)
  out[0] = 0xff
  out.set(text, 1)
  return out
}

/**
 * A pay key's signature over the address of the profile it pays, for that profile record's
 * `paySig`, in base64url without padding. solana: an Ed25519 signature (RFC 8032), 64 bytes. evm: a
 * secp256k1 signature over keccak256 of the bytes, 65 bytes, r || s || the recovery id. Both are
 * deterministic: the same key and address always give the same signature.
 */
export function signPay(key: PayKey, profileAddress: string): string {
  const bytes = payBytes(profileAddress)
  if (key.type === 'solana') return base64urlnopad.encode(ed25519.sign(bytes, key.privateKey))
  // noble writes the recovery id first; the standard writes it last, as Ethereum does.
  const signed = secp256k1.sign(keccak_256(bytes), key.privateKey, { prehash: false, format: 'recovered' })
  const out = new Uint8Array(65)
  out.set(signed.subarray(1), 0)
  out[64] = signed[0]!
  return base64urlnopad.encode(out)
}

/**
 * Whether `sig` is the pay key at `payAddress` signing `profileAddress`. solana: the Ed25519
 * signature holds for the key the address spells, checked strictly (RFC 8032, no ZIP-215
 * leniency). evm: the key recovered from r, s and the recovery id has this EIP-55 address. A high
 * s is not refused: the record around the signature is signed by the profile's main key, so no one
 * else can put its twin spelling there.
 */
export function checkPaySig(type: PayType, payAddress: string, profileAddress: string, sig: string): boolean {
  try {
    const bytes = payBytes(profileAddress)
    const signature = base64urlnopad.decode(sig)
    if (type === 'solana') {
      const publicKey = base58.decode(payAddress)
      if (signature.length !== 64 || publicKey.length !== 32 || base58.encode(publicKey) !== payAddress) return false
      return ed25519.verify(signature, bytes, publicKey, { zip215: false })
    }
    if (type !== 'evm' || signature.length !== 65 || !isEvmAddress(payAddress)) return false
    const recovered = new Uint8Array(65)
    recovered[0] = signature[64]!
    recovered.set(signature.subarray(0, 64), 1)
    return evmAddressOf(secp256k1.recoverPublicKey(recovered, keccak_256(bytes), { prehash: false })) === payAddress
  } catch {
    return false
  }
}

/** EIP-55: a hex letter is upper case where the same place in keccak256 of the lower-case hex is 8 or more. */
function checksum(lower: string): string {
  const hash = hex.encode(keccak_256(new TextEncoder().encode(lower)))
  let out = '0x'
  for (let i = 0; i < lower.length; i++) out += parseInt(hash[i]!, 16) >= 8 ? lower[i]!.toUpperCase() : lower[i]!
  return out
}
