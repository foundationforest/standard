// Numbers a circuit takes: each below BN254's scalar order. The seed goes in as its own number. Text
// goes in as keccak256 of its bytes, shifted right one byte: a label becomes its scope this way, and
// a verifier's name its name hash, each from its text (hkdf.ts, TEXT).

import { keccak_256 } from '@noble/hashes/sha3.js'
import { SEED_LENGTH, TEXT, assertBytes, assertText, utf8 } from './hkdf.ts'

/** BN254's scalar field order. Every number a circuit takes is below it. */
export const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/** Bytes read as one big-endian number. */
export function numberOf(bytes: Uint8Array): bigint {
  let value = 0n
  for (const b of bytes) value = (value << 8n) | BigInt(b)
  return value
}

/**
 * The seed's number: its 32 bytes read big-endian, reduced mod BN254's order. Every Poseidon mix of
 * the seed, and both proofs, take it.
 */
export function seedNumber(seed: Uint8Array): bigint {
  assertBytes('seed', seed, SEED_LENGTH)
  return numberOf(seed) % BN254_R
}

/**
 * `keccak256(text || parts...) >> 8`, the parts joined to the text with nothing between, text as
 * UTF-8 and bytes as they are.
 */
export function fieldHash(text: string, ...parts: (string | Uint8Array)[]): bigint {
  const bytes = [text, ...parts].map((p) => (typeof p === 'string' ? utf8(p) : p))
  const input = new Uint8Array(bytes.reduce((n, b) => n + b.length, 0))
  let at = 0
  for (const b of bytes) {
    input.set(b, at)
    at += b.length
  }
  return numberOf(keccak_256(input)) >> 8n
}

/** A label as a number, its scope: `keccak256("forest/profile/" || label) >> 8`. */
export function scopeOf(label: string): bigint {
  assertText('label', label)
  return fieldHash(TEXT.profile(label))
}

/** A verifier's name as a number, its name hash: `keccak256("forest/verifier/" || name) >> 8`. */
export function nameHashOf(name: string): bigint {
  assertText('verifier name', name)
  return fieldHash(TEXT.verifier(name))
}

export function isFieldElement(value: unknown): value is bigint {
  return typeof value === 'bigint' && value >= 0n && value < BN254_R
}
