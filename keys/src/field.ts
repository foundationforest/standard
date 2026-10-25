// Text as a number a circuit takes: keccak256 of the bytes, shifted right one byte so it is below
// BN254's scalar order. A label becomes its scope this way, a verifier's name its name hash, and
// each fixed prefix that keeps one Poseidon mix apart from another its value.

import { keccak_256 } from '@noble/hashes/sha3.js'
import { assertText, utf8 } from './hkdf.ts'

/** BN254's scalar field order. Every number a circuit takes is below it. */
export const BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/** What a label is hashed after. Fixed: a change gives every profile a new key and tag. */
export const SCOPE_NS = 'forest/v1/label/'
/**
 * What a verifier's name is hashed after. The text keeps its bytes, the old word issuer among them:
 * every name hash, and so every tag, is made with it.
 */
export const VERIFIER_NS = 'forest/v1/issuer/'

/**
 * `keccak256(namespace || parts...) >> 8`. A namespaced string lets a label or a name be any
 * text, and keeps one namespace's values from ever colliding with another's.
 */
export function fieldHash(namespace: string, ...parts: (string | Uint8Array)[]): bigint {
  const bytes = [namespace, ...parts].map((p) => (typeof p === 'string' ? utf8(p) : p))
  const input = new Uint8Array(bytes.reduce((n, b) => n + b.length, 0))
  let at = 0
  for (const b of bytes) {
    input.set(b, at)
    at += b.length
  }
  let value = 0n
  for (const b of keccak_256(input)) value = (value << 8n) | BigInt(b)
  return value >> 8n
}

/**
 * The prefixes that start each Poseidon mix of the seed scalar, so no mix gives another's number.
 * The verifier's keeps its text's bytes, the old word issuer among them, as the circuits do.
 */
export const PREFIX = {
  verifier: fieldHash('forest/v1/issuer'),
  profile: fieldHash('forest/v1/profile'),
} as const

/** A label as a number: `keccak256("forest/v1/label/" || label) >> 8`. */
export function scopeOf(label: string): bigint {
  assertText('label', label)
  return fieldHash(SCOPE_NS, label)
}

/** A verifier's name as a number: `keccak256("forest/v1/issuer/" || name) >> 8`. */
export function nameHashOf(name: string): bigint {
  assertText('verifier name', name)
  return fieldHash(VERIFIER_NS, name)
}

export function isFieldElement(value: unknown): value is bigint {
  return typeof value === 'bigint' && value >= 0n && value < BN254_R
}
