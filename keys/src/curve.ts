// Keys on Baby Jubjub: a profile's or the vault's public key, its address, and EdDSA-Poseidon
// signatures made from the scalar itself. The circuits check the same curve and the same
// signature equation, circomlib's, so what signs a record is what a proof can derive.
//
// A key's scalar is below 2^250. Baby Jubjub's subgroup order l is above 2^250, so every such
// number is already a scalar, with no reduction, and a circuit takes its 250 bits as they are.

import { sha512 } from '@noble/hashes/sha2.js'
import { base58 } from '@scure/base'
import { Base8, mulPointEscalar, packPoint, subOrder, unpackPoint } from '@zk-kit/baby-jubjub'
import { verifySignature } from '@zk-kit/eddsa-poseidon'
import { poseidon5 } from 'poseidon-lite/poseidon5'
import { BN254_R, isFieldElement } from './field.ts'
import { utf8 } from './hkdf.ts'

/** A point on Baby Jubjub, x then y. */
export type Point = [bigint, bigint]

/** An EdDSA-Poseidon signature on Baby Jubjub, as zk-kit and circomlib take it. */
export type Signature = { R8: Point; S: bigint }

/** Every key's scalar is below 2^250. */
export const SCALAR_BITS = 250
const MASK = (1n << 250n) - 1n

/** What a signature's secret nonce is mixed under. */
const NONCE = 'forest/v1/nonce'

/** A key's scalar from a Poseidon output: its lowest 250 bits. */
export function keyScalar(raw: bigint): bigint {
  return raw & MASK
}

/** The public key of a scalar: `scalar · Base8`. */
export function publicKeyOf(scalar: bigint): Point {
  assertScalar(scalar)
  return mulPointEscalar(Base8, scalar) as Point
}

/** A public key's address: its 32 packed bytes (y little-endian, x's sign in the top bit), in base58. */
export function addressOf(publicKey: Point): string {
  if (!inSubgroup(publicKey)) throw new Error('not a key: a point of the prime-order subgroup')
  return base58.encode(le32(packPoint(publicKey)))
}

/** The public key an address names. Throws for anything that is not one key's only spelling. */
export function pointOf(address: string): Point {
  if (typeof address !== 'string') throw new Error('an address is text')
  let bytes: Uint8Array
  try {
    bytes = base58.decode(address)
  } catch {
    throw new Error('an address is base58')
  }
  if (bytes.length !== 32 || base58.encode(bytes) !== address) throw new Error('an address is 32 bytes in base58')
  const point = unpackPoint(fromLe(bytes)) as Point | null
  if (point === null || !inSubgroup(point)) throw new Error('an address names a point of the prime-order subgroup')
  if (base58.encode(le32(packPoint(point))) !== address) throw new Error('an address in more than one spelling')
  return point
}

/**
 * Sign a field element with a key's scalar. The nonce is SHA-512 of a fixed text, the scalar and
 * the message, so the same message always gets the same signature and no two messages share a
 * nonce. `S = r + 8·hm·scalar mod l`, so `S·Base8 = R8 + 8·hm·A`, the equation zk-kit and
 * circomlib check.
 */
export function signWithScalar(scalar: bigint, message: bigint): Signature {
  assertScalar(scalar)
  if (!isFieldElement(message)) throw new RangeError('a message is a field element')
  const A = publicKeyOf(scalar)
  const r = fromLe(sha512(concat(utf8(NONCE), le32(scalar), le32(message)))) % subOrder
  const R8 = mulPointEscalar(Base8, r) as Point
  const hm = poseidon5([R8[0], R8[1], A[0], A[1], message])
  return { R8, S: (r + ((8n * hm) % subOrder) * scalar) % subOrder }
}

/** Does this signature hold for this message, under this key or the key this address names? */
export function verifyWithPublicKey(publicKey: Point | string, message: bigint, signature: Signature): boolean {
  try {
    const point = typeof publicKey === 'string' ? pointOf(publicKey) : publicKey
    if (!inSubgroup(point) || !isFieldElement(message)) return false
    return verifySignature(message, signature, point)
  } catch {
    return false
  }
}

function assertScalar(scalar: bigint): void {
  if (typeof scalar !== 'bigint' || scalar <= 0n || scalar >= subOrder) throw new RangeError('a scalar is from 1 to l - 1')
}

function inSubgroup(point: Point): boolean {
  if (!Array.isArray(point) || point.length !== 2 || !point.every(isFieldElement)) return false
  // On the curve, a·x² + y² = 1 + d·x²·y² over BN254's scalar field; then l·P is the identity.
  const [a, d, p] = [168700n, 168696n, BN254_R]
  const [x, y] = point
  const x2 = (x * x) % p
  const y2 = (y * y) % p
  if ((a * x2 + y2) % p !== (1n + ((d * x2) % p) * y2) % p) return false
  const zero = mulPointEscalar(point, subOrder)
  return zero[0] === 0n && zero[1] === 1n && !(x === 0n && y === 1n)
}

function le32(value: bigint): Uint8Array {
  const out = new Uint8Array(32)
  let v = value
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

function fromLe(bytes: Uint8Array): bigint {
  return bytes.reduceRight((v, b) => (v << 8n) | BigInt(b), 0n)
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}
