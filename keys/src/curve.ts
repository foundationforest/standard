// Keys on Baby Jubjub: a profile's or the vault's public key, its address, and EdDSA-Poseidon
// signatures made from the scalar itself. The circuits check the same curve and the same
// signature equation, circomlib's, so what signs a record is what a proof can derive.
//
// A key's scalar is below 2^250. Baby Jubjub's subgroup order l is above 2^250, so every such
// number is already a scalar, with no reduction, and a circuit takes its 250 bits as they are.
//
// The arithmetic is @noble/curves' twisted Edwards curves, given circomlib's parameters: a = 168700,
// d = 168696, over BN254's scalar field, with Base8 as the generator of the prime-order subgroup.
// Points are packed as circomlib and zk-kit pack them, by hand: y in 32 little-endian bytes, the
// top bit set when x is above (p - 1) / 2.

import { edwards } from '@noble/curves/abstract/edwards.js'
import { sha256, sha512 } from '@noble/hashes/sha2.js'
import { base58 } from '@scure/base'
import { poseidon5 } from 'poseidon-lite/poseidon5'
import { BN254_R, isFieldElement } from './field.ts'
import { utf8 } from './hkdf.ts'

/** A point on Baby Jubjub, x then y. */
export type Point = [bigint, bigint]

/** An EdDSA-Poseidon signature on Baby Jubjub, as zk-kit and circomlib take it. */
export type Signature = { R8: Point; S: bigint }

/** Baby Jubjub's prime subgroup order. */
export const SUBGROUP_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n
/** The generator of the prime-order subgroup, as circomlib's templates have it. */
export const BASE8: Point = [
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
]
const A = 168700n
const D = 168696n
const P = BN254_R
const L = SUBGROUP_ORDER

const Curve = edwards({ p: P, n: L, h: 8n, a: A, d: D, Gx: BASE8[0], Gy: BASE8[1] })
type CurvePoint = InstanceType<typeof Curve>
const Fp = Curve.Fp

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
  return affine(Curve.BASE.multiply(scalar))
}

/** A public key's address: its 32 packed bytes (y little-endian, x's sign in the top bit), in base58. */
export function addressOf(publicKey: Point): string {
  if (!subgroupPoint(publicKey)) throw new Error('not a key: a point of the prime-order subgroup')
  return base58.encode(packPoint(publicKey))
}

/** Addresses already decoded and checked: an address names one key, ever, so the answer keeps. */
const decoded = new Map<string, Point>()
const DECODED_MAX = 4096

/** The public key an address names. Throws for anything that is not one key's only spelling. */
export function pointOf(address: string): Point {
  if (typeof address !== 'string') throw new Error('an address is text')
  const known = decoded.get(address)
  if (known) return [known[0], known[1]]
  let bytes: Uint8Array
  try {
    bytes = base58.decode(address)
  } catch {
    throw new Error('an address is base58')
  }
  if (bytes.length !== 32 || base58.encode(bytes) !== address) throw new Error('an address is 32 bytes in base58')
  const point = unpackPoint(bytes)
  if (point === null || !subgroupPoint(point)) throw new Error('an address names a point of the prime-order subgroup')
  if (decoded.size >= DECODED_MAX) decoded.delete(decoded.keys().next().value!)
  decoded.set(address, point)
  return [point[0], point[1]]
}

/** A point packed into 32 bytes: y little-endian, the top bit set when x is above (p - 1) / 2. */
export function packPoint(point: Point): Uint8Array {
  const out = le32(point[1])
  if (point[0] > (P - 1n) / 2n) out[31]! |= 0x80
  return out
}

/** The point 32 packed bytes name, or null: on the curve, in its one spelling. Its subgroup is not checked here. */
export function unpackPoint(bytes: Uint8Array): Point | null {
  if (bytes.length !== 32) return null
  const raw = bytes.slice()
  const negative = (raw[31]! & 0x80) !== 0
  raw[31]! &= 0x7f
  const y = fromLe(raw)
  if (y >= P) return null
  // a·x² + y² = 1 + d·x²·y², so x² = (1 - y²) / (a - d·y²).
  const y2 = Fp.sqr(y)
  const below = Fp.sub(A, Fp.mul(D, y2))
  if (Fp.is0(below)) return null
  let x: bigint
  try {
    x = Fp.sqrt(Fp.div(Fp.sub(1n, y2), below))
  } catch {
    return null
  }
  if (x > (P - 1n) / 2n !== negative) x = Fp.neg(x)
  if (x > (P - 1n) / 2n !== negative) return null // x = 0 with the sign bit set: a second spelling
  return [x, y]
}

/** A signature in 64 bytes: R8 packed, then S, 32 bytes little-endian, as zk-kit packs it. */
export function packSignature(signature: Signature): Uint8Array {
  const out = new Uint8Array(64)
  out.set(packPoint(signature.R8), 0)
  out.set(le32(signature.S), 32)
  return out
}

/**
 * A signature from its 64 bytes, or null: R8 a point on the curve in its one spelling, and S below
 * l. That R8 is in the prime-order subgroup the check's equation itself demands.
 */
export function unpackSignature(bytes: Uint8Array): Signature | null {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 64) return null
  const R8 = unpackPoint(bytes.subarray(0, 32))
  const S = fromLe(bytes.subarray(32))
  if (R8 === null || S >= L) return null
  return { R8, S }
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
  const [ax, ay] = publicKeyOf(scalar)
  const r = fromLe(sha512(concat(utf8(NONCE), le32(scalar), le32(message)))) % L
  const R8 = affine(Curve.BASE.multiply(r))
  const hm = poseidon5([R8[0], R8[1], ax, ay, message])
  return { R8, S: (r + ((8n * hm) % L) * scalar) % L }
}

/**
 * Does this signature hold for this message, under this key or the key this address names? The
 * key must be a point of the prime-order subgroup, R8 a point on the curve, S below l, and
 * `S·Base8 = R8 + 8·hm·A`. Both sides but R8 are in the subgroup, so the equation holds only when
 * R8 is too.
 */
export function checkWithPublicKey(publicKey: Point | string, message: bigint, signature: Signature): boolean {
  try {
    if (!isFieldElement(message) || typeof signature !== 'object' || signature === null) return false
    const { R8, S } = signature
    if (typeof S !== 'bigint' || S < 0n || S >= L) return false
    const key = typeof publicKey === 'string' ? pointOf(publicKey) : publicKey
    const a = typeof publicKey === 'string' ? curvePoint(key) : subgroupPoint(key)
    const r = curvePoint(R8)
    if (!a || !r) return false
    const hm = poseidon5([R8[0], R8[1], key[0], key[1], message])
    return Curve.BASE.multiplyUnsafe(S).equals(r.add(a.multiplyUnsafe((8n * hm) % L)))
  } catch {
    return false
  }
}

/**
 * The number a signature over bytes signs: SHA-256 of the bytes, read big-endian, shifted right one
 * byte so it is a field element. Records, messages, pulls and an index's roots are signed this way,
 * each over its own signed bytes.
 */
export function bytesMessage(bytes: Uint8Array): bigint {
  return sha256(bytes).reduce((v, b) => (v << 8n) | BigInt(b), 0n) >> 8n
}

/** Sign bytes: `signWithScalar(scalar, bytesMessage(bytes))`. */
export function signBytes(scalar: bigint, bytes: Uint8Array): Signature {
  return signWithScalar(scalar, bytesMessage(bytes))
}

/** Does this signature hold for these bytes, under this key or the key this address names? */
export function checkBytes(publicKey: Point | string, bytes: Uint8Array, signature: Signature): boolean {
  return checkWithPublicKey(publicKey, bytesMessage(bytes), signature)
}

function assertScalar(scalar: bigint): void {
  if (typeof scalar !== 'bigint' || scalar <= 0n || scalar >= L) throw new RangeError('a scalar is from 1 to l - 1')
}

/** The point, if it is on the curve. */
function curvePoint(point: Point): CurvePoint | null {
  if (!Array.isArray(point) || point.length !== 2 || !point.every(isFieldElement)) return null
  try {
    const p = Curve.fromAffine({ x: point[0], y: point[1] })
    p.assertValidity()
    return p
  } catch {
    return null
  }
}

/** The point, if it is on the curve and in the prime-order subgroup, other than the identity. */
function subgroupPoint(point: Point): CurvePoint | null {
  const p = curvePoint(point)
  return p && !p.is0() && p.isTorsionFree() ? p : null
}

function affine(p: CurvePoint): Point {
  const { x, y } = p.toAffine()
  return [x, y]
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
