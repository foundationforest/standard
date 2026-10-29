// Field elements as 32 big-endian bytes, and the numbers the proofs take, which are keys/'s: the
// seed's number, a label's scope, a verifier's name hash and the stamp number come from the same
// recipe that mixes the keys.

export { BN254_R, fieldHash, isFieldElement, nameHashOf, scopeOf, seedNumber, stampNumberOf } from '@foundationforest/keys'

/** BN254's base field modulus: every coordinate of a proof's points is below it. */
export const BN254_P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n

export function toBytes32(value: bigint): Uint8Array {
  if (value < 0n || value >= 1n << 256n) throw new RangeError('not a 256-bit value')
  const out = new Uint8Array(32)
  let v = value
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn)
    v >>= 8n
  }
  return out
}

export function fromBytes32(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) throw new RangeError('expected 32 bytes')
  let v = 0n
  for (const b of bytes) v = (v << 8n) | BigInt(b)
  return v
}
