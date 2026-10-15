// A proof as 256 bytes, the form a profile record carries it in, and back.

import { BN254_P, fromBytes32, toBytes32 } from './field.ts'

/** snarkjs writes points as decimal strings in projective form; the trailing 1 is dropped. */
export type SnarkjsProof = {
  pi_a: [string, string, string]
  pi_b: [[string, string], [string, string], [string, string]]
  pi_c: [string, string, string]
}

/**
 * The proof as a profile record stores it (records/README.md, Proofs), a human proof or a
 * reputation proof: its three points whole, 256 bytes, eight 32-byte big-endian numbers in the order
 * Ethereum's and Solana's BN254 precompiles read, each G2 pair's imaginary part first.
 */
export function proofBytes(proof: SnarkjsProof): Uint8Array {
  const { pi_a, pi_b, pi_c } = proof
  if (BigInt(pi_a[2]) !== 1n || BigInt(pi_c[2]) !== 1n || BigInt(pi_b[2][0]) !== 1n || BigInt(pi_b[2][1]) !== 0n) {
    throw new Error('a proof is three points as snarkjs writes them, each with its last coordinate 1')
  }
  const order = [pi_a[0], pi_a[1], pi_b[0][1], pi_b[0][0], pi_b[1][1], pi_b[1][0], pi_c[0], pi_c[1]]
  const out = new Uint8Array(256)
  order.forEach((s, i) => out.set(toBytes32(coordinate(BigInt(s))), i * 32))
  return out
}

/** The proof as snarkjs writes it, from its 256 bytes. */
export function proofFromBytes(bytes: Uint8Array): SnarkjsProof {
  if (bytes.length !== 256) throw new RangeError('a proof is 256 bytes')
  const n = Array.from({ length: 8 }, (_, i) => coordinate(fromBytes32(bytes.subarray(i * 32, i * 32 + 32))).toString())
  return { pi_a: [n[0], n[1], '1'], pi_b: [[n[3], n[2]], [n[5], n[4]], ['1', '0']], pi_c: [n[6], n[7], '1'] }
}

// snarkjs reads a coordinate modulo the field, so one with the modulus added would be the same
// point in other bytes. The precompiles refuse it, and so does this.
function coordinate(value: bigint): bigint {
  if (value >= BN254_P) throw new RangeError('a coordinate is below the base field modulus')
  return value
}
