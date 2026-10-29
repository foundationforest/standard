// The proofs a profile entry carries (README.md, Proofs), as their proof checks take them. Folders
// checks no proof itself: a verification's check is proofs/'s checkVerification, a reputation
// proof's its checkReputation. These turn a profile entry's proof into what each one takes, for the
// profile that carries it, or null when the proof is not that shape. A reader calls the proof check
// itself.

import { b64u } from './bytes.ts'
import { publicKeyFromAddress } from './keys.ts'
import type { Body } from './entry.ts'

/** What checkVerification takes, for one verification on a profile entry. */
export type VerificationCheck = {
  proof: Uint8Array
  /** The verifier's key: its address. */
  verifier: string
  verifierName: string
  label: string
  /** The profile that carries the proof: its address. */
  profile: string
}

/** What checkReputation takes, for one reputation proof on a profile entry. */
export type ReputationCheck = {
  proof: Uint8Array
  root: bigint
  score: bigint
  /** The profile that carries the proof: its address. */
  profile: string
  /** The index's key: its address. */
  index: string
  time: number
  signature: Uint8Array
}

const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)
const HEX64 = /^[0-9a-f]{64}$/
const PROOF = /^[A-Za-z0-9_-]{342}$/
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/

/** The proofs a profile entry's body carries, those that are objects with a circuit. */
export function proofsOf(body: Body | null | undefined): Array<{ [key: string]: unknown; circuit: string }> {
  const proofs = body?.proofs
  if (!Array.isArray(proofs)) return []
  return (proofs as unknown[]).filter((p): p is { [key: string]: unknown; circuit: string } => isObject(p) && typeof p.circuit === 'string')
}

/** A verification on a profile entry as checkVerification takes it, for the profile `profile`; null if it is not one. */
export function verificationCheck(proof: unknown, profile: string): VerificationCheck | null {
  if (!isObject(proof) || proof.circuit !== 'verification') return null
  const { verifier, verifierName, label } = proof
  if (!publicKeyFromAddress(verifier) || typeof verifierName !== 'string' || typeof label !== 'string') return null
  if (typeof proof.proof !== 'string' || !PROOF.test(proof.proof)) return null
  return {
    proof: b64u.decode(proof.proof),
    verifier: verifier as string,
    verifierName,
    label,
    profile,
  }
}

/** A reputation proof on a profile entry as checkReputation takes it, for the profile `profile`; null if it is not one. */
export function reputationCheck(proof: unknown, profile: string): ReputationCheck | null {
  if (!isObject(proof) || proof.circuit !== 'reputation') return null
  const { root, score, index, time, signature } = proof
  if (typeof root !== 'string' || !HEX64.test(root) || !Number.isSafeInteger(score) || !Number.isSafeInteger(time)) return null
  if (typeof index !== 'string' || typeof signature !== 'string' || !SIGNATURE.test(signature) || typeof proof.proof !== 'string' || !PROOF.test(proof.proof)) return null
  return {
    proof: b64u.decode(proof.proof),
    root: BigInt('0x' + root),
    score: BigInt(score as number),
    profile,
    index,
    time: time as number,
    signature: b64u.decode(signature),
  }
}
