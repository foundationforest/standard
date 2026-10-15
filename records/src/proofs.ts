// The proofs a card carries (README.md, Proofs), as their verifiers take them. Records checks no
// proof itself: a human proof's verifier is proofs/human/client's verifyHuman, a reputation proof's
// proofs/reputation/client's verifyReputation. These turn a card's proof into what each one takes,
// for the profile that carries it, or null when the proof is not that shape. A host that keeps
// inboxes with an issuer's rule is given verifyHuman (HostOptions); a reader calls them itself.

import { b64u, hex } from './bytes.ts'
import type { Body } from './record.ts'

/** What verifyHuman takes, for one card's human proof. */
export type HumanCheck = {
  proof: Uint8Array
  issuer: [bigint, bigint]
  issuerName: string
  label: string
  /** The profile that carries the proof: its address. */
  profile: string
  stamp: Uint8Array
}

/** What verifyReputation takes, for one card's reputation proof. */
export type ReputationCheck = {
  proof: Uint8Array
  root: bigint
  score: bigint
  /** The profile that carries the proof: its address. */
  profile: string
  label?: string
  /** The index's key: its address. */
  index: string
  time: number
  signature: Uint8Array
}

const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)
const HEX64 = /^[0-9a-f]{64}$/
const ISSUER = /^[0-9a-f]{128}$/
const PROOF = /^[A-Za-z0-9_-]{342}$/
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/

/** The proofs a card's body carries, those that are objects with a circuit. */
export function proofsOf(card: Body | null | undefined): Array<{ [key: string]: unknown; circuit: string }> {
  const proofs = card?.proofs
  if (!Array.isArray(proofs)) return []
  return (proofs as unknown[]).filter((p): p is { [key: string]: unknown; circuit: string } => isObject(p) && typeof p.circuit === 'string')
}

/** A card's human proof as verifyHuman takes it, for the profile `profile`; null if it is not one. */
export function humanCheck(proof: unknown, profile: string): HumanCheck | null {
  if (!isObject(proof) || proof.circuit !== 'human') return null
  const { issuer, issuerName, label, stamp } = proof
  if (typeof issuer !== 'string' || !ISSUER.test(issuer) || typeof issuerName !== 'string' || typeof label !== 'string') return null
  if (typeof stamp !== 'string' || !HEX64.test(stamp) || typeof proof.proof !== 'string' || !PROOF.test(proof.proof)) return null
  return {
    proof: b64u.decode(proof.proof),
    issuer: [BigInt('0x' + issuer.slice(0, 64)), BigInt('0x' + issuer.slice(64))],
    issuerName,
    label,
    profile,
    stamp: hex.decode(stamp),
  }
}

/** A card's reputation proof as verifyReputation takes it, for the profile `profile`; null if it is not one. */
export function reputationCheck(proof: unknown, profile: string): ReputationCheck | null {
  if (!isObject(proof) || proof.circuit !== 'reputation') return null
  const { root, score, label, index, time, signature } = proof
  if (typeof root !== 'string' || !HEX64.test(root) || !Number.isSafeInteger(score) || !Number.isSafeInteger(time)) return null
  if (typeof index !== 'string' || typeof signature !== 'string' || !SIGNATURE.test(signature) || typeof proof.proof !== 'string' || !PROOF.test(proof.proof)) return null
  if ('label' in proof && typeof label !== 'string') return null
  return {
    proof: b64u.decode(proof.proof),
    root: BigInt('0x' + root),
    score: BigInt(score as number),
    profile,
    ...(typeof label === 'string' && { label }),
    index,
    time: time as number,
    signature: b64u.decode(signature),
  }
}
