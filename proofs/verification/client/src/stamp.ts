// The stamp (../README.md, The stamp and the verification).
//
// A verifier signs a stamp for each person: { stamp number, facts }. The stamp number is Poseidon
// of the person's secret for that verifier (`keys/`'s `verifierSecret`), so the verifier never
// learns the secret, nor the seed it comes from. The facts are one field element, whatever the
// verifier attests; the proof keeps them private. The verifier signs Poseidon(prefix, stamp number,
// facts) with its EdDSA key on Baby Jubjub over Poseidon: zk-kit's signMessage, unchanged, which
// circomlib's EdDSAPoseidonVerifier checks inside the circuit. The prefix is fixed, so nothing the
// verifier signs for another purpose can be turned into a stamp. Its key is an address, as every
// key in the standard is: its point packed into 32 bytes, in base58; keys/'s pointOf gives x and y
// back. The verification a profile shows, the proof that its seed holds a stamp, is
// verification.ts's.

import { derivePublicKey, signMessage, verifySignature } from '@zk-kit/eddsa-poseidon'
import { poseidon1 } from 'poseidon-lite/poseidon1'
import { poseidon3 } from 'poseidon-lite/poseidon3'

import { addressOf, pointOf, verifierScalarOf } from '@foundationforest/keys'
import { fieldHash, isFieldElement } from './field.ts'

/**
 * The text whose field value starts every stamp a verifier signs. The circuit has it as a constant,
 * `var STAMP_PREFIX`. It keeps its bytes, the old word note among them: it is part of every stamp
 * ever signed.
 */
export const STAMP_PREFIX_TEXT = 'forest/v1/note'
/** `keccak256("forest/v1/note") >> 8`: the first input of every signed stamp. */
export const STAMP_PREFIX = fieldHash(STAMP_PREFIX_TEXT)

/** A verifier's key: the address of its EdDSA public key on Baby Jubjub, the point packed into 32 bytes, in base58. */
export type VerifierKey = string

export type Stamp = {
  /** The person's stamp number for this verifier: `keys/`'s `verifierSecret(seed, name).stampNumber`. */
  stampNumber: bigint
  /** What the verifier attests, as one field element of its choosing. The proof keeps it private. */
  facts: bigint
}

/** A JSON value: what a verifier adds beside a stamp is one. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

/** An EdDSA signature on Baby Jubjub, as zk-kit writes it. */
export type StampSignature = { R8: [bigint, bigint]; S: bigint }

/**
 * A stamp, the key of the verifier that signed it, and the signature. The person keeps it. Any
 * other field is one the verifier added beside them, such as what `facts` was made from: the
 * stamp's functions pass it through unchanged, and nothing here reads it.
 */
export type SignedStamp = Stamp & { verifier: VerifierKey; signature: StampSignature; [field: string]: unknown }

/** The person's stamp number for one verifier, from the seed scalar: what the verifier signs in the stamp. */
export function stampNumberOf(seedScalar: bigint, verifierName: string): bigint {
  return poseidon1([verifierScalarOf(seedScalar, verifierName)])
}

/** What a verifier signs: Poseidon(prefix, stamp number, facts). */
export function stampHash(stamp: Stamp): bigint {
  if (!isFieldElement(stamp.stampNumber)) throw new RangeError('a stamp number is a field element')
  if (!isFieldElement(stamp.facts)) throw new RangeError('facts are a field element')
  return poseidon3([STAMP_PREFIX, stamp.stampNumber, stamp.facts])
}

/** The verifier's key, its address, from its 32-byte private key. */
export function verifierKeyOf(privateKey: Uint8Array): VerifierKey {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) throw new Error("a verifier's private key is 32 bytes")
  return addressOf(derivePublicKey(privateKey))
}

/** For a verifier: sign a stamp with its 32-byte private key. Fields it adds beside the stamp pass through. */
export function signStamp(privateKey: Uint8Array, stamp: Stamp & { [field: string]: unknown }): SignedStamp {
  const verifier = verifierKeyOf(privateKey)
  return { ...stamp, verifier, signature: signMessage(privateKey, stampHash(stamp)) }
}

/**
 * A signed stamp as JSON: the form a person's device keeps it in (README.md, The stamp and the
 * verification), and a verifier may hand it over in. Big numbers in decimal text, the verifier's key as its
 * address. Every key starts in lower case, so it fits inside an entry. Any other field is the
 * verifier's, as it wrote it.
 */
export type StampJson = {
  stampNumber: string
  facts: string
  verifier: string
  signature: { r8: [string, string]; s: string }
  [field: string]: Json
}

const field = (n: bigint, what: string): bigint => {
  if (!isFieldElement(n)) throw new Error(`${what} is below BN254's scalar order`)
  return n
}
const decimal = (text: unknown, what: string): bigint => {
  if (typeof text !== 'string' || !/^(0|[1-9][0-9]{0,76})$/.test(text)) throw new Error(`${what} is a whole number in decimal text`)
  return field(BigInt(text), what)
}

const isAddress = (value: unknown): value is string => {
  try {
    return typeof value === 'string' && addressOf(pointOf(value)) === value
  } catch {
    return false
  }
}

/** A signed stamp as JSON (StampJson). */
export function stampToJson(stamp: SignedStamp): StampJson {
  const { stampNumber, facts, verifier, signature, ...added } = stamp
  return {
    stampNumber: String(stampNumber),
    facts: String(facts),
    verifier,
    signature: { r8: [String(signature.R8[0]), String(signature.R8[1])], s: String(signature.S) },
    // What the verifier added, as it wrote it: JSON values, so they travel as they came.
    ...(added as { [field: string]: Json }),
  }
}

/**
 * A signed stamp back from its JSON. Refuses a stamp whose own fields are not as StampJson says; passes
 * every other field through unchanged. Whether its verifier signed it is stampSigned's to say.
 */
export function stampFromJson(value: unknown): SignedStamp {
  const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)
  if (!isObject(value)) throw new Error('a stamp is an object')
  const { stampNumber, facts, verifier, signature: sig, ...added } = value
  if (!isAddress(verifier)) throw new Error("a verifier's key is an address: a point on Baby Jubjub, packed, in base58")
  if (!isObject(sig) || Object.keys(sig).sort().join() !== 'r8,s' || !Array.isArray(sig.r8) || sig.r8.length !== 2) throw new Error('a signature is { r8: [x, y], s }')
  return {
    ...added,
    stampNumber: decimal(stampNumber, 'stampNumber'),
    facts: decimal(facts, 'facts'),
    verifier,
    signature: { R8: [decimal(sig.r8[0], 'r8 x'), decimal(sig.r8[1], 'r8 y')], S: decimal(sig.s, 's') },
  }
}

/** Did the stamp's verifier sign it? zk-kit's check, the same equation the circuit checks. */
export function stampSigned(stamp: SignedStamp): boolean {
  try {
    return verifySignature(stampHash(stamp), stamp.signature, pointOf(stamp.verifier))
  } catch {
    return false
  }
}
