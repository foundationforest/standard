// The stamp (../README.md, The stamp and the verification).
//
// A verifier signs a stamp for each person: { stamp number, facts, verifier name }. The stamp number
// is keys/'s stampNumberOf, Poseidon of the seed's number and the verifier's name hash, so the
// verifier never learns the seed. The facts are one field element, whatever the verifier attests;
// the proof keeps them private. The verifier signs Poseidon(name hash, stamp number, facts) with its
// key on Baby Jubjub, a service key (keys/'s serviceKey), by keys/'s signWithScalar: the signature
// circomlib's EdDSAPoseidonVerifier checks inside the circuit. Its name hash comes first, so nothing
// it signs for another purpose can be turned into a stamp. Its key is an address, as every key in
// the standard is: its point packed into 32 bytes, in base58; keys/'s pointOf gives x and y back. The
// verification a profile shows, the proof that its seed holds a stamp, is verification.ts's.

import { poseidon3 } from 'poseidon-lite/poseidon3'

import { type Signature, addressOf, checkWithPublicKey, pointOf, serviceKey, signWithScalar } from '@foundationforest/keys'
import { isFieldElement, nameHashOf } from './field.ts'

/** A verifier's key: the address of its EdDSA public key on Baby Jubjub, the point packed into 32 bytes, in base58. */
export type VerifierKey = string

export type Stamp = {
  /** The person's stamp number at this verifier: `keys/`'s `stampNumberOf(seedNumber(seed), verifierName)`. */
  stampNumber: bigint
  /** What the verifier attests, as one field element of its choosing. The proof keeps it private. */
  facts: bigint
  /** The name the verifier publishes as its own, used exactly as given: its name hash is in the stamp number and in what it signs. */
  verifierName: string
}

/** A JSON value: what a verifier adds beside a stamp is one. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

/** An EdDSA signature on Baby Jubjub, as keys/ and zk-kit write it. */
export type StampSignature = Signature

/**
 * A stamp, the key of the verifier that signed it, and the signature. The person keeps it. Any
 * other field is one the verifier added beside them, such as what `facts` was made from: the
 * stamp's functions pass it through unchanged, and nothing here reads it.
 */
export type SignedStamp = Stamp & { verifier: VerifierKey; signature: StampSignature; [field: string]: unknown }

/** What a verifier signs: Poseidon(name hash, stamp number, facts). */
export function stampHash(stamp: Stamp): bigint {
  if (!isFieldElement(stamp.stampNumber)) throw new RangeError('a stamp number is a field element')
  if (!isFieldElement(stamp.facts)) throw new RangeError('facts are a field element')
  return poseidon3([nameHashOf(stamp.verifierName), stamp.stampNumber, stamp.facts])
}

/** The verifier's key, its address, from its 32-byte private key: a service key. */
export function verifierKeyOf(privateKey: Uint8Array): VerifierKey {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) throw new Error("a verifier's private key is 32 bytes")
  return serviceKey(privateKey).address
}

/** For a verifier: sign a stamp with its 32-byte private key. Fields it adds beside the stamp pass through. */
export function signStamp(privateKey: Uint8Array, stamp: Stamp & { [field: string]: unknown }): SignedStamp {
  const verifier = verifierKeyOf(privateKey)
  return { ...stamp, verifier, signature: signWithScalar(serviceKey(privateKey).scalar, stampHash(stamp)) }
}

/**
 * A signed stamp as JSON: the form a person's device keeps it in (README.md, The stamp and the
 * verification), and a verifier may hand it over in. Big numbers in decimal text, the verifier's key
 * as its address. Every key starts in lower case, so it fits inside an entry. Any other field is the
 * verifier's, as it wrote it.
 */
export type StampJson = {
  stampNumber: string
  facts: string
  verifier: string
  verifierName: string
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
  const { stampNumber, facts, verifier, verifierName, signature, ...added } = stamp
  return {
    stampNumber: String(stampNumber),
    facts: String(facts),
    verifier,
    verifierName,
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
  const { stampNumber, facts, verifier, verifierName, signature: sig, ...added } = value
  if (!isAddress(verifier)) throw new Error("a verifier's key is an address: a point on Baby Jubjub, packed, in base58")
  if (typeof verifierName !== 'string') throw new Error("a verifier's name is text")
  nameHashOf(verifierName) // refuses a name with no one UTF-8 spelling
  if (!isObject(sig) || Object.keys(sig).sort().join() !== 'r8,s' || !Array.isArray(sig.r8) || sig.r8.length !== 2) throw new Error('a signature is { r8: [x, y], s }')
  return {
    ...added,
    stampNumber: decimal(stampNumber, 'stampNumber'),
    facts: decimal(facts, 'facts'),
    verifier,
    verifierName,
    signature: { R8: [decimal(sig.r8[0], 'r8 x'), decimal(sig.r8[1], 'r8 y')], S: decimal(sig.s, 's') },
  }
}

/** Did the stamp's verifier sign it, under its name? keys/'s check, the same equation the circuit checks. */
export function stampSigned(stamp: SignedStamp): boolean {
  try {
    return checkWithPublicKey(stamp.verifier, stampHash(stamp), stamp.signature)
  } catch {
    return false
  }
}
