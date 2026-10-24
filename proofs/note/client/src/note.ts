// The note and the note proof (../README.md, The note and the note proof).
//
// An issuer signs a note for each person: { note number, attributes }. The note number is Poseidon
// of the person's secret for that issuer (`keys/`'s `issuerSecret`), so the issuer never learns the
// secret, nor the seed it comes from. The attributes are one field element, whatever the issuer
// attests; the proof keeps them private. The issuer signs Poseidon(prefix, note number, attributes)
// with its EdDSA key on Baby Jubjub over Poseidon: zk-kit's signer, unchanged, which circomlib's
// verifier checks inside the circuit. The prefix is fixed, so nothing the issuer signs for another
// purpose can be turned into a note. Its key is an address, as every key in the standard is: its
// point packed into 32 bytes, in base58; keys/'s pointOf gives x and y back.
//
// The person proves on the device, from the seed scalar and the note: "this issuer signed a note
// for the note number my seed gives at it; my stamp for this label at it is this one; this
// profile's key is the one my seed gives for this label". Public: the stamp, the profile's key,
// the issuer's key, the label's scope and the issuer's name hash.

import { derivePublicKey, signMessage, verifySignature } from '@zk-kit/eddsa-poseidon'
import { poseidon1 } from 'poseidon-lite/poseidon1'
import { poseidon3 } from 'poseidon-lite/poseidon3'
import { groth16 } from 'snarkjs'

import {
  type Point,
  addressOf,
  issuerScalarOf,
  pointOf,
  profileScalarOf,
  publicKeyOf,
  stampOf,
} from '@foundationforest/keys'
import { type SnarkjsProof, proofFromBytes } from './bytes.ts'
import { fieldHash, fromBytes32, isFieldElement, nameHashOf, scopeOf } from './field.ts'
import { NOTE_KEY } from './note-key.ts'

/** The setup's proving files (`circuit/setup/`): paths on Node, or the bytes in a browser. */
export type Artifacts = {
  wasm: string | Uint8Array
  zkey: string | Uint8Array
}

/**
 * The text whose field value starts every note an issuer signs. The circuit has it as a constant,
 * under the name it was set up with, `var NOTE_TAG`.
 */
export const NOTE_PREFIX_TEXT = 'forest/v1/note'
/** `keccak256("forest/v1/note") >> 8`: the first input of every signed note. */
export const NOTE_PREFIX = fieldHash(NOTE_PREFIX_TEXT)

/** An issuer's key: the address of its EdDSA public key on Baby Jubjub, the point packed into 32 bytes, in base58. */
export type IssuerKey = string

export type Note = {
  /** The person's note number for this issuer: `keys/`'s `issuerSecret(seed, name).noteNumber`. */
  noteNumber: bigint
  /** What the issuer attests, as one field element of its choosing. The proof keeps it private. */
  attributes: bigint
}

/** A JSON value: what an issuer adds beside a note is one. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

/** An EdDSA signature on Baby Jubjub, as zk-kit writes it. */
export type NoteSignature = { R8: [bigint, bigint]; S: bigint }

/**
 * A note, the key of the issuer that signed it, and the signature. The person keeps it. Any other
 * field is one the issuer added beside them, such as what `attributes` was made from: the note's
 * functions pass it through unchanged, and nothing here reads it.
 */
export type SignedNote = Note & { issuer: IssuerKey; signature: NoteSignature; [field: string]: unknown }

export type NoteProof = {
  /** The stamp for this label at this issuer, `Poseidon(scope, issuer secret)`. */
  stamp: bigint
  /** The profile's key, which the seed gives for this label. */
  profile: Point
  /** The profile's address: its key packed, in base58. */
  address: string
  issuer: IssuerKey
  issuerName: string
  nameHash: bigint
  scope: bigint
  /** The proof as snarkjs wrote it. */
  proof: SnarkjsProof
  /** In the circuit's order: stamp, profile x, profile y, issuer x, issuer y, scope, name hash. */
  publicSignals: string[]
}

/** The person's note number for one issuer, from the seed scalar: what the issuer signs in the note. */
export function noteNumberOf(seedScalar: bigint, issuerName: string): bigint {
  return poseidon1([issuerScalarOf(seedScalar, issuerName)])
}

/** What an issuer signs: Poseidon(prefix, note number, attributes). */
export function noteHash(note: Note): bigint {
  if (!isFieldElement(note.noteNumber)) throw new RangeError('a note number is a field element')
  if (!isFieldElement(note.attributes)) throw new RangeError('attributes are a field element')
  return poseidon3([NOTE_PREFIX, note.noteNumber, note.attributes])
}

/** The issuer's key, its address, from its 32-byte private key. */
export function issuerKeyOf(privateKey: Uint8Array): IssuerKey {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) throw new Error("an issuer's private key is 32 bytes")
  return addressOf(derivePublicKey(privateKey))
}

/** For an issuer: sign a note with its 32-byte private key. Fields it adds beside the note pass through. */
export function signNote(privateKey: Uint8Array, note: Note & { [field: string]: unknown }): SignedNote {
  const issuer = issuerKeyOf(privateKey)
  return { ...note, issuer, signature: signMessage(privateKey, noteHash(note)) }
}

/**
 * A signed note as JSON: the form a person's vault keeps it in (records/README.md, The vault), and
 * an issuer may hand it over in. Big numbers in decimal text, the issuer's key as its address.
 * Every key starts in lower case, so it fits inside a record. Any other field is the issuer's, as
 * it wrote it.
 */
export type NoteJson = {
  noteNumber: string
  attributes: string
  issuer: string
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

/** A signed note as JSON (NoteJson). */
export function noteToJson(note: SignedNote): NoteJson {
  const { noteNumber, attributes, issuer, signature, ...added } = note
  return {
    noteNumber: String(noteNumber),
    attributes: String(attributes),
    issuer,
    signature: { r8: [String(signature.R8[0]), String(signature.R8[1])], s: String(signature.S) },
    // What the issuer added, as it wrote it: JSON values, so they travel as they came.
    ...(added as { [field: string]: Json }),
  }
}

/**
 * A signed note back from its JSON. Refuses a note whose own fields are not as NoteJson says; passes
 * every other field through unchanged. Whether its issuer signed it is noteSigned's to say.
 */
export function noteFromJson(value: unknown): SignedNote {
  const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)
  if (!isObject(value)) throw new Error('a note is an object')
  const { noteNumber, attributes, issuer, signature: sig, ...added } = value
  if (!isAddress(issuer)) throw new Error("an issuer's key is an address: a point on Baby Jubjub, packed, in base58")
  if (!isObject(sig) || Object.keys(sig).sort().join() !== 'r8,s' || !Array.isArray(sig.r8) || sig.r8.length !== 2) throw new Error('a signature is { r8: [x, y], s }')
  return {
    ...added,
    noteNumber: decimal(noteNumber, 'noteNumber'),
    attributes: decimal(attributes, 'attributes'),
    issuer,
    signature: { R8: [decimal(sig.r8[0], 'r8 x'), decimal(sig.r8[1], 'r8 y')], S: decimal(sig.s, 's') },
  }
}

/** Did the note's issuer sign it? zk-kit's check, the same equation the circuit checks. */
export function noteSigned(note: SignedNote): boolean {
  try {
    return verifySignature(noteHash(note), note.signature, pointOf(note.issuer))
  } catch {
    return false
  }
}

/**
 * The circuit's input, and the public signals it must give. `proveNote` proves it; it is
 * exported for a caller that drives snarkjs itself.
 */
export function noteInput(input: {
  /** The seed scalar: `keys/`'s `seedScalar(seed)`. */
  seedScalar: bigint
  /** The name the issuer publishes as its own, as `keys/`'s `issuerSecret` took it. */
  issuerName: string
  note: SignedNote
  /** The profile's label. The proof is for the key the seed gives for it, and for no other. */
  label: string
}): { input: Record<string, unknown>; publicSignals: bigint[] } {
  const { note, seedScalar } = input
  if (!isFieldElement(seedScalar)) throw new RangeError('a seed scalar is a field element')
  if (!isFieldElement(note.attributes)) throw new RangeError('attributes are a field element')
  const [issuerX, issuerY] = pointOf(note.issuer)
  const issuerScalar = issuerScalarOf(seedScalar, input.issuerName)
  const nameHash = nameHashOf(input.issuerName)
  const scope = scopeOf(input.label)
  const profile = publicKeyOf(profileScalarOf(seedScalar, input.label))
  const stamp = stampOf(issuerScalar, input.label)
  return {
    input: {
      seedScalar,
      attributes: note.attributes,
      R8x: note.signature.R8[0],
      R8y: note.signature.R8[1],
      S: note.signature.S,
      profileX: profile[0],
      profileY: profile[1],
      issuerX,
      issuerY,
      scope,
      issuerNameHash: nameHash,
    },
    publicSignals: [stamp, profile[0], profile[1], issuerX, issuerY, scope, nameHash],
  }
}

/**
 * Make the note proof, on the device. Refuses a note for another seed or issuer name, or one its
 * issuer did not sign, before proving anything.
 */
export async function proveNote(input: Parameters<typeof noteInput>[0] & { artifacts: Artifacts }): Promise<NoteProof> {
  if (input.note.noteNumber !== noteNumberOf(input.seedScalar, input.issuerName)) throw new Error('this note is not for this seed at this issuer')
  if (!noteSigned(input.note)) throw new Error("the issuer's signature is not on this note")
  const { input: signals, publicSignals: want } = noteInput(input)
  const { proof, publicSignals } = (await groth16.fullProve(signals, input.artifacts.wasm, input.artifacts.zkey)) as {
    proof: SnarkjsProof
    publicSignals: string[]
  }
  // The circuit's order: stamp, profile x, profile y, issuer x, issuer y, scope, name hash.
  // Checked so a change in the circuit or the setup files shows up here, and not as a proof every
  // reader refuses.
  if (publicSignals.length !== 7 || publicSignals.some((s, i) => BigInt(s) !== want[i])) {
    throw new Error('the proof carries other public signals than the ones asked for')
  }
  const [stamp, px, py, ix, iy, scope, nameHash] = want as [bigint, bigint, bigint, bigint, bigint, bigint, bigint]
  const profile: Point = [px, py]
  return {
    stamp,
    profile,
    address: addressOf(profile),
    issuer: addressOf([ix, iy]),
    issuerName: input.issuerName,
    nameHash,
    scope,
    proof,
    publicSignals,
  }
}

/**
 * Does this proof hold: did the issuer with this key and this name sign a note for whoever holds
 * the seed behind this profile's key, with this stamp for this label? Every public value must be a
 * field element, the scope and the name hash are derived from the label and the name, and the
 * proof is checked with the committed verification key. Which issuers to trust is the reader's
 * choice. Anything that is not a good proof for these inputs is false.
 */
export async function verifyNote(input: {
  /** The proof as snarkjs writes it, `proveNote`'s `proof`, or its 256 bytes (`proofBytes`). */
  proof: SnarkjsProof | Uint8Array
  /** The issuer's key: its address, or its point. */
  issuer: IssuerKey | Point
  issuerName: string
  label: string
  /** The profile the proof is for: its address, or its key. */
  profile: string | Point
  stamp: bigint | Uint8Array
}): Promise<boolean> {
  try {
    const stamp = typeof input.stamp === 'bigint' ? input.stamp : fromBytes32(input.stamp)
    const profile = typeof input.profile === 'string' ? pointOf(input.profile) : pointOf(addressOf(input.profile))
    const issuer = typeof input.issuer === 'string' ? pointOf(input.issuer) : pointOf(addressOf(input.issuer))
    if (!isFieldElement(stamp)) return false
    const values = [stamp, profile[0], profile[1], issuer[0], issuer[1], scopeOf(input.label), nameHashOf(input.issuerName)]
    const proof = input.proof instanceof Uint8Array ? proofFromBytes(input.proof) : input.proof
    return await groth16.verify(NOTE_KEY, values.map(String), proof)
  } catch {
    return false
  }
}
