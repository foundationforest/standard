// The note and the human proof (../README.md, The note and the human proof).
//
// An issuer signs a note for each person: { note number, face embedding, model name, month }. The
// note number is Poseidon of the person's secret for that issuer (`keys/`'s `issuerSecret`), so
// the issuer never learns the secret, nor the seed it comes from. The issuer signs
// Poseidon(tag, note number, the embedding's hash, the model's hash, month) with its EdDSA key on
// Baby Jubjub over Poseidon: zk-kit's signer, unchanged, which circomlib's verifier checks inside
// the circuit. The tag is fixed, so nothing the issuer signs for another purpose can be turned
// into a note. The tag, the embedding and the model enter as `keccak256 >> 8` of their bytes, like
// the scope and the name hash; the circuit never reads the embedding or the model.
//
// The person proves on the device, from the seed scalar and the note: "this issuer signed a note
// for the note number my seed gives at it; my stamp for this label at it is this one; this
// profile's key is the one my seed gives for this label". Public: the stamp, the profile's key,
// the issuer's key, the label's scope, the issuer's name hash and the month.

import { derivePublicKey, signMessage, verifySignature } from '@zk-kit/eddsa-poseidon'
import { poseidon1 } from 'poseidon-lite/poseidon1'
import { poseidon5 } from 'poseidon-lite/poseidon5'
import { groth16 } from 'snarkjs'

import {
  type Point,
  addressOf,
  issuerScalarOf,
  pointOf,
  profileScalarOf,
  publicKeyOf,
  stampOf,
} from '../../../../keys/src/index.ts'
import { type SnarkjsProof, proofFromBytes } from './bytes.ts'
import { fieldHash, fromBytes32, isFieldElement, nameHashOf, scopeOf, toBytes32 } from './field.ts'
import { HUMAN_KEY } from './human-key.ts'

/** The setup's proving files (`circuit/devnet/`): paths on Node, or the bytes in a browser. */
export type Artifacts = {
  wasm: string | Uint8Array
  zkey: string | Uint8Array
}

/** The text whose field value starts every note an issuer signs. The circuit has it as a constant. */
export const NOTE_TAG_TEXT = 'forest/v1/note'
/** `keccak256("forest/v1/note") >> 8`: the first input of every signed note. */
export const NOTE_TAG = fieldHash(NOTE_TAG_TEXT)

/** An issuer's key: its EdDSA public key, a point on Baby Jubjub, as two field elements. */
export type IssuerKey = [bigint, bigint]

export type Note = {
  /** The person's note number for this issuer: `keys/`'s `issuerSecret(seed, name).noteNumber`. */
  noteNumber: bigint
  /** The face embedding, in the bytes the model gives. Only its hash is signed. */
  embedding: Uint8Array
  /** The model that made the embedding. Only its hash is signed. */
  model: string
  /** The month the issuer checked the person, as the number YYYYMM, such as 202610. */
  month: number
}

/** An EdDSA signature on Baby Jubjub, as zk-kit writes it. */
export type NoteSignature = { R8: [bigint, bigint]; S: bigint }

/** A note, the key of the issuer that signed it, and the signature. The person keeps it. */
export type SignedNote = Note & { issuer: IssuerKey; signature: NoteSignature }

export type HumanProof = {
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
  month: number
  /** The proof as snarkjs wrote it. */
  proof: SnarkjsProof
  /** In the circuit's order: stamp, profile x, profile y, issuer x, issuer y, scope, name hash, month. */
  publicSignals: string[]
}

/** A month as the number YYYYMM: a year from 1000 to 9999, a month from 01 to 12. */
export function isMonth(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 100001 && (value as number) <= 999912 && (value as number) % 100 >= 1 && (value as number) % 100 <= 12
}

/** The person's note number for one issuer, from the seed scalar: what the issuer signs in the note. */
export function noteNumberOf(seedScalar: bigint, issuerName: string): bigint {
  return poseidon1([issuerScalarOf(seedScalar, issuerName)])
}

/** What an issuer signs: Poseidon(tag, note number, keccak256(embedding) >> 8, keccak256(model) >> 8, month). */
export function noteHash(note: Note): bigint {
  if (!isFieldElement(note.noteNumber)) throw new RangeError('a note number is a field element')
  if (!isMonth(note.month)) throw new RangeError('a month is YYYYMM')
  if (!(note.embedding instanceof Uint8Array) || typeof note.model !== 'string') throw new TypeError('an embedding is bytes and a model is text')
  // keys/'s hash with no namespace: the place in the note keeps the two apart.
  return poseidon5([NOTE_TAG, note.noteNumber, fieldHash('', note.embedding), fieldHash('', note.model), BigInt(note.month)])
}

/** The issuer's key, from its 32-byte private key. */
export function issuerKeyOf(privateKey: Uint8Array): IssuerKey {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) throw new Error("an issuer's private key is 32 bytes")
  return derivePublicKey(privateKey)
}

/** For an issuer: sign a note with its 32-byte private key. */
export function signNote(privateKey: Uint8Array, note: Note): SignedNote {
  const issuer = issuerKeyOf(privateKey)
  return { ...note, issuer, signature: signMessage(privateKey, noteHash(note)) }
}

/**
 * A signed note as JSON: the form a person's vault keeps it in (records/README.md, The vault), and
 * an issuer may hand it over in. Big numbers in decimal text, the month as a number, the
 * embedding in base64url without padding, the issuer's key as 128 characters of lowercase hex,
 * x then y. Every key starts in lower case, so it fits inside a record.
 */
export type NoteJson = {
  noteNumber: string
  embedding: string
  model: string
  month: number
  issuer: string
  signature: { r8: [string, string]; s: string }
}

const base64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const fromBase64url = (text: string): Uint8Array => {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('not base64url')
  const bytes = Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4)), (c) => c.charCodeAt(0))
  if (base64url(bytes) !== text) throw new Error('base64url in more than one spelling')
  return bytes
}
const field = (n: bigint, what: string): bigint => {
  if (!isFieldElement(n)) throw new Error(`${what} is below BN254's scalar order`)
  return n
}
const decimal = (text: unknown, what: string): bigint => {
  if (typeof text !== 'string' || !/^(0|[1-9][0-9]{0,76})$/.test(text)) throw new Error(`${what} is a whole number in decimal text`)
  return field(BigInt(text), what)
}

/** A signed note as JSON (NoteJson). */
export function noteToJson(note: SignedNote): NoteJson {
  const hex = (n: bigint) => Array.from(toBytes32(n), (b) => b.toString(16).padStart(2, '0')).join('')
  return {
    noteNumber: String(note.noteNumber),
    embedding: base64url(note.embedding),
    model: note.model,
    month: note.month,
    issuer: hex(note.issuer[0]) + hex(note.issuer[1]),
    signature: { r8: [String(note.signature.R8[0]), String(note.signature.R8[1])], s: String(note.signature.S) },
  }
}

/** A signed note back from its JSON. Refuses any other shape; whether its issuer signed it is noteSigned's to say. */
export function noteFromJson(value: unknown): SignedNote {
  const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)
  if (!isObject(value)) throw new Error('a note is an object')
  const fields = ['noteNumber', 'embedding', 'model', 'month', 'issuer', 'signature']
  for (const key of Object.keys(value)) if (!fields.includes(key)) throw new Error(`unknown note field ${key}`)
  if (typeof value.embedding !== 'string' || typeof value.model !== 'string') throw new Error('an embedding is base64url and a model is text')
  if (!isMonth(value.month)) throw new Error('a month is the number YYYYMM')
  if (typeof value.issuer !== 'string' || !/^[0-9a-f]{128}$/.test(value.issuer)) throw new Error("an issuer's key is 128 characters of lowercase hex")
  const sig = value.signature
  if (!isObject(sig) || Object.keys(sig).sort().join() !== 'r8,s' || !Array.isArray(sig.r8) || sig.r8.length !== 2) throw new Error('a signature is { r8: [x, y], s }')
  return {
    noteNumber: decimal(value.noteNumber, 'noteNumber'),
    embedding: fromBase64url(value.embedding),
    model: value.model,
    month: value.month,
    issuer: [field(BigInt('0x' + value.issuer.slice(0, 64)), 'issuer x'), field(BigInt('0x' + value.issuer.slice(64)), 'issuer y')],
    signature: { R8: [decimal(sig.r8[0], 'r8 x'), decimal(sig.r8[1], 'r8 y')], S: decimal(sig.s, 's') },
  }
}

/** Did the note's issuer sign it? zk-kit's check, the same equation the circuit checks. */
export function noteSigned(note: SignedNote): boolean {
  try {
    return verifySignature(noteHash(note), note.signature, note.issuer)
  } catch {
    return false
  }
}

/**
 * The circuit's input, and the public signals it must give. `proveHuman` proves it; it is
 * exported for a caller that drives snarkjs itself.
 */
export function humanInput(input: {
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
  if (!isMonth(note.month)) throw new RangeError('a month is YYYYMM')
  const issuerScalar = issuerScalarOf(seedScalar, input.issuerName)
  const nameHash = nameHashOf(input.issuerName)
  const scope = scopeOf(input.label)
  const profile = publicKeyOf(profileScalarOf(seedScalar, input.label))
  const stamp = stampOf(issuerScalar, input.label)
  const month = BigInt(note.month)
  return {
    input: {
      seedScalar,
      embedding: fieldHash('', note.embedding),
      model: fieldHash('', note.model),
      R8x: note.signature.R8[0],
      R8y: note.signature.R8[1],
      S: note.signature.S,
      profileX: profile[0],
      profileY: profile[1],
      issuerX: note.issuer[0],
      issuerY: note.issuer[1],
      scope,
      issuerNameHash: nameHash,
      month,
    },
    publicSignals: [stamp, profile[0], profile[1], note.issuer[0], note.issuer[1], scope, nameHash, month],
  }
}

/**
 * Make the human proof, on the device. Refuses a note for another seed or issuer name, or one its
 * issuer did not sign, before proving anything.
 */
export async function proveHuman(input: Parameters<typeof humanInput>[0] & { artifacts: Artifacts }): Promise<HumanProof> {
  if (input.note.noteNumber !== noteNumberOf(input.seedScalar, input.issuerName)) throw new Error('this note is not for this seed at this issuer')
  if (!noteSigned(input.note)) throw new Error("the issuer's signature is not on this note")
  const { input: signals, publicSignals: want } = humanInput(input)
  const { proof, publicSignals } = (await groth16.fullProve(signals, input.artifacts.wasm, input.artifacts.zkey)) as {
    proof: SnarkjsProof
    publicSignals: string[]
  }
  // The circuit's order: stamp, profile x, profile y, issuer x, issuer y, scope, name hash, month.
  // Checked so a change in the circuit or the setup files shows up here, and not as a proof every
  // reader refuses.
  if (publicSignals.length !== 8 || publicSignals.some((s, i) => BigInt(s) !== want[i])) {
    throw new Error('the proof carries other public signals than the ones asked for')
  }
  const [stamp, px, py, ix, iy, scope, nameHash] = want as [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint]
  const profile: Point = [px, py]
  return {
    stamp,
    profile,
    address: addressOf(profile),
    issuer: [ix, iy],
    issuerName: input.issuerName,
    nameHash,
    scope,
    month: input.note.month,
    proof,
    publicSignals,
  }
}

/**
 * Does this proof hold: did the issuer with this key and this name sign, in this month, a note for
 * whoever holds the seed behind this profile's key, with this stamp for this label? Every public
 * value must be a field element, the scope and the name hash are derived from the label and the
 * name, and the proof is checked with the committed verification key. Which issuers to trust is
 * the reader's choice. Anything that is not a good proof for these inputs is false.
 */
export async function verifyHuman(input: {
  /** The proof as snarkjs writes it, `proveHuman`'s `proof`, or its 256 bytes (`proofBytes`). */
  proof: SnarkjsProof | Uint8Array
  issuer: IssuerKey
  issuerName: string
  label: string
  /** The profile the proof is for: its address, or its key. */
  profile: string | Point
  stamp: bigint | Uint8Array
  month: number
}): Promise<boolean> {
  try {
    const stamp = typeof input.stamp === 'bigint' ? input.stamp : fromBytes32(input.stamp)
    const profile = typeof input.profile === 'string' ? pointOf(input.profile) : pointOf(addressOf(input.profile))
    if (input.issuer.length !== 2 || ![stamp, ...input.issuer].every(isFieldElement) || !isMonth(input.month)) return false
    const values = [stamp, profile[0], profile[1], input.issuer[0], input.issuer[1], scopeOf(input.label), nameHashOf(input.issuerName), BigInt(input.month)]
    const proof = input.proof instanceof Uint8Array ? proofFromBytes(input.proof) : input.proof
    return await groth16.verify(HUMAN_KEY, values.map(String), proof)
  } catch {
    return false
  }
}
