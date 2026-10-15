// The note and the person proof (../README.md, The note and the person proof).
//
// An issuer signs a note for each person: { note number, face embedding, model name, tier }. The
// note number is Poseidon of the person's secret for that issuer (`keys/`'s `issuerSecret`), so
// the issuer never learns the secret. The issuer signs Poseidon(tag, note number, the embedding's
// hash, the model's hash, tier) with its EdDSA key on Baby Jubjub over Poseidon: zk-kit's signer,
// unchanged, which circomlib's verifier checks inside the circuit. The tag is fixed, so nothing the
// issuer signs for another purpose can be turned into a note. The tag, the embedding and the model
// enter as `keccak256 >> 8` of their bytes, like the scope and the message; the circuit never reads
// the embedding or the model.
//
// The person proves on the device, from the secret and the note: "this issuer signed a note for my
// note number; my stamp for this label is Poseidon(scope, secret); this proof is for this main
// key". Public: the issuer's key, the label, the main key, the stamp and the tier. The stamp is the
// number a registry row sits at, and the program checks this proof before it writes the row.

import type { PublicKey } from '@solana/web3.js'
import { derivePublicKey, signMessage, verifySignature } from '@zk-kit/eddsa-poseidon'
import { poseidon1 } from 'poseidon-lite/poseidon1'
import { poseidon5 } from 'poseidon-lite/poseidon5'
import { groth16 } from 'snarkjs'

import { type SnarkjsProof, proofFromBytes } from './compress.ts'
import { fieldHash, fromBytes32, isFieldElement, messageOf, scopeOf, toBytes32 } from './field.ts'
import { PERSON_KEY } from './person-key.ts'
import { scalarOf, stampOf } from './stamp.ts'

/** The setup's proving files (`registry/circuit/devnet/`): paths on Node, or the bytes in a browser. */
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
  /** The tier the issuer gives the person. Any field element; what it means is the issuer's. */
  tier: bigint
}

/** An EdDSA signature on Baby Jubjub, as zk-kit writes it. */
export type NoteSignature = { R8: [bigint, bigint]; S: bigint }

/** A note, the key of the issuer that signed it, and the signature. The person keeps it. */
export type SignedNote = Note & { issuer: IssuerKey; signature: NoteSignature }

export type PersonProof = {
  /** The stamp for this label, `Poseidon(scope, secret)`: the number a registry row sits at. */
  stamp: bigint
  issuer: IssuerKey
  scope: bigint
  message: bigint
  tier: bigint
  /** The proof as snarkjs wrote it. */
  proof: SnarkjsProof
  /** In the circuit's order: stamp, issuer x, issuer y, scope, message, tier. */
  publicSignals: string[]
}

/** The person's note number for one issuer: Poseidon of the secret. What the issuer signs in the note. */
export function noteNumberOf(secret: Uint8Array): bigint {
  return poseidon1([scalarOf(secret)])
}

/** What an issuer signs: Poseidon(tag, note number, keccak256(embedding) >> 8, keccak256(model) >> 8, tier). */
export function noteHash(note: Note): bigint {
  if (!isFieldElement(note.noteNumber) || !isFieldElement(note.tier)) throw new RangeError('a note number and a tier are field elements')
  if (!(note.embedding instanceof Uint8Array) || typeof note.model !== 'string') throw new TypeError('an embedding is bytes and a model is text')
  // The registry's hash with no namespace: the place in the note keeps the two apart.
  return poseidon5([NOTE_TAG, note.noteNumber, fieldHash('', note.embedding), fieldHash('', note.model), note.tier])
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
 * an issuer may hand it over in. Numbers in decimal text, the embedding in base64url without
 * padding, the issuer's key as a row holds it, 128 characters of lowercase hex. Every key starts in
 * lower case, so it fits inside a record.
 */
export type NoteJson = {
  noteNumber: string
  embedding: string
  model: string
  tier: string
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
    tier: String(note.tier),
    issuer: hex(note.issuer[0]) + hex(note.issuer[1]),
    signature: { r8: [String(note.signature.R8[0]), String(note.signature.R8[1])], s: String(note.signature.S) },
  }
}

/** A signed note back from its JSON. Refuses any other shape; whether its issuer signed it is noteSigned's to say. */
export function noteFromJson(value: unknown): SignedNote {
  const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)
  if (!isObject(value)) throw new Error('a note is an object')
  const fields = ['noteNumber', 'embedding', 'model', 'tier', 'issuer', 'signature']
  for (const key of Object.keys(value)) if (!fields.includes(key)) throw new Error(`unknown note field ${key}`)
  if (typeof value.embedding !== 'string' || typeof value.model !== 'string') throw new Error('an embedding is base64url and a model is text')
  if (typeof value.issuer !== 'string' || !/^[0-9a-f]{128}$/.test(value.issuer)) throw new Error("an issuer's key is 128 characters of lowercase hex")
  const sig = value.signature
  if (!isObject(sig) || Object.keys(sig).sort().join() !== 'r8,s' || !Array.isArray(sig.r8) || sig.r8.length !== 2) throw new Error('a signature is { r8: [x, y], s }')
  return {
    noteNumber: decimal(value.noteNumber, 'noteNumber'),
    embedding: fromBase64url(value.embedding),
    model: value.model,
    tier: decimal(value.tier, 'tier'),
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
 * The circuit's input, and the public signals it must give. `provePerson` proves it; it is
 * exported for a caller that drives snarkjs itself.
 */
export function personInput(input: {
  /** The 32 bytes `keys/`'s `issuerSecret(seed, name)` returns. */
  secret: Uint8Array
  note: SignedNote
  label: string
  /** The main key the proof is for. The proof names it and counts for it alone. */
  profile: PublicKey | Uint8Array
}): { input: Record<string, unknown>; publicSignals: bigint[] } {
  const { note } = input
  const secret = scalarOf(input.secret)
  const scope = scopeOf(input.label)
  const message = messageOf(input.profile)
  const stamp = stampOf(input.secret, input.label)
  return {
    input: {
      secret,
      embedding: fieldHash('', note.embedding),
      model: fieldHash('', note.model),
      R8x: note.signature.R8[0],
      R8y: note.signature.R8[1],
      S: note.signature.S,
      issuerX: note.issuer[0],
      issuerY: note.issuer[1],
      scope,
      message,
      tier: note.tier,
    },
    publicSignals: [stamp, note.issuer[0], note.issuer[1], scope, message, note.tier],
  }
}

/**
 * Make the person proof, on the device. Refuses a note for another secret, or one its issuer did
 * not sign, before proving anything.
 */
export async function provePerson(input: Parameters<typeof personInput>[0] & { artifacts: Artifacts }): Promise<PersonProof> {
  if (input.note.noteNumber !== noteNumberOf(input.secret)) throw new Error('this note is not for this secret')
  if (!noteSigned(input.note)) throw new Error("the issuer's signature is not on this note")
  const { input: signals, publicSignals: want } = personInput(input)
  const { proof, publicSignals } = (await groth16.fullProve(signals, input.artifacts.wasm, input.artifacts.zkey)) as {
    proof: SnarkjsProof
    publicSignals: string[]
  }
  // The circuit's order: stamp, issuer x, issuer y, scope, message, tier. Checked so a change in
  // the circuit or the setup files shows up here, and not as a proof every reader refuses.
  if (publicSignals.length !== 6 || publicSignals.some((s, i) => BigInt(s) !== want[i])) {
    throw new Error('the proof carries other public signals than the ones asked for')
  }
  const [stamp, x, y, scope, message, tier] = want
  return { stamp, issuer: [x, y], scope, message, tier, proof, publicSignals }
}

/**
 * Does this proof hold: did this issuer sign a note with this tier for whoever holds the secret
 * behind this stamp, for this label and this main key? Every public value must be a field element,
 * the scope and the message are derived from the label and the main key, and the proof is checked
 * with the committed verification key. Which issuers to trust is the reader's choice. Anything
 * that is not a good proof for these inputs is false.
 */
export async function verifyPerson(input: {
  /** The proof as snarkjs writes it, `provePerson`'s `proof`, or its 256 bytes (`proofBytes`). */
  proof: SnarkjsProof | Uint8Array
  issuer: IssuerKey
  label: string
  /** The main key the proof is for. */
  profile: PublicKey | Uint8Array
  stamp: bigint | Uint8Array
  tier: bigint
}): Promise<boolean> {
  try {
    const stamp = typeof input.stamp === 'bigint' ? input.stamp : fromBytes32(input.stamp)
    const values = [stamp, input.issuer[0], input.issuer[1], input.tier]
    if (input.issuer.length !== 2 || !values.every((v) => typeof v === 'bigint' && isFieldElement(v))) return false
    const publicSignals = [stamp, input.issuer[0], input.issuer[1], scopeOf(input.label), messageOf(input.profile), input.tier].map(String)
    const proof = input.proof instanceof Uint8Array ? proofFromBytes(input.proof) : input.proof
    return await groth16.verify(PERSON_KEY, publicSignals, proof)
  } catch {
    return false
  }
}
