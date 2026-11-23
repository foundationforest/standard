// A stamp's facts as a list, and the facts proof (../README.md, Facts as a list, and The facts
// proof): the recipe that makes a stamp's facts number from its list, the proof a person makes on the
// device to show some of those facts to one reader from one profile, the check that reader makes,
// and the JSON a proof travels in with the facts it shows. It talks to no network.
//
// A fact is a name, a value and a salt. Its leaf is Poseidon(name's number, value's number, salt),
// each text's number keys/'s fieldHash of it, nothing joined. The list's leaves, in order, then 0s,
// fill the FACTS_LISTED leaves of a tree whose every node is Poseidon(left, right); its root is the
// facts number the verifier signs. A verifier may put any other number in facts, and then none of
// it can be shown.

import { poseidon2 } from 'poseidon-lite/poseidon2'
import { poseidon3 } from 'poseidon-lite/poseidon3'
import { poseidon4 } from 'poseidon-lite/poseidon4'
import { groth16 } from 'snarkjs'

import { type Point, addressOf, pointOf } from '@foundationforest/keys'
import { type SnarkjsProof, proofBytes, proofFromBytes } from './bytes.ts'
import { fieldHash, isFieldElement, nameHashOf, scopeOf, seedNumber, stampNumberOf } from './field.ts'
import { type SignedStamp, type VerifierKey, stampSigned } from './stamp.ts'
import { type Artifacts, verificationInput } from './verification.ts'
import { FACTS_KEY } from './facts-key.ts'

/** The circuit's slots: a proof shows up to this many facts. */
export const FACTS_SHOWN = 8
/** The tree's depth. */
const DEPTH = 8
/** A list holds up to this many facts: the leaves of a tree of depth 8. */
export const FACTS_LISTED = 2 ** DEPTH

/**
 * One of a stamp's facts, as its list holds it in the stamp's JSON. The name and the value are text,
 * named and written as the verifier chooses; the salt is a random number below BN254's scalar order,
 * in decimal text, which the verifier draws for each fact so that the facts number says nothing to
 * someone who can guess the rest of the list.
 */
export type Fact = { name: string; value: string; salt: string }

/** A fact as a proof shows it: its name and its value, never its salt. */
export type ShownFact = { name: string; value: string }

/** The key a stamp's list sits under, beside the stamp in its JSON. */
export const FACT_LIST = 'factList'

// Text with one UTF-8 spelling, as keys/ tests a label: one with a lone surrogate has none.
const isText = (value: unknown): value is string => typeof value === 'string' && new TextDecoder().decode(new TextEncoder().encode(value)) === value
const isObject = (value: unknown): value is { [key: string]: unknown } => value !== null && typeof value === 'object' && !Array.isArray(value)
const DECIMAL = /^(0|[1-9][0-9]{0,76})$/

/** A text as a number, fieldHash of it; refuses a text with a lone surrogate, which has no one UTF-8 spelling. */
function textNumber(text: unknown, what: string): bigint {
  if (!isText(text)) throw new Error(`${what} is text`)
  return fieldHash(text)
}

function decimal(text: unknown, what: string): bigint {
  if (typeof text !== 'string' || !DECIMAL.test(text) || !isFieldElement(BigInt(text))) {
    throw new Error(`${what} is a whole number below BN254's scalar order, in decimal text`)
  }
  return BigInt(text)
}

/** A fact's leaf: Poseidon(name's number, value's number, salt). Refuses a fact in any other shape. */
function leafOf(fact: unknown): bigint {
  if (!isObject(fact) || Object.keys(fact).sort().join() !== 'name,salt,value') throw new Error('a fact is { name, value, salt }')
  return poseidon3([textNumber(fact.name, "a fact's name"), textNumber(fact.value, "a fact's value"), decimal(fact.salt, "a fact's salt")])
}

/** The tree over a list, level by level from its leaves to its root. */
function levelsOf(list: unknown): bigint[][] {
  if (!Array.isArray(list)) throw new Error('a list of facts is an array')
  if (list.length > FACTS_LISTED) throw new RangeError(`a list holds up to ${FACTS_LISTED} facts`)
  const levels = [[...list.map(leafOf), ...Array<bigint>(FACTS_LISTED - list.length).fill(0n)]]
  for (let d = 0; d < DEPTH; d++) {
    const below = levels[d]!
    levels.push(Array.from({ length: below.length / 2 }, (_, i) => poseidon2([below[2 * i]!, below[2 * i + 1]!])))
  }
  return levels
}

/** For a verifier: a fact with its own salt, 31 random bytes read big-endian, so always below BN254's scalar order. */
export function newFact(name: string, value: string): Fact {
  let salt = 0n
  for (const b of crypto.getRandomValues(new Uint8Array(31))) salt = (salt << 8n) | BigInt(b)
  const fact = { name, value, salt: salt.toString() }
  leafOf(fact) // refuses a name or a value that is not text
  return fact
}

/**
 * The facts number of a list: the root of the tree over its leaves, in order, then 0s. A verifier
 * that wants its people to show facts signs this as the stamp's facts. Refuses more than
 * FACTS_LISTED facts, and a fact in any other shape.
 */
export function factsNumber(list: Fact[]): bigint {
  return levelsOf(list)[DEPTH]![0]!
}

/**
 * The list beside a stamp, under `factList`, as the verifier wrote it. Refuses a stamp with none,
 * a list in any other shape, and one that does not make the stamp's facts: only the list the
 * verifier signed can show its facts.
 */
export function factListOf(stamp: SignedStamp): Fact[] {
  return listOf(stamp).list
}

/** The list beside a stamp, checked as factListOf says, and its tree, built once. */
function listOf(stamp: SignedStamp): { list: Fact[]; levels: bigint[][] } {
  const list = stamp[FACT_LIST]
  if (list === undefined) throw new Error('this stamp has no list of facts beside it')
  const levels = levelsOf(list)
  if (levels[DEPTH]![0] !== stamp.facts) throw new Error("this list does not make the stamp's facts")
  return { list: list as Fact[], levels }
}

/**
 * Whom a proof is made for, and when, as one number: fieldHash of the canonical JSON of
 * `{ time, to }`, the time in whole ms since 1970, the maker's own, and `to` any text the reader
 * knows as itself, the main way its profile address.
 */
export function madeForOf(time: number, to: string): bigint {
  if (!Number.isSafeInteger(time) || time < 0) throw new RangeError('a time is whole ms, 0 to 2^53 - 1')
  if (!isText(to)) throw new Error('to is text')
  // RFC 8785 for this one shape: its two keys in order, the time's digits, and `to` as
  // JSON.stringify writes a well-formed text, which is RFC 8785's own way.
  return fieldHash(JSON.stringify({ time, to }))
}

/** A facts proof, with the facts it shows and everything a reader needs to check it. */
export type FactsProof = {
  /** The key of the verifier that signed the stamp. */
  verifier: VerifierKey
  verifierName: string
  /** The label of the profile the proof was made from. */
  label: string
  /** That profile's address. */
  profile: string
  /** When it was made, in whole ms since 1970: the maker's own word. */
  time: number
  /** Whom it was made for. */
  to: string
  /** The facts it shows, in its slots' order. */
  shown: ShownFact[]
  /** Poseidon(seed, scope, facts, made for): the same for every proof from one stamp, on one profile, for one made for. */
  match: bigint
  /** The proof as snarkjs wrote it. */
  proof: SnarkjsProof
}

/**
 * The circuit's input for these facts, and the public signals it must give. `proveFacts` proves it;
 * it is exported for a caller that drives snarkjs itself. Refuses a stamp whose list does not make
 * its facts, more than FACTS_SHOWN facts, and a fact the list does not hold.
 */
export function factsInput(input: {
  /** The person's seed, its 32 bytes. It goes in as its number, and stays on the device. */
  seed: Uint8Array
  /** The stamp, with its list beside it. */
  stamp: SignedStamp
  /** The label of the profile the proof is made from. */
  label: string
  /** The facts to show, each by its name and value, as the stamp's list holds them. */
  show: ShownFact[]
  /** When it is made, in whole ms since 1970. */
  time: number
  /** Whom it is made for: any text the reader knows as itself, the main way its profile address. */
  to: string
}): { input: Record<string, unknown>; publicSignals: bigint[] } {
  const { stamp, show } = input
  if (!Array.isArray(show) || show.length > FACTS_SHOWN) throw new RangeError(`up to ${FACTS_SHOWN} facts`)
  const { list, levels } = listOf(stamp)
  const slots = show.map((fact) => {
    const at = list.findIndex((held) => held.name === fact.name && held.value === fact.value)
    if (at < 0) throw new Error(`the stamp holds no fact ${JSON.stringify(fact.name)} with that value`)
    return {
      shown: [fieldHash(list[at]!.name), fieldHash(list[at]!.value)],
      salt: BigInt(list[at]!.salt),
      at,
      siblings: levels.slice(0, DEPTH).map((level, d) => level[(at >> d) ^ 1]!),
    }
  })
  // A blank slot shows 0 and 0; its salt and path are read by nothing.
  const blank = { shown: [0n, 0n], salt: 0n, at: 0, siblings: Array<bigint>(DEPTH).fill(0n) }
  const all = [...slots, ...Array(FACTS_SHOWN - slots.length).fill(blank)] as typeof slots

  const { input: verification, publicSignals: six } = verificationInput(input)
  const madeFor = madeForOf(input.time, input.to)
  const match = poseidon4([verification.seed as bigint, verification.scope as bigint, stamp.facts, madeFor])
  const shown = all.map((s) => s.shown)
  return {
    input: {
      ...verification,
      salts: all.map((s) => s.salt),
      pathIndices: all.map((s) => s.at),
      pathSiblings: all.map((s) => s.siblings),
      madeFor,
      shown,
      match,
    },
    publicSignals: [...six, madeFor, ...shown.flat(), match],
  }
}

/**
 * Make the proof, on the device. Refuses a stamp for another seed or verifier name, one its
 * verifier did not sign, one whose list does not make its facts, and a fact the list does not
 * hold, before proving anything.
 */
export async function proveFacts(input: Parameters<typeof factsInput>[0] & { artifacts: Artifacts }): Promise<FactsProof> {
  const { stamp } = input
  if (stamp.stampNumber !== stampNumberOf(seedNumber(input.seed), stamp.verifierName)) throw new Error('this stamp is not for this seed at this verifier')
  if (!stampSigned(stamp)) throw new Error("the verifier's signature is not on this stamp")
  const { input: signals, publicSignals: want } = factsInput(input)
  const { proof, publicSignals } = (await groth16.fullProve(signals, input.artifacts.wasm, input.artifacts.zkey)) as {
    proof: SnarkjsProof
    publicSignals: string[]
  }
  // The circuit's order: the verification's six, made for, each slot's name and value, the match
  // number. Checked so a change in the circuit or the setup files shows up here, and not as a proof
  // every reader refuses.
  if (publicSignals.length !== want.length || publicSignals.some((s, i) => BigInt(s) !== want[i])) {
    throw new Error('the proof carries other public signals than the ones asked for')
  }
  return {
    verifier: stamp.verifier,
    verifierName: stamp.verifierName,
    label: input.label,
    profile: addressOf([want[0]!, want[1]!]),
    time: input.time,
    to: input.to,
    shown: input.show.map(({ name, value }) => ({ name, value })),
    match: want[want.length - 1]!,
    proof,
  }
}

/**
 * Does this proof hold, for what the reader expects: did the verifier with this key and this name
 * sign these facts, in a stamp for the seed behind this profile's key for this label, and was the
 * proof made for this reader no earlier than `oldest`? The reader's own values are used, never the
 * proof's; from the proof come only the facts it shows, its time and its match number. Which
 * verifiers to trust, and how old a time to accept, is the reader's. Anything that is not a good
 * proof for these inputs is false.
 */
export async function checkFacts(input: {
  /** The proof, as `proveFacts` or `factsProofFromJson` gives it. */
  proof: FactsProof
  /** The verifier's key: its address, or its point. */
  verifier: VerifierKey | Point
  verifierName: string
  /** The label of the profile the reader expects. */
  label: string
  /** That profile: its address, or its key. */
  profile: string | Point
  /** Whom the reader knows itself as. */
  to: string
  /** The oldest time it accepts, in whole ms since 1970. */
  oldest: number
}): Promise<boolean> {
  try {
    const { proof } = input
    if (!Number.isSafeInteger(input.oldest) || !(proof.time >= input.oldest)) return false
    if (!Array.isArray(proof.shown) || proof.shown.length > FACTS_SHOWN || !isFieldElement(proof.match)) return false
    const profile = typeof input.profile === 'string' ? pointOf(input.profile) : pointOf(addressOf(input.profile))
    const verifier = typeof input.verifier === 'string' ? pointOf(input.verifier) : pointOf(addressOf(input.verifier))
    const shown = proof.shown.map(({ name, value }) => [textNumber(name, "a fact's name"), textNumber(value, "a fact's value")])
    const blanks = Array<bigint>(2 * (FACTS_SHOWN - shown.length)).fill(0n)
    const values = [
      ...[profile[0], profile[1], verifier[0], verifier[1], scopeOf(input.label), nameHashOf(input.verifierName)],
      madeForOf(proof.time, input.to),
      ...shown.flat(),
      ...blanks,
      proof.match,
    ]
    return await groth16.verify(FACTS_KEY, values.map(String), proof.proof)
  } catch {
    return false
  }
}

/**
 * A facts proof as JSON: the form one app sends it in and another reads, the proof and the facts
 * it shows together. The match number in decimal text, the proof as its 256 bytes (`proofBytes`) in
 * base64url without padding, as a profile entry carries a proof. Every key starts in lower case,
 * so it fits inside an entry or a message.
 */
export type FactsProofJson = {
  verifier: string
  verifierName: string
  label: string
  profile: string
  time: number
  to: string
  shown: ShownFact[]
  match: string
  proof: string
}

/** A facts proof as JSON (FactsProofJson). */
export function factsProofToJson(proof: FactsProof): FactsProofJson {
  return {
    verifier: proof.verifier,
    verifierName: proof.verifierName,
    label: proof.label,
    profile: proof.profile,
    time: proof.time,
    to: proof.to,
    shown: proof.shown.map(({ name, value }) => ({ name, value })),
    match: String(proof.match),
    proof: toBase64url(proofBytes(proof.proof)),
  }
}

/**
 * A facts proof back from its JSON. Refuses one whose fields are not as FactsProofJson says, and
 * skips any other field. Whether it holds is checkFacts's to say, against what the reader expects.
 */
export function factsProofFromJson(value: unknown): FactsProof {
  if (!isObject(value)) throw new Error('a facts proof is an object')
  const { verifier, verifierName, label, profile, time, to, shown, match, proof } = value
  for (const [what, address] of [['verifier', verifier], ['profile', profile]] as const) {
    if (typeof address !== 'string' || addressOf(pointOf(address)) !== address) throw new Error(`${what} is an address`)
  }
  if (!isText(verifierName) || !isText(label) || !isText(to)) throw new Error('verifierName, label and to are text')
  madeForOf(time as number, to) // refuses a time that is not whole ms, 0 to 2^53 - 1
  if (!Array.isArray(shown) || shown.length > FACTS_SHOWN) throw new Error(`shown is a list of up to ${FACTS_SHOWN} facts`)
  const facts = shown.map((fact: unknown) => {
    if (!isObject(fact) || !isText(fact.name) || !isText(fact.value)) throw new Error('a shown fact is { name, value }, each text')
    return { name: fact.name, value: fact.value }
  })
  if (typeof proof !== 'string') throw new Error('proof is its 256 bytes in base64url')
  return {
    verifier: verifier as string,
    verifierName,
    label,
    profile: profile as string,
    time: time as number,
    to,
    shown: facts,
    match: decimal(match, 'match'),
    proof: proofFromBytes(fromBase64url(proof)),
  }
}

// base64url without padding, by the platform's btoa and atob, so it needs no Buffer.
function toBase64url(bytes: Uint8Array): string {
  let text = ''
  for (const b of bytes) text += String.fromCharCode(b)
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Refuses any spelling but the one toBase64url writes. */
function fromBase64url(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('not base64url')
  const bytes = Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
  if (toBase64url(bytes) !== text) throw new Error('base64url in its one spelling')
  return bytes
}
