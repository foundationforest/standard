// The reputation proof's client: the tree an index publishes, the proof an app makes from it on the
// device, and the check any reader makes. It talks to no network: the caller passes in the index's
// published leaves, root, time and signature.
//
// The tag, the scope and the profile's key come from keys/ unchanged, so a leaf names a profile
// exactly as its stamp proof does, and a proof names the key of the profile it is shown on.

import { Group } from '@semaphore-protocol/group'
import { poseidon4 } from 'poseidon-lite/poseidon4'
import { groth16 } from 'snarkjs'

import {
  type Point,
  addressOf,
  isFieldElement,
  issuerScalarOf,
  nameHashOf,
  pointOf,
  profileScalarOf,
  publicKeyOf,
  scopeOf,
  tagOf,
  unpackSignature,
  verifyBytes,
} from '@foundationforest/keys'
import { type SnarkjsProof, proofFromBytes, toBytes32 } from '@foundationforest/stamp'
import { REPUTATION_KEY } from './reputation-key.ts'

/** The circuit's slots: a proof counts up to this many profiles. */
export const SLOTS = 8
/** The circuit's depth: a tree holds at most 2^DEPTH leaves. */
export const DEPTH = 20
/** Every score and count is below this. */
export const BOUND = 2n ** 32n
/** What an index's signed bytes start with, after 0xff: its own text, so the signature is never anything else's. */
export const SIGNED_PREFIX = 'forest/v1/reputation\n'

/** One profile in an index's tree. */
export type Leaf = {
  /** The profile's tag at the issuer its stamp proof names. */
  tag: bigint
  /** The scope of the profile's label (`scopeOf`). */
  scope: bigint
  /** The leaf's score: a whole number below 2^32 whose meaning is the index's. */
  score: bigint
  /** The leaf's count, which weighs its score: a whole number below 2^32 whose meaning is the index's. */
  count: bigint
}

/** One of the person's profiles to count: its label, and the issuer whose tag the index's leaf carries. */
export type Source = { label: string; issuerName: string }

/** Where a leaf sits: Semaphore's Merkle proof, as the circuit reads it. */
export type Path = { length: number; index: number; siblings: bigint[] }

export type Tree = {
  /** What the index signs, with a time. */
  root: bigint
  /** The path to the leaf with this tag, if the tree has one. */
  pathOf(tag: bigint): Path | undefined
}

/** The pinned setup files. Paths on Node, or the bytes themselves in a browser. */
export type Artifacts = {
  wasm: string | Uint8Array
  zkey: string | Uint8Array
}

export type ReputationProof = {
  /** The count-weighted average of the scores of the profiles counted, rounded down. */
  score: bigint
  root: bigint
  /** The key of the profile the proof is shown on. */
  profile: Point
  /** Its address. */
  address: string
  /** The scope shown, or 0. */
  scope: bigint
  /** The proof as snarkjs wrote it. */
  proof: SnarkjsProof
  publicSignals: string[]
}

/** A leaf's hash: Poseidon(tag, scope, score, count). */
export function leafHash(leaf: Leaf): bigint {
  return poseidon4([leaf.tag, leaf.scope, leaf.score, leaf.count])
}

/**
 * The tree an index publishes: Semaphore's, over the leaves' hashes in the index's order. Refuses
 * an empty tree, one deeper than the circuit, a field out of range, and two leaves for one tag.
 */
export function buildTree(leaves: Leaf[]): Tree {
  if (leaves.length === 0) throw new RangeError('a tree has at least one leaf')
  if (leaves.length > 2 ** DEPTH) throw new RangeError(`a tree has at most 2^${DEPTH} leaves`)
  const at = new Map<bigint, number>()
  leaves.forEach((leaf, i) => {
    if (!isFieldElement(leaf.tag) || !isFieldElement(leaf.scope)) throw new RangeError(`leaf ${i}: not a field element`)
    if (leaf.score < 0n || leaf.score >= BOUND || leaf.count < 0n || leaf.count >= BOUND) {
      throw new RangeError(`leaf ${i}: a score and a count are each from 0 to 2^32 - 1`)
    }
    if (at.has(leaf.tag)) throw new Error(`leaf ${i}: a second leaf for one tag`)
    at.set(leaf.tag, i)
  })
  const group = new Group(leaves.map(leafHash))
  return {
    root: group.root,
    pathOf(tag) {
      const i = at.get(tag)
      if (i === undefined) return undefined
      const proof = group.generateMerkleProof(i)
      return { length: proof.siblings.length, index: proof.index, siblings: proof.siblings }
    },
  }
}

/**
 * What an index signs: 0xff, its text, the root as 32 big-endian bytes, the time as 8 (ms). It
 * signs them as a record is signed: EdDSA-Poseidon on Baby Jubjub, by keys/'s signBytes.
 */
export function signedBytes(root: bigint, time: bigint | number): Uint8Array {
  const ms = BigInt(time)
  if (!isFieldElement(root)) throw new RangeError('a root is a field element')
  if (ms < 0n || ms >= 2n ** 64n) throw new RangeError('a time is 0 to 2^64 - 1 ms')
  const text = new TextEncoder().encode(SIGNED_PREFIX)
  const out = new Uint8Array(1 + text.length + 32 + 8)
  out[0] = 0xff
  out.set(text, 1)
  out.set(toBytes32(root), 1 + text.length)
  new DataView(out.buffer).setBigUint64(1 + text.length + 32, ms)
  return out
}

/**
 * The circuit's input for these profiles, and the public signals it must give. `proveReputation`
 * proves it; it is exported for a caller that drives snarkjs itself.
 */
export function circuitInput(input: {
  /** The seed scalar: `keys/`'s `seedScalar(seed)`. */
  seedScalar: bigint
  /** The person's profiles to count, one to eight, each with the issuer its leaf's tag is at. */
  sources: Source[]
  /** The index's published leaves, in its order. */
  leaves: Leaf[]
  /** The label of the profile the proof is shown on, one of the person's. The proof names its key. */
  profileLabel: string
  /** Show the label. Only with one profile. */
  show?: boolean
}): { input: Record<string, unknown>; publicSignals: bigint[] } {
  const { sources, seedScalar } = input
  if (!isFieldElement(seedScalar)) throw new RangeError('a seed scalar is a field element')
  if (sources.length < 1 || sources.length > SLOTS) throw new RangeError(`one to ${SLOTS} profiles`)
  if (new Set(sources.map((s) => s.label)).size !== sources.length) throw new Error('a label twice')
  if (input.show && sources.length !== 1) throw new Error('a label is shown only when it is the only one')

  const tree = buildTree(input.leaves)
  const byTag = new Map(input.leaves.map((leaf) => [leaf.tag, leaf]))

  const slots = sources.map(({ label, issuerName }) => {
    const tag = tagOf(issuerScalarOf(seedScalar, issuerName), label)
    const leaf = byTag.get(tag)
    const path = tree.pathOf(tag)
    if (leaf === undefined || path === undefined) throw new Error(`the tree has no leaf for ${label} at ${issuerName}`)
    return { leaf, path, nameHash: nameHashOf(issuerName) }
  })

  const countSum = slots.reduce((n, s) => n + s.leaf.count, 0n)
  if (countSum === 0n) throw new Error('no reviews to count')
  const score = slots.reduce((n, s) => n + s.leaf.score * s.leaf.count, 0n) / countSum

  const blank = { leaf: { tag: 0n, scope: 0n, score: 0n, count: 0n }, path: { length: 0, index: 0, siblings: [] as bigint[] }, nameHash: 0n }
  const all = [...slots, ...Array(SLOTS - slots.length).fill(blank)] as typeof slots
  const scope = input.show ? scopeOf(sources[0]!.label) : 0n
  const profile = publicKeyOf(profileScalarOf(seedScalar, input.profileLabel))

  return {
    input: {
      seedScalar,
      issuerNameHashes: all.map((s) => s.nameHash),
      used: all.map((_, i) => (i < slots.length ? 1 : 0)),
      // The circuit's signal for the leaves' tags is named stamps: reputation.circom keeps its bytes.
      stamps: all.map((s) => s.leaf.tag),
      scopes: all.map((s) => s.leaf.scope),
      scores: all.map((s) => s.leaf.score),
      counts: all.map((s) => s.leaf.count),
      pathLengths: all.map((s) => s.path.length),
      pathIndices: all.map((s) => s.path.index),
      // The circuit walks `pathLengths` levels; the rest is padding it never reads.
      pathSiblings: all.map((s) => [...s.path.siblings, ...Array(DEPTH - s.path.siblings.length).fill(0n)]),
      profileScope: scopeOf(input.profileLabel),
      root: tree.root,
      profileX: profile[0],
      profileY: profile[1],
      scope,
    },
    publicSignals: [score, tree.root, profile[0], profile[1], scope],
  }
}

/** Make the proof, on the device. */
export async function proveReputation(input: Parameters<typeof circuitInput>[0] & { artifacts: Artifacts }): Promise<ReputationProof> {
  const { input: signals, publicSignals: want } = circuitInput(input)
  const { proof, publicSignals } = (await groth16.fullProve(signals, input.artifacts.wasm, input.artifacts.zkey)) as {
    proof: SnarkjsProof
    publicSignals: string[]
  }
  // The circuit's order: score, root, profile x, profile y, scope. Checked so a change in the
  // circuit or the setup files shows up here, and not as a proof every reader refuses.
  if (publicSignals.length !== 5 || publicSignals.some((s, i) => BigInt(s) !== want[i])) {
    throw new Error('the proof carries other public signals than the ones asked for')
  }
  const [score, root, x, y, scope] = want as [bigint, bigint, bigint, bigint, bigint]
  const profile: Point = [x, y]
  return { score, root, profile, address: addressOf(profile), scope, proof, publicSignals }
}

// The proof as a profile record stores it, 256 bytes, and back: the stamp client's, which a stamp
// proof uses too (records/README.md, Proofs).
export { proofBytes, proofFromBytes } from '@foundationforest/stamp'

/**
 * Does this proof hold, under a root this index signed with this time, on this profile? Checks the
 * index's signature (keys/'s verifyBytes over signedBytes), that every public value is in range,
 * and the proof with the committed verification key for this profile's key and, if one is given,
 * this shown label. The key is derived inside the proof from the same seed as every counted
 * profile, so a proof holds only on a profile of the prover's own. How old a time to accept, and
 * which indexes to trust, is the reader's choice. Anything that is not a good proof for these
 * inputs is false.
 */
export async function verifyReputation(input: {
  /** The proof as snarkjs writes it, `proveReputation`'s `proof`, or its 256 bytes (`proofBytes`). */
  proof: SnarkjsProof | Uint8Array
  root: bigint
  score: bigint
  /** The profile that shows the proof: its address, or its key. */
  profile: string | Point
  /** The label shown, if the proof shows one. */
  label?: string
  /** The index's key: its address, or its point on Baby Jubjub. */
  index: string | Point
  /** The time the index signed with the root, in ms. */
  time: bigint | number
  /** The index's signature over `signedBytes(root, time)`: its 64 bytes, R8 packed then S (keys/'s packSignature). */
  signature: Uint8Array
}): Promise<boolean> {
  try {
    const signature = unpackSignature(input.signature)
    if (signature === null || !verifyBytes(input.index, signedBytes(input.root, input.time), signature)) return false
    if (input.score < 0n || input.score >= BOUND) return false
    const profile = typeof input.profile === 'string' ? pointOf(input.profile) : pointOf(addressOf(input.profile))
    const scope = input.label === undefined ? 0n : scopeOf(input.label)
    const publicSignals = [input.score, input.root, profile[0], profile[1], scope].map(String)
    const proof = input.proof instanceof Uint8Array ? proofFromBytes(input.proof) : input.proof
    return await groth16.verify(REPUTATION_KEY, publicSignals, proof)
  } catch {
    return false
  }
}
