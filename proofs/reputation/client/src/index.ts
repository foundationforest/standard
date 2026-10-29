// The reputation proof's client: the tree an index publishes, the proof an app makes from it on the
// device, and the check any reader makes. It talks to no network: the caller passes in the index's
// published leaves, root, time and signature.
//
// The scope and the profile's key come from keys/ unchanged, so a leaf names a profile by the key
// its records are signed with, and a proof names the key of the profile it is shown on.

import { Group } from '@semaphore-protocol/group'
import { poseidon3 } from 'poseidon-lite/poseidon3'
import { groth16 } from 'snarkjs'

import {
  type Point,
  addressOf,
  checkBytes,
  isFieldElement,
  pointOf,
  profileScalarOf,
  publicKeyOf,
  scopeOf,
  unpackSignature,
} from '@foundationforest/keys'
import { type SnarkjsProof, proofFromBytes, toBytes32 } from '@foundationforest/verification'
import { REPUTATION_KEY } from './reputation-key.ts'

/** The circuit's slots: a proof counts up to this many profiles. */
export const SLOTS = 8
/** The circuit's depth: a tree holds at most 2^DEPTH leaves. */
export const DEPTH = 20
/** Every score is below this. */
export const BOUND = 2n ** 32n
/** What an index's signed bytes start with, after 0xff: its own text, so the signature is never anything else's. */
export const SIGNED_PREFIX = 'forest/v1/reputation\n'

/** One profile in an index's tree. */
export type Leaf = {
  /** The profile's key, the point its address names (`keys/`'s `pointOf`). */
  profile: Point
  /** The profile's score: a whole number below 2^32 whose meaning is the index's. */
  score: bigint
}

/** Where a leaf sits: Semaphore's Merkle proof, as the circuit reads it. */
export type Path = { length: number; index: number; siblings: bigint[] }

export type Tree = {
  /** What the index signs, with a time. */
  root: bigint
  /** The path to the leaf with this key, if the tree has one. */
  pathOf(profile: Point): Path | undefined
}

/** The pinned setup files. Paths on Node, or the bytes themselves in a browser. */
export type Artifacts = {
  wasm: string | Uint8Array
  zkey: string | Uint8Array
}

export type ReputationProof = {
  /** The plain average of the scores of the profiles counted, rounded down. */
  score: bigint
  root: bigint
  /** The key of the profile the proof is shown on. */
  profile: Point
  /** Its address. */
  address: string
  /** The proof as snarkjs wrote it. */
  proof: SnarkjsProof
  publicSignals: string[]
}

/** A leaf's hash: Poseidon(key x, key y, score). */
export function leafHash(leaf: Leaf): bigint {
  return poseidon3([leaf.profile[0], leaf.profile[1], leaf.score])
}

const keyOf = (profile: Point) => `${profile[0]},${profile[1]}`

/**
 * The tree an index publishes: Semaphore's, over the leaves' hashes in the index's order. Refuses
 * an empty tree, one deeper than the circuit, a field out of range, and two leaves for one key.
 */
export function buildTree(leaves: Leaf[]): Tree {
  if (leaves.length === 0) throw new RangeError('a tree has at least one leaf')
  if (leaves.length > 2 ** DEPTH) throw new RangeError(`a tree has at most 2^${DEPTH} leaves`)
  const at = new Map<string, number>()
  leaves.forEach((leaf, i) => {
    // A key is not checked to be a point of the curve: no seed gives one that is not, so such a leaf
    // can never be counted, and holding it harms no proof.
    if (!isFieldElement(leaf.profile[0]) || !isFieldElement(leaf.profile[1])) throw new RangeError(`leaf ${i}: not a field element`)
    if (leaf.score < 0n || leaf.score >= BOUND) throw new RangeError(`leaf ${i}: a score is from 0 to 2^32 - 1`)
    const key = keyOf(leaf.profile)
    if (at.has(key)) throw new Error(`leaf ${i}: a second leaf for one key`)
    at.set(key, i)
  })
  const group = new Group(leaves.map(leafHash))
  return {
    root: group.root,
    pathOf(profile) {
      const i = at.get(keyOf(profile))
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
  /** The labels of the person's profiles to count, one to eight. */
  labels: string[]
  /** The index's published leaves, in its order. */
  leaves: Leaf[]
  /** The label of the profile the proof is shown on, one of the person's. The proof names its key. */
  profileLabel: string
}): { input: Record<string, unknown>; publicSignals: bigint[] } {
  const { labels, seedScalar } = input
  if (!isFieldElement(seedScalar)) throw new RangeError('a seed scalar is a field element')
  if (labels.length < 1 || labels.length > SLOTS) throw new RangeError(`one to ${SLOTS} profiles`)
  if (new Set(labels).size !== labels.length) throw new Error('a label twice')

  const tree = buildTree(input.leaves)
  const byKey = new Map(input.leaves.map((leaf) => [keyOf(leaf.profile), leaf]))

  const slots = labels.map((label) => {
    const key = publicKeyOf(profileScalarOf(seedScalar, label))
    const leaf = byKey.get(keyOf(key))
    const path = tree.pathOf(key)
    if (leaf === undefined || path === undefined) throw new Error(`the tree has no leaf for ${label}`)
    return { scope: scopeOf(label), score: leaf.score, path }
  })

  const score = slots.reduce((n, s) => n + s.score, 0n) / BigInt(slots.length)

  const blank = { scope: 0n, score: 0n, path: { length: 0, index: 0, siblings: [] as bigint[] } }
  const all = [...slots, ...Array(SLOTS - slots.length).fill(blank)] as typeof slots
  const profile = publicKeyOf(profileScalarOf(seedScalar, input.profileLabel))

  return {
    input: {
      seedScalar,
      used: all.map((_, i) => (i < slots.length ? 1 : 0)),
      scopes: all.map((s) => s.scope),
      scores: all.map((s) => s.score),
      pathLengths: all.map((s) => s.path.length),
      pathIndices: all.map((s) => s.path.index),
      // The circuit walks `pathLengths` levels; the rest is padding it never reads.
      pathSiblings: all.map((s) => [...s.path.siblings, ...Array(DEPTH - s.path.siblings.length).fill(0n)]),
      profileScope: scopeOf(input.profileLabel),
      root: tree.root,
      profileX: profile[0],
      profileY: profile[1],
    },
    publicSignals: [score, tree.root, profile[0], profile[1]],
  }
}

/** Make the proof, on the device. */
export async function proveReputation(input: Parameters<typeof circuitInput>[0] & { artifacts: Artifacts }): Promise<ReputationProof> {
  const { input: signals, publicSignals: want } = circuitInput(input)
  const { proof, publicSignals } = (await groth16.fullProve(signals, input.artifacts.wasm, input.artifacts.zkey)) as {
    proof: SnarkjsProof
    publicSignals: string[]
  }
  // The circuit's order: score, root, profile x, profile y. Checked so a change in the circuit or
  // the setup files shows up here, and not as a proof every reader refuses.
  if (publicSignals.length !== 4 || publicSignals.some((s, i) => BigInt(s) !== want[i])) {
    throw new Error('the proof carries other public signals than the ones asked for')
  }
  const [score, root, x, y] = want as [bigint, bigint, bigint, bigint]
  const profile: Point = [x, y]
  return { score, root, profile, address: addressOf(profile), proof, publicSignals }
}

// The proof as a profile record stores it, 256 bytes, and back: the verification client's, which a
// verification uses too (records/README.md, Proofs).
export { proofBytes, proofFromBytes } from '@foundationforest/verification'

/**
 * Does this proof hold, under a root this index signed with this time, on this profile? Checks the
 * index's signature (keys/'s checkBytes over signedBytes), that every public value is in range,
 * and the proof with the committed verification key for this profile's key. The key is derived
 * inside the proof from the same seed as every counted profile, so a proof holds only on a profile
 * of the prover's own. How old a time to accept, and which indexes to trust, is the reader's
 * choice. Anything that is not a good proof for these inputs is false.
 */
export async function checkReputation(input: {
  /** The proof as snarkjs writes it, `proveReputation`'s `proof`, or its 256 bytes (`proofBytes`). */
  proof: SnarkjsProof | Uint8Array
  root: bigint
  score: bigint
  /** The profile that shows the proof: its address, or its key. */
  profile: string | Point
  /** The index's key: its address, or its point on Baby Jubjub. */
  index: string | Point
  /** The time the index signed with the root, in ms. */
  time: bigint | number
  /** The index's signature over `signedBytes(root, time)`: its 64 bytes, R8 packed then S (keys/'s packSignature). */
  signature: Uint8Array
}): Promise<boolean> {
  try {
    const signature = unpackSignature(input.signature)
    if (signature === null || !checkBytes(input.index, signedBytes(input.root, input.time), signature)) return false
    if (input.score < 0n || input.score >= BOUND) return false
    const profile = typeof input.profile === 'string' ? pointOf(input.profile) : pointOf(addressOf(input.profile))
    const publicSignals = [input.score, input.root, profile[0], profile[1]].map(String)
    const proof = input.proof instanceof Uint8Array ? proofFromBytes(input.proof) : input.proof
    return await groth16.verify(REPUTATION_KEY, publicSignals, proof)
  } catch {
    return false
  }
}
