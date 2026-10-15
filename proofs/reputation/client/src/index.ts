// The reputation proof's client: the tree an index publishes, the proof an app makes from it on the
// device, and the check any reader makes. It talks to no network of its own: the caller passes in
// the index's published leaves, root, time and signature, and a connection to Solana to read the
// row of the profile a proof is shown on.
//
// The market stamp and the scope come from the registry client unchanged, so a leaf names a profile
// exactly as its registry row does, and a proof names the row of the profile it is shown on.
//
// Nothing here is in production: the circuit's setup is devnet only (../README.md).

import { ed25519 } from '@noble/curves/ed25519.js'
import { Group } from '@semaphore-protocol/group'
import { poseidon4 } from 'poseidon-lite/poseidon4'
import { groth16 } from 'snarkjs'

import { type SnarkjsProof, proofFromBytes } from '../../../registry/client/src/compress.ts'
import { fromBytes32, isFieldElement, scopeOf, toBytes32 } from '../../../registry/client/src/field.ts'
import { type Row, keyBytes } from '../../../registry/client/src/program.ts'
import { fetchRow } from '../../../registry/client/src/rows.ts'
import { scalarOf, stampOf } from '../../../registry/client/src/stamp.ts'
import { REPUTATION_KEY } from './reputation-key.ts'

/** An issuer secret: the 32 bytes `keys/`'s `issuerSecret(seed, name)` returns. */
type Secret = Uint8Array
/** A 32-byte ed25519 key: a main key or an index's key. */
type Key = Parameters<typeof keyBytes>[0]

/** The circuit's slots: a proof counts up to this many profiles. */
export const SLOTS = 8
/** The circuit's depth: a tree holds at most 2^DEPTH leaves. */
export const DEPTH = 20
/** Every score and count is below this. */
export const BOUND = 2n ** 32n
/** What an index's signature starts with. 0xff starts no Solana message; the text no other signature. */
export const SIGNED_PREFIX = 'forest/v1/reputation\n'

/** One profile in an index's tree. */
export type Leaf = {
  /** The profile's market stamp: its registry row's seed. */
  stamp: bigint
  /** The scope of the profile's label, as the registry computes it (`scopeOf`). */
  scope: bigint
  /** The index's score for the profile, times ten. */
  score: bigint
  /** How many reviews the score comes from. */
  count: bigint
}

/** Where a leaf sits: Semaphore's Merkle proof, as the circuit reads it. */
export type Path = { length: number; index: number; siblings: bigint[] }

export type Tree = {
  /** What the index signs, with a time. */
  root: bigint
  /** The path to the leaf with this market stamp, if the tree has one. */
  pathOf(stamp: bigint): Path | undefined
}

/** The pinned setup files. Paths on Node, or the bytes themselves in a browser. */
export type Artifacts = {
  wasm: string | Uint8Array
  zkey: string | Uint8Array
}

export type ReputationProof = {
  /** The count-weighted score of the profiles counted, times ten, rounded down. */
  score: bigint
  root: bigint
  /** The stamp of the profile the proof is shown on: its registry row's. */
  stamp: bigint
  /** The scope shown, or 0. */
  scope: bigint
  /** The proof as snarkjs wrote it. */
  proof: SnarkjsProof
  publicSignals: string[]
}

/** A leaf's hash: Poseidon(stamp, scope, score, count). */
export function leafHash(leaf: Leaf): bigint {
  return poseidon4([leaf.stamp, leaf.scope, leaf.score, leaf.count])
}

/**
 * The tree an index publishes: Semaphore's, the kind an issuer's list is, over the leaves' hashes in
 * the index's order. Refuses an empty tree, one deeper than the circuit, a field out of range, and
 * two leaves for one market stamp.
 */
export function buildTree(leaves: Leaf[]): Tree {
  if (leaves.length === 0) throw new RangeError('a tree has at least one leaf')
  if (leaves.length > 2 ** DEPTH) throw new RangeError(`a tree has at most 2^${DEPTH} leaves`)
  const at = new Map<bigint, number>()
  leaves.forEach((leaf, i) => {
    if (!isFieldElement(leaf.stamp) || !isFieldElement(leaf.scope)) throw new RangeError(`leaf ${i}: not a field element`)
    if (leaf.score < 0n || leaf.score >= BOUND || leaf.count < 0n || leaf.count >= BOUND) {
      throw new RangeError(`leaf ${i}: a score and a count are each from 0 to 2^32 - 1`)
    }
    if (at.has(leaf.stamp)) throw new Error(`leaf ${i}: a second leaf for one market stamp`)
    at.set(leaf.stamp, i)
  })
  const group = new Group(leaves.map(leafHash))
  return {
    root: group.root,
    pathOf(stamp) {
      const i = at.get(stamp)
      if (i === undefined) return undefined
      const proof = group.generateMerkleProof(i)
      return { length: proof.siblings.length, index: proof.index, siblings: proof.siblings }
    },
  }
}

/** What an index signs: 0xff, its text, the root as 32 big-endian bytes, the time as 8 (ms). */
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
  /** The person's secret for one issuer. */
  secret: Secret
  /** The labels of the person's profiles from that issuer to count: one to eight. */
  labels: string[]
  /** The index's published leaves, in its order. */
  leaves: Leaf[]
  /**
   * The label of the profile the proof is shown on: one of the person's profiles registered with
   * this issuer. The proof names its stamp, so it counts on that profile alone.
   */
  profileLabel: string
  /** Show the label. Only with one label. */
  show?: boolean
}): { input: Record<string, unknown>; publicSignals: bigint[] } {
  const { labels } = input
  if (labels.length < 1 || labels.length > SLOTS) throw new RangeError(`one to ${SLOTS} labels`)
  if (new Set(labels).size !== labels.length) throw new Error('a label twice')
  if (input.show && labels.length !== 1) throw new Error('a label is shown only when it is the only one')

  const scalar = scalarOf(input.secret)
  const tree = buildTree(input.leaves)
  const byStamp = new Map(input.leaves.map((leaf) => [leaf.stamp, leaf]))

  const slots = labels.map((label) => {
    const stamp = stampOf(input.secret, label)
    const leaf = byStamp.get(stamp)
    const path = tree.pathOf(stamp)
    if (leaf === undefined || path === undefined) throw new Error(`the tree has no leaf for ${label}`)
    return { leaf, path }
  })

  const countSum = slots.reduce((n, s) => n + s.leaf.count, 0n)
  if (countSum === 0n) throw new Error('no reviews to count')
  const score = slots.reduce((n, s) => n + s.leaf.score * s.leaf.count, 0n) / countSum

  const blank = { leaf: { stamp: 0n, scope: 0n, score: 0n, count: 0n }, path: { length: 0, index: 0, siblings: [] as bigint[] } }
  const all = [...slots, ...Array(SLOTS - slots.length).fill(blank)] as typeof slots
  const scope = input.show ? scopeOf(labels[0]) : 0n
  const profileScope = scopeOf(input.profileLabel)
  const stamp = stampOf(input.secret, input.profileLabel)

  return {
    input: {
      secret: scalar,
      used: all.map((_, i) => (i < slots.length ? 1 : 0)),
      stamps: all.map((s) => s.leaf.stamp),
      scopes: all.map((s) => s.leaf.scope),
      scores: all.map((s) => s.leaf.score),
      counts: all.map((s) => s.leaf.count),
      pathLengths: all.map((s) => s.path.length),
      pathIndices: all.map((s) => s.path.index),
      // The circuit walks `pathLengths` levels; the rest is padding it never reads.
      pathSiblings: all.map((s) => [...s.path.siblings, ...Array(DEPTH - s.path.siblings.length).fill(0n)]),
      profileScope,
      root: tree.root,
      stamp,
      scope,
    },
    publicSignals: [score, tree.root, stamp, scope],
  }
}

/** Make the proof, on the device. */
export async function proveReputation(input: Parameters<typeof circuitInput>[0] & { artifacts: Artifacts }): Promise<ReputationProof> {
  const { input: signals, publicSignals: want } = circuitInput(input)
  const { proof, publicSignals } = (await groth16.fullProve(signals, input.artifacts.wasm, input.artifacts.zkey)) as {
    proof: SnarkjsProof
    publicSignals: string[]
  }
  // The circuit's order: score, root, stamp, scope. Checked so a change in the circuit or the
  // setup files shows up here, and not as a proof every reader refuses.
  if (publicSignals.length !== 4 || publicSignals.some((s, i) => BigInt(s) !== want[i])) {
    throw new Error('the proof carries other public signals than the ones asked for')
  }
  const [score, root, stamp, scope] = want
  return { score, root, stamp, scope, proof, publicSignals }
}

// The proof as a profile record stores it, 256 bytes, and back: the registry client's, which a
// person proof uses too (records/README.md, Proofs).
export { proofBytes, proofFromBytes } from '../../../registry/client/src/compress.ts'

/**
 * Does this proof hold, under a root this index signed with this time, on this profile? Checks the
 * index's signature (strict ed25519, as `records/` checks every record), that every public value is
 * in range, the proof with the committed verification key for this stamp and, if one is given, this
 * shown label; then that the registry row at the stamp names this profile. So a proof counts only on
 * the profile it was made for, the prover's own. Gives the row, so the reader can weigh its issuer,
 * whose secret every counted profile shares, and when it was made; null when anything fails. Throws
 * when the connection does, or when what sits at the stamp's address is not the registry's. How old
 * a time to accept, and which indexes and issuers to trust, is the reader's choice.
 */
export async function verifyReputation(
  connection: Parameters<typeof fetchRow>[0],
  input: {
    /** The proof as snarkjs writes it, `proveReputation`'s `proof`, or its 256 bytes (`proofBytes`). */
    proof: SnarkjsProof | Uint8Array
    root: bigint
    score: bigint
    /** The stamp the proof shows: the registry row of the profile it is shown on. */
    stamp: bigint | Uint8Array
    /** The main key of the profile that shows the proof. */
    profile: Key
    /** The label shown, if the proof shows one. */
    label?: string
    /** The index's ed25519 key. */
    index: Key
    /** The time the index signed with the root, in ms. */
    time: bigint | number
    /** The index's signature over `signedBytes(root, time)`. */
    signature: Uint8Array
  },
  options: Parameters<typeof fetchRow>[2] = {},
): Promise<Row | null> {
  let stamp: bigint
  try {
    const index = keyBytes(input.index)
    if (input.signature.length !== 64) return null
    if (!ed25519.verify(input.signature, signedBytes(input.root, input.time), index, { zip215: false })) return null
    if (input.score < 0n || input.score >= BOUND) return null
    stamp = typeof input.stamp === 'bigint' ? input.stamp : fromBytes32(input.stamp)
    if (!isFieldElement(stamp)) return null
    const scope = input.label === undefined ? 0n : scopeOf(input.label)
    const publicSignals = [input.score, input.root, stamp, scope].map(String)
    const proof = input.proof instanceof Uint8Array ? proofFromBytes(input.proof) : input.proof
    if (!(await groth16.verify(REPUTATION_KEY, publicSignals, proof))) return null
  } catch {
    return null
  }
  const row = await fetchRow(connection, stamp, options)
  const profile = keyBytes(input.profile)
  if (!row || row.stamp !== stamp || !keyBytes(row.profile).every((b, i) => b === profile[i])) return null
  return row
}
