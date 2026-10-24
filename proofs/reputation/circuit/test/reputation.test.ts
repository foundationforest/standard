// The reputation proof, end to end: an index's tree of made-up leaves around keys/'s test person,
// proofs with one slot and with three, from two issuers, shown on another profile of the person's
// own, and every way a proof must fail, a proof lent to someone else's profile among them. The
// tree, what an index signs and what the client refuses on its own are the client's tests
// (../../client/test/).
//
// They need the setup's files: `npm run fetch` first. A missing file fails; nothing skips.

import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { groth16 } from 'snarkjs'

import { BN254_R, issuerSecret, mainKey, nameHashOf, packSignature, scopeOf, seedScalar, serviceKey, signBytes, tagOf } from '@foundationforest/keys'
import { BN254_P, fromBytes32, toBytes32 } from '@foundationforest/note'
import {
  buildTree,
  circuitInput,
  proofBytes,
  proofFromBytes,
  proveReputation,
  signedBytes,
  verifyReputation,
  type Leaf,
} from '@foundationforest/reputation'

const here = dirname(fileURLToPath(import.meta.url))
const artifacts = { wasm: join(here, '../setup/reputation.wasm'), zkey: join(here, '../setup/reputation.zkey') }
const keysVectors = JSON.parse(readFileSync(join(here, '../../../../keys/test/vectors.json'), 'utf8'))
const seed = Uint8Array.from(Buffer.from(keysVectors.seed, 'hex'))
const S = await seedScalar(seed)
const [A, B] = keysVectors.issuers.map((i: { name: string }) => i.name) as [string, string]
const at = { [A]: (await issuerSecret(seed, A)).scalar, [B]: (await issuerSecret(seed, B)).scalar }

// The person's three profiles, two checked by issuer A and one by issuer B, as an index scores them;
// and their tutoring/seller profile's second leaf, at issuer B.
const sources = [
  { label: 'tutoring/seller', issuerName: A },
  { label: 'tutoring/buyer', issuerName: A },
  { label: 'cleaning/seller', issuerName: B },
]
const leafOf = (label: string, issuerName: string, score: bigint, count: bigint): Leaf => ({ tag: tagOf(at[issuerName], label), scope: scopeOf(label), score, count })
const mine = [leafOf(sources[0].label, A, 47n, 12n), leafOf(sources[1].label, A, 39n, 3n), leafOf(sources[2].label, B, 50n, 1n)]
const sellerAtB = leafOf('tutoring/seller', B, 10n, 9n)
const field = () => BigInt('0x' + randomBytes(32).toString('hex')) % BN254_R
const madeUp = (n: number): Leaf[] =>
  Array.from({ length: n }, (_, i) => ({ tag: field(), scope: scopeOf(`made-up/${i}`), score: BigInt(i % 51), count: BigInt(i % 40) }))
const others = madeUp(97)
const leaves = [...others.slice(0, 40), mine[0], ...others.slice(40, 70), mine[1], sellerAtB, mine[2], ...others.slice(70)]
const tree = buildTree(leaves)

// The index signs the root with a time, with its key on Baby Jubjub.
const sign = (key: { scalar: bigint }, root: bigint, at: bigint) => packSignature(signBytes(key.scalar, signedBytes(root, at)))
const indexKey = serviceKey(randomBytes(32))
const index = indexKey.address
const time = 1_791_072_000_000n
const signature = sign(indexKey, tree.root, time)

// The person shows the proof on a new profile of theirs. Someone else has a profile under the same
// label, from their own seed.
const profileLabel = 'tutoring/new'
const profile = await mainKey(seed, profileLabel)
const otherSeed = randomBytes(32)
const stranger = await mainKey(otherSeed, profileLabel)
const strangerScalar = await seedScalar(otherSeed)

const shownOf = (r: Awaited<ReturnType<typeof proveReputation>>) => ({ proof: r.proof, root: r.root, score: r.score, profile: profile.address, index, time, signature })

test("single: one profile, its label shown, its score exactly, on the prover's own profile", async () => {
  const r = await proveReputation({ seedScalar: S, sources: [sources[0]], leaves, profileLabel, show: true, artifacts })
  assert.equal(r.score, 47n)
  assert.equal(r.scope, scopeOf('tutoring/seller'))
  assert.equal(r.address, profile.address, 'the key of the profile it is shown on')
  const shown = shownOf(r)
  assert.equal(await verifyReputation({ ...shown, label: 'tutoring/seller' }), true)
  assert.equal(await verifyReputation(shown), false, 'not as a proof that shows no label')
  assert.equal(await verifyReputation({ ...shown, label: 'cleaning/seller' }), false, 'not for another label')
})

test('global: three profiles from two issuers, no label shown, their count-weighted score rounded down', async () => {
  const r = await proveReputation({ seedScalar: S, sources, leaves, profileLabel, artifacts })
  assert.equal(r.score, (47n * 12n + 39n * 3n + 50n * 1n) / 16n)
  assert.equal(r.scope, 0n)
  const shown = shownOf(r)
  assert.equal(await verifyReputation(shown), true)
  assert.equal(await verifyReputation({ ...shown, profile: profile.publicKey }), true, 'the profile as its key')

  // Each public value is bound: a changed output, root or time fails.
  assert.equal(await verifyReputation({ ...shown, score: r.score + 1n }), false, 'a changed output')
  assert.equal(await verifyReputation({ ...shown, time: time + 1n }), false, 'a time the index did not sign')
  const otherKey = serviceKey(randomBytes(32))
  const forged = { index: otherKey.address, signature: sign(otherKey, r.root, time) }
  assert.equal(await verifyReputation({ ...shown, ...forged }), true, 'any index may sign a root; the reader picks whom to trust')
  assert.equal(await verifyReputation({ ...shown, index: forged.index }), false, 'a root this index did not sign')
  assert.equal(await verifyReputation({ ...shown, index: indexKey.publicKey }), true, 'the index as its key')
  const flipped = signature.slice()
  flipped[40]! ^= 1
  assert.equal(await verifyReputation({ ...shown, signature: flipped }), false, 'a changed signature')
  assert.equal(await verifyReputation({ ...shown, signature: signature.subarray(1) }), false, 'not 64 bytes')
  const otherRoot = buildTree([...leaves, ...madeUp(1)]).root
  const otherSigned = { root: otherRoot, signature: sign(indexKey, otherRoot, time) }
  assert.equal(await verifyReputation({ ...shown, ...otherSigned }), false, 'another root, even one the index signed')
})

test("a proof lands only on the prover's own profile: it cannot be lent", async () => {
  const r = await proveReputation({ seedScalar: S, sources, leaves, profileLabel, artifacts })
  const shown = shownOf(r)
  // Copied, or lent, to someone else's profile, or to another profile of mine: not this proof.
  assert.equal(await verifyReputation({ ...shown, profile: stranger.address }), false, "someone else's profile")
  assert.equal(await verifyReputation({ ...shown, profile: (await mainKey(seed, 'tutoring/seller')).address }), false, 'my other profile')
  // Straight to the circuit: my leaves with the stranger's key, or the stranger's seed with my
  // leaves: no witness. Only a seed that gives both the leaves' tags and the profile's key does.
  const lent = circuitInput({ seedScalar: S, sources, leaves, profileLabel }).input as Record<string, any>
  lent.profileX = stranger.publicKey[0]
  lent.profileY = stranger.publicKey[1]
  await refused(lent)
  const borrowed = circuitInput({ seedScalar: S, sources, leaves, profileLabel }).input as Record<string, any>
  borrowed.seedScalar = strangerScalar
  borrowed.profileX = stranger.publicKey[0]
  borrowed.profileY = stranger.publicKey[1]
  await refused(borrowed)
})

test('the 256 bytes a record stores: the same proof back, and it verifies from them', async () => {
  const r = await proveReputation({ seedScalar: S, sources, leaves, profileLabel, artifacts })
  const { pi_a, pi_b, pi_c } = r.proof
  const bytes = proofBytes(r.proof)
  const order = [pi_a[0], pi_a[1], pi_b[0][1], pi_b[0][0], pi_b[1][1], pi_b[1][0], pi_c[0], pi_c[1]]
  assert.deepEqual(Buffer.from(bytes), Buffer.concat(order.map((s) => toBytes32(BigInt(s)))), "records/'s order")
  assert.deepEqual(proofFromBytes(bytes), { pi_a, pi_b, pi_c })
  const shown = { ...shownOf(r), proof: bytes }
  assert.equal(await verifyReputation(shown), true)

  // A changed byte in any of the eight numbers fails, and so does a number with the modulus added,
  // which snarkjs would read as the same point.
  for (let i = 0; i < 8; i++) {
    const flipped = bytes.slice()
    flipped[i * 32 + 31] ^= 1
    assert.equal(await verifyReputation({ ...shown, proof: flipped }), false, `number ${i}, a byte changed`)
    const plusModulus = bytes.slice()
    plusModulus.set(toBytes32(fromBytes32(bytes.subarray(i * 32, i * 32 + 32)) + BN254_P), i * 32)
    assert.equal(await verifyReputation({ ...shown, proof: plusModulus }), false, `number ${i}, the modulus added`)
  }
  assert.equal(await verifyReputation({ ...shown, proof: bytes.subarray(0, 255) }), false, 'not 256 bytes')
})

// The circuit itself refuses: each case starts from a good input and breaks one thing, past the
// client's own checks.
const good = () => circuitInput({ seedScalar: S, sources: sources.slice(0, 2), leaves, profileLabel }).input as Record<string, any>
const refused = (input: Record<string, unknown>) => assert.rejects(groth16.fullProve(input, artifacts.wasm, artifacts.zkey))

test('the circuit refuses a wrong seed scalar', async () => {
  const input = good()
  input.seedScalar = S + 1n
  await refused(input)
})

test('the circuit refuses a slot with the wrong issuer', async () => {
  const input = good()
  input.issuerNameHashes[1] = nameHashOf(B)
  await refused(input)
})

test('the circuit refuses a leaf not in the tree', async () => {
  const input = good()
  input.scores[0] = 50n
  await refused(input)
})

test('the circuit refuses one profile counted twice, even from two issuers', async () => {
  const input = good()
  // The circuit's own signal names: reputation.circom keeps its bytes, so the tags' is stamps.
  for (const key of ['stamps', 'scopes', 'scores', 'counts', 'pathLengths', 'pathIndices', 'pathSiblings', 'issuerNameHashes']) input[key][1] = input[key][0]
  await refused(input)
  // tutoring/seller's leaf at issuer A and its leaf at issuer B: two tags, one profile.
  const twoIssuers = good()
  const path = tree.pathOf(sellerAtB.tag)!
  twoIssuers.issuerNameHashes[1] = nameHashOf(B)
  twoIssuers.stamps[1] = sellerAtB.tag
  twoIssuers.scopes[1] = sellerAtB.scope
  twoIssuers.scores[1] = sellerAtB.score
  twoIssuers.counts[1] = sellerAtB.count
  twoIssuers.pathLengths[1] = path.length
  twoIssuers.pathIndices[1] = path.index
  twoIssuers.pathSiblings[1] = [...path.siblings, ...Array(20 - path.siblings.length).fill(0n)]
  await refused(twoIssuers)
})

test('the circuit refuses a label shown with two profiles', async () => {
  const input = good()
  input.scope = input.scopes[0]
  await refused(input)
})

test("the circuit refuses a main key that is not the prover's for its label", async () => {
  const otherLabel = good()
  otherLabel.profileScope = scopeOf('tutoring/other')
  await refused(otherLabel)
  const myOtherProfile = good()
  const seller = await mainKey(seed, 'tutoring/seller')
  myOtherProfile.profileX = seller.publicKey[0]
  myOtherProfile.profileY = seller.publicKey[1]
  await refused(myOtherProfile)
})
