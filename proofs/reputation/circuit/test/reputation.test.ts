// The reputation proof, end to end: an index's tree of made-up profiles around keys/'s test person,
// proofs with one slot and with three, shown on another profile of the person's own, and every way
// a proof must fail, a proof lent to someone else's profile among them. The tree, what an index
// signs and what the client refuses on its own are the client's tests (../../client/test/).
//
// They need the setup's files, committed in setup/: `npm run fetch` checks their hashes first. A
// missing file fails; nothing skips.

import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { groth16 } from 'snarkjs'

import { BN254_R, keyScalar, mainKey, packSignature, publicKeyOf, scopeOf, seedScalar, serviceKey, signBytes } from '@foundationforest/keys'
import { BN254_P, fromBytes32, toBytes32 } from '@foundationforest/verification'
import {
  buildTree,
  checkReputation,
  circuitInput,
  proofBytes,
  proofFromBytes,
  proveReputation,
  signedBytes,
  type Leaf,
} from '@foundationforest/reputation'

const here = dirname(fileURLToPath(import.meta.url))
const artifacts = { wasm: join(here, '../setup/reputation.wasm'), zkey: join(here, '../setup/reputation.zkey') }
const keysVectors = JSON.parse(readFileSync(join(here, '../../../../keys/test/vectors.json'), 'utf8'))
const seed = Uint8Array.from(Buffer.from(keysVectors.seed, 'hex'))
const S = await seedScalar(seed)

// Someone else, with their own seed, and a profile under the same label as one of the person's.
const otherSeed = randomBytes(32)
const strangerScalar = await seedScalar(otherSeed)

// The person's three profiles as an index scores them, the stranger's cleaning/buyer profile, and
// made-up profiles.
const labels = ['tutoring/seller', 'tutoring/buyer', 'cleaning/seller']
const leafOf = async (s: Uint8Array, label: string, score: bigint): Promise<Leaf> => ({ profile: (await mainKey(s, label)).publicKey, score })
const mine = [await leafOf(seed, labels[0]!, 47n), await leafOf(seed, labels[1]!, 39n), await leafOf(seed, labels[2]!, 50n)]
const theirs = await leafOf(otherSeed, 'cleaning/buyer', 99n)
const field = () => BigInt('0x' + randomBytes(32).toString('hex')) % BN254_R
const madeUp = (n: number): Leaf[] => Array.from({ length: n }, (_, i) => ({ profile: publicKeyOf(keyScalar(field())), score: BigInt(i % 51) }))
const others = madeUp(97)
const leaves = [...others.slice(0, 40), mine[0]!, ...others.slice(40, 70), mine[1]!, theirs, mine[2]!, ...others.slice(70)]
const tree = buildTree(leaves)

// The index signs the root with a time, with its key on Baby Jubjub.
const sign = (key: { scalar: bigint }, root: bigint, at: bigint) => packSignature(signBytes(key.scalar, signedBytes(root, at)))
const indexKey = serviceKey(randomBytes(32))
const index = indexKey.address
const time = 1_791_072_000_000n
const signature = sign(indexKey, tree.root, time)

// The person shows the proof on a new profile of theirs. The stranger has a profile under the same
// label, from their own seed.
const profileLabel = 'tutoring/new'
const profile = await mainKey(seed, profileLabel)
const stranger = await mainKey(otherSeed, profileLabel)

const shownOf = (r: Awaited<ReturnType<typeof proveReputation>>) => ({ proof: r.proof, root: r.root, score: r.score, profile: profile.address, index, time, signature })

test("one profile: its score exactly, on the prover's own profile", async () => {
  const r = await proveReputation({ seedScalar: S, labels: [labels[0]!], leaves, profileLabel, artifacts })
  assert.equal(r.score, 47n)
  assert.equal(r.address, profile.address, 'the key of the profile it is shown on')
  assert.equal(await checkReputation(shownOf(r)), true)
})

test('three profiles: the plain average of their scores, rounded down', async () => {
  const r = await proveReputation({ seedScalar: S, labels, leaves, profileLabel, artifacts })
  assert.equal(r.score, (47n + 39n + 50n) / 3n)
  const shown = shownOf(r)
  assert.equal(await checkReputation(shown), true)
  assert.equal(await checkReputation({ ...shown, profile: profile.publicKey }), true, 'the profile as its key')

  // Each public value is bound: a changed output, root or time fails.
  assert.equal(await checkReputation({ ...shown, score: r.score + 1n }), false, 'a changed output')
  assert.equal(await checkReputation({ ...shown, score: r.score + 2n ** 32n }), false, 'an output out of range')
  assert.equal(await checkReputation({ ...shown, time: time + 1n }), false, 'a time the index did not sign')
  const otherKey = serviceKey(randomBytes(32))
  const forged = { index: otherKey.address, signature: sign(otherKey, r.root, time) }
  assert.equal(await checkReputation({ ...shown, ...forged }), true, 'any index may sign a root; the reader picks whom to trust')
  assert.equal(await checkReputation({ ...shown, index: forged.index }), false, 'a root this index did not sign')
  assert.equal(await checkReputation({ ...shown, index: indexKey.publicKey }), true, 'the index as its key')
  const flipped = signature.slice()
  flipped[40]! ^= 1
  assert.equal(await checkReputation({ ...shown, signature: flipped }), false, 'a changed signature')
  assert.equal(await checkReputation({ ...shown, signature: signature.subarray(1) }), false, 'not 64 bytes')
  const otherRoot = buildTree([...leaves, ...madeUp(1)]).root
  const otherSigned = { root: otherRoot, signature: sign(indexKey, otherRoot, time) }
  assert.equal(await checkReputation({ ...shown, ...otherSigned }), false, 'another root, even one the index signed')
})

test("a proof lands only on the prover's own profile: it cannot be lent", async () => {
  const r = await proveReputation({ seedScalar: S, labels, leaves, profileLabel, artifacts })
  const shown = shownOf(r)
  // Copied, or lent, to someone else's profile, or to another profile of mine: not this proof.
  assert.equal(await checkReputation({ ...shown, profile: stranger.address }), false, "someone else's profile")
  assert.equal(await checkReputation({ ...shown, profile: (await mainKey(seed, labels[0]!)).address }), false, 'my other profile')
  // Straight to the circuit: my leaves with the stranger's key, or the stranger's seed with my
  // leaves: no witness. Only a seed that gives both the leaves' keys and the profile's key does.
  const lent = circuitInput({ seedScalar: S, labels, leaves, profileLabel }).input as Record<string, any>
  lent.profileX = stranger.publicKey[0]
  lent.profileY = stranger.publicKey[1]
  await refused(lent)
  const borrowed = circuitInput({ seedScalar: S, labels, leaves, profileLabel }).input as Record<string, any>
  borrowed.seedScalar = strangerScalar
  borrowed.profileX = stranger.publicKey[0]
  borrowed.profileY = stranger.publicKey[1]
  await refused(borrowed)
})

test('the 256 bytes a profile entry stores: the same proof back, and it checks from them', async () => {
  const r = await proveReputation({ seedScalar: S, labels, leaves, profileLabel, artifacts })
  const { pi_a, pi_b, pi_c } = r.proof
  const bytes = proofBytes(r.proof)
  const order = [pi_a[0], pi_a[1], pi_b[0][1], pi_b[0][0], pi_b[1][1], pi_b[1][0], pi_c[0], pi_c[1]]
  assert.deepEqual(Buffer.from(bytes), Buffer.concat(order.map((s) => toBytes32(BigInt(s)))), "folders/'s order")
  assert.deepEqual(proofFromBytes(bytes), { pi_a, pi_b, pi_c })
  const shown = { ...shownOf(r), proof: bytes }
  assert.equal(await checkReputation(shown), true)

  // A changed byte in any of the eight numbers fails, and so does a number with the modulus added,
  // which snarkjs would read as the same point.
  for (let i = 0; i < 8; i++) {
    const flipped = bytes.slice()
    flipped[i * 32 + 31] ^= 1
    assert.equal(await checkReputation({ ...shown, proof: flipped }), false, `number ${i}, a byte changed`)
    const plusModulus = bytes.slice()
    plusModulus.set(toBytes32(fromBytes32(bytes.subarray(i * 32, i * 32 + 32)) + BN254_P), i * 32)
    assert.equal(await checkReputation({ ...shown, proof: plusModulus }), false, `number ${i}, the modulus added`)
  }
  assert.equal(await checkReputation({ ...shown, proof: bytes.subarray(0, 255) }), false, 'not 256 bytes')
})

// The circuit itself refuses: each case starts from a good input and breaks one thing, past the
// client's own checks.
const good = () => circuitInput({ seedScalar: S, labels: labels.slice(0, 2), leaves, profileLabel }).input as Record<string, any>
/** What circom's witness generator says when a constraint does not hold: there is nothing to prove. */
const refused = (input: Record<string, unknown>) => assert.rejects(groth16.fullProve(input, artifacts.wasm, artifacts.zkey), /Assert Failed/)

test('the circuit refuses a wrong seed scalar', async () => {
  const input = good()
  input.seedScalar = S + 1n
  await refused(input)
})

test('the circuit refuses a leaf not in the tree', async () => {
  const input = good()
  input.scores[0] = 50n
  await refused(input)
})

test('the circuit refuses a blank slot with a score', async () => {
  const input = good()
  input.scores[2] = 50n
  await refused(input)
})

test('the circuit refuses one profile counted twice', async () => {
  const input = good()
  for (const key of ['scopes', 'scores', 'pathLengths', 'pathIndices', 'pathSiblings']) input[key][1] = input[key][0]
  await refused(input)
})

test("the circuit refuses someone else's profile in a slot", async () => {
  // The stranger's cleaning/buyer leaf, with its path: my seed gives another key for that label.
  const input = good()
  const path = tree.pathOf(theirs.profile)!
  input.scopes[1] = scopeOf('cleaning/buyer')
  input.scores[1] = theirs.score
  input.pathLengths[1] = path.length
  input.pathIndices[1] = path.index
  input.pathSiblings[1] = [...path.siblings, ...Array(20 - path.siblings.length).fill(0n)]
  await refused(input)
})

test("the circuit refuses a main key that is not the prover's for its label", async () => {
  const otherLabel = good()
  otherLabel.profileScope = scopeOf('tutoring/other')
  await refused(otherLabel)
  const myOtherProfile = good()
  const seller = await mainKey(seed, labels[0]!)
  myOtherProfile.profileX = seller.publicKey[0]
  myOtherProfile.profileY = seller.publicKey[1]
  await refused(myOtherProfile)
})

test('the circuit refuses a root of 0 and no slot used', async () => {
  const zero = good()
  zero.root = 0n
  await refused(zero)
  const none = good()
  for (const key of ['used', 'scopes', 'scores', 'pathLengths', 'pathIndices']) none[key] = none[key].map(() => 0)
  await refused(none)
})
