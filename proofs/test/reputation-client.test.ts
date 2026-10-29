// The reputation client without the setup's files: the tree an index publishes, what it signs,
// what the client refuses before any proof is made, the constants the circuit shares with keys/,
// and the verification key it checks with. The proofs themselves are the circuit's tests
// (reputation.test.ts).

import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { Group } from '@semaphore-protocol/group'
import { poseidon3 } from 'poseidon-lite/poseidon3'

import { BN254_R, PREFIX, checkBytes, keyScalar, mainKey, packSignature, publicKeyOf, scopeOf, seedScalar, serviceKey, signBytes } from '@foundationforest/keys'
import { BOUND, DEPTH, SIGNED_PREFIX, buildTree, reputationInput, leafHash, signedBytes, type Leaf } from '../src/index.ts'
import { REPUTATION_KEY } from '../src/reputation-key.ts'

const here = dirname(fileURLToPath(import.meta.url))
const keysVectors = JSON.parse(readFileSync(join(here, '../../keys/test/vectors.json'), 'utf8'))
const seed = Uint8Array.from(Buffer.from(keysVectors.seed, 'hex'))
const S = await seedScalar(seed)

// The person's three profiles, as an index scores them, among made-up profiles.
const labels = ['tutoring/seller', 'tutoring/buyer', 'cleaning/seller']
const mine: Leaf[] = await Promise.all(labels.map(async (label, i) => ({ profile: (await mainKey(seed, label)).publicKey, score: [47n, 39n, 50n][i]! })))
const field = () => BigInt('0x' + randomBytes(32).toString('hex')) % BN254_R
const madeUp = (n: number): Leaf[] => Array.from({ length: n }, (_, i) => ({ profile: publicKeyOf(keyScalar(field())), score: BigInt(i % 51) }))
const others = madeUp(97)
const leaves = [...others.slice(0, 40), mine[0]!, ...others.slice(40, 70), mine[1]!, mine[2]!, ...others.slice(70)]
const tree = buildTree(leaves)

// The index signs the root with a time, with its key on Baby Jubjub.
const indexKey = serviceKey(randomBytes(32))
const time = 1_791_072_000_000n

// The person shows the proof on a new profile of theirs.
const profileLabel = 'tutoring/new'

test("a leaf is Poseidon(key x, key y, score), and the tree is Semaphore's over them", () => {
  assert.equal(leafHash(mine[0]!), poseidon3([...mine[0]!.profile, 47n]))
  assert.equal(tree.root, new Group(leaves.map(leafHash)).root)
  const path = tree.pathOf(mine[1]!.profile)
  assert.ok(path)
  assert.equal(path.length, path.siblings.length)
  assert.ok(path.length <= DEPTH)
  assert.equal(tree.pathOf(publicKeyOf(keyScalar(field()))), undefined)
})

test('buildTree refuses an empty tree, one too deep, a field out of range, and two leaves for one key', () => {
  assert.throws(() => buildTree([]), /at least one leaf/)
  assert.throws(() => buildTree(Array(2 ** DEPTH + 1).fill(mine[0])), /at most 2\^20/)
  assert.throws(() => buildTree([{ ...mine[0]!, score: BOUND }]), /0 to 2\^32 - 1/)
  assert.throws(() => buildTree([{ ...mine[0]!, score: -1n }]), /0 to 2\^32 - 1/)
  assert.throws(() => buildTree([{ ...mine[0]!, profile: [BN254_R, mine[0]!.profile[1]] }]), /field element/)
  assert.throws(() => buildTree([mine[0]!, { ...mine[0]!, score: 50n }]), /second leaf/)
})

test('an index signs 0xff, its text, the root as 32 bytes and the time as 8, both big-endian', () => {
  const bytes = signedBytes(tree.root, time)
  const text = Buffer.from(SIGNED_PREFIX)
  assert.equal(bytes.length, 1 + text.length + 32 + 8)
  assert.equal(bytes[0], 0xff)
  assert.deepEqual(Buffer.from(bytes.subarray(1, 1 + text.length)), text)
  assert.equal(BigInt('0x' + Buffer.from(bytes.subarray(1 + text.length, -8)).toString('hex')), tree.root)
  assert.equal(Buffer.from(bytes.subarray(-8)).readBigUInt64BE(), time)
  const signature = signBytes(indexKey.scalar, bytes)
  assert.ok(checkBytes(indexKey.address, bytes, signature), 'signed as an entry is: keys/\'s signBytes')
  assert.equal(packSignature(signature).length, 64)
})

test('the client refuses what the circuit would', () => {
  assert.throws(() => reputationInput({ seedScalar: S, labels: ['tutoring/other'], leaves, profileLabel }), /no leaf/, 'a profile the tree does not hold')
  assert.throws(() => reputationInput({ seedScalar: S + 1n, labels: [labels[0]!], leaves, profileLabel }), /no leaf/, 'another seed')
  assert.throws(() => reputationInput({ seedScalar: S, labels: [labels[0]!, labels[0]!], leaves, profileLabel }), /twice/)
  assert.throws(() => reputationInput({ seedScalar: S, labels: [], leaves, profileLabel }), /one to 8/)
  assert.throws(() => reputationInput({ seedScalar: S, labels: Array.from({ length: 9 }, (_, i) => `x/${i}`), leaves, profileLabel }), /one to 8/)
  assert.throws(() => reputationInput({ seedScalar: BN254_R, labels: [labels[0]!], leaves, profileLabel }), /field element/)
})

test("the proof names the key of the profile it is shown on, keys/'s main key, and the plain average", async () => {
  const { input, publicSignals } = reputationInput({ seedScalar: S, labels, leaves, profileLabel })
  const profile = await mainKey(seed, profileLabel)
  assert.deepEqual(publicSignals, [(47n + 39n + 50n) / 3n, tree.root, ...profile.publicKey], 'score, root, profile x, profile y')
  assert.equal(input.profileScope, scopeOf(profileLabel))
  assert.deepEqual(input.scopes, [...labels.map(scopeOf), 0n, 0n, 0n, 0n, 0n])
  assert.deepEqual(input.used, [1, 1, 1, 0, 0, 0, 0, 0])
  assert.equal(reputationInput({ seedScalar: S, labels: [labels[2]!], leaves, profileLabel }).publicSignals[0], 50n, 'one profile: its score')
})

test("the circuit's constants are keys/'s: the profile prefix, and Base8", () => {
  const circuit = readFileSync(join(here, '../reputation/reputation.circom'), 'utf8')
  assert.ok(circuit.includes(`var PROFILE_PREFIX = ${PREFIX.profile};`))
  const [x, y] = publicKeyOf(1n)
  assert.ok(circuit.includes(`${x},\n        ${y}\n    ];`))
})

test("the verification key is the circuit setup's, value for value", () => {
  const committed = JSON.parse(readFileSync(join(here, '../reputation/setup/verification-key.json'), 'utf8'))
  assert.deepEqual(REPUTATION_KEY, committed)
  assert.equal(REPUTATION_KEY.nPublic, 4)
})
