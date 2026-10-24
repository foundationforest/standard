// The reputation client without the setup's files: the tree an index publishes, what it signs,
// what the client refuses before any proof is made, the constants the circuit shares with keys/,
// and the verification key it checks with. The proofs themselves are the circuit's tests
// (../../circuit/test/).

import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { Group } from '@semaphore-protocol/group'
import { poseidon4 } from 'poseidon-lite/poseidon4'

import { BN254_R, PREFIX, issuerSecret, mainKey, nameHashOf, packSignature, publicKeyOf, scopeOf, seedScalar, serviceKey, signBytes, tagOf, verifyBytes } from '@foundationforest/keys'
import { BOUND, DEPTH, SIGNED_PREFIX, buildTree, circuitInput, leafHash, signedBytes, type Leaf } from '../src/index.ts'
import { REPUTATION_KEY } from '../src/reputation-key.ts'

const here = dirname(fileURLToPath(import.meta.url))
const keysVectors = JSON.parse(readFileSync(join(here, '../../../../keys/test/vectors.json'), 'utf8'))
const seed = Uint8Array.from(Buffer.from(keysVectors.seed, 'hex'))
const S = await seedScalar(seed)
const [A, B] = keysVectors.issuers.map((i: { name: string }) => i.name) as [string, string]
const at = { [A]: (await issuerSecret(seed, A)).scalar, [B]: (await issuerSecret(seed, B)).scalar }

// The person's three profiles, two checked by issuer A and one by issuer B, as an index scores them.
const sources = [
  { label: 'tutoring/seller', issuerName: A },
  { label: 'tutoring/buyer', issuerName: A },
  { label: 'cleaning/seller', issuerName: B },
]
const mine: Leaf[] = sources.map((s, i) => ({
  tag: tagOf(at[s.issuerName], s.label),
  scope: scopeOf(s.label),
  score: [47n, 39n, 50n][i],
  count: [12n, 3n, 1n][i],
}))
const field = () => BigInt('0x' + randomBytes(32).toString('hex')) % BN254_R
const madeUp = (n: number): Leaf[] =>
  Array.from({ length: n }, (_, i) => ({ tag: field(), scope: scopeOf(`made-up/${i}`), score: BigInt(i % 51), count: BigInt(i % 40) }))
const others = madeUp(97)
const leaves = [...others.slice(0, 40), mine[0], ...others.slice(40, 70), mine[1], mine[2], ...others.slice(70)]
const tree = buildTree(leaves)

// The index signs the root with a time, with its key on Baby Jubjub.
const indexKey = serviceKey(randomBytes(32))
const time = 1_791_072_000_000n

// The person shows the proof on a new profile of theirs.
const profileLabel = 'tutoring/new'

test("a leaf is Poseidon(tag, scope, score, count), and the tree is Semaphore's over them", () => {
  assert.equal(leafHash(mine[0]), poseidon4([mine[0].tag, mine[0].scope, 47n, 12n]))
  assert.equal(tree.root, new Group(leaves.map(leafHash)).root)
  const path = tree.pathOf(mine[1].tag)
  assert.ok(path)
  assert.equal(path.length, path.siblings.length)
  assert.ok(path.length <= DEPTH)
  assert.equal(tree.pathOf(field()), undefined)
})

test('buildTree refuses an empty tree, one too deep, a field out of range, and two leaves for one tag', () => {
  assert.throws(() => buildTree([]), /at least one leaf/)
  assert.throws(() => buildTree(Array(2 ** DEPTH + 1).fill(mine[0])), /at most 2\^20/)
  assert.throws(() => buildTree([{ ...mine[0], score: BOUND }]), /0 to 2\^32 - 1/)
  assert.throws(() => buildTree([{ ...mine[0], count: -1n }]), /0 to 2\^32 - 1/)
  assert.throws(() => buildTree([{ ...mine[0], tag: BN254_R }]), /field element/)
  assert.throws(() => buildTree([mine[0], { ...mine[0], score: 50n }]), /second leaf/)
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
  assert.ok(verifyBytes(indexKey.address, bytes, signature), 'signed as a record is: keys/\'s signBytes')
  assert.equal(packSignature(signature).length, 64)
})

test('the client refuses what the circuit would', () => {
  const one = [sources[0]]
  assert.throws(() => circuitInput({ seedScalar: S, sources: [{ ...sources[0], issuerName: B }], leaves, profileLabel }), /no leaf/, 'the wrong issuer for a leaf')
  assert.throws(() => circuitInput({ seedScalar: S + 1n, sources: one, leaves, profileLabel }), /no leaf/, 'another seed')
  assert.throws(() => circuitInput({ seedScalar: S, sources: sources.slice(0, 2), leaves, profileLabel, show: true }), /only one/)
  assert.throws(() => circuitInput({ seedScalar: S, sources: [sources[0], { ...sources[0], issuerName: B }], leaves, profileLabel }), /twice/)
  assert.throws(() => circuitInput({ seedScalar: S, sources: Array.from({ length: 9 }, (_, i) => ({ label: `x/${i}`, issuerName: A })), leaves, profileLabel }), /one to 8/)
  assert.throws(() => circuitInput({ seedScalar: BN254_R, sources: one, leaves, profileLabel }), /field element/)
})

test("the proof names the key of the profile it is shown on, keys/'s main key, and each slot its issuer", async () => {
  const { input, publicSignals } = circuitInput({ seedScalar: S, sources, leaves, profileLabel })
  const profile = await mainKey(seed, profileLabel)
  assert.deepEqual(publicSignals.slice(1, 4), [tree.root, ...profile.publicKey], 'score, root, profile x, profile y, scope')
  assert.equal(publicSignals[0], (47n * 12n + 39n * 3n + 50n * 1n) / 16n)
  assert.equal(publicSignals[4], 0n, 'no label shown')
  assert.equal(input.profileScope, scopeOf(profileLabel))
  assert.deepEqual(input.issuerNameHashes, [nameHashOf(A), nameHashOf(A), nameHashOf(B), 0n, 0n, 0n, 0n, 0n])
  assert.equal('tag' in input, false, 'no tag of the profile shown on: its key is what names it')
  const shown = circuitInput({ seedScalar: S, sources: [sources[2]], leaves, profileLabel, show: true }).publicSignals
  assert.equal(shown[4], scopeOf('cleaning/seller'))
})

test("the circuit's constants are keys/'s: the issuer and profile prefixes, and Base8", () => {
  const circuit = readFileSync(join(here, '../../circuit/reputation.circom'), 'utf8')
  // reputation.circom keeps its bytes, the names of its constants among them: ISSUER_TAG and
  // PROFILE_TAG are the prefixes.
  assert.ok(circuit.includes(`var ISSUER_TAG = ${PREFIX.issuer};`))
  assert.ok(circuit.includes(`var PROFILE_TAG = ${PREFIX.profile};`))
  const [x, y] = publicKeyOf(1n)
  assert.ok(circuit.includes(`${x},\n        ${y}\n    ];`))
})

test("the verification key is the circuit setup's, value for value", () => {
  const committed = JSON.parse(readFileSync(join(here, '../../circuit/setup/verification-key.json'), 'utf8'))
  assert.deepEqual(REPUTATION_KEY, committed)
  assert.equal(REPUTATION_KEY.nPublic, 5)
})
