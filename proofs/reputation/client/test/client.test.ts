// The reputation client without the setup's files: the tree an index publishes, what it signs,
// what the client refuses before any proof is made, and the verification key it checks with. The
// proofs themselves are the circuit's tests (../../circuit/test/).

import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { ed25519 } from '@noble/curves/ed25519.js'
import { Group } from '@semaphore-protocol/group'
import { poseidon4 } from 'poseidon-lite/poseidon4'

import { issuerSecret } from '../../../keys/src/index.ts'
import { BN254_R, scopeOf } from '../../../registry/client/src/field.ts'
import { stampOf } from '../../../registry/client/src/stamp.ts'
import { PROGRAM_ID } from '../../../registry/client/src/program.ts'
import { base58 } from '../../../registry/client/src/rows.ts'
import { BOUND, DEPTH, SIGNED_PREFIX, buildTree, circuitInput, leafHash, signedBytes, verifyReputation, type Leaf } from '../src/index.ts'
import { REPUTATION_KEY } from '../src/reputation-key.ts'

const here = dirname(fileURLToPath(import.meta.url))
const keysVectors = JSON.parse(readFileSync(join(here, '../../../keys/test/vectors.json'), 'utf8'))
const seed = Buffer.from(keysVectors.seed, 'hex')
const secret = (await issuerSecret(seed, keysVectors.issuers[0].name)).secret
const stranger = await issuerSecret(seed, keysVectors.issuers[1].name)

// The person's three profiles from the first issuer, as an index scores them.
const labels = ['tutoring/seller', 'tutoring/buyer', 'cleaning/seller']
const mine: Leaf[] = labels.map((label, i) => ({
  stamp: stampOf(secret, label),
  scope: scopeOf(label),
  score: [47n, 39n, 50n][i],
  count: [12n, 3n, 1n][i],
}))
const field = () => BigInt('0x' + randomBytes(32).toString('hex')) % BN254_R
const madeUp = (n: number): Leaf[] =>
  Array.from({ length: n }, (_, i) => ({ stamp: field(), scope: scopeOf(`made-up/${i}`), score: BigInt(i % 51), count: BigInt(i % 40) }))
const others = madeUp(97)
const leaves = [...others.slice(0, 40), mine[0], ...others.slice(40, 70), mine[1], mine[2], ...others.slice(70)]
const tree = buildTree(leaves)

// The index signs the root with a time.
const indexKey = ed25519.utils.randomSecretKey()
const index = ed25519.getPublicKey(indexKey)
const time = 1_791_072_000_000n
const signature = ed25519.sign(signedBytes(tree.root, time), indexKey)

// The person shows the proof on a new profile, registered with the same issuer.
const profileLabel = 'tutoring/new'

test('a leaf is Poseidon(stamp, scope, score, count), and the tree is Semaphore\'s over them', () => {
  assert.equal(leafHash(mine[0]), poseidon4([mine[0].stamp, mine[0].scope, 47n, 12n]))
  assert.equal(tree.root, new Group(leaves.map(leafHash)).root)
  const path = tree.pathOf(mine[1].stamp)
  assert.ok(path)
  assert.equal(path.length, path.siblings.length)
  assert.ok(path.length <= DEPTH)
  assert.equal(tree.pathOf(field()), undefined)
})

test('buildTree refuses an empty tree, one too deep, a field out of range, and two leaves for one stamp', () => {
  assert.throws(() => buildTree([]), /at least one leaf/)
  assert.throws(() => buildTree(Array(2 ** DEPTH + 1).fill(mine[0])), /at most 2\^20/)
  assert.throws(() => buildTree([{ ...mine[0], score: BOUND }]), /0 to 2\^32 - 1/)
  assert.throws(() => buildTree([{ ...mine[0], count: -1n }]), /0 to 2\^32 - 1/)
  assert.throws(() => buildTree([{ ...mine[0], stamp: BN254_R }]), /field element/)
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
})

test('the client refuses what the circuit would', () => {
  assert.throws(() => circuitInput({ secret: stranger.secret, labels: ['tutoring/seller'], leaves, profileLabel }), /no leaf/)
  assert.throws(() => circuitInput({ secret, labels: labels.slice(0, 2), leaves, profileLabel, show: true }), /only one/)
  assert.throws(() => circuitInput({ secret, labels: [labels[0], labels[0]], leaves, profileLabel }), /twice/)
  assert.throws(() => circuitInput({ secret, labels: Array.from({ length: 9 }, (_, i) => `x/${i}`), leaves, profileLabel }), /one to 8/)
})

test('the proof names the stamp of the profile it is shown on, from the same secret', () => {
  const { input, publicSignals } = circuitInput({ secret, labels, leaves, profileLabel })
  assert.equal(publicSignals[2], stampOf(secret, profileLabel), 'score, root, stamp, scope')
  assert.equal(input.stamp, stampOf(secret, profileLabel))
  assert.equal(input.profileScope, scopeOf(profileLabel))
  assert.notEqual(publicSignals[2], stampOf(stranger.secret, profileLabel), 'another issuer, another stamp')
  assert.equal('message' in input, false, 'no main key in the proof: the stamp names the profile')
})

test('the verification key is the circuit setup\'s, value for value', () => {
  const committed = JSON.parse(readFileSync(join(here, '../../circuit/devnet/verification-key.json'), 'utf8'))
  assert.deepEqual(REPUTATION_KEY, committed)
  assert.equal(REPUTATION_KEY.nPublic, 4)
})

test('a reputation proof as a profile shows it (records/schemas/examples/profile.json): verifyReputation takes it as it is', async () => {
  // The example card is keys/'s tutoring/seller. Its row is the one the registry's tests landed for
  // it (registry/program/tests-litesvm/fixtures/proofs.json), at the stamp its person proof shows.
  const card = JSON.parse(readFileSync(join(here, '../../../records/schemas/examples/profile.json'), 'utf8'))
  const shown = card.proofs.find((p: { circuit: string }) => p.circuit === 'reputation')
  assert.equal(shown.stamp, card.proofs.find((p: { circuit: string }) => p.circuit === 'person').stamp, 'the same row as its person proof')
  const fixtures = JSON.parse(readFileSync(join(here, '../../../registry/program/tests-litesvm/fixtures/proofs.json'), 'utf8'))
  const w = fixtures.wire
  const connection = {
    async getAccountInfo(at: { toBase58(): string }) {
      return at.toBase58() === w.rowAddress ? { data: Buffer.from(w.row, 'hex'), owner: PROGRAM_ID, lamports: 1, executable: false } : null
    },
  } as never
  const seller = keysVectors.mainKeys[0]
  const index = ed25519.getPublicKey(new Uint8Array(32).fill(0x2c)) // the example index's key: 32 bytes of 0x2c
  assert.equal(base58(index), shown.index)
  const input = {
    proof: new Uint8Array(Buffer.from(shown.proof, 'base64url')),
    root: BigInt('0x' + shown.root),
    score: BigInt(shown.score),
    stamp: new Uint8Array(Buffer.from(shown.stamp, 'hex')),
    profile: ed25519.getPublicKey(Buffer.from(seller.privateKey, 'hex')),
    index,
    time: shown.time,
    signature: new Uint8Array(Buffer.from(shown.signature, 'base64url')),
  }
  const row = await verifyReputation(connection, input)
  assert.equal(row?.label, 'tutoring/seller')
  assert.equal(await verifyReputation(connection, { ...input, profile: ed25519.getPublicKey(Buffer.from(keysVectors.mainKeys[1].privateKey, 'hex')) }), null, 'not on the buyer profile')
  assert.equal(await verifyReputation(connection, { ...input, score: input.score - 1n }), null, 'not with another score')
})
