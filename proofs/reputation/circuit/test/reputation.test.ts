// The reputation proof, end to end: an index's tree of made-up leaves around keys/'s test person,
// proofs with one slot and with three shown on the person's own registered profile, and every way a
// proof must fail, a proof aimed at someone else's profile among them. The registry's rows come from
// a stand-in connection, so no chain is needed. The tree, what an index signs and what the client
// refuses on its own are the client's tests (../../client/test/).
//
// They need the devnet setup's files: `npm run fetch` first. A missing file fails; nothing skips.

import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { ed25519 } from '@noble/curves/ed25519.js'
import { groth16 } from 'snarkjs'

import { issuerSecret } from '../../../keys/src/index.ts'
import { BN254_P, BN254_R, fromBytes32, scopeOf, toBytes32 } from '../../../registry/client/src/field.ts'
import { PROGRAM_ID, ROW_DISCRIMINATOR, ROW_OFFSET, rowAddress, rowSpace } from '../../../registry/client/src/program.ts'
import { stampOf } from '../../../registry/client/src/stamp.ts'
import {
  buildTree,
  circuitInput,
  proofBytes,
  proofFromBytes,
  proveReputation,
  signedBytes,
  verifyReputation,
  type Leaf,
} from '../../client/src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
const artifacts = { wasm: join(here, '../devnet/reputation.wasm'), zkey: join(here, '../devnet/reputation.zkey') }
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

// The person shows the proof on a new profile, registered with the same issuer: the registry holds
// its row, naming its main key. Rows are written here by hand, in the layout registry/README.md gives.
const profileLabel = 'tutoring/new'
const profile = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
const rows = new Map<string, Uint8Array>()
function register(label: string, main: Uint8Array, from: Uint8Array = secret) {
  const stamp = stampOf(from, label)
  const text = new TextEncoder().encode(label)
  const row = new Uint8Array(rowSpace(text.length))
  const view = new DataView(row.buffer)
  row.set(ROW_DISCRIMINATOR, 0)
  row.set(main, ROW_OFFSET.profile)
  row.set(toBytes32(stamp), ROW_OFFSET.stamp)
  row.set(toBytes32(1n), ROW_OFFSET.issuer)
  row.set(toBytes32(2n), ROW_OFFSET.issuer + 32)
  row.set(new Uint8Array(32).fill(9), ROW_OFFSET.payer)
  view.setBigInt64(ROW_OFFSET.made, 1_791_000_000n, true)
  view.setUint32(ROW_OFFSET.label, text.length, true)
  row.set(text, ROW_OFFSET.label + 4)
  rows.set(rowAddress(stamp).toBase58(), row)
}
const connection = {
  async getAccountInfo(at: { toBase58(): string }) {
    const data = rows.get(at.toBase58())
    return data ? { data: Buffer.from(data), owner: PROGRAM_ID, lamports: 1, executable: false } : null
  },
} as never
register(profileLabel, profile)
// A stranger's profile, and the stranger's own row.
const strangerProfile = ed25519.getPublicKey(ed25519.utils.randomSecretKey())
const otherPerson = await issuerSecret(randomBytes(32), keysVectors.issuers[0].name)
register(profileLabel, strangerProfile, otherPerson.secret)

test('single: one profile, its label shown, its score exactly, on the prover\'s own profile', async () => {
  const r = await proveReputation({ secret, labels: ['tutoring/seller'], leaves, profileLabel, show: true, artifacts })
  assert.equal(r.score, 47n)
  assert.equal(r.scope, scopeOf('tutoring/seller'))
  assert.equal(r.stamp, stampOf(secret, profileLabel), 'the stamp of the profile it is shown on')
  const shown = { proof: r.proof, root: r.root, score: r.score, stamp: r.stamp, profile, index, time, signature }
  const row = await verifyReputation(connection, { ...shown, label: 'tutoring/seller' })
  assert.equal(row?.label, profileLabel, 'gives the row it landed on')
  assert.equal(await verifyReputation(connection, shown), null, 'not as a proof that shows no label')
  assert.equal(await verifyReputation(connection, { ...shown, label: 'cleaning/seller' }), null, 'not for another label')
})

test('global: three profiles, no label shown, their count-weighted score rounded down', async () => {
  const r = await proveReputation({ secret, labels, leaves, profileLabel, artifacts })
  assert.equal(r.score, (47n * 12n + 39n * 3n + 50n * 1n) / 16n)
  assert.equal(r.scope, 0n)
  const shown = { proof: r.proof, root: r.root, score: r.score, stamp: r.stamp, profile, index, time, signature }
  assert.ok(await verifyReputation(connection, shown))

  // Each public value is bound: a changed output, stamp, root or time fails.
  assert.equal(await verifyReputation(connection, { ...shown, score: r.score + 1n }), null, 'a changed output')
  assert.equal(await verifyReputation(connection, { ...shown, stamp: stampOf(otherPerson.secret, profileLabel) }), null, 'a changed stamp')
  assert.equal(await verifyReputation(connection, { ...shown, time: time + 1n }), null, 'a time the index did not sign')
  const otherKey = ed25519.utils.randomSecretKey()
  const forged = { index: ed25519.getPublicKey(otherKey), signature: ed25519.sign(signedBytes(r.root, time), otherKey) }
  assert.ok(await verifyReputation(connection, { ...shown, ...forged }), 'any index may sign a root; the reader picks whom to trust')
  assert.equal(await verifyReputation(connection, { ...shown, index: forged.index }), null, 'a root this index did not sign')
  const otherRoot = buildTree([...leaves, ...madeUp(1)]).root
  const otherSigned = { root: otherRoot, signature: ed25519.sign(signedBytes(otherRoot, time), indexKey) }
  assert.equal(await verifyReputation(connection, { ...shown, ...otherSigned }), null, 'another root, even one the index signed')
})

test('a proof lands only on the prover\'s own registered profile', async () => {
  const r = await proveReputation({ secret, labels, leaves, profileLabel, artifacts })
  const shown = { proof: r.proof, root: r.root, score: r.score, stamp: r.stamp, profile, index, time, signature }
  assert.ok(await verifyReputation(connection, shown))
  // Copied, or lent, to someone else's profile: the row at its stamp names the prover's main key.
  assert.equal(await verifyReputation(connection, { ...shown, profile: strangerProfile }), null, "someone else's profile")
  // Shown with the stranger's stamp instead, which names the stranger: the proof is not for it.
  assert.equal(await verifyReputation(connection, { ...shown, profile: strangerProfile, stamp: stampOf(otherPerson.secret, profileLabel) }), null, "someone else's stamp")
  // Made for a profile the registry has no row for: it lands nowhere.
  const nowhere = await proveReputation({ secret, labels, leaves, profileLabel: 'tutoring/unregistered', artifacts })
  assert.equal(await verifyReputation(connection, { ...shown, proof: nowhere.proof, stamp: nowhere.stamp }), null, 'a stamp with no row')
})

test('the 256 bytes a record stores: the same proof back, and it verifies from them', async () => {
  const r = await proveReputation({ secret, labels, leaves, profileLabel, artifacts })
  const { pi_a, pi_b, pi_c } = r.proof
  const bytes = proofBytes(r.proof)
  const order = [pi_a[0], pi_a[1], pi_b[0][1], pi_b[0][0], pi_b[1][1], pi_b[1][0], pi_c[0], pi_c[1]]
  assert.deepEqual(Buffer.from(bytes), Buffer.concat(order.map((s) => toBytes32(BigInt(s)))), "records/'s order")
  assert.deepEqual(proofFromBytes(bytes), { pi_a, pi_b, pi_c })
  const shown = { root: r.root, score: r.score, stamp: toBytes32(r.stamp), profile, index, time, signature }
  assert.ok(await verifyReputation(connection, { ...shown, proof: bytes }), 'and the stamp as 32 bytes, as a record carries it')

  // A changed byte in any of the eight numbers fails, and so does a number with the modulus added,
  // which snarkjs would read as the same point.
  for (let i = 0; i < 8; i++) {
    const flipped = bytes.slice()
    flipped[i * 32 + 31] ^= 1
    assert.equal(await verifyReputation(connection, { ...shown, proof: flipped }), null, `number ${i}, a byte changed`)
    const plusModulus = bytes.slice()
    plusModulus.set(toBytes32(fromBytes32(bytes.subarray(i * 32, i * 32 + 32)) + BN254_P), i * 32)
    assert.equal(await verifyReputation(connection, { ...shown, proof: plusModulus }), null, `number ${i}, the modulus added`)
  }
  assert.equal(await verifyReputation(connection, { ...shown, proof: bytes.subarray(0, 255) }), null, 'not 256 bytes')
})

// The circuit itself refuses: each case starts from a good input and breaks one thing, past the
// client's own checks.
const good = () => circuitInput({ secret, labels: labels.slice(0, 2), leaves, profileLabel }).input as Record<string, any>
const refused = (input: Record<string, unknown>) => assert.rejects(groth16.fullProve(input, artifacts.wasm, artifacts.zkey))

test('the circuit refuses a wrong secret', async () => {
  const input = good()
  input.secret = stranger.scalar
  await refused(input)
})

test('the circuit refuses a leaf not in the tree', async () => {
  const input = good()
  input.scores[0] = 50n
  await refused(input)
})

test('the circuit refuses one profile counted twice', async () => {
  const input = good()
  for (const key of ['stamps', 'scopes', 'scores', 'counts', 'pathLengths', 'pathIndices', 'pathSiblings']) input[key][1] = input[key][0]
  await refused(input)
})

test('the circuit refuses a label shown with two profiles', async () => {
  const input = good()
  input.scope = input.scopes[0]
  await refused(input)
})

test('the circuit refuses a stamp that is not from the prover\'s secret', async () => {
  const someoneElse = good()
  someoneElse.stamp = stampOf(otherPerson.secret, profileLabel)
  await refused(someoneElse)
  const myOtherIssuer = good()
  myOtherIssuer.stamp = stampOf(stranger.secret, profileLabel)
  await refused(myOtherIssuer)
  const otherLabel = good()
  otherLabel.profileScope = scopeOf('tutoring/other')
  await refused(otherLabel)
})
