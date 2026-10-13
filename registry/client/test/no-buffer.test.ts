// The registration path as a browser runs it: with no Buffer. Node's global is taken away before
// the client loads; then the instructions against the program's wire vectors, and a registration
// from a real note, its transaction serialized and read back.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

// To this client and keys/, Buffer is undefined. Node's internals and the dependencies still see
// it: Node loads the dependencies' Node builds (web3.js's uses it), where a browser's bundler takes
// their browser builds.
const buffer = globalThis.Buffer
Object.defineProperty(globalThis, 'Buffer', { configurable: true, get: () => (/\(node:|at node:|\/node_modules\//.test(new Error().stack?.split('\n')[2] ?? '') ? buffer : undefined) })
const { bytesToHex, hexToBytes } = await import('@noble/hashes/utils.js')
const { sha256 } = await import('@noble/hashes/sha2.js')
const { Keypair, PublicKey, VersionedTransaction } = await import('@solana/web3.js')
const { issuerSecret } = await import('../../../keys/src/index.ts')
const { buildRegistration, fromBytes32, noteNumberOf, refundIx, registerIx, rowAddress, signNote } = await import('../src/index.ts')

const here = dirname(fileURLToPath(import.meta.url))
const fixtures = JSON.parse(readFileSync(join(here, '../../program/tests-litesvm/fixtures/proofs.json'), 'utf8'))
const keysVectors = JSON.parse(readFileSync(join(here, '../../../keys/test/vectors.json'), 'utf8'))
const artifacts = { wasm: join(here, '../../circuit/devnet/person.wasm'), zkey: join(here, '../../circuit/devnet/person.zkey') }
const a = fixtures.proofs.find((p: { name: string }) => p.name === 'alice-tutoring-A')
const w = fixtures.wire

test('with no Buffer, register, refund and the row address are the wire vectors', () => {
  assert.equal(typeof Buffer, 'undefined')
  const payer = new PublicKey(w.payer)
  const register = registerIx({
    profile: new PublicKey(a.profile),
    label: a.label,
    stamp: hexToBytes(a.stamp),
    issuer: [fromBytes32(hexToBytes(a.issuerKey.slice(0, 64))), fromBytes32(hexToBytes(a.issuerKey.slice(64)))],
    tier: hexToBytes(a.tier),
    proof: { a: hexToBytes(a.a), b: hexToBytes(a.b), c: hexToBytes(a.c) },
    payer,
  })
  const row = rowAddress(hexToBytes(a.stamp))
  assert.equal(bytesToHex(register.data), w.register)
  assert.equal(bytesToHex(refundIx({ row, payer }).data), w.refund)
  assert.equal(row.toBase58(), w.rowAddress)
})

test('with no Buffer, a registration from a real note: its transaction serializes and reads back', async () => {
  const secret = (await issuerSecret(hexToBytes(keysVectors.seed), keysVectors.issuers[0].name)).secret
  const note = signNote(sha256(new TextEncoder().encode('forest registry fixture: issuer A')), {
    noteNumber: noteNumberOf(secret),
    embedding: new Uint8Array(Float32Array.from([0.25, -0.5, 0.125]).buffer),
    model: 'example-face-model/1',
    tier: 2n,
  })
  const payer = Keypair.generate().publicKey
  const r = await buildRegistration({ secret, note, label: a.label, profile: new PublicKey(a.profile), artifacts, payer, recentBlockhash: PublicKey.default.toBase58() })
  assert.equal(r.row.toBase58(), w.rowAddress)
  const back = VersionedTransaction.deserialize(r.transaction.serialize())
  assert.equal(bytesToHex(back.message.compiledInstructions.at(-1)!.data), bytesToHex(r.instruction.data))
  assert.equal(back.message.header.numRequiredSignatures, 2)
})
