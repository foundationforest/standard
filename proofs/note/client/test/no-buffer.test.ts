// The note proof as a browser runs it: with no Buffer. Node's global is taken away before the
// client and keys/ load; then an issuer signs a note, the device proves for one profile, and a
// reader checks the proof, from its 256 bytes too.

import assert from 'node:assert/strict'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

// To this client and keys/, Buffer is undefined. Node's internals and the dependencies still see
// it: Node loads the dependencies' Node builds, where a browser's bundler takes their browser builds.
const buffer = globalThis.Buffer
Object.defineProperty(globalThis, 'Buffer', { configurable: true, get: () => (/\(node:|at node:|\/node_modules\//.test(new Error().stack?.split('\n')[2] ?? '') ? buffer : undefined) })
const { hexToBytes } = await import('@noble/hashes/utils.js')
const { sha256 } = await import('@noble/hashes/sha2.js')
const { mainKey, seedScalar } = await import('@foundationforest/keys')
const { fieldHash, noteNumberOf, proofBytes, proveNote, signNote, verifyNote } = await import('../src/index.ts')

const here = dirname(fileURLToPath(import.meta.url))
const artifacts = { wasm: join(here, '../../circuit/setup/note.wasm'), zkey: join(here, '../../circuit/setup/note.zkey') }
const seed = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
const NAME = 'issuer-a.example'
const LABEL = 'tutoring/seller'

test('with no Buffer: an issuer signs a note, the device proves, a reader checks', async () => {
  assert.equal(typeof Buffer, 'undefined')
  const S = await seedScalar(seed)
  const note = signNote(sha256(new TextEncoder().encode('forest note fixture: issuer A')), {
    noteNumber: noteNumberOf(S, NAME),
    attributes: fieldHash('forest example attributes', 'issuer-a'),
  })
  const r = await proveNote({ seedScalar: S, issuerName: NAME, note, label: LABEL, artifacts })
  const main = await mainKey(seed, LABEL)
  assert.equal(r.address, main.address)
  const shown = { issuer: r.issuer, issuerName: NAME, label: LABEL, profile: main.address, tag: r.tag }
  assert.equal(await verifyNote({ ...shown, proof: r.proof }), true)
  assert.equal(await verifyNote({ ...shown, proof: proofBytes(r.proof) }), true, 'from its 256 bytes')
})
