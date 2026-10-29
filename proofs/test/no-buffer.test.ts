// The verification as a browser runs it: with no Buffer. Node's global is taken away before the
// client and keys/ load; then a verifier signs a stamp, the device proves for one profile, and a
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
const { mainKey, seedNumber } = await import('@foundationforest/keys')
const { checkVerification, fieldHash, proofBytes, proveVerification, signStamp, stampNumberOf } = await import('../src/index.ts')

const here = dirname(fileURLToPath(import.meta.url))
const artifacts = { wasm: join(here, '../verification/setup/verification.wasm'), zkey: join(here, '../verification/setup/verification.zkey') }
const seed = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
const NAME = 'verifier-a.example'
const LABEL = 'tutoring/seller'

test('with no Buffer: a verifier signs a stamp, the device proves, a reader checks', async () => {
  assert.equal(typeof Buffer, 'undefined')
  const stamp = signStamp(sha256(new TextEncoder().encode('forest stamp fixture: verifier A')), {
    stampNumber: stampNumberOf(seedNumber(seed), NAME),
    facts: fieldHash('forest example facts', 'verifier-a'),
    verifierName: NAME,
  })
  const r = await proveVerification({ seed, stamp, label: LABEL, artifacts })
  const main = await mainKey(seed, LABEL)
  assert.equal(r.address, main.address)
  const shown = { verifier: r.verifier, verifierName: NAME, label: LABEL, profile: main.address }
  assert.equal(await checkVerification({ ...shown, proof: r.proof }), true)
  assert.equal(await checkVerification({ ...shown, proof: proofBytes(r.proof) }), true, 'from its 256 bytes')
})
