// The verification, end to end: keys/'s test person, a stamp a verifier signed for them, a proof for
// one label and the main key their seed gives for it, and every way a proof must fail.
//
// They need the setup's files, committed in verification/setup/: `npm run fetch` checks their hashes first. A
// missing file fails; nothing skips.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { derivePublicKey, signMessage } from '@zk-kit/eddsa-poseidon'
import { poseidon2 } from 'poseidon-lite/poseidon2'
import { groth16 } from 'snarkjs'

import { addressOf, mainKey, nameHashOf, pointOf, publicKeyOf, seedNumber, serviceKey, signWithScalar } from '@foundationforest/keys'
import {
  BN254_R,
  checkVerification,
  fieldHash,
  proveVerification,
  signStamp,
  stampHash,
  stampNumberOf,
  stampSigned,
  verificationInput,
  verifierKeyOf,
  type SignedStamp,
} from '../src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
const artifacts = { wasm: join(here, '../verification/setup/verification.wasm'), zkey: join(here, '../verification/setup/verification.zkey') }
const keysVectors = JSON.parse(readFileSync(join(here, '../../keys/test/vectors.json'), 'utf8'))
const seed = Uint8Array.from(Buffer.from(keysVectors.seed, 'hex'))
const NAME = keysVectors.verifiers[0].name
const OTHER_NAME = keysVectors.verifiers[1].name

// Another person, with their own seed.
const theirSeed = new Uint8Array(32).fill(9)

// The verifier that checked them, another verifier, and a key that issues nothing anyone trusts.
const verifierPrivate = new Uint8Array(32).fill(1)
const otherPrivate = new Uint8Array(32).fill(2)
const strangerPrivate = new Uint8Array(32).fill(3)
const verifier = verifierKeyOf(verifierPrivate)
const otherVerifier = verifierKeyOf(otherPrivate)

const FACTS = fieldHash('forest example facts', 'verifier-a')
const stampFor = (stampNumber: bigint, key = verifierPrivate): SignedStamp => signStamp(key, { stampNumber, facts: FACTS, verifierName: NAME })
const stamp = stampFor(stampNumberOf(seedNumber(seed), NAME))

const LABEL = 'tutoring/seller'
const OTHER_LABEL = 'tutoring/buyer'
const profile = await mainKey(seed, LABEL)
const otherProfile = await mainKey(seed, OTHER_LABEL)
const theirProfile = await mainKey(theirSeed, LABEL)

const valid = await proveVerification({ seed, stamp, label: LABEL, artifacts })
const good = { proof: valid.proof, verifier, verifierName: NAME, label: LABEL, profile: profile.address }

/** The circuit's witness for these inputs, proven straight through snarkjs. */
const prove = (input: Record<string, unknown>) => groth16.fullProve(input, artifacts.wasm, artifacts.zkey)
const inputOf = (n: SignedStamp, from = seed, label = LABEL) => verificationInput({ seed: from, stamp: n, label }).input
/** What circom's witness generator says when a constraint does not hold: there is nothing to prove. */
const NO_WITNESS = /Assert Failed/

test("a valid proof: the verifier signed my stamp, and the profile's key is keys/'s main key", async () => {
  assert.equal(stampSigned(stamp), true)
  assert.equal(await checkVerification(good), true)
  assert.equal(await checkVerification({ ...good, profile: profile.publicKey }), true, 'the profile as its key')
  assert.equal(await checkVerification({ ...good, verifier: pointOf(verifier) }), true, 'the verifier as its point')
  assert.equal(valid.address, profile.address)
  assert.deepEqual(valid.profile, profile.publicKey)
  assert.deepEqual(valid.verifier, verifier)
  assert.equal(valid.publicSignals.length, 6, 'profileX, profileY, verifierX, verifierY, scope, verifierNameHash')
})

test('a proof for another profile fails, and so does a key the seed does not give for the label', async () => {
  // Shown on my other profile, or on someone else's: not this proof.
  assert.equal(await checkVerification({ ...good, profile: otherProfile.address }), false, 'my other profile')
  assert.equal(await checkVerification({ ...good, profile: theirProfile.address }), false, "someone else's profile")
  // Straight to the circuit: my other label's key, someone else's key, or a key of my choosing,
  // with my stamp and this label: no witness.
  for (const [what, key] of [
    ['my other label', otherProfile.publicKey],
    ["someone else's", theirProfile.publicKey],
    ['a key of my choosing', publicKeyOf(12345n)],
  ] as const) {
    await assert.rejects(prove({ ...inputOf(stamp), profileX: key[0], profileY: key[1] }), NO_WITNESS, what)
  }
  // My stamp lent to their seed, for their profile: their seed gives another stamp number.
  await assert.rejects(prove(inputOf(stamp, theirSeed)), NO_WITNESS)
})

test('a wrong verifier key or verifier name fails', async () => {
  assert.equal(await checkVerification({ ...good, verifier: otherVerifier }), false, 'another key')
  assert.equal(await checkVerification({ ...good, verifierName: OTHER_NAME }), false, 'another name')
  // A stamp the other verifier signed, presented under this verifier's key: no witness.
  const theirStamp = stampFor(stamp.stampNumber, otherPrivate)
  await assert.rejects(prove({ ...inputOf(theirStamp), verifierX: pointOf(verifier)[0], verifierY: pointOf(verifier)[1] }), NO_WITNESS)
  // My stamp, with another verifier's name: neither the stamp number nor the stamp the circuit
  // computes is the signed one.
  await assert.rejects(prove({ ...inputOf(stamp), verifierNameHash: nameHashOf(OTHER_NAME) }), NO_WITNESS)
  await assert.rejects(proveVerification({ seed, stamp: { ...stamp, verifierName: OTHER_NAME }, label: LABEL, artifacts }), /not for this seed at this verifier/)
})

test("a forged signature fails, and so do a signature without the verifier's name hash and facts the verifier did not sign", async () => {
  // A key that is not the verifier's signs a stamp, which then claims the verifier's key.
  const forged = { ...stampFor(stamp.stampNumber, strangerPrivate), verifier }
  assert.equal(stampSigned(forged), false)
  await assert.rejects(proveVerification({ seed, stamp: forged, label: LABEL, artifacts }), /signature is not on this stamp/)
  await assert.rejects(prove(inputOf(forged)), NO_WITNESS)
  // The verifier's own signature with S changed, or with S plus the subgroup order: no witness.
  await assert.rejects(prove(inputOf({ ...stamp, signature: { ...stamp.signature, S: stamp.signature.S + 1n } })), NO_WITNESS)
  const l = 2736030358979909402780800718157159386076813972158567259200215660948447373041n
  await assert.rejects(prove(inputOf({ ...stamp, signature: { ...stamp.signature, S: stamp.signature.S + l } })), NO_WITNESS)
  // The verifier's own signature over the same fields without its name hash: no witness.
  const nameless = poseidon2([stamp.stampNumber, stamp.facts])
  await assert.rejects(prove(inputOf({ ...stamp, signature: signWithScalar(serviceKey(verifierPrivate).scalar, nameless) })), NO_WITNESS)
  // The signed stamp with other facts: no witness.
  await assert.rejects(prove(inputOf({ ...stamp, facts: stamp.facts + 1n })), NO_WITNESS)
  await assert.rejects(proveVerification({ seed, stamp: { ...stamp, facts: 0n }, label: LABEL, artifacts }), /signature is not on this stamp/)
})

test("another person's seed fails", async () => {
  await assert.rejects(proveVerification({ seed: theirSeed, stamp, label: LABEL, artifacts }), /not for this seed at this verifier/)
})

test('a label for another label fails', async () => {
  assert.equal(await checkVerification({ ...good, label: OTHER_LABEL }), false)
  assert.equal(await checkVerification({ ...good, label: OTHER_LABEL, profile: otherProfile.address }), false, 'the other profile, whole')
  // Straight to the circuit: my stamp and key, with the other label's scope: no witness.
  await assert.rejects(prove({ ...inputOf(stamp), scope: inputOf(stamp, seed, OTHER_LABEL).scope }), NO_WITNESS)
})

test('a public value outside the field, or a proof changed, fails', async () => {
  assert.equal(await checkVerification({ ...good, verifier: [pointOf(verifier)[0] + BN254_R, pointOf(verifier)[1]] }), false)
  assert.equal(await checkVerification({ ...good, verifier: 'not an address' }), false)
  assert.equal(await checkVerification({ ...good, profile: [profile.publicKey[0] + BN254_R, profile.publicKey[1]] }), false)
  const changed = { ...valid.proof, pi_a: [valid.proof.pi_c[0], valid.proof.pi_c[1], '1'] as typeof valid.proof.pi_a }
  assert.equal(await checkVerification({ ...good, proof: changed }), false)
})

test("a stamp zk-kit signs passes too: any EdDSA-Poseidon signature by the verifier's key, which circomlib's verifier checks inside the proof", async () => {
  // An independent signer: zk-kit makes its own key from the 32 bytes, and its own nonce.
  const privateKey = new Uint8Array(32).fill(4)
  const key = derivePublicKey(privateKey)
  const unsigned = { stampNumber: stamp.stampNumber, facts: stamp.facts, verifierName: NAME }
  const zkStamp: SignedStamp = { ...unsigned, verifier: addressOf(key), signature: signMessage(privateKey, stampHash(unsigned)) }
  assert.equal(stampSigned(zkStamp), true)
  const r = await proveVerification({ seed, stamp: zkStamp, label: LABEL, artifacts })
  assert.equal(await checkVerification({ ...good, proof: r.proof, verifier: key }), true)
})
