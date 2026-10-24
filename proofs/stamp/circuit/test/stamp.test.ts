// The stamp proof, end to end: keys/'s test person, a stamp a verifier signed for them, a proof for
// one label and the main key their seed gives for it, and every way a proof must fail.
//
// They need the setup's files, committed in setup/: `npm run fetch` checks their hashes first. A
// missing file fails; nothing skips.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { signMessage } from '@zk-kit/eddsa-poseidon'
import { poseidon2 } from 'poseidon-lite/poseidon2'
import { groth16 } from 'snarkjs'

import { addressOf, keyScalar, mainKey, pointOf, publicKeyOf, seedScalar, signWithScalar, tagOf, verifierSecret } from '@foundationforest/keys'
import {
  BN254_R,
  fieldHash,
  stampInput,
  verifierKeyOf,
  stampHash,
  stampNumberOf,
  stampSigned,
  proveStamp,
  signStamp,
  toBytes32,
  checkStamp,
  type SignedStamp,
} from '@foundationforest/stamp'

const here = dirname(fileURLToPath(import.meta.url))
const artifacts = { wasm: join(here, '../setup/note.wasm'), zkey: join(here, '../setup/note.zkey') }
const keysVectors = JSON.parse(readFileSync(join(here, '../../../../keys/test/vectors.json'), 'utf8'))
const seed = Uint8Array.from(Buffer.from(keysVectors.seed, 'hex'))
const NAME = keysVectors.verifiers[0].name
const OTHER_NAME = keysVectors.verifiers[1].name

// The person, and another person with their own seed.
const mine = await seedScalar(seed)
const theirSeed = new Uint8Array(32).fill(9)
const theirs = await seedScalar(theirSeed)

// The verifier that checked them, another verifier, and a key that issues nothing anyone trusts.
const verifierPrivate = new Uint8Array(32).fill(1)
const otherPrivate = new Uint8Array(32).fill(2)
const strangerPrivate = new Uint8Array(32).fill(3)
const verifier = verifierKeyOf(verifierPrivate)
const otherVerifier = verifierKeyOf(otherPrivate)

// Made from the same text as the example's facts (records/scripts/example-profile.ts), whose bytes stay.
const FACTS = fieldHash('forest example attributes', 'issuer-a')
const stampFor = (stampNumber: bigint, key = verifierPrivate): SignedStamp => signStamp(key, { stampNumber, facts: FACTS })
const stamp = stampFor(stampNumberOf(mine, NAME))

const LABEL = 'tutoring/seller'
const OTHER_LABEL = 'tutoring/buyer'
const profile = await mainKey(seed, LABEL)
const otherProfile = await mainKey(seed, OTHER_LABEL)
const theirProfile = await mainKey(theirSeed, LABEL)

const valid = await proveStamp({ seedScalar: mine, verifierName: NAME, stamp, label: LABEL, artifacts })
const good = { proof: valid.proof, verifier, verifierName: NAME, label: LABEL, profile: profile.address, tag: valid.tag }

/** The circuit's witness for these inputs, proven straight through snarkjs. */
const prove = (input: Record<string, unknown>) => groth16.fullProve(input, artifacts.wasm, artifacts.zkey)
const inputOf = (n: SignedStamp, seedScalar = mine, label = LABEL) => stampInput({ seedScalar, verifierName: NAME, stamp: n, label }).input
/** What circom's witness generator says when a constraint does not hold: there is nothing to prove. */
const NO_WITNESS = /Assert Failed/

test("a valid proof: the verifier signed my stamp; my tag for this label; the profile's key is keys/'s main key", async () => {
  assert.equal(stampSigned(stamp), true)
  assert.equal(await checkStamp(good), true)
  assert.equal(await checkStamp({ ...good, tag: toBytes32(valid.tag) }), true, 'the tag as 32 bytes')
  assert.equal(await checkStamp({ ...good, profile: profile.publicKey }), true, 'the profile as its key')
  assert.equal(await checkStamp({ ...good, verifier: pointOf(verifier) }), true, 'the verifier as its point')
  assert.equal(valid.address, profile.address)
  assert.deepEqual(valid.profile, profile.publicKey)
  assert.equal(valid.tag, tagOf((await verifierSecret(seed, NAME)).scalar, LABEL))
  assert.equal(valid.tag.toString(), keysVectors.verifiers[0].tags[LABEL], "keys/'s pinned tag")
  assert.deepEqual(valid.verifier, verifier)
  assert.equal(valid.publicSignals.length, 7, 'the tag, then profileX, profileY, issuerX, issuerY, scope, issuerNameHash')
})

test('a proof for another profile fails, and so does a key the seed does not give for the label', async () => {
  // Shown on my other profile, or on someone else's: not this proof.
  assert.equal(await checkStamp({ ...good, profile: otherProfile.address }), false, 'my other profile')
  assert.equal(await checkStamp({ ...good, profile: theirProfile.address }), false, "someone else's profile")
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
  await assert.rejects(prove(inputOf(stamp, theirs)), NO_WITNESS)
})

test('a wrong verifier key or verifier name fails', async () => {
  assert.equal(await checkStamp({ ...good, verifier: otherVerifier }), false, 'another key')
  assert.equal(await checkStamp({ ...good, verifierName: OTHER_NAME }), false, 'another name')
  // A stamp the other verifier signed, presented under this verifier's key: no witness. issuerX,
  // issuerY and issuerNameHash are the circuit's names for the verifier's key and name hash.
  const theirStamp = stampFor(stamp.stampNumber, otherPrivate)
  await assert.rejects(prove({ ...inputOf(theirStamp), issuerX: pointOf(verifier)[0], issuerY: pointOf(verifier)[1] }), NO_WITNESS)
  // My stamp, with another verifier's name: the stamp number the circuit computes is not the signed
  // one.
  await assert.rejects(prove({ ...inputOf(stamp), issuerNameHash: fieldHash('forest/v1/issuer/', OTHER_NAME) }), NO_WITNESS)
  await assert.rejects(proveStamp({ seedScalar: mine, verifierName: OTHER_NAME, stamp, label: LABEL, artifacts }), /not for this seed at this verifier/)
})

test('a forged signature fails, and so do a signature without the prefix and facts the verifier did not sign', async () => {
  // A key that is not the verifier's signs a stamp, which then claims the verifier's key.
  const forged = { ...stampFor(stamp.stampNumber, strangerPrivate), verifier }
  assert.equal(stampSigned(forged), false)
  await assert.rejects(proveStamp({ seedScalar: mine, verifierName: NAME, stamp: forged, label: LABEL, artifacts }), /signature is not on this stamp/)
  await assert.rejects(prove(inputOf(forged)), NO_WITNESS)
  // The verifier's own signature with S changed, or with S plus the subgroup order: no witness.
  await assert.rejects(prove(inputOf({ ...stamp, signature: { ...stamp.signature, S: stamp.signature.S + 1n } })), NO_WITNESS)
  const l = 2736030358979909402780800718157159386076813972158567259200215660948447373041n
  await assert.rejects(prove(inputOf({ ...stamp, signature: { ...stamp.signature, S: stamp.signature.S + l } })), NO_WITNESS)
  // The verifier's own signature over the same fields without the prefix: no witness.
  const unprefixed = poseidon2([stamp.stampNumber, stamp.facts])
  await assert.rejects(prove(inputOf({ ...stamp, signature: signMessage(verifierPrivate, unprefixed) })), NO_WITNESS)
  // The signed stamp with other facts: no witness.
  await assert.rejects(prove(inputOf({ ...stamp, facts: stamp.facts + 1n })), NO_WITNESS)
  await assert.rejects(proveStamp({ seedScalar: mine, verifierName: NAME, stamp: { ...stamp, facts: 0n }, label: LABEL, artifacts }), /signature is not on this stamp/)
})

test("another person's seed fails", async () => {
  await assert.rejects(proveStamp({ seedScalar: theirs, verifierName: NAME, stamp, label: LABEL, artifacts }), /not for this seed at this verifier/)
  // My proof does not hold for their tag either.
  const theirTag = tagOf((await verifierSecret(theirSeed, NAME)).scalar, LABEL)
  assert.equal(await checkStamp({ ...good, tag: theirTag }), false)
})

test('a tag or a label for another label fails', async () => {
  const otherTag = tagOf((await verifierSecret(seed, NAME)).scalar, OTHER_LABEL)
  assert.equal(await checkStamp({ ...good, label: OTHER_LABEL }), false)
  assert.equal(await checkStamp({ ...good, tag: otherTag }), false)
  assert.equal(await checkStamp({ ...good, label: OTHER_LABEL, tag: otherTag }), false)
  assert.equal(await checkStamp({ ...good, label: OTHER_LABEL, tag: otherTag, profile: otherProfile.address }), false, 'the other profile, whole')
})

test('a public value outside the field, or a proof changed, fails', async () => {
  assert.equal(await checkStamp({ ...good, tag: valid.tag + BN254_R }), false)
  assert.equal(await checkStamp({ ...good, verifier: [pointOf(verifier)[0] + BN254_R, pointOf(verifier)[1]] }), false)
  assert.equal(await checkStamp({ ...good, verifier: 'not an address' }), false)
  assert.equal(await checkStamp({ ...good, profile: [profile.publicKey[0] + BN254_R, profile.publicKey[1]] }), false)
  const changed = { ...valid.proof, pi_a: [valid.proof.pi_c[0], valid.proof.pi_c[1], '1'] as typeof valid.proof.pi_a }
  assert.equal(await checkStamp({ ...good, proof: changed }), false)
})

test("a verifier may sign with keys/'s signWithScalar: circomlib's EdDSAPoseidonVerifier, inside the proof, takes it", async () => {
  // An independent check of keys/'s signing: the circuit's EdDSAPoseidonVerifier accepts it.
  const scalar = keyScalar(fieldHash('example verifier scalar'))
  const key = publicKeyOf(scalar)
  const unsigned = { stampNumber: stamp.stampNumber, facts: stamp.facts }
  const scalarStamp: SignedStamp = { ...unsigned, verifier: addressOf(key), signature: signWithScalar(scalar, stampHash(unsigned)) }
  assert.equal(stampSigned(scalarStamp), true)
  const r = await proveStamp({ seedScalar: mine, verifierName: NAME, stamp: scalarStamp, label: LABEL, artifacts })
  assert.equal(await checkStamp({ ...good, proof: r.proof, verifier: key }), true)
})
