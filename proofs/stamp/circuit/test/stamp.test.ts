// The stamp proof, end to end: keys/'s test person, a stamp an issuer signed for them, a proof for
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

import { addressOf, keyScalar, mainKey, pointOf, publicKeyOf, seedScalar, signWithScalar, tagOf, issuerSecret } from '@foundationforest/keys'
import {
  BN254_R,
  fieldHash,
  stampInput,
  issuerKeyOf,
  stampHash,
  stampNumberOf,
  stampSigned,
  proveStamp,
  signStamp,
  toBytes32,
  verifyStamp,
  type SignedStamp,
} from '@foundationforest/stamp'

const here = dirname(fileURLToPath(import.meta.url))
const artifacts = { wasm: join(here, '../setup/note.wasm'), zkey: join(here, '../setup/note.zkey') }
const keysVectors = JSON.parse(readFileSync(join(here, '../../../../keys/test/vectors.json'), 'utf8'))
const seed = Uint8Array.from(Buffer.from(keysVectors.seed, 'hex'))
const NAME = keysVectors.issuers[0].name
const OTHER_NAME = keysVectors.issuers[1].name

// The person, and another person with their own seed.
const mine = await seedScalar(seed)
const theirSeed = new Uint8Array(32).fill(9)
const theirs = await seedScalar(theirSeed)

// The issuer that checked them, another issuer, and a key that issues nothing anyone trusts.
const issuerPrivate = new Uint8Array(32).fill(1)
const otherPrivate = new Uint8Array(32).fill(2)
const strangerPrivate = new Uint8Array(32).fill(3)
const issuer = issuerKeyOf(issuerPrivate)
const otherIssuer = issuerKeyOf(otherPrivate)

// Made from the same text as the example's facts (records/scripts/example-profile.ts), whose bytes stay.
const FACTS = fieldHash('forest example attributes', 'issuer-a')
const stampFor = (stampNumber: bigint, key = issuerPrivate): SignedStamp => signStamp(key, { stampNumber, facts: FACTS })
const stamp = stampFor(stampNumberOf(mine, NAME))

const LABEL = 'tutoring/seller'
const OTHER_LABEL = 'tutoring/buyer'
const profile = await mainKey(seed, LABEL)
const otherProfile = await mainKey(seed, OTHER_LABEL)
const theirProfile = await mainKey(theirSeed, LABEL)

const valid = await proveStamp({ seedScalar: mine, issuerName: NAME, stamp, label: LABEL, artifacts })
const good = { proof: valid.proof, issuer, issuerName: NAME, label: LABEL, profile: profile.address, tag: valid.tag }

/** The circuit's witness for these inputs, proven straight through snarkjs. */
const prove = (input: Record<string, unknown>) => groth16.fullProve(input, artifacts.wasm, artifacts.zkey)
const inputOf = (n: SignedStamp, seedScalar = mine, label = LABEL) => stampInput({ seedScalar, issuerName: NAME, stamp: n, label }).input
/** What circom's witness generator says when a constraint does not hold: there is nothing to prove. */
const NO_WITNESS = /Assert Failed/

test("a valid proof: the issuer signed my stamp; my tag for this label; the profile's key is keys/'s main key", async () => {
  assert.equal(stampSigned(stamp), true)
  assert.equal(await verifyStamp(good), true)
  assert.equal(await verifyStamp({ ...good, tag: toBytes32(valid.tag) }), true, 'the tag as 32 bytes')
  assert.equal(await verifyStamp({ ...good, profile: profile.publicKey }), true, 'the profile as its key')
  assert.equal(await verifyStamp({ ...good, issuer: pointOf(issuer) }), true, 'the issuer as its point')
  assert.equal(valid.address, profile.address)
  assert.deepEqual(valid.profile, profile.publicKey)
  assert.equal(valid.tag, tagOf((await issuerSecret(seed, NAME)).scalar, LABEL))
  assert.equal(valid.tag.toString(), keysVectors.issuers[0].tags[LABEL], "keys/'s pinned tag")
  assert.deepEqual(valid.issuer, issuer)
  assert.equal(valid.publicSignals.length, 7, 'the tag, then profileX, profileY, issuerX, issuerY, scope, issuerNameHash')
})

test('a proof for another profile fails, and so does a key the seed does not give for the label', async () => {
  // Shown on my other profile, or on someone else's: not this proof.
  assert.equal(await verifyStamp({ ...good, profile: otherProfile.address }), false, 'my other profile')
  assert.equal(await verifyStamp({ ...good, profile: theirProfile.address }), false, "someone else's profile")
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

test('a wrong issuer key or issuer name fails', async () => {
  assert.equal(await verifyStamp({ ...good, issuer: otherIssuer }), false, 'another key')
  assert.equal(await verifyStamp({ ...good, issuerName: OTHER_NAME }), false, 'another name')
  // A stamp the other issuer signed, presented under this issuer's key: no witness.
  const theirStamp = stampFor(stamp.stampNumber, otherPrivate)
  await assert.rejects(prove({ ...inputOf(theirStamp), issuerX: pointOf(issuer)[0], issuerY: pointOf(issuer)[1] }), NO_WITNESS)
  // My stamp, with another issuer's name: the stamp number the circuit computes is not the signed one.
  await assert.rejects(prove({ ...inputOf(stamp), issuerNameHash: fieldHash('forest/v1/issuer/', OTHER_NAME) }), NO_WITNESS)
  await assert.rejects(proveStamp({ seedScalar: mine, issuerName: OTHER_NAME, stamp, label: LABEL, artifacts }), /not for this seed at this issuer/)
})

test('a forged signature fails, and so do a signature without the prefix and facts the issuer did not sign', async () => {
  // A key that is not the issuer's signs a stamp, which then claims the issuer's key.
  const forged = { ...stampFor(stamp.stampNumber, strangerPrivate), issuer }
  assert.equal(stampSigned(forged), false)
  await assert.rejects(proveStamp({ seedScalar: mine, issuerName: NAME, stamp: forged, label: LABEL, artifacts }), /signature is not on this stamp/)
  await assert.rejects(prove(inputOf(forged)), NO_WITNESS)
  // The issuer's own signature with S changed, or with S plus the subgroup order: no witness.
  await assert.rejects(prove(inputOf({ ...stamp, signature: { ...stamp.signature, S: stamp.signature.S + 1n } })), NO_WITNESS)
  const l = 2736030358979909402780800718157159386076813972158567259200215660948447373041n
  await assert.rejects(prove(inputOf({ ...stamp, signature: { ...stamp.signature, S: stamp.signature.S + l } })), NO_WITNESS)
  // The issuer's own signature over the same fields without the prefix: no witness.
  const unprefixed = poseidon2([stamp.stampNumber, stamp.facts])
  await assert.rejects(prove(inputOf({ ...stamp, signature: signMessage(issuerPrivate, unprefixed) })), NO_WITNESS)
  // The signed stamp with other facts: no witness.
  await assert.rejects(prove(inputOf({ ...stamp, facts: stamp.facts + 1n })), NO_WITNESS)
  await assert.rejects(proveStamp({ seedScalar: mine, issuerName: NAME, stamp: { ...stamp, facts: 0n }, label: LABEL, artifacts }), /signature is not on this stamp/)
})

test("another person's seed fails", async () => {
  await assert.rejects(proveStamp({ seedScalar: theirs, issuerName: NAME, stamp, label: LABEL, artifacts }), /not for this seed at this issuer/)
  // My proof does not hold for their tag either.
  const theirTag = tagOf((await issuerSecret(theirSeed, NAME)).scalar, LABEL)
  assert.equal(await verifyStamp({ ...good, tag: theirTag }), false)
})

test('a tag or a label for another label fails', async () => {
  const otherTag = tagOf((await issuerSecret(seed, NAME)).scalar, OTHER_LABEL)
  assert.equal(await verifyStamp({ ...good, label: OTHER_LABEL }), false)
  assert.equal(await verifyStamp({ ...good, tag: otherTag }), false)
  assert.equal(await verifyStamp({ ...good, label: OTHER_LABEL, tag: otherTag }), false)
  assert.equal(await verifyStamp({ ...good, label: OTHER_LABEL, tag: otherTag, profile: otherProfile.address }), false, 'the other profile, whole')
})

test('a public value outside the field, or a proof changed, fails', async () => {
  assert.equal(await verifyStamp({ ...good, tag: valid.tag + BN254_R }), false)
  assert.equal(await verifyStamp({ ...good, issuer: [pointOf(issuer)[0] + BN254_R, pointOf(issuer)[1]] }), false)
  assert.equal(await verifyStamp({ ...good, issuer: 'not an address' }), false)
  assert.equal(await verifyStamp({ ...good, profile: [profile.publicKey[0] + BN254_R, profile.publicKey[1]] }), false)
  const changed = { ...valid.proof, pi_a: [valid.proof.pi_c[0], valid.proof.pi_c[1], '1'] as typeof valid.proof.pi_a }
  assert.equal(await verifyStamp({ ...good, proof: changed }), false)
})

test("an issuer may sign with keys/'s signWithScalar: circomlib's verifier, inside the proof, takes it", async () => {
  // An independent check of keys/'s signer: the circuit's EdDSA-Poseidon verifier accepts it.
  const scalar = keyScalar(fieldHash('example issuer scalar'))
  const key = publicKeyOf(scalar)
  const unsigned = { stampNumber: stamp.stampNumber, facts: stamp.facts }
  const scalarStamp: SignedStamp = { ...unsigned, issuer: addressOf(key), signature: signWithScalar(scalar, stampHash(unsigned)) }
  assert.equal(stampSigned(scalarStamp), true)
  const r = await proveStamp({ seedScalar: mine, issuerName: NAME, stamp: scalarStamp, label: LABEL, artifacts })
  assert.equal(await verifyStamp({ ...good, proof: r.proof, issuer: key }), true)
})
