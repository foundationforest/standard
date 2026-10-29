// The example profile entry (schemas/examples/profile.json): its hosts, its open key, its pay
// addresses, each signed by its pay key, keys/'s access key listed with read and write, and a
// verification and a reputation proof for keys/'s test person, tutoring/seller, made with the
// circuits' setups. A proof is made with fresh randomness, so running this again gives
// other proofs for the same statements; the example keeps the ones made once, and
// test/schemas.test.ts checks them with both proof checks, and the pay signatures with checkPay.
//
//   node scripts/example-profile.ts
//
// It needs the setup files committed in proofs/verification/setup/ and
// proofs/reputation/setup/.

import { readFileSync, writeFileSync } from 'node:fs'
import { sha256 } from '@noble/hashes/sha2.js'
import { PAY_TYPES, accessKey, fieldHash, keyScalar, mainKey, openingHalf, packSignature, payAddresses, payKey, publicKeyOf, seedScalar, serviceKey, signBytes, signPay } from '@foundationforest/keys'
import { proofBytes, proveVerification, signStamp, stampNumberOf, toBytes32 } from '@foundationforest/proofs'
import { type Leaf, proveReputation, signedBytes } from '@foundationforest/proofs'
import { b64u, hex } from '../src/bytes.ts'

const KEYS = JSON.parse(readFileSync(new URL('../../keys/test/vectors.json', import.meta.url), 'utf8'))
const seed = hex.decode(KEYS.seed)
const LABEL = 'tutoring/seller'
const VERIFIER = 'issuer-a.example'
const setup = (proof: string, file: string) => new URL(`../../proofs/${proof}/setup/${file}`, import.meta.url).pathname

const S = await seedScalar(seed)
const me = await mainKey(seed, LABEL)
const access = await accessKey(hex.decode(KEYS.accessKey.secret))

// The verification: an example verifier signed the person a stamp, with example facts. The two texts
// below keep the bytes they had when the example was made, old words and all: the example
// verifier's key and the facts come from them.
const verifierPrivate = sha256(new TextEncoder().encode(`forest example issuer: ${VERIFIER}`))
const stamp = signStamp(verifierPrivate, {
  stampNumber: stampNumberOf(S, VERIFIER),
  facts: fieldHash('forest example attributes', VERIFIER),
})
const verification = await proveVerification({ seedScalar: S, verifierName: VERIFIER, stamp, label: LABEL, artifacts: { wasm: setup('verification', 'verification.wasm'), zkey: setup('verification', 'verification.zkey') } })

// The reputation proof: the person's tutoring/buyer and cleaning/seller profiles in an example
// index's tree, among made-up leaves, shown on tutoring/seller.
const mine: Leaf[] = [
  { profile: (await mainKey(seed, 'tutoring/buyer')).publicKey, score: 90n },
  { profile: (await mainKey(seed, 'cleaning/seller')).publicKey, score: 80n },
]
const madeUp: Leaf[] = Array.from({ length: 30 }, (_, i) => ({ profile: publicKeyOf(keyScalar(fieldHash('forest example leaf', String(i)))), score: BigInt((i * 7) % 51) }))
const leaves = [...madeUp.slice(0, 11), mine[0]!, ...madeUp.slice(11, 23), mine[1]!, ...madeUp.slice(23)]
const index = serviceKey(new Uint8Array(32).fill(0x2c)) // the example index's key: 32 bytes of 0x2c
const time = 1_790_812_800_000
const reputation = await proveReputation({
  seedScalar: S,
  labels: ['tutoring/buyer', 'cleaning/seller'],
  leaves,
  profileLabel: LABEL,
  artifacts: { wasm: setup('reputation', 'reputation.wasm'), zkey: setup('reputation', 'reputation.zkey') },
})

const profile = {
  market: 'tutoring',
  role: 'seller',
  hosts: ['https://host-a.example'],
  openKey: (await openingHalf(me.secret)).openKey,
  pay: await payAddresses(seed, LABEL),
  paySig: Object.fromEntries(await Promise.all(PAY_TYPES.map(async (type) => [type, signPay(await payKey(seed, LABEL, type), me.address)]))),
  keys: [{ key: access.address, open: access.openKey, can: ['read', 'write'] }],
  proofs: [
    {
      circuit: 'reputation',
      index: index.address,
      root: hex.encode(toBytes32(reputation.root)),
      time,
      signature: b64u.encode(packSignature(signBytes(index.scalar, signedBytes(reputation.root, time)))),
      score: Number(reputation.score),
      proof: b64u.encode(proofBytes(reputation.proof)),
    },
    {
      circuit: 'verification',
      verifier: verification.verifier,
      verifierName: VERIFIER,
      label: LABEL,
      proof: b64u.encode(proofBytes(verification.proof)),
    },
  ],
}
writeFileSync(new URL('../schemas/examples/profile.json', import.meta.url), JSON.stringify(profile, null, 2) + '\n')
console.log(`the example profile entry for ${me.address}: a reputation score of ${reputation.score}, and a verification from ${VERIFIER}`)
process.exit(0)
