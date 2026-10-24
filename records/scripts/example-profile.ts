// The example profile record's proofs (schemas/examples/profile.json): a stamp proof and a
// reputation proof for keys/'s test person, tutoring/seller, made with the circuits' setups. A proof
// is made with fresh randomness, so running this again gives other proofs for the same statements;
// the example keeps the ones made once, and test/schemas.test.ts checks them with both verifiers.
//
//   node scripts/example-profile.ts
//
// It needs proofs/stamp/circuit/setup/ (committed) and proofs/reputation/circuit/setup/'s proving
// files (npm run fetch there).

import { readFileSync, writeFileSync } from 'node:fs'
import { sha256 } from '@noble/hashes/sha2.js'
import { fieldHash, inboxKey, issuerSecret, mainKey, packSignature, payAddresses, scopeOf, seedScalar, serviceKey, signBytes, tagOf } from '@foundationforest/keys'
import { proofBytes, proveStamp, signStamp, stampNumberOf, toBytes32 } from '@foundationforest/stamp'
import { type Leaf, proveReputation, signedBytes } from '@foundationforest/reputation'
import { b64u, hex } from '../src/bytes.ts'

const KEYS = JSON.parse(readFileSync(new URL('../../keys/test/vectors.json', import.meta.url), 'utf8'))
const seed = hex.decode(KEYS.seed)
const LABEL = 'tutoring/seller'
const ISSUER = 'issuer-a.example'
const setup = (proof: string, file: string) => new URL(`../../proofs/${proof}/circuit/setup/${file}`, import.meta.url).pathname

const S = await seedScalar(seed)
const me = await mainKey(seed, LABEL)

// The stamp proof: an example issuer signed the person a stamp, with example facts. The two texts
// below keep the bytes they had when the example was made, old words and all: the example issuer's
// key and the facts come from them.
const issuerPrivate = sha256(new TextEncoder().encode(`forest example issuer: ${ISSUER}`))
const stamp = signStamp(issuerPrivate, {
  stampNumber: stampNumberOf(S, ISSUER),
  facts: fieldHash('forest example attributes', ISSUER),
})
const stampProof = await proveStamp({ seedScalar: S, issuerName: ISSUER, stamp, label: LABEL, artifacts: { wasm: setup('stamp', 'note.wasm'), zkey: setup('stamp', 'note.zkey') } })

// The reputation proof: the person's tutoring/buyer and cleaning/seller profiles in an example
// index's tree, among made-up leaves, shown on tutoring/seller.
const at = (await issuerSecret(seed, ISSUER)).scalar
const mine: Leaf[] = [
  { tag: tagOf(at, 'tutoring/buyer'), scope: scopeOf('tutoring/buyer'), score: 90n, count: 7n },
  { tag: tagOf(at, 'cleaning/seller'), scope: scopeOf('cleaning/seller'), score: 80n, count: 3n },
]
const madeUp: Leaf[] = Array.from({ length: 30 }, (_, i) => ({ tag: fieldHash('forest example leaf', String(i)), scope: scopeOf(`made-up/${i}`), score: BigInt((i * 7) % 51), count: BigInt(i % 9) }))
const leaves = [...madeUp.slice(0, 11), mine[0]!, ...madeUp.slice(11, 23), mine[1]!, ...madeUp.slice(23)]
const index = serviceKey(new Uint8Array(32).fill(0x2c)) // the example index's key: 32 bytes of 0x2c
const time = 1_790_812_800_000
const reputation = await proveReputation({
  seedScalar: S,
  sources: [{ label: 'tutoring/buyer', issuerName: ISSUER }, { label: 'cleaning/seller', issuerName: ISSUER }],
  leaves,
  profileLabel: LABEL,
  artifacts: { wasm: setup('reputation', 'reputation.wasm'), zkey: setup('reputation', 'reputation.zkey') },
})

const profile = {
  market: 'tutoring',
  role: 'seller',
  pay: await payAddresses(seed, LABEL),
  inboxKey: (await inboxKey(me.secret)).sealTo,
  inbox: { senders: 'anyone', maxBytes: 16384 },
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
      circuit: 'stamp',
      issuer: stampProof.issuer,
      issuerName: ISSUER,
      label: LABEL,
      tag: hex.encode(toBytes32(stampProof.tag)),
      proof: b64u.encode(proofBytes(stampProof.proof)),
    },
  ],
}
writeFileSync(new URL('../schemas/examples/profile.json', import.meta.url), JSON.stringify(profile, null, 2) + '\n')
console.log(`the example profile record for ${me.address}: a reputation score of ${reputation.score}, and a stamp proof from ${ISSUER}`)
process.exit(0)
