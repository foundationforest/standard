// The example card's proofs (schemas/examples/profile.json): a human proof and a reputation proof
// for keys/'s test person, tutoring/seller, made with the devnet setups. A proof is made with fresh
// randomness, so running this again gives other proofs for the same statements; the example keeps
// the ones made once, and test/schemas.test.ts checks them with both verifiers.
//
//   node scripts/example-card.ts
//
// It needs proofs/human/circuit/devnet/ (committed) and proofs/reputation/circuit/devnet/'s
// proving files (npm run fetch there).

import { readFileSync, writeFileSync } from 'node:fs'
import { sha256 } from '@noble/hashes/sha2.js'
import { accessKey, fieldHash, inboxKey, issuerSecret, mainKey, packSignature, payKey, scopeOf, seedScalar, signBytes, stampOf } from '../../keys/src/index.ts'
import { noteNumberOf, proofBytes, proveHuman, signNote, toBytes32 } from '../../proofs/human/client/src/index.ts'
import { type Leaf, proveReputation, signedBytes } from '../../proofs/reputation/client/src/index.ts'
import { b64u, hex } from '../src/bytes.ts'

const KEYS = JSON.parse(readFileSync(new URL('../../keys/test/vectors.json', import.meta.url), 'utf8'))
const seed = hex.decode(KEYS.seed)
const LABEL = 'tutoring/seller'
const ISSUER = 'issuer-a.example'
const devnet = (proof: string, file: string) => new URL(`../../proofs/${proof}/circuit/devnet/${file}`, import.meta.url).pathname

const S = await seedScalar(seed)
const me = await mainKey(seed, LABEL)

// The human proof: an example issuer signed the person a note, with example attributes.
const issuerPrivate = sha256(new TextEncoder().encode(`forest example issuer: ${ISSUER}`))
const note = signNote(issuerPrivate, {
  noteNumber: noteNumberOf(S, ISSUER),
  attributes: fieldHash('forest example attributes', ISSUER),
})
const human = await proveHuman({ seedScalar: S, issuerName: ISSUER, note, label: LABEL, artifacts: { wasm: devnet('human', 'human.wasm'), zkey: devnet('human', 'human.zkey') } })
const issuerHex = hex.encode(toBytes32(human.issuer[0])) + hex.encode(toBytes32(human.issuer[1]))

// The reputation proof: the person's tutoring/buyer and cleaning/seller profiles in an example
// index's tree, among made-up leaves, shown on tutoring/seller.
const at = (await issuerSecret(seed, ISSUER)).scalar
const mine: Leaf[] = [
  { stamp: stampOf(at, 'tutoring/buyer'), scope: scopeOf('tutoring/buyer'), score: 90n, count: 7n },
  { stamp: stampOf(at, 'cleaning/seller'), scope: scopeOf('cleaning/seller'), score: 80n, count: 3n },
]
const madeUp: Leaf[] = Array.from({ length: 30 }, (_, i) => ({ stamp: fieldHash('forest example leaf', String(i)), scope: scopeOf(`made-up/${i}`), score: BigInt((i * 7) % 51), count: BigInt(i % 9) }))
const leaves = [...madeUp.slice(0, 11), mine[0]!, ...madeUp.slice(11, 23), mine[1]!, ...madeUp.slice(23)]
const index = accessKey(new Uint8Array(32).fill(0x2c)) // the example index's key: 32 bytes of 0x2c
const time = 1_790_812_800_000
const reputation = await proveReputation({
  seedScalar: S,
  sources: [{ label: 'tutoring/buyer', issuerName: ISSUER }, { label: 'cleaning/seller', issuerName: ISSUER }],
  leaves,
  profileLabel: LABEL,
  artifacts: { wasm: devnet('reputation', 'reputation.wasm'), zkey: devnet('reputation', 'reputation.zkey') },
})

const card = {
  market: 'tutoring',
  role: 'seller',
  pay: (await payKey(seed, LABEL)).address,
  inboxKey: (await inboxKey(me.secret)).recipient,
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
      circuit: 'human',
      issuer: issuerHex,
      issuerName: ISSUER,
      label: LABEL,
      stamp: hex.encode(toBytes32(human.stamp)),
      proof: b64u.encode(proofBytes(human.proof)),
    },
  ],
}
writeFileSync(new URL('../schemas/examples/profile.json', import.meta.url), JSON.stringify(card, null, 2) + '\n')
console.log(`the example card for ${me.address}: a reputation score of ${reputation.score}, and a human proof from ${ISSUER}`)
process.exit(0)
