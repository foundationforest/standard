// The example profile record's proofs (schemas/examples/profile.json): a note proof and a
// reputation proof for keys/'s test person, tutoring/seller, made with the circuits' setups. A proof
// is made with fresh randomness, so running this again gives other proofs for the same statements;
// the example keeps the ones made once, and test/schemas.test.ts checks them with both verifiers.
//
//   node scripts/example-profile.ts
//
// It needs proofs/note/circuit/setup/ (committed) and proofs/reputation/circuit/setup/'s proving
// files (npm run fetch there).

import { readFileSync, writeFileSync } from 'node:fs'
import { sha256 } from '@noble/hashes/sha2.js'
import { fieldHash, inboxKey, issuerSecret, mainKey, packSignature, payKey, scopeOf, seedScalar, serviceKey, signBytes, stampOf } from '@foundationforest/keys'
import { noteNumberOf, proofBytes, proveNote, signNote, toBytes32 } from '@foundationforest/note'
import { type Leaf, proveReputation, signedBytes } from '@foundationforest/reputation'
import { b64u, hex } from '../src/bytes.ts'

const KEYS = JSON.parse(readFileSync(new URL('../../keys/test/vectors.json', import.meta.url), 'utf8'))
const seed = hex.decode(KEYS.seed)
const LABEL = 'tutoring/seller'
const ISSUER = 'issuer-a.example'
const setup = (proof: string, file: string) => new URL(`../../proofs/${proof}/circuit/setup/${file}`, import.meta.url).pathname

const S = await seedScalar(seed)
const me = await mainKey(seed, LABEL)

// The note proof: an example issuer signed the person a note, with example attributes.
const issuerPrivate = sha256(new TextEncoder().encode(`forest example issuer: ${ISSUER}`))
const note = signNote(issuerPrivate, {
  noteNumber: noteNumberOf(S, ISSUER),
  attributes: fieldHash('forest example attributes', ISSUER),
})
const noteProof = await proveNote({ seedScalar: S, issuerName: ISSUER, note, label: LABEL, artifacts: { wasm: setup('note', 'note.wasm'), zkey: setup('note', 'note.zkey') } })

// The reputation proof: the person's tutoring/buyer and cleaning/seller profiles in an example
// index's tree, among made-up leaves, shown on tutoring/seller.
const at = (await issuerSecret(seed, ISSUER)).scalar
const mine: Leaf[] = [
  { stamp: stampOf(at, 'tutoring/buyer'), scope: scopeOf('tutoring/buyer'), score: 90n, count: 7n },
  { stamp: stampOf(at, 'cleaning/seller'), scope: scopeOf('cleaning/seller'), score: 80n, count: 3n },
]
const madeUp: Leaf[] = Array.from({ length: 30 }, (_, i) => ({ stamp: fieldHash('forest example leaf', String(i)), scope: scopeOf(`made-up/${i}`), score: BigInt((i * 7) % 51), count: BigInt(i % 9) }))
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
  pay: (await payKey(seed, LABEL)).address,
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
      circuit: 'note',
      issuer: noteProof.issuer,
      issuerName: ISSUER,
      label: LABEL,
      stamp: hex.encode(toBytes32(noteProof.stamp)),
      proof: b64u.encode(proofBytes(noteProof.proof)),
    },
  ],
}
writeFileSync(new URL('../schemas/examples/profile.json', import.meta.url), JSON.stringify(profile, null, 2) + '\n')
console.log(`the example profile record for ${me.address}: a reputation score of ${reputation.score}, and a note proof from ${ISSUER}`)
process.exit(0)
