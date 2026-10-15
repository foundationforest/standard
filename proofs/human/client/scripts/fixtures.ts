// Generate the real person proofs and the wire vectors the LiteSVM tests run against, with the
// person circuit's committed devnet setup.
//
//   npm run fixtures
//
// Writes ../program/tests-litesvm/fixtures/proofs.json. The file is committed so `cargo test`
// needs nothing but Rust; this script is what proves the file was not written by hand.
//
// The `wire` section is the client's own bytes for one row's register and refund, and the bytes
// that row should hold when the chain's clock reads `made`. The Rust harness encodes the same
// instructions by hand and must get the same bytes, the program must write exactly that row, and
// the client's tests decode it: the wire format written twice, checked against each other.

import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { sha256 } from '@noble/hashes/sha2.js'
import { Keypair, PublicKey } from '@solana/web3.js'

import { issuerSecret, mainKey } from '../../../keys/src/index.ts'
import { compressProof } from '../src/compress.ts'
import { MESSAGE_NS, SCOPE_NS, toBytes32 } from '../src/field.ts'
import { issuerKeyOf, noteNumberOf, provePerson, signNote, type SignedNote } from '../src/person.ts'
import { ROW_DISCRIMINATOR, issuerKeyBytes, refundIx, registerIx, rowAddress, rowSpace } from '../src/program.ts'

const here = dirname(fileURLToPath(import.meta.url))
const setup = join(here, '../../circuit/devnet')
const outPath = join(here, '../../program/tests-litesvm/fixtures/proofs.json')
const artifacts = { wasm: join(setup, 'person.wasm'), zkey: join(setup, 'person.zkey') }

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
const sha256File = (p: string) => createHash('sha256').update(readFileSync(p)).digest('hex')
/** A fixed 32 bytes for a fixture key or secret: sha256 of a name. Test keys only. */
const seedOf = (name: string) => sha256(new TextEncoder().encode(`forest registry fixture: ${name}`))
const fixtureKey = (name: string) => Keypair.fromSeed(seedOf(name))

// Two issuers, each with its EdDSA key on Baby Jubjub.
const issuerPrivate = { A: seedOf('issuer A'), B: seedOf('issuer B') }
type Issuer = keyof typeof issuerPrivate

// Alice is the test person: keys/'s pinned test seed (keys/test/vectors.json), her secret for each
// issuer mixed from it under the issuer's name, and her two profiles, tutoring/seller and
// tutoring/buyer, all through `keys/` itself. Bob and Carol are fixed bytes, at one issuer each,
// with fixed main keys: the registry does not care how a main key was made.
const keysVectors = JSON.parse(readFileSync(join(here, '../../../keys/test/vectors.json'), 'utf8'))
const seed = Buffer.from(keysVectors.seed, 'hex')
const [nameA, nameB] = keysVectors.issuers.map((i: { name: string }) => i.name)
const secrets = {
  'alice at A': (await issuerSecret(seed, nameA)).secret,
  'alice at B': (await issuerSecret(seed, nameB)).secret,
  'bob at A': seedOf('bob at A'),
  'carol at B': seedOf('carol at B'),
}
type Who = keyof typeof secrets
const tiers: Record<Who, bigint> = { 'alice at A': 2n, 'alice at B': 1n, 'bob at A': 1n, 'carol at B': 3n }

const profileSeeds = {
  alice: (await mainKey(seed, 'tutoring/seller')).privateKey,
  'alice 2': (await mainKey(seed, 'tutoring/buyer')).privateKey,
  bob: seedOf('profile bob'),
  carol: seedOf('profile carol'),
}
type Profile = keyof typeof profileSeeds
for (const [i, name] of (['alice', 'alice 2'] as const).entries()) {
  if (Keypair.fromSeed(profileSeeds[name]).publicKey.toBase58() !== keysVectors.mainKeys[i].address) throw new Error(`${name} is not keys/'s profile`)
}

// The note each issuer signed for each person: their note number, a face embedding, the model that
// made it, and a tier.
const notes = Object.fromEntries(
  (Object.keys(secrets) as Who[]).map((who) => [
    who,
    signNote(issuerPrivate[who.endsWith('A') ? 'A' : 'B'], {
      noteNumber: noteNumberOf(secrets[who]),
      embedding: new Uint8Array(Float32Array.from({ length: 128 }, (_, i) => Math.sin(i + who.length)).buffer),
      model: 'example-face-model/1',
      tier: tiers[who],
    }),
  ]),
) as Record<Who, SignedNote>

const labels = { tutoring: 'tutoring/seller', cleaning: 'cleaning/seller' }
// The longest label a row can carry: 128 bytes.
const longest = ['c'.repeat(42), 'm'.repeat(42), 'r'.repeat(42)].join('/')
if (Buffer.byteLength(longest) !== 128) throw new Error('the longest label is not 128 bytes')

const cases: { name: string; who: Who; profile: Profile; label: string }[] = [
  { name: 'alice-tutoring-A', who: 'alice at A', profile: 'alice', label: labels.tutoring },
  // The same person, issuer and label for a second profile: the same stamp, so one row only.
  { name: 'alice-tutoring-A-second-profile', who: 'alice at A', profile: 'alice 2', label: labels.tutoring },
  // The second profile under the same label through another issuer: another stamp.
  { name: 'alice-tutoring-B', who: 'alice at B', profile: 'alice 2', label: labels.tutoring },
  { name: 'alice-cleaning-A', who: 'alice at A', profile: 'alice', label: labels.cleaning },
  { name: 'bob-tutoring-A', who: 'bob at A', profile: 'bob', label: labels.tutoring },
  { name: 'carol-tutoring-B', who: 'carol at B', profile: 'carol', label: labels.tutoring },
  { name: 'alice-longest-A', who: 'alice at A', profile: 'alice', label: longest },
]

const pair = (a: string, b: string) => hex(Buffer.concat([toBytes32(BigInt(a)), toBytes32(BigInt(b))]))

type FixtureProof = Record<'name' | 'issuer' | 'issuerKey' | 'label' | 'profile' | 'profileSeed' | 'stamp' | 'tier' | 'scope' | 'message' | 'a' | 'b' | 'c', string> & {
  uncompressed: { a: string; b: string; c: string }
}
const proofs: FixtureProof[] = []
for (const c of cases) {
  const t0 = performance.now()
  const profile = Keypair.fromSeed(profileSeeds[c.profile])
  const p = await provePerson({ secret: secrets[c.who], note: notes[c.who], label: c.label, profile: profile.publicKey, artifacts })
  const compressed = compressProof(p.proof)
  console.log(`${c.name}: ${Math.round(performance.now() - t0)} ms, stamp ${p.stamp}`)
  proofs.push({
    name: c.name,
    issuer: c.who.endsWith('A') ? 'A' : 'B',
    issuerKey: hex(issuerKeyBytes(p.issuer)),
    label: c.label,
    profile: profile.publicKey.toBase58(),
    profileSeed: hex(profileSeeds[c.profile]),
    stamp: hex(toBytes32(p.stamp)),
    tier: hex(toBytes32(p.tier)),
    scope: hex(toBytes32(p.scope)),
    message: hex(toBytes32(p.message)),
    a: hex(compressed.a),
    b: hex(compressed.b),
    c: hex(compressed.c),
    // snarkjs's own points, so the Rust side can check that decompressing what the client wrote
    // gives back exactly these. G2 as x.c1, x.c0, y.c1, y.c0.
    uncompressed: {
      a: pair(p.proof.pi_a[0], p.proof.pi_a[1]),
      b: pair(p.proof.pi_b[0][1], p.proof.pi_b[0][0]) + pair(p.proof.pi_b[1][1], p.proof.pi_b[1][0]),
      c: pair(p.proof.pi_c[0], p.proof.pi_c[1]),
    },
  })
}
const byName = (name: string) => proofs.find((p) => p.name === name)!
if (byName('alice-tutoring-A').stamp !== byName('alice-tutoring-A-second-profile').stamp) throw new Error('one issuer, one label: one stamp')
if (byName('alice-tutoring-A').stamp === byName('alice-tutoring-B').stamp) throw new Error('two issuers: two stamps')

// The wire vectors: Alice's tutoring/seller row at issuer A, paid by a fixed key, written while the
// chain's clock reads `made`, as the client writes it.
const made = 1_791_331_200 // 2026-10-07, 00:00 UTC
const first = byName('alice-tutoring-A')
const stamp = Buffer.from(first.stamp, 'hex')
const issuerKey = Buffer.from(first.issuerKey, 'hex')
const payer = fixtureKey('payer')
const profile = new PublicKey(first.profile)
const register = registerIx({
  profile,
  label: first.label,
  stamp,
  issuer: [BigInt('0x' + first.issuerKey.slice(0, 64)), BigInt('0x' + first.issuerKey.slice(64))],
  tier: Buffer.from(first.tier, 'hex'),
  proof: { a: Buffer.from(first.a, 'hex'), b: Buffer.from(first.b, 'hex'), c: Buffer.from(first.c, 'hex') },
  payer: payer.publicKey,
})
const row = rowAddress(stamp)
const refund = refundIx({ row, payer: payer.publicKey })
const label = Buffer.from(first.label, 'utf8')
const time = Buffer.alloc(8)
time.writeBigInt64LE(BigInt(made))
const rowBytes = Buffer.concat([
  ROW_DISCRIMINATOR,
  profile.toBytes(),
  stamp,
  issuerKey,
  payer.publicKey.toBytes(),
  time,
  Buffer.from(Uint32Array.of(label.length).buffer),
  label,
])
if (rowBytes.length !== rowSpace(label.length)) throw new Error('the expected row is not its own size')

const out = {
  note: 'Generated by registry/client/scripts/fixtures.ts. Real person proofs, made with the committed devnet setup in registry/circuit/devnet. Every key here is a test key. Alice is keys/\'s test person: her secrets for issuer-a.example and issuer-b.example and her two profiles (tutoring/seller, tutoring/buyer) come from keys/test/vectors.json\'s seed through keys/. Every other secret, key and private seed is sha256 of "forest registry fixture: <name>": the issuers\' are "issuer A" and "issuer B".',
  setup: {
    circuit: 'registry/circuit/person.circom, the devnet setup',
    zkeySha256: sha256File(artifacts.zkey),
    wasmSha256: sha256File(artifacts.wasm),
  },
  scopeNamespace: SCOPE_NS,
  messageNamespace: MESSAGE_NS,
  messageLayout: 'keccak256(messageNamespace || main key (32 bytes)) >> 8',
  issuers: Object.fromEntries((Object.keys(issuerPrivate) as Issuer[]).map((i) => [i, hex(issuerKeyBytes(issuerKeyOf(issuerPrivate[i])))])),
  proofs,
  wire: {
    what: "Alice's tutoring/seller row at issuer A, paid by payerSeed's key, written while the clock reads made",
    programId: register.programId.toBase58(),
    payer: payer.publicKey.toBase58(),
    payerSeed: hex(seedOf('payer')),
    made,
    rowAddress: row.toBase58(),
    register: hex(register.data),
    refund: hex(refund.data),
    row: hex(rowBytes),
  },
}

mkdirSync(dirname(outPath), { recursive: true })
writeFileSync(outPath, JSON.stringify(out, null, 1) + '\n')
console.log(`wrote ${outPath}`)
// snarkjs leaves worker threads running; nothing else is pending.
process.exit(0)
