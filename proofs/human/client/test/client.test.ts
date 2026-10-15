// What the client computes, checked against the proofs the program accepted and the wire vectors
// the program wrote, and one registration made from a real note with the committed devnet setup.
//
// No chain: the fixtures are the ones the LiteSVM tests run against the real program, so if either
// side drifted, one of the two fails.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { sha256 } from '@noble/hashes/sha2.js'
import { ComputeBudgetProgram, Keypair, PublicKey, SystemProgram } from '@solana/web3.js'

import { issuerSecret } from '../../../keys/src/index.ts'
import {
  BN254_R,
  MAX_LABEL,
  MESSAGE_NS,
  PROGRAM_ID,
  ROW_DISCRIMINATOR,
  ROW_OFFSET,
  ROW_SEED,
  SCOPE_NS,
  base58,
  buildRegistration,
  compressG1,
  compressG2,
  decodeRow,
  discriminator,
  fetchRow,
  fetchRows,
  fromBytes32,
  isFieldElement,
  issuerKeyBytes,
  issuerKeyOf,
  messageOf,
  noteNumberOf,
  proofBytes,
  proofFromBytes,
  refundIx,
  registerIx,
  rowAddress,
  rowSpace,
  scalarOf,
  scopeOf,
  signNote,
  stampOf,
  toBytes32,
  verifyPerson,
  verifyTier,
  type IssuerKey,
  type SnarkjsProof,
} from '../src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
const fixtures = JSON.parse(readFileSync(join(here, '../../program/tests-litesvm/fixtures/proofs.json'), 'utf8'))
const lib = readFileSync(join(here, '../../program/src/lib.rs'), 'utf8')
const keysVectors = JSON.parse(readFileSync(join(here, '../../../keys/test/vectors.json'), 'utf8'))
const seed = Buffer.from(keysVectors.seed, 'hex')
const [nameA, nameB] = keysVectors.issuers.map((i: { name: string }) => i.name)
const artifacts = { wasm: join(here, '../../circuit/devnet/person.wasm'), zkey: join(here, '../../circuit/devnet/person.zkey') }
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
const bytes = (h: string) => new Uint8Array(Buffer.from(h, 'hex'))
/** The fixtures' rule for a fixed secret or key: sha256 of a name. */
const seedOf = (name: string) => sha256(new TextEncoder().encode(`forest registry fixture: ${name}`))

type Fixture = Record<'name' | 'issuer' | 'issuerKey' | 'label' | 'profile' | 'stamp' | 'tier' | 'scope' | 'message' | 'a' | 'b' | 'c', string> & {
  uncompressed: { a: string; b: string; c: string }
}
const proofNamed = (name: string): Fixture => fixtures.proofs.find((p: Fixture) => p.name === name)
const issuerOf = (h: string): IssuerKey => [fromBytes32(bytes(h.slice(0, 64))), fromBytes32(bytes(h.slice(64)))]
const argsOf = (p: Fixture, payer: PublicKey) => ({
  profile: new PublicKey(p.profile),
  label: p.label,
  stamp: bytes(p.stamp),
  issuer: issuerOf(p.issuerKey),
  tier: bytes(p.tier),
  proof: { a: bytes(p.a), b: bytes(p.b), c: bytes(p.c) },
  payer,
})
/** A fixture's proof as snarkjs writes it, from the points the program decompressed. G2 arrives
 * as x.c1, x.c0, y.c1, y.c0; snarkjs writes each pair c0 first. */
const snarkjsOf = (p: Fixture): SnarkjsProof => {
  const u = p.uncompressed
  const n = (h: string, i: number) => fromBytes32(bytes(h.slice(i * 64, i * 64 + 64))).toString()
  return {
    pi_a: [n(u.a, 0), n(u.a, 1), '1'],
    pi_b: [[n(u.b, 1), n(u.b, 0)], [n(u.b, 3), n(u.b, 2)], ['1', '0']],
    pi_c: [n(u.c, 0), n(u.c, 1), '1'],
  }
}

test("the namespaces, the program id, the seed and the limits are the program's own", () => {
  assert.ok(lib.includes(`b"${SCOPE_NS}"`), 'the scope namespace must match the program')
  assert.ok(lib.includes(`b"${MESSAGE_NS}"`), 'the message namespace must match the program')
  assert.equal(SCOPE_NS, 'forest.foundation/label/v1/')
  assert.ok(lib.includes(`declare_id!("${PROGRAM_ID.toBase58()}")`), 'the program id')
  assert.ok(lib.includes(`pub const ROW_SEED: &[u8] = b"${new TextDecoder().decode(ROW_SEED)}";`), 'the seed')
  assert.ok(lib.includes(`pub const MAX_LABEL: usize = ${MAX_LABEL};`), 'the longest label')
  assert.ok(lib.includes(`assert!(Row::space(0) == ${rowSpace(0)});`), "the row's size")
  assert.ok(!lib.includes('realloc') && !lib.includes('close ='), 'a row is written once: nothing grows or closes it')
  assert.equal(fixtures.scopeNamespace, SCOPE_NS)
  assert.equal(fixtures.messageNamespace, MESSAGE_NS)
})

test('the scope and the message are what the accepted proofs carry', () => {
  for (const p of fixtures.proofs as Fixture[]) {
    assert.equal(hex(toBytes32(scopeOf(p.label))), p.scope, `${p.name}: scope`)
    assert.equal(hex(toBytes32(messageOf(new PublicKey(p.profile)))), p.message, `${p.name}: message`)
  }
})

test('the message names the main key and nothing else', () => {
  const key = new PublicKey(proofNamed('alice-tutoring-A').profile)
  assert.equal(messageOf(key), messageOf(key.toBytes()), 'a key or its bytes')
  assert.notEqual(messageOf(key), messageOf(Keypair.generate().publicKey), 'another key, another message')
  assert.throws(() => messageOf(new Uint8Array(31)), /32 bytes/)
  assert.throws(() => messageOf(new Uint8Array(33)), /32 bytes/)
})

test('a label of any text gives a scope, every scope is a field element, and namespaces never collide', () => {
  for (const label of ['', 'a', 'tutoring/seller', 'x'.repeat(128), 'ünïcødé/ラベル']) {
    const s = scopeOf(label)
    assert.ok(isFieldElement(s) && s < BN254_R, label)
  }
  const key = new Uint8Array(32).fill(7)
  assert.notEqual(scopeOf(new TextDecoder().decode(key)), messageOf(key))
})

test("the stamp is Poseidon(scope, scalar), keys/'s scalar: one per person, per issuer, per label", async () => {
  for (const issuer of keysVectors.issuers) {
    const s = await issuerSecret(seed, issuer.name)
    assert.equal(scalarOf(s.secret), s.scalar)
  }
  assert.throws(() => scalarOf(new Uint8Array(31)), /32 bytes/)

  // Alice is keys/'s test person: the fixtures' stamps are hers, from her seed and each issuer's
  // name, and her profiles are keys/'s pinned ones.
  const atA = (await issuerSecret(seed, nameA)).secret
  const atB = (await issuerSecret(seed, nameB)).secret
  assert.equal(proofNamed('alice-tutoring-A').profile, keysVectors.mainKeys[0].address, 'her tutoring/seller profile')
  assert.equal(proofNamed('alice-tutoring-A-second-profile').profile, keysVectors.mainKeys[1].address, 'her tutoring/buyer profile')
  for (const [name, secret] of [
    ['alice-tutoring-A', atA],
    ['alice-tutoring-A-second-profile', atA],
    ['alice-tutoring-B', atB],
    ['alice-cleaning-A', atA],
    ['alice-longest-A', atA],
  ] as const) {
    const p = proofNamed(name)
    assert.equal(hex(toBytes32(stampOf(secret, p.label))), p.stamp, name)
  }
  const stamp = (name: string) => proofNamed(name).stamp
  assert.equal(stamp('alice-tutoring-A'), stamp('alice-tutoring-A-second-profile'), 'one issuer, one label, two profiles: one stamp')
  assert.notEqual(stamp('alice-tutoring-A'), stamp('alice-tutoring-B'), 'another issuer, another stamp')
  assert.notEqual(stamp('alice-tutoring-A'), stamp('alice-cleaning-A'), 'another label, another stamp')
})

test("a row's address is a hash of its stamp and nothing else", () => {
  const stamp = bytes(proofNamed('alice-tutoring-A').stamp)
  const [expected] = PublicKey.findProgramAddressSync([Buffer.from('row'), Buffer.from(stamp)], PROGRAM_ID)
  assert.equal(rowAddress(stamp).toBase58(), expected.toBase58())
  assert.equal(rowAddress(fromBytes32(stamp)).toBase58(), expected.toBase58(), 'as bytes or as a number')
  assert.equal(rowAddress(stamp).toBase58(), fixtures.wire.rowAddress)
})

test('the compressed points are the ones the program decompressed', () => {
  for (const p of fixtures.proofs as Fixture[]) {
    const u = p.uncompressed
    const n = (h: string, i: number) => fromBytes32(bytes(h.slice(i * 64, i * 64 + 64)))
    assert.equal(hex(compressG1(n(u.a, 0), n(u.a, 1))), p.a, `${p.name}: A`)
    // G2 arrives as x.c1, x.c0, y.c1, y.c0.
    assert.equal(hex(compressG2(n(u.b, 1), n(u.b, 0), n(u.b, 3), n(u.b, 2))), p.b, `${p.name}: B`)
    assert.equal(hex(compressG1(n(u.c, 0), n(u.c, 1))), p.c, `${p.name}: C`)
  }
})

test('every proof the program accepted holds off chain too, for its issuer, label, main key, stamp and tier', async () => {
  for (const p of fixtures.proofs as Fixture[]) {
    const input = { proof: snarkjsOf(p), issuer: issuerOf(p.issuerKey), label: p.label, profile: new PublicKey(p.profile), stamp: bytes(p.stamp), tier: fromBytes32(bytes(p.tier)) }
    assert.equal(await verifyPerson(input), true, p.name)
    assert.equal(hex(issuerKeyBytes(input.issuer)), fixtures.issuers[p.issuer], `${p.name}: its issuer's key`)
  }
  assert.equal(fixtures.issuers.A, hex(issuerKeyBytes(issuerKeyOf(seedOf('issuer A')))), "issuer A's key is the fixtures' rule")
})

test('the wire format written twice still matches', () => {
  // The client's bytes, from its own builders, against the vectors the Rust harness checks against
  // its own hand-written bytes and against the row the program actually writes.
  const w = fixtures.wire
  const a = proofNamed('alice-tutoring-A')
  const payer = new PublicKey(w.payer)
  assert.equal(PROGRAM_ID.toBase58(), w.programId)

  const register = registerIx(argsOf(a, payer))
  const row = rowAddress(bytes(a.stamp))
  const refund = refundIx({ row, payer })
  assert.equal(hex(register.data), w.register, 'register')
  assert.equal(hex(refund.data), w.refund, 'refund')
  assert.deepEqual([...register.data.subarray(0, 8)], [...discriminator('global', 'register')])
  assert.equal(register.data.length, 8 + 32 + 64 + 32 + 128 + 4 + a.label.length, 'no time: the program sets it')

  // Accounts: the row, the profile (a signer), the payer (a signer), the system program; refund
  // signs nothing.
  assert.deepEqual(
    register.keys.map((k) => [k.pubkey.toBase58(), k.isSigner, k.isWritable]),
    [
      [row.toBase58(), false, true],
      [a.profile, true, false],
      [payer.toBase58(), true, true],
      [SystemProgram.programId.toBase58(), false, false],
    ],
  )
  assert.deepEqual(refund.keys.map((k) => [k.pubkey.toBase58(), k.isSigner, k.isWritable]), [
    [row.toBase58(), false, true],
    [payer.toBase58(), false, true],
  ])

  // The row the program wrote, decoded: every fixed field at its fixed offset, the label last.
  const decoded = decodeRow(bytes(w.row))
  assert.equal(decoded.profile.toBase58(), a.profile)
  assert.equal(hex(toBytes32(decoded.stamp)), a.stamp)
  assert.equal(hex(issuerKeyBytes(decoded.issuer)), fixtures.issuers.A)
  assert.equal(decoded.payer.toBase58(), w.payer)
  assert.equal(decoded.made, w.made)
  assert.equal(decoded.label, a.label)
  assert.equal(bytes(w.row).length, rowSpace(a.label.length))
  assert.equal(rowSpace(a.label.length), 195, 'a 15-byte label: 195 bytes, forever')
  assert.deepEqual([...bytes(w.row).subarray(0, 8)], [...ROW_DISCRIMINATOR])
})

test('decodeRow refuses anything that is not exactly a row', () => {
  const good = bytes(fixtures.wire.row)
  assert.throws(() => decodeRow(good.subarray(0, good.length - 1)), /not a row/, 'one byte short')
  assert.throws(() => decodeRow(new Uint8Array([...good, 0])), /not a row/, 'one byte extra')
  const wrong = good.slice()
  wrong[0] ^= 1
  assert.throws(() => decodeRow(wrong), /not a row/, 'another discriminator')
  const longLabel = good.slice()
  new DataView(longLabel.buffer).setUint32(ROW_OFFSET.label, MAX_LABEL + 1, true)
  assert.throws(() => decodeRow(longLabel), /not a row/, 'a label over 128 bytes')
})

test('the builders refuse what the program would refuse, before any proof is made', async () => {
  const a = proofNamed('alice-tutoring-A')
  const payer = Keypair.generate().publicKey
  assert.throws(() => registerIx({ ...argsOf(a, payer), label: 'x'.repeat(MAX_LABEL + 1) }), /at most 128 bytes/)
  assert.throws(() => registerIx({ ...argsOf(a, payer), issuer: [1n] as unknown as IssuerKey }), /two numbers/)
  assert.throws(() => registerIx({ ...argsOf(a, payer), stamp: new Uint8Array(31) }), /32 bytes/)
  assert.throws(() => registerIx({ ...argsOf(a, payer), proof: { a: new Uint8Array(32), b: new Uint8Array(32), c: new Uint8Array(32) } }), /32, 64 and 32/)

  const secret = (await issuerSecret(seed, nameA)).secret
  const note = signNote(seedOf('issuer A'), { noteNumber: noteNumberOf(secret), embedding: new Uint8Array(4), model: 'm', tier: 1n })
  const base = { secret, note, label: 'tutoring/seller', profile: payer, artifacts: { wasm: '', zkey: '' }, payer, recentBlockhash: PublicKey.default.toBase58() }
  await assert.rejects(buildRegistration({ ...base, label: 'x'.repeat(129) }), /at most 128 bytes/)
  await assert.rejects(buildRegistration({ ...base, secret: (await issuerSecret(seed, nameB)).secret }), /not for this secret/)
  await assert.rejects(buildRegistration({ ...base, note: { ...note, tier: 2n } }), /signature is not on this note/)
})

test('buildRegistration: a real proof from a signed note, and the register the program takes', async () => {
  // Alice's note at issuer A, signed again with the fixtures' key: the stamp depends on her secret
  // and the label only, so it is the fixture's, and the row's address too.
  const secret = (await issuerSecret(seed, nameA)).secret
  const note = signNote(seedOf('issuer A'), {
    noteNumber: noteNumberOf(secret),
    embedding: new Uint8Array(Float32Array.from([0.25, -0.5, 0.125]).buffer),
    model: 'example-face-model/1',
    tier: 2n,
  })
  const a = proofNamed('alice-tutoring-A')
  const profile = new PublicKey(a.profile)
  const payer = Keypair.generate().publicKey
  const r = await buildRegistration({ secret, note, label: a.label, profile, artifacts, payer, recentBlockhash: PublicKey.default.toBase58() })

  assert.equal(hex(toBytes32(r.stamp)), a.stamp, "the fixture's stamp")
  assert.equal(r.row.toBase58(), fixtures.wire.rowAddress)
  assert.equal(hex(issuerKeyBytes(r.issuer)), fixtures.issuers.A)
  assert.equal(r.tier, 2n)
  assert.equal(await verifyPerson({ proof: r.proof, issuer: r.issuer, label: a.label, profile, stamp: r.stamp, tier: r.tier }), true)
  assert.equal(hex(r.instruction.data), hex(registerIx({ profile, label: a.label, stamp: r.stamp, issuer: r.issuer, tier: r.tier, proof: r.compressed, payer }).data))
  const tx = r.transaction
  assert.equal(tx.message.header.numRequiredSignatures, 2, 'the payer and the main key sign')
  assert.ok(!tx.message.staticAccountKeys.some((k) => k.equals(ComputeBudgetProgram.programId)), 'no compute-budget instruction')
})

test('rows read back through any connection, filtered at fixed offsets', async () => {
  const w = fixtures.wire
  const data = Buffer.from(w.row, 'hex')
  const address = new PublicKey(w.rowAddress)
  const seen: unknown[] = []
  const connection = {
    async getProgramAccounts(programId: PublicKey, config: unknown) {
      seen.push([programId.toBase58(), config])
      return [{ pubkey: address, account: { data, owner: PROGRAM_ID, lamports: 1, executable: false } }]
    },
    async getAccountInfo(at: PublicKey) {
      return at.equals(address) ? { data, owner: PROGRAM_ID, lamports: 1, executable: false } : null
    },
  }
  const a = proofNamed('alice-tutoring-A')
  const profile = new PublicKey(a.profile)
  const issuer = issuerOf(fixtures.issuers.A)
  const rows = await fetchRows(connection as never, { profile, issuer, label: 'tutoring/seller' })
  assert.equal(rows.length, 1)
  assert.equal(rows[0].row.label, 'tutoring/seller')
  assert.equal(rows[0].address.toBase58(), address.toBase58())
  const [[programId, config]] = seen as [[string, { filters: { memcmp: { offset: number; bytes: string } }[] }]]
  assert.equal(programId, PROGRAM_ID.toBase58())
  assert.deepEqual(config.filters.map((f) => f.memcmp.offset), [0, 8, 72, 176], 'the discriminator, the profile, the issuer, the label')
  assert.equal(config.filters[0].memcmp.bytes, base58(ROW_DISCRIMINATOR))
  assert.equal(config.filters[1].memcmp.bytes, profile.toBase58())
  assert.equal(config.filters[2].memcmp.bytes, base58(bytes(fixtures.issuers.A)), "the issuer's key, x then y")
  assert.equal(config.filters[3].memcmp.bytes, base58(new Uint8Array([15, 0, 0, 0, ...new TextEncoder().encode('tutoring/seller')])), 'the length, then the label')
  assert.deepEqual(await fetchRows(connection as never, { label: 'tutoring/sellers' }), [], 'checked exactly too')

  assert.equal((await fetchRow(connection as never, bytes(a.stamp)))?.label, 'tutoring/seller')
  assert.equal(await fetchRow(connection as never, bytes(proofNamed('bob-tutoring-A').stamp)), null, 'no row')
  const foreign = { getAccountInfo: async () => ({ data, owner: Keypair.generate().publicKey, lamports: 1, executable: false }) }
  await assert.rejects(fetchRow(foreign as never, bytes(a.stamp)), /not the registry's/)
})

test('verifyTier: the tier a profile shows, its proof checked against its row', async () => {
  // Alice's row as the program wrote it, and the proof it took, attached to her profile.
  const w = fixtures.wire
  const connectionWith = (data: Uint8Array) => ({
    async getAccountInfo(at: PublicKey) {
      return at.toBase58() === w.rowAddress ? { data: Buffer.from(data), owner: PROGRAM_ID, lamports: 1, executable: false } : null
    },
  })
  const connection = connectionWith(bytes(w.row))
  const a = proofNamed('alice-tutoring-A')
  const shown = { profile: new PublicKey(a.profile), stamp: bytes(a.stamp), tier: 2n, proof: snarkjsOf(a) }

  const row = await verifyTier(connection as never, shown)
  assert.ok(row, 'her tier holds')
  assert.equal(hex(issuerKeyBytes(row.issuer)), fixtures.issuers.A, 'the row gives the issuer to weigh')
  assert.equal(row.made, w.made, 'and when the row was made')

  // The issuer's key in the row replaced by another: the proof no longer holds for it.
  const otherIssuer = bytes(w.row)
  otherIssuer.set(bytes(fixtures.issuers.B), ROW_OFFSET.issuer)
  const cases: [string, Parameters<typeof verifyTier>[1], ReturnType<typeof connectionWith>?][] = [
    ['another tier', { ...shown, tier: 3n }],
    ['the proof on her other profile', { ...shown, profile: new PublicKey(proofNamed('alice-tutoring-A-second-profile').profile) }],
    ["a stamp with no row: Bob's", { ...shown, stamp: bytes(proofNamed('bob-tutoring-A').stamp) }],
    ['her proof for another label', { ...shown, proof: snarkjsOf(proofNamed('alice-cleaning-A')) }],
    ["another issuer's key in the row", shown, connectionWith(otherIssuer)],
  ]
  for (const [what, input, c] of cases) assert.equal(await verifyTier((c ?? connection) as never, input), null, what)
})

test('a person proof as a profile shows it (records/schemas/examples/profile.json): verifyTier takes it as it is', async () => {
  // The example card's person proof, read as any reader reads a profile's `proofs`.
  const card = JSON.parse(readFileSync(join(here, '../../../records/schemas/examples/profile.json'), 'utf8'))
  const shown = card.proofs.find((p: { circuit: string }) => p.circuit === 'person')
  const a = proofNamed('alice-tutoring-A')
  const input = {
    profile: new PublicKey(a.profile),
    issuer: bytes(shown.issuer),
    label: shown.label,
    stamp: bytes(shown.stamp),
    tier: BigInt(shown.tier),
    proof: new Uint8Array(Buffer.from(shown.proof, 'base64url')),
  }
  assert.deepEqual(input.proof, proofBytes(snarkjsOf(a)), 'the 256 bytes of the proof the program took')
  assert.deepEqual(proofFromBytes(input.proof), snarkjsOf(a), 'and back')

  const w = fixtures.wire
  const connection = {
    async getAccountInfo(at: PublicKey) {
      return at.toBase58() === w.rowAddress ? { data: Buffer.from(bytes(w.row)), owner: PROGRAM_ID, lamports: 1, executable: false } : null
    },
  }
  const row = await verifyTier(connection as never, input)
  assert.ok(row, 'her tier holds, from the card as it is')
  assert.equal(hex(issuerKeyBytes(row.issuer)), shown.issuer)
  assert.ok(await verifyTier(connection as never, { ...input, issuer: issuerOf(shown.issuer) }), 'the issuer as its key, too')
  assert.ok(await verifyTier(connection as never, { ...input, issuer: undefined, label: undefined }), 'or not shown')

  const bent = input.proof.slice()
  bent[255] ^= 1
  const cases: [string, Parameters<typeof verifyTier>[1]][] = [
    ['another issuer shown than the row’s', { ...input, issuer: bytes(fixtures.issuers.B) }],
    ['another label shown than the row’s', { ...input, label: 'cleaning/seller' }],
    ['another tier', { ...input, tier: 3n }],
    ['a bent byte', { ...input, proof: bent }],
    ['not 256 bytes', { ...input, proof: input.proof.subarray(0, 255) }],
  ]
  for (const [what, c] of cases) assert.equal(await verifyTier(connection as never, c), null, what)
  assert.equal(await verifyPerson({ ...input, issuer: issuerOf(shown.issuer), proof: input.proof.subarray(0, 255) }), false, 'verifyPerson says false, and never throws')
  assert.ok(await verifyPerson({ ...input, issuer: issuerOf(shown.issuer) }), 'and takes the bytes too')
})
