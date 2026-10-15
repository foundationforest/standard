// The client against a real validator: start one, load the program, and make rows end to end, from
// the keys recipe's seed and a note an issuer signed to rows on the chain, and a tier checked
// against one.
//
//   npm run test:validator
//
// Needs `solana-test-validator` on the PATH and the program built (`cargo build-sbf` in
// ../program); the person circuit's proving files are committed in ../circuit/devnet. If either is
// missing the test says which and skips, rather than failing for the wrong reason.
//
// Everything here polls `getSignatureStatuses` rather than calling `confirmTransaction`, which
// opens a websocket subscription that keeps Node alive long after the test has passed.

import assert from 'node:assert/strict'
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { after, before, test } from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  ComputeBudgetProgram,
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  VersionedTransaction,
} from '@solana/web3.js'

import { issuerSecret, mainKey } from '../../../keys/src/index.ts'
import {
  PROGRAM_ID,
  buildRegistration,
  fetchRow,
  fetchRows,
  issuerKeyOf,
  noteNumberOf,
  refundIx,
  rowSpace,
  signNote,
  verifyTier,
} from '../src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
const soPath = join(here, '../../program/target/deploy/forest_registry.so')
const artifacts = {
  wasm: join(here, '../../circuit/devnet/person.wasm'),
  zkey: join(here, '../../circuit/devnet/person.zkey'),
}
const RPC = 'http://127.0.0.1:8899'
const LABEL = 'tutoring/seller'

function missing(): string | null {
  if (!existsSync(soPath)) return `no program at ${soPath}; run \`cargo build-sbf\` in registry/program`
  if (!existsSync(artifacts.zkey)) return `no proving key at ${artifacts.zkey}`
  return null
}

let validator: ChildProcess | undefined
let ledger: string | undefined
let connection: Connection

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** Wait for a signature without opening a websocket. Returns its error, if it failed. */
async function settle(signature: string): Promise<unknown> {
  for (let i = 0; i < 120; i++) {
    const { value } = await connection.getSignatureStatuses([signature])
    const status = value[0]
    if (status && (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized')) return status.err
    await sleep(250)
  }
  throw new Error(`${signature} was never confirmed`)
}

async function sendVersioned(tx: VersionedTransaction, signers: Keypair[], skipPreflight = false): Promise<{ signature: string; err: unknown }> {
  tx.sign(signers)
  const signature = await connection.sendRawTransaction(tx.serialize(), { skipPreflight })
  return { signature, err: await settle(signature) }
}

async function sendLegacy(tx: Transaction, signer: Keypair): Promise<{ signature: string; err: unknown }> {
  tx.feePayer = signer.publicKey
  tx.recentBlockhash = (await connection.getLatestBlockhash('confirmed')).blockhash
  tx.sign(signer)
  const signature = await connection.sendRawTransaction(tx.serialize())
  return { signature, err: await settle(signature) }
}

async function fund(key: PublicKey): Promise<void> {
  const err = await settle(await connection.requestAirdrop(key, 10 * LAMPORTS_PER_SOL))
  if (err) throw new Error(`airdrop failed: ${JSON.stringify(err)}`)
}

before(
  async () => {
    if (missing()) return
    ledger = mkdtempSync(join(tmpdir(), 'forest-registry-ledger-'))
    validator = spawn('solana-test-validator', ['--reset', '--quiet', '--ledger', ledger, '--bpf-program', PROGRAM_ID.toBase58(), soPath], {
      stdio: 'ignore',
    })
    validator.on('error', () => {
      validator = undefined
    })
    connection = new Connection(RPC, 'confirmed')
    for (let i = 0; i < 90 && validator; i++) {
      try {
        await connection.getVersion()
        return
      } catch {
        await sleep(1000)
      }
    }
    validator = undefined
  },
  { timeout: 150_000 },
)

after(() => {
  validator?.kill('SIGKILL')
  if (ledger) rmSync(ledger, { recursive: true, force: true })
})

test('rows go through a real validator: the main key signs, a fee payer pays, one row per stamp, a tier checked', { timeout: 300_000 }, async (t) => {
  const why = missing()
  if (why) return t.skip(why)
  if (!validator) return t.skip('solana-test-validator did not start (is it on the PATH?)')

  // The person: keys/'s pinned test seed, and two of their profiles, mixed from it by keys/.
  const vectors = JSON.parse(readFileSync(join(here, '../../../keys/test/vectors.json'), 'utf8'))
  const seed = Buffer.from(vectors.seed, 'hex')
  const profile = Keypair.fromSeed((await mainKey(seed, LABEL)).privateKey)
  const second = Keypair.fromSeed((await mainKey(seed, 'tutoring/buyer')).privateKey)

  // Two issuers. Each signs a note for the person's note number with its own key: tier 2 and 1.
  const issuers = [new Uint8Array(32).fill(21), new Uint8Array(32).fill(22)]
  const notes = await Promise.all(
    issuers.map(async (key, i) => {
      const { secret } = await issuerSecret(seed, `issuer-${i}.example`)
      const note = signNote(key, { noteNumber: noteNumberOf(secret), embedding: new Uint8Array(16).fill(i), model: 'example-face-model/1', tier: BigInt(2 - i) })
      return { secret, note }
    }),
  )

  // A fee payer pays for everything; the main key signs its own row.
  const feePayer = Keypair.generate()
  await fund(feePayer.publicKey)
  const build = async (who: Keypair, n: (typeof notes)[number]) =>
    buildRegistration({
      secret: n.secret,
      note: n.note,
      label: LABEL,
      profile: who.publicKey,
      artifacts,
      payer: feePayer.publicKey,
      recentBlockhash: (await connection.getLatestBlockhash('confirmed')).blockhash,
    })

  const reg = await build(profile, notes[0])
  const tx = reg.transaction
  assert.equal(tx.message.header.numRequiredSignatures, 2, 'the fee payer and the main key sign')
  assert.ok(!tx.message.staticAccountKeys.some((k) => k.equals(ComputeBudgetProgram.programId)), 'no compute-budget instruction')
  const sentAt = Math.floor(Date.now() / 1000)
  const { signature, err } = await sendVersioned(tx, [feePayer, profile])
  assert.equal(err, null, signature)
  const meta = await connection.getTransaction(signature, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 })
  const units = meta?.meta?.computeUnitsConsumed ?? 0

  const row = await fetchRow(connection, reg.stamp)
  assert.ok(row)
  assert.equal(row.profile.toBase58(), profile.publicKey.toBase58())
  assert.equal(row.stamp, reg.stamp)
  assert.deepEqual(row.issuer, issuerKeyOf(issuers[0]))
  assert.equal(row.label, LABEL)
  assert.equal(row.payer.toBase58(), feePayer.publicKey.toBase58())
  assert.ok(Math.abs(row.made - sentAt) < 120, `the validator's clock: ${row.made}, sent at ${sentAt}`)
  const written = (await connection.getAccountInfo(reg.row))!.data
  assert.equal(written.length, rowSpace(Buffer.byteLength(LABEL)))

  // A reader checks the tier the profile shows: the proof, against the row.
  const shown = { profile: profile.publicKey, stamp: reg.stamp, tier: 2n, proof: reg.proof }
  assert.ok(await verifyTier(connection, shown), 'tier 2 holds')
  assert.equal(await verifyTier(connection, { ...shown, tier: 3n }), null, 'tier 3 does not')

  // Refused on chain: the same issuer and label for the person's second profile, the same stamp.
  // Through the second issuer, it is another stamp, and lands.
  const again = await build(second, notes[0])
  assert.equal(again.row.toBase58(), reg.row.toBase58())
  assert.notEqual((await sendVersioned(again.transaction, [feePayer, second], true)).err, null, 'a second row for the stamp')
  const other = await build(second, notes[1])
  assert.equal((await sendVersioned(other.transaction, [feePayer, second])).err, null, 'the second profile, through the second issuer')
  const rows = await fetchRows(connection, { label: LABEL })
  assert.deepEqual(rows.map((r) => r.row.profile.toBase58()).sort(), [profile.publicKey.toBase58(), second.publicKey.toBase58()].sort())
  assert.equal((await fetchRows(connection, { issuer: issuerKeyOf(issuers[1]) })).length, 1)

  // Refund: someone sends the row lamports; anyone sends refund; the fee payer, its recorded payer,
  // gets exactly them back, and the row is byte for byte what register wrote.
  const stranger = Keypair.generate()
  await fund(stranger.publicKey)
  const gift = new Transaction().add(SystemProgram.transfer({ fromPubkey: stranger.publicKey, toPubkey: reg.row, lamports: 1_000_000 }))
  assert.equal((await sendLegacy(gift, stranger)).err, null)
  const before = await connection.getBalance(feePayer.publicKey)
  assert.equal((await sendLegacy(new Transaction().add(refundIx({ row: reg.row, payer: feePayer.publicKey })), stranger)).err, null)
  assert.equal((await connection.getBalance(feePayer.publicKey)) - before, 1_000_000)
  assert.deepEqual((await connection.getAccountInfo(reg.row))!.data, written)

  console.log(`register ${units} compute units on a local validator; two rows through two issuers, one refused, a tier checked, a refund to the fee payer`)
})
