// The registry on devnet, used for real: a stand-in issuer signs a note for a person, and a fee
// payer pays for one row, which the main key signs; then the refusal of a second row for the same
// stamp, a refund, and the tier the profile shows checked against its row the way any reader would.
//
//   FOREST_DEVNET_KEYS=<dir> node scripts/devnet.ts        (after registry/devnet/deploy.sh)
//
// <dir> holds payer.json, as registry/devnet/deploy.sh writes it: the fee payer, which pays every
// fee and every deposit. It is read, never printed and never written anywhere. Everything public
// (addresses, signatures, what each did, and the proof the profile shows) goes into
// registry/devnet/devnet.json (FOREST_DEVNET_RECORD overrides the path; FOREST_DEVNET_RPC the
// endpoint). Each step checks the chain first and is skipped if it is done, so the script can be run
// again after a failure.
//
// The person is keys/'s pinned test seed (`keys/test/vectors.json`): their secret for the stand-in
// issuer, and their two profiles (freelance/seller, which the row names, and freelance/buyer, which
// tries for the same stamp), come from it through `keys/` itself. The issuer is a stand-in this
// script makes, its key from a fixed text, and is recorded as such: no issuer signs notes yet.

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import { sha256 } from '@noble/hashes/sha2.js'
import { Connection, Keypair, PublicKey, SystemProgram, Transaction, VersionedTransaction } from '@solana/web3.js'

import { issuerSecret, mainKey } from '../../../keys/src/index.ts'
import {
  buildRegistration,
  fetchRow,
  fetchRows,
  issuerKeyBytes,
  issuerKeyOf,
  noteNumberOf,
  refundIx,
  rowAddress,
  rowSpace,
  signNote,
  stampOf,
  toBytes32,
  verifyTier,
  type SnarkjsProof,
} from '../src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
/** A label as `market/role`, the recommended shape: this profile sells in `freelance`. */
const LABEL = 'freelance/seller'
/** The stand-in issuer's name: what the person's secret for it is mixed from. */
const ISSUER_NAME = 'stand-in.devnet.forest.example'
const TIER = 1n

const keysDir = process.env.FOREST_DEVNET_KEYS
if (!keysDir) throw new Error('set FOREST_DEVNET_KEYS to the directory holding the devnet keypairs')
const recordPath = resolve(process.env.FOREST_DEVNET_RECORD ?? join(here, '../../devnet/devnet.json'))
const record = JSON.parse(readFileSync(recordPath, 'utf8'))
if (!record.registry?.programId) throw new Error('no registry in the record: run registry/devnet/deploy.sh first')
const rpc = process.env.FOREST_DEVNET_RPC ?? record.rpc
const connection = new Connection(rpc, 'confirmed')
const programId = new PublicKey(record.registry.programId)

const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(join(keysDir, 'payer.json'), 'utf8'))))
if (payer.publicKey.toBase58() !== record.keys.payer) throw new Error('the payer key is not the one the record names')

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
/** A stand-in's private seed: sha256 of this text. Public on purpose; devnet only. */
const standInSeed = (name: string) => sha256(new TextEncoder().encode(`forest devnet stand-in: ${name}`))

function save(): void {
  writeFileSync(recordPath, JSON.stringify(record, null, 2) + '\n')
}

function note(what: string, signature: string): void {
  record.transactions ??= []
  record.transactions.push({ what, signature })
  save()
  console.log(`  ${signature}  ${what}`)
}

/** Polls rather than subscribing. A rate limit while polling is waited out, not thrown: the
 * transaction is already sent, and throwing would lose its signature from the record. */
async function settle(signature: string): Promise<unknown> {
  for (let i = 0; i < 240; i++) {
    let value
    try {
      ;({ value } = await connection.getSignatureStatuses([signature], { searchTransactionHistory: true }))
    } catch (e) {
      if (!String(e).includes('429')) throw e
      await sleep(5_000)
      continue
    }
    const status = value[0]
    if (status && (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized')) return status.err
    await sleep(500)
  }
  throw new Error(`${signature} was never confirmed`)
}

async function meta(signature: string) {
  for (let i = 0; i < 20; i++) {
    const tx = await connection
      .getTransaction(signature, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 })
      .catch((e) => (String(e).includes('429') ? null : Promise.reject(e)))
    if (tx?.meta) return tx.meta
    await sleep(3_000)
  }
  throw new Error(`no transaction for ${signature}`)
}

async function sendVersioned(tx: VersionedTransaction, signers: Keypair[], skipPreflight = false): Promise<{ signature: string; err: unknown }> {
  tx.sign(signers)
  const signature = await connection.sendRawTransaction(tx.serialize(), { skipPreflight })
  return { signature, err: await settle(signature) }
}

async function sendLegacy(tx: Transaction): Promise<{ signature: string; err: unknown }> {
  tx.feePayer = payer.publicKey
  tx.recentBlockhash = (await connection.getLatestBlockhash('confirmed')).blockhash
  tx.sign(payer)
  const signature = await connection.sendRawTransaction(tx.serialize())
  return { signature, err: await settle(signature) }
}

const blockhash = async () => (await connection.getLatestBlockhash('confirmed')).blockhash

// ---------------------------------------------------------------------------------------------

console.log(`registry ${programId.toBase58()} on ${rpc}`)

// The person: keys/'s pinned test seed, and their secret for the stand-in issuer.
const vectors = JSON.parse(readFileSync(join(here, '../../../keys/test/vectors.json'), 'utf8'))
const seed = Buffer.from(vectors.seed, 'hex')
const { secret } = await issuerSecret(seed, ISSUER_NAME)

// The stand-in issuer signs a note for the person's note number: a made-up embedding, a model
// name, and a tier.
const issuerPrivate = standInSeed('issuer')
const issuer = issuerKeyOf(issuerPrivate)
const signed = signNote(issuerPrivate, {
  noteNumber: noteNumberOf(secret),
  embedding: new Uint8Array(Float32Array.from({ length: 128 }, (_, i) => Math.cos(i)).buffer),
  model: 'stand-in-face-model/1',
  tier: TIER,
})

// Two profiles the person holds, both from keys/: the row's, and a second one the registry refuses
// for the same stamp.
const profile = Keypair.fromSeed((await mainKey(seed, LABEL)).privateKey)
const second = Keypair.fromSeed((await mainKey(seed, 'freelance/buyer')).privateKey)
const stamp = stampOf(secret, LABEL)
const address = rowAddress(stamp, programId)
const artifacts = { wasm: join(here, '../../circuit/devnet/person.wasm'), zkey: join(here, '../../circuit/devnet/person.zkey') }

if (record.row && record.row.stamp !== hex(toBytes32(stamp))) throw new Error(`the record holds another row (${record.row.address}); move it first`)
record.row = {
  ...(record.row ?? {}),
  what: "one row: keys/'s test person (its test seed), with a note a stand-in issuer signed, under freelance/seller, for their freelance/seller profile; the main key signs, a fee payer pays",
  label: LABEL,
  profile: profile.publicKey.toBase58(),
  issuer: { standIn: true, name: ISSUER_NAME, key: hex(issuerKeyBytes(issuer)), tier: TIER.toString() },
  stamp: hex(toBytes32(stamp)),
  address: address.toBase58(),
  keys: "the profiles are keys/'s mainKey(test seed, 'freelance/seller') and (test seed, 'freelance/buyer'); the person's secret is keys/'s issuerSecret(test seed, name); the issuer's private key is sha256 of `forest devnet stand-in: issuer`",
}
save()

const build = async (who: Keypair) =>
  buildRegistration({ secret, note: signed, label: LABEL, profile: who.publicKey, artifacts, payer: payer.publicKey, recentBlockhash: await blockhash(), programId })

// register: the main key signs, the fee payer pays. The proof goes in the record: it is what the
// profile shows for its tier.
if (!(await fetchRow(connection, stamp, { programId }))) {
  const started = Date.now()
  const reg = await build(profile)
  const provingMs = Date.now() - started
  const bytes = reg.transaction.serialize().length
  const { signature, err } = await sendVersioned(reg.transaction, [payer, profile])
  if (err) throw new Error(`register failed: ${JSON.stringify(err)}`)
  const m = await meta(signature)
  record.row.register = { signature, provingMs, bytes, computeUnits: m.computeUnitsConsumed ?? null, fee: m.fee }
  record.row.shown = { what: 'the person proof the profile shows for its tier, as snarkjs writes it', tier: TIER.toString(), proof: reg.proof }
  note(`register: a row under "${LABEL}", the main key signing, the fee payer paying`, signature)
}
// A run stopped between register and the record keeping its proof: a new proof for the same row
// shows the same tier.
if (!record.row.shown) {
  record.row.shown = { what: 'the person proof the profile shows for its tier, as snarkjs writes it', tier: TIER.toString(), proof: (await build(profile)).proof }
  save()
}
const written = (await connection.getAccountInfo(address, 'confirmed'))!.data

// Refused on chain, sent without a preflight so the refusal has a signature: the same person,
// issuer and label for their second profile. The same stamp, so the row already exists.
if (!record.row.refused) {
  const again = await build(second)
  if (!again.row.equals(address)) throw new Error('the second profile has another stamp')
  const sent = await sendVersioned(again.transaction, [payer, second], true)
  if (!sent.err) throw new Error('a second row for the stamp landed')
  const logs = ((await meta(sent.signature)).logMessages ?? []).filter((l) => /already in use|Error Code|failed/.test(l))
  record.row.refused = { secondProfile: second.publicKey.toBase58(), signature: sent.signature, err: sent.err, log: logs }
  note("register again for the same stamp, for the person's second profile: refused, the row already exists", sent.signature)
}

// Refund: 0.001 SOL sent to the row, then refund, which anyone may send, pays exactly that back to
// the payer the row records.
if (!record.row.refund) {
  const gift = await sendLegacy(new Transaction().add(SystemProgram.transfer({ fromPubkey: payer.publicKey, toPubkey: address, lamports: 1_000_000 })))
  if (gift.err) throw new Error(`the gift failed: ${JSON.stringify(gift.err)}`)
  note('0.001 SOL sent to the row, above its minimum', gift.signature)
  const before = await connection.getBalance(address, 'confirmed')
  const refund = await sendLegacy(new Transaction().add(refundIx({ row: address, payer: payer.publicKey, programId })))
  if (refund.err) throw new Error(`refund failed: ${JSON.stringify(refund.err)}`)
  const m = await meta(refund.signature)
  const after = await connection.getBalance(address, 'confirmed')
  if (before - after !== 1_000_000) throw new Error(`refund moved ${before - after}, not the gift`)
  record.row.refund = { gift: gift.signature, signature: refund.signature, lamports: before - after, computeUnits: m.computeUnitsConsumed ?? null }
  note('refund: exactly the 0.001 SOL above the minimum, back to the payer the row records', refund.signature)
}

// Read back the way any reader would: every row of this profile, and the tier it shows checked
// against its row.
const read = await fetchRows(connection, { profile: profile.publicKey, programId }).catch((e) => {
  console.log(`  getProgramAccounts refused by this RPC (${String(e).slice(0, 80)}); read the one row directly`)
  return null
})
const shown = { profile: profile.publicKey, stamp, tier: BigInt(record.row.shown.tier), proof: record.row.shown.proof as SnarkjsProof }
const final = await verifyTier(connection, shown, { programId })
if (!final) throw new Error('the tier the profile shows does not check against its row')
const account = (await connection.getAccountInfo(address, 'confirmed'))!
if (!account.data.equals(written) || account.data.length !== rowSpace(Buffer.byteLength(LABEL))) throw new Error('the row changed')
record.row.onChain = {
  readBy: read ? 'getProgramAccounts, filtered by profile' : "getAccountInfo at the stamp's address",
  rowsOfThisProfile: read?.length ?? null,
  profile: final.profile.toBase58(),
  stamp: hex(toBytes32(final.stamp)),
  issuer: hex(issuerKeyBytes(final.issuer)),
  payer: final.payer.toBase58(),
  made: final.made,
  label: final.label,
  tierChecked: true,
  bytes: account.data.length,
  lamports: account.lamports,
}
save()
if (record.row.onChain.issuer !== record.row.issuer.key || !final.profile.equals(profile.publicKey) || !final.payer.equals(payer.publicKey)) {
  throw new Error('the row is not what was sent')
}
console.log('done')
// snarkjs leaves worker threads running; nothing else is pending.
process.exit(0)
