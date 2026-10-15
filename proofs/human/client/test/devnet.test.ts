// Read-only smoke tests against the registry's devnet deploy, as registry/devnet/devnet.json
// records it. They send nothing.
//
//   npm run test:devnet          (FOREST_DEVNET_RPC for another endpoint, FOREST_DEVNET_RECORD another record)
//
// Skipped unless FOREST_DEVNET=1 (the npm script sets it), so `npm test` never needs a network, and
// until the record holds a deployed registry and its row.

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { Connection, PublicKey } from '@solana/web3.js'

import { fetchRow, fetchRows, fromBytes32, issuerKeyBytes, rowAddress, rowSpace, toBytes32, verifyTier, type IssuerKey } from '../src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
const record = JSON.parse(readFileSync(process.env.FOREST_DEVNET_RECORD ?? join(here, '../../devnet/devnet.json'), 'utf8'))
const skip =
  process.env.FOREST_DEVNET !== '1' ? 'set FOREST_DEVNET=1 (npm run test:devnet)' : !record.registry || !record.row ? 'not deployed yet: the record holds no registry and row' : false
const connection = new Connection(process.env.FOREST_DEVNET_RPC ?? record.rpc, 'confirmed')
const programId = skip ? PublicKey.default : new PublicKey(record.registry.programId)
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
const issuerOf = (h: string): IssuerKey => [fromBytes32(Buffer.from(h.slice(0, 64), 'hex')), fromBytes32(Buffer.from(h.slice(64), 'hex'))]

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
/** The public RPC rate-limits; wait it out rather than fail. */
async function retry<T>(f: () => Promise<T>): Promise<T> {
  for (let i = 0; ; i++) {
    try {
      return await f()
    } catch (e) {
      if (i >= 8 || !String(e).includes('429')) throw e
      await sleep(2_000 * (i + 1))
    }
  }
}

test('the registry is deployed at its recorded id, its bytes the build, its upgrade key the deploy key', { skip }, async () => {
  const program = await retry(() => connection.getAccountInfo(programId))
  assert.ok(program?.executable, 'an executable program')
  const data = await retry(() => connection.getAccountInfo(new PublicKey(record.registry.programData)))
  assert.ok(data)
  // The program data account: 4 bytes of kind, 8 of slot, 1 + 32 of upgrade authority, then the program.
  assert.equal(new PublicKey(data.data.subarray(13, 45)).toBase58(), record.registry.upgradeAuthority)
  const so = data.data.subarray(45, 45 + record.registry.soBytes)
  assert.equal(createHash('sha256').update(so).digest('hex'), record.registry.soSha256)
})

test('the row is on chain as recorded, never changed, exactly rent exempt after the refund', { skip }, async () => {
  const r = record.row
  const stamp = Buffer.from(r.stamp, 'hex')
  assert.equal(rowAddress(stamp, programId).toBase58(), r.address)
  const row = await retry(() => fetchRow(connection, stamp, { programId }))
  assert.ok(row, 'the row exists')
  assert.equal(row.profile.toBase58(), r.profile)
  assert.equal(hex(toBytes32(row.stamp)), r.stamp)
  assert.equal(hex(issuerKeyBytes(row.issuer)), r.issuer.key)
  assert.equal(row.label, r.label)
  assert.equal(row.payer.toBase58(), r.onChain.payer)
  assert.equal(row.made, r.onChain.made)
  const info = await retry(() => connection.getAccountInfo(new PublicKey(r.address)))
  assert.equal(info?.data.length, rowSpace(Buffer.byteLength(r.label)))
  assert.equal(info?.lamports, await retry(() => connection.getMinimumBalanceForRentExemption(info!.data.length)), 'exactly rent exempt after the refund')
})

test('the tier the profile shows checks against its row, and no other tier does', { skip }, async () => {
  const r = record.row
  const shown = { profile: new PublicKey(r.profile), stamp: Buffer.from(r.stamp, 'hex'), tier: BigInt(r.shown.tier), proof: r.shown.proof }
  assert.ok(await retry(() => verifyTier(connection, shown, { programId })))
  assert.equal(await retry(() => verifyTier(connection, { ...shown, tier: shown.tier + 1n }, { programId })), null)
})

test('the profile has one row and the issuer one, read the way any reader reads', { skip }, async () => {
  const byProfile = await retry(() => fetchRows(connection, { profile: new PublicKey(record.row.profile), programId }))
  assert.deepEqual(byProfile.map((r) => r.address.toBase58()), [record.row.address])
  const byIssuer = await retry(() => fetchRows(connection, { issuer: issuerOf(record.row.issuer.key), programId }))
  assert.deepEqual(byIssuer.map((r) => r.address.toBase58()), [record.row.address])
})

test('every recorded transaction landed, and only the refusal failed', { skip, timeout: 300_000 }, async () => {
  for (const { what, signature } of record.transactions.filter((t: { signature?: string }) => t.signature)) {
    const { value } = await retry(() => connection.getSignatureStatuses([signature], { searchTransactionHistory: true }))
    assert.ok(value[0], `${what}: not found`)
    assert.equal(value[0].err !== null, signature === record.row.refused.signature, `${what}: ${JSON.stringify(value[0].err)}`)
    await sleep(300)
  }
})
