// The escrow on devnet, used for real: deals between the devnet parties through
// escrows/solana/devnet/deploy.sh's deploy, in a classic test dollar and in a Token-2022 dollar with
// Open USD's extensions. The `buyer` key is each escrow's payer and the `seller` key its recipient;
// the labels are the key recipe's.
//
//   FOREST_DEVNET_KEYS=<dir> node scripts/devnet.ts        (after escrows/solana/devnet/deploy.sh)
//
// In the classic test dollar:
// 1. invoice: the recipient invoices; the payer reads it, checks its options, and pays in one tap
//    (the deposit address made first, a transfer and `pay`, in one transaction). Nobody marks it:
//    the receipt records the funding time anyway, the ending's.
// 2. takeBack: the payer opens a schedule of one window, half back until a day from now, then paid;
//    funds and marks it in the same transaction; takes back its half.
// 3. stop: the payer opens "paid in a day unless stopped", funds and marks it; stops it; the
//    default is refused, by the client and by the program; both sign a 60/40 split.
// 4. end: the payer opens "paid in a minute and a half unless stopped", funds and marks it; the
//    default is refused before the end time and sent from it by the sponsor's key, a third party.
// 5. late: the payer opens the same kind of schedule and pays nothing in time; after the end time
//    a plain transfer lands; the mark and the default are refused; the payer closes it, and
//    everything goes back.
// In the Open USD-shaped Token-2022 dollar (every extension Open USD has on mainnet, the payer key
// holding every role of the dollar's maker): deals 1 and 3 again, so a one tap and both payouts of
// a split cross Token-2022.
//
// Each dollar is the record's (`testDollar`, `openUsdShaped`) if the payer key holds its mint
// authority on chain; otherwise it is made here, with the payer key as its maker and a mint key
// made for it and kept nowhere, since once the mint is made nothing needs that key again. Before
// the deals, the payer is topped up by minting if it holds less than they need.
//
// The `payer` key pays every network fee and fronts every rent, the way a fee payer would, and is
// recorded as each escrow's sponsor. <dir> holds payer.json, buyer.json and seller.json, as
// escrows/solana/devnet/deploy.sh writes them, read and never printed. The keys must be the ones
// escrows/solana/devnet/devnet.json names in `keys`. Everything public goes into
// escrows/solana/devnet/devnet.json. Each step checks the chain first, so the script can be run again
// after a failure; a mint, and a deal's schedule, are written down before they are sent, so a
// second run finds the same addresses. FOREST_DEVNET_RPC points it at another devnet RPC.

import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  AccountState,
  createAssociatedTokenAccountIdempotentInstruction,
  createInitializeDefaultAccountStateInstruction,
  createInitializeMetadataPointerInstruction,
  createInitializeMint2Instruction,
  createInitializeMintCloseAuthorityInstruction,
  createInitializePermanentDelegateInstruction,
  createInitializeTransferHookInstruction,
  createMintToCheckedInstruction,
  ExtensionType,
  getAccount,
  getExtensionTypes,
  getMinimumBalanceForRentExemptMint,
  getMintLen,
  MINT_SIZE,
  tokenMetadataInitializeWithRentTransfer,
  unpackMint,
} from '@solana/spl-token'
import { Connection, Keypair, PublicKey, SystemProgram, SYSVAR_CLOCK_PUBKEY, Transaction, TransactionInstruction } from '@solana/web3.js'

import {
  agreeIx,
  assertOptionsAgreed,
  canEnd,
  canStop,
  canTakeBack,
  closeUnfundedIx,
  createAndFund,
  createIx,
  decodeEscrow,
  decodeEvents,
  endIx,
  endTime,
  hookAccounts,
  invoiceIx,
  keysFor,
  keysOf,
  markFundedIx,
  payerAccount,
  payInvoiceInOneTap,
  payoutTransfers,
  randomId,
  recipientAccount,
  stopIx,
  takeBackIx,
  termsFor,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  tokenOf,
  transferIx,
  VERSION,
  type EscrowAccount,
  type EscrowKeys,
  type PostTerms,
  type Token,
} from '../src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))

const keysDir = process.env.FOREST_DEVNET_KEYS
if (!keysDir) throw new Error('set FOREST_DEVNET_KEYS to the directory holding the devnet keypairs')
const recordPath = resolve(join(here, '../../devnet/devnet.json'))
const record = JSON.parse(readFileSync(recordPath, 'utf8'))
const connection = new Connection(process.env.FOREST_DEVNET_RPC ?? record.rpc, 'confirmed')
const programId = new PublicKey(record.escrow.programId)
const earlier = (record.earlier ?? []).map((e: { escrow: { programId: string } }) => e.escrow.programId)
if (earlier.includes(programId.toBase58())) throw new Error("that is an earlier escrow program's id")

function key(name: string): Keypair {
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(join(keysDir!, `${name}.json`), 'utf8'))))
}
const sponsor = key('payer')
const payer = key('buyer')
const recipient = key('seller')
for (const [name, k] of [['payer', sponsor], ['buyer', payer], ['seller', recipient]] as const) {
  if (k.publicKey.toBase58() !== record.keys[name]) throw new Error(`the ${name} key is not the one the record names`)
}

function save(): void {
  writeFileSync(recordPath, JSON.stringify(record, null, 2) + '\n')
}

function note(deal: Record<string, unknown>, what: string, signature: string): void {
  record.transactions ??= []
  record.transactions.push({ program: `escrow-v${VERSION}`, what, signature })
  ;(deal.signatures as Record<string, string>)[what.split(':')[0]] = signature
  save()
  console.log(`  ${signature}  ${what}`)
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

function transaction(instructions: TransactionInstruction[], signers: Keypair[], blockhash: string): Transaction {
  const tx = new Transaction().add(...instructions)
  tx.feePayer = signers[0].publicKey
  tx.recentBlockhash = blockhash
  tx.sign(...signers)
  return tx
}

async function send(instructions: TransactionInstruction[], signers: Keypair[]): Promise<string> {
  const tx = transaction(instructions, signers, (await connection.getLatestBlockhash('confirmed')).blockhash)
  const signature = await connection.sendRawTransaction(tx.serialize())
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
    if (status?.err) throw new Error(`${signature} failed: ${JSON.stringify(status.err)}`)
    if (status && (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized')) return signature
    await sleep(500)
  }
  throw new Error(`${signature} was never confirmed`)
}

/** Simulates `instructions` and returns the program's error code, which must be `code`: a refusal checked on the real runtime without spending anything. */
async function refused(instructions: TransactionInstruction[], signers: Keypair[], code: string): Promise<string> {
  const tx = transaction(instructions, signers, (await connection.getLatestBlockhash('confirmed')).blockhash)
  const sim = await connection.simulateTransaction(tx)
  const line = (sim.value.logs ?? []).find((l) => l.includes('Error Code: '))
  if (!sim.value.err || !line?.includes(`Error Code: ${code}.`)) throw new Error(`expected ${code}, got ${JSON.stringify(sim.value.err)}: ${line}`)
  return code
}

async function kinds(signature: string): Promise<string> {
  for (let i = 0; i < 20; i++) {
    const tx = await connection
      .getTransaction(signature, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 })
      .catch((e) => (String(e).includes('429') ? null : Promise.reject(e)))
    if (tx?.meta?.logMessages) return decodeEvents(tx.meta.logMessages, programId).map((e) => e.kind).join()
    await sleep(3_000)
  }
  throw new Error(`no log for ${signature}`)
}

async function escrowAt(address: PublicKey): Promise<EscrowAccount | null> {
  const info = await connection.getAccountInfo(address)
  if (info && !info.owner.equals(programId)) throw new Error(`${address.toBase58()} is not owned by the escrow program`)
  return info ? decodeEscrow(new Uint8Array(info.data)) : null
}

async function tokens(address: PublicKey, token: Token): Promise<bigint> {
  return (await getAccount(connection, address, 'confirmed', token.program)).amount
}

async function readToken(mint: PublicKey): Promise<Token> {
  const info = await connection.getAccountInfo(mint)
  if (!info) throw new Error(`no mint at ${mint.toBase58()}`)
  return tokenOf(mint, info)
}

/** The chain's clock, the one the program reads: the Clock sysvar's unix timestamp. */
async function chainNow(): Promise<bigint> {
  const info = await connection.getAccountInfo(SYSVAR_CLOCK_PUBKEY, 'confirmed')
  if (!info) throw new Error('no clock')
  return info.data.readBigInt64LE(32)
}

async function waitUntil(t: bigint): Promise<void> {
  for (;;) {
    const now = await chainNow()
    if (now >= t) return
    console.log(`  waiting ${t - now} s for the chain's clock to reach the end time`)
    await sleep(Number(t - now) * 1000 + 2_000)
  }
}

function receipt(e: EscrowAccount) {
  return {
    version: e.version,
    status: e.status,
    outcome: e.outcome,
    amount: e.amount.toString(),
    toPayer: e.toPayer.toString(),
    toRecipient: e.toRecipient.toString(),
    creator: e.creator,
    arbiter: e.arbiter?.toBase58() ?? null,
    schedule: e.schedule ? { windows: e.schedule.windows.map((w) => ({ until: w.until.toString(), payerShare: w.payerShare })), end: e.schedule.end } : null,
    createdAt: e.createdAt.toString(),
    fundedAt: e.fundedAt?.toString() ?? null,
    endedAt: e.endedAt?.toString() ?? null,
    stop: e.stop,
    stoppedAt: e.stoppedAt?.toString() ?? null,
    sponsor: e.sponsor.toBase58(),
  }
}

function deal(name: string, what: string): Record<string, any> {
  record.deals ??= {}
  record.deals[name] ??= { what, id: randomId().toString(), signatures: {} }
  save()
  return record.deals[name]
}

/** A deal's terms: its schedule's times fixed once, from the chain's clock, and written down before the escrow opens. */
async function scheduled(d: Record<string, any>, windows: { after: number; payerShare: number }[], end: 'pay' | 'refund'): Promise<PostTerms> {
  if (!d.post) {
    const now = Number(await chainNow())
    d.post = { schedule: { windows: windows.map((w) => ({ until: now + w.after, payerShare: w.payerShare })), end } }
    save()
  }
  return d.post
}

/** The accounts a mint's transfer hook needs: the payment into a deposit address the same transaction may make, and each payout. Empty unless the mint names a hook program. */
async function hooks(token: Token, keys: EscrowKeys, to: ('payer' | 'recipient')[]) {
  const planned = [{ address: keys.vault, owner: keys.escrow, mint: token.mint, tokenProgram: token.program }]
  const from = payerAccount(keys.payer, token.mint, token.program)
  const fund = await hookAccounts({ reader: connection, mint: token.mint, transfers: [{ source: from, destination: keys.vault, authority: keys.payer }], planned })
  const pay = to.length ? await hookAccounts({ reader: connection, mint: token.mint, transfers: payoutTransfers(keys, to) }) : []
  return { fund, pay }
}

/** Opens, funds and marks `d`'s escrow in one transaction, if it is not open yet; returns it as read back. */
async function openAndFund(d: Record<string, any>, token: Token, label: string, post: PostTerms, amount: bigint, what: string): Promise<{ keys: EscrowKeys; e: EscrowAccount }> {
  const terms = termsFor(post, { recipient: recipient.publicKey, amount, id: BigInt(d.id) })
  const keys = keysFor({ payer: payer.publicKey, sponsor: sponsor.publicKey, mint: token.mint, tokenProgram: token.program, terms, programId })
  d.escrow = keys.escrow.toBase58()
  d.mint = token.mint.toBase58()
  save()
  if (!(await escrowAt(keys.escrow))) {
    const { fund } = await hooks(token, keys, [])
    const sig = await send(createAndFund({ payer: payer.publicKey, sponsor: sponsor.publicKey, token, terms, hookAccounts: { fund }, programId }), [sponsor, payer])
    if ((await kinds(sig)) !== 'created,funded') throw new Error('create, fund and mark logged something else')
    note(d, `create and fund: the deposit address made first, the payer opens ${what} pays it in and marks it, in one transaction`, sig)
  }
  return { keys, e: (await escrowAt(keys.escrow))! }
}

/** 1: an invoice paid in one tap; nobody marks it. */
async function invoiceDeal(name: string, token: Token, label: string): Promise<void> {
  const d = deal(name, `the recipient invoices 1.00 ${label}; the payer checks it, then, in one transaction, the deposit address made first, pays it in and pays it out to the recipient; nobody marks it`)
  const terms = termsFor(undefined, { recipient: recipient.publicKey, amount: 1_000_000n, id: BigInt(d.id) })
  const keys = keysFor({ payer: payer.publicKey, sponsor: sponsor.publicKey, mint: token.mint, tokenProgram: token.program, terms, programId })
  d.escrow = keys.escrow.toBase58()
  d.mint = token.mint.toBase58()
  save()
  if (!(await escrowAt(keys.escrow))) {
    const ix = invoiceIx({ recipient: recipient.publicKey, payer: payer.publicKey, sponsor: sponsor.publicKey, mint: token.mint, tokenProgram: token.program, terms, programId })
    const sig = await send([ix], [sponsor, recipient])
    if ((await kinds(sig)) !== 'created') throw new Error('the invoice logged something else')
    note(d, `invoice: the recipient opens an escrow naming the payer, 1.00 ${label}, no options, the sponsor fronting the rent`, sig)
  }
  let e = (await escrowAt(keys.escrow))!
  if (e.status !== 'ended') {
    assertOptionsAgreed({ escrow: e, agreed: null })
    if (!e.payer.equals(payer.publicKey)) throw new Error('the invoice names another payer')
    const k = keysOf(e, { tokenProgram: token.program, programId })
    const { fund, pay } = await hooks(token, k, ['recipient'])
    const before = await tokens(recipientAccount(recipient.publicKey, token.mint, token.program), token)
    const sig = await send(payInvoiceInOneTap({ escrow: e, sponsor: sponsor.publicKey, token, hookAccounts: { fund, pay }, programId }), [sponsor, payer])
    if ((await kinds(sig)) !== 'ended') throw new Error('the one tap logged something else')
    if ((await tokens(recipientAccount(recipient.publicKey, token.mint, token.program), token)) !== before + 1_000_000n) throw new Error('the recipient was not paid')
    note(d, `one tap: the deposit address made first, then the payer pays 1.00 ${label} into it and pays it out to the recipient, in one transaction`, sig)
    e = (await escrowAt(keys.escrow))!
  }
  if (e.status !== 'ended' || e.outcome !== 'pay' || e.creator !== 'recipient') throw new Error('not ended by pay, created by the recipient')
  if (e.fundedAt === null || e.fundedAt !== e.endedAt) throw new Error("nobody marked it, so the funding time must be the ending's")
  if (!e.sponsor.equals(sponsor.publicKey)) throw new Error('the sponsor is not recorded')
  d.receipt = receipt(e)
  save()
  console.log(`  receipt ${keys.escrow.toBase58()}: ${e.outcome}, funded at ${e.fundedAt}, ended at ${e.endedAt}`)
}

/** 2: half back until a day from now, then paid; the payer takes its half back. */
async function takeBackDeal(token: Token, label: string): Promise<void> {
  const d = deal('takeBack', `the payer opens 2.00 ${label} with one window, half back until a day from now, then paid; funds and marks it at once; takes back its half`)
  const post = await scheduled(d, [{ after: 86_400, payerShare: 5_000 }], 'pay')
  const { keys, e: opened } = await openAndFund(d, token, label, post, 2_000_000n, `2.00 ${label}, half back until a day from now, then paid,`)
  let e = opened
  if (e.status !== 'ended') {
    if (!canTakeBack(e, await chainNow())) throw new Error('no window with a share above 0 is in force')
    const { pay } = await hooks(token, keys, ['payer', 'recipient'])
    const before = await tokens(payerAccount(payer.publicKey, token.mint, token.program), token)
    const sig = await send([takeBackIx({ keys, hookAccounts: pay, programId })], [sponsor, payer])
    if ((await kinds(sig)) !== 'ended') throw new Error('the take-back logged something else')
    if ((await tokens(payerAccount(payer.publicKey, token.mint, token.program), token)) !== before + 1_000_000n) throw new Error('the payer did not get half back')
    note(d, `take_back: the payer takes back the window's half, 1.00 ${label}; the other 1.00 to the recipient`, sig)
    e = (await escrowAt(keys.escrow))!
  }
  if (e.status !== 'ended' || e.outcome !== 'takeBack' || e.toPayer !== 1_000_000n || e.toRecipient !== 1_000_000n || e.stop) throw new Error('not ended by a take-back of half')
  d.receipt = receipt(e)
  save()
  console.log(`  receipt ${keys.escrow.toBase58()}: ${e.outcome}, ${e.toPayer} to the payer, ${e.toRecipient} to the recipient`)
}

/** 3: paid in a day unless stopped; the payer stops; the default is refused; both sign 60/40. */
async function stopDeal(name: string, token: Token, label: string): Promise<void> {
  const d = deal(name, `the payer opens 2.00 ${label}, paid in a day unless stopped, and funds and marks it at once; the payer stops it; the default is refused; both sign a 60/40 split`)
  const post = await scheduled(d, [{ after: 86_400, payerShare: 0 }], 'pay')
  const { keys, e: opened } = await openAndFund(d, token, label, post, 2_000_000n, `2.00 ${label}, paid in a day unless stopped,`)
  let e = opened
  if (e.status !== 'ended' && !e.stop) {
    if (!canStop(e, await chainNow())) throw new Error('the end time has passed: too late to stop')
    const sig = await send([stopIx({ account: e, party: payer.publicKey, programId })], [sponsor, payer])
    if ((await kinds(sig)) !== 'stopped') throw new Error('the stop logged something else')
    note(d, 'stop: the payer stops it before the end time; the default is off', sig)
    e = (await escrowAt(keys.escrow))!
  }
  if (e.status !== 'ended') {
    // The default, refused twice: by the client, and by the program, sent as if nobody had stopped.
    let client = ''
    try {
      endIx({ account: e, tokenProgram: token.program, programId })
    } catch (err) {
      client = String(err)
    }
    if (!client.includes('Stopped')) throw new Error('the client builds the default after a stop')
    d.endRefused = await refused([endIx({ account: { ...e, stop: null }, tokenProgram: token.program, programId })], [sponsor], 'Stopped')
    const { pay } = await hooks(token, keys, ['payer', 'recipient'])
    const before = await tokens(recipientAccount(recipient.publicKey, token.mint, token.program), token)
    const sig = await send([agreeIx({ keys, payerShare: 4_000, hookAccounts: pay, programId })], [sponsor, payer, recipient])
    if ((await kinds(sig)) !== 'ended') throw new Error('the agreement logged something else')
    if ((await tokens(recipientAccount(recipient.publicKey, token.mint, token.program), token)) !== before + 1_200_000n) throw new Error('the recipient was not paid 60%')
    note(d, `agree: payer and recipient both sign 60/40; 1.20 ${label} to the recipient, 0.80 back to the payer`, sig)
    e = (await escrowAt(keys.escrow))!
  }
  if (e.status !== 'ended' || e.outcome !== 'agree' || e.stop !== 'payer' || e.toRecipient !== 1_200_000n || e.toPayer !== 800_000n) {
    throw new Error('not ended by an agreement of 1.20 and 0.80, stopped by the payer')
  }
  d.receipt = receipt(e)
  save()
  console.log(`  receipt ${keys.escrow.toBase58()}: ${e.outcome}, stopped by the ${e.stop} at ${e.stoppedAt}, funded at ${e.fundedAt}`)
}

/** 4, opening: paid in a minute and a half unless stopped, funded and marked at once. */
async function openEndDeal(token: Token, label: string) {
  const d = deal('end', `the payer opens 1.00 ${label}, paid in a minute and a half unless stopped, and funds and marks it at once; the default is refused before the end time and sent from it by a third key`)
  const post = await scheduled(d, [{ after: 90, payerShare: 0 }], 'pay')
  return { d, ...(await openAndFund(d, token, label, post, 1_000_000n, `1.00 ${label}, paid in a minute and a half unless stopped,`)) }
}

/** 4, ending: the default refused before the end time, then sent by the sponsor's key. */
async function endDeal(token: Token, label: string, open: Awaited<ReturnType<typeof openEndDeal>>): Promise<void> {
  const { d, keys } = open
  let e = (await escrowAt(keys.escrow))!
  if (e.status !== 'ended') {
    if (!d.endRefusedEarly && (await chainNow()) < endTime(e)!) {
      d.endRefusedEarly = await refused([endIx({ account: e, tokenProgram: token.program, programId })], [sponsor], 'ScheduleNotOver')
      save()
    }
    await waitUntil(endTime(e)!)
    if (!canEnd(e, await chainNow())) throw new Error('the default cannot run')
    const { pay } = await hooks(token, keys, ['recipient'])
    const sig = await send([endIx({ account: e, tokenProgram: token.program, hookAccounts: pay, programId })], [sponsor])
    if ((await kinds(sig)) !== 'ended') throw new Error('the default logged something else')
    note(d, `end: from the end time, the sponsor's key, neither party, sends the default; 1.00 ${label} to the recipient`, sig)
    e = (await escrowAt(keys.escrow))!
  }
  if (e.status !== 'ended' || e.outcome !== 'end' || e.toRecipient !== 1_000_000n || e.endedAt! < endTime(e)!) throw new Error('not ended by the default, to the recipient, from the end time')
  d.receipt = receipt(e)
  save()
  console.log(`  receipt ${keys.escrow.toBase58()}: ${e.outcome}, end time ${endTime(e)}, ended at ${e.endedAt}`)
}

/** 5, opening: the same kind of schedule, nothing paid in. */
async function openLateDeal(token: Token, label: string) {
  const d = deal('late', `the payer opens 1.00 ${label}, paid in a minute and a half unless stopped, and pays nothing in time; after the end time a plain transfer lands; the mark and the default are refused; the payer closes it and everything goes back`)
  const post = await scheduled(d, [{ after: 90, payerShare: 0 }], 'pay')
  const terms = termsFor(post, { recipient: recipient.publicKey, amount: 1_000_000n, id: BigInt(d.id) })
  const keys = keysFor({ payer: payer.publicKey, sponsor: sponsor.publicKey, mint: token.mint, tokenProgram: token.program, terms, programId })
  d.escrow = keys.escrow.toBase58()
  d.mint = token.mint.toBase58()
  save()
  // Once closed, the address is free again: the record, not the chain, says it is done.
  if (!d.signatures.close_unfunded && !(await escrowAt(keys.escrow))) {
    const sig = await send([createIx({ payer: payer.publicKey, sponsor: sponsor.publicKey, mint: token.mint, tokenProgram: token.program, terms, programId })], [sponsor, payer])
    if ((await kinds(sig)) !== 'created') throw new Error('the create logged something else')
    note(d, `create: the payer opens 1.00 ${label}, paid in a minute and a half unless stopped, and pays nothing in`, sig)
  }
  return { d, keys }
}

/** 5, after the end time: a plain transfer lands; the mark and the default are refused; the payer closes it. */
async function lateDeal(token: Token, label: string, open: Awaited<ReturnType<typeof openLateDeal>>): Promise<void> {
  const { d, keys } = open
  if (d.signatures.close_unfunded) return
  let e = (await escrowAt(keys.escrow))!
  await waitUntil(endTime(e)!)
  const vault = await tokens(keys.vault, token)
  if (vault < e.amount) {
    const { fund } = await hooks(token, keys, [])
    const ix = transferIx({ from: payerAccount(payer.publicKey, token.mint, token.program), to: keys.vault, owner: payer.publicKey, mint: token.mint, amount: e.amount - vault, decimals: token.decimals, tokenProgram: token.program, hookAccounts: fund })
    const sig = await send([ix], [sponsor, payer])
    note(d, `late transfer: after the end time, the payer sends 1.00 ${label} to the deposit address by a plain transfer, without a mark`, sig)
  }
  e = (await escrowAt(keys.escrow))!
  d.markRefused = await refused([markFundedIx({ escrow: keys.escrow, vault: keys.vault, programId })], [sponsor], 'ScheduleOver')
  d.endRefused = await refused([endIx({ account: { ...e, status: 'funded' }, tokenProgram: token.program, programId })], [sponsor], 'FundingNotMarked')
  save()
  const before = await tokens(payerAccount(payer.publicKey, token.mint, token.program), token)
  const sig = await send([closeUnfundedIx({ keys, closer: payer.publicKey, programId })], [sponsor, payer])
  if ((await kinds(sig)) !== 'closed') throw new Error('the close logged something else')
  if ((await tokens(payerAccount(payer.publicKey, token.mint, token.program), token)) !== before + 1_000_000n) throw new Error('the payer did not get the late money back')
  if (await connection.getAccountInfo(keys.escrow)) throw new Error('the escrow account is still there')
  note(d, `close_unfunded: from the end time, never marked and never stopped, the payer closes it; 1.00 ${label} back to the payer, both rents to the sponsor, no receipt`, sig)
  d.receipt = null
  save()
  console.log(`  ${keys.escrow.toBase58()}: closed, everything back to the payer, no receipt`)
}

/** Token-2022's extension instructions `@solana/spl-token` 0.4.9 does not build, byte for byte as spl-token-2022-interface 2.1 builds them. */
function initializeConfidentialTransferMintIx(mint: PublicKey, authority: PublicKey): TransactionInstruction {
  // ConfidentialTransferExtension (27), InitializeMint (0): authority, auto-approve off, no auditor.
  const data = Buffer.concat([Buffer.from([27, 0]), authority.toBuffer(), Buffer.from([0]), Buffer.alloc(32)])
  return new TransactionInstruction({ programId: TOKEN_2022_PROGRAM_ID, keys: [{ pubkey: mint, isSigner: false, isWritable: true }], data })
}
function initializePausableIx(mint: PublicKey, authority: PublicKey): TransactionInstruction {
  // PausableExtension (44), Initialize (0): the pause authority.
  const data = Buffer.concat([Buffer.from([44, 0]), authority.toBuffer()])
  return new TransactionInstruction({ programId: TOKEN_2022_PROGRAM_ID, keys: [{ pubkey: mint, isSigner: false, isWritable: true }], data })
}

/** Open USD's extension types on mainnet, in order: close authority, permanent delegate, default account state, confidential transfer mint, transfer hook, metadata pointer, pausable, token metadata. */
const OPEN_USD_EXTENSIONS = [3, 12, 6, 4, 14, 18, 26, 19]

/** Whether `mint` is on chain under `program` and the sponsor key, this phrase's payer key, holds its mint authority. */
async function ours(mint: string | undefined, program: PublicKey): Promise<boolean> {
  if (!mint) return false
  const address = new PublicKey(mint)
  const info = await connection.getAccountInfo(address)
  if (!info || !info.owner.equals(program)) return false
  return unpackMint(address, info, program).mintAuthority?.equals(sponsor.publicKey) ?? false
}

/** The classic deals' mint: the record's if the sponsor key can mint it, else made here in one transaction, with both parties' standard accounts and six of it for the payer. */
async function testDollar(): Promise<Token> {
  if (!(await ours(record.testDollar?.mint, TOKEN_PROGRAM_ID))) {
    const mintKey = Keypair.generate()
    const mint = mintKey.publicKey
    record.testDollar = {
      what: 'The classic test dollar: an SPL Token mint, 6 decimals, the devnet payer key its mint authority, no freeze authority; six of it minted to the buyer.',
      mint: mint.toBase58(),
      decimals: 6,
      authority: sponsor.publicKey.toBase58(),
      signatures: {},
    }
    save()
    const payerTokens = payerAccount(payer.publicKey, mint, TOKEN_PROGRAM_ID)
    const lamports = await getMinimumBalanceForRentExemptMint(connection)
    const sig = await send(
      [
        SystemProgram.createAccount({ fromPubkey: sponsor.publicKey, newAccountPubkey: mint, lamports, space: MINT_SIZE, programId: TOKEN_PROGRAM_ID }),
        createInitializeMint2Instruction(mint, 6, sponsor.publicKey, null, TOKEN_PROGRAM_ID),
        createAssociatedTokenAccountIdempotentInstruction(sponsor.publicKey, payerTokens, payer.publicKey, mint, TOKEN_PROGRAM_ID),
        createAssociatedTokenAccountIdempotentInstruction(sponsor.publicKey, recipientAccount(recipient.publicKey, mint, TOKEN_PROGRAM_ID), recipient.publicKey, mint, TOKEN_PROGRAM_ID),
        createMintToCheckedInstruction(mint, payerTokens, sponsor.publicKey, 6_000_000n, 6, [], TOKEN_PROGRAM_ID),
      ],
      [sponsor, mintKey],
    )
    record.testDollar.signatures['mint, accounts and six to the buyer'] = sig
    save()
    console.log(`  ${sig}  the classic test dollar, both parties' standard accounts, six to the payer`)
  }
  return readToken(new PublicKey(record.testDollar.mint))
}

/** The Token-2022 deals' mint: Open USD's extensions, the sponsor key holding every role of the dollar's maker; three of it for the payer. The record's if the sponsor key can mint it, else made here. */
async function openUsdShaped(): Promise<Token> {
  const issuer = sponsor.publicKey
  let mintKey: Keypair | null = null
  if (!(await ours(record.openUsdShaped?.mint, TOKEN_2022_PROGRAM_ID))) {
    mintKey = Keypair.generate()
    record.openUsdShaped = {
      what: "A Token-2022 mint with every extension Open USD (ousd2mJsPEckLHcSCDxyKD7NDGARZcfLbDZkKiatYHB) has on mainnet, in its order, six decimals, the devnet payer key holding every role of the dollar's maker; three of it minted to the buyer.",
      mint: mintKey.publicKey.toBase58(),
      issuer: issuer.toBase58(),
      signatures: {},
    }
    save()
  }
  const mint = new PublicKey(record.openUsdShaped.mint)
  if (mintKey) {
    const fixed = getMintLen([
      ExtensionType.MintCloseAuthority,
      ExtensionType.PermanentDelegate,
      ExtensionType.DefaultAccountState,
      ExtensionType.ConfidentialTransferMint,
      ExtensionType.TransferHook,
      ExtensionType.MetadataPointer,
    ]) + 4 + 33 // and pausable: its header and config
    const lamports = await connection.getMinimumBalanceForRentExemption(fixed)
    const sig = await send(
      [
        SystemProgram.createAccount({ fromPubkey: issuer, newAccountPubkey: mint, lamports, space: fixed, programId: TOKEN_2022_PROGRAM_ID }),
        createInitializeMintCloseAuthorityInstruction(mint, issuer, TOKEN_2022_PROGRAM_ID),
        createInitializePermanentDelegateInstruction(mint, issuer, TOKEN_2022_PROGRAM_ID),
        createInitializeDefaultAccountStateInstruction(mint, AccountState.Initialized, TOKEN_2022_PROGRAM_ID),
        initializeConfidentialTransferMintIx(mint, issuer),
        createInitializeTransferHookInstruction(mint, issuer, PublicKey.default, TOKEN_2022_PROGRAM_ID),
        createInitializeMetadataPointerInstruction(mint, issuer, mint, TOKEN_2022_PROGRAM_ID),
        initializePausableIx(mint, issuer),
        createInitializeMint2Instruction(mint, 6, issuer, issuer, TOKEN_2022_PROGRAM_ID),
      ],
      [sponsor, mintKey],
    )
    record.openUsdShaped.signatures.mint = sig
    save()
    console.log(`  ${sig}  the Open USD-shaped mint`)
  }
  let info = (await connection.getAccountInfo(mint))!
  if (!getExtensionTypes(unpackMint(mint, info, TOKEN_2022_PROGRAM_ID).tlvData).includes(ExtensionType.TokenMetadata)) {
    const sig = await tokenMetadataInitializeWithRentTransfer(
      connection,
      sponsor,
      mint,
      issuer,
      sponsor,
      'OpenUSD-shaped test dollar',
      'OUSDT',
      'https://forest.foundation/',
      [],
      { commitment: 'confirmed' },
      TOKEN_2022_PROGRAM_ID,
    )
    record.openUsdShaped.signatures.metadata = sig
    save()
    console.log(`  ${sig}  its metadata`)
    info = (await connection.getAccountInfo(mint, 'confirmed'))!
  }
  const types = getExtensionTypes(unpackMint(mint, info, TOKEN_2022_PROGRAM_ID).tlvData) as number[]
  if (JSON.stringify(types) !== JSON.stringify(OPEN_USD_EXTENSIONS)) throw new Error(`the mint's extensions are ${types}, not Open USD's`)
  record.openUsdShaped.extensions = types
  const token = tokenOf(mint, info)
  const payerTokens = payerAccount(payer.publicKey, mint, TOKEN_2022_PROGRAM_ID)
  if (!(await connection.getAccountInfo(payerTokens))) {
    const sig = await send(
      [
        createAssociatedTokenAccountIdempotentInstruction(issuer, payerTokens, payer.publicKey, mint, TOKEN_2022_PROGRAM_ID),
        createAssociatedTokenAccountIdempotentInstruction(issuer, recipientAccount(recipient.publicKey, mint, TOKEN_2022_PROGRAM_ID), recipient.publicKey, mint, TOKEN_2022_PROGRAM_ID),
        createMintToCheckedInstruction(mint, payerTokens, issuer, 3_000_000n, 6, [], TOKEN_2022_PROGRAM_ID),
      ],
      [sponsor],
    )
    record.openUsdShaped.signatures['accounts and three to the buyer'] = sig
    console.log(`  ${sig}  both parties' standard accounts, three to the payer`)
  }
  save()
  return token
}

/** The payer topped up to `need` if it holds less: `give` sends the difference. */
async function topUp(token: Token, label: string, need: bigint, how: string, give: (amount: bigint) => Promise<string>): Promise<void> {
  const held = await tokens(payerAccount(payer.publicKey, token.mint, token.program), token)
  if (held >= need) return
  const sig = await give(need - held)
  record.transactions ??= []
  record.transactions.push({ program: `escrow-v${VERSION}`, what: `top-up: ${how} ${Number(need - held) / 1e6} ${label} to the payer key for the v${VERSION} deals`, signature: sig })
  save()
  console.log(`  ${sig}  ${how} ${need - held} base units of ${label} to the payer key`)
}

/** Whether every named deal has run to its end: its receipt read back, or none, for a close. */
const done = (...names: string[]) => names.every((n) => record.deals?.[n] && 'receipt' in record.deals[n])

console.log(`escrow ${programId.toBase58()}`)

// In the classic test dollar. The payer needs 5.20 at most at once: what deals 1 to 5 put in,
// less what 2, 3 and 5 give back before the next one.
const classic = await testDollar()
if (!done('invoice', 'takeBack', 'stop', 'end', 'late')) await topUp(classic, 'test dollar', 6_000_000n, 'the payer key mints', (amount) =>
  send([createMintToCheckedInstruction(classic.mint, payerAccount(payer.publicKey, classic.mint, classic.program), sponsor.publicKey, amount, 6, [], classic.program)], [sponsor]),
)
await invoiceDeal('invoice', classic, 'test dollar')
await takeBackDeal(classic, 'test dollar')
await stopDeal('stop', classic, 'test dollar')
// 4 and 5 open together, so one wait covers both end times.
const endOpen = await openEndDeal(classic, 'test dollar')
const lateOpen = await openLateDeal(classic, 'test dollar')
await endDeal(classic, 'test dollar', endOpen)
await lateDeal(classic, 'test dollar', lateOpen)

// Deals 1 and 3 again, in the Open USD-shaped Token-2022 dollar.
const ousd = await openUsdShaped()
if (!done('invoice, Token-2022', 'stop, Token-2022')) await topUp(ousd, 'Open USD-shaped dollar', 3_000_000n, 'the issuer mints', (amount) =>
  send([createMintToCheckedInstruction(ousd.mint, payerAccount(payer.publicKey, ousd.mint, ousd.program), sponsor.publicKey, amount, 6, [], TOKEN_2022_PROGRAM_ID)], [sponsor]),
)
await invoiceDeal('invoice, Token-2022', ousd, 'Open USD-shaped dollar')
await stopDeal('stop, Token-2022', ousd, 'Open USD-shaped dollar')

console.log('done')
