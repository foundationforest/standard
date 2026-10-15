// The escrow on devnet, used for real: deals between the devnet parties through
// escrow/devnet/deploy.sh's deploy, in the classic test dollar the record names and in a
// Token-2022 dollar made here with Open USD's extensions.
//
//   FOREST_DEVNET_KEYS=<dir> node scripts/devnet.ts        (after escrow/devnet/deploy.sh)
//
// 1. The seller invoices; the buyer reads it, checks its options, and pays with one tap (the
//    deposit address made first, a transfer and the release, in one transaction). Nobody marks
//    it: the receipt records the funding time anyway, the ending's.
// 2. The buyer opens an escrow with a one-day timer to the seller and funds it in the same
//    transaction; anyone marks it; the buyer objects before the timer is due, so the timer is off;
//    both sign a 60/40 split. The receipt keeps the objection.
// 3. A Token-2022 mint with every extension Open USD has on mainnet (mint close authority,
//    permanent delegate, default account state, confidential transfers, a transfer hook naming no
//    program, a metadata pointer, pause, metadata; and a freeze authority), the payer key holding
//    every role of the dollar's maker, and three of it minted to the buyer. Then deals 1 and 2
//    again in it, so a one tap and both payouts of a split cross Token-2022.
// 4. After the upgrade in place that refuses a non-transferable mint: deal 1 once more in the
//    Token-2022 dollar (the buyer topped up to one if it holds less), and a non-transferable
//    Token-2022 mint made there, its `create` simulated, which must fail with `NonTransferable`.
//
// A payer key pays every network fee and fronts every rent, the way a fee payer would, and is
// recorded as the escrow's payer. <dir> holds payer.json, buyer.json and seller.json, as
// escrow/devnet/deploy.sh writes them, read and never printed, and on the first run
// open-usd-shaped-mint.json, the Token-2022 mint's key, made there; from then on the record names
// the mint, and its key is not needed. The keys must be the ones
// escrow/devnet/devnet.json names in `keys`, and the classic mint is its `testDollar`.
// Everything public goes into escrow/devnet/devnet.json. Each step checks the chain first, so
// the script can be run again after a failure. FOREST_DEVNET_RPC points it at another devnet RPC.

import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  AccountState,
  createAssociatedTokenAccountIdempotentInstruction,
  createInitializeNonTransferableMintInstruction,
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
  getMintLen,
  tokenMetadataInitializeWithRentTransfer,
  unpackMint,
} from '@solana/spl-token'
import { Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction } from '@solana/web3.js'

import {
  assertOptionsAgreed,
  canObject,
  createAndFund,
  decodeEscrow,
  decodeEvents,
  escrowAddress,
  hookAccounts,
  invoiceIx,
  keysFor,
  keysOf,
  markFundedIx,
  objectIx,
  payInvoiceInOneTap,
  payoutAddress,
  payoutTransfers,
  randomId,
  refundAddress,
  splitIx,
  termsFor,
  timerReleaseIx,
  TOKEN_2022_PROGRAM_ID,
  tokenOf,
  type EscrowAccount,
  type EscrowKeys,
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
if (earlier.includes(programId.toBase58())) throw new Error('that is an earlier escrow program\'s id')
const classicMint = new PublicKey(record.testDollar.mint)

function key(name: string): Keypair {
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(join(keysDir!, `${name}.json`), 'utf8'))))
}
const payer = key('payer')
const buyer = key('buyer')
const seller = key('seller')
for (const [name, k] of [['payer', payer], ['buyer', buyer], ['seller', seller]] as const) {
  if (k.publicKey.toBase58() !== record.keys[name]) throw new Error(`the ${name} key is not the one the record names`)
}

function save(): void {
  writeFileSync(recordPath, JSON.stringify(record, null, 2) + '\n')
}

function note(deal: Record<string, unknown>, what: string, signature: string): void {
  record.transactions ??= []
  record.transactions.push({ program: 'escrow-v2', what, signature })
  ;(deal.signatures as Record<string, string>)[what.split(':')[0]] = signature
  save()
  console.log(`  ${signature}  ${what}`)
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function send(instructions: TransactionInstruction[], signers: Keypair[]): Promise<string> {
  const tx = new Transaction().add(...instructions)
  tx.feePayer = signers[0].publicKey
  tx.recentBlockhash = (await connection.getLatestBlockhash('confirmed')).blockhash
  tx.sign(...signers)
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

function receipt(e: EscrowAccount) {
  return {
    status: e.status,
    outcome: e.outcome,
    amount: e.amount.toString(),
    toSeller: e.toSeller.toString(),
    toBuyer: e.toBuyer.toString(),
    creator: e.creator,
    createdAt: e.createdAt.toString(),
    fundedAt: e.fundedAt?.toString() ?? null,
    endedAt: e.endedAt?.toString() ?? null,
    objection: e.objection,
    objectedAt: e.objectedAt?.toString() ?? null,
    rentRecipient: e.rentRecipient.toBase58(),
    payer: e.payer.toBase58(),
  }
}

function deal(name: string, what: string): Record<string, any> {
  record.deals ??= {}
  record.deals[name] ??= { what, id: randomId().toString(), signatures: {} }
  save()
  return record.deals[name]
}

/**
 * The accounts a mint's transfer hook needs for a one tap: the payment into a deposit address the
 * same transaction makes, and the release to the seller. Empty unless the mint names a hook program.
 */
async function oneTapHooks(token: Token, keys: EscrowKeys) {
  const planned = [{ address: keys.vault, owner: keys.escrow, mint: token.mint, tokenProgram: token.program }]
  const from = refundAddress(keys.buyer, token.mint, token.program)
  const fund = await hookAccounts({ reader: connection, mint: token.mint, transfers: [{ source: from, destination: keys.vault, authority: keys.buyer }], planned })
  const release = await hookAccounts({ reader: connection, mint: token.mint, transfers: payoutTransfers(keys, ['seller']) })
  return { fund, release }
}

/** Deal 1, in `token`: an invoice paid with one tap; nobody marks it. */
async function invoiceDeal(name: string, token: Token, label: string): Promise<void> {
  const d = deal(name, `the seller invoices 1.00 ${label}; the buyer checks it, then, in one transaction, the deposit address made first, pays and releases; nobody marks it`)
  const terms = termsFor(undefined, { seller: seller.publicKey, amount: 1_000_000n, id: BigInt(d.id) })
  const escrow = escrowAddress({ buyer: buyer.publicKey, mint: token.mint, terms }, programId)
  d.escrow = escrow.toBase58()
  d.mint = token.mint.toBase58()
  save()
  if (!(await escrowAt(escrow))) {
    const ix = invoiceIx({ seller: seller.publicKey, buyer: buyer.publicKey, payer: payer.publicKey, mint: token.mint, tokenProgram: token.program, terms, programId })
    const sig = await send([ix], [payer, seller])
    if ((await kinds(sig)) !== 'created') throw new Error('the invoice logged something else')
    note(d, `invoice: the seller opens an escrow naming the buyer, 1.00 ${label}, no options, the payer fronting the rent`, sig)
  }
  let e = (await escrowAt(escrow))!
  if (e.status !== 'ended') {
    assertOptionsAgreed({ escrow: e, me: 'buyer', agreed: null })
    if (!e.buyer.equals(buyer.publicKey)) throw new Error('the invoice names another buyer')
    const keys = keysOf(e, { tokenProgram: token.program, programId })
    const hooks = await oneTapHooks(token, keys)
    const sellerBefore = await tokens(payoutAddress(seller.publicKey, token.mint, token.program), token)
    const sig = await send(payInvoiceInOneTap({ escrow: e, payer: payer.publicKey, token, hookAccounts: hooks, programId }), [payer, buyer])
    if ((await kinds(sig)) !== 'ended') throw new Error('the one tap logged something else')
    if ((await tokens(payoutAddress(seller.publicKey, token.mint, token.program), token)) !== sellerBefore + 1_000_000n) throw new Error('the seller was not paid')
    note(d, `one tap: the deposit address made first, then the buyer pays 1.00 ${label} into it and releases it to the seller, in one transaction`, sig)
    e = (await escrowAt(escrow))!
  }
  if (e.status !== 'ended' || e.outcome !== 'releasedToSeller' || e.creator !== 'seller') throw new Error('not ended, released to the seller, created by the seller')
  if (e.fundedAt === null || e.fundedAt !== e.endedAt) throw new Error('nobody marked it, so the funding time must be the ending\'s')
  if (!e.payer.equals(payer.publicKey)) throw new Error('the payer is not recorded')
  d.receipt = receipt(e)
  save()
  console.log(`  receipt ${escrow.toBase58()}: ${e.outcome}, funded at ${e.fundedAt}, ended at ${e.endedAt}`)
}

/** Deal 2, in `token`: a timer, an objection, and a 60/40 split by both. */
async function objectionDeal(name: string, token: Token, label: string): Promise<void> {
  const d = deal(name, `the buyer opens 2.00 ${label} with a one-day timer to the seller and funds it at once; anyone marks it; the buyer objects before the timer is due; both sign a 60/40 split`)
  const terms = termsFor({ timer: { days: 1, to: 'seller' } }, { seller: seller.publicKey, amount: 2_000_000n, id: BigInt(d.id) })
  const k = keysFor({ buyer: buyer.publicKey, payer: payer.publicKey, mint: token.mint, tokenProgram: token.program, terms, programId })
  d.escrow = k.escrow.toBase58()
  d.mint = token.mint.toBase58()
  save()
  if (!(await escrowAt(k.escrow))) {
    const { fund } = await oneTapHooks(token, k)
    const sig = await send(createAndFund({ buyer: buyer.publicKey, payer: payer.publicKey, token, terms, hookAccounts: { fund }, programId }), [payer, buyer])
    if ((await kinds(sig)) !== 'created') throw new Error('create and fund logged something else')
    note(d, `create and fund: the deposit address made first, the buyer opens 2.00 ${label} with a one-day timer to the seller and pays it in, in one transaction`, sig)
  }
  let e = (await escrowAt(k.escrow))!
  if (e.status === 'open') {
    const sig = await send([markFundedIx({ escrow: k.escrow, vault: k.vault, programId })], [payer])
    if ((await kinds(sig)) !== 'funded') throw new Error('the mark logged something else')
    note(d, 'mark_funded: the payer marks the funding; the timer is due a day later', sig)
    e = (await escrowAt(k.escrow))!
  }
  if (e.status === 'funded' && !e.objection) {
    if (!canObject(e)) throw new Error('the timer is already due: too late to object')
    const sig = await send([objectIx({ account: e, party: buyer.publicKey, programId })], [payer, buyer])
    if ((await kinds(sig)) !== 'objected') throw new Error('the objection logged something else')
    note(d, 'object: the buyer objects before the timer is due; the timer is off', sig)
    e = (await escrowAt(k.escrow))!
  }
  if (e.status === 'funded') {
    let refused = ''
    try {
      timerReleaseIx({ account: e, tokenProgram: token.program, programId })
    } catch (err) {
      refused = String(err)
    }
    if (!refused.includes('Objected')) throw new Error('the timer is not refused after the objection')
    const sellerTokens = payoutAddress(seller.publicKey, token.mint, token.program)
    const sellerBefore = await tokens(sellerTokens, token)
    const hooks = await hookAccounts({ reader: connection, mint: token.mint, transfers: payoutTransfers(k, ['seller', 'buyer']) })
    const sig = await send([splitIx({ keys: k, sellerBps: 6_000, hookAccounts: hooks, programId })], [payer, buyer, seller])
    if ((await kinds(sig)) !== 'ended') throw new Error('the split logged something else')
    if ((await tokens(sellerTokens, token)) !== sellerBefore + 1_200_000n) throw new Error('the seller was not paid 60%')
    note(d, `split: buyer and seller both sign 60/40; 1.20 ${label} to the seller, 0.80 back to the buyer`, sig)
    e = (await escrowAt(k.escrow))!
  }
  if (e.status !== 'ended' || e.outcome !== 'split' || e.objection !== 'buyer' || e.toSeller !== 1_200_000n || e.toBuyer !== 800_000n) {
    throw new Error('not ended, split 1.20 and 0.80, objected by the buyer')
  }
  d.receipt = receipt(e)
  save()
  console.log(`  receipt ${k.escrow.toBase58()}: ${e.outcome}, objected by the ${e.objection} at ${e.objectedAt}, funded at ${e.fundedAt}`)
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

/** Deal 3's mint: made once with Open USD's extensions, the payer holding every role of the dollar's maker; three of it for the buyer. */
async function openUsdShaped(): Promise<Token> {
  const issuer = payer.publicKey
  // Once made, the mint is the record's; its key is needed only to make it, so any machine holding
  // the phrase can run the deals again.
  if (!record.openUsdShaped) {
    const file = join(keysDir!, 'open-usd-shaped-mint.json')
    if (!existsSync(file)) writeFileSync(file, JSON.stringify([...Keypair.generate().secretKey]), { mode: 0o600 })
    record.openUsdShaped = {
      what: "A Token-2022 mint with every extension Open USD (ousd2mJsPEckLHcSCDxyKD7NDGARZcfLbDZkKiatYHB) has on mainnet, in its order, six decimals, the devnet payer key holding every role of the dollar's maker; three of it minted to the buyer.",
      mint: key('open-usd-shaped-mint').publicKey.toBase58(),
      issuer: issuer.toBase58(),
      signatures: {},
    }
    save()
  }
  const mint = new PublicKey(record.openUsdShaped.mint)
  if (!(await connection.getAccountInfo(mint))) {
    const mintKey = key('open-usd-shaped-mint')
    if (!mintKey.publicKey.equals(mint)) throw new Error('the record names an Open USD-shaped mint that this keys directory cannot make')
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
      [payer, mintKey],
    )
    record.openUsdShaped.signatures.mint = sig
    save()
    console.log(`  ${sig}  the Open USD-shaped mint`)
  }
  let info = (await connection.getAccountInfo(mint))!
  if (!getExtensionTypes(unpackMint(mint, info, TOKEN_2022_PROGRAM_ID).tlvData).includes(ExtensionType.TokenMetadata)) {
    const sig = await tokenMetadataInitializeWithRentTransfer(
      connection,
      payer,
      mint,
      issuer,
      payer,
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
  const buyerTokens = refundAddress(buyer.publicKey, mint, TOKEN_2022_PROGRAM_ID)
  if (!(await connection.getAccountInfo(buyerTokens))) {
    const sig = await send(
      [
        createAssociatedTokenAccountIdempotentInstruction(issuer, buyerTokens, buyer.publicKey, mint, TOKEN_2022_PROGRAM_ID),
        createAssociatedTokenAccountIdempotentInstruction(issuer, payoutAddress(seller.publicKey, mint, TOKEN_2022_PROGRAM_ID), seller.publicKey, mint, TOKEN_2022_PROGRAM_ID),
        createMintToCheckedInstruction(mint, buyerTokens, issuer, 3_000_000n, 6, [], TOKEN_2022_PROGRAM_ID),
      ],
      [payer],
    )
    record.openUsdShaped.signatures['accounts and three to the buyer'] = sig
    console.log(`  ${sig}  both parties' standard accounts, three to the buyer`)
  }
  save()
  return token
}

console.log(`escrow ${programId.toBase58()}`)

// 1 and 2, in the classic test dollar.
const classic = await readToken(classicMint)
await invoiceDeal('invoice', classic, 'test dollar')
await objectionDeal('objection', classic, 'test dollar')

// 3. The same two in the Open USD-shaped Token-2022 dollar.
const ousd = await openUsdShaped()
await invoiceDeal('invoice, Token-2022', ousd, 'Open USD-shaped dollar')
await objectionDeal('objection, Token-2022', ousd, 'Open USD-shaped dollar')

// 4. After the upgrade in place.
const upgraded = record.escrow.upgrades?.at(-1)
if (upgraded) {
  const buyerTokens = refundAddress(buyer.publicKey, ousd.mint, ousd.program)
  const d = (record.upgradeChecks ??= { what: `after the upgrade in slot ${upgraded.slot}: deal 1 again in the Open USD-shaped dollar, and a non-transferable mint's create simulated`, signatures: {} })
  if (!record.deals['invoice, Token-2022, after the upgrade'] && (await tokens(buyerTokens, ousd)) < 1_000_000n) {
    const sig = await send([createMintToCheckedInstruction(ousd.mint, buyerTokens, payer.publicKey, 1_000_000n, 6, [], TOKEN_2022_PROGRAM_ID)], [payer])
    d.signatures['one more to the buyer'] = sig
    save()
    console.log(`  ${sig}  one more Open USD-shaped dollar to the buyer`)
  }
  await invoiceDeal('invoice, Token-2022, after the upgrade', ousd, 'Open USD-shaped dollar')

  const file = join(keysDir!, 'non-transferable-mint.json')
  if (!existsSync(file)) writeFileSync(file, JSON.stringify([...Keypair.generate().secretKey]), { mode: 0o600 })
  const nt = key('non-transferable-mint')
  d.nonTransferableMint = nt.publicKey.toBase58()
  if (!(await connection.getAccountInfo(nt.publicKey))) {
    const space = getMintLen([ExtensionType.NonTransferable])
    const sig = await send(
      [
        SystemProgram.createAccount({ fromPubkey: payer.publicKey, newAccountPubkey: nt.publicKey, lamports: await connection.getMinimumBalanceForRentExemption(space), space, programId: TOKEN_2022_PROGRAM_ID }),
        createInitializeNonTransferableMintInstruction(nt.publicKey, TOKEN_2022_PROGRAM_ID),
        createInitializeMint2Instruction(nt.publicKey, 6, payer.publicKey, null, TOKEN_2022_PROGRAM_ID),
      ],
      [payer, nt],
    )
    d.signatures['a non-transferable mint'] = sig
    save()
    console.log(`  ${sig}  a non-transferable Token-2022 mint`)
  }
  const terms = termsFor(undefined, { seller: seller.publicKey, amount: 1_000_000n, id: randomId() })
  const create = invoiceIx({ seller: seller.publicKey, buyer: buyer.publicKey, payer: payer.publicKey, mint: nt.publicKey, tokenProgram: TOKEN_2022_PROGRAM_ID, terms, programId })
  const tx = new Transaction().add(create)
  tx.feePayer = payer.publicKey
  tx.recentBlockhash = (await connection.getLatestBlockhash('confirmed')).blockhash
  tx.sign(payer, seller)
  const sim = await connection.simulateTransaction(tx)
  const refused = (sim.value.logs ?? []).find((l) => l.includes('Error Code: NonTransferable'))
  if (!sim.value.err || !refused) throw new Error(`create with a non-transferable mint was not refused: ${JSON.stringify(sim.value.err)}`)
  d.nonTransferableCreate = { simulated: true, err: sim.value.err, log: refused.replace(/^Program log: /, '') }
  save()
  console.log(`  a non-transferable mint's create, simulated: ${d.nonTransferableCreate.log}`)
}

console.log('done')
