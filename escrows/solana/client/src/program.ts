// The wire format of the escrow: addresses, discriminators, instruction bytes, the account
// layout and the event layouts.
//
// Everything here is sealed with the program. These bytes are what clients and indexes read and
// write forever, so this file is written out by hand rather than generated: a reader can check it
// against `escrow/program/src/lib.rs` line by line, and the Rust tests encode the same bytes
// independently, so a drift on either side fails a test. An escrow of v1, an earlier program no
// longer in this repo, is read with that program's own client, in this repo's git history.

import { sha256 } from '@noble/hashes/sha2.js'
import {
  addExtraAccountMetasForExecute,
  ExtensionType,
  getExtensionTypes,
  getTransferHook,
  unpackMint,
} from '@solana/spl-token'
import {
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  type AccountInfo,
  type AccountMeta,
  type Connection,
} from '@solana/web3.js'

export const PROGRAM_ID = new PublicKey('FoRE2EscrowV2objectsTimerFundedAtPayer222222')
/** The classic SPL Token program. */
export const TOKEN_PROGRAM_ID = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')
/** Token-2022. The escrow takes a mint of either; every instruction names the one that owns it. */
export const TOKEN_2022_PROGRAM_ID = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb')
export const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL')
/** Wrapped SOL: a classic SPL Token mint that `create` refuses by name. */
export const NATIVE_MINT = new PublicKey('So11111111111111111111111111111111111111112')
/** Token-2022's wrapped SOL, refused the same way. */
export const NATIVE_MINT_2022 = new PublicKey('9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP')

/** Written into every escrow. A v3 is a new program at a new address. */
export const VERSION = 2
/** One hundred percent. */
export const BPS = 10_000
export const SECONDS_PER_DAY = 86_400n
/** The longest timer: its days are sixteen bits. */
export const MAX_TIMER_DAYS = 65_535
/** The escrow account's bytes after Anchor's eight-byte discriminator: v1's 256, then the payer and the objection. */
export const ESCROW_LEN = 297
export const ESCROW_SEED = new TextEncoder().encode('escrow')

/** One of the two parties. */
export type Side = 'buyer' | 'seller'
const SIDES: Side[] = ['buyer', 'seller']

/** The optional timer: this many whole days after the funding is marked, everything goes to `to`, unless a party objected first. */
export type Timer = { days: number; to: Side }

/** What `create` carries, besides the buyer, whose key is passed beside it. Every option is off unless set. */
export type Terms = {
  /** Tells apart two deals with the same terms. `randomId()` picks one. */
  id: bigint
  seller: PublicKey
  /** In the mint's base units: what the deal is for, and what funds it. */
  amount: bigint
  /** null: no arbiter. Any key but the zero key and the two parties' otherwise. */
  arbiter: PublicKey | null
  /** null: no timer. */
  timer: Timer | null
}

/** `amount × bps / 10,000`, rounded down. */
export function share(amount: bigint, bps: number): bigint {
  if (!Number.isInteger(bps) || bps < 0 || bps > BPS) throw new RangeError(`${bps} is not 0..=10,000 basis points`)
  return (amount * BigInt(bps)) / BigInt(BPS)
}

/** Anchor's discriminator: the first eight bytes of `sha256("<namespace>:<name>")`. */
export function discriminator(namespace: string, name: string): Uint8Array {
  return sha256(new TextEncoder().encode(`${namespace}:${name}`)).slice(0, 8)
}

const u8 = (n: number) => new Uint8Array([n])
function u16le(n: number): Uint8Array {
  const b = new Uint8Array(2)
  new DataView(b.buffer).setUint16(0, n, true)
  return b
}
function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, BigInt.asUintN(64, n), true)
  return b
}

function concat(parts: Uint8Array[]): Buffer {
  let n = 0
  for (const p of parts) n += p.length
  const out = new Uint8Array(n)
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return Buffer.from(out)
}

class Reader {
  at = 0
  private b: Uint8Array
  private view: DataView
  constructor(b: Uint8Array) {
    this.b = b
    this.view = new DataView(b.buffer, b.byteOffset, b.byteLength)
  }
  u8(): number {
    return this.b[this.at++]
  }
  u16(): number {
    const v = this.view.getUint16(this.at, true)
    this.at += 2
    return v
  }
  u64(): bigint {
    const v = this.view.getBigUint64(this.at, true)
    this.at += 8
    return v
  }
  i64(): bigint {
    const v = this.view.getBigInt64(this.at, true)
    this.at += 8
    return v
  }
  key(): PublicKey {
    const v = new PublicKey(this.b.subarray(this.at, this.at + 32))
    this.at += 32
    return v
  }
  side(): Side {
    const s = SIDES[this.u8()]
    if (!s) throw new Error('unknown side byte')
    return s
  }
  done(): void {
    if (this.at !== this.b.length) throw new Error(`${this.b.length - this.at} trailing bytes`)
  }
}

/** A random 64-bit id, from the platform's random source. */
export function randomId(): bigint {
  const b = new Uint8Array(8)
  crypto.getRandomValues(b)
  return new DataView(b.buffer).getBigUint64(0, true)
}

/** Every term of an escrow: what `create` carries, and the mint. */
export type AllTerms = { buyer: PublicKey; mint: PublicKey; terms: Terms }

/**
 * The seed of an escrow's address: SHA-256 of all its terms, each at a fixed length, in the
 * receipt's order. id (8 bytes, little-endian), buyer, seller, arbiter (the zero key for none),
 * mint (32 each), amount (8, little-endian), the timer's days (2, little-endian; 0 for none) and
 * its side (1: buyer 0, seller 1; the buyer's when there is no timer).
 */
export function termsHash(all: AllTerms): Uint8Array {
  const { buyer, mint, terms } = all
  return sha256(
    concat([
      u64le(terms.id),
      buyer.toBytes(),
      terms.seller.toBytes(),
      (terms.arbiter ?? PublicKey.default).toBytes(),
      mint.toBytes(),
      u64le(terms.amount),
      u16le(terms.timer?.days ?? 0),
      u8(SIDES.indexOf(terms.timer?.to ?? 'buyer')),
    ]),
  )
}

/**
 * The escrow's address: `["escrow", termsHash]`. Every term is in it, so a payment sent to it
 * counts only toward a deal with exactly those terms. Who opens it is not a term: the buyer and
 * the seller land at the same address with the same terms, and only they can open it.
 */
export function escrowAddress(all: AllTerms, programId: PublicKey = PROGRAM_ID): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from(ESCROW_SEED), Buffer.from(termsHash(all))], programId)[0]
}

/** An escrow's terms, as read off the chain. */
export function termsOf(account: Pick<EscrowAccount, 'id' | 'buyer' | 'seller' | 'mint' | 'amount' | 'arbiter' | 'timer'>): AllTerms {
  const { id, seller, amount, arbiter, timer } = account
  return { buyer: account.buyer, mint: account.mint, terms: { id, seller, amount, arbiter, timer } }
}

/**
 * A mint as the escrow takes it: the token program that owns it (classic or Token-2022) and its
 * decimals, which every transfer names. `tokenOf` reads it from the mint's account.
 */
export type Token = { mint: PublicKey; program: PublicKey; decimals: number }

/**
 * The mint, from its account as read from the chain (`owner` and `data`). Throws with the
 * program's own error name where `create` would refuse it: wrapped SOL of either program, or a
 * Token-2022 mint with a transfer fee or that cannot be transferred. Whatever else the token's
 * maker can do with its mint (freeze, pause, a permanent delegate, a transfer hook) is accepted;
 * `escrow/security-checklist.md` lists each, with the test that pins it.
 */
export function tokenOf(mint: PublicKey, account: { owner: PublicKey; data: Uint8Array }): Token {
  const program = account.owner
  if (!program.equals(TOKEN_PROGRAM_ID) && !program.equals(TOKEN_2022_PROGRAM_ID)) {
    throw new Error(`${mint.toBase58()} is not a mint of either token program`)
  }
  if (mint.equals(NATIVE_MINT) || mint.equals(NATIVE_MINT_2022)) throw new Error('NativeMint: wrapped SOL is not accepted')
  const state = unpackMint(mint, { ...asAccountInfo(account), owner: program }, program)
  const types: number[] = program.equals(TOKEN_2022_PROGRAM_ID) ? getExtensionTypes(state.tlvData) : []
  if (types.includes(ExtensionType.TransferFeeConfig) || types.includes(CONFIDENTIAL_TRANSFER_FEE_CONFIG)) {
    throw new Error('TransferFee: a token with a transfer fee is not accepted')
  }
  if (types.includes(ExtensionType.NonTransferable)) throw new Error('NonTransferable: a token that cannot be transferred is not accepted')
  return { mint, program, decimals: state.decimals }
}

/** Token-2022's extension type 16, which `@solana/spl-token` 0.4.9 does not name. */
const CONFIDENTIAL_TRANSFER_FEE_CONFIG = 16

function asAccountInfo(account: { owner: PublicKey; data: Uint8Array }): AccountInfo<Buffer> {
  return { owner: account.owner, data: Buffer.from(account.data), lamports: 0, executable: false }
}

/**
 * An associated token account: the standard address of `owner`'s account for `mint`, under the
 * token program that owns the mint (the classic one unless named). The address differs between
 * the two programs.
 */
export function associatedTokenAddress(owner: PublicKey, mint: PublicKey, tokenProgram: PublicKey = TOKEN_PROGRAM_ID): PublicKey {
  return PublicKey.findProgramAddressSync(
    [owner.toBuffer(), tokenProgram.toBuffer(), mint.toBuffer()],
    ASSOCIATED_TOKEN_PROGRAM_ID,
  )[0]
}

/**
 * The deposit address: the escrow's associated token account for the mint, under the mint's
 * token program. The standard derivation, so any wallet app that sends this token "to the escrow's
 * address" lands it here.
 */
export function vaultAddress(escrow: PublicKey, mint: PublicKey, tokenProgram: PublicKey = TOKEN_PROGRAM_ID): PublicKey {
  return associatedTokenAddress(escrow, mint, tokenProgram)
}

/**
 * The buyer's refund address: the buyer's standard token account for the mint, computed from two
 * keys fixed at creation. Every payout to the buyer lands here and nowhere else. It has to exist
 * only when the buyer is paid something; `makeRefundAddressIx` makes it first in the same
 * transaction when it might not.
 */
export function refundAddress(buyer: PublicKey, mint: PublicKey, tokenProgram: PublicKey = TOKEN_PROGRAM_ID): PublicKey {
  return associatedTokenAddress(buyer, mint, tokenProgram)
}

/**
 * The seller's payout address: the seller's standard token account for the mint. Every payout to
 * the seller lands here and nowhere else, the same rule as the buyer's. It has to exist when the
 * seller is paid something; `makeStandardAccountIx` makes it first when it might not.
 */
export function payoutAddress(seller: PublicKey, mint: PublicKey, tokenProgram: PublicKey = TOKEN_PROGRAM_ID): PublicKey {
  return associatedTokenAddress(seller, mint, tokenProgram)
}

/**
 * Make `owner`'s standard token account for `mint` if it is missing, and do nothing if it is
 * there: the associated token program's idempotent create, `payer` paying its rent, under the
 * mint's token program, which gives the account whatever extensions the mint requires. The
 * account, and its rent, are the owner's from then on.
 */
export function makeStandardAccountIx(args: { payer: PublicKey; owner: PublicKey; mint: PublicKey; tokenProgram?: PublicKey }): TransactionInstruction {
  const tokenProgram = args.tokenProgram ?? TOKEN_PROGRAM_ID
  return new TransactionInstruction({
    programId: ASSOCIATED_TOKEN_PROGRAM_ID,
    keys: [
      rw(args.payer, true),
      rw(associatedTokenAddress(args.owner, args.mint, tokenProgram)),
      ro(args.owner),
      ro(args.mint),
      ro(SystemProgram.programId),
      ro(tokenProgram),
    ],
    data: Buffer.from([1]),
  })
}

/** The buyer's refund address, made if missing: put it before a way out that pays the buyer. */
export function makeRefundAddressIx(args: { payer: PublicKey; buyer: PublicKey; mint: PublicKey; tokenProgram?: PublicKey }): TransactionInstruction {
  return makeStandardAccountIx({ payer: args.payer, owner: args.buyer, mint: args.mint, tokenProgram: args.tokenProgram })
}

/**
 * The deposit address, made if missing, `payer` paying its rent: the first instruction of every
 * transaction that funds an escrow it creates. `create` adopts it. Made at the top of the
 * transaction by the associated token program, not inside `create`, so a fee payer that checks
 * every transfer's destination before it signs finds the deposit address already made.
 */
export function makeDepositAddressIx(args: { payer: PublicKey; escrow: PublicKey; mint: PublicKey; tokenProgram?: PublicKey }): TransactionInstruction {
  return makeStandardAccountIx({ payer: args.payer, owner: args.escrow, mint: args.mint, tokenProgram: args.tokenProgram })
}

/**
 * A wallet app's `transfer_checked` (instruction 12: amount, decimals) under the mint's token
 * program, the way a person funds a deposit account: the one transfer both programs take for every
 * mint, and the only one Token-2022 takes from an account with a hook extension. `hookAccounts`,
 * from `hookAccounts`, go after the four it names.
 */
export function transferIx(args: {
  from: PublicKey
  to: PublicKey
  owner: PublicKey
  mint: PublicKey
  amount: bigint
  decimals: number
  tokenProgram?: PublicKey
  hookAccounts?: AccountMeta[]
}): TransactionInstruction {
  return new TransactionInstruction({
    programId: args.tokenProgram ?? TOKEN_PROGRAM_ID,
    keys: [rw(args.from), ro(args.mint), rw(args.to), ro(args.owner, true), ...(args.hookAccounts ?? [])],
    data: concat([u8(12), u64le(args.amount), u8(args.decimals)]),
  })
}

// ---------------------------------------------------------------------------------------------
// Transfer hooks.
// ---------------------------------------------------------------------------------------------

/** Reads one account: a `Connection`, or anything with its `getAccountInfo`. */
export type AccountReader = Pick<Connection, 'getAccountInfo'>

/** One transfer a transaction makes, as a transfer hook sees it. */
export type HookTransfer = { source: PublicKey; destination: PublicKey; authority: PublicKey; amount?: bigint }

/**
 * A token account the same transaction makes before a transfer reaches it, such as the deposit
 * address in a one tap: read as a fresh account of `owner` for `mint`, since the chain has none yet.
 */
export type PlannedAccount = { address: PublicKey; owner: PublicKey; mint: PublicKey; tokenProgram: PublicKey }

/**
 * The accounts a Token-2022 mint's transfer hook needs for `transfers`, for the escrow to forward
 * (append them to a way out, or pass them to `transferIx`): the hook's program, its validation
 * account and every account that lists, resolved through `reader` by `@solana/spl-token`'s own
 * resolver. Empty for a classic mint and for a mint whose hook names no program; the token's maker
 * can name one at any time, so resolve before each transaction rather than once per escrow.
 * Each appears once, writable if any transfer needs it so, and never as a signer: the escrow
 * forwards none as one.
 */
export async function hookAccounts(args: { reader: AccountReader; mint: PublicKey; transfers: HookTransfer[]; planned?: PlannedAccount[] }): Promise<AccountMeta[]> {
  const mintInfo = await args.reader.getAccountInfo(args.mint)
  if (!mintInfo || !mintInfo.owner.equals(TOKEN_2022_PROGRAM_ID)) return []
  const hook = getTransferHook(unpackMint(args.mint, mintInfo, TOKEN_2022_PROGRAM_ID))
  if (!hook || hook.programId.equals(PublicKey.default)) return []
  const planned = new Map((args.planned ?? []).map((p) => [p.address.toBase58(), p]))
  const reader = {
    getAccountInfo: async (address: PublicKey): Promise<AccountInfo<Buffer> | null> => {
      const p = planned.get(address.toBase58())
      if (!p) return args.reader.getAccountInfo(address)
      const data = Buffer.alloc(165)
      p.mint.toBuffer().copy(data, 0)
      p.owner.toBuffer().copy(data, 32)
      data[108] = 1 // initialized
      return { owner: p.tokenProgram, data, lamports: 0, executable: false }
    },
  } as unknown as Connection
  const out = new Map<string, AccountMeta>()
  const add = (meta: AccountMeta) => {
    const seen = out.get(meta.pubkey.toBase58())
    out.set(meta.pubkey.toBase58(), { pubkey: meta.pubkey, isSigner: false, isWritable: meta.isWritable || (seen?.isWritable ?? false) })
  }
  add({ pubkey: hook.programId, isSigner: false, isWritable: false })
  for (const t of args.transfers) {
    const ix = new TransactionInstruction({
      programId: TOKEN_2022_PROGRAM_ID,
      keys: [rw(t.source), ro(args.mint), rw(t.destination), ro(t.authority)],
      data: Buffer.alloc(0),
    })
    await addExtraAccountMetasForExecute(reader, ix, hook.programId, t.source, args.mint, t.destination, t.authority, t.amount ?? 0n)
    for (const meta of ix.keys.slice(4)) add(meta)
  }
  return [...out.values()]
}

/** The transfers a way out makes: from the deposit account, the escrow signing, to each of `to`. */
export function payoutTransfers(keys: EscrowKeys, to: Side[]): HookTransfer[] {
  return to.map((side) => ({
    source: keys.vault,
    authority: keys.escrow,
    destination: side === 'buyer' ? refundAddress(keys.buyer, keys.mint, keys.tokenProgram) : payoutAddress(keys.seller, keys.mint, keys.tokenProgram),
  }))
}

/**
 * The checks `create` makes, made here first so a bad set of terms fails before a transaction is
 * built. Throws with the program's own error name.
 */
export function validateTerms(terms: Terms, buyer: PublicKey): void {
  if (terms.seller.equals(buyer)) throw new Error('SameParty: the buyer and the seller must be different keys')
  if (buyer.equals(PublicKey.default)) throw new Error('EmptyKey: the buyer cannot be the zero key')
  if (terms.seller.equals(PublicKey.default)) throw new Error('EmptyKey: the seller cannot be the zero key')
  if (terms.arbiter && terms.arbiter.equals(PublicKey.default)) throw new Error('EmptyKey: the arbiter cannot be the zero key')
  if (terms.arbiter && (terms.arbiter.equals(buyer) || terms.arbiter.equals(terms.seller))) {
    throw new Error('ArbiterIsAParty: the arbiter cannot be the buyer or the seller')
  }
  if (terms.amount <= 0n) throw new Error('AmountZero: the amount must be above zero')
  if (terms.amount >= 1n << 64n) throw new RangeError('the amount does not fit in 64 bits')
  if (terms.timer) {
    const { days, to } = terms.timer
    if (!Number.isInteger(days) || days < 1 || days > MAX_TIMER_DAYS) {
      throw new Error('TimerZero: a timer runs for a whole number of days, from 1 to 65,535')
    }
    if (!SIDES.includes(to)) throw new Error(`a timer pays the buyer or the seller, not ${String(to)}`)
  }
}

/**
 * id u64, buyer, seller, amount u64, arbiter as an `Option` (0, or 1 then the key), timer as an
 * `Option` (0, or 1 then days u16 and the side as one byte: buyer 0, seller 1).
 */
export function createArgsBytes(terms: Terms, buyer: PublicKey): Uint8Array {
  return concat([
    u64le(terms.id),
    buyer.toBytes(),
    terms.seller.toBytes(),
    u64le(terms.amount),
    terms.arbiter ? concat([u8(1), terms.arbiter.toBytes()]) : u8(0),
    terms.timer ? concat([u8(1), u16le(terms.timer.days), u8(SIDES.indexOf(terms.timer.to))]) : u8(0),
  ])
}

const ro = (pubkey: PublicKey, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: false })
const rw = (pubkey: PublicKey, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: true })

/**
 * `create`. The creator signs: the buyer (the default), or the seller, invoicing (`invoiceIx`).
 * The escrow's address comes from the terms (`escrowAddress`); who signs as creator does not change
 * it. The payer signs and fronts both rents, and is recorded: every rent goes back to it. The
 * terms are checked against the program's rules (`validateTerms`, and neither party the escrow
 * itself or its deposit address) before anything is built.
 */
export function createIx(args: {
  buyer: PublicKey
  payer: PublicKey
  mint: PublicKey
  terms: Terms
  /** Who signs as creator: the buyer, unless the seller is invoicing. */
  creator?: PublicKey
  /** The program that owns the mint (`tokenOf`); the classic one unless named. */
  tokenProgram?: PublicKey
  programId?: PublicKey
}): TransactionInstruction {
  const programId = args.programId ?? PROGRAM_ID
  const tokenProgram = args.tokenProgram ?? TOKEN_PROGRAM_ID
  const creator = args.creator ?? args.buyer
  validateTerms(args.terms, args.buyer)
  if (!creator.equals(args.buyer) && !creator.equals(args.terms.seller)) {
    throw new Error('NotAParty: the buyer or the seller opens an escrow')
  }
  if (args.mint.equals(NATIVE_MINT) || args.mint.equals(NATIVE_MINT_2022)) throw new Error('NativeMint: wrapped SOL is not accepted')
  const escrow = escrowAddress({ buyer: args.buyer, mint: args.mint, terms: args.terms }, programId)
  const vault = vaultAddress(escrow, args.mint, tokenProgram)
  for (const party of [args.buyer, args.terms.seller]) {
    if (party.equals(escrow) || party.equals(vault)) {
      throw new Error("PartyIsTheEscrow: neither party can be the escrow's own address or its deposit address")
    }
  }
  return new TransactionInstruction({
    programId,
    keys: [
      rw(escrow),
      rw(vault),
      ro(creator, true),
      rw(args.payer, true),
      ro(args.mint),
      ro(tokenProgram),
      ro(ASSOCIATED_TOKEN_PROGRAM_ID),
      ro(SystemProgram.programId),
    ],
    data: concat([discriminator('global', 'create'), createArgsBytes(args.terms, args.buyer)]),
  })
}

/** `create` by the seller: an invoice naming the buyer. */
export function invoiceIx(args: {
  seller: PublicKey
  buyer: PublicKey
  payer: PublicKey
  mint: PublicKey
  terms: Terms
  tokenProgram?: PublicKey
  programId?: PublicKey
}): TransactionInstruction {
  if (!args.terms.seller.equals(args.seller)) throw new Error('an invoice names its own seller in the terms')
  return createIx({ ...args, creator: args.seller })
}

/**
 * `mark_funded`: anyone, once, when the deposit account holds the amount. It records the time and
 * nothing else; the timer counts from it, and no way out needs it: an ending nobody marked records
 * its own time as the funding time.
 */
export function markFundedIx(args: { escrow: PublicKey; vault: PublicKey; programId?: PublicKey }): TransactionInstruction {
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [rw(args.escrow), ro(args.vault)],
    data: concat([discriminator('global', 'mark_funded')]),
  })
}

/**
 * The keys every way out needs, all fixed at creation: the escrow, its deposit account, both
 * parties, the mint, the token program that owns it, and the rent recipient (the payer, who gets
 * every rent back). `keysOf` reads them from an escrow account off the chain, with
 * the mint's owner, which the escrow does not store (`tokenOf`); `keysFor` computes them from
 * terms, for an escrow created in the same transaction.
 */
export type EscrowKeys = {
  escrow: PublicKey
  vault: PublicKey
  buyer: PublicKey
  seller: PublicKey
  mint: PublicKey
  tokenProgram: PublicKey
  rentRecipient: PublicKey
}

export function keysOf(account: EscrowAccount, opts: { tokenProgram?: PublicKey; programId?: PublicKey } = {}): EscrowKeys {
  const escrow = escrowAddress(termsOf(account), opts.programId ?? PROGRAM_ID)
  const tokenProgram = opts.tokenProgram ?? TOKEN_PROGRAM_ID
  if (!account.vault.equals(vaultAddress(escrow, account.mint, tokenProgram))) {
    throw new Error("the escrow's deposit account is not under that token program: name the program that owns the mint")
  }
  return { escrow, vault: account.vault, buyer: account.buyer, seller: account.seller, mint: account.mint, tokenProgram, rentRecipient: account.rentRecipient }
}

export function keysFor(args: { buyer: PublicKey; payer: PublicKey; mint: PublicKey; terms: Terms; tokenProgram?: PublicKey; programId?: PublicKey }): EscrowKeys {
  const tokenProgram = args.tokenProgram ?? TOKEN_PROGRAM_ID
  const escrow = escrowAddress({ buyer: args.buyer, mint: args.mint, terms: args.terms }, args.programId)
  return { escrow, vault: vaultAddress(escrow, args.mint, tokenProgram), buyer: args.buyer, seller: args.terms.seller, mint: args.mint, tokenProgram, rentRecipient: args.payer }
}

/** Hook accounts, as the escrow takes them: after its own, and never signing. */
function forwarded(hookAccounts: AccountMeta[] | undefined): AccountMeta[] {
  return (hookAccounts ?? []).map((m) => ({ pubkey: m.pubkey, isSigner: false, isWritable: m.isWritable }))
}

function checkBps(sellerBps: number): void {
  if (!Number.isInteger(sellerBps) || sellerBps < 0 || sellerBps > BPS) {
    throw new RangeError(`BadSplit: ${sellerBps} is not 0..=10,000 basis points`)
  }
}

/**
 * `release_to_seller`: the buyer signs; the whole balance to the seller's payout address, which
 * must exist (`makeStandardAccountIx` first if the seller may not hold the token yet). Names no
 * buyer account: the buyer is paid nothing. Every way out takes `hookAccounts` (`hookAccounts`
 * with `payoutTransfers`) after its own: needed only for a mint whose transfer hook names a program.
 */
export function releaseToSellerIx(args: { keys: EscrowKeys; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  const k = args.keys
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [
      rw(k.escrow),
      rw(k.vault),
      ro(k.mint),
      rw(payoutAddress(k.seller, k.mint, k.tokenProgram)),
      rw(k.rentRecipient),
      ro(k.tokenProgram),
      ro(k.buyer, true),
      ...forwarded(args.hookAccounts),
    ],
    data: concat([discriminator('global', 'release_to_seller')]),
  })
}

/**
 * `release_to_buyer`: the seller signs; the whole balance back to the buyer's refund address.
 * Names no seller account: the seller is paid nothing.
 */
export function releaseToBuyerIx(args: { keys: EscrowKeys; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  const k = args.keys
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [
      rw(k.escrow),
      rw(k.vault),
      ro(k.mint),
      rw(refundAddress(k.buyer, k.mint, k.tokenProgram)),
      rw(k.rentRecipient),
      ro(k.tokenProgram),
      ro(k.seller, true),
      ...forwarded(args.hookAccounts),
    ],
    data: concat([discriminator('global', 'release_to_buyer')]),
  })
}

function bothAccounts(k: EscrowKeys): AccountMeta[] {
  return [
    rw(k.escrow),
    rw(k.vault),
    ro(k.mint),
    rw(refundAddress(k.buyer, k.mint, k.tokenProgram)),
    rw(payoutAddress(k.seller, k.mint, k.tokenProgram)),
    rw(k.rentRecipient),
    ro(k.tokenProgram),
  ]
}

/**
 * `split`: both sign; `sellerBps` of the whole balance to the seller, rounded down, the rest to the
 * buyer. Each side's standard account must exist if its share is above zero.
 */
export function splitIx(args: { keys: EscrowKeys; sellerBps: number; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  checkBps(args.sellerBps)
  const k = args.keys
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [...bothAccounts(k), ro(k.buyer, true), ro(k.seller, true), ...forwarded(args.hookAccounts)],
    data: concat([discriminator('global', 'split'), u16le(args.sellerBps)]),
  })
}

/** `arbitrate`: the arbiter named at creation signs any split, the same way both parties can. */
export function arbitrateIx(args: { keys: EscrowKeys; arbiter: PublicKey; sellerBps: number; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  checkBps(args.sellerBps)
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [...bothAccounts(args.keys), ro(args.arbiter, true), ...forwarded(args.hookAccounts)],
    data: concat([discriminator('global', 'arbitrate'), u16le(args.sellerBps)]),
  })
}

/**
 * `timer_release`: anyone, once the timer set at creation is due (`timerDueAt`); the whole balance
 * to the side it names, at that side's standard account (the buyer's refund address or the
 * seller's payout address). Built only from the escrow account as read from the chain, since the
 * account it pays depends on the timer.
 */
export function timerReleaseIx(args: { account: EscrowAccount; tokenProgram?: PublicKey; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  const programId = args.programId ?? PROGRAM_ID
  const a = args.account
  if (a.status === 'ended') throw new Error('Ended: this escrow has ended')
  if (!a.timer) throw new Error('NoTimer: no timer was set at creation')
  if (a.objection) throw new Error('Objected: a party objected; the timer is off')
  if (a.status !== 'funded') throw new Error('FundingNotMarked: send mark_funded first; the timer counts from it')
  const k = keysOf(a, { tokenProgram: args.tokenProgram, programId })
  const to = a.timer.to === 'buyer' ? refundAddress(k.buyer, k.mint, k.tokenProgram) : payoutAddress(k.seller, k.mint, k.tokenProgram)
  return new TransactionInstruction({
    programId,
    keys: [rw(k.escrow), rw(k.vault), ro(k.mint), rw(to), rw(k.rentRecipient), ro(k.tokenProgram), ...forwarded(args.hookAccounts)],
    data: concat([discriminator('global', 'timer_release')]),
  })
}

/**
 * `close_unfunded`: an escrow that never held the amount, by the buyer or the seller, at any time.
 * Whatever it holds goes back to the buyer's refund address (which must exist only if it holds
 * something); both accounts close; both rents go to the payer.
 */
export function closeUnfundedIx(args: { keys: EscrowKeys; closer: PublicKey; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  const k = args.keys
  if (!args.closer.equals(k.buyer) && !args.closer.equals(k.seller)) {
    throw new Error('NotACloser: only the buyer or the seller can close an escrow that never held the amount')
  }
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [
      rw(k.escrow),
      rw(k.vault),
      ro(k.mint),
      rw(refundAddress(k.buyer, k.mint, k.tokenProgram)),
      rw(k.rentRecipient),
      ro(k.tokenProgram),
      ro(args.closer, true),
      ...forwarded(args.hookAccounts),
    ],
    data: concat([discriminator('global', 'close_unfunded')]),
  })
}

/**
 * `recover_late`: anyone, on an escrow that has ended. Whatever a later payment left at its deposit
 * address goes to the buyer's refund address (made first at `caller`'s cost if it does not exist);
 * the deposit account closes again and its rent goes to the buyer. The receipt does not change.
 * Built only from the escrow account as read from the chain.
 */
export function recoverLateIx(args: { account: EscrowAccount; caller: PublicKey; tokenProgram?: PublicKey; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  const programId = args.programId ?? PROGRAM_ID
  const a = args.account
  if (a.status !== 'ended') throw new Error('NotEnded: money there is part of the deal')
  const k = keysOf(a, { tokenProgram: args.tokenProgram, programId })
  return new TransactionInstruction({
    programId,
    keys: [
      ro(k.escrow),
      rw(a.vault),
      rw(a.buyer),
      rw(refundAddress(a.buyer, a.mint, k.tokenProgram)),
      ro(a.mint),
      rw(args.caller, true),
      ro(k.tokenProgram),
      ro(ASSOCIATED_TOKEN_PROGRAM_ID),
      ro(SystemProgram.programId),
      ...forwarded(args.hookAccounts),
    ],
    data: concat([discriminator('global', 'recover_late')]),
  })
}

/**
 * `sweep_rent`: anyone, on any escrow. What the escrow account holds above its current rent-exempt
 * minimum goes to the payer recorded at creation, the key that fronted the rent; the account keeps
 * exactly the minimum and its bytes. Nobody signs but the transaction's fee payer.
 */
export function sweepRentIx(args: { escrow: PublicKey; payer: PublicKey; programId?: PublicKey }): TransactionInstruction {
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [rw(args.escrow), rw(args.payer)],
    data: concat([discriminator('global', 'sweep_rent')]),
  })
}

/**
 * `object`: the buyer or the seller, once per escrow, while it is live and before its timer is due
 * (`canObject`). It moves no money; from then on the timer never runs, and the money moves only by
 * a release, a split, or the arbiter if one was named. Built only from the escrow account as read
 * from the chain, and refused here where the program would refuse it, but for the time, which
 * only the chain's clock decides.
 */
export function objectIx(args: { account: EscrowAccount; party: PublicKey; programId?: PublicKey }): TransactionInstruction {
  const programId = args.programId ?? PROGRAM_ID
  const a = args.account
  if (a.status === 'ended') throw new Error('Ended: this escrow has ended')
  if (!args.party.equals(a.buyer) && !args.party.equals(a.seller)) throw new Error('NotAnObjector: only the buyer or the seller can object')
  if (a.objection) throw new Error('AlreadyObjected: an escrow takes one objection')
  return new TransactionInstruction({
    programId,
    keys: [rw(escrowAddress(termsOf(a), programId)), ro(args.party, true)],
    data: concat([discriminator('global', 'object')]),
  })
}

/**
 * What a hook needs for each transfer of a one-tap: the payment in, and the payment out. Resolve
 * each with `hookAccounts` (the payment in with the deposit address as a `PlannedAccount`, since
 * the same transaction makes it).
 */
export type OneTapHookAccounts = { fund?: AccountMeta[]; release?: AccountMeta[] }

/**
 * Open and fund in one transaction: the deposit address made first (`makeDepositAddressIx`, the
 * payer paying), the buyer's `create`, and a `transfer_checked` of the amount into the deposit
 * account. The buyer signs, with the payer. The buyer pays from its standard account unless `from`
 * names another it holds. `token` is `tokenOf` the mint.
 */
export function createAndFund(args: {
  buyer: PublicKey
  payer: PublicKey
  token: Token
  terms: Terms
  from?: PublicKey
  hookAccounts?: OneTapHookAccounts
  programId?: PublicKey
}): TransactionInstruction[] {
  const { mint, program: tokenProgram, decimals } = args.token
  const keys = keysFor({ ...args, mint, tokenProgram })
  return [
    makeDepositAddressIx({ payer: args.payer, escrow: keys.escrow, mint, tokenProgram }),
    createIx({ ...args, mint, tokenProgram }),
    transferIx({
      from: args.from ?? associatedTokenAddress(args.buyer, mint, tokenProgram),
      to: keys.vault,
      owner: args.buyer,
      mint,
      amount: args.terms.amount,
      decimals,
      tokenProgram,
      hookAccounts: args.hookAccounts?.fund,
    }),
  ]
}

/**
 * Pay in one tap: `createAndFund`, then `release_to_seller`, for one transaction the buyer signs
 * (with the payer). Put `makeStandardAccountIx` for the seller first if the seller may not hold
 * the token yet: the seller is paid only at its standard account.
 */
export function payInOneTap(args: {
  buyer: PublicKey
  payer: PublicKey
  token: Token
  terms: Terms
  from?: PublicKey
  hookAccounts?: OneTapHookAccounts
  programId?: PublicKey
}): TransactionInstruction[] {
  const keys = keysFor({ ...args, mint: args.token.mint, tokenProgram: args.token.program })
  return [...createAndFund(args), releaseToSellerIx({ keys, hookAccounts: args.hookAccounts?.release, programId: args.programId })]
}

/**
 * Pay an invoice in one tap: the deposit address made first (`makeDepositAddressIx`, the payer
 * paying if it is missing), a `transfer_checked` of the amount from the buyer into it, and
 * `release_to_seller`, for one transaction the buyer signs (with the payer). The seller opened the
 * escrow; `escrow` is it as read off the chain (`decodeEscrow`), after the buyer's app has checked
 * it (`assertOptionsAgreed`, and that it names the buyer's own key as buyer). The deposit address is
 * made at the top, as in `createAndFund`, so a fee payer that checks every transfer's destination
 * before it signs finds it made, and can sign "Pay". It sends the whole amount, so it is for an
 * invoice nothing has been paid into yet: read the deposit address's balance first (`funds`),
 * since every way out pays out the whole balance. Put `makeStandardAccountIx` for the seller
 * first if the seller may not hold the token yet. The buyer pays from its standard account unless
 * `from` names another it holds.
 */
export function payInvoiceInOneTap(args: {
  escrow: EscrowAccount
  payer: PublicKey
  token: Token
  from?: PublicKey
  hookAccounts?: OneTapHookAccounts
  programId?: PublicKey
}): TransactionInstruction[] {
  const e = args.escrow
  if (e.status !== 'open') {
    throw new Error(`this escrow is ${e.status === 'ended' ? 'ended' : 'already funded'}: nothing to pay`)
  }
  if (!args.token.mint.equals(e.mint)) throw new Error("the token is not the escrow's mint")
  const keys = keysOf(e, { tokenProgram: args.token.program, programId: args.programId })
  return [
    makeDepositAddressIx({ payer: args.payer, escrow: keys.escrow, mint: keys.mint, tokenProgram: keys.tokenProgram }),
    transferIx({
      from: args.from ?? associatedTokenAddress(keys.buyer, keys.mint, keys.tokenProgram),
      to: keys.vault,
      owner: keys.buyer,
      mint: keys.mint,
      amount: e.amount,
      decimals: args.token.decimals,
      tokenProgram: keys.tokenProgram,
      hookAccounts: args.hookAccounts?.fund,
    }),
    releaseToSellerIx({ keys, hookAccounts: args.hookAccounts?.release, programId: args.programId }),
  ]
}

// ---------------------------------------------------------------------------------------------
// The account.
// ---------------------------------------------------------------------------------------------

/** open: created, the funding not marked. funded: marked. ended: paid out; the receipt. An objection is not a status: see `objection`. */
export type Status = 'open' | 'funded' | 'ended'
const STATUS: Status[] = ['open', 'funded', 'ended']

export type Outcome = 'releasedToSeller' | 'releasedToBuyer' | 'split' | 'arbitrated' | 'timerReleased'
const OUTCOME: Outcome[] = ['releasedToSeller', 'releasedToBuyer', 'split', 'arbitrated', 'timerReleased']

export type EscrowAccount = {
  version: number
  id: bigint
  buyer: PublicKey
  seller: PublicKey
  /** null when none was named. */
  arbiter: PublicKey | null
  mint: PublicKey
  vault: PublicKey
  /** Where every rent goes back: the payer's key, the same as `payer`. */
  rentRecipient: PublicKey
  amount: bigint
  /** Who opened it: the seller, for an invoice. Not a term: it does not change the address. */
  creator: Side
  /** null when none was set. */
  timer: Timer | null
  createdAt: bigint
  /** When the money was there: the mark's time, or the ending's if nobody marked it; null before either. */
  fundedAt: bigint | null
  status: Status
  bump: number
  /** When it ended, or null. */
  endedAt: bigint | null
  /** How it ended, or null while it has not. */
  outcome: Outcome | null
  /** What each party was paid at the end; 0 before. */
  toSeller: bigint
  toBuyer: bigint
  /** The key that fronted the rent: rent above the receipt's minimum goes back to it. */
  payer: PublicKey
  /** Which party objected, or null. Once one has, the timer never runs. */
  objection: Side | null
  /** When the objection was made, or null. */
  objectedAt: bigint | null
}

/**
 * version 0, id 1..9, buyer 9..41, seller 41..73, arbiter 73..105, mint 105..137, vault 137..169,
 * rent_recipient 169..201, amount 201..209, creator 209, timer_days 210..212, timer_to 212,
 * created_at 213..221, funded_at 221..229, status 229, bump 230, ended_at 231..239, outcome 239,
 * to_seller 240..248, to_buyer 248..256, then v2's: payer 256..288, objection 288 (none 0, the
 * buyer 1, the seller 2), objected_at 289..297.
 */
export function decodeEscrow(data: Uint8Array): EscrowAccount {
  if (data.length !== 8 + ESCROW_LEN) throw new Error(`an escrow account is ${8 + ESCROW_LEN} bytes, not ${data.length}`)
  const want = discriminator('account', 'Escrow')
  if (!want.every((v, i) => data[i] === v)) throw new Error('not an escrow account')
  const r = new Reader(data.subarray(8))
  const version = r.u8()
  const id = r.u64()
  const buyer = r.key()
  const seller = r.key()
  const arbiter = r.key()
  const mint = r.key()
  const vault = r.key()
  const rentRecipient = r.key()
  const amount = r.u64()
  const creator = r.side()
  const timerDays = r.u16()
  const timerTo = r.side()
  const createdAt = r.i64()
  const fundedAt = r.i64()
  const status = STATUS[r.u8()]
  const bump = r.u8()
  const endedAt = r.i64()
  const outcomeByte = r.u8()
  const toSeller = r.u64()
  const toBuyer = r.u64()
  const payer = r.key()
  const objectionByte = r.u8()
  const objectedAt = r.i64()
  r.done()
  if (!status) throw new Error('unknown status byte')
  if (objectionByte > 2) throw new Error('unknown objection byte')
  const objection = objectionByte === 0 ? null : SIDES[objectionByte - 1]
  const outcome = status === 'ended' ? OUTCOME[outcomeByte] : null
  if (status === 'ended' && !outcome) throw new Error('unknown outcome byte')
  return {
    version,
    id,
    buyer,
    seller,
    arbiter: arbiter.equals(PublicKey.default) ? null : arbiter,
    mint,
    vault,
    rentRecipient,
    amount,
    creator,
    timer: timerDays === 0 ? null : { days: timerDays, to: timerTo },
    createdAt,
    fundedAt: fundedAt === 0n ? null : fundedAt,
    status,
    bump,
    endedAt: endedAt === 0n ? null : endedAt,
    outcome,
    toSeller,
    toBuyer,
    payer,
    objection,
    objectedAt: objection === null ? null : objectedAt,
  }
}

// ---------------------------------------------------------------------------------------------
// Events, from the `Program data:` lines in a transaction's log.
// ---------------------------------------------------------------------------------------------

export type EscrowEvent =
  | {
      kind: 'created'
      escrow: PublicKey
      version: number
      id: bigint
      buyer: PublicKey
      seller: PublicKey
      creator: Side
      arbiter: PublicKey | null
      mint: PublicKey
      vault: PublicKey
      rentRecipient: PublicKey
      amount: bigint
      timer: Timer | null
      createdAt: bigint
      /** The key that fronted the rent. */
      payer: PublicKey
    }
  | { kind: 'funded'; escrow: PublicKey; balance: bigint; fundedAt: bigint }
  | {
      kind: 'ended'
      escrow: PublicKey
      outcome: Outcome
      amount: bigint
      balance: bigint
      toSeller: bigint
      toBuyer: bigint
      endedAt: bigint
      rentRecipient: PublicKey
      /** The deposit account's rent, returned to the payer. The escrow account's stays in the receipt. */
      rentLamports: bigint
      /** The mark's time, or `endedAt` when nobody marked it. */
      fundedAt: bigint
    }
  | { kind: 'closed'; escrow: PublicKey; closedBy: PublicKey; toBuyer: bigint; rentRecipient: PublicKey; rentLamports: bigint }
  /** Money that came after the end went back to the buyer's refund address; the deposit account's rent to the buyer. */
  | { kind: 'recoveredLate'; escrow: PublicKey; toBuyer: bigint; rentLamports: bigint }
  /** Lamports above the minimum went to the payer; `left` is the minimum kept. */
  | { kind: 'rentSwept'; escrow: PublicKey; payer: PublicKey; lamports: bigint; left: bigint }
  /** A party objected; from then on the timer never runs. */
  | { kind: 'objected'; escrow: PublicKey; by: Side; objectedAt: bigint }

const EVENT_NAMES: [string, EscrowEvent['kind']][] = [
  ['Created', 'created'],
  ['Funded', 'funded'],
  ['Ended', 'ended'],
  ['Closed', 'closed'],
  ['RecoveredLate', 'recoveredLate'],
  ['RentSwept', 'rentSwept'],
  ['Objected', 'objected'],
]

export function decodeEvent(bytes: Uint8Array): EscrowEvent | null {
  if (bytes.length < 8) return null
  const found = EVENT_NAMES.find(([name]) => discriminator('event', name).every((v, i) => bytes[i] === v))
  if (!found) return null
  const kind = found[1]
  const r = new Reader(bytes.subarray(8))
  const escrow = r.key()
  let event: EscrowEvent
  switch (kind) {
    case 'created': {
      const version = r.u8()
      const id = r.u64()
      const buyer = r.key()
      const seller = r.key()
      const creator = r.side()
      const arbiter = r.key()
      const mint = r.key()
      const vault = r.key()
      const rentRecipient = r.key()
      const amount = r.u64()
      const timerDays = r.u16()
      const timerTo = r.side()
      const createdAt = r.i64()
      const payer = r.key()
      event = {
        kind,
        escrow,
        version,
        id,
        buyer,
        seller,
        creator,
        arbiter: arbiter.equals(PublicKey.default) ? null : arbiter,
        mint,
        vault,
        rentRecipient,
        amount,
        timer: timerDays === 0 ? null : { days: timerDays, to: timerTo },
        createdAt,
        payer,
      }
      break
    }
    case 'funded':
      event = { kind, escrow, balance: r.u64(), fundedAt: r.i64() }
      break
    case 'ended': {
      const outcome = OUTCOME[r.u8()]
      if (!outcome) throw new Error('unknown outcome byte')
      event = {
        kind,
        escrow,
        outcome,
        amount: r.u64(),
        balance: r.u64(),
        toSeller: r.u64(),
        toBuyer: r.u64(),
        endedAt: r.i64(),
        rentRecipient: r.key(),
        rentLamports: r.u64(),
        fundedAt: r.i64(),
      }
      break
    }
    case 'closed':
      event = { kind, escrow, closedBy: r.key(), toBuyer: r.u64(), rentRecipient: r.key(), rentLamports: r.u64() }
      break
    case 'recoveredLate':
      event = { kind, escrow, toBuyer: r.u64(), rentLamports: r.u64() }
      break
    case 'rentSwept':
      event = { kind, escrow, payer: r.key(), lamports: r.u64(), left: r.u64() }
      break
    case 'objected':
      event = { kind, escrow, by: r.side(), objectedAt: r.i64() }
      break
  }
  r.done()
  return event
}

/**
 * The `Program data:` payloads that `programId` itself wrote, in order. Any program can write a
 * data line holding an escrow event's exact bytes, so the bytes alone prove nothing. What does is
 * the runtime's own `Program <id> invoke [n]` and `Program <id> success` or `failed` lines, which
 * no program can forge (a program's own output always starts `Program log:` or `Program data:`):
 * a data line belongs to whichever program is innermost at that point.
 */
export function programDataLines(logs: string[], programId: PublicKey = PROGRAM_ID): string[] {
  const id = programId.toBase58()
  const running: string[] = []
  const out: string[] = []
  for (const line of logs) {
    const invoked = /^Program (\S+) invoke \[\d+\]$/.exec(line)
    if (invoked) {
      running.push(invoked[1])
      continue
    }
    if (/^Program \S+ (success$|failed)/.test(line)) {
      running.pop()
      continue
    }
    if (line.startsWith('Program data: ') && running[running.length - 1] === id) {
      out.push(line.slice('Program data: '.length))
    }
  }
  return out
}

/** Every event the escrow program wrote in a transaction's log lines, in order. */
export function decodeEvents(logs: string[], programId: PublicKey = PROGRAM_ID): EscrowEvent[] {
  const out: EscrowEvent[] = []
  for (const payload of programDataLines(logs, programId)) {
    const event = decodeEvent(new Uint8Array(Buffer.from(payload, 'base64')))
    if (event) out.push(event)
  }
  return out
}
