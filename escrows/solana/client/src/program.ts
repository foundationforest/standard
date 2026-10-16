// The wire format of the escrow: addresses, discriminators, instruction bytes, the account
// layout and the event layouts.
//
// Everything here is fixed with the program, which cannot change once deployed to Solana's mainnet.
// These bytes are what clients and indexes read and write forever, so this file is written out by hand rather than generated: a reader can check it
// against `escrows/solana/program/src/lib.rs` line by line, and the Rust tests encode the same
// bytes independently, so a drift on either side fails a test. An escrow of v2 or v1, earlier
// programs no longer in this repo, is read with that program's own client, in this repo's git
// history.

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

export const PROGRAM_ID = new PublicKey('FoRE3EscrowV3scheduLeWindowsPayRefund3333333')
/** The classic SPL Token program. */
export const TOKEN_PROGRAM_ID = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')
/** Token-2022. The escrow takes a mint of either; every instruction names the one that owns it. */
export const TOKEN_2022_PROGRAM_ID = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb')
export const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL')
/** Wrapped SOL: a classic SPL Token mint that `create` refuses by name. */
export const NATIVE_MINT = new PublicKey('So11111111111111111111111111111111111111112')
/** Token-2022's wrapped SOL, refused the same way. */
export const NATIVE_MINT_2022 = new PublicKey('9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP')

/** Written into every escrow: which program's rules it follows. */
export const VERSION = 3
/** One hundred percent. */
export const BPS = 10_000
/** The most windows a schedule holds. */
export const MAX_WINDOWS = 4
/** The escrow account's bytes after Anchor's eight-byte discriminator. */
export const ESCROW_LEN = 304
export const ESCROW_SEED = new TextEncoder().encode('escrow')

/** One of the two parties. */
export type Side = 'payer' | 'recipient'
const SIDES: Side[] = ['payer', 'recipient']

/** The default from the end time on: everything to the recipient, or back to the payer. */
export type End = 'pay' | 'refund'
const ENDS: End[] = ['pay', 'refund']

/**
 * One window: from the `until` before it (the first, from the opening) up to, not including, its
 * own `until`, in unix seconds, the payer may take back `payerShare` basis points alone.
 */
export type Window = { until: bigint; payerShare: number }

/** A schedule: one to four windows, each `until` later than the one before, and the default. */
export type Schedule = { windows: Window[]; end: End }

/** What `create` carries, besides the payer, whose key is passed beside it. Every option is off unless set. */
export type Terms = {
  /** Tells apart two deals with the same terms. `randomId()` picks one. */
  id: bigint
  recipient: PublicKey
  /** In the mint's base units: what the deal is for, and what funds it. */
  amount: bigint
  /** null: no arbiter. Any key but the zero key and the two parties' otherwise. */
  arbiter: PublicKey | null
  /** null: no schedule, so no take-back and no default. */
  schedule: Schedule | null
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
function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, true)
  return b
}
function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigUint64(0, BigInt.asUintN(64, n), true)
  return b
}
function i64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8)
  new DataView(b.buffer).setBigInt64(0, BigInt.asIntN(64, n), true)
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
  end(): End {
    const e = ENDS[this.u8()]
    if (!e) throw new Error('unknown end byte')
    return e
  }
  /** The window count, four windows, then the default: a schedule, or null when the count is 0. */
  schedule(): Schedule | null {
    const count = this.u8()
    const windows: Window[] = []
    for (let i = 0; i < MAX_WINDOWS; i++) windows.push({ until: this.i64(), payerShare: this.u16() })
    const end = this.end()
    if (count > MAX_WINDOWS) throw new Error(`a schedule of ${count} windows`)
    if (windows.slice(count).some((w) => w.until !== 0n || w.payerShare !== 0)) throw new Error('a window past the count is not zero')
    if (count === 0) {
      if (end !== 'pay') throw new Error('no schedule is stored as pay')
      return null
    }
    return { windows: windows.slice(0, count), end }
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
export type AllTerms = { payer: PublicKey; mint: PublicKey; terms: Terms }

/** The schedule as the account stores it and the address hashes it: the count, four windows (zeros past the count), the default. */
function scheduleBytes(schedule: Schedule | null): Uint8Array {
  const windows = schedule?.windows ?? []
  const parts: Uint8Array[] = [u8(windows.length)]
  for (let i = 0; i < MAX_WINDOWS; i++) {
    const w = windows[i] ?? { until: 0n, payerShare: 0 }
    parts.push(i64le(w.until), u16le(w.payerShare))
  }
  parts.push(u8(ENDS.indexOf(schedule?.end ?? 'pay')))
  return concat(parts)
}

/**
 * The seed of an escrow's address: SHA-256 of all its terms, each at a fixed length, in the
 * receipt's order. id (8 bytes, little-endian), payer, recipient, arbiter (the zero key for none),
 * mint (32 each), amount (8, little-endian), the window count (1), four windows (`until` 8 and
 * `payerShare` 2, little-endian; zeros past the count), the default (1: pay 0, refund 1; pay when
 * there is no schedule): 186 bytes.
 */
export function termsHash(all: AllTerms): Uint8Array {
  const { payer, mint, terms } = all
  return sha256(
    concat([
      u64le(terms.id),
      payer.toBytes(),
      terms.recipient.toBytes(),
      (terms.arbiter ?? PublicKey.default).toBytes(),
      mint.toBytes(),
      u64le(terms.amount),
      scheduleBytes(terms.schedule),
    ]),
  )
}

/**
 * The escrow's address: `["escrow", termsHash]`. Every term is in it, so a payment sent to it
 * counts only toward a deal with exactly those terms. Who opens it is not a term: the payer and
 * the recipient land at the same address with the same terms, and only they can open it.
 */
export function escrowAddress(all: AllTerms, programId: PublicKey = PROGRAM_ID): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from(ESCROW_SEED), Buffer.from(termsHash(all))], programId)[0]
}

/** An escrow's terms, as read off the chain. */
export function termsOf(account: Pick<EscrowAccount, 'id' | 'payer' | 'recipient' | 'mint' | 'amount' | 'arbiter' | 'schedule'>): AllTerms {
  const { id, recipient, amount, arbiter, schedule } = account
  return { payer: account.payer, mint: account.mint, terms: { id, recipient, amount, arbiter, schedule } }
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
 * `escrows/solana/security-checklist.md` lists each, with the test that pins it.
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
 * The payer's standard token account for the mint, computed from two keys fixed at creation.
 * Every payout to the payer lands here and nowhere else. It has to exist only when the payer is
 * paid something; `makeStandardAccountIx` makes it first in the same transaction when it might not.
 */
export function payerAccount(payer: PublicKey, mint: PublicKey, tokenProgram: PublicKey = TOKEN_PROGRAM_ID): PublicKey {
  return associatedTokenAddress(payer, mint, tokenProgram)
}

/**
 * The recipient's standard token account for the mint. Every payout to the recipient lands here
 * and nowhere else, the same rule as the payer's.
 */
export function recipientAccount(recipient: PublicKey, mint: PublicKey, tokenProgram: PublicKey = TOKEN_PROGRAM_ID): PublicKey {
  return associatedTokenAddress(recipient, mint, tokenProgram)
}

/**
 * Make `owner`'s standard token account for `mint` if it is missing, and do nothing if it is
 * there: the associated token program's idempotent create, `funder` paying its rent, under the
 * mint's token program, which gives the account whatever extensions the mint requires. The
 * account, and its rent, are the owner's from then on.
 */
export function makeStandardAccountIx(args: { funder: PublicKey; owner: PublicKey; mint: PublicKey; tokenProgram?: PublicKey }): TransactionInstruction {
  const tokenProgram = args.tokenProgram ?? TOKEN_PROGRAM_ID
  return new TransactionInstruction({
    programId: ASSOCIATED_TOKEN_PROGRAM_ID,
    keys: [
      rw(args.funder, true),
      rw(associatedTokenAddress(args.owner, args.mint, tokenProgram)),
      ro(args.owner),
      ro(args.mint),
      ro(SystemProgram.programId),
      ro(tokenProgram),
    ],
    data: Buffer.from([1]),
  })
}

/**
 * The deposit address, made if missing, `sponsor` paying its rent: the first instruction of every
 * transaction that funds an escrow. `create` adopts it. Made at the top of the transaction by the
 * associated token program, not inside `create`, so a fee payer that checks every transfer's
 * destination before it signs finds the deposit address already made.
 */
export function makeDepositAddressIx(args: { sponsor: PublicKey; escrow: PublicKey; mint: PublicKey; tokenProgram?: PublicKey }): TransactionInstruction {
  return makeStandardAccountIx({ funder: args.sponsor, owner: args.escrow, mint: args.mint, tokenProgram: args.tokenProgram })
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
    destination: side === 'payer' ? payerAccount(keys.payer, keys.mint, keys.tokenProgram) : recipientAccount(keys.recipient, keys.mint, keys.tokenProgram),
  }))
}

/**
 * A schedule's own rules, as `create` checks them: one to four windows, each `until` a whole
 * number of seconds that fits a 64-bit signed time and later than the one before, each share a
 * whole number from 0 to 10,000, the default pay or refund. Throws with the program's own error
 * name. Nothing here compares a window with the clock: the app shows the dates before anyone pays.
 */
export function validateSchedule(schedule: Schedule): void {
  const { windows, end } = schedule
  if (!Array.isArray(windows) || windows.length === 0) throw new Error('ScheduleEmpty: a schedule has at least one window')
  if (windows.length > MAX_WINDOWS) throw new Error(`TooManyWindows: a schedule has at most ${MAX_WINDOWS} windows`)
  for (const w of windows) {
    if (typeof w.until !== 'bigint' || w.until < -(1n << 63n) || w.until >= 1n << 63n) throw new RangeError('a window\'s until is a 64-bit signed unix time')
    if (!Number.isInteger(w.payerShare) || w.payerShare < 0 || w.payerShare > BPS) throw new Error(`BadShare: ${w.payerShare} is not 0..=10,000 basis points`)
  }
  for (let i = 1; i < windows.length; i++) {
    if (windows[i - 1].until >= windows[i].until) throw new Error('WindowsOutOfOrder: each window\'s until must be later than the one before')
  }
  if (!ENDS.includes(end)) throw new Error(`a schedule ends "pay" or "refund", not ${String(end)}`)
}

/**
 * The checks `create` makes, made here first so a bad set of terms fails before a transaction is
 * built. Throws with the program's own error name.
 */
export function validateTerms(terms: Terms, payer: PublicKey): void {
  if (terms.recipient.equals(payer)) throw new Error('SameParty: the payer and the recipient must be different keys')
  if (payer.equals(PublicKey.default)) throw new Error('EmptyKey: the payer cannot be the zero key')
  if (terms.recipient.equals(PublicKey.default)) throw new Error('EmptyKey: the recipient cannot be the zero key')
  if (terms.arbiter && terms.arbiter.equals(PublicKey.default)) throw new Error('EmptyKey: the arbiter cannot be the zero key')
  if (terms.arbiter && (terms.arbiter.equals(payer) || terms.arbiter.equals(terms.recipient))) {
    throw new Error('ArbiterIsAParty: the arbiter cannot be the payer or the recipient')
  }
  if (terms.amount <= 0n) throw new Error('AmountZero: the amount must be above zero')
  if (terms.amount >= 1n << 64n) throw new RangeError('the amount does not fit in 64 bits')
  if (terms.schedule) validateSchedule(terms.schedule)
}

/**
 * id u64, payer, recipient, amount u64, arbiter as an `Option` (0, or 1 then the key), schedule as
 * an `Option` (0, or 1 then the windows as a vector, a u32 count then each `until` i64 and
 * `payerShare` u16, then the default as one byte: pay 0, refund 1).
 */
export function createArgsBytes(terms: Terms, payer: PublicKey): Uint8Array {
  const schedule = terms.schedule
    ? concat([u8(1), u32le(terms.schedule.windows.length), ...terms.schedule.windows.flatMap((w) => [i64le(w.until), u16le(w.payerShare)]), u8(ENDS.indexOf(terms.schedule.end))])
    : u8(0)
  return concat([
    u64le(terms.id),
    payer.toBytes(),
    terms.recipient.toBytes(),
    u64le(terms.amount),
    terms.arbiter ? concat([u8(1), terms.arbiter.toBytes()]) : u8(0),
    schedule,
  ])
}

const ro = (pubkey: PublicKey, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: false })
const rw = (pubkey: PublicKey, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: true })

/**
 * `create`. The creator signs: the payer (the default), or the recipient, invoicing (`invoiceIx`).
 * The escrow's address comes from the terms (`escrowAddress`); who signs as creator does not change
 * it. The sponsor signs and fronts both rents, and is recorded: every rent goes back to it. The
 * terms are checked against the program's rules (`validateTerms`, and neither party the escrow
 * itself or its deposit address) before anything is built.
 */
export function createIx(args: {
  payer: PublicKey
  sponsor: PublicKey
  mint: PublicKey
  terms: Terms
  /** Who signs as creator: the payer, unless the recipient is invoicing. */
  creator?: PublicKey
  /** The program that owns the mint (`tokenOf`); the classic one unless named. */
  tokenProgram?: PublicKey
  programId?: PublicKey
}): TransactionInstruction {
  const programId = args.programId ?? PROGRAM_ID
  const tokenProgram = args.tokenProgram ?? TOKEN_PROGRAM_ID
  const creator = args.creator ?? args.payer
  validateTerms(args.terms, args.payer)
  if (!creator.equals(args.payer) && !creator.equals(args.terms.recipient)) {
    throw new Error('NotAParty: the payer or the recipient opens an escrow')
  }
  if (args.mint.equals(NATIVE_MINT) || args.mint.equals(NATIVE_MINT_2022)) throw new Error('NativeMint: wrapped SOL is not accepted')
  const escrow = escrowAddress({ payer: args.payer, mint: args.mint, terms: args.terms }, programId)
  const vault = vaultAddress(escrow, args.mint, tokenProgram)
  for (const party of [args.payer, args.terms.recipient]) {
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
      rw(args.sponsor, true),
      ro(args.mint),
      ro(tokenProgram),
      ro(ASSOCIATED_TOKEN_PROGRAM_ID),
      ro(SystemProgram.programId),
    ],
    data: concat([discriminator('global', 'create'), createArgsBytes(args.terms, args.payer)]),
  })
}

/** `create` by the recipient: an invoice naming the payer. */
export function invoiceIx(args: {
  recipient: PublicKey
  payer: PublicKey
  sponsor: PublicKey
  mint: PublicKey
  terms: Terms
  tokenProgram?: PublicKey
  programId?: PublicKey
}): TransactionInstruction {
  if (!args.terms.recipient.equals(args.recipient)) throw new Error('an invoice names its own recipient in the terms')
  return createIx({ ...args, creator: args.recipient })
}

/**
 * `mark_funded`: anyone, with no signature, once, while the deposit account holds the amount and
 * before the schedule's end time. It records the time and nothing else; `end` pays only a marked
 * escrow, so the side the default favours marks any payment it sees in time, and every builder
 * here that funds an escrow it leaves live marks in the same transaction.
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
 * parties, the mint, the token program that owns it, and the sponsor, who gets every rent back.
 * `keysOf` reads them from an escrow account off the chain, with the mint's owner, which the escrow
 * does not store (`tokenOf`); `keysFor` computes them from terms, for an escrow created in the same
 * transaction.
 */
export type EscrowKeys = {
  escrow: PublicKey
  vault: PublicKey
  payer: PublicKey
  recipient: PublicKey
  mint: PublicKey
  tokenProgram: PublicKey
  sponsor: PublicKey
}

export function keysOf(account: EscrowAccount, opts: { tokenProgram?: PublicKey; programId?: PublicKey } = {}): EscrowKeys {
  const escrow = escrowAddress(termsOf(account), opts.programId ?? PROGRAM_ID)
  const tokenProgram = opts.tokenProgram ?? TOKEN_PROGRAM_ID
  if (!account.vault.equals(vaultAddress(escrow, account.mint, tokenProgram))) {
    throw new Error("the escrow's deposit account is not under that token program: name the program that owns the mint")
  }
  return { escrow, vault: account.vault, payer: account.payer, recipient: account.recipient, mint: account.mint, tokenProgram, sponsor: account.sponsor }
}

export function keysFor(args: { payer: PublicKey; sponsor: PublicKey; mint: PublicKey; terms: Terms; tokenProgram?: PublicKey; programId?: PublicKey }): EscrowKeys {
  const tokenProgram = args.tokenProgram ?? TOKEN_PROGRAM_ID
  const escrow = escrowAddress({ payer: args.payer, mint: args.mint, terms: args.terms }, args.programId)
  return { escrow, vault: vaultAddress(escrow, args.mint, tokenProgram), payer: args.payer, recipient: args.terms.recipient, mint: args.mint, tokenProgram, sponsor: args.sponsor }
}

/** Hook accounts, as the escrow takes them: after its own, and never signing. */
function forwarded(hookAccounts: AccountMeta[] | undefined): AccountMeta[] {
  return (hookAccounts ?? []).map((m) => ({ pubkey: m.pubkey, isSigner: false, isWritable: m.isWritable }))
}

function checkShare(payerShare: number): void {
  if (!Number.isInteger(payerShare) || payerShare < 0 || payerShare > BPS) {
    throw new RangeError(`BadShare: ${payerShare} is not 0..=10,000 basis points`)
  }
}

/**
 * `pay`: the payer signs; the whole balance to the recipient's standard account, which must exist
 * (`makeStandardAccountIx` first if the recipient may not hold the token yet). In every live state,
 * a stop included. Names no payer account: the payer is paid nothing. Every way out takes
 * `hookAccounts` (`hookAccounts` with `payoutTransfers`) after its own: needed only for a mint
 * whose transfer hook names a program.
 */
export function payIx(args: { keys: EscrowKeys; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  const k = args.keys
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [
      rw(k.escrow),
      rw(k.vault),
      ro(k.mint),
      rw(recipientAccount(k.recipient, k.mint, k.tokenProgram)),
      rw(k.sponsor),
      ro(k.tokenProgram),
      ro(k.payer, true),
      ...forwarded(args.hookAccounts),
    ],
    data: concat([discriminator('global', 'pay')]),
  })
}

/**
 * `refund`: the recipient signs; the whole balance back to the payer's standard account. In every
 * live state, a stop included. Names no recipient account: the recipient is paid nothing.
 */
export function refundIx(args: { keys: EscrowKeys; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  const k = args.keys
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [
      rw(k.escrow),
      rw(k.vault),
      ro(k.mint),
      rw(payerAccount(k.payer, k.mint, k.tokenProgram)),
      rw(k.sponsor),
      ro(k.tokenProgram),
      ro(k.recipient, true),
      ...forwarded(args.hookAccounts),
    ],
    data: concat([discriminator('global', 'refund')]),
  })
}

function bothAccounts(k: EscrowKeys): AccountMeta[] {
  return [
    rw(k.escrow),
    rw(k.vault),
    ro(k.mint),
    rw(payerAccount(k.payer, k.mint, k.tokenProgram)),
    rw(recipientAccount(k.recipient, k.mint, k.tokenProgram)),
    rw(k.sponsor),
    ro(k.tokenProgram),
  ]
}

/**
 * `take_back`: the payer signs; inside a window whose share is above 0, nobody having stopped,
 * that share of the whole balance to the payer, rounded down, the rest to the recipient
 * (`windowAt`, `canTakeBack`). The share is the window's, so the instruction carries none. Each
 * side's standard account must exist if its share is above zero.
 */
export function takeBackIx(args: { keys: EscrowKeys; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  const k = args.keys
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [...bothAccounts(k), ro(k.payer, true), ...forwarded(args.hookAccounts)],
    data: concat([discriminator('global', 'take_back')]),
  })
}

/**
 * `agree`: both sign; `payerShare` of the whole balance to the payer, rounded down, the rest to the
 * recipient. In every live state, a stop included. Each side's standard account must exist if its
 * share is above zero.
 */
export function agreeIx(args: { keys: EscrowKeys; payerShare: number; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  checkShare(args.payerShare)
  const k = args.keys
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [...bothAccounts(k), ro(k.payer, true), ro(k.recipient, true), ...forwarded(args.hookAccounts)],
    data: concat([discriminator('global', 'agree'), u16le(args.payerShare)]),
  })
}

/** `decide`: the arbiter named at creation signs any split, stated as the payer's share, the same way both parties can. */
export function decideIx(args: { keys: EscrowKeys; arbiter: PublicKey; payerShare: number; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  checkShare(args.payerShare)
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [...bothAccounts(args.keys), ro(args.arbiter, true), ...forwarded(args.hookAccounts)],
    data: concat([discriminator('global', 'decide'), u16le(args.payerShare)]),
  })
}

/**
 * `end`: anyone, from the end time on (`canEnd`), if the funding was marked before it and nobody
 * stopped; the whole balance to the side the schedule's default names, at that side's standard
 * account. Built only from the escrow account as read from the chain, since the account it pays
 * depends on the default, and refused here where the program would refuse it, but for the time,
 * which only the chain's clock decides.
 */
export function endIx(args: { account: EscrowAccount; tokenProgram?: PublicKey; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  const programId = args.programId ?? PROGRAM_ID
  const a = args.account
  if (a.status === 'ended') throw new Error('Ended: this escrow has ended')
  if (!a.schedule) throw new Error('NoSchedule: this escrow has no schedule')
  if (a.stop) throw new Error('Stopped: a party stopped this escrow; the schedule is off')
  if (a.status !== 'funded') throw new Error('FundingNotMarked: nobody marked the funding before the end time')
  const k = keysOf(a, { tokenProgram: args.tokenProgram, programId })
  const to = a.schedule.end === 'refund' ? payerAccount(k.payer, k.mint, k.tokenProgram) : recipientAccount(k.recipient, k.mint, k.tokenProgram)
  return new TransactionInstruction({
    programId,
    keys: [rw(k.escrow), rw(k.vault), ro(k.mint), rw(to), rw(k.sponsor), ro(k.tokenProgram), ...forwarded(args.hookAccounts)],
    data: concat([discriminator('global', 'end')]),
  })
}

/**
 * `close_unfunded`: by the payer or the recipient, an escrow that holds less than the amount, at
 * any time, or, from the end time on, one nobody marked and nobody stopped. Whatever it holds goes
 * back to the payer's standard account (which must exist only if it holds something); both
 * accounts close; both rents go to the sponsor; no receipt is kept.
 */
export function closeUnfundedIx(args: { keys: EscrowKeys; closer: PublicKey; hookAccounts?: AccountMeta[]; programId?: PublicKey }): TransactionInstruction {
  const k = args.keys
  if (!args.closer.equals(k.payer) && !args.closer.equals(k.recipient)) {
    throw new Error('NotAParty: only the payer or the recipient can close an escrow')
  }
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [
      rw(k.escrow),
      rw(k.vault),
      ro(k.mint),
      rw(payerAccount(k.payer, k.mint, k.tokenProgram)),
      rw(k.sponsor),
      ro(k.tokenProgram),
      ro(args.closer, true),
      ...forwarded(args.hookAccounts),
    ],
    data: concat([discriminator('global', 'close_unfunded')]),
  })
}

/**
 * `recover_late`: anyone, on an escrow that has ended. Whatever a later payment left at its deposit
 * address goes to the payer's standard account (made first at `caller`'s cost if it does not
 * exist); the deposit account closes again and its rent goes to the payer. The receipt does not
 * change. Built only from the escrow account as read from the chain.
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
      rw(a.payer),
      rw(payerAccount(a.payer, a.mint, k.tokenProgram)),
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
 * minimum goes to the sponsor recorded at creation, the key that fronted the rent; the account
 * keeps exactly the minimum and its bytes. Nobody signs but the transaction's fee payer.
 */
export function sweepRentIx(args: { escrow: PublicKey; sponsor: PublicKey; programId?: PublicKey }): TransactionInstruction {
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [rw(args.escrow), rw(args.sponsor)],
    data: concat([discriminator('global', 'sweep_rent')]),
  })
}

/**
 * `stop`: the payer or the recipient, once per escrow, while it is live and before its end time
 * (`canStop`). It moves no money; from then on neither `take_back` nor `end` runs, and the money
 * moves only by a side giving, both agreeing, or the arbiter if one was named. Built only from the
 * escrow account as read from the chain, and refused here where the program would refuse it, but
 * for the time, which only the chain's clock decides.
 */
export function stopIx(args: { account: EscrowAccount; party: PublicKey; programId?: PublicKey }): TransactionInstruction {
  const programId = args.programId ?? PROGRAM_ID
  const a = args.account
  if (a.status === 'ended') throw new Error('Ended: this escrow has ended')
  if (!args.party.equals(a.payer) && !args.party.equals(a.recipient)) throw new Error('NotAParty: only the payer or the recipient can stop an escrow')
  if (a.stop) throw new Error('AlreadyStopped: an escrow takes one stop')
  return new TransactionInstruction({
    programId,
    keys: [rw(escrowAddress(termsOf(a), programId)), ro(args.party, true)],
    data: concat([discriminator('global', 'stop')]),
  })
}

/**
 * What a hook needs for each transfer of a one-tap: the payment in, and the payment out. Resolve
 * each with `hookAccounts` (the payment in with the deposit address as a `PlannedAccount`, since
 * the same transaction makes it).
 */
export type OneTapHookAccounts = { fund?: AccountMeta[]; pay?: AccountMeta[] }

/**
 * Open, fund and mark in one transaction, the escrow left live to run its schedule: the deposit
 * address made first (`makeDepositAddressIx`, the sponsor paying), the payer's `create`, a
 * `transfer_checked` of the amount into the deposit account, and `mark_funded`. The payer signs,
 * with the sponsor. Since the mark is refused from the end time on, a funding sent after it fails
 * whole and moves no money. The payer pays from its standard account unless `from` names another
 * it holds. `token` is `tokenOf` the mint.
 */
export function createAndFund(args: {
  payer: PublicKey
  sponsor: PublicKey
  token: Token
  terms: Terms
  from?: PublicKey
  hookAccounts?: OneTapHookAccounts
  programId?: PublicKey
}): TransactionInstruction[] {
  const { mint, program: tokenProgram } = args.token
  const keys = keysFor({ ...args, mint, tokenProgram })
  return [...createAndTransfer(args), markFundedIx({ escrow: keys.escrow, vault: keys.vault, programId: args.programId })]
}

/** The deposit address made, `create`, and the payment in: what `createAndFund` and `payInOneTap` share. */
function createAndTransfer(args: Parameters<typeof createAndFund>[0]): TransactionInstruction[] {
  const { mint, program: tokenProgram, decimals } = args.token
  const keys = keysFor({ ...args, mint, tokenProgram })
  return [
    makeDepositAddressIx({ sponsor: args.sponsor, escrow: keys.escrow, mint, tokenProgram }),
    createIx({ ...args, mint, tokenProgram }),
    transferIx({
      from: args.from ?? associatedTokenAddress(args.payer, mint, tokenProgram),
      to: keys.vault,
      owner: args.payer,
      mint,
      amount: args.terms.amount,
      decimals,
      tokenProgram,
      hookAccounts: args.hookAccounts?.fund,
    }),
  ]
}

/**
 * Pay in one tap: the deposit address made, `create`, the payment in, then `pay`, for one
 * transaction the payer signs (with the sponsor). No mark: `pay` needs none. Put
 * `makeStandardAccountIx` for the recipient first if the recipient may not hold the token yet: the
 * recipient is paid only at its standard account.
 */
export function payInOneTap(args: Parameters<typeof createAndFund>[0]): TransactionInstruction[] {
  const keys = keysFor({ ...args, mint: args.token.mint, tokenProgram: args.token.program })
  return [...createAndTransfer(args), payIx({ keys, hookAccounts: args.hookAccounts?.pay, programId: args.programId })]
}

/**
 * The deposit address made first and the payment of the whole amount into an invoice: what both
 * invoice builders share. The recipient opened the escrow; `escrow` is it as read off the chain
 * (`decodeEscrow`), after the payer's app has checked it (`assertOptionsAgreed`, the schedule's
 * dates, and that it names the payer's own key as payer). It sends the whole amount, so it is for
 * an invoice nothing has been paid into yet: read the deposit address's balance first (`funds`),
 * since every way out pays out the whole balance.
 */
function payIntoInvoice(args: { escrow: EscrowAccount; sponsor: PublicKey; token: Token; from?: PublicKey; hookAccounts?: OneTapHookAccounts; programId?: PublicKey }): { keys: EscrowKeys; ixs: TransactionInstruction[] } {
  const e = args.escrow
  if (e.status !== 'open') {
    throw new Error(`this escrow is ${e.status === 'ended' ? 'ended' : 'already funded'}: nothing to pay`)
  }
  if (!args.token.mint.equals(e.mint)) throw new Error("the token is not the escrow's mint")
  const keys = keysOf(e, { tokenProgram: args.token.program, programId: args.programId })
  return {
    keys,
    ixs: [
      makeDepositAddressIx({ sponsor: args.sponsor, escrow: keys.escrow, mint: keys.mint, tokenProgram: keys.tokenProgram }),
      transferIx({
        from: args.from ?? associatedTokenAddress(keys.payer, keys.mint, keys.tokenProgram),
        to: keys.vault,
        owner: keys.payer,
        mint: keys.mint,
        amount: e.amount,
        decimals: args.token.decimals,
        tokenProgram: keys.tokenProgram,
        hookAccounts: args.hookAccounts?.fund,
      }),
    ],
  }
}

/**
 * Fund an invoice and leave it live to run its schedule: the deposit address made first, the
 * payment of the amount, and `mark_funded`, for one transaction the payer signs (with the sponsor).
 * After the invoice's end time the mark is refused, so the whole transaction fails and no money
 * moves. The deposit address is made at the top so a fee payer that checks every transfer's
 * destination before it signs finds it made.
 */
export function fundInvoice(args: { escrow: EscrowAccount; sponsor: PublicKey; token: Token; from?: PublicKey; hookAccounts?: OneTapHookAccounts; programId?: PublicKey }): TransactionInstruction[] {
  const { keys, ixs } = payIntoInvoice(args)
  return [...ixs, markFundedIx({ escrow: keys.escrow, vault: keys.vault, programId: args.programId })]
}

/**
 * Pay an invoice in one tap: the deposit address made first, the payment of the amount, and `pay`,
 * for one transaction the payer signs (with the sponsor). No mark: `pay` needs none. Put
 * `makeStandardAccountIx` for the recipient first if the recipient may not hold the token yet.
 */
export function payInvoiceInOneTap(args: { escrow: EscrowAccount; sponsor: PublicKey; token: Token; from?: PublicKey; hookAccounts?: OneTapHookAccounts; programId?: PublicKey }): TransactionInstruction[] {
  const { keys, ixs } = payIntoInvoice(args)
  return [...ixs, payIx({ keys, hookAccounts: args.hookAccounts?.pay, programId: args.programId })]
}

// ---------------------------------------------------------------------------------------------
// The account.
// ---------------------------------------------------------------------------------------------

/** open: created, the funding not marked. funded: marked. ended: paid out; the receipt. A stop is not a status: see `stop`. */
export type Status = 'open' | 'funded' | 'ended'
const STATUS: Status[] = ['open', 'funded', 'ended']

/** The move that ended an escrow. */
export type Outcome = 'pay' | 'refund' | 'takeBack' | 'agree' | 'decide' | 'end'
const OUTCOME: Outcome[] = ['pay', 'refund', 'takeBack', 'agree', 'decide', 'end']

export type EscrowAccount = {
  version: number
  id: bigint
  payer: PublicKey
  recipient: PublicKey
  /** null when none was named. */
  arbiter: PublicKey | null
  mint: PublicKey
  vault: PublicKey
  /** The key that fronted the rent: every rent goes back to it. */
  sponsor: PublicKey
  amount: bigint
  /** Who opened it: the recipient, for an invoice. Not a term: it does not change the address. */
  creator: Side
  /** null when none was set. */
  schedule: Schedule | null
  createdAt: bigint
  /** When the money was there: the mark's time, or the ending's if nobody marked it; null before either. */
  fundedAt: bigint | null
  status: Status
  bump: number
  /** When it ended, or null. */
  endedAt: bigint | null
  /** The move that ended it, or null while it has not. */
  outcome: Outcome | null
  /** What each party was paid at the end; 0 before. */
  toPayer: bigint
  toRecipient: bigint
  /** Which party stopped it, or null. Once one has, neither take_back nor end runs. */
  stop: Side | null
  /** When the stop was made, or null. */
  stoppedAt: bigint | null
}

/**
 * version 0, id 1..9, payer 9..41, recipient 41..73, arbiter 73..105, mint 105..137,
 * vault 137..169, sponsor 169..201, amount 201..209, creator 209, window count 210,
 * windows 211..251 (each: until 8, payerShare 2), end 251, created_at 252..260,
 * funded_at 260..268, status 268, bump 269, ended_at 270..278, outcome 278, to_payer 279..287,
 * to_recipient 287..295, stop 295 (none 0, the payer 1, the recipient 2), stopped_at 296..304.
 */
export function decodeEscrow(data: Uint8Array): EscrowAccount {
  if (data.length !== 8 + ESCROW_LEN) throw new Error(`an escrow account is ${8 + ESCROW_LEN} bytes, not ${data.length}`)
  const want = discriminator('account', 'Escrow')
  if (!want.every((v, i) => data[i] === v)) throw new Error('not an escrow account')
  const r = new Reader(data.subarray(8))
  const version = r.u8()
  const id = r.u64()
  const payer = r.key()
  const recipient = r.key()
  const arbiter = r.key()
  const mint = r.key()
  const vault = r.key()
  const sponsor = r.key()
  const amount = r.u64()
  const creator = r.side()
  const schedule = r.schedule()
  const createdAt = r.i64()
  const fundedAt = r.i64()
  const status = STATUS[r.u8()]
  const bump = r.u8()
  const endedAt = r.i64()
  const outcomeByte = r.u8()
  const toPayer = r.u64()
  const toRecipient = r.u64()
  const stopByte = r.u8()
  const stoppedAt = r.i64()
  r.done()
  if (!status) throw new Error('unknown status byte')
  if (stopByte > 2) throw new Error('unknown stop byte')
  const stop = stopByte === 0 ? null : SIDES[stopByte - 1]
  const outcome = status === 'ended' ? OUTCOME[outcomeByte] : null
  if (status === 'ended' && !outcome) throw new Error('unknown outcome byte')
  return {
    version,
    id,
    payer,
    recipient,
    arbiter: arbiter.equals(PublicKey.default) ? null : arbiter,
    mint,
    vault,
    sponsor,
    amount,
    creator,
    schedule,
    createdAt,
    fundedAt: fundedAt === 0n ? null : fundedAt,
    status,
    bump,
    endedAt: endedAt === 0n ? null : endedAt,
    outcome,
    toPayer,
    toRecipient,
    stop,
    stoppedAt: stop === null ? null : stoppedAt,
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
      payer: PublicKey
      recipient: PublicKey
      creator: Side
      arbiter: PublicKey | null
      mint: PublicKey
      vault: PublicKey
      /** The key that fronted the rent. */
      sponsor: PublicKey
      amount: bigint
      schedule: Schedule | null
      createdAt: bigint
    }
  | { kind: 'funded'; escrow: PublicKey; balance: bigint; fundedAt: bigint }
  /** A party stopped the escrow; from then on neither take_back nor end runs. */
  | { kind: 'stopped'; escrow: PublicKey; by: Side; stoppedAt: bigint }
  | {
      kind: 'ended'
      escrow: PublicKey
      /** The move that ended it. */
      outcome: Outcome
      amount: bigint
      balance: bigint
      toPayer: bigint
      toRecipient: bigint
      endedAt: bigint
      sponsor: PublicKey
      /** The deposit account's rent, returned to the sponsor. The escrow account's stays in the receipt. */
      rentLamports: bigint
      /** The mark's time, or `endedAt` when nobody marked it. */
      fundedAt: bigint
    }
  /** Closed without a receipt: it never held the amount, or its schedule ended before anyone marked it. */
  | { kind: 'closed'; escrow: PublicKey; closedBy: PublicKey; toPayer: bigint; sponsor: PublicKey; rentLamports: bigint }
  /** Money that came after the end went back to the payer's standard account; the deposit account's rent to the payer. */
  | { kind: 'recoveredLate'; escrow: PublicKey; toPayer: bigint; rentLamports: bigint }
  /** Lamports above the minimum went to the sponsor; `left` is the minimum kept. */
  | { kind: 'rentSwept'; escrow: PublicKey; sponsor: PublicKey; lamports: bigint; left: bigint }

const EVENT_NAMES: [string, EscrowEvent['kind']][] = [
  ['Created', 'created'],
  ['Funded', 'funded'],
  ['Stopped', 'stopped'],
  ['Ended', 'ended'],
  ['Closed', 'closed'],
  ['RecoveredLate', 'recoveredLate'],
  ['RentSwept', 'rentSwept'],
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
      const payer = r.key()
      const recipient = r.key()
      const creator = r.side()
      const arbiter = r.key()
      const mint = r.key()
      const vault = r.key()
      const sponsor = r.key()
      const amount = r.u64()
      const schedule = r.schedule()
      const createdAt = r.i64()
      event = {
        kind,
        escrow,
        version,
        id,
        payer,
        recipient,
        creator,
        arbiter: arbiter.equals(PublicKey.default) ? null : arbiter,
        mint,
        vault,
        sponsor,
        amount,
        schedule,
        createdAt,
      }
      break
    }
    case 'funded':
      event = { kind, escrow, balance: r.u64(), fundedAt: r.i64() }
      break
    case 'stopped':
      event = { kind, escrow, by: r.side(), stoppedAt: r.i64() }
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
        toPayer: r.u64(),
        toRecipient: r.u64(),
        endedAt: r.i64(),
        sponsor: r.key(),
        rentLamports: r.u64(),
        fundedAt: r.i64(),
      }
      break
    }
    case 'closed':
      event = { kind, escrow, closedBy: r.key(), toPayer: r.u64(), sponsor: r.key(), rentLamports: r.u64() }
      break
    case 'recoveredLate':
      event = { kind, escrow, toPayer: r.u64(), rentLamports: r.u64() }
      break
    case 'rentSwept':
      event = { kind, escrow, sponsor: r.key(), lamports: r.u64(), left: r.u64() }
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
