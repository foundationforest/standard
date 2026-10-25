// What the v3 client computes, with no chain: the bytes it writes, the bytes it reads back, the
// options check, the schedule's windows and deadlines. The LiteSVM tests write the same bytes by
// hand in Rust, and the devnet run sends these through the deployed program; if either side
// drifted, one of them fails.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { getAssociatedTokenAddressSync } from '@solana/spl-token'
import { Keypair, PublicKey } from '@solana/web3.js'

import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  BPS,
  ESCROW_LEN,
  MAX_WINDOWS,
  NATIVE_MINT,
  NATIVE_MINT_2022,
  PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  VERSION,
  agreeIx,
  assertOptionsAgreed,
  associatedTokenAddress,
  canEnd,
  canMark,
  canStop,
  canTakeBack,
  closeUnfundedIx,
  createAndFund,
  createArgsBytes,
  createIx,
  decideIx,
  decodeEscrow,
  decodeEvent,
  decodeEvents,
  discriminator,
  endIx,
  endTime,
  escrowAddress,
  fundInvoice,
  funds,
  hookAccounts,
  invoiceIx,
  keysFor,
  keysOf,
  makeDepositAddressIx,
  makeStandardAccountIx,
  markFundedIx,
  optionsFromPost,
  optionsNotAgreed,
  payerAccount,
  payInOneTap,
  payInvoiceInOneTap,
  payIx,
  payoutTransfers,
  randomId,
  recipientAccount,
  recoverLateIx,
  refundIx,
  share,
  split,
  stopIx,
  sweepRentIx,
  takeBackIx,
  termsFor,
  termsHash,
  termsOf,
  tokenOf,
  transferIx,
  validateTerms,
  depositAddress,
  windowAt,
  type EscrowAccount,
  type Schedule,
  type Terms,
} from '../src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
const DAY = 86_400n
const T0 = 1_800_000_000n

const payer = Keypair.generate().publicKey
const recipient = Keypair.generate().publicKey
const arbiter = Keypair.generate().publicKey
const mint = Keypair.generate().publicKey
const sponsor = Keypair.generate().publicKey
const stranger = Keypair.generate().publicKey

/** Two windows: all back until a day in, half until two days in, then the default pays the recipient. */
const twoWindows: Schedule = { windows: [{ until: T0 + DAY, payerShare: 10_000 }, { until: T0 + 2n * DAY, payerShare: 5_000 }], end: 'pay' }

/** The address of the standard terms: the payer's, 1.00, every option off. */
function baseEscrow(): PublicKey {
  return escrowAddress({ payer, mint, terms: terms() })
}

/**
 * An escrow account as `decodeEscrow` would return it: the payer's, open, unfunded, every option
 * off. Its deposit account is that of its own terms' address, unless named.
 */
function escrowAccount(over: Partial<EscrowAccount> = {}): EscrowAccount {
  const e: EscrowAccount = {
    version: VERSION,
    id: 7n,
    payer,
    recipient,
    arbiter: null,
    mint,
    vault: PublicKey.default,
    sponsor,
    amount: 1_000_000n,
    creator: 'payer',
    schedule: null,
    createdAt: T0,
    fundedAt: null,
    status: 'open',
    bump: 255,
    endedAt: null,
    outcome: null,
    toPayer: 0n,
    toRecipient: 0n,
    stop: null,
    stoppedAt: null,
    ...over,
  }
  return over.vault ? e : { ...e, vault: depositAddress(escrowAddress(termsOf(e)), e.mint) }
}

/** The same, opened by the recipient: an invoice, at the same address as the same terms the payer opens. */
function invoiceAccount(over: Partial<EscrowAccount> = {}): EscrowAccount {
  return escrowAccount({ creator: 'recipient', ...over })
}

function terms(over: Partial<Terms> = {}): Terms {
  return { id: 7n, recipient, amount: 1_000_000n, arbiter: null, schedule: null, ...over }
}

const meta = (ix: { keys: { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }[] }) =>
  ix.keys.map((k) => [k.pubkey.toBase58(), k.isSigner, k.isWritable])

test('the program id, the seed and the sizes are the ones the program bakes in', () => {
  const lib = readFileSync(join(here, '../../program/src/lib.rs'), 'utf8')
  const state = readFileSync(join(here, '../../program/src/state.rs'), 'utf8')
  assert.ok(lib.includes(`declare_id!("${PROGRAM_ID.toBase58()}")`))
  assert.ok(lib.includes(`pub const VERSION: u8 = ${VERSION};`))
  assert.ok(lib.includes('pub const ESCROW_SEED: &[u8] = b"escrow";'))
  assert.ok(lib.includes(`pub const NATIVE_MINT: Pubkey = pubkey!("${NATIVE_MINT.toBase58()}");`))
  assert.ok(lib.includes(`assert!(Escrow::LEN == ${ESCROW_LEN});`))
  assert.ok(lib.includes(`assert!(MAX_WINDOWS == ${MAX_WINDOWS});`))
  assert.ok(state.includes('pub const BPS: u16 = 10_000;'))
  assert.ok(state.includes('pub until: i64,') && state.includes('pub payer_share: u16,'), 'a window is a signed time and sixteen bits of share')
  assert.equal(BPS, 10_000)
})

test('the discriminators are pinned', () => {
  const ixs: Record<string, string> = {
    create: '181ec828051c0777',
    mark_funded: '9a19863dc8b81d38',
    pay: '7712d841c0757adc',
    refund: '0260b7fb3fd02e2e',
    take_back: '63ffb785991e0c20',
    stop: '2a85203cabfdb89b',
    agree: 'd24a26e1bfd12265',
    decide: '7b7db87df92b710f',
    end: 'b4a0f9d9c2794610',
    close_unfunded: '06d9705bfa5c6746',
    recover_late: '525629b57534cce3',
    sweep_rent: '11ea3af1fb9487b9',
  }
  for (const [name, want] of Object.entries(ixs)) assert.equal(hex(discriminator('global', name)), want, name)
  const events: Record<string, string> = {
    Created: '41fe44f56694f44c',
    Funded: '43543858c00cc9b1',
    Stopped: '401b21a42351e76d',
    Ended: '467b96d69c092dc5',
    Closed: '321f579b87dcc3ef',
    RecoveredLate: 'bd249dc10194f8ce',
    RentSwept: 'cb5605b151a70c19',
  }
  for (const [name, want] of Object.entries(events)) assert.equal(hex(discriminator('event', name)), want, name)
  assert.equal(hex(discriminator('account', 'Escrow')), '1fd57bbbba16da9b')
})

test('the deposit address is the standard associated token account of the escrow', () => {
  const escrow = baseEscrow()
  assert.ok(!PublicKey.isOnCurve(escrow.toBytes()), 'a program-derived address')
  const vault = depositAddress(escrow, mint)
  assert.deepEqual(vault, getAssociatedTokenAddressSync(mint, escrow, true, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID))
  assert.deepEqual(payerAccount(payer, mint), getAssociatedTokenAddressSync(mint, payer, false, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID))
  assert.deepEqual(recipientAccount(recipient, mint), getAssociatedTokenAddressSync(mint, recipient, false, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID))
  // Random ids are 64 bits and do not repeat.
  const ids = new Set(Array.from({ length: 100 }, () => randomId()))
  assert.equal(ids.size, 100)
  for (const id of ids) assert.ok(id >= 0n && id < 1n << 64n)
})

test('the address is a hash of every term, the bytes the program hashes', () => {
  // The same vector as the program's harness (`the_address_of_fixed_terms_is_the_clients`).
  const key = (b: number) => new PublicKey(new Uint8Array(32).fill(b))
  const schedule: Schedule = { windows: [{ until: 1_800_000_000n, payerShare: 10_000 }, { until: 1_800_604_800n, payerShare: 2_500 }], end: 'refund' }
  const fixed = { payer: key(1), mint: key(3), terms: { id: 7n, recipient: key(2), amount: 1_000_000n, arbiter: key(4), schedule } }
  assert.equal(hex(termsHash(fixed)), 'a760919547aa835383ec68fb8e789c2466386d7fafd9849faaf5fdfa97eeec04')
  assert.equal(escrowAddress(fixed).toBase58(), 'BrkprqAdZVPaEd6ygGrGeHtcPbzsyKRz9UhvJtHnPdoV')

  // Change any one term and the address moves.
  const all = { payer, mint, terms: terms({ arbiter, schedule: twoWindows }) }
  const at = escrowAddress(all)
  const t = all.terms
  const w = twoWindows.windows
  const variants: [string, typeof all][] = [
    ['the id', { ...all, terms: { ...t, id: 8n } }],
    ['the payer', { ...all, payer: stranger }],
    ['the recipient', { ...all, terms: { ...t, recipient: stranger } }],
    ['the amount', { ...all, terms: { ...t, amount: 1_000_001n } }],
    ['the mint', { ...all, mint: stranger }],
    ['the arbiter', { ...all, terms: { ...t, arbiter: stranger } }],
    ['no arbiter', { ...all, terms: { ...t, arbiter: null } }],
    ["a window's until", { ...all, terms: { ...t, schedule: { ...twoWindows, windows: [{ ...w[0], until: w[0].until + 1n }, w[1]] } } }],
    ["a window's share", { ...all, terms: { ...t, schedule: { ...twoWindows, windows: [{ ...w[0], payerShare: 9_999 }, w[1]] } } }],
    ['one window fewer', { ...all, terms: { ...t, schedule: { ...twoWindows, windows: [w[1]] } } }],
    ['the default', { ...all, terms: { ...t, schedule: { ...twoWindows, end: 'refund' } } }],
    ['no schedule', { ...all, terms: { ...t, schedule: null } }],
  ]
  for (const [what, v] of variants) assert.notDeepEqual(escrowAddress(v), at, what)
  // Read back off the chain, an escrow's terms give its own address.
  assert.deepEqual(escrowAddress(termsOf(escrowAccount({ arbiter, schedule: twoWindows }))), at)
})

test('create carries exactly the bytes the program reads', () => {
  const t = terms({ arbiter, schedule: twoWindows })
  const bytes = createArgsBytes(t, payer)
  // id 8, payer 32, recipient 32, amount 8, arbiter 1+32, schedule 1 + 4 + 2 × (8 + 2) + 1.
  assert.equal(bytes.length, 8 + 32 + 32 + 8 + 33 + 1 + 4 + 20 + 1)
  const v = new DataView(bytes.buffer, bytes.byteOffset)
  assert.equal(v.getBigUint64(0, true), 7n)
  assert.deepEqual(new PublicKey(bytes.subarray(8, 40)), payer)
  assert.deepEqual(new PublicKey(bytes.subarray(40, 72)), recipient)
  assert.equal(v.getBigUint64(72, true), 1_000_000n)
  assert.equal(bytes[80], 1)
  assert.deepEqual(new PublicKey(bytes.subarray(81, 113)), arbiter)
  assert.equal(bytes[113], 1, 'a schedule')
  assert.equal(v.getUint32(114, true), 2, 'two windows, as a vector')
  assert.deepEqual([v.getBigInt64(118, true), v.getUint16(126, true)], [T0 + DAY, 10_000])
  assert.deepEqual([v.getBigInt64(128, true), v.getUint16(136, true)], [T0 + 2n * DAY, 5_000])
  assert.equal(bytes[138], 0, 'pay is 0')
  assert.equal(createArgsBytes(terms({ schedule: { ...twoWindows, end: 'refund' } }), payer).at(-1), 1, 'refund is 1')
  // A time before 1970 is a negative i64.
  const before1970 = createArgsBytes(terms({ schedule: { windows: [{ until: -1n, payerShare: 0 }], end: 'pay' } }), payer)
  assert.equal(new DataView(before1970.buffer, before1970.byteOffset).getBigInt64(86, true), -1n)

  // Every option off: one byte each.
  const bare = createArgsBytes(terms(), payer)
  assert.equal(bare.length, 8 + 32 + 32 + 8 + 1 + 1)
  assert.deepEqual([bare[80], bare[81]], [0, 0])

  const ix = createIx({ payer, sponsor, mint, terms: t })
  assert.deepEqual(ix.programId, PROGRAM_ID)
  assert.equal(hex(ix.data.subarray(0, 8)), '181ec828051c0777')
  assert.equal(hex(ix.data.subarray(8)), hex(bytes))
  const escrow = escrowAddress({ payer, mint, terms: t })
  assert.deepEqual(meta(ix), [
    [escrow.toBase58(), false, true],
    [depositAddress(escrow, mint).toBase58(), false, true],
    [payer.toBase58(), true, false],
    [sponsor.toBase58(), true, true],
    [mint.toBase58(), false, false],
    [TOKEN_PROGRAM_ID.toBase58(), false, false],
    [ASSOCIATED_TOKEN_PROGRAM_ID.toBase58(), false, false],
    ['11111111111111111111111111111111', false, false],
  ])

  // An invoice: the same bytes, with the recipient in the creator's slot, at the same address.
  const inv = invoiceIx({ recipient, payer, sponsor, mint, terms: t })
  assert.equal(hex(inv.data), hex(ix.data))
  assert.deepEqual(inv.keys[0].pubkey, escrow)
  assert.deepEqual(inv.keys[1].pubkey, depositAddress(escrow, mint))
  assert.deepEqual([inv.keys[2].pubkey.toBase58(), inv.keys[2].isSigner], [recipient.toBase58(), true])
  assert.throws(() => createIx({ payer, sponsor, mint, terms: t, creator: arbiter }), /NotAParty/)
  assert.throws(() => createIx({ payer, sponsor, mint: NATIVE_MINT, terms: t }), /NativeMint/)
  assert.throws(() => invoiceIx({ recipient: arbiter, payer, sponsor, mint, terms: t }), /its own recipient/)
  assert.throws(() => createIx({ payer, sponsor, mint, terms: terms({ arbiter: recipient }) }), /ArbiterIsAParty/)
  assert.throws(() => invoiceIx({ recipient, payer, sponsor, mint, terms: terms({ arbiter: payer }) }), /ArbiterIsAParty/)
})

test("bad terms fail before a transaction is built, with the program's own error names", () => {
  const sched = (windows: { until: bigint; payerShare: number }[], end: 'pay' | 'refund' = 'pay') => terms({ schedule: { windows, end } })
  const cases: [string, Terms, PublicKey, RegExp][] = [
    ['payer is recipient', terms({ recipient: payer }), payer, /SameParty/],
    ['zero payer', terms(), PublicKey.default, /EmptyKey/],
    ['zero recipient', terms({ recipient: PublicKey.default }), payer, /EmptyKey/],
    ['zero arbiter', terms({ arbiter: PublicKey.default }), payer, /EmptyKey/],
    ['the payer as arbiter', terms({ arbiter: payer }), payer, /ArbiterIsAParty/],
    ['the recipient as arbiter', terms({ arbiter: recipient }), payer, /ArbiterIsAParty/],
    ['amount zero', terms({ amount: 0n }), payer, /AmountZero/],
    ['an amount over 64 bits', terms({ amount: 1n << 64n }), payer, /64 bits/],
    ['no windows', sched([]), payer, /ScheduleEmpty/],
    ['five windows', sched([1n, 2n, 3n, 4n, 5n].map((d) => ({ until: T0 + d * DAY, payerShare: 0 }))), payer, /TooManyWindows/],
    ['a share of 10,001', sched([{ until: T0, payerShare: 10_001 }]), payer, /BadShare/],
    ['a share of a half', sched([{ until: T0, payerShare: 0.5 }]), payer, /BadShare/],
    ['a negative share', sched([{ until: T0, payerShare: -1 }]), payer, /BadShare/],
    ['two windows ending together', sched([{ until: T0, payerShare: 10_000 }, { until: T0, payerShare: 0 }]), payer, /WindowsOutOfOrder/],
    ['windows out of order', sched([{ until: T0 + DAY, payerShare: 10_000 }, { until: T0, payerShare: 0 }]), payer, /WindowsOutOfOrder/],
    ['a time past 64 bits', sched([{ until: 1n << 63n, payerShare: 0 }]), payer, /64-bit/],
    ['a default that is neither', terms({ schedule: { windows: [{ until: T0, payerShare: 0 }], end: 'release' as 'pay' } }), payer, /"pay" or "refund"/],
  ]
  for (const [what, t, p, want] of cases) assert.throws(() => validateTerms(t, p), want, what)
  // A third key as arbiter, four windows at the widest times, and a schedule already past, are fine.
  const widest = [
    { until: -(1n << 63n), payerShare: 10_000 },
    { until: -1n, payerShare: 5_000 },
    { until: T0, payerShare: 1 },
    { until: (1n << 63n) - 1n, payerShare: 0 },
  ]
  validateTerms(terms({ arbiter, schedule: { windows: widest, end: 'refund' } }), payer)
  validateTerms(sched([{ until: 0n, payerShare: 0 }]), payer)
})

test('each move names the accounts it pays and the keys that sign it', () => {
  const account = escrowAccount({ arbiter, schedule: twoWindows })
  const k = keysOf(account)
  const escrow = escrowAddress({ payer, mint, terms: terms({ arbiter, schedule: twoWindows }) })
  assert.deepEqual(k, { escrow, vault: depositAddress(escrow, mint), payer, recipient, mint, tokenProgram: TOKEN_PROGRAM_ID, sponsor })
  assert.deepEqual(keysFor({ payer, sponsor, mint, terms: terms({ arbiter, schedule: twoWindows }) }), k, 'from the terms, the same keys')
  // An invoice of the same terms: the same keys.
  assert.deepEqual(keysOf(invoiceAccount({ arbiter, schedule: twoWindows })), k)
  const payers = payerAccount(payer, mint).toBase58()
  const recipients = recipientAccount(recipient, mint).toBase58()
  const head = [
    [escrow.toBase58(), false, true],
    [depositAddress(escrow, mint).toBase58(), false, true],
    [mint.toBase58(), false, false],
  ]
  // Every rent back to the sponsor.
  const tail = [
    [sponsor.toBase58(), false, true],
    [TOKEN_PROGRAM_ID.toBase58(), false, false],
  ]

  const pay = payIx({ keys: k })
  assert.equal(hex(pay.data), '7712d841c0757adc')
  assert.deepEqual(meta(pay), [...head, [recipients, false, true], ...tail, [payer.toBase58(), true, false]], 'the recipient paid at its standard account')

  const refund = refundIx({ keys: k })
  assert.equal(hex(refund.data), '0260b7fb3fd02e2e')
  assert.deepEqual(meta(refund), [...head, [payers, false, true], ...tail, [recipient.toBase58(), true, false]])

  const takeBack = takeBackIx({ keys: k })
  assert.equal(hex(takeBack.data), '63ffb785991e0c20', 'the discriminator, and no share: it is the window\'s')
  assert.deepEqual(meta(takeBack), [...head, [payers, false, true], [recipients, false, true], ...tail, [payer.toBase58(), true, false]])

  const agree = agreeIx({ keys: k, payerShare: 7_000 })
  assert.equal(hex(agree.data), 'd24a26e1bfd12265' + '581b')
  assert.deepEqual(meta(agree), [...head, [payers, false, true], [recipients, false, true], ...tail, [payer.toBase58(), true, false], [recipient.toBase58(), true, false]])

  const decide = decideIx({ keys: k, arbiter, payerShare: 2_500 })
  assert.equal(hex(decide.data), '7b7db87df92b710f' + 'c409')
  assert.deepEqual(meta(decide), [...head, [payers, false, true], [recipients, false, true], ...tail, [arbiter.toBase58(), true, false]])
  for (const bps of [-1, 10_001, 1.5]) {
    assert.throws(() => agreeIx({ keys: k, payerShare: bps }), /BadShare/)
    assert.throws(() => decideIx({ keys: k, arbiter, payerShare: bps }), /BadShare/)
  }

  const close = closeUnfundedIx({ keys: k, closer: recipient })
  assert.equal(hex(close.data), '06d9705bfa5c6746')
  assert.deepEqual(meta(close), [...head, [payers, false, true], ...tail, [recipient.toBase58(), true, false]])
  assert.deepEqual(meta(closeUnfundedIx({ keys: k, closer: payer })).at(-1), [payer.toBase58(), true, false], 'the payer closing')
  for (const closer of [sponsor, arbiter, stranger]) assert.throws(() => closeUnfundedIx({ keys: k, closer }), /NotAParty/)

  const mark = markFundedIx({ escrow, vault: k.vault })
  assert.equal(hex(mark.data), '9a19863dc8b81d38')
  assert.deepEqual(meta(mark), [[escrow.toBase58(), false, true], [k.vault.toBase58(), false, false]], 'no signer: anyone marks')
  // The sweep pays the sponsor recorded at creation, not the creator.
  assert.deepEqual(meta(sweepRentIx({ escrow, sponsor })), [[escrow.toBase58(), false, true], [sponsor.toBase58(), false, true]])
})

test('a stop: the escrow and the party who signs, refused here where the program would refuse it', () => {
  const account = escrowAccount({ status: 'funded', fundedAt: T0, schedule: twoWindows })
  const escrow = escrowAddress(termsOf(account))
  for (const party of [payer, recipient]) {
    const ix = stopIx({ account, party })
    assert.deepEqual(ix.programId, PROGRAM_ID)
    assert.equal(hex(ix.data), '2a85203cabfdb89b', 'the discriminator, and no arguments')
    assert.deepEqual(meta(ix), [[escrow.toBase58(), false, true], [party.toBase58(), true, false]])
  }
  // An invoice's stop names the escrow at its terms' address, the same as the payer's.
  assert.deepEqual(stopIx({ account: invoiceAccount(), party: payer }).keys[0].pubkey, baseEscrow())
  for (const party of [arbiter, sponsor, stranger]) assert.throws(() => stopIx({ account, party }), /NotAParty/)
  assert.throws(() => stopIx({ account: escrowAccount({ stop: 'payer', stoppedAt: T0 }), party: recipient }), /AlreadyStopped/)
  assert.throws(() => stopIx({ account: escrowAccount({ status: 'ended', outcome: 'agree' }), party: payer }), /Ended/)

  // Until when: before the end time, never at or after it; any time with no schedule.
  const end = T0 + 2n * DAY
  assert.equal(canStop(account, end - 1n), true)
  assert.equal(canStop(account, end), false)
  assert.equal(canStop(escrowAccount(), T0 + 10_000n * DAY), true, 'no schedule')
  assert.equal(canStop(escrowAccount({ schedule: twoWindows }), end - 1n), true, 'marked or not')
  assert.equal(canStop(escrowAccount({ schedule: twoWindows, stop: 'recipient', stoppedAt: T0 }), T0), false, 'once per escrow')
  assert.equal(canStop(escrowAccount({ status: 'ended', outcome: 'pay' }), T0), false, 'ended')
})

test('the default pays the side the schedule names, and its builder refuses what the program would', () => {
  const marked = { status: 'funded' as const, fundedAt: T0 }
  const account = escrowAccount({ ...marked, schedule: twoWindows })
  const k = keysOf(account)
  const toRecipient = endIx({ account })
  assert.equal(hex(toRecipient.data), 'b4a0f9d9c2794610')
  assert.deepEqual(
    meta(toRecipient),
    [
      [k.escrow.toBase58(), false, true],
      [k.vault.toBase58(), false, true],
      [mint.toBase58(), false, false],
      [recipientAccount(recipient, mint).toBase58(), false, true],
      [sponsor.toBase58(), false, true],
      [TOKEN_PROGRAM_ID.toBase58(), false, false],
    ],
    'no signer: anyone may send it; the recipient paid at its standard account',
  )
  const toPayer = endIx({ account: escrowAccount({ ...marked, schedule: { ...twoWindows, end: 'refund' } }) })
  assert.deepEqual(toPayer.keys[3].pubkey, payerAccount(payer, mint))
  // An invoice's default: its terms' address, its rent back to the sponsor.
  const invAccount = invoiceAccount({ ...marked, schedule: twoWindows })
  const inv = endIx({ account: invAccount })
  assert.deepEqual([inv.keys[0].pubkey, inv.keys[3].pubkey, inv.keys[4].pubkey], [escrowAddress(termsOf(invAccount)), recipientAccount(recipient, mint), sponsor])
  assert.throws(() => endIx({ account: escrowAccount(marked) }), /NoSchedule/)
  assert.throws(() => endIx({ account: escrowAccount({ schedule: twoWindows }) }), /FundingNotMarked/)
  assert.throws(() => endIx({ account: escrowAccount({ status: 'ended', schedule: twoWindows }) }), /Ended/)
  assert.throws(() => endIx({ account: escrowAccount({ ...marked, schedule: twoWindows, stop: 'payer', stoppedAt: T0 }) }), /Stopped/)

  // From the end time on, to the second; only marked; never after a stop.
  assert.equal(endTime(account), T0 + 2n * DAY)
  assert.equal(endTime(escrowAccount()), null)
  assert.equal(canEnd(account, T0 + 2n * DAY - 1n), false)
  assert.equal(canEnd(account, T0 + 2n * DAY), true)
  assert.equal(canEnd(escrowAccount({ schedule: twoWindows }), T0 + 10n * DAY), false, 'never marked')
  assert.equal(canEnd(escrowAccount({ ...marked, schedule: twoWindows, stop: 'recipient', stoppedAt: T0 }), T0 + 10n * DAY), false, 'stopped')
  assert.equal(canEnd(escrowAccount(marked), T0 + 10n * DAY), false, 'no schedule')
})

test('the window in force, and when a take-back or a mark lands', () => {
  const three: Schedule = { windows: [...twoWindows.windows, { until: T0 + 3n * DAY, payerShare: 0 }], end: 'pay' }
  const e = escrowAccount({ status: 'funded', fundedAt: T0, schedule: three })
  // The first window whose until is still ahead: until itself is not included.
  assert.deepEqual(windowAt(e, T0), three.windows[0])
  assert.deepEqual(windowAt(e, T0 + DAY - 1n), three.windows[0])
  assert.deepEqual(windowAt(e, T0 + DAY), three.windows[1])
  assert.deepEqual(windowAt(e, T0 + 3n * DAY - 1n), three.windows[2])
  assert.equal(windowAt(e, T0 + 3n * DAY), null, 'from the end time on, no window')
  assert.equal(windowAt(escrowAccount(), T0), null, 'no schedule')
  // A take-back: a window whose share is above 0, a stop or not.
  assert.equal(canTakeBack(e, T0), true)
  assert.equal(canTakeBack(e, T0 + 2n * DAY - 1n), true)
  assert.equal(canTakeBack(e, T0 + 2n * DAY), false, 'a share of 0: that is pay')
  assert.equal(canTakeBack(e, T0 + 3n * DAY), false, 'past the end')
  assert.equal(canTakeBack({ ...e, stop: 'recipient' }, T0), true, 'a stop leaves the take-back to its windows')
  assert.equal(canTakeBack({ ...e, status: 'ended' }, T0), false, 'ended')
  // A mark: once, before the end time; any time with no schedule.
  const open = escrowAccount({ schedule: three })
  assert.equal(canMark(open, T0 + 3n * DAY - 1n), true)
  assert.equal(canMark(open, T0 + 3n * DAY), false)
  assert.equal(canMark(e, T0), false, 'already marked')
  assert.equal(canMark(escrowAccount(), T0 + 10_000n * DAY), true, 'no schedule')
})

test('pay in one tap, fund with the mark, and an invoice either way: the deposit address made first, a transfer_checked of the amount, then pay or the mark', () => {
  const t = terms({ schedule: twoWindows })
  const token = { mint, program: TOKEN_PROGRAM_ID, decimals: 6 }
  const k = keysFor({ payer, sponsor, mint, terms: t })
  const ixs = payInOneTap({ payer, sponsor, token, terms: t })
  assert.equal(ixs.length, 4)
  const [deposit, create, transfer, pay] = ixs
  // The deposit address, made by the associated token program at the top of the transaction, the
  // sponsor paying: a fee payer that checks every transfer's destination finds it made.
  assert.deepEqual(deposit.programId, ASSOCIATED_TOKEN_PROGRAM_ID)
  assert.equal(hex(deposit.data), '01', 'the idempotent create')
  assert.deepEqual(meta(deposit), [
    [sponsor.toBase58(), true, true],
    [k.vault.toBase58(), false, true],
    [k.escrow.toBase58(), false, false],
    [mint.toBase58(), false, false],
    ['11111111111111111111111111111111', false, false],
    [TOKEN_PROGRAM_ID.toBase58(), false, false],
  ])
  assert.deepEqual(meta(deposit), meta(makeDepositAddressIx({ sponsor, escrow: k.escrow, mint })))
  assert.equal(hex(create.data), hex(createIx({ payer, sponsor, mint, terms: t }).data))
  assert.deepEqual(meta(create), meta(createIx({ payer, sponsor, mint, terms: t })))
  // transfer_checked: 12, the amount, the decimals; source, mint, destination, owner.
  assert.deepEqual(transfer.programId, TOKEN_PROGRAM_ID)
  assert.equal(hex(transfer.data), '0c' + '40420f0000000000' + '06')
  assert.deepEqual(meta(transfer), [
    [associatedTokenAddress(payer, mint).toBase58(), false, true],
    [mint.toBase58(), false, false],
    [k.vault.toBase58(), false, true],
    [payer.toBase58(), true, false],
  ])
  assert.deepEqual(meta(pay), meta(payIx({ keys: k })))
  const from = Keypair.generate().publicKey
  assert.deepEqual(payInOneTap({ payer, sponsor, token, terms: t, from })[2].keys[0].pubkey, from)

  // Funding left live to run its schedule: the same first three, then the mark, so a funding sent
  // after the end time fails whole.
  const funded = createAndFund({ payer, sponsor, token, terms: t })
  assert.equal(funded.length, 4)
  assert.deepEqual(funded.slice(0, 3).map(meta), ixs.slice(0, 3).map(meta))
  assert.deepEqual(meta(funded[3]), meta(markFundedIx({ escrow: k.escrow, vault: k.vault })))
  assert.deepEqual(createAndFund({ payer, sponsor, token, terms: t, from })[2].keys[0].pubkey, from)

  // An invoice: the recipient opened it, so no create; the deposit address made first all the
  // same, then the transfer of the amount, then pay, or the mark.
  const inv = invoiceAccount({ schedule: twoWindows })
  const invKeys = keysOf(inv)
  assert.deepEqual(invKeys.escrow, k.escrow, 'an invoice of the same terms is at the same address')
  const paid = payInvoiceInOneTap({ escrow: inv, sponsor, token })
  assert.equal(paid.length, 3)
  const [invDeposit, invTransfer, invPay] = paid
  assert.deepEqual(meta(invDeposit), meta(makeDepositAddressIx({ sponsor, escrow: invKeys.escrow, mint })))
  assert.equal(hex(invDeposit.data), '01', 'the idempotent create')
  assert.deepEqual(invTransfer.programId, TOKEN_PROGRAM_ID)
  assert.equal(hex(invTransfer.data), '0c' + '40420f0000000000' + '06')
  assert.deepEqual(meta(invTransfer), [
    [associatedTokenAddress(payer, mint).toBase58(), false, true],
    [mint.toBase58(), false, false],
    [depositAddress(invKeys.escrow, mint).toBase58(), false, true],
    [payer.toBase58(), true, false],
  ])
  assert.deepEqual(meta(invPay), meta(payIx({ keys: invKeys })))
  assert.deepEqual(meta(invPay)[4], [sponsor.toBase58(), false, true], 'the rent back to the sponsor, not the recipient who opened it')
  const kept = fundInvoice({ escrow: inv, sponsor, token })
  assert.deepEqual(kept.slice(0, 2).map(meta), paid.slice(0, 2).map(meta))
  assert.deepEqual(meta(kept[2]), meta(markFundedIx({ escrow: invKeys.escrow, vault: invKeys.vault })))
  assert.deepEqual(payInvoiceInOneTap({ escrow: inv, sponsor, token, from })[1].keys[0].pubkey, from)
  for (const build of [payInvoiceInOneTap, fundInvoice]) {
    assert.throws(() => build({ escrow: { ...inv, status: 'funded' }, sponsor, token }), /already funded/)
    assert.throws(() => build({ escrow: { ...inv, status: 'ended' }, sponsor, token }), /ended/)
    assert.throws(() => build({ escrow: inv, sponsor, token: { ...token, mint: stranger } }), /not the escrow's mint/)
  }

  // A party's standard account, made when a way out pays it.
  const make = makeStandardAccountIx({ funder: sponsor, owner: payer, mint })
  assert.deepEqual(make.programId, ASSOCIATED_TOKEN_PROGRAM_ID)
  assert.deepEqual(make.keys[1].pubkey, payerAccount(payer, mint))
  assert.equal(hex(make.data), '01')
})

test('late money and the rent sweep: their accounts, and what the builders refuse', () => {
  const ended = escrowAccount({ status: 'ended', outcome: 'pay', endedAt: T0 })
  const ix = recoverLateIx({ account: ended, caller: stranger })
  assert.equal(hex(ix.data), '525629b57534cce3')
  const escrow = baseEscrow()
  assert.deepEqual(meta(ix), [
    [escrow.toBase58(), false, false],
    [ended.vault.toBase58(), false, true],
    [payer.toBase58(), false, true],
    [payerAccount(payer, mint).toBase58(), false, true],
    [mint.toBase58(), false, false],
    [stranger.toBase58(), true, true],
    [TOKEN_PROGRAM_ID.toBase58(), false, false],
    [ASSOCIATED_TOKEN_PROGRAM_ID.toBase58(), false, false],
    ['11111111111111111111111111111111', false, false],
  ])
  assert.throws(() => recoverLateIx({ account: escrowAccount(), caller: stranger }), /NotEnded/)
  // An invoice's late money: the same address, still back to the payer.
  const late = recoverLateIx({ account: invoiceAccount({ status: 'ended', outcome: 'pay', endedAt: T0 }), caller: stranger })
  assert.deepEqual([late.keys[0].pubkey, late.keys[2].pubkey, late.keys[3].pubkey], [baseEscrow(), payer, payerAccount(payer, mint)])
})

/** An escrow account's bytes, at the pinned offsets. */
function escrowBytes(o: {
  arbiter?: PublicKey
  sponsor?: PublicKey
  creator?: number
  count?: number
  windows?: [bigint, number][]
  end?: number
  fundedAt?: bigint
  status?: number
  endedAt?: bigint
  outcome?: number
  toPayer?: bigint
  toRecipient?: bigint
  stop?: number
  stoppedAt?: bigint
  schedule?: Schedule
} = {}): Uint8Array {
  const data = Buffer.alloc(8 + ESCROW_LEN)
  Buffer.from(discriminator('account', 'Escrow')).copy(data, 0)
  const b = data.subarray(8)
  b[0] = VERSION
  b.writeBigUInt64LE(7n, 1)
  payer.toBuffer().copy(b, 9)
  recipient.toBuffer().copy(b, 41)
  ;(o.arbiter ?? PublicKey.default).toBuffer().copy(b, 73)
  mint.toBuffer().copy(b, 105)
  ;(o.sponsor ?? sponsor).toBuffer().copy(b, 169)
  b.writeBigUInt64LE(1_000_000n, 201)
  b[209] = o.creator ?? 0
  const windows = o.windows ?? []
  b[210] = o.count ?? windows.length
  windows.forEach(([until, payerShare], i) => {
    b.writeBigInt64LE(until, 211 + 10 * i)
    b.writeUInt16LE(payerShare, 219 + 10 * i)
  })
  b[251] = o.end ?? 0
  b.writeBigInt64LE(T0, 252)
  b.writeBigInt64LE(o.fundedAt ?? 0n, 260)
  b[268] = o.status ?? 0
  b[269] = 254
  b.writeBigInt64LE(o.endedAt ?? 0n, 270)
  b[278] = o.outcome ?? 0
  b.writeBigUInt64LE(o.toPayer ?? 0n, 279)
  b.writeBigUInt64LE(o.toRecipient ?? 0n, 287)
  b[295] = o.stop ?? 0
  b.writeBigInt64LE(o.stoppedAt ?? 0n, 296)
  // The vault is the deposit account of the address these terms make, schedule and arbiter included.
  const schedule = windows.length > 0 ? { windows: windows.map(([until, payerShare]) => ({ until, payerShare })), end: o.end === 1 ? ('refund' as const) : ('pay' as const) } : null
  const escrow = escrowAddress({ payer, mint, terms: terms({ arbiter: o.arbiter ?? null, schedule }) })
  depositAddress(escrow, mint).toBuffer().copy(b, 137)
  return new Uint8Array(data)
}

test('the escrow account decodes at the pinned offsets', () => {
  assert.deepEqual(decodeEscrow(escrowBytes()), escrowAccount({ bump: 254 }))
  const windows: [bigint, number][] = [[T0 + DAY, 10_000], [T0 + 2n * DAY, 5_000], [T0 + 3n * DAY, 0]]
  const e = decodeEscrow(
    escrowBytes({ arbiter, sponsor: recipient, creator: 1, windows, end: 1, fundedAt: T0 + 60n, status: 2, endedAt: T0 + DAY, outcome: 2, toPayer: 1_000_003n, toRecipient: 0n }),
  )
  const schedule: Schedule = { windows: windows.map(([until, payerShare]) => ({ until, payerShare })), end: 'refund' }
  assert.deepEqual(e, {
    ...escrowAccount({ bump: 254, arbiter, schedule }),
    sponsor: recipient,
    creator: 'recipient',
    fundedAt: T0 + 60n,
    status: 'ended',
    endedAt: T0 + DAY,
    outcome: 'takeBack',
    toPayer: 1_000_003n,
  })
  // Four windows, the most a schedule holds, at the widest times.
  const four: [bigint, number][] = [[-(1n << 63n), 10_000], [-1n, 5_000], [T0, 1], [(1n << 63n) - 1n, 0]]
  assert.deepEqual(decodeEscrow(escrowBytes({ windows: four })).schedule?.windows.map((w) => [w.until, w.payerShare]), four)
  // The stop, by its byte: none 0, the payer 1, the recipient 2; its time only with it.
  assert.deepEqual([decodeEscrow(escrowBytes()).stop, decodeEscrow(escrowBytes()).stoppedAt], [null, null])
  const byPayer = decodeEscrow(escrowBytes({ stop: 1, stoppedAt: T0 + 5n }))
  assert.deepEqual([byPayer.stop, byPayer.stoppedAt], ['payer', T0 + 5n])
  assert.equal(decodeEscrow(escrowBytes({ stop: 2, stoppedAt: T0 })).stop, 'recipient')
  assert.deepEqual(decodeEscrow(escrowBytes({ stop: 1, stoppedAt: 0n })).stoppedAt, 0n, 'stopped at a zero clock still reads as stopped')
  assert.throws(() => decodeEscrow(escrowBytes({ stop: 3 })), /stop/)
  // Each outcome, by its byte.
  const outcomes = ['pay', 'refund', 'takeBack', 'agree', 'decide', 'end']
  outcomes.forEach((name, i) => assert.equal(decodeEscrow(escrowBytes({ status: 2, outcome: i })).outcome, name))
  // A receipt always has a funding time (the program writes the ending's when nobody marked it);
  // the decoder reads a zero as none all the same.
  assert.equal(decodeEscrow(escrowBytes({ status: 2, fundedAt: T0 + DAY, endedAt: T0 + DAY })).fundedAt, T0 + DAY)
  assert.equal(decodeEscrow(escrowBytes({ status: 0 })).fundedAt, null)
  assert.equal(decodeEscrow(escrowBytes({ status: 1, fundedAt: T0 })).status, 'funded')
  // Refusals.
  assert.throws(() => decodeEscrow(escrowBytes().subarray(1)), /bytes/)
  const wrong = escrowBytes()
  wrong[0] ^= 1
  assert.throws(() => decodeEscrow(wrong), /not an escrow/)
  assert.throws(() => decodeEscrow(escrowBytes({ status: 3 })), /status/)
  assert.throws(() => decodeEscrow(escrowBytes({ status: 2, outcome: 6 })), /outcome/)
  assert.throws(() => decodeEscrow(escrowBytes({ creator: 2 })), /side/)
  assert.throws(() => decodeEscrow(escrowBytes({ windows: [[T0, 0]], end: 2 })), /end/)
  assert.throws(() => decodeEscrow(escrowBytes({ windows: [[T0, 0]], count: 5 })), /5 windows/)
  assert.throws(() => decodeEscrow(escrowBytes({ windows: [[T0, 0], [T0 + 1n, 0]], count: 1 })), /past the count/)
  assert.throws(() => decodeEscrow(escrowBytes({ end: 1 })), /stored as pay/)
})

function eventBytes(name: string, size: number, fill: (b: Buffer) => void): Buffer {
  const b = Buffer.alloc(size)
  Buffer.from(discriminator('event', name)).copy(b, 0)
  baseEscrow().toBuffer().copy(b, 8)
  fill(b)
  return b
}

test('events decode from the log, in order', () => {
  const escrow = baseEscrow()
  const vault = depositAddress(escrow, mint)
  const created = eventBytes('Created', 300, (b) => {
    b[40] = VERSION
    b.writeBigUInt64LE(7n, 41)
    payer.toBuffer().copy(b, 49)
    recipient.toBuffer().copy(b, 81)
    b[113] = 1
    arbiter.toBuffer().copy(b, 114)
    mint.toBuffer().copy(b, 146)
    vault.toBuffer().copy(b, 178)
    sponsor.toBuffer().copy(b, 210)
    b.writeBigUInt64LE(1_000_000n, 242)
    b[250] = 2
    b.writeBigInt64LE(T0 + DAY, 251)
    b.writeUInt16LE(10_000, 259)
    b.writeBigInt64LE(T0 + 2n * DAY, 261)
    b.writeUInt16LE(5_000, 269)
    b[291] = 1
    b.writeBigInt64LE(T0, 292)
  })
  const funded = eventBytes('Funded', 56, (b) => {
    b.writeBigUInt64LE(1_000_000n, 40)
    b.writeBigInt64LE(T0 + 60n, 48)
  })
  const stopped = eventBytes('Stopped', 49, (b) => {
    b[40] = 1
    b.writeBigInt64LE(T0 + 30n, 41)
  })
  const ended = eventBytes('Ended', 129, (b) => {
    b[40] = 3
    b.writeBigUInt64LE(1_000_000n, 41)
    b.writeBigUInt64LE(1_000_003n, 49)
    b.writeBigUInt64LE(300_000n, 57)
    b.writeBigUInt64LE(700_003n, 65)
    b.writeBigInt64LE(T0 + DAY, 73)
    sponsor.toBuffer().copy(b, 81)
    b.writeBigUInt64LE(2_039_280n, 113)
    b.writeBigInt64LE(T0 + 60n, 121)
  })
  const closed = eventBytes('Closed', 120, (b) => {
    recipient.toBuffer().copy(b, 40)
    b.writeBigUInt64LE(5n, 72)
    sponsor.toBuffer().copy(b, 80)
    b.writeBigUInt64LE(4_767_600n, 112)
  })
  const late = eventBytes('RecoveredLate', 56, (b) => {
    b.writeBigUInt64LE(400_000n, 40)
    b.writeBigUInt64LE(2_039_280n, 48)
  })
  const swept = eventBytes('RentSwept', 88, (b) => {
    sponsor.toBuffer().copy(b, 40)
    b.writeBigUInt64LE(2_455_488n, 72)
    b.writeBigUInt64LE(306_240n, 80)
  })
  const id = PROGRAM_ID.toBase58()
  const logs = [
    `Program ${id} invoke [1]`,
    `Program data: ${created.toString('base64')}`,
    'Program log: something else',
    `Program data: ${funded.toString('base64')}`,
    `Program data: ${stopped.toString('base64')}`,
    `Program data: ${ended.toString('base64')}`,
    `Program data: ${closed.toString('base64')}`,
    `Program data: ${late.toString('base64')}`,
    `Program data: ${swept.toString('base64')}`,
    'Program data: AAAA',
    `Program ${id} success`,
  ]
  assert.deepEqual(decodeEvents(logs), [
    {
      kind: 'created',
      escrow,
      version: VERSION,
      id: 7n,
      payer,
      recipient,
      creator: 'recipient',
      arbiter,
      mint,
      vault,
      sponsor,
      amount: 1_000_000n,
      schedule: { windows: twoWindows.windows, end: 'refund' },
      createdAt: T0,
    },
    { kind: 'funded', escrow, balance: 1_000_000n, fundedAt: T0 + 60n },
    { kind: 'stopped', escrow, by: 'recipient', stoppedAt: T0 + 30n },
    {
      kind: 'ended',
      escrow,
      outcome: 'agree',
      amount: 1_000_000n,
      balance: 1_000_003n,
      toPayer: 300_000n,
      toRecipient: 700_003n,
      endedAt: T0 + DAY,
      sponsor,
      rentLamports: 2_039_280n,
      fundedAt: T0 + 60n,
    },
    { kind: 'closed', escrow, closedBy: recipient, toPayer: 5n, sponsor, rentLamports: 4_767_600n },
    { kind: 'recoveredLate', escrow, toPayer: 400_000n, rentLamports: 2_039_280n },
    { kind: 'rentSwept', escrow, sponsor, lamports: 2_455_488n, left: 306_240n },
  ])
  // A Created with no options: the zero key, and no windows with the default stored as pay.
  const bare = Buffer.from(created)
  PublicKey.default.toBuffer().copy(bare, 114)
  bare.fill(0, 250, 292)
  const e = decodeEvent(new Uint8Array(bare))
  assert.ok(e?.kind === 'created' && e.arbiter === null && e.schedule === null)
  assert.equal(decodeEvent(new Uint8Array(7)), null)
  assert.throws(() => decodeEvent(new Uint8Array([...ended, 0])), /trailing/)
})

test('an event only counts when the escrow program itself wrote it', () => {
  // Any program can write a `Program data:` line with an escrow event's exact bytes: a receipt
  // for a deal that never happened, at any address. The runtime's own invoke and success lines
  // say which program wrote each line, and no program can forge those.
  const ended = eventBytes('Ended', 129, (b) => {
    b.writeBigUInt64LE(10_000_000_000n, 41)
    b.writeBigUInt64LE(10_000_000_000n, 49)
    b.writeBigUInt64LE(10_000_000_000n, 65)
  })
  const line = `Program data: ${ended.toString('base64')}`
  const forger = 'Forger1111111111111111111111111111111111111'
  const token = TOKEN_PROGRAM_ID.toBase58()
  const id = PROGRAM_ID.toBase58()

  // Written by another program, alone or around a real escrow instruction.
  assert.deepEqual(decodeEvents([`Program ${forger} invoke [1]`, line, `Program ${forger} success`]), [])
  assert.deepEqual(decodeEvents([`Program ${id} invoke [1]`, `Program ${id} success`, `Program ${forger} invoke [1]`, line, `Program ${forger} success`]), [])
  // Written by a program the escrow called, while the escrow waits.
  assert.deepEqual(decodeEvents([`Program ${id} invoke [1]`, `Program ${token} invoke [2]`, line, `Program ${token} success`, `Program ${id} success`]), [])
  // A line with no program open at all.
  assert.deepEqual(decodeEvents([line]), [])
  // The escrow's own, after its call into the token program returned, counts; so does the
  // escrow's own when another program called it.
  assert.equal(decodeEvents([`Program ${id} invoke [1]`, `Program ${token} invoke [2]`, `Program ${token} success`, line, `Program ${id} success`]).length, 1)
  assert.equal(decodeEvents([`Program ${forger} invoke [1]`, `Program ${id} invoke [2]`, line, `Program ${id} success`, `Program ${forger} success`]).length, 1)
  // Another deployment of the same code, at another address, is another program.
  assert.deepEqual(decodeEvents([`Program ${id} invoke [1]`, line, `Program ${id} success`], new PublicKey(token)), [])
})

test("terms come from a post's optional terms block: every option off unless set", () => {
  assert.deepEqual(optionsFromPost(undefined), { arbiter: null, schedule: null })
  assert.deepEqual(optionsFromPost(null), { arbiter: null, schedule: null })
  assert.deepEqual(optionsFromPost({}), { arbiter: null, schedule: null })
  assert.deepEqual(optionsFromPost({ arbiter: arbiter.toBase58() }), { arbiter, schedule: null })
  const json = { windows: [{ until: 1_800_086_400, payerShare: 10_000 }, { until: 1_800_172_800, payerShare: 5_000 }], end: 'pay' as const }
  assert.deepEqual(optionsFromPost({ schedule: json }), { arbiter: null, schedule: twoWindows })
  // The format as JSON text, as a record carries it.
  assert.deepEqual(optionsFromPost(JSON.parse(JSON.stringify({ schedule: json }))).schedule, twoWindows)
  // An old post's leftover keys pass and mean nothing; a v2 timer among them.
  assert.deepEqual(optionsFromPost({ autoReleaseDays: 7, timer: { days: 7, to: 'seller' } }), { arbiter: null, schedule: null })
  for (const [what, bad, want] of [
    ['an arbiter that is not a key', { arbiter: 'not a key' }, /./],
    ['an arbiter that is not a string', { arbiter: 7 }, /base58/],
    ['the zero key', { arbiter: PublicKey.default.toBase58() }, /EmptyKey/],
    ['a schedule with no windows array', { schedule: { end: 'pay' } }, /windows, end/],
    ['no windows', { schedule: { windows: [], end: 'pay' } }, /ScheduleEmpty/],
    ['five windows', { schedule: { windows: [1, 2, 3, 4, 5].map((i) => ({ until: i, payerShare: 0 })), end: 'pay' } }, /at most 4/],
    ['an until that is not whole', { schedule: { windows: [{ until: 1.5, payerShare: 0 }], end: 'pay' } }, /whole number of unix seconds/],
    ['an until as a string', { schedule: { windows: [{ until: '1800000000', payerShare: 0 }], end: 'pay' } }, /whole number of unix seconds/],
    ['a share over 10,000', { schedule: { windows: [{ until: 1, payerShare: 10_001 }], end: 'pay' } }, /payerShare/],
    ['windows out of order', { schedule: { windows: [{ until: 2, payerShare: 0 }, { until: 1, payerShare: 0 }], end: 'pay' } }, /WindowsOutOfOrder/],
    ['a default that is neither', { schedule: { windows: [{ until: 1, payerShare: 0 }], end: 'release' } }, /"pay" or "refund"/],
  ] as const) {
    assert.throws(() => optionsFromPost(bad as never), want, what)
  }
  const t = termsFor({ arbiter: arbiter.toBase58(), schedule: json }, { recipient, amount: 5n, id: 9n })
  assert.deepEqual(t, { id: 9n, recipient, amount: 5n, arbiter, schedule: twoWindows })
  const fresh = termsFor(undefined, { recipient, amount: 5n })
  assert.deepEqual([fresh.arbiter, fresh.schedule], [null, null])
  assert.ok(fresh.id >= 0n)
})

test('before working or paying, a person sees every option they did not set', () => {
  const none = { arbiter: null, schedule: null }
  // Nothing set, nothing there.
  assert.deepEqual(optionsNotAgreed({ escrow: escrowAccount(), agreed: none }), [])
  assert.deepEqual(optionsNotAgreed({ escrow: escrowAccount(), agreed: null }), [])

  // The payer names an arbiter and a month to take everything back; the recipient agreed to none.
  const month: Schedule = { windows: [{ until: T0 + 30n * DAY, payerShare: 10_000 }], end: 'refund' }
  const rigged = escrowAccount({ arbiter: stranger, schedule: month })
  assert.deepEqual(optionsNotAgreed({ escrow: rigged, agreed: null }), [
    { option: 'arbiter', kind: 'added', arbiter: stranger },
    { option: 'schedule', kind: 'added', schedule: month },
  ])
  // The same escrow, seen by the payer who made it from its own post: nothing to show.
  const post = { arbiter: stranger.toBase58(), schedule: { windows: [{ until: Number(T0 + 30n * DAY), payerShare: 10_000 }], end: 'refund' as const } }
  assert.deepEqual(optionsNotAgreed({ escrow: rigged, agreed: post }), [])

  // An invoice with a shorter window than the offer said, and another arbiter than the one agreed.
  const offer = { arbiter: arbiter.toBase58(), schedule: { windows: [{ until: Number(T0 + 7n * DAY), payerShare: 10_000 }], end: 'pay' as const } }
  const short: Schedule = { windows: [{ until: T0 + DAY, payerShare: 10_000 }], end: 'pay' }
  const invoiced = escrowAccount({ creator: 'recipient', arbiter: stranger, schedule: short })
  assert.deepEqual(optionsNotAgreed({ escrow: invoiced, agreed: offer }), [
    { option: 'arbiter', kind: 'changed', arbiter: stranger },
    { option: 'schedule', kind: 'changed', schedule: short },
  ])
  // The same windows with the other default is another schedule.
  assert.equal(optionsNotAgreed({ escrow: escrowAccount({ arbiter, schedule: { ...optionsFromPost(offer).schedule!, end: 'refund' } }), agreed: offer }).length, 1)
  // An option agreed and missing.
  assert.deepEqual(optionsNotAgreed({ escrow: escrowAccount(), agreed: offer }), [
    { option: 'arbiter', kind: 'removed', expected: arbiter },
    { option: 'schedule', kind: 'removed', expected: optionsFromPost(offer).schedule },
  ])
  assert.throws(() => assertOptionsAgreed({ escrow: rigged, agreed: null }), /arbiter not agreed: .*schedule not agreed: 10000 until \d+, then refund/)
  assertOptionsAgreed({ escrow: rigged, agreed: optionsFromPost(post) })
})

test("payouts: the whole balance, the payer's share of a split rounded down", () => {
  assert.deepEqual(split(1_000_003n, 5_000), { toPayer: 500_001n, toRecipient: 500_002n })
  assert.deepEqual(split(1_000_003n, 10_000), { toPayer: 1_000_003n, toRecipient: 0n })
  assert.deepEqual(split(1_000_003n, 0), { toPayer: 0n, toRecipient: 1_000_003n })
  assert.deepEqual(split(1n, 9_999), { toPayer: 0n, toRecipient: 1n })
  const max = (1n << 64n) - 1n
  const { toPayer, toRecipient } = split(max, 7_777)
  assert.equal(toPayer + toRecipient, max)
  assert.equal(share(max, 10_000), max)
  assert.throws(() => share(1n, 10_001), RangeError)
  assert.equal(funds(999_999n, 1_000_000n), false)
  assert.equal(funds(1_000_000n, 1_000_000n), true)
})

// ---------------------------------------------------------------------------------------------
// Token-2022.
// ---------------------------------------------------------------------------------------------

/** A mint account's bytes: six decimals, initialized, and for Token-2022 its extensions as TLV. */
function mintBytes(extensions: [number, Uint8Array][] | null): Uint8Array {
  const base = Buffer.alloc(82)
  base[44] = 6
  base[45] = 1
  if (!extensions) return new Uint8Array(base)
  const parts: Buffer[] = [base, Buffer.alloc(165 - 82), Buffer.from([1])]
  for (const [type, data] of extensions) {
    const head = Buffer.alloc(4)
    head.writeUInt16LE(type, 0)
    head.writeUInt16LE(data.length, 2)
    parts.push(head, Buffer.from(data))
  }
  return new Uint8Array(Buffer.concat(parts))
}

/** The transfer hook extension (14): its authority, then its program (the zero key for none). */
function hookExtension(program: PublicKey | null): [number, Uint8Array] {
  return [14, Buffer.concat([Keypair.generate().publicKey.toBuffer(), (program ?? PublicKey.default).toBuffer()])]
}

/** A hook's validation account: the execute discriminator, then its list of extra accounts. */
function validationBytes(metas: { discriminator: number; config: Uint8Array; signer: boolean; writable: boolean }[]): Buffer {
  const entries = metas.map((m) => {
    const e = Buffer.alloc(35)
    e[0] = m.discriminator
    Buffer.from(m.config).copy(e, 1)
    e[33] = m.signer ? 1 : 0
    e[34] = m.writable ? 1 : 0
    return e
  })
  const head = Buffer.alloc(16)
  Buffer.from(sha256Prefix('spl-transfer-hook-interface:execute')).copy(head, 0)
  head.writeUInt32LE(4 + 35 * entries.length, 8)
  head.writeUInt32LE(entries.length, 12)
  return Buffer.concat([head, ...entries])
}

function sha256Prefix(text: string): Uint8Array {
  return discriminator(text.split(':')[0], text.split(':')[1])
}

/** A seed list: a literal, or bytes of an earlier account's data. */
function literalSeed(bytes: string): Uint8Array {
  const b = Buffer.alloc(32)
  b[0] = 1
  b[1] = bytes.length
  Buffer.from(bytes).copy(b, 2)
  return b
}
function literalThenAccountData(bytes: string, accountIndex: number, dataIndex: number, length: number): Uint8Array {
  const b = Buffer.from(literalSeed(bytes))
  b.set([4, accountIndex, dataIndex, length], 2 + bytes.length)
  return b
}

/** A reader over a fixed set of accounts, as a `Connection` would read them. */
function readerOf(accounts: Map<string, { owner: PublicKey; data: Uint8Array }>) {
  return {
    getAccountInfo: async (address: PublicKey) => {
      const a = accounts.get(address.toBase58())
      return a ? { owner: a.owner, data: Buffer.from(a.data), lamports: 1, executable: false } : null
    },
  }
}

test('a mint is read with its token program and decimals; wrapped SOL, a transfer fee and a non-transferable mint are refused', () => {
  assert.deepEqual(tokenOf(mint, { owner: TOKEN_PROGRAM_ID, data: mintBytes(null) }), { mint, program: TOKEN_PROGRAM_ID, decimals: 6 })
  const openUsdShaped = mintBytes([
    [3, Buffer.alloc(32)], // mint close authority
    [12, Buffer.alloc(32)], // permanent delegate
    [6, Buffer.from([1])], // default account state
    hookExtension(null),
    [26, Buffer.alloc(33)], // pausable
  ])
  assert.deepEqual(tokenOf(mint, { owner: TOKEN_2022_PROGRAM_ID, data: openUsdShaped }), { mint, program: TOKEN_2022_PROGRAM_ID, decimals: 6 })
  assert.throws(() => tokenOf(mint, { owner: TOKEN_2022_PROGRAM_ID, data: mintBytes([[1, Buffer.alloc(108)]]) }), /TransferFee/)
  assert.throws(() => tokenOf(mint, { owner: TOKEN_2022_PROGRAM_ID, data: mintBytes([[16, Buffer.alloc(64)]]) }), /TransferFee/, 'the confidential fee too')
  assert.throws(() => tokenOf(mint, { owner: TOKEN_2022_PROGRAM_ID, data: mintBytes([[9, Buffer.alloc(0)]]) }), /NonTransferable/)
  // Interest-bearing (10) and scaled (25) mints are accepted: the escrow deals in raw amounts.
  for (const [type, len] of [[10, 52], [25, 56]]) {
    assert.deepEqual(tokenOf(mint, { owner: TOKEN_2022_PROGRAM_ID, data: mintBytes([[type, Buffer.alloc(len)]]) }).program, TOKEN_2022_PROGRAM_ID)
  }
  assert.throws(() => tokenOf(NATIVE_MINT, { owner: TOKEN_PROGRAM_ID, data: mintBytes(null) }), /NativeMint/)
  assert.throws(() => tokenOf(NATIVE_MINT_2022, { owner: TOKEN_2022_PROGRAM_ID, data: mintBytes([]) }), /NativeMint/)
  assert.throws(() => tokenOf(mint, { owner: PROGRAM_ID, data: mintBytes(null) }), /not a mint of either token program/)
  assert.throws(() => createIx({ payer, sponsor, mint: NATIVE_MINT_2022, terms: terms(), tokenProgram: TOKEN_2022_PROGRAM_ID }), /NativeMint/)
})

test('under Token-2022 every address is derived with it and every instruction names it; hook accounts go last, never signing', () => {
  const t22 = TOKEN_2022_PROGRAM_ID
  const t = terms({ arbiter, schedule: twoWindows })
  const escrow = escrowAddress({ payer, mint, terms: t })
  const vault = depositAddress(escrow, mint, t22)
  assert.notDeepEqual(vault, depositAddress(escrow, mint), 'another address than under the classic program')
  assert.deepEqual(vault, getAssociatedTokenAddressSync(mint, escrow, true, t22, ASSOCIATED_TOKEN_PROGRAM_ID))
  assert.deepEqual(payerAccount(payer, mint, t22), getAssociatedTokenAddressSync(mint, payer, false, t22, ASSOCIATED_TOKEN_PROGRAM_ID))
  assert.deepEqual(recipientAccount(recipient, mint, t22), getAssociatedTokenAddressSync(mint, recipient, false, t22, ASSOCIATED_TOKEN_PROGRAM_ID))

  const create = createIx({ payer, sponsor, mint, terms: t, tokenProgram: t22 })
  assert.deepEqual([create.keys[1].pubkey, create.keys[5].pubkey], [vault, t22])
  const k = keysFor({ payer, sponsor, mint, terms: t, tokenProgram: t22 })
  const account = escrowAccount({ vault, arbiter, status: 'funded', fundedAt: T0, schedule: twoWindows })
  assert.deepEqual(keysOf(account, { tokenProgram: t22 }), k)
  assert.throws(() => keysOf(account), /not under that token program/, 'the classic program named for a Token-2022 escrow')

  const hook = [
    { pubkey: stranger, isSigner: true, isWritable: false },
    { pubkey: arbiter, isSigner: false, isWritable: true },
  ]
  const forwarded = [
    [stranger.toBase58(), false, false],
    [arbiter.toBase58(), false, true],
  ]
  const payers = payerAccount(payer, mint, t22).toBase58()
  const recipients = recipientAccount(recipient, mint, t22).toBase58()
  const head = [[escrow.toBase58(), false, true], [vault.toBase58(), false, true], [mint.toBase58(), false, false]]
  const tail = [[sponsor.toBase58(), false, true], [t22.toBase58(), false, false]]
  assert.deepEqual(meta(payIx({ keys: k, hookAccounts: hook })), [...head, [recipients, false, true], ...tail, [payer.toBase58(), true, false], ...forwarded])
  assert.deepEqual(meta(refundIx({ keys: k, hookAccounts: hook })), [...head, [payers, false, true], ...tail, [recipient.toBase58(), true, false], ...forwarded])
  assert.deepEqual(meta(takeBackIx({ keys: k, hookAccounts: hook })).slice(8), forwarded)
  assert.deepEqual(meta(agreeIx({ keys: k, payerShare: 1, hookAccounts: hook })).slice(9), forwarded)
  assert.deepEqual(meta(decideIx({ keys: k, arbiter, payerShare: 1, hookAccounts: hook })).slice(8), forwarded)
  assert.deepEqual(meta(closeUnfundedIx({ keys: k, closer: payer, hookAccounts: hook })).slice(7), forwarded)
  const end = endIx({ account, tokenProgram: t22, hookAccounts: hook })
  assert.deepEqual(meta(end), [...head, [recipients, false, true], ...tail, ...forwarded])
  const late = recoverLateIx({ account: { ...account, status: 'ended' }, caller: stranger, tokenProgram: t22, hookAccounts: hook })
  assert.deepEqual([late.keys[3].pubkey, late.keys[6].pubkey], [payerAccount(payer, mint, t22), t22])
  assert.deepEqual(meta(late).slice(9), forwarded)

  // A wallet app's transfer_checked under Token-2022, hook accounts after its four.
  const pay = transferIx({ from: sponsor, to: vault, owner: payer, mint, amount: 5n, decimals: 6, tokenProgram: t22, hookAccounts: [{ pubkey: arbiter, isSigner: false, isWritable: true }] })
  assert.deepEqual(pay.programId, t22)
  assert.equal(hex(pay.data), '0c' + '0500000000000000' + '06')
  assert.equal(pay.keys.length, 5)

  // The one tap under Token-2022, with each transfer's hook accounts in place.
  const token = { mint, program: t22, decimals: 6 }
  const [deposit, , fund, paid] = payInOneTap({ payer, sponsor, token, terms: t, hookAccounts: { fund: [hook[1]], pay: [hook[0]] } })
  assert.deepEqual([deposit.keys[1].pubkey, deposit.keys[5].pubkey], [vault, t22])
  assert.deepEqual(fund.keys.map((m) => m.pubkey).slice(4), [arbiter])
  assert.deepEqual(meta(paid).slice(7), [[stranger.toBase58(), false, false]])
})

test("a hook's accounts are resolved by spl-token's resolver: none without a hook program, each once, never signing", async () => {
  const t22 = TOKEN_2022_PROGRAM_ID
  const hookProgram = Keypair.generate().publicKey
  const listed = Keypair.generate().publicKey
  const k = keysFor({ payer, sponsor, mint, terms: terms(), tokenProgram: t22 })
  const validation = PublicKey.findProgramAddressSync([Buffer.from('extra-account-metas'), mint.toBuffer()], hookProgram)[0]
  const counter = PublicKey.findProgramAddressSync([Buffer.from('counter')], hookProgram)[0]
  const tokenAccount = (owner: PublicKey) => {
    const d = Buffer.alloc(165)
    mint.toBuffer().copy(d, 0)
    owner.toBuffer().copy(d, 32)
    d[108] = 1
    return { owner: t22, data: new Uint8Array(d) }
  }
  const accounts = new Map<string, { owner: PublicKey; data: Uint8Array }>([
    [mint.toBase58(), { owner: t22, data: mintBytes([hookExtension(hookProgram)]) }],
    [
      validation.toBase58(),
      {
        owner: hookProgram,
        data: validationBytes([
          { discriminator: 0, config: listed.toBytes(), signer: true, writable: false },
          { discriminator: 1, config: literalSeed('counter'), signer: false, writable: true },
          { discriminator: 1, config: literalThenAccountData('holder', 2, 32, 32), signer: false, writable: false },
        ]),
      },
    ],
    [recipientAccount(recipient, mint, t22).toBase58(), tokenAccount(recipient)],
    [payerAccount(payer, mint, t22).toBase58(), tokenAccount(payer)],
  ])
  const reader = readerOf(accounts)
  const entry = (owner: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from('holder'), owner.toBuffer()], hookProgram)[0]

  const both = await hookAccounts({ reader, mint, transfers: payoutTransfers(k, ['recipient', 'payer']) })
  const byKey = new Map(both.map((m) => [m.pubkey.toBase58(), m]))
  assert.equal(both.length, 6, 'the program, the listed key, the counter, an entry per destination owner, the validation account')
  for (const [key, writable] of [[hookProgram, false], [listed, false], [counter, true], [entry(recipient), false], [entry(payer), false], [validation, false]] as const) {
    assert.deepEqual([byKey.get(key.toBase58())?.isWritable, byKey.get(key.toBase58())?.isSigner], [writable, false], key.toBase58())
  }

  // A payment into a deposit account the same transaction makes: read as planned.
  const fund = { source: sponsor, destination: k.vault, authority: payer }
  await assert.rejects(hookAccounts({ reader, mint, transfers: [fund] }), 'the deposit account is not on the chain yet')
  const planned = await hookAccounts({ reader, mint, transfers: [fund], planned: [{ address: k.vault, owner: k.escrow, mint, tokenProgram: t22 }] })
  assert.ok(planned.some((m) => m.pubkey.equals(entry(k.escrow))))

  // No hook program named, a classic mint, or no mint: nothing to forward.
  accounts.set(mint.toBase58(), { owner: t22, data: mintBytes([hookExtension(null)]) })
  assert.deepEqual(await hookAccounts({ reader, mint, transfers: payoutTransfers(k, ['recipient']) }), [])
  accounts.set(mint.toBase58(), { owner: TOKEN_PROGRAM_ID, data: mintBytes(null) })
  assert.deepEqual(await hookAccounts({ reader, mint, transfers: payoutTransfers(k, ['recipient']) }), [])
  accounts.delete(mint.toBase58())
  assert.deepEqual(await hookAccounts({ reader, mint, transfers: payoutTransfers(k, ['recipient']) }), [])
})
