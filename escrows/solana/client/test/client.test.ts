// What the v2 client computes, with no chain: the bytes it writes, the bytes it reads back, the
// options check, the timer and the objection. The LiteSVM tests write the same bytes by hand in
// Rust, and the devnet run sends these through the deployed program; if either side drifted, one
// of them fails.

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
  MAX_TIMER_DAYS,
  NATIVE_MINT,
  NATIVE_MINT_2022,
  PROGRAM_ID,
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  VERSION,
  arbitrateIx,
  assertOptionsAgreed,
  associatedTokenAddress,
  canObject,
  closeUnfundedIx,
  createArgsBytes,
  createAndFund,
  createIx,
  decodeEscrow,
  decodeEvent,
  decodeEvents,
  discriminator,
  escrowAddress,
  funds,
  hookAccounts,
  invoiceIx,
  keysFor,
  keysOf,
  makeDepositAddressIx,
  makeRefundAddressIx,
  markFundedIx,
  objectIx,
  optionsFromPost,
  optionsNotAgreed,
  payInOneTap,
  payInvoiceInOneTap,
  payoutAddress,
  payoutTransfers,
  payout,
  randomId,
  recoverLateIx,
  refundAddress,
  releaseToBuyerIx,
  releaseToSellerIx,
  share,
  splitIx,
  sweepRentIx,
  termsFor,
  termsHash,
  termsOf,
  tokenOf,
  transferIx,
  timerDue,
  timerDueAt,
  timerReleaseIx,
  validateTerms,
  vaultAddress,
  type EscrowAccount,
  type Terms,
} from '../src/index.ts'

const here = dirname(fileURLToPath(import.meta.url))
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
const DAY = 86_400n
const T0 = 1_800_000_000n

const buyer = Keypair.generate().publicKey
const seller = Keypair.generate().publicKey
const arbiter = Keypair.generate().publicKey
const mint = Keypair.generate().publicKey
const payer = Keypair.generate().publicKey
const stranger = Keypair.generate().publicKey

/** The address of the standard terms: the buyer's, 1.00, every option off. */
function baseEscrow(): PublicKey {
  return escrowAddress({ buyer, mint, terms: terms() })
}

/**
 * An escrow account as `decodeEscrow` would return it: the buyer's, open, unfunded, every option
 * off. Its deposit account is that of its own terms' address, unless named.
 */
function escrowAccount(over: Partial<EscrowAccount> = {}): EscrowAccount {
  const e: EscrowAccount = {
    version: 2,
    id: 7n,
    buyer,
    seller,
    arbiter: null,
    mint,
    vault: PublicKey.default,
    rentRecipient: payer,
    amount: 1_000_000n,
    creator: 'buyer',
    timer: null,
    createdAt: T0,
    fundedAt: null,
    status: 'open',
    bump: 255,
    endedAt: null,
    outcome: null,
    toSeller: 0n,
    toBuyer: 0n,
    payer,
    objection: null,
    objectedAt: null,
    ...over,
  }
  return over.vault ? e : { ...e, vault: vaultAddress(escrowAddress(termsOf(e)), e.mint) }
}

/** The same, opened by the seller: an invoice, at the same address as the same terms the buyer opens. */
function invoiceAccount(over: Partial<EscrowAccount> = {}): EscrowAccount {
  return escrowAccount({ creator: 'seller', ...over })
}

function terms(over: Partial<Terms> = {}): Terms {
  return { id: 7n, seller, amount: 1_000_000n, arbiter: null, timer: null, ...over }
}

const meta = (ix: { keys: { pubkey: PublicKey; isSigner: boolean; isWritable: boolean }[] }) =>
  ix.keys.map((k) => [k.pubkey.toBase58(), k.isSigner, k.isWritable])

test('the program id, the seed and the size are the ones the program bakes in', () => {
  const lib = readFileSync(join(here, '../../program/src/lib.rs'), 'utf8')
  const state = readFileSync(join(here, '../../program/src/state.rs'), 'utf8')
  assert.ok(lib.includes(`declare_id!("${PROGRAM_ID.toBase58()}")`))
  assert.ok(lib.includes(`pub const VERSION: u8 = ${VERSION};`))
  assert.ok(lib.includes('pub const ESCROW_SEED: &[u8] = b"escrow";'))
  assert.ok(lib.includes(`pub const NATIVE_MINT: Pubkey = pubkey!("${NATIVE_MINT.toBase58()}");`))
  assert.ok(lib.includes(`assert!(Escrow::LEN == ${ESCROW_LEN});`))
  assert.ok(state.includes('pub const BPS: u16 = 10_000;'))
  assert.ok(state.includes('pub timer_days: u16,'), 'the timer is sixteen bits of days')
  assert.equal(BPS, 10_000)
  assert.equal(MAX_TIMER_DAYS, 0xffff)
})

test('the discriminators are pinned', () => {
  const ixs: Record<string, string> = {
    create: '181ec828051c0777',
    mark_funded: '9a19863dc8b81d38',
    release_to_seller: 'da5329093136ff38',
    release_to_buyer: '91d4dc55139c198a',
    split: '7cbd1b2bd8289342',
    arbitrate: '695b6e96d80b8e8e',
    timer_release: '6121b42562d607cf',
    close_unfunded: '06d9705bfa5c6746',
    recover_late: '525629b57534cce3',
    sweep_rent: '11ea3af1fb9487b9',
    object: '2351ffae3d579786',
  }
  for (const [name, want] of Object.entries(ixs)) assert.equal(hex(discriminator('global', name)), want, name)
  const events: Record<string, string> = {
    Created: '41fe44f56694f44c',
    Funded: '43543858c00cc9b1',
    Ended: '467b96d69c092dc5',
    Closed: '321f579b87dcc3ef',
    RecoveredLate: 'bd249dc10194f8ce',
    RentSwept: 'cb5605b151a70c19',
    Objected: 'e8d59f3063e1e34a',
  }
  for (const [name, want] of Object.entries(events)) assert.equal(hex(discriminator('event', name)), want, name)
  assert.equal(hex(discriminator('account', 'Escrow')), '1fd57bbbba16da9b')
})

test('the deposit address is the standard associated token account of the escrow', () => {
  const escrow = baseEscrow()
  assert.ok(!PublicKey.isOnCurve(escrow.toBytes()), 'a program-derived address')
  const vault = vaultAddress(escrow, mint)
  assert.deepEqual(vault, getAssociatedTokenAddressSync(mint, escrow, true, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID))
  assert.deepEqual(refundAddress(buyer, mint), getAssociatedTokenAddressSync(mint, buyer, false, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID))
  assert.deepEqual(payoutAddress(seller, mint), getAssociatedTokenAddressSync(mint, seller, false, TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID))
  // Random ids are 64 bits and do not repeat.
  const ids = new Set(Array.from({ length: 100 }, () => randomId()))
  assert.equal(ids.size, 100)
  for (const id of ids) assert.ok(id >= 0n && id < 1n << 64n)
})

test('the address is a hash of every term, the bytes the program hashes', () => {
  // The same vector as the program's harness (`the_address_of_fixed_terms_is_the_clients`).
  const key = (b: number) => new PublicKey(new Uint8Array(32).fill(b))
  const fixed = { buyer: key(1), mint: key(3), terms: { id: 7n, seller: key(2), amount: 1_000_000n, arbiter: key(4), timer: { days: 3, to: 'seller' as const } } }
  assert.equal(hex(termsHash(fixed)), '8e18bf2edbfebf9ff5fad9a21a034c5c9cfca68e03cd0cb65cd00e09c789821a')
  assert.equal(escrowAddress(fixed).toBase58(), 'Cxa9ex9RSxEPHnDbsmGvNbcLQZ2U4XUmSvdwgGegiKS5')

  // Change any one term and the address moves.
  const all = { buyer, mint, terms: terms({ arbiter, timer: { days: 7, to: 'seller' } }) }
  const at = escrowAddress(all)
  const t = all.terms
  const variants: [string, typeof all][] = [
    ['the id', { ...all, terms: { ...t, id: 8n } }],
    ['the buyer', { ...all, buyer: stranger }],
    ['the seller', { ...all, terms: { ...t, seller: stranger } }],
    ['the amount', { ...all, terms: { ...t, amount: 1_000_001n } }],
    ['the mint', { ...all, mint: stranger }],
    ['the arbiter', { ...all, terms: { ...t, arbiter: stranger } }],
    ['no arbiter', { ...all, terms: { ...t, arbiter: null } }],
    ['the timer\'s days', { ...all, terms: { ...t, timer: { days: 8, to: 'seller' } } }],
    ['the timer\'s side', { ...all, terms: { ...t, timer: { days: 7, to: 'buyer' } } }],
    ['no timer', { ...all, terms: { ...t, timer: null } }],
  ]
  for (const [what, v] of variants) assert.notDeepEqual(escrowAddress(v), at, what)
  // Read back off the chain, an escrow's terms give its own address.
  assert.deepEqual(escrowAddress(termsOf(escrowAccount({ arbiter, timer: { days: 7, to: 'seller' } }))), at)
})

test('create carries exactly the bytes the program reads', () => {
  const t = terms({ arbiter, timer: { days: 14, to: 'seller' } })
  const bytes = createArgsBytes(t, buyer)
  // id 8, buyer 32, seller 32, amount 8, arbiter 1+32, timer 1+2+1.
  assert.equal(bytes.length, 8 + 32 + 32 + 8 + 33 + 4)
  const v = new DataView(bytes.buffer, bytes.byteOffset)
  assert.equal(v.getBigUint64(0, true), 7n)
  assert.deepEqual(new PublicKey(bytes.subarray(8, 40)), buyer)
  assert.deepEqual(new PublicKey(bytes.subarray(40, 72)), seller)
  assert.equal(v.getBigUint64(72, true), 1_000_000n)
  assert.equal(bytes[80], 1)
  assert.deepEqual(new PublicKey(bytes.subarray(81, 113)), arbiter)
  assert.equal(bytes[113], 1)
  assert.equal(v.getUint16(114, true), 14)
  assert.equal(bytes[116], 1, 'the seller is side 1')
  assert.equal(createArgsBytes(terms({ timer: { days: 1, to: 'buyer' } }), buyer).at(-1), 0, 'the buyer is side 0')

  // Every option off: one byte each.
  const bare = createArgsBytes(terms(), buyer)
  assert.equal(bare.length, 8 + 32 + 32 + 8 + 1 + 1)
  assert.deepEqual([bare[80], bare[81]], [0, 0])

  const ix = createIx({ buyer, payer, mint, terms: t })
  assert.deepEqual(ix.programId, PROGRAM_ID)
  assert.equal(hex(ix.data.subarray(0, 8)), '181ec828051c0777')
  assert.equal(hex(ix.data.subarray(8)), hex(bytes))
  const escrow = escrowAddress({ buyer, mint, terms: t })
  assert.deepEqual(meta(ix), [
    [escrow.toBase58(), false, true],
    [vaultAddress(escrow, mint).toBase58(), false, true],
    [buyer.toBase58(), true, false],
    [payer.toBase58(), true, true],
    [mint.toBase58(), false, false],
    [TOKEN_PROGRAM_ID.toBase58(), false, false],
    [ASSOCIATED_TOKEN_PROGRAM_ID.toBase58(), false, false],
    ['11111111111111111111111111111111', false, false],
  ])

  // An invoice: the same bytes, with the seller in the creator's slot, at the same address.
  const inv = invoiceIx({ seller, buyer, payer, mint, terms: t })
  assert.equal(hex(inv.data), hex(ix.data))
  assert.deepEqual(inv.keys[0].pubkey, escrow)
  assert.deepEqual(inv.keys[1].pubkey, vaultAddress(escrow, mint))
  assert.deepEqual([inv.keys[2].pubkey.toBase58(), inv.keys[2].isSigner], [seller.toBase58(), true])
  assert.throws(() => createIx({ buyer, payer, mint, terms: t, creator: arbiter }), /NotAParty/)
  assert.throws(() => createIx({ buyer, payer, mint: NATIVE_MINT, terms: t }), /NativeMint/)
  assert.throws(() => invoiceIx({ seller: arbiter, buyer, payer, mint, terms: t }), /its own seller/)
  assert.throws(() => createIx({ buyer, payer, mint, terms: terms({ arbiter: seller }) }), /ArbiterIsAParty/)
  assert.throws(() => invoiceIx({ seller, buyer, payer, mint, terms: terms({ arbiter: buyer }) }), /ArbiterIsAParty/)
})

test('bad terms fail before a transaction is built, with the program\'s own error names', () => {
  const cases: [string, Terms, PublicKey, RegExp][] = [
    ['buyer is seller', terms({ seller: buyer }), buyer, /SameParty/],
    ['zero buyer', terms(), PublicKey.default, /EmptyKey/],
    ['zero seller', terms({ seller: PublicKey.default }), buyer, /EmptyKey/],
    ['zero arbiter', terms({ arbiter: PublicKey.default }), buyer, /EmptyKey/],
    ['the buyer as arbiter', terms({ arbiter: buyer }), buyer, /ArbiterIsAParty/],
    ['the seller as arbiter', terms({ arbiter: seller }), buyer, /ArbiterIsAParty/],
    ['amount zero', terms({ amount: 0n }), buyer, /AmountZero/],
    ['a timer of 0 days', terms({ timer: { days: 0, to: 'seller' } }), buyer, /TimerZero/],
    ['a timer of 65,536 days', terms({ timer: { days: 65_536, to: 'seller' } }), buyer, /TimerZero/],
    ['a timer of 1.5 days', terms({ timer: { days: 1.5, to: 'seller' } }), buyer, /TimerZero/],
    ['a timer to nobody', terms({ timer: { days: 1, to: 'arbiter' as 'seller' } }), buyer, /buyer or the seller/],
    ['an amount over 64 bits', terms({ amount: 1n << 64n }), buyer, /64 bits/],
  ]
  for (const [what, t, b, want] of cases) assert.throws(() => validateTerms(t, b), want, what)
  // A third key as arbiter, and the longest timer, are fine.
  validateTerms(terms({ arbiter, timer: { days: MAX_TIMER_DAYS, to: 'buyer' } }), buyer)
})

test('each way out names the accounts it pays and the keys that sign it', () => {
  const account = escrowAccount({ arbiter })
  const k = keysOf(account)
  const escrow = escrowAddress({ buyer, mint, terms: terms({ arbiter }) })
  assert.deepEqual(k, { escrow, vault: vaultAddress(escrow, mint), buyer, seller, mint, tokenProgram: TOKEN_PROGRAM_ID, rentRecipient: payer })
  assert.deepEqual(keysFor({ buyer, payer, mint, terms: terms({ arbiter }) }), k, 'from the terms, the same keys')
  // An invoice of the same terms: the same keys.
  assert.deepEqual(keysOf(invoiceAccount({ arbiter })), k)
  const refund = refundAddress(buyer, mint).toBase58()
  const sellers = payoutAddress(seller, mint).toBase58()
  const head = [
    [escrow.toBase58(), false, true],
    [vaultAddress(escrow, mint).toBase58(), false, true],
    [mint.toBase58(), false, false],
  ]
  // Every rent back to the payer.
  const tail = [
    [payer.toBase58(), false, true],
    [TOKEN_PROGRAM_ID.toBase58(), false, false],
  ]

  const toSeller = releaseToSellerIx({ keys: k })
  assert.equal(hex(toSeller.data), 'da5329093136ff38')
  assert.deepEqual(meta(toSeller), [...head, [sellers, false, true], ...tail, [buyer.toBase58(), true, false]], 'the seller paid at its standard account')

  const toBuyer = releaseToBuyerIx({ keys: k })
  assert.equal(hex(toBuyer.data), '91d4dc55139c198a')
  assert.deepEqual(meta(toBuyer), [...head, [refund, false, true], ...tail, [seller.toBase58(), true, false]])

  const split = splitIx({ keys: k, sellerBps: 7_000 })
  assert.equal(hex(split.data), '7cbd1b2bd8289342' + '581b')
  assert.deepEqual(meta(split), [...head, [refund, false, true], [sellers, false, true], ...tail, [buyer.toBase58(), true, false], [seller.toBase58(), true, false]])

  const arb = arbitrateIx({ keys: k, arbiter, sellerBps: 2_500 })
  assert.equal(hex(arb.data), '695b6e96d80b8e8e' + 'c409')
  assert.deepEqual(meta(arb), [...head, [refund, false, true], [sellers, false, true], ...tail, [arbiter.toBase58(), true, false]])
  for (const bps of [-1, 10_001, 1.5]) {
    assert.throws(() => splitIx({ keys: k, sellerBps: bps }), /BadSplit/)
    assert.throws(() => arbitrateIx({ keys: k, arbiter, sellerBps: bps }), /BadSplit/)
  }

  const close = closeUnfundedIx({ keys: k, closer: seller })
  assert.equal(hex(close.data), '06d9705bfa5c6746')
  assert.deepEqual(meta(close), [...head, [refund, false, true], ...tail, [seller.toBase58(), true, false]])
  assert.deepEqual(meta(closeUnfundedIx({ keys: k, closer: buyer })).at(-1), [buyer.toBase58(), true, false], 'the buyer closing')
  for (const closer of [payer, arbiter, stranger]) assert.throws(() => closeUnfundedIx({ keys: k, closer }), /NotACloser/)

  const mark = markFundedIx({ escrow, vault: k.vault })
  assert.deepEqual(meta(mark), [[escrow.toBase58(), false, true], [k.vault.toBase58(), false, false]])
  // The sweep pays the payer recorded at creation, not the creator.
  assert.deepEqual(meta(sweepRentIx({ escrow, payer })), [[escrow.toBase58(), false, true], [payer.toBase58(), false, true]])
})

test('an objection: the escrow and the party who signs, refused here where the program would refuse it', () => {
  const account = escrowAccount({ status: 'funded', fundedAt: T0, timer: { days: 3, to: 'seller' } })
  const escrow = escrowAddress(termsOf(account))
  for (const party of [buyer, seller]) {
    const ix = objectIx({ account, party })
    assert.deepEqual(ix.programId, PROGRAM_ID)
    assert.equal(hex(ix.data), '2351ffae3d579786', 'the discriminator, and no arguments')
    assert.deepEqual(meta(ix), [[escrow.toBase58(), false, true], [party.toBase58(), true, false]])
  }
  // An invoice's objection names the escrow at its terms' address, the same as the buyer's.
  assert.deepEqual(objectIx({ account: invoiceAccount(), party: buyer }).keys[0].pubkey, baseEscrow())
  for (const party of [arbiter, payer, stranger]) assert.throws(() => objectIx({ account, party }), /NotAnObjector/)
  assert.throws(() => objectIx({ account: escrowAccount({ objection: 'buyer', objectedAt: T0 }), party: seller }), /AlreadyObjected/)
  assert.throws(() => objectIx({ account: escrowAccount({ status: 'ended', outcome: 'split' }), party: buyer }), /Ended/)

  // Until when: before the timer is due, never at or after it; any time with no timer or no mark.
  const due = T0 + 3n * DAY
  assert.equal(canObject(account, due - 1n), true)
  assert.equal(canObject(account, due), false)
  assert.equal(canObject(escrowAccount(), T0 + 10_000n * DAY), true, 'no timer')
  assert.equal(canObject(escrowAccount({ timer: { days: 1, to: 'seller' } }), T0 + 10_000n * DAY), true, 'a timer nobody marked is never due')
  assert.equal(canObject(escrowAccount({ status: 'funded', fundedAt: T0, timer: { days: 3, to: 'seller' }, objection: 'seller', objectedAt: T0 }), T0), false, 'once per escrow')
  assert.equal(canObject(escrowAccount({ status: 'ended', outcome: 'releasedToSeller' }), T0), false, 'ended')
})

test('the timer pays the side it names, and its builder refuses what the program would', () => {
  const k = keysOf(escrowAccount({ timer: { days: 3, to: 'seller' } }))
  const funded = { status: 'funded' as const, fundedAt: T0 }
  const toSeller = timerReleaseIx({ account: escrowAccount({ ...funded, timer: { days: 3, to: 'seller' } }) })
  assert.equal(hex(toSeller.data), '6121b42562d607cf')
  assert.deepEqual(
    meta(toSeller),
    [
      [k.escrow.toBase58(), false, true],
      [k.vault.toBase58(), false, true],
      [mint.toBase58(), false, false],
      [payoutAddress(seller, mint).toBase58(), false, true],
      [payer.toBase58(), false, true],
      [TOKEN_PROGRAM_ID.toBase58(), false, false],
    ],
    'no signer: anyone may send it; the seller paid at its standard account',
  )
  const toBuyer = timerReleaseIx({ account: escrowAccount({ ...funded, timer: { days: 3, to: 'buyer' } }) })
  assert.deepEqual(toBuyer.keys[3].pubkey, refundAddress(buyer, mint))
  // An invoice's timer: its terms' address, its rent back to the payer.
  const invAccount = invoiceAccount({ ...funded, timer: { days: 1, to: 'seller' } })
  const inv = timerReleaseIx({ account: invAccount })
  assert.deepEqual([inv.keys[0].pubkey, inv.keys[3].pubkey, inv.keys[4].pubkey], [escrowAddress(termsOf(invAccount)), payoutAddress(seller, mint), payer])
  assert.throws(() => timerReleaseIx({ account: escrowAccount(funded) }), /NoTimer/)
  assert.throws(() => timerReleaseIx({ account: escrowAccount({ timer: { days: 3, to: 'seller' } }) }), /FundingNotMarked/)
  assert.throws(() => timerReleaseIx({ account: escrowAccount({ status: 'ended', timer: { days: 3, to: 'seller' } }) }), /Ended/)
  assert.throws(() => timerReleaseIx({ account: escrowAccount({ ...funded, timer: { days: 3, to: 'seller' }, objection: 'buyer', objectedAt: T0 }) }), /Objected/)

  // Due to the second, from the mark.
  const e = escrowAccount({ ...funded, timer: { days: 3, to: 'seller' } })
  assert.equal(timerDueAt(e), T0 + 3n * DAY)
  assert.equal(timerDue(e, T0 + 3n * DAY - 1n), false)
  assert.equal(timerDue(e, T0 + 3n * DAY), true)
  assert.equal(timerDueAt(escrowAccount({ timer: { days: 3, to: 'seller' } })), null, 'not marked')
  assert.equal(timerDueAt(escrowAccount(funded)), null, 'no timer')
  assert.equal(timerDueAt(escrowAccount({ ...funded, status: 'ended', timer: { days: 3, to: 'seller' } })), null, 'ended')
  const objected = escrowAccount({ ...funded, timer: { days: 3, to: 'seller' }, objection: 'seller', objectedAt: T0 + DAY })
  assert.equal(timerDueAt(objected), null, 'objected: never due')
  assert.equal(timerDue(objected, T0 + 1_000n * DAY), false)
})

test('pay in one tap, and an invoice in one tap: the deposit address made first, create unless the seller opened it, a transfer_checked of the amount, and the buyer\'s release', () => {
  const t = terms()
  const token = { mint, program: TOKEN_PROGRAM_ID, decimals: 6 }
  const k = keysFor({ buyer, payer, mint, terms: t })
  const ixs = payInOneTap({ buyer, payer, token, terms: t })
  assert.equal(ixs.length, 4)
  const [deposit, create, transfer, release] = ixs
  // The deposit address, made by the associated token program at the top of the transaction, the
  // payer paying: a fee payer that checks every transfer's destination finds it made.
  assert.deepEqual(deposit.programId, ASSOCIATED_TOKEN_PROGRAM_ID)
  assert.equal(hex(deposit.data), '01', 'the idempotent create')
  assert.deepEqual(meta(deposit), [
    [payer.toBase58(), true, true],
    [k.vault.toBase58(), false, true],
    [k.escrow.toBase58(), false, false],
    [mint.toBase58(), false, false],
    ['11111111111111111111111111111111', false, false],
    [TOKEN_PROGRAM_ID.toBase58(), false, false],
  ])
  assert.deepEqual(meta(deposit), meta(makeDepositAddressIx({ payer, escrow: k.escrow, mint })))
  assert.equal(hex(create.data), hex(createIx({ buyer, payer, mint, terms: t }).data))
  assert.deepEqual(meta(create), meta(createIx({ buyer, payer, mint, terms: t })))
  // transfer_checked: 12, the amount, the decimals; source, mint, destination, owner.
  assert.deepEqual(transfer.programId, TOKEN_PROGRAM_ID)
  assert.equal(hex(transfer.data), '0c' + '40420f0000000000' + '06')
  assert.deepEqual(meta(transfer), [
    [associatedTokenAddress(buyer, mint).toBase58(), false, true],
    [mint.toBase58(), false, false],
    [k.vault.toBase58(), false, true],
    [buyer.toBase58(), true, false],
  ])
  assert.deepEqual(meta(release), meta(releaseToSellerIx({ keys: k })))
  const from = Keypair.generate().publicKey
  assert.deepEqual(payInOneTap({ buyer, payer, token, terms: t, from })[2].keys[0].pubkey, from)

  // Funding in the same transaction without releasing: the same first three.
  const funded = createAndFund({ buyer, payer, token, terms: t })
  assert.deepEqual(funded.map(meta), ixs.slice(0, 3).map(meta))
  assert.deepEqual(createAndFund({ buyer, payer, token, terms: t, from })[2].keys[0].pubkey, from)

  // An invoice paid in one tap: the seller opened it, so no create; the deposit address made
  // first all the same, then the transfer of the amount and the buyer's release.
  const inv = invoiceAccount()
  const invKeys = keysOf(inv)
  assert.deepEqual(invKeys.escrow, k.escrow, 'an invoice of the same terms is at the same address')
  const paid = payInvoiceInOneTap({ escrow: inv, payer, token })
  assert.equal(paid.length, 3)
  const [invDeposit, invTransfer, invRelease] = paid
  assert.deepEqual(meta(invDeposit), meta(makeDepositAddressIx({ payer, escrow: invKeys.escrow, mint })))
  assert.equal(hex(invDeposit.data), '01', 'the idempotent create')
  assert.deepEqual(invTransfer.programId, TOKEN_PROGRAM_ID)
  assert.equal(hex(invTransfer.data), '0c' + '40420f0000000000' + '06')
  assert.deepEqual(meta(invTransfer), [
    [associatedTokenAddress(buyer, mint).toBase58(), false, true],
    [mint.toBase58(), false, false],
    [vaultAddress(invKeys.escrow, mint).toBase58(), false, true],
    [buyer.toBase58(), true, false],
  ])
  assert.deepEqual(meta(invRelease), meta(releaseToSellerIx({ keys: invKeys })))
  assert.deepEqual(meta(invRelease)[4], [payer.toBase58(), false, true], 'the rent back to the payer, not the seller who opened it')
  assert.deepEqual(payInvoiceInOneTap({ escrow: inv, payer, token, from })[1].keys[0].pubkey, from)
  assert.throws(() => payInvoiceInOneTap({ escrow: { ...inv, status: 'funded' }, payer, token }), /already funded/)
  assert.throws(() => payInvoiceInOneTap({ escrow: { ...inv, status: 'ended' }, payer, token }), /ended/)
  assert.throws(() => payInvoiceInOneTap({ escrow: inv, payer, token: { ...token, mint: stranger } }), /not the escrow's mint/)

  // The buyer's standard account, made when a way out pays the buyer.
  const make = makeRefundAddressIx({ payer, buyer, mint })
  assert.deepEqual(make.programId, ASSOCIATED_TOKEN_PROGRAM_ID)
  assert.deepEqual(make.keys[1].pubkey, refundAddress(buyer, mint))
  assert.equal(hex(make.data), '01')
})

test('late money and the rent sweep: their accounts, and what the builders refuse', () => {
  const ended = escrowAccount({ status: 'ended', outcome: 'releasedToSeller', endedAt: T0 })
  const ix = recoverLateIx({ account: ended, caller: stranger })
  assert.equal(hex(ix.data), '525629b57534cce3')
  const escrow = baseEscrow()
  assert.deepEqual(meta(ix), [
    [escrow.toBase58(), false, false],
    [ended.vault.toBase58(), false, true],
    [buyer.toBase58(), false, true],
    [refundAddress(buyer, mint).toBase58(), false, true],
    [mint.toBase58(), false, false],
    [stranger.toBase58(), true, true],
    [TOKEN_PROGRAM_ID.toBase58(), false, false],
    [ASSOCIATED_TOKEN_PROGRAM_ID.toBase58(), false, false],
    ['11111111111111111111111111111111', false, false],
  ])
  assert.throws(() => recoverLateIx({ account: escrowAccount(), caller: stranger }), /NotEnded/)
  // An invoice's late money: the same address, still back to the buyer.
  const late = recoverLateIx({ account: invoiceAccount({ status: 'ended', outcome: 'releasedToSeller', endedAt: T0 }), caller: stranger })
  assert.deepEqual([late.keys[0].pubkey, late.keys[2].pubkey, late.keys[3].pubkey], [baseEscrow(), buyer, refundAddress(buyer, mint)])
})

/** An escrow account's bytes, at the pinned offsets. */
function escrowBytes(o: {
  arbiter?: PublicKey
  rentRecipient?: PublicKey
  creator?: number
  timerDays?: number
  timerTo?: number
  fundedAt?: bigint
  status?: number
  endedAt?: bigint
  outcome?: number
  toSeller?: bigint
  toBuyer?: bigint
  payer?: PublicKey
  objection?: number
  objectedAt?: bigint
} = {}): Uint8Array {
  const data = Buffer.alloc(8 + ESCROW_LEN)
  Buffer.from(discriminator('account', 'Escrow')).copy(data, 0)
  const b = data.subarray(8)
  const escrow = baseEscrow()
  b[0] = 2
  b.writeBigUInt64LE(7n, 1)
  buyer.toBuffer().copy(b, 9)
  seller.toBuffer().copy(b, 41)
  ;(o.arbiter ?? PublicKey.default).toBuffer().copy(b, 73)
  mint.toBuffer().copy(b, 105)
  vaultAddress(escrow, mint).toBuffer().copy(b, 137)
  ;(o.rentRecipient ?? payer).toBuffer().copy(b, 169)
  b.writeBigUInt64LE(1_000_000n, 201)
  b[209] = o.creator ?? 0
  b.writeUInt16LE(o.timerDays ?? 0, 210)
  b[212] = o.timerTo ?? 0
  b.writeBigInt64LE(T0, 213)
  b.writeBigInt64LE(o.fundedAt ?? 0n, 221)
  b[229] = o.status ?? 0
  b[230] = 254
  b.writeBigInt64LE(o.endedAt ?? 0n, 231)
  b[239] = o.outcome ?? 0
  b.writeBigUInt64LE(o.toSeller ?? 0n, 240)
  b.writeBigUInt64LE(o.toBuyer ?? 0n, 248)
  ;(o.payer ?? payer).toBuffer().copy(b, 256)
  b[288] = o.objection ?? 0
  b.writeBigInt64LE(o.objectedAt ?? 0n, 289)
  return new Uint8Array(data)
}

test('the escrow account decodes at the pinned offsets', () => {
  assert.deepEqual(decodeEscrow(escrowBytes()), escrowAccount({ bump: 254 }))
  const e = decodeEscrow(
    escrowBytes({ arbiter, rentRecipient: seller, creator: 1, timerDays: 7, timerTo: 1, fundedAt: T0 + 60n, status: 2, endedAt: T0 + DAY, outcome: 4, toSeller: 1_000_003n, toBuyer: 0n, payer: stranger }),
  )
  assert.deepEqual(e, {
    ...escrowAccount({ bump: 254 }),
    arbiter,
    rentRecipient: seller,
    creator: 'seller',
    timer: { days: 7, to: 'seller' },
    fundedAt: T0 + 60n,
    status: 'ended',
    endedAt: T0 + DAY,
    outcome: 'timerReleased',
    toSeller: 1_000_003n,
    payer: stranger,
  })
  // The objection, by its byte: none 0, the buyer 1, the seller 2; its time only with it.
  assert.deepEqual([decodeEscrow(escrowBytes()).objection, decodeEscrow(escrowBytes()).objectedAt], [null, null])
  const byBuyer = decodeEscrow(escrowBytes({ objection: 1, objectedAt: T0 + 5n }))
  assert.deepEqual([byBuyer.objection, byBuyer.objectedAt], ['buyer', T0 + 5n])
  assert.equal(decodeEscrow(escrowBytes({ objection: 2, objectedAt: T0 })).objection, 'seller')
  assert.deepEqual(decodeEscrow(escrowBytes({ objection: 1, objectedAt: 0n })).objectedAt, 0n, 'objected at a zero clock still reads as objected')
  assert.throws(() => decodeEscrow(escrowBytes({ objection: 3 })), /objection/)
  // Each outcome, by its byte.
  const outcomes = ['releasedToSeller', 'releasedToBuyer', 'split', 'arbitrated', 'timerReleased']
  outcomes.forEach((name, i) => assert.equal(decodeEscrow(escrowBytes({ status: 2, outcome: i })).outcome, name))
  // A receipt always has a funding time in v2 (the program writes the ending's when nobody
  // marked it); the decoder reads a zero as none all the same.
  assert.equal(decodeEscrow(escrowBytes({ status: 2, fundedAt: T0 + DAY, endedAt: T0 + DAY })).fundedAt, T0 + DAY)
  assert.equal(decodeEscrow(escrowBytes({ status: 0 })).fundedAt, null)
  assert.equal(decodeEscrow(escrowBytes({ status: 1, fundedAt: T0 })).status, 'funded')
  // Refusals.
  assert.throws(() => decodeEscrow(escrowBytes().subarray(1)), /bytes/)
  const wrong = escrowBytes()
  wrong[0] ^= 1
  assert.throws(() => decodeEscrow(wrong), /not an escrow/)
  assert.throws(() => decodeEscrow(escrowBytes({ status: 3 })), /status/)
  assert.throws(() => decodeEscrow(escrowBytes({ status: 2, outcome: 5 })), /outcome/)
  assert.throws(() => decodeEscrow(escrowBytes({ creator: 2 })), /side/)
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
  const vault = vaultAddress(escrow, mint)
  const created = eventBytes('Created', 293, (b) => {
    b[40] = 2
    b.writeBigUInt64LE(7n, 41)
    buyer.toBuffer().copy(b, 49)
    seller.toBuffer().copy(b, 81)
    b[113] = 1
    arbiter.toBuffer().copy(b, 114)
    mint.toBuffer().copy(b, 146)
    vault.toBuffer().copy(b, 178)
    seller.toBuffer().copy(b, 210)
    b.writeBigUInt64LE(1_000_000n, 242)
    b.writeUInt16LE(3, 250)
    b[252] = 0
    b.writeBigInt64LE(T0, 253)
    payer.toBuffer().copy(b, 261)
  })
  const funded = eventBytes('Funded', 56, (b) => {
    b.writeBigUInt64LE(1_000_000n, 40)
    b.writeBigInt64LE(T0 + 60n, 48)
  })
  const ended = eventBytes('Ended', 129, (b) => {
    b[40] = 2
    b.writeBigUInt64LE(1_000_000n, 41)
    b.writeBigUInt64LE(1_000_003n, 49)
    b.writeBigUInt64LE(700_002n, 57)
    b.writeBigUInt64LE(300_001n, 65)
    b.writeBigInt64LE(T0 + DAY, 73)
    seller.toBuffer().copy(b, 81)
    b.writeBigUInt64LE(2_039_280n, 113)
    b.writeBigInt64LE(T0 + 60n, 121)
  })
  const closed = eventBytes('Closed', 120, (b) => {
    seller.toBuffer().copy(b, 40)
    b.writeBigUInt64LE(5n, 72)
    seller.toBuffer().copy(b, 80)
    b.writeBigUInt64LE(4_767_600n, 112)
  })
  const late = eventBytes('RecoveredLate', 56, (b) => {
    b.writeBigUInt64LE(400_000n, 40)
    b.writeBigUInt64LE(2_039_280n, 48)
  })
  const swept = eventBytes('RentSwept', 88, (b) => {
    payer.toBuffer().copy(b, 40)
    b.writeBigUInt64LE(2_455_488n, 72)
    b.writeBigUInt64LE(272_832n, 80)
  })
  const objected = eventBytes('Objected', 49, (b) => {
    b[40] = 1
    b.writeBigInt64LE(T0 + 30n, 41)
  })
  const id = PROGRAM_ID.toBase58()
  const logs = [
    `Program ${id} invoke [1]`,
    `Program data: ${created.toString('base64')}`,
    'Program log: something else',
    `Program data: ${funded.toString('base64')}`,
    `Program data: ${ended.toString('base64')}`,
    `Program data: ${closed.toString('base64')}`,
    `Program data: ${late.toString('base64')}`,
    `Program data: ${swept.toString('base64')}`,
    `Program data: ${objected.toString('base64')}`,
    'Program data: AAAA',
    `Program ${id} success`,
  ]
  assert.deepEqual(decodeEvents(logs), [
    {
      kind: 'created',
      escrow,
      version: 2,
      id: 7n,
      buyer,
      seller,
      creator: 'seller',
      arbiter,
      mint,
      vault,
      rentRecipient: seller,
      amount: 1_000_000n,
      timer: { days: 3, to: 'buyer' },
      createdAt: T0,
      payer,
    },
    { kind: 'funded', escrow, balance: 1_000_000n, fundedAt: T0 + 60n },
    {
      kind: 'ended',
      escrow,
      outcome: 'split',
      amount: 1_000_000n,
      balance: 1_000_003n,
      toSeller: 700_002n,
      toBuyer: 300_001n,
      endedAt: T0 + DAY,
      rentRecipient: seller,
      rentLamports: 2_039_280n,
      fundedAt: T0 + 60n,
    },
    { kind: 'closed', escrow, closedBy: seller, toBuyer: 5n, rentRecipient: seller, rentLamports: 4_767_600n },
    { kind: 'recoveredLate', escrow, toBuyer: 400_000n, rentLamports: 2_039_280n },
    { kind: 'rentSwept', escrow, payer, lamports: 2_455_488n, left: 272_832n },
    { kind: 'objected', escrow, by: 'seller', objectedAt: T0 + 30n },
  ])
  // A Created with no options.
  const bare = Buffer.from(created)
  PublicKey.default.toBuffer().copy(bare, 114)
  bare.writeUInt16LE(0, 250)
  const e = decodeEvent(new Uint8Array(bare))
  assert.ok(e?.kind === 'created' && e.arbiter === null && e.timer === null)
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
    b.writeBigUInt64LE(10_000_000_000n, 57)
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

test('terms come from a post\'s optional terms block: every option off unless set', () => {
  assert.deepEqual(optionsFromPost(undefined), { arbiter: null, timer: null })
  assert.deepEqual(optionsFromPost(null), { arbiter: null, timer: null })
  assert.deepEqual(optionsFromPost({}), { arbiter: null, timer: null })
  assert.deepEqual(optionsFromPost({ arbiter: arbiter.toBase58() }), { arbiter, timer: null })
  assert.deepEqual(optionsFromPost({ timer: { days: 7, to: 'seller' } }), { arbiter: null, timer: { days: 7, to: 'seller' } })
  // An old post's leftover keys pass and mean nothing.
  assert.deepEqual(optionsFromPost({ autoReleaseDays: 7, cancellationSteps: [] }), { arbiter: null, timer: null })
  for (const [what, bad, want] of [
    ['an arbiter that is not a key', { arbiter: 'not a key' }, /./],
    ['an arbiter that is not a string', { arbiter: 7 }, /base58/],
    ['the zero key', { arbiter: PublicKey.default.toBase58() }, /EmptyKey/],
    ['zero days', { timer: { days: 0, to: 'seller' } }, /whole number/],
    ['too many days', { timer: { days: 65_536, to: 'buyer' } }, /whole number/],
    ['half a day', { timer: { days: 0.5, to: 'buyer' } }, /whole number/],
    ['a timer to the arbiter', { timer: { days: 1, to: 'arbiter' } }, /seller" or "buyer/],
    ['a timer with no side', { timer: { days: 1 } }, /seller" or "buyer/],
  ] as const) {
    assert.throws(() => optionsFromPost(bad as never), want, what)
  }
  const t = termsFor({ arbiter: arbiter.toBase58(), timer: { days: 3, to: 'buyer' } }, { seller, amount: 5n, id: 9n })
  assert.deepEqual(t, { id: 9n, seller, amount: 5n, arbiter, timer: { days: 3, to: 'buyer' } })
  const fresh = termsFor(undefined, { seller, amount: 5n })
  assert.deepEqual([fresh.arbiter, fresh.timer], [null, null])
  assert.ok(fresh.id >= 0n)
})

test('before working or paying, a person sees every option they did not set', () => {
  const none = { arbiter: null, timer: null }
  // Nothing set, nothing there.
  assert.deepEqual(optionsNotAgreed({ escrow: escrowAccount(), me: 'seller', agreed: none }), [])
  assert.deepEqual(optionsNotAgreed({ escrow: escrowAccount(), me: 'buyer', agreed: null }), [])

  // The buyer names an arbiter and a one-day timer back to itself; the seller agreed to none.
  const rigged = escrowAccount({ arbiter: stranger, timer: { days: 1, to: 'buyer' } })
  assert.deepEqual(optionsNotAgreed({ escrow: rigged, me: 'seller', agreed: null }), [
    { option: 'arbiter', kind: 'added', arbiter: stranger },
    { option: 'timer', kind: 'added', timer: { days: 1, to: 'buyer' }, favours: 'otherParty' },
  ])
  // The same escrow, seen by the buyer who made it from its own post: nothing to show.
  const post = { arbiter: stranger.toBase58(), timer: { days: 1, to: 'buyer' as const } }
  assert.deepEqual(optionsNotAgreed({ escrow: rigged, me: 'buyer', agreed: post }), [])

  // An invoice with a shorter timer than the offer said, and a third-party arbiter the buyer
  // expected but another one named.
  const offer = { arbiter: arbiter.toBase58(), timer: { days: 7, to: 'seller' as const } }
  const invoiced = escrowAccount({ creator: 'seller', arbiter: stranger, timer: { days: 1, to: 'seller' } })
  assert.deepEqual(optionsNotAgreed({ escrow: invoiced, me: 'buyer', agreed: offer }), [
    { option: 'arbiter', kind: 'changed', arbiter: stranger },
    { option: 'timer', kind: 'changed', timer: { days: 1, to: 'seller' }, favours: 'otherParty' },
  ])
  // An option agreed and missing.
  assert.deepEqual(optionsNotAgreed({ escrow: escrowAccount(), me: 'buyer', agreed: offer }), [
    { option: 'arbiter', kind: 'removed', expected: arbiter },
    { option: 'timer', kind: 'removed', expected: { days: 7, to: 'seller' } },
  ])
  // A timer in the person's favour is still shown if not set.
  assert.deepEqual(optionsNotAgreed({ escrow: escrowAccount({ arbiter, timer: { days: 2, to: 'seller' } }), me: 'seller', agreed: none }), [
    { option: 'arbiter', kind: 'added', arbiter },
    { option: 'timer', kind: 'added', timer: { days: 2, to: 'seller' }, favours: 'me' },
  ])
  assert.throws(() => assertOptionsAgreed({ escrow: rigged, me: 'seller', agreed: null }), /arbiter not agreed: .*timer not agreed: 1 days to the buyer/)
  assertOptionsAgreed({ escrow: rigged, me: 'buyer', agreed: optionsFromPost(post) })
})

test('payouts: the whole balance, the seller\'s share of a split rounded down', () => {
  assert.deepEqual(payout(1_000_003n, 5_000), { toSeller: 500_001n, toBuyer: 500_002n })
  assert.deepEqual(payout(1_000_003n, 10_000), { toSeller: 1_000_003n, toBuyer: 0n })
  assert.deepEqual(payout(1_000_003n, 0), { toSeller: 0n, toBuyer: 1_000_003n })
  assert.deepEqual(payout(1n, 9_999), { toSeller: 0n, toBuyer: 1n })
  const max = (1n << 64n) - 1n
  const { toSeller, toBuyer } = payout(max, 7_777)
  assert.equal(toSeller + toBuyer, max)
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
  assert.throws(() => createIx({ buyer, payer, mint: NATIVE_MINT_2022, terms: terms(), tokenProgram: TOKEN_2022_PROGRAM_ID }), /NativeMint/)
})

test('under Token-2022 every address is derived with it and every instruction names it; hook accounts go last, never signing', () => {
  const t22 = TOKEN_2022_PROGRAM_ID
  const t = terms({ arbiter, timer: { days: 1, to: 'seller' } })
  const escrow = escrowAddress({ buyer, mint, terms: t })
  const vault = vaultAddress(escrow, mint, t22)
  assert.notDeepEqual(vault, vaultAddress(escrow, mint), 'another address than under the classic program')
  assert.deepEqual(vault, getAssociatedTokenAddressSync(mint, escrow, true, t22, ASSOCIATED_TOKEN_PROGRAM_ID))
  assert.deepEqual(refundAddress(buyer, mint, t22), getAssociatedTokenAddressSync(mint, buyer, false, t22, ASSOCIATED_TOKEN_PROGRAM_ID))
  assert.deepEqual(payoutAddress(seller, mint, t22), getAssociatedTokenAddressSync(mint, seller, false, t22, ASSOCIATED_TOKEN_PROGRAM_ID))

  const create = createIx({ buyer, payer, mint, terms: t, tokenProgram: t22 })
  assert.deepEqual([create.keys[1].pubkey, create.keys[5].pubkey], [vault, t22])
  const k = keysFor({ buyer, payer, mint, terms: t, tokenProgram: t22 })
  const account = escrowAccount({ vault, arbiter, status: 'funded', fundedAt: T0, timer: { days: 1, to: 'seller' } })
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
  const refund = refundAddress(buyer, mint, t22).toBase58()
  const sellers = payoutAddress(seller, mint, t22).toBase58()
  const head = [[escrow.toBase58(), false, true], [vault.toBase58(), false, true], [mint.toBase58(), false, false]]
  const tail = [[payer.toBase58(), false, true], [t22.toBase58(), false, false]]
  assert.deepEqual(meta(releaseToSellerIx({ keys: k, hookAccounts: hook })), [...head, [sellers, false, true], ...tail, [buyer.toBase58(), true, false], ...forwarded])
  assert.deepEqual(meta(releaseToBuyerIx({ keys: k, hookAccounts: hook })), [...head, [refund, false, true], ...tail, [seller.toBase58(), true, false], ...forwarded])
  assert.deepEqual(meta(splitIx({ keys: k, sellerBps: 1, hookAccounts: hook })).slice(9), forwarded)
  assert.deepEqual(meta(arbitrateIx({ keys: k, arbiter, sellerBps: 1, hookAccounts: hook })).slice(8), forwarded)
  assert.deepEqual(meta(closeUnfundedIx({ keys: k, closer: buyer, hookAccounts: hook })).slice(7), forwarded)
  const timer = timerReleaseIx({ account, tokenProgram: t22, hookAccounts: hook })
  assert.deepEqual(meta(timer), [...head, [sellers, false, true], ...tail, ...forwarded])
  const late = recoverLateIx({ account: { ...account, status: 'ended' }, caller: stranger, tokenProgram: t22, hookAccounts: hook })
  assert.deepEqual([late.keys[3].pubkey, late.keys[6].pubkey], [refundAddress(buyer, mint, t22), t22])
  assert.deepEqual(meta(late).slice(9), forwarded)

  // A wallet app's transfer_checked under Token-2022, hook accounts after its four.
  const pay = transferIx({ from: payer, to: vault, owner: buyer, mint, amount: 5n, decimals: 6, tokenProgram: t22, hookAccounts: [{ pubkey: arbiter, isSigner: false, isWritable: true }] })
  assert.deepEqual(pay.programId, t22)
  assert.equal(hex(pay.data), '0c' + '0500000000000000' + '06')
  assert.equal(pay.keys.length, 5)

  // The one tap under Token-2022, with each transfer's hook accounts in place.
  const token = { mint, program: t22, decimals: 6 }
  const [deposit, , fund, release] = payInOneTap({ buyer, payer, token, terms: t, hookAccounts: { fund: [hook[1]], release: [hook[0]] } })
  assert.deepEqual([deposit.keys[1].pubkey, deposit.keys[5].pubkey], [vault, t22])
  assert.deepEqual(fund.keys.map((m) => m.pubkey).slice(4), [arbiter])
  assert.deepEqual(meta(release).slice(7), [[stranger.toBase58(), false, false]])
})

test('a hook\'s accounts are resolved by spl-token\'s resolver: none without a hook program, each once, never signing', async () => {
  const t22 = TOKEN_2022_PROGRAM_ID
  const hookProgram = Keypair.generate().publicKey
  const listed = Keypair.generate().publicKey
  const k = keysFor({ buyer, payer, mint, terms: terms(), tokenProgram: t22 })
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
    [payoutAddress(seller, mint, t22).toBase58(), tokenAccount(seller)],
    [refundAddress(buyer, mint, t22).toBase58(), tokenAccount(buyer)],
  ])
  const reader = readerOf(accounts)
  const entry = (owner: PublicKey) => PublicKey.findProgramAddressSync([Buffer.from('holder'), owner.toBuffer()], hookProgram)[0]

  const both = await hookAccounts({ reader, mint, transfers: payoutTransfers(k, ['seller', 'buyer']) })
  const byKey = new Map(both.map((m) => [m.pubkey.toBase58(), m]))
  assert.equal(both.length, 6, 'the program, the listed key, the counter, an entry per destination owner, the validation account')
  for (const [key, writable] of [[hookProgram, false], [listed, false], [counter, true], [entry(seller), false], [entry(buyer), false], [validation, false]] as const) {
    assert.deepEqual([byKey.get(key.toBase58())?.isWritable, byKey.get(key.toBase58())?.isSigner], [writable, false], key.toBase58())
  }

  // A payment into a deposit account the same transaction makes: read as planned.
  const fund = { source: payer, destination: k.vault, authority: buyer }
  await assert.rejects(hookAccounts({ reader, mint, transfers: [fund] }), 'the deposit account is not on the chain yet')
  const planned = await hookAccounts({ reader, mint, transfers: [fund], planned: [{ address: k.vault, owner: k.escrow, mint, tokenProgram: t22 }] })
  assert.ok(planned.some((m) => m.pubkey.equals(entry(k.escrow))))

  // No hook program named, a classic mint, or no mint: nothing to forward.
  accounts.set(mint.toBase58(), { owner: t22, data: mintBytes([hookExtension(null)]) })
  assert.deepEqual(await hookAccounts({ reader, mint, transfers: payoutTransfers(k, ['seller']) }), [])
  accounts.set(mint.toBase58(), { owner: TOKEN_PROGRAM_ID, data: mintBytes(null) })
  assert.deepEqual(await hookAccounts({ reader, mint, transfers: payoutTransfers(k, ['seller']) }), [])
  accounts.delete(mint.toBase58())
  assert.deepEqual(await hookAccounts({ reader, mint, transfers: payoutTransfers(k, ['seller']) }), [])
})
