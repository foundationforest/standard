# Security checklist: the Forest escrow

Written with the safe-solana-builder skill (Frank Castle's, copied unchanged into this repo while
the programs were written, and in its git history since): every rule in its
`references/shared-base.md` (sections 1 to 31), `references/anchor.md` and `references/litesvm.md`,
how this program applies it or why it does not apply, and every limit known today. The program is
`program/src/`; the tests named here are in `program/tests-litesvm/tests/` and
`program/trident-tests/`. Devnet only: nothing here is shipped or on mainnet, and no paid review
has happened.

This program writes version 2 into every escrow. Version 1, an earlier program with classic tokens
only and no objection, is no longer in this repo; its source and its own checklist are in git
history.

| | |
|---|---|
| Program | `forest_escrow`, version byte 2, `FoRE2EscrowV2objectsTimerFundedAtPayer222222` for local work, `FA6ZodkyhMDj9yjzY27dk8JDCtcHnJx8mr45Mx9TfKg8` on devnet, upgraded in place three times (its first deploy, classic only, at `B3p13G8xvNvUrAnaXg9AUtwffBAUHcp6XoMwGV2jKPi7`, closed) |
| Framework | Anchor 1.2 with `anchor-spl`'s token interface, `cargo build-sbf --arch v3` (Solana CLI 4.2.2, platform-tools v1.54), no IDL, no build warning |
| Testing | LiteSVM, 91 tests on every pull request: 67 on a classic mint, 24 on Token-2022 mints (one made with Open USD's mainnet extensions compared with the mainnet account's bytes; others with one extension each), with a builtin test hook and a builtin spy standing in for Token-2022; a mutation check of each rule added after version 1, the terms in the address included (removing it fails at least one test). A Trident fuzzer: fifteen invariants, 50,000 iterations nightly, on an SBPF v0 build and a classic mint. On devnet: five deals through the client, three of them in a Token-2022 dollar with Open USD's extensions, and a non-transferable mint's `create` refused there. **No local-validator test** |
| Risk level | 🟡 Medium by the skill's table (an escrow: token transfers, basic CPI, PDAs, no admin). Treated as 🔴 **Critical**, because it is sealed at deploy and holds other people's money, so this checklist carries a High-Risk Decisions section |
| Upgrade authority | Removed at mainnet deploy with `solana program set-upgrade-authority --final` (`README.md`). No admin key, no config, no pause, no fee. A change is a new program at a new address. On devnet the authority stays on the deploy key |

## High-risk decisions

Each is on purpose, and none can be changed after deploy.

1. **Sealed.** No upgrade, no pause, no admin. A bug found after deploy stays in every escrow made
   on this program; the only remedy is a new program for new deals.
2. **The creator sets a release gate** (skill §29.2 says release gates should be protocol-defined).
   The timer is chosen at creation by whichever party opens the escrow: any number of whole days
   from 1 to 65,535, to either side. It is off by default, it is in the account and the `Created`
   event, and the other side sees it before working or paying (the client's `optionsNotAgreed`).
   Once the funding is marked it cannot be moved: `mark_funded` runs once, and the timer counts
   from that moment only (§31.7). Either side can turn it off (7).
3. **The arbiter is never a party, and may be any other key.** `create` refuses the buyer's or the
   seller's key as arbiter (`ArbiterIsAParty`): a party as arbiter could split any way alone, and so
   take everything. Who holds any other key, the program cannot tell: a party can name a key it holds.
   The other side sees every arbiter it did not agree to before working or paying
   (`optionsNotAgreed`). Pinned by `the_arbiter_cannot_be_the_buyer_or_the_seller`.
4. **Every way out pays the whole balance.** No excess rule: a payment above the amount goes where
   the rest goes. Pinned by `finding_an_overpayment_goes_wherever_the_way_out_sends_the_balance`.
5. **Anyone may send `mark_funded`, `timer_release`, `recover_late` and `sweep_rent`.** Each moves
   money or lamports only to destinations fixed at creation (the standard account of the side the
   timer names, the buyer's standard account, the payer), and needs no signature.
6. **Any mint of either token program is accepted,** but for those in 9, including one the buyer
   minted itself; which tokens count is the index's call. Pinned by
   `finding_a_self_minted_token_makes_a_receipt_that_looks_like_real_money`.
7. **Either party can turn the timer off, alone.** An objection before the timer is due ends it for
   good. So a timer guarantees the side it names nothing: it pays that side only if the
   other side stays silent until it is due. After an objection with no arbiter named, the money
   moves only when the parties agree; each side alone can still give (release everything to the
   other), so the program never strands it, but neither side can take it.
8. **Every rent goes back to whoever fronted it, not to the person who opened the escrow.** The
   deposit account's at every ending, both at `close_unfunded`, and what a sweep takes, all to the
   payer recorded at creation, which `create` also records as the rent recipient. When a fee payer
   fronts the rent and charges the person for it, it gets the rent back too. Intended: the fee payer
   keeps what it fronted and says so plainly to people. See Known limit 14.
9. **Any Token-2022 mint without a transfer fee that can be transferred, the powers of the token's
   maker included.** The skill says to refuse a permanent delegate, an outside freeze authority and
   confidential transfers (§23.1), and a mint close authority (§17). The program refuses only the
   transfer fee, non-transferable mints and wrapped SOL; everything else the dollar's maker can do
   is the maker's, each listed here (Known limits 16 to 21).
   Open USD has every one: a permanent delegate that can empty any deposit account, a freeze
   authority, pause, a hook it can name at any time, a close authority. Known limits 16 to 21.
10. **A hook's accounts are forwarded unchecked, and never signing.** Every way out passes the
   accounts after its own to each `transfer_checked`, as a pool Token-2022 picks the hook's accounts
   from by address; the escrow checks none of them (§9.3 asks for it), and passes each without a
   signature (§5.3). Known limit 22.

## Shared base, sections 1 to 31

### 1. Account and identity validation

- **1.1 Signer checks. Applied.** Every authority is an Anchor `Signer`: the creator, one of the
  two parties the terms name, and the payer (`create`), the buyer (`release_to_seller`,
  `split`), the seller (`release_to_buyer`, `split`), the arbiter (`arbitrate`), the closer
  (`close_unfunded`), the objecting party (`object`), the caller (`recover_late`, who pays for an
  account). Each is then compared to the key recorded at creation, in the handler, with its own
  error (`NotTheBuyer`, `NotTheSeller`, `NotTheArbiter`, `NotACloser`, `NotAParty`,
  `NotAnObjector`). `mark_funded`, `timer_release` and `sweep_rent` take no signer by design.
  Tested for every instruction by `the_wrong_signer_is_refused_for_every_instruction`, `object` by
  a stranger, the arbiter, the payer and the buyer's key unsigned by
  `a_stranger_the_arbiter_or_the_payer_cannot_object`, and in the fuzzer by I5, I7 and I15; the
  creator's signature at `create` by `the_escrow_address_is_its_terms_and_only_a_party_opens_it`
  and fuzzer I13.
- **1.2 Ownership checks. Applied.** The escrow is `Account<Escrow>` everywhere, `object`
  included (owned by this program). The mint and every token account are `InterfaceAccount`s,
  owned by the classic program or Token-2022; the mint must be owned by the token program named
  (`mint::token_program`, on every instruction that names a mint), and the token program must be
  one of the two (`Interface<TokenInterface>`). The other programs are `Program<…>`. The unchecked
  accounts are listed under anchor.md §1.1 below, each with why it is safe. The classic program
  named for a Token-2022 mint, or the other way round, is refused
  (`only_the_mints_token_program_and_the_standard_accounts_under_it`,
  `substitution_payout_accounts_of_the_wrong_mint_owner_or_program_are_refused`,
  `substitution_an_escrow_shaped_account_owned_by_another_program_is_refused`).
- **1.3 Account data matching. Applied.** `has_one = vault`, `has_one = mint` and
  `has_one = rent_recipient` on every way out and `close_unfunded`; `has_one = vault` on
  `mark_funded`; `has_one = vault`, `has_one = buyer` and `has_one = mint` in `recover_late`;
  `has_one = payer` in `sweep_rent`. The buyer's account by `address = escrow.refund_address(..)`,
  the seller's by `address = escrow.payout_address(..)`, each derived under the token program
  named, which is the mint's; the timer's one account by the same two addresses, by side, in the
  handler. A sweep to the creator, the seller or a thief is refused. Tested by the
  `substitution_…` tests, `a_payout_lands_only_at_the_receiving_partys_standard_account`,
  `sweep_pays_only_the_recorded_payer_and_only_from_an_escrow`,
  `a_sweep_returns_rent_above_the_minimum_to_the_payer_and_never_goes_below_it` and
  `every_rent_goes_back_to_the_payer`.
- **1.4 Type cosplay. Applied.** Anchor's eight-byte discriminator on `Escrow` (`account:Escrow`,
  the same as version 1's, at another size; each program accepts only accounts it owns, so neither
  can read the other's). Token accounts and the mint by owner, length and initialized state, as
  `InterfaceAccount` unpacks them.
- **1.5 Reinitialization. Applied.** `init` on the escrow account. An escrow that held the amount is
  never closed, so its address can never be opened again; one that never held it is closed whole.
  `init_if_needed` is used twice, both justified under anchor.md §2.4. Tested by
  `reinit_create_on_a_live_escrow_is_refused` and
  `reinit_an_ended_escrows_address_never_holds_a_second_deal`.
- **1.6 Writable checks. Applied.** Every account the program writes is `mut`; the deposit account
  is read-only in `mark_funded`, the escrow read-only in `recover_late`; `object` writes only the
  escrow, and the party is read-only.

### 2. PDAs

- **2.1 Canonical bumps. Applied.** `seeds` and `bump` at `init` find the canonical bump; it is
  stored in `bump` and used for every signature after. The escrow account is trusted afterwards by
  owner and discriminator, which only this program can produce at an address it derives.
- **2.2 PDA sharing. Applied.** One escrow per `["escrow", terms_hash]`, the SHA-256 of every term,
  both parties' keys among them, computed by the program from what `create` carries and the mint;
  its deposit account is its own associated token account. No shared vault. Every signature the
  escrow makes uses the same seeds, the hash rebuilt from the terms the account stores
  (`Escrow::terms_hash`), which `create` writes exactly as it hashed them (`CreateArgs::options`).
- **2.3 Seed collisions. Applied.** The seeds are a fixed tag and one 32-byte hash of the terms,
  each term at a fixed length (147 bytes in all), so two different sets of terms share an address
  only if SHA-256 collides. No arbiter is the zero key and no timer is 0 days, which `create` refuses
  as named options, so each set of terms it accepts has one encoding. Pinned by
  `every_term_is_in_the_address`, and by one fixed vector asserted in the harness and the client
  (`the_address_of_fixed_terms_is_the_clients`). Version 1's program id differs from this one's,
  so the same seeds land at different addresses under the two; the registry's seeds never collide
  with these (`pda_the_two_programs_cannot_share_an_address`).
- **2.4 Purpose isolation. Applied.** One PDA type.

### 3. Arithmetic and logic

- **3.1 Checked math. Applied.** A split is computed in 128 bits (`share`: a 64-bit balance times at
  most 10,000 cannot overflow), the buyer's part by `checked_sub`, the timer by `checked_add`
  (`TimeOverflow`). `Closed`'s rent sum uses `saturating_add`: two accounts' lamports cannot reach
  `u64::MAX`. `sweep_rent` uses `saturating_sub`, where a floor of zero is the rule (nothing to
  sweep). `object` adds no arithmetic: it compares `now` with `timer_due`. `overflow-checks = true`
  in the release profile. Tested at 1 base unit and at `u64::MAX` by
  `arithmetic_splits_at_the_edges_add_up_and_never_overflow`.
- **3.2 Multiply before divide. Applied** in `share`.
- **3.3 Slippage. Does not apply:** nothing is priced or swapped. The nearest thing, a split's
  percentage, is signed by the parties or the arbiter named at creation.
- **3.4 Lamport balance. Applied.** Every rent to the payer recorded at creation: the deposit
  account's at every ending, both at `close_unfunded`, the excess above the escrow account's minimum
  at `sweep_rent`; a re-created deposit account's to the buyer. Each destination is recorded at
  creation. The sweep subtracts from the escrow and adds to the payer, then asserts the escrow holds
  exactly its minimum. Tested with a sponsor that is neither party nor the transaction's fee payer,
  to the lamport (`every_rent_goes_back_to_the_payer`), and by
  `close_unfunded_after_a_sweep_returns_every_rent_to_the_payer`;
  fuzzer I3 names the wrong key in each rent slot now and then and expects a refusal.

### 4. Duplicate mutable accounts

**Applied.** Anchor 1.2 refuses duplicate mutable `Account` fields, and skips `UncheckedAccount`.
The unchecked ones are pinned by address or by `has_one`, and no two of them can be the same
account: the buyer's and the seller's standard accounts are two different derivations (buyer and
seller differ), the rent recipient is the payer, a key that signed `create` and so is not either of
those program-derived addresses, nor the escrow, nor its deposit account. A buyer's standard account
cannot fill both payout slots: the seller's slot takes only the seller's own standard address. The
rent recipient may be the same key as a signer (a party that fronted its own rent); the runtime
passes one account for both, and it only receives lamports. In `sweep_rent` the payer cannot be the
escrow (the payer signed `create`; the escrow is a program-derived address and cannot sign). The
payer may be the creator, or the transaction's fee payer; it only receives lamports.

### 5. CPIs

- **5.1 Program ids. Applied.** The only programs the escrow calls are the token program, one of
  the two by `Interface<TokenInterface>` and the mint's own by `mint::token_program`, and, at
  `create` and `recover_late`, the associated token and system programs, fixed. A hook is called
  by Token-2022, never by the escrow; which hook is up to the dollar's maker (High-risk decision 9).
- **The transfer, by hand.** Anchor's `token_interface::transfer_checked` passes only its four
  accounts, which a mint with a hook refuses. `transfer_out` builds the same instruction with
  `spl_token_2022::instruction::transfer_checked` (it takes either program's id), appends the hook
  accounts, and signs as the escrow.
- **5.2 Reload after CPI. Applied:** no decision reads an account a CPI changed. The deposit
  account's lamports are read before its close, and token transfers do not change lamports.
- **5.3 Signer pass-through. Applied.** Each forwarded account goes to the token program with
  `is_signer: false`, whatever the transaction marks: a party's signature, a fee payer's, never
  reaches the token program or a hook through the escrow. The escrow's own signature is the
  authority's, and Token-2022 passes the authority to a hook as a plain account. Tested with a
  spy in Token-2022's place that refuses any signature after the authority, handed the seller and
  the fee payer as signing accounts (`the_escrow_hands_the_token_program_no_signature_but_its_own`),
  and with a hook listing the seller as a signer, the client marking it so and the seller signing
  (`a_hook_that_asks_for_a_signature_gets_none`). Removing the rule fails the first.
- **5.4 SOL around CPI. Applied:** the named signers (buyer, seller, arbiter, closer) are never
  passed to the token program, and forwarded accounts carry no signature, so no CPI can spend from
  them. Anchor's own rent transfers at `init` take from the payer, who signed for them.
- **5.5 Post-CPI ownership. Does not apply:** no account the escrow reads after a transfer can be
  reassigned by it; the escrow account is the program's own and a hook cannot write it.
- **5.6 Errors propagate. Applied:** every CPI ends in `?`.
- **5.7 `invoke_signed` only for PDAs. Applied:** only the escrow signs, for its own deposit account.
- **5.8 Isolation. Applied:** a deposit account per escrow; an exploit of one escrow reaches no other.
- **Reentrancy.** A hook cannot call back into the escrow while it runs: the runtime refuses
  reentry except a program calling itself directly.
- **Writability.** Forwarded accounts keep the writability they came with; the test hook writes a
  counter it owns only because it arrives writable
  (`every_hook_account_is_needed_and_each_keeps_its_writability`). Removing it fails that test and
  ten others.
- `object` makes no CPI.

### 6. Storage and lifecycle

- **6.1 Sizing. Applied.** `Escrow::LEN` = 297 (version 1's 256, then 32 + 1 + 8), written field by
  field with a compile-time assertion; the space is `8 + LEN`, and the harness asserts it on every
  read.
- **6.2 Rent exemption. Applied.** `init` funds the minimum; `sweep_rent` leaves exactly it, and
  refuses when the account is at or below it (`NothingToSweep`). Tested by
  `a_sweep_returns_rent_above_the_minimum_to_the_payer_and_never_goes_below_it`; fuzzer I10.
- **6.3 Closing. Applied.** `close = rent_recipient` (the payer) for the escrow account in
  `close_unfunded` (zeroed, drained, reassigned); the deposit account by the token program's
  `close_account`. A receipt is never closed, by design. Tested with `assert_closed` (no lamports,
  no data, owned by the system program).
- **6.4 Sysvars. Applied:** `Clock::get()` and `Rent::get()`, never an account passed in.

### 7. Token-2022

**Applied.** Every payment out is a `transfer_checked` with the mint and its decimals, read from the
mint at each transfer, under the mint's own token program; every close is `token_interface`'s,
which takes either program. Token-2022's extensions expand the surface: see §23 and High-risk
decisions 9 and 10.

### 8. Transaction model

- **8.1 Atomicity. Applied.** One-tap Pay is the deposit address made, `create`, a transfer and
  `release_to_seller` in one transaction; two ways out in one transaction revert together
  (`an_escrow_ends_once`); an objection and the timer in one transaction, in either order, too
  (`an_objection_from_the_moment_the_timer_is_due_is_refused`); and two objections
  (`an_escrow_takes_one_objection`).
- **8.2 Compute. Applied.** No loop over input beyond the two payouts and the hook accounts each
  carries. The heaviest transaction measured under LiteSVM is a one tap whose mint names a hook
  with two accounts, about 99,000 units (`README.md`); `object` is about 4,000.
- **8.3 Address lookup tables. Does not apply.**
- **8.4 Durable nonces. Does not apply.**

### 9. Safe Rust

- **9.1 `vec![0; N]`. Does not apply** to the program.
- **9.2 No `unsafe`. Applied.**
- **9.3 `remaining_accounts`.** The ways out and `recover_late` take them and do one thing with
  them: forward them to the token program's `transfer_checked`, without signature, never reading
  them. They are not checked for owner or type (High-risk decision 10): Token-2022 resolves the
  hook's accounts from the hook's own list by address and ignores the rest, and the classic
  program ignores them all. An account passed that no one asked for is harmless
  (`every_hook_account_is_needed_and_each_keeps_its_writability`).
- **9.4 No `unwrap` or `expect` on input. Applied:** none in the program. The one cast is
  `share`'s 128-to-64-bit narrowing of a value no greater than the balance.

### 10. The curiosity principle

**Applied** as `adversarial.rs` and `objection.rs`: the same account twice, another program's
account, a mint under the wrong token program, a look-alike deposit account, another escrow's
deposit account, a replayed signature, a timer marked and fired together, a front-run address; an
objection at the due second and after it, beside the timer in one transaction in both orders,
twice in one transaction, by a key that is both arbiter and seller, before any money, on an escrow
with no timer, on one whose funding nobody marked.

### 11. Oracles. Does not apply.

### 12. Fees. Does not apply: the escrow charges nothing.

### 13. Dust and time-limited accounts

**Applied.** Dust cannot block a close: every way out pays the whole balance before the deposit
account closes, and `close_unfunded` returns whatever is there. Money sent to a closed never-funded
escrow's address waits for an escrow with exactly those terms, which either party can open, and
which adopts it. Nothing expires, so
nothing needs closing by a stranger: a never-funded escrow can be closed by either party at any
time; a funded one is the parties' money and ends only by their ways out. Whoever fronted the rent
cannot close anything. An objection blocks no close: `close_unfunded` runs on an objected,
part-paid escrow (`an_objection_before_the_money_or_the_mark_turns_the_timer_off_all_the_same`).
`init_if_needed` is justified under anchor.md §2.4.

### 14. Coupled fields. Applied.

One helper, `end`, writes status, `ended_at`, outcome, both amounts, and `funded_at` when nobody
marked it, together, for every way out. `mark_funded` writes the status and the time together;
`object` writes the objection and its time together.

### 15. Shared positions and pools. Does not apply.

### 16. Clock. Applied.

One unit, unix seconds; days are `× 86,400` in one place (`Escrow::timer_due`), which both `object`
and `timer_release` read.

### 17. Mint integrity. By decision.

A mint with a close authority is accepted (High-risk decision 9): Open USD has one. It can be
closed only when nobody holds any of that dollar, so never while a deposit account holds some;
decimals are read from the mint at every transfer, not stored. A mint's freeze authority is under
Known limits.

### 18. Input validation

**Applied:** amount above zero, timer days above zero (the `u16` bounds the top), no zero keys,
buyer and seller different, creator a party, the arbiter neither party (`ArbiterIsAParty`), neither
party the escrow's own address or its deposit address (`PartyIsTheEscrow`: neither can ever sign,
so a party named as either could never give, agree or be paid; since the address is a hash of both
parties, a party equal to it would need a SHA-256 fixed point, so the check cannot fire and stays
as version 1 wrote it, untested), the mint owned by the token
program named, not wrapped SOL of either program, no transfer fee, transferable. No strings. Any
other mint is accepted by decision (High-risk decisions 6 and 9). `object` takes no arguments.
Tested by `bad_terms_are_refused_at_creation` and `the_arbiter_cannot_be_the_buyer_or_the_seller`
(from either creator); fuzzer I14.

### 19. Type narrowing. Applied.

Instruction arguments, state and events use the same types (u64 amounts, u16 days and basis
points, i64 times, `objected_at` included); the one narrowing is bounded (9.4).

### 20. Events. Applied.

Seven fixed-size events with every amount: `Created`, `Funded`, `Objected`, `Ended`, `Closed`,
`RecoveredLate`, `RentSwept`. `Ended` carries `funded_at`, `RentSwept` the payer, `Objected` the
side and the time. The receipt keeps the same numbers in the account, so nothing depends on logs
alone. The client counts an event only when the runtime's own log lines say the escrow program
wrote it.

### 21. Reward accounting. Does not apply.

### 22. Withdrawal paths. Applied.

Every token that enters a deposit account has a way out: a funded one by the ways out, an
unfunded one by `close_unfunded`, a late one by `recover_late`. Fuzzer I11 ends every live escrow
with the parties' signatures alone at the end of every run, and I9 returns every late payment. An
objection removes one way out (the timer) and no other: after one, each party alone can still end
a funded escrow by giving, both can split, the arbiter can decide, and an unfunded one still closes
(`after_an_objection_the_parties_agreeing_or_the_arbiter_end_it`). With Token-2022, a mint's
permanent delegate can also take money out of a deposit account (Known limits 17 and 18); an escrow
that then holds less than its amount still has a way out, `close_unfunded`
(`the_permanent_delegate_can_take_the_money_and_the_escrow_then_ends_only_by_close`). **Not
covered:** tokens of another mint sent to the escrow's address (Known limit 9).

### 23. Token-2022 extensions. Applied, by decision.

- **Refused at `create`:** the transfer fee and the confidential transfer fee extensions
  (`TransferFee`), any rate, since the rate can be raised later; §21.6's delta accounting is
  therefore never needed. The non-transferable extension (`NonTransferable`): no payment in, and
  what the token's maker mints into a deposit account could never leave. Token-2022's wrapped SOL, by
  address (`a_transfer_fee_mint_is_refused_at_create`, `a_non_transferable_mint_is_refused_at_create`,
  `wrapped_sol_of_either_token_program_is_refused`). Removing the non-transferable rule fails its test.
- **Accepted, as the powers of the dollar's maker** (High-risk decision 9): permanent delegate,
  freeze authority, pause, default account state, transfer hook, mint close authority, confidential
  transfers, metadata and its pointer; and every extension Open USD does not have (Known limits).
  Each tested as Open USD has it: `the_issuer_can_pause_every_transfer`,
  `the_issuer_can_freeze_a_deposit_account_or_a_partys_account`,
  `the_issuer_can_make_new_accounts_start_frozen`,
  `the_permanent_delegate_can_take_the_money_and_the_escrow_then_ends_only_by_close`,
  `a_hook_switched_on_after_funding_is_honoured_by_forwarding_its_accounts`.
- **Transfer hooks:** forwarded, §5.
- **Account extensions:** the deposit account is made by the associated token program under the
  mint's token program, which sizes it for the mint (immutable owner, hook and pause account
  extensions for Open USD: 179 bytes)
  (`a_deposit_account_is_made_under_token_2022_with_the_extensions_the_mint_requires`).

### 24. Access control

- **24.1 Lockups. Does not apply.**
- **24.2 Admin rotation. Does not apply:** there is no admin key, on purpose.

### 25. Stack frames. Applied.

`cargo build-sbf` reports no stack-offset warning; every instruction runs under LiteSVM and on devnet.

### 26. State machine and lifecycle

- **26.1 Sentinel timestamps. Applied.** Neither a zero `funded_at` nor a zero `objected_at` is ever
  read to decide anything: the timer reads the `Funded` status, the ending reads the status to
  decide whether to write the funding time, and the objection has its own byte (`Objection`), so
  an objection made at a zero clock still counts.
- **26.2 One cleanup for every terminal path. Applied:** `pay_out` then `end`, for all five ways
  out; `end` also writes the funding time, once, for all of them.
- **26.3 Zero after draining. Applied:** the deposit account is closed after the payout, and the
  token program refuses to close it while anything is left, so an ending that does not pay the
  exact balance reverts whole.
- **26.4 Allowlists. Applied:** `live()` is open or funded; `mark_funded` needs open; `object`
  needs live; the timer needs funded and no objection; `recover_late` needs ended.
- **26.5 Sub-state. Applied.** The objection is kept apart from the status, and no transition
  resets it: it survives the mark and the ending, and is on the receipt
  (`after_an_objection_…`, `an_objection_before_the_money_…`; fuzzer I8 and I15).
- **26.6 One deadline source. Applied:** `timer_due` is the single deadline. `object` requires
  `now < due`; `timer_release` requires `now >= due`. At no second can both land, and at every
  second after the mark one of them can, until an objection lands
  (`either_side_objects_before_the_timer_is_due_and_then_the_timer_never_runs`,
  `an_objection_from_the_moment_the_timer_is_due_is_refused`; fuzzer I15, which moves the clock to
  a second either side of each due time).
- **26.7 Absorbing terminal state. Applied.** An ended escrow accepts only `recover_late` and
  `sweep_rent`, and neither changes its bytes; it refuses `object` as it refuses every way out.
  Tested by `an_escrow_ends_once`; fuzzer I4 and I8.

### 27. Slippage and fee ordering. Does not apply.

### 28. Bonding curves and AMMs. Does not apply.

### 29. Permissionless initialization and user parameters

- **29.1 Front-runnable initialization. Applied.** The escrow's address is `["escrow", terms_hash]`,
  computed by the program from every term, and only the buyer or the seller the terms name can sign
  `create`. So nobody else can open an escrow at a deal's address: a stranger with the same terms
  is refused (`NotAParty`), and naming itself a party changes the terms and so the address
  (`ConstraintSeeds` aimed at another's, `AccountNotSigner` without the key). Either party may open
  the same terms; the second finds the address taken (Known limit 30). Tested by
  `nobody_can_open_the_address_a_buyer_is_about_to_use`,
  `the_escrow_address_is_its_terms_and_only_a_party_opens_it` and fuzzer I13. Anyone can
  still make the escrow's deposit account first (the associated token program lets anyone), or pay
  into it early: `create` adopts it, and the one who did pays for nothing that is theirs.
- **29.2 User-controlled parameters. Applies, by decision:** High-risk decisions 2 and 7.
  Reachability holds: while an escrow is live, each party alone can always end it by giving (the
  buyer to the seller, the seller back to the buyer), whatever the options and whether or not
  anyone objected; fuzzer I11.
- **29.3 and 29.4, config. Do not apply:** there is no config.

### 30. Withdraw and drain. Applied.

Every way out drains the whole balance and closes the deposit account; nothing is reserved.

### 31. Miscellaneous

- **31.1 Shared config. Does not apply.**
- **31.2 Stack. See 25.**
- **31.3 Unclosed accounts lock rent. Applied as designed:** the deposit account closes at every
  ending; the receipt stays on purpose, and `sweep_rent` returns what the rent cuts free, to the
  payer.
- **31.4 Recipients that can receive and move tokens. Applied:** each party is paid at its
  standard account for the mint; each holder can move what it gets. A party who has handed that
  account to another key sends its own payouts there, and blocks nothing
  (`a_party_who_hands_its_standard_account_away_blocks_no_way_out`). The payer receives only
  lamports; see Known limit 8.
- **31.5 Token-2022 mint space. Applied:** the associated token program sizes the deposit account
  for the mint (§23).
- **31.6 Signer-as-new-account. Does not apply:** PDAs only. The PDA analogue is 29.1, applied.
- **31.7 Repeated actions resetting time. Applied:** `mark_funded` runs once (`AlreadyFunded`);
  `object` runs once (`AlreadyObjected`) and never moves the mark, so neither can restart or delay
  anything.

## anchor.md

- **§1.1 Account types.** Every unchecked account has a `/// CHECK:` comment:
  - `rent_recipient` (every way out, `close_unfunded`): the payer's key, recorded at creation as
    the rent recipient, by `has_one`; it only receives lamports.
  - `payer` (`sweep_rent`): the key that fronted the rent, recorded at creation, by `has_one`; it
    only receives lamports.
  - `buyer_tokens` (`release_to_buyer`, `split`, `arbitrate`, `close_unfunded`): the buyer's
    standard account, by address; the token program checks it when it pays it. Unchecked so it
    must exist only when the buyer is paid.
  - `seller_tokens` (`release_to_seller`, `split`, `arbitrate`): the seller's standard account, by
    address, the same way.
  - `to` (`timer_release`): checked in the handler, by address, against the standard account of the
    side the timer names.
  - `buyer` (`recover_late`): the recorded key, by `has_one`; it receives the re-created deposit
    account's rent.

  `object` has none. The mint and token accounts are `InterfaceAccount`s and the token program an
  `Interface<TokenInterface>`, as §4.1 asks.
- **§2.1 to 2.3 Constraints.** `has_one`, `mint::token_program`, `associated_token::` with
  `associated_token::token_program`, `address`, and `seeds` with `bump` at `init`.
- **§2.4 `init_if_needed`.** Used twice, each checked:
  - the deposit account at `create`: only the associated token program can make an account at that
    address, and only as a token account of that token program for this mint held by the escrow,
    whose authority only this program uses. So a pre-existing one can differ only in its balance,
    which is part of the deal;
  - the buyer's standard account at `recover_late`: Anchor checks its mint, holder and token
    program when it exists.
- **§2.5 `close`.** Used in `close_unfunded`, to the payer, recorded as the rent recipient.
- **§2.6 `realloc`. Not used.**
- **§3 State.** No reload needed (5.2); `init` once; checks in handlers rather than `access_control`,
  so each rule and its error sit in the instruction's own text.
- **§4 Tokens.** Either token program; `transfer_checked` built by hand (§5 above), since
  `token_interface::transfer_checked` drops a hook's accounts; decimals read from the mint.
- **§5 CPI.** `Interface<TokenInterface>`; seeds from the stored bump.
- **§6 Errors.** `#[error_code]` with a message on each of 32 errors: version 1's 25 at their
  numbers, then `NotAnObjector`, `AlreadyObjected`, `TimerDue`, `Objected`, `TransferFee`,
  `NonTransferable`, `ArbiterIsAParty`. The `require!` family throughout.
- **§8 Tooling.** Anchor 1.2 against platform-tools v1.54; `overflow-checks = true`; the features
  Anchor's macros test for (`custom-heap`, `custom-panic`, `anchor-debug`) are declared, so the
  build has no warnings.

## LiteSVM checklist (litesvm.md §9)

- **Happy path, with full state verified. Done:** every way out with exact token balances, rent,
  the receipt's fields and the event; the objection; the sweep to the payer; the funding time in
  the one tap, in the invoice paid in one tap and in a marked invoice; and under Token-2022 with
  Open USD's extensions, every way out, the one taps, a part payment closed and late money
  recovered, each with the hook naming no program and naming the test hook, which counts every
  transfer.
- **Wrong signer. Done:** for every instruction that takes a signer, `object` included.
- **Re-initialization. Done:** over a live escrow and over an ended one's address.
- **Before and after a deadline. Done:** the timer is refused a second early and runs at due, for
  both sides and at 65,535 days; the objection a second before the timer is due, at due, a second
  after; the timer a thousand days after an objection.
- **Over-limit arithmetic. Done:** `BadSplit` at 10,001 and 65,535, splits at 1 unit and at `u64::MAX`.
- **Closure verified. Done:** no lamports, no data, owned by the system program.
- **Token balances after every transfer. Done.**
- **PDA seeds written down. Done,** in the harness beside each derivation.
- **`expire_blockhash` after every transaction. Done** (`Harness::send_tx`).
- **Failures asserted without `unwrap`. Done** (`expect_err` and the error name).
- **Compute units logged. Done** for every instruction and the one taps. **Deviation:** each
  measuring test prints its own table rather than a `zz_cu_summary` test, so the table does not
  depend on the order tests run in.

What LiteSVM does not show is covered, in part, by the client's devnet script (five deals sent
through devnet). The fuzzer adds random flows, but Trident's runtime checks no signatures, so its
signer rules hold on key comparisons alone; LiteSVM checks the real signatures. There is no
local-validator test.

## Known limits

Each is reported, not fixed: fixing it would change a decided rule, or add one.

1. **A frozen token account.** A mint's freeze authority (USDC has one) can freeze, each pinned by
   a test:
   - the deposit account, which stops every way out until it is thawed, since each moves tokens out
     of it (`finding_a_frozen_deposit_account_blocks_every_way_out`);
   - the buyer's standard account, which stops every way out that pays the buyer anything; the ones
     that pay the buyer nothing still run (`finding_a_frozen_buyer_account_blocks_only_the_ways_out_that_pay_the_buyer`);
   - the seller's standard account, which, by the same rule, stops every way out that pays the
     seller anything (`finding_a_frozen_seller_account_blocks_only_the_ways_out_that_pay_the_seller`).
2. **Options nobody checked.** The program runs any option its creator set. A seller who works
   without reading the escrow can lose to a buyer's one-day timer to itself, and a buyer who pays
   without reading an invoice can lose to a one-day timer to the seller. `optionsNotAgreed` exists
   for this; the program cannot know what was agreed (`finding_an_invoice_with_a_short_timer…`,
   `finding_a_buyers_short_timer…`). An objection before the timer is due turns either off.
3. **A party key nobody controls.** `create` refuses the two it can see, the escrow's own address
   and its deposit address (`PartyIsTheEscrow`). Any other key nobody can sign for (a lost key,
   another program's address, some other token account) cannot be told apart, and a party named as
   one locks what it would be paid, as in any transfer. The app names parties by keys people hold.
4. **A part payment can be closed under the buyer** by the seller, at any time. The part comes
   back; a second part sent to the closed address waits for an escrow with exactly those terms,
   which the buyer can open, and close to get it back
   (`finding_a_part_payment_can_be_closed_under_the_buyer_by_the_seller`,
   `a_deposit_address_never_adopts_money_meant_for_other_terms`). Money sent to an address counts
   only toward a deal with exactly the terms it was made from
   (`a_payment_to_an_address_lands_only_in_a_deal_with_its_terms`); the program cannot tell whose
   money arrived, so a buyer still pays only an escrow it has read (the client's checks).
5. **An overpayment follows the balance** (High-risk decision 4).
6. **A party's standard account must exist to be paid.** A seller who has never held the token has
   none: whoever sends the way out makes it first, at their own cost
   (`makeStandardAccountIx`; anyone may). A timer to that seller waits until someone does.
7. **`recover_late` checks who holds the buyer's standard account** (Anchor's create-if-missing
   does), so a buyer who hands that account away blocks its own late money there, and nothing else
   (`finding_a_buyer_who_hands_its_standard_account_away_blocks_its_own_late_money`).
8. **SOL sent to an escrow's address** goes to the payer, by `sweep_rent` or with the rents at
   `close_unfunded`, not to whoever sent it;
   the program cannot tell it from rent. A sweep into a key that holds no SOL (a one-time sponsor
   key emptied) fails unless it leaves that key at least at the rent-exempt minimum of an empty
   account (128 bytes' worth); it can be sent again once more has built up.
9. **Tokens of another mint sent to an escrow's address** are lost to everyone: the escrow's
   associated token account for that mint has no way out, since nothing here signs for it.
10. **Self-minted tokens** make receipts of any size (High-risk decision 6).
11. **A one-sided receipt.** A buyer can release money to a seller who never signed anything, for one
    base unit. The receipt says the buyer created it, so an index can weigh it as one-sided.
12. **An objection makes the timer a default, not a promise** (High-risk decision 7). A seller who
    works under a timer to itself can have it turned off the day before it is due; a buyer who pays
    under a refund timer to itself can too. The client's `optionsNotAgreed` still reports the timer;
    what an app says about it is the app's.
13. **A deadlock holds the money.** With no arbiter, if neither side gives and they do not agree,
    the money stays in the deposit account for good: after an objection, or with no timer at all.
    Nothing in the program can break it.
14. **The fee payer gets every rent back, by decision.** When a fee payer signs as payer, every rent
    goes back to the fee payer's key, which already charged the person for it, in dollars. Intended:
    the fee payer keeps what it fronted and says so to people. A product that wants the person to
    get it back makes the person's own key the payer, which then needs SOL.
15. **An objection sent late may land after the deadline.** The chain's clock decides; the client's
    `canObject` reads the local clock.

Taking both token programs:

16. **The dollar's maker can stop an escrow**, by freezing its deposit account, pausing the dollar,
    making new accounts start frozen, or a hook that refuses; and can stop a party being paid by
    freezing that party's account. Nothing in the program routes around any of it.
17. **The dollar's maker can end the "held until the end" rule.** Only this program can move money
    out of a deposit account for a classic mint and a Token-2022 mint without a permanent delegate;
    with one, the delegate can take it at any time.
18. **A permanent delegate's escrow ends by `close_unfunded`.** Once it holds less than its amount,
    no release, split, arbitration or timer runs; a party closes it and the rest goes to the buyer,
    even if its funding was marked, and the receipt is gone with it.
19. **A closed mint strands an escrow that never held money.** Its ways out and `close_unfunded`
    need the mint, so its rent stays.
20. **Extensions Open USD does not have are accepted too,** but for non-transferable. An
    interest-bearing or scaled mint works on raw amounts: the escrow holds and pays base units, and
    only the displayed amount drifts, with time or when the token's maker changes the scale
    (`interest_bearing_and_scaled_mints_deal_in_raw_amounts_and_only_their_display_drifts`: 1.00
    shown as 1.051237 after a year at 5%, and as 3 instead of 2 after a rescale, paid as 1,000,000
    raw both times).
21. **A party can block its own payouts.** A standard account that requires a memo on incoming
    transfers is not paid until its owner turns that off: the escrow sends no memo.
22. **Hook accounts are the client's to find.** Missing ones fail the transfer and nothing moves.
    A hook that reads a destination's data cannot be resolved before that account exists: the
    client reads a deposit address the same transaction makes as planned. The test hook is a
    LiteSVM builtin, not an SBF program; Token-2022's resolution and the runtime's privilege checks
    are the real ones, and no dollar on devnet names a hook program.
23. **A hook uses up call depth.** The escrow calls Token-2022, which calls the hook; an escrow
    called from another program leaves the hook one level less of the runtime's limit.
24. **Wallet apps must pay in with `transfer_checked`.** Token-2022 refuses a plain transfer from an
    account with a hook extension, as Open USD's accounts have.

Testing and review:

25. **The fuzzer runs SBPF v0, on a classic mint.** The program builds, passes its tests and runs on
    devnet as SBPF v3 (`cargo build-sbf --arch v3`). Trident's runtime turns every feature off and
    runs only v0 programs, so the fuzzer runs a v0 build of the same source; its mint is a classic
    SPL Token mint, so Token-2022 is the LiteSVM tests' alone. There is no local-validator test:
    the devnet script is the client's only run against a real runtime.
26. **A fee payer pays only for what its configuration allows.** A fee payer pays for the escrow's
    transactions only if its configuration allows this program's id and Token-2022; that
    configuration lives in `foundationforest/services`.
27. **No Solana Pay link.** The client builds none: an app does. A Solana Pay recipient would be
    the escrow's own address, a program-derived address, which has not been tried in a wallet app
    on a phone.
28. **Unaudited.** No paid review, no lawyer pass.
29. **Refunds arrive in SOL,** to whichever key fronted the rent. How an app shows them to a person
    who fronted their own, without saying "SOL", is the app's choice and open.
30. **Either party can open the same terms.** The creator is not a term, so the buyer and the seller
    land at the same address with the same terms; whoever is second finds it taken, and a buyer's
    one tap fails whole if the seller opened those terms first. The app then pays the escrow already
    there, which has exactly the terms it meant
    (`the_escrow_address_is_its_terms_and_only_a_party_opens_it`).
