# Security checklist: the Forest escrow

Written with the safe-solana-builder skill (Frank Castle's, copied unchanged into this repo while
the programs were written, and in its git history since): every rule in its
`references/shared-base.md` (sections 1 to 31), `references/anchor.md` and `references/litesvm.md`,
how this program applies it or why it does not apply, and every limit known today. The program is
`program/src/`; the tests named here are in `program/tests-litesvm/tests/` and
`program/trident-tests/`. Devnet only: nothing here is shipped or on mainnet, and no paid review
has happened.

This program writes version 3 into every escrow: a schedule of windows, the payer and the
recipient. Version 2 (a timer, an objection, a buyer and a seller) ran at the same devnet id until
the upgrade to this one, and version 1 before it at another; their sources and checklists are in
git history.

| | |
|---|---|
| Program | `forest_escrow`, version byte 3, `FoRE3EscrowV3scheduLeWindowsPayRefund3333333` for local work, `FA6ZodkyhMDj9yjzY27dk8JDCtcHnJx8mr45Mx9TfKg8` on devnet, upgraded in place four times (its first deploy, classic only, at `B3p13G8xvNvUrAnaXg9AUtwffBAUHcp6XoMwGV2jKPi7`, closed) |
| Framework | Anchor 1.2 with `anchor-spl`'s token interface, `cargo build-sbf --arch v3` (Solana CLI 4.2.2, platform-tools v1.54), no IDL, no build warning |
| Testing | LiteSVM, 95 tests on every pull request: 71 on a classic mint, 24 on Token-2022 mints (one made with Open USD's mainnet extensions compared with the mainnet account's bytes; others with one extension each), with a builtin test hook and a builtin spy standing in for Token-2022; one of them sends every move in every state (`every_move_in_every_state`). A mutation check of each of the 17 rules version 3 added (each removed in turn fails at least one test), and of the hook rules, the non-transferable refusal and the terms in the address. A Trident fuzzer: seventeen invariants, 50,000 iterations nightly, on an SBPF v0 build and a classic mint. On devnet: seven deals through the client, two of them in a Token-2022 dollar with Open USD's extensions, and five refusals simulated there. **No local-validator test** |
| Risk level | 🟡 Medium by the skill's table (an escrow: token transfers, basic CPI, PDAs, no admin). Treated as 🔴 **Critical**, because it is sealed at deploy and holds other people's money, so this checklist carries a High-Risk Decisions section |
| Upgrade authority | Removed at mainnet deploy with `solana program set-upgrade-authority --final` (`README.md`). No admin key, no config, no pause, no fee. A change is a new program at a new address. On devnet the authority stays on the deploy key |

## High-risk decisions

Each is on purpose, and none can be changed after deploy.

1. **Sealed.** No upgrade, no pause, no admin. A bug found after deploy stays in every escrow made
   on this program; the only remedy is a new program for new deals.
2. **The creator sets the schedule** (skill §29.2 says release gates should be protocol-defined).
   The schedule is chosen at creation by whichever party opens the escrow: one to four windows,
   each with the share the payer may take back alone until its `until`, and a default to either
   side from the last one. It is off by default, it is in the address, the account and the
   `Created` event, and the other side sees it before working or paying (the client's
   `optionsNotAgreed`). Its times are dates fixed at creation: nothing restarts or moves them
   (§31.7). Either side can freeze it (7).
3. **The arbiter is never a party, and may be any other key.** `create` refuses the payer's or the
   recipient's key as arbiter (`ArbiterIsAParty`): a party as arbiter could split any way alone, and
   so take everything. Who holds any other key, the program cannot tell: a party can name a key it
   holds. The other side sees every arbiter it did not agree to before working or paying
   (`optionsNotAgreed`). Pinned by `the_arbiter_cannot_be_the_payer_or_the_recipient`.
4. **Every way out pays the whole balance.** No excess rule: a payment above the amount goes where
   the rest goes. Pinned by `finding_an_overpayment_goes_wherever_the_way_out_sends_the_balance`.
5. **Anyone may send `mark_funded`, `end`, `recover_late` and `sweep_rent`.** Each moves money or
   lamports only to destinations fixed at creation (the standard account of the side the default
   names, the payer's standard account, the sponsor), or none, and needs no signature.
6. **Any mint of either token program is accepted,** but for those in 9, including one the payer
   minted itself; which tokens count is the index's call. Pinned by
   `finding_a_self_minted_token_makes_a_receipt_that_looks_like_real_money`.
7. **Either party can freeze the schedule, alone.** A stop before the end time turns off the
   take-back and the default for good, for both sides. So a schedule guarantees neither side
   anything: the default pays its side only if the other side stays silent until the end time, and
   the payer's take-back lasts only until the recipient stops. After a stop with no arbiter named,
   the money moves only when the parties agree; each side alone can still give (everything to the
   other), so the program never strands it, but neither side can take it.
8. **Every rent goes back to whoever fronted it, not to the person who opened the escrow.** The
   deposit account's at every ending, both at `close_unfunded`, and what a sweep takes, all to the
   sponsor recorded at creation. When a fee payer fronts the rent and charges the person for it, it
   gets the rent back too. Intended: the fee payer keeps what it fronted and says so plainly to
   people. See Known limit 14.
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
  two parties the terms name, and the sponsor (`create`), the payer (`pay`, `take_back`, `agree`),
  the recipient (`refund`, `agree`), the arbiter (`decide`), the closer (`close_unfunded`), the
  stopping party (`stop`), the caller (`recover_late`, who pays for an account). Each is then
  compared to the key recorded at creation, in the handler, with its own error (`NotThePayer`,
  `NotTheRecipient`, `NotTheArbiter`, `NotAParty`). `mark_funded`, `end` and `sweep_rent` take no
  signer by design. Tested for every instruction by
  `the_wrong_signer_is_refused_for_every_instruction`, `stop` among them by a stranger, the
  arbiter, the sponsor and the payer's key unsigned, and in the fuzzer by I5, I7 and I15; the
  creator's signature at `create` by `the_escrow_address_is_its_terms_and_only_a_party_opens_it`
  and fuzzer I13.
- **1.2 Ownership checks. Applied.** The escrow is `Account<Escrow>` everywhere, `stop` included
  (owned by this program). The mint and every token account are `InterfaceAccount`s, owned by the
  classic program or Token-2022; the mint must be owned by the token program named
  (`mint::token_program`, on every instruction that names a mint), and the token program must be
  one of the two (`Interface<TokenInterface>`). The other programs are `Program<…>`. The unchecked
  accounts are listed under anchor.md §1.1 below, each with why it is safe. The classic program
  named for a Token-2022 mint, or the other way round, is refused
  (`only_the_mints_token_program_and_the_standard_accounts_under_it`,
  `substitution_payout_accounts_of_the_wrong_mint_owner_or_program_are_refused`,
  `substitution_an_escrow_shaped_account_owned_by_another_program_is_refused`).
- **1.3 Account data matching. Applied.** `has_one = vault`, `has_one = mint` and
  `has_one = sponsor` on every way out and `close_unfunded`; `has_one = vault` on `mark_funded`;
  `has_one = vault`, `has_one = payer` and `has_one = mint` in `recover_late`; `has_one = sponsor`
  in `sweep_rent`. The payer's account by `address = escrow.payer_account(..)`, the recipient's by
  `address = escrow.recipient_account(..)`, each derived under the token program named, which is
  the mint's; the default's one account by the same two addresses, by side, in the handler. A sweep
  to the creator, the recipient or a thief is refused. Tested by the `substitution_…` tests,
  `a_payout_lands_only_at_the_receiving_partys_standard_account`,
  `end_whoever_sends_the_default_can_pay_only_the_recipients_standard_account`,
  `sweep_pays_only_the_recorded_sponsor_and_only_from_an_escrow`,
  `a_sweep_returns_rent_above_the_minimum_to_the_sponsor_and_never_goes_below_it` and
  `every_rent_goes_back_to_the_sponsor`.
- **1.4 Type cosplay. Applied.** Anchor's eight-byte discriminator on `Escrow` (`account:Escrow`,
  the same as versions 1 and 2, at another size). On mainnet each version is its own program, and
  each accepts only accounts it owns. On devnet, where version 3 replaced version 2 at the same id,
  a version 2 account is 7 bytes short and fails to load (`AccountDidNotDeserialize`, simulated
  there on each version 2 receipt). Token accounts and the mint by owner, length and initialized
  state, as `InterfaceAccount` unpacks them.
- **1.5 Reinitialization. Applied.** `init` on the escrow account. An escrow that ended by a way
  out is never closed, so its address can never be opened again; one closed by `close_unfunded` is
  closed whole. `init_if_needed` is used twice, both justified under anchor.md §2.4. Tested by
  `reinit_create_on_a_live_escrow_is_refused` and
  `reinit_an_ended_escrows_address_never_holds_a_second_deal`.
- **1.6 Writable checks. Applied.** Every account the program writes is `mut`; the deposit account
  is read-only in `mark_funded`, the escrow read-only in `recover_late`; `stop` writes only the
  escrow, and the party is read-only.

### 2. PDAs

- **2.1 Canonical bumps. Applied.** `seeds` and `bump` at `init` find the canonical bump; it is
  stored in `bump` and used for every signature after. The escrow account is trusted afterwards by
  owner and discriminator, which only this program can produce at an address it derives.
- **2.2 PDA sharing. Applied.** One escrow per `["escrow", terms_hash]`, the SHA-256 of every term,
  both parties' keys and the schedule among them, computed by the program from what `create`
  carries and the mint; its deposit account is its own associated token account. No shared vault.
  Every signature the escrow makes uses the same seeds, the hash rebuilt from the terms the account
  stores (`Escrow::terms_hash`), which `create` writes exactly as it hashed them
  (`CreateArgs::options`).
- **2.3 Seed collisions. Applied.** The seeds are a fixed tag and one 32-byte hash of the terms,
  each term at a fixed length (186 bytes in all: the schedule as its count, four windows with zeros
  past the count, and the default), so two different sets of terms share an address only if
  SHA-256 collides. No arbiter is the zero key and no schedule has zero windows, which `create`
  refuses as named options, so each set of terms it accepts has one encoding. Pinned by
  `every_term_is_in_the_address`, and by one fixed vector, a schedule of two windows included,
  asserted in the harness and the client (`the_address_of_fixed_terms_is_the_clients`). Version 1's
  program id differs from this one's; version 2's hashed 147 bytes at the same devnet id, so no
  set of terms gives both the same seeds.
- **2.4 Purpose isolation. Applied.** One PDA type.

### 3. Arithmetic and logic

- **3.1 Checked math. Applied.** A split is computed in 128 bits (`share`: a 64-bit balance times
  at most 10,000 cannot overflow), the recipient's part by `checked_sub`. Times are never added
  to: every one is a date compared with the clock. `Closed`'s rent sum uses `saturating_add`: two
  accounts' lamports cannot reach `u64::MAX`. `sweep_rent` uses `saturating_sub`, where a floor of
  zero is the rule (nothing to sweep). `overflow-checks = true` in the release profile. Tested at
  1 base unit and at `u64::MAX` by `arithmetic_splits_at_the_edges_add_up_and_never_overflow`.
- **3.2 Multiply before divide. Applied** in `share`.
- **3.3 Slippage. Does not apply:** nothing is priced or swapped. The nearest thing, a split's
  share, is fixed by the schedule at creation, or signed by the parties or the arbiter named at
  creation.
- **3.4 Lamport balance. Applied.** Every rent to the sponsor recorded at creation: the deposit
  account's at every ending, both at `close_unfunded`, the excess above the escrow account's
  minimum at `sweep_rent`; a re-created deposit account's to the payer. Each destination is
  recorded at creation. The sweep subtracts from the escrow and adds to the sponsor, then asserts
  the escrow holds exactly its minimum. Tested with a sponsor that is neither party nor the
  transaction's fee payer, to the lamport (`every_rent_goes_back_to_the_sponsor`), and by
  `close_unfunded_after_a_sweep_returns_every_rent_to_the_sponsor`; fuzzer I3 names the wrong key
  in each rent slot now and then and expects a refusal.

### 4. Duplicate mutable accounts

**Applied.** Anchor 1.2 refuses duplicate mutable `Account` fields, and skips `UncheckedAccount`.
The unchecked ones are pinned by address or by `has_one`, and no two of them can be the same
account: the payer's and the recipient's standard accounts are two different derivations (payer
and recipient differ), the sponsor is a key that signed `create` and so is not either of those
program-derived addresses, nor the escrow, nor its deposit account. A payer's standard account
cannot fill both payout slots: the recipient's slot takes only the recipient's own standard
address. The sponsor may be the same key as a signer (a party that fronted its own rent); the
runtime passes one account for both, and it only receives lamports. In `sweep_rent` the sponsor
cannot be the escrow (the sponsor signed `create`; the escrow is a program-derived address and
cannot sign). The sponsor may be the creator, or the transaction's fee payer; it only receives
lamports.

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
  spy in Token-2022's place that refuses any signature after the authority, handed the recipient
  and the fee payer as signing accounts (`the_escrow_hands_the_token_program_no_signature_but_its_own`),
  and with a hook listing the recipient as a signer, the client marking it so and the recipient
  signing (`a_hook_that_asks_for_a_signature_gets_none`). Removing the rule fails the first.
- **5.4 SOL around CPI. Applied:** the named signers (payer, recipient, arbiter, closer) are never
  passed to the token program, and forwarded accounts carry no signature, so no CPI can spend from
  them. Anchor's own rent transfers at `init` take from the sponsor, who signed for them.
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
- `stop` and `mark_funded` make no CPI.

### 6. Storage and lifecycle

- **6.1 Sizing. Applied.** `Escrow::LEN` = 304, written field by field with a compile-time
  assertion; the space is `8 + LEN`, and the harness asserts it on every read.
- **6.2 Rent exemption. Applied.** `init` funds the minimum; `sweep_rent` leaves exactly it, and
  refuses when the account is at or below it (`NothingToSweep`). Tested by
  `a_sweep_returns_rent_above_the_minimum_to_the_sponsor_and_never_goes_below_it`; fuzzer I10.
- **6.3 Closing. Applied.** `close = sponsor` for the escrow account in `close_unfunded` (zeroed,
  drained, reassigned); the deposit account by the token program's `close_account`. A receipt is
  never closed, by design. Tested with `assert_closed` (no lamports, no data, owned by the system
  program).
- **6.4 Sysvars. Applied:** `Clock::get()` and `Rent::get()`, never an account passed in.

### 7. Token-2022

**Applied.** Every payment out is a `transfer_checked` with the mint and its decimals, read from the
mint at each transfer, under the mint's own token program; every close is `token_interface`'s,
which takes either program. Token-2022's extensions expand the surface: see §23 and High-risk
decisions 9 and 10.

### 8. Transaction model

- **8.1 Atomicity. Applied.** One-tap Pay is the deposit address made, `create`, a transfer and
  `pay` in one transaction. `createAndFund` and `fundInvoice` put the mark in the payment's
  transaction, so a payment through the client after the end time fails whole
  (`money_that_arrives_after_the_end_time_never_counts_toward_the_default`). Two ways out in one
  transaction revert together (`an_escrow_ends_once`); a stop and the default in one transaction,
  in either order, at the second before the end time and at it, too
  (`stop_and_mark_land_only_before_the_end_time_and_end_only_from_it`).
- **8.2 Compute. Applied.** No loop over input beyond the two payouts, the hook accounts each
  carries, and at most four windows (`check_schedule`, `window_at`). The heaviest transaction
  measured under LiteSVM is a one tap whose mint names a hook with two accounts, about 97,000 units
  (`README.md`); `stop` is about 4,400.
- **8.3 Address lookup tables. Does not apply.**
- **8.4 Durable nonces. Does not apply.**

### 9. Safe Rust

- **9.1 `vec![0; N]`. Does not apply** to the program.
- **9.2 No `unsafe`. Applied.**
- **9.3 `remaining_accounts`.** The ways out, `close_unfunded` and `recover_late` take them and do
  one thing with them: forward them to the token program's `transfer_checked`, without signature,
  never reading them. They are not checked for owner or type (High-risk decision 10): Token-2022
  resolves the hook's accounts from the hook's own list by address and ignores the rest, and the
  classic program ignores them all. An account passed that no one asked for is harmless
  (`every_hook_account_is_needed_and_each_keeps_its_writability`).
- **9.4 No `unwrap` or `expect` on input. Applied:** none in the program. The casts are `share`'s
  128-to-64-bit narrowing of a value no greater than the balance, and a schedule's window count to
  a byte, saturating, for a schedule `create` then refuses.

### 10. The curiosity principle

**Applied** as `adversarial.rs` and `schedule.rs`: the same account twice, another program's
account, a mint under the wrong token program, a look-alike deposit account, another escrow's
deposit account, a replayed signature, a front-run address; every move in every state, each answer
checked to the error; a window's last second and the next; a stop and a mark at the end time, a
stop beside the default in one transaction in both orders, a second stop by the other side, a stop
before any money and on an escrow with no schedule; money paid after the end time, through the
client and by a plain transfer; an invoice paid late; a payer's schedule that takes back money the
recipient worked for.

### 11. Oracles. Does not apply.

### 12. Fees. Does not apply: the escrow charges nothing.

### 13. Dust and time-limited accounts

**Applied.** Dust cannot block a close: every way out pays the whole balance before the deposit
account closes, and `close_unfunded` returns whatever is there. Money sent to a closed escrow's
address waits for an escrow with exactly those terms, which either party can open, and which
adopts it. No money expires: an escrow that holds less than the amount can be closed by either
party at any time, and one nobody marked or stopped by its end time closes the same way from then
on; a marked one is the parties' money and ends only by their ways out or the default. Whoever
fronted the rent cannot close anything. A stop blocks no close of an escrow that holds less than
the amount (`every_move_in_every_state`; fuzzer I16). `init_if_needed` is justified under
anchor.md §2.4.

### 14. Coupled fields. Applied.

One helper, `finish`, writes status, `ended_at`, outcome, both amounts, and `funded_at` when nobody
marked it, together, for every way out. `mark_funded` writes the status and the time together;
`stop` writes the stop and its time together.

### 15. Shared positions and pools. Does not apply.

### 16. Clock. Applied.

One unit, unix seconds, and every time in a schedule a date fixed at creation, compared with
`Clock::get()` and never added to. One deadline, `Escrow::end_time()`, the last window's `until`,
which `stop`, `mark_funded`, `end` and the late close read; one window rule, `Escrow::window_at`,
the first window whose `until` is still ahead, which `take_back` reads.

### 17. Mint integrity. By decision.

A mint with a close authority is accepted (High-risk decision 9): Open USD has one. It can be
closed only when nobody holds any of that dollar, so never while a deposit account holds some;
decimals are read from the mint at every transfer, not stored. A mint's freeze authority is under
Known limits.

### 18. Input validation

**Applied:** amount above zero; a schedule of one to four windows, each `until` later than the one
before, each share at most 10,000 (`ScheduleEmpty`, `TooManyWindows`, `BadShare`,
`WindowsOutOfOrder`); no zero keys; payer and recipient different; creator a party; the arbiter
neither party (`ArbiterIsAParty`); neither party the escrow's own address or its deposit address
(`PartyIsTheEscrow`: neither can ever sign, so a party named as either could never give, agree or
be paid; since the address is a hash of both parties, a party equal to it would need a SHA-256
fixed point, so the check cannot fire and stays as version 1 wrote it, untested); the mint owned by
the token program named, not wrapped SOL of either program, no transfer fee, transferable. No
strings. Any other mint is accepted by decision (High-risk decisions 6 and 9). Nothing compares a
schedule's windows with the clock at `create`: that would be a new rule, and the app checks the
dates. `stop` takes no arguments; `agree` and `decide` take a share of at most 10,000 (`BadShare`).
Tested by `bad_terms_are_refused_at_creation` (one schedule already past opens),
`the_arbiter_cannot_be_the_payer_or_the_recipient` (from either creator) and
`a_share_over_ten_thousand_basis_points_is_refused`; fuzzer I14.

### 19. Type narrowing. Applied.

Instruction arguments, state and events use the same types (u64 amounts, u16 basis points, i64
times, each `until` and `stopped_at` included, a u8 window count of at most 4); the narrowings are
bounded (9.4).

### 20. Events. Applied.

Seven fixed-size events with every amount: `Created` (with the window count, all four windows and
the default), `Funded`, `Stopped`, `Ended`, `Closed`, `RecoveredLate`, `RentSwept`. `Ended`
carries `funded_at`, `RentSwept` the sponsor, `Stopped` the side and the time. The receipt keeps
the same numbers in the account, so nothing depends on logs alone
(`the_receipt_and_the_events_carry_the_whole_schedule`). The client counts an event only when the
runtime's own log lines say the escrow program wrote it.

### 21. Reward accounting. Does not apply.

### 22. Withdrawal paths. Applied.

Every token that enters a deposit account has a way out: a funded one by the ways out, an
unfunded one by `close_unfunded`, one that arrived after the end time without a mark by
`close_unfunded` too (`money_that_arrives_after_the_end_time_never_counts_toward_the_default`), a
late one after an ending by `recover_late`. Fuzzer I11 ends every live escrow with the parties'
signatures alone at the end of every run, and I9 returns every late payment. A stop removes two
ways out (the take-back and the default) and no other: after one, each party alone can still end a
funded escrow by giving, both can agree, the arbiter can decide
(`a_stop_freezes_the_schedule_and_the_money_leaves_by_giving_agreeing_or_the_arbiter`), and one
that holds less than the amount still closes (`every_move_in_every_state`; fuzzer I16). With
Token-2022, a mint's permanent delegate can also take money out of a deposit account (Known limits
17 and 18); an escrow that then holds less than its amount still has a way out, `close_unfunded`
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

- **26.1 Sentinel timestamps. Applied.** Neither a zero `funded_at` nor a zero `stopped_at` is ever
  read to decide anything: the default reads the `Funded` status, the ending reads the status to
  decide whether to write the funding time, and the stop has its own byte (`Stop`), so a stop made
  at a zero clock still counts. The zero windows past the count are never read: the end time and
  the window in force read only the first `window_count`.
- **26.2 One cleanup for every terminal path. Applied:** `pay_out` then `finish`, for all six ways
  out; `finish` also writes the funding time, once, for all of them.
- **26.3 Zero after draining. Applied:** the deposit account is closed after the payout, and the
  token program refuses to close it while anything is left, so an ending that does not pay the
  exact balance reverts whole.
- **26.4 Allowlists. Applied:** `live()` is open or funded; `mark_funded` needs open; `stop` needs
  live and no stop; `take_back` needs live and no stop; `end` needs funded and no stop;
  `recover_late` needs ended.
- **26.5 Sub-state. Applied.** The stop is kept apart from the status, and no transition resets
  it: it survives the mark and the ending, and is on the receipt
  (`a_stop_freezes_the_schedule_and_the_money_leaves_by_giving_agreeing_or_the_arbiter`,
  `a_stop_with_no_schedule_is_on_the_receipt_and_nothing_else`; fuzzer I8 and I15).
- **26.6 One deadline source. Applied:** the end time is the single deadline. `stop` and
  `mark_funded` require `now < end_time`, and `take_back` a window with `now < until`; `end`
  requires `now >= end_time`, as does the late close. At no second can a stop and the default both
  land, and at every second after the mark one of them can, until a stop lands
  (`stop_and_mark_land_only_before_the_end_time_and_end_only_from_it`,
  `take_back_follows_the_window_in_force_to_the_second`; fuzzer I12, I15 and I17, which move the
  clock to a second either side of each `until`).
- **26.7 Absorbing terminal state. Applied.** An ended escrow accepts only `recover_late` and
  `sweep_rent`, and neither changes its bytes; it refuses `stop` and `mark_funded` as it refuses
  every way out. Tested by `an_escrow_ends_once` and `every_move_in_every_state`; fuzzer I4 and I8.

### 27. Slippage and fee ordering. Does not apply.

### 28. Bonding curves and AMMs. Does not apply.

### 29. Permissionless initialization and user parameters

- **29.1 Front-runnable initialization. Applied.** The escrow's address is `["escrow", terms_hash]`,
  computed by the program from every term, and only the payer or the recipient the terms name can
  sign `create`. So nobody else can open an escrow at a deal's address: a stranger with the same
  terms is refused (`NotAParty`), and naming itself a party changes the terms and so the address
  (`ConstraintSeeds` aimed at another's, `AccountNotSigner` without the key). Either party may open
  the same terms; the second finds the address taken (Known limit 29). Tested by
  `nobody_can_open_the_address_a_payer_is_about_to_use`,
  `the_escrow_address_is_its_terms_and_only_a_party_opens_it` and fuzzer I13. Anyone can
  still make the escrow's deposit account first (the associated token program lets anyone), or pay
  into it early: `create` adopts it, and the one who did pays for nothing that is theirs.
- **29.2 User-controlled parameters. Applies, by decision:** High-risk decisions 2 and 7.
  Reachability holds: while an escrow is live, each party alone can always end it by giving (the
  payer to the recipient, the recipient back to the payer), whatever the options and whether or
  not anyone stopped; fuzzer I11.
- **29.3 and 29.4, config. Do not apply:** there is no config.

### 30. Withdraw and drain. Applied.

Every way out drains the whole balance and closes the deposit account; nothing is reserved.

### 31. Miscellaneous

- **31.1 Shared config. Does not apply.**
- **31.2 Stack. See 25.**
- **31.3 Unclosed accounts lock rent. Applied as designed:** the deposit account closes at every
  ending; the receipt stays on purpose, and `sweep_rent` returns what the rent cuts free, to the
  sponsor.
- **31.4 Recipients that can receive and move tokens. Applied:** each party is paid at its
  standard account for the mint; each holder can move what it gets. A party who has handed that
  account to another key sends its own payouts there, and blocks nothing
  (`a_party_who_hands_its_standard_account_away_blocks_no_way_out`). The sponsor receives only
  lamports; see Known limit 8.
- **31.5 Token-2022 mint space. Applied:** the associated token program sizes the deposit account
  for the mint (§23).
- **31.6 Signer-as-new-account. Does not apply:** PDAs only. The PDA analogue is 29.1, applied.
- **31.7 Repeated actions resetting time. Applied:** `mark_funded` runs once (`AlreadyFunded`) and
  `stop` once (`AlreadyStopped`), and neither moves a time: every time in a schedule is a date
  fixed at creation, so nothing can restart or delay it.

## anchor.md

- **§1.1 Account types.** Every unchecked account has a `/// CHECK:` comment:
  - `sponsor` (every way out, `close_unfunded`, `sweep_rent`): the key recorded at creation as the
    sponsor, by `has_one`; it only receives lamports.
  - `payer_tokens` (`refund`, `take_back`, `agree`, `decide`, `close_unfunded`): the payer's
    standard account, by address; the token program checks it when it pays it. Unchecked so it
    must exist only when the payer is paid.
  - `recipient_tokens` (`pay`, `take_back`, `agree`, `decide`): the recipient's standard account,
    by address, the same way.
  - `to` (`end`): checked in the handler, by address, against the standard account of the side
    the default names.
  - `payer` (`recover_late`): the recorded key, by `has_one`; it receives the re-created deposit
    account's rent.

  `stop` and `mark_funded` have none. The mint and token accounts are `InterfaceAccount`s and the
  token program an `Interface<TokenInterface>`, as §4.1 asks.
- **§2.1 to 2.3 Constraints.** `has_one`, `mint::token_program`, `associated_token::` with
  `associated_token::token_program`, `address`, and `seeds` with `bump` at `init`.
- **§2.4 `init_if_needed`.** Used twice, each checked:
  - the deposit account at `create`: only the associated token program can make an account at that
    address, and only as a token account of that token program for this mint held by the escrow,
    whose authority only this program uses. So a pre-existing one can differ only in its balance,
    which is part of the deal;
  - the payer's standard account at `recover_late`: Anchor checks its mint, holder and token
    program when it exists.
- **§2.5 `close`.** Used in `close_unfunded`, to the sponsor.
- **§2.6 `realloc`. Not used.**
- **§3 State.** No reload needed (5.2); `init` once; checks in handlers rather than `access_control`,
  so each rule and its error sit in the instruction's own text.
- **§4 Tokens.** Either token program; `transfer_checked` built by hand (§5 above), since
  `token_interface::transfer_checked` drops a hook's accounts; decimals read from the mint.
- **§5 CPI.** `Interface<TokenInterface>`; seeds from the stored bump.
- **§6 Errors.** `#[error_code]` with a message on each of 31 errors, numbered from 6000 in the
  order `program/src/errors.rs` lists them: version 3 numbers its own, as a new program would. The
  `require!` family throughout.
- **§8 Tooling.** Anchor 1.2 against platform-tools v1.54; `overflow-checks = true`; the features
  Anchor's macros test for (`custom-heap`, `custom-panic`, `anchor-debug`) are declared, so the
  build has no warnings.

## LiteSVM checklist (litesvm.md §9)

- **Happy path, with full state verified. Done:** every way out with exact token balances, rent,
  the receipt's fields and the event; the stop; the sweep to the sponsor; the funding time in the
  one tap, in the invoice paid in one tap and in a marked invoice; and under Token-2022 with Open
  USD's extensions, every way out (the take-back, and the default to either side, among them), the
  one taps, a stop then an agreement, a part payment closed and late money recovered, each with the
  hook naming no program and naming the test hook, which counts every transfer.
- **Every move in every state. Done:** nine moves in twelve states, each answer checked, accepted
  or the exact error, and nothing changed by a refusal (`every_move_in_every_state`).
- **Wrong signer. Done:** for every instruction that takes a signer, `stop` included.
- **Re-initialization. Done:** over a live escrow and over an ended one's address.
- **Before and after a deadline. Done:** `take_back` at each window's last second and at its
  `until`; a stop and a mark a second before the end time and at it; the default a second early
  and at the end time, to both sides; the default a thousand days after a stop.
- **Over-limit arithmetic. Done:** `BadShare` at 10,001 and 65,535 for `agree` and `decide`, and
  above 10,000 in a window; splits at 1 unit and at `u64::MAX`; `take_back` refused at a share of
  0, and paid at 5,000 and 10,000.
- **Closure verified. Done:** no lamports, no data, owned by the system program.
- **Token balances after every transfer. Done.**
- **PDA seeds written down. Done,** in the harness beside each derivation.
- **`expire_blockhash` after every transaction. Done** (`Harness::send_tx`).
- **Failures asserted without `unwrap`. Done** (`expect_err` and the error name).
- **Compute units logged. Done** for every instruction and the one taps: each measuring test
  prints its own table, so no table depends on the order tests run in, and `token_2022.rs` also
  prints its rows together in a `zz_cu_summary` test.

What LiteSVM does not show is covered, in part, by the client's devnet script (seven deals sent
through devnet, and five refusals simulated there). The fuzzer adds random flows, but Trident's
runtime checks no signatures, so its signer rules hold on key comparisons alone; LiteSVM checks the
real signatures. There is no local-validator test.

## Known limits

Each is reported, not fixed: fixing it would change a decided rule, or add one.

1. **A frozen token account.** A mint's freeze authority (USDC has one) can freeze, each pinned by
   a test:
   - the deposit account, which stops every way out until it is thawed, since each moves tokens out
     of it (`finding_a_frozen_deposit_account_blocks_every_way_out`);
   - the payer's standard account, which stops every way out that pays the payer anything; the ones
     that pay the payer nothing still run (`finding_a_frozen_payer_account_blocks_only_the_ways_out_that_pay_the_payer`);
   - the recipient's standard account, which, by the same rule, stops every way out that pays the
     recipient anything (`finding_a_frozen_recipient_account_blocks_only_the_ways_out_that_pay_the_recipient`).
2. **Options nobody checked.** The program runs any option its creator set. A recipient who works
   without reading the escrow can lose to a payer's schedule that takes everything back
   (`finding_a_payers_schedule_can_take_back_money_the_recipient_worked_for`), and a payer who pays
   without reading an invoice can lose to a short schedule paying the recipient
   (`finding_an_invoice_with_a_short_schedule_pays_the_recipient_whatever_the_payer_thinks`).
   `optionsNotAgreed` exists for this; the program cannot know what was agreed. A stop before the
   end time turns either off.
3. **A party key nobody controls.** `create` refuses the two it can see, the escrow's own address
   and its deposit address (`PartyIsTheEscrow`). Any other key nobody can sign for (a lost key,
   another program's address, some other token account) cannot be told apart, and a party named as
   one locks what it would be paid, as in any transfer. The app names parties by keys people hold.
4. **A part payment can be closed under the payer** by the recipient, at any time. The part comes
   back; a second part sent to the closed address waits for an escrow with exactly those terms,
   which the payer can open, and close to get it back
   (`finding_a_part_payment_can_be_closed_under_the_payer_by_the_recipient`,
   `a_deposit_address_never_adopts_money_meant_for_other_terms`). Money sent to an address counts
   only toward a deal with exactly the terms it was made from
   (`a_payment_to_an_address_lands_only_in_a_deal_with_its_terms`); the program cannot tell whose
   money arrived, so a payer still pays only an escrow it has read (the client's checks).
5. **An overpayment follows the balance** (High-risk decision 4).
6. **A party's standard account must exist to be paid.** A recipient who has never held the token
   has none: whoever sends the way out makes it first, at their own cost
   (`makeStandardAccountIx`; anyone may). A default to that recipient waits until someone does.
7. **`recover_late` checks who holds the payer's standard account** (Anchor's create-if-missing
   does), so a payer who hands that account away blocks its own late money there, and nothing else
   (`finding_a_payer_who_hands_its_standard_account_away_blocks_its_own_late_money`).
8. **SOL sent to an escrow's address** goes to the sponsor, by `sweep_rent` or with the rents at
   `close_unfunded`, not to whoever sent it; the program cannot tell it from rent. A sweep into a
   key that holds no SOL (a one-time sponsor key emptied) fails unless it leaves that key at least
   at the rent-exempt minimum of an empty account (128 bytes' worth); it can be sent again once
   more has built up.
9. **Tokens of another mint sent to an escrow's address** are lost to everyone: the escrow's
   associated token account for that mint has no way out, since nothing here signs for it.
10. **Self-minted tokens** make receipts of any size (High-risk decision 6).
11. **A one-sided receipt.** A payer can pay a recipient who never signed anything, for one base
    unit. The receipt says the payer created it, so an index can weigh it as one-sided.
12. **A stop makes the schedule a default, not a promise** (High-risk decision 7). A recipient who
    works under a default to itself can have it stopped the second before the end time; a payer who
    pays under a take-back window can have it stopped by the recipient at once, and then gets the
    money back only if the recipient refunds, both agree, or the arbiter decides. The client's
    `optionsNotAgreed` still reports the schedule; what an app says about it is the app's.
13. **A deadlock holds the money.** With no arbiter, if neither side gives and they do not agree,
    the money stays in the deposit account for good: after a stop, or with no schedule at all.
    Nothing in the program can break it.
14. **The fee payer gets every rent back, by decision.** When a fee payer signs as the sponsor,
    every rent goes back to the fee payer's key, which already charged the person for it, in
    dollars. Intended: the fee payer keeps what it fronted and says so to people. A product that
    wants the person to get it back makes the person's own key the sponsor, which then needs SOL.
15. **A move sent near a deadline may land on the other side of it.** A stop or a mark sent late
    may land after the end time, and a take-back near a window's `until` in the next window. The
    chain's clock decides; the client's `canStop`, `canMark`, `canTakeBack` and `canEnd` read the
    local clock.

Taking both token programs:

16. **The dollar's maker can stop an escrow**, by freezing its deposit account, pausing the dollar,
    making new accounts start frozen, or a hook that refuses; and can stop a party being paid by
    freezing that party's account. Nothing in the program routes around any of it.
17. **The dollar's maker can end the "held until the end" rule.** Only this program can move money
    out of a deposit account for a classic mint and a Token-2022 mint without a permanent delegate;
    with one, the delegate can take it at any time.
18. **A permanent delegate's escrow ends by `close_unfunded`.** Once it holds less than its amount,
    no payout, take-back, split or default runs; a party closes it and the rest goes to the payer,
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
27. **Unaudited.** No paid review, no lawyer pass.
28. **Refunds arrive in SOL,** to whichever key fronted the rent. How an app shows them to a person
    who fronted their own, without saying "SOL", is the app's choice and open.
29. **Either party can open the same terms.** The creator is not a term, so the payer and the
    recipient land at the same address with the same terms; whoever is second finds it taken, and a
    payer's one tap fails whole if the recipient opened those terms first. The app then pays the
    escrow already there, which has exactly the terms it meant
    (`the_escrow_address_is_its_terms_and_only_a_party_opens_it`).

The schedule:

30. **Money that arrives in time but nobody marks loses the default.** If nobody marks a funded
    escrow before its end time, from then on either side can close it and everything goes back to
    the payer, a recipient who did the work included. Anyone may mark, with no signature, so the
    side the default favours marks any payment it sees in time
    (`schedule_the_mark_needs_the_money_and_lands_only_before_the_end_time`,
    `money_that_arrives_after_the_end_time_never_counts_toward_the_default`).
31. **An invoice's windows are dates.** A payer who pays an invoice late has less of each window;
    one who pays after its end time through the client fails whole, and a plain transfer then goes
    back by `close_unfunded` (`finding_an_invoices_windows_are_dates_so_paying_late_shortens_them`).
32. **One escrow, one payment.** A rule about many payments at once, such as a floor on how many
    tickets must sell before any is paid, cannot be written as one escrow's schedule
    ([escrows](../README.md#limits)).
