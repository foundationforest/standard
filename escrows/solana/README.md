# solana

Part of Forest's standard: [the top README](../../README.md), under [escrows](../README.md). Down:
the [security checklist](security-checklist.md).

## What it is

A program Forest offers on Solana, and its client; use any escrow. An escrow holds an amount of
one mint, one kind of money such as a dollar, between two keys, a payer and a recipient, under the
schedule [escrows](../README.md) sets out: it lets the money out when one side gives it to the
other, both sides agree, the arbiter named at the start decides, or the schedule set at the start
says so. Every escrow that held the money leaves a receipt at its address, for good: its account,
saying how the deal ended.

It runs on devnet at `FA6ZodkyhMDj9yjzY27dk8JDCtcHnJx8mr45Mx9TfKg8`, still upgradable
([record](devnet/devnet.json)). It cannot change once deployed to Solana's mainnet, because money
sits inside it and nobody, the Open Forest Foundation included, may change the rules around money
already there: a new version is a new program beside it, at a new address, never an upgrade, and
the old ones keep working.

- `program/`: the program (Anchor 1.2), its LiteSVM tests and its fuzzer.
- `client/`: builds every instruction and reads every account and event. It talks to no network
  of its own.
- `devnet/`: the deploy script and the public record of what runs on devnet.

## How it works

### A deal, start to end

A payer pays a recipient for an hour of maths.

1. **The offer.** The recipient publishes an offer, whose body its market defines
   ([markets](https://github.com/foundationforest/markets)), and an index, a service that reads
   what profiles publish and scores them, shows it. The payer's app reads the offer and agrees the
   amount.
2. **Opening and paying in.** The payer's app makes the terms (`termsFor`), then in one transaction
   opens the escrow (`create`), pays the amount in and marks it (`createAndFund`). Or the recipient
   opens it first, as an invoice, and the payer pays into it
   ([Two ways to open it](#two-ways-to-open-it)).
3. **The money waits.** Neither side can take it alone, but for the share the schedule lets the
   payer take back inside a window. Each side can always give it to the other, and either can stop
   the schedule before its end time.
4. **The money leaves.** The payer pays the recipient once the hour is done; or the recipient
   refunds; or the payer takes back its window's share; or both sign a split; or the arbiter
   decides; or, from the end time, if nobody stopped, anyone sends the default
   ([How money leaves](#how-money-leaves)).
5. **The receipt stays.** The escrow's account stays at its address, saying how the deal ended,
   and a review can point to that address ([The receipt](#the-receipt)).

A payer with nothing to wait for does steps 2 and 4 in one transaction: `payInOneTap`.

### The terms in the address

An escrow's terms are the payer, the recipient, the mint, the amount, the arbiter, the schedule,
and an id. Its address is `["escrow", sha256(terms)]`, the terms at fixed lengths in the receipt's
order, 186 bytes (`terms_hash` in `program/src/state.rs`). So:

- a payment sent to that address counts only toward a deal with exactly those terms;
- only the payer or the recipient can open it, and who opens it is not a term, so either lands at
  the same address; one the recipient opens is an invoice;
- the id tells apart two deals with the same terms: the app picks a fresh 64-bit number for each
  (`randomId()`).

`create` names both keys, the mint, the amount and any options. The party opening it signs, and
so does whoever fronts the rent, the deposit Solana holds in every account and gives back when it
closes, recorded as the sponsor ([Rent](#rent)).

### Two ways to open it

`create` takes either party as its creator, so an escrow opens one of two ways:

- **The payer opens it from the offer's terms.** The payer's app names the recipient's address,
  the amount, the dollar and the options the offer carries, if any: an arbiter, and a schedule in
  the format [escrows](../README.md#the-schedule) sets (`termsFor`, then `createIx`). An offer
  field that carries them is the market's to suggest. It usually pays and marks in the same
  transaction (`createAndFund`).
- **The recipient opens it for one payer: an invoice.** The recipient's app names the payer, the
  amount, the dollar and the options (`invoiceIx`). The payer pays into its address with a plain
  transfer, from anywhere ([Paying in](#paying-in)), and marks it; `fundInvoice` does both in one
  transaction, and `payInvoiceInOneTap` pays it in and pays it out. An invoice's windows are dates
  the recipient chose, so a payer who pays late has less of each.

### Paying in

- **The mint** is one made by the classic SPL Token program or by Token-2022. `create` refuses
  three kinds (`program/src/errors.rs`): wrapped SOL (`NativeMint`: a plain SOL transfer to its
  deposit account would not count); a token with a transfer fee (`TransferFee`: the fee would take
  part of every payment in and out, while every way out pays the whole balance); and a token that
  cannot be transferred (`NonTransferable`: nothing could be paid into the escrow, and nothing
  minted into it could leave). A dollar, here, is such a mint made to track the US dollar, such as
  Open USD; what its maker can still do is in [Limits](#limits).
- **The deposit address** is the escrow's associated token account for the mint, so a payment
  sent "to the escrow's address" from anywhere lands there. Money arrives by a plain transfer,
  from anywhere; a payment in a Token-2022 mint must be a `transfer_checked`. Confidential
  transfers never reach a deposit account: turning them on needs a signature the escrow never
  gives. Interest-bearing and scaled dollars work: the escrow holds and pays raw base units,
  fixed at creation, and only what they display drifts.
- **Funded** is the live balance: the escrow is funded while its deposit account holds at least
  the amount. Every way out checks the balance itself.
- **`mark_funded`** records when the amount was there. A plain token transfer into the deposit
  account never calls the program, so the program cannot see on its own when money arrived: someone
  marks it. Anyone may send it, with no signature, once, while the deposit account holds the amount,
  and only before the end time. Only `end` needs it: the default pays only a marked escrow, so money
  that arrives after the end time never counts toward it. `createAndFund` and `fundInvoice` mark in
  the same transaction as the payment, so a payment they send after the end time fails whole and
  moves nothing. A plain transfer can still land late: from the end time on, either side may close
  an escrow nobody marked or stopped, and the money goes back to the payer (`close_unfunded`). So
  the side the default favours marks any payment it sees before the end time.
- **The amount** is one payment: one escrow per payment.
- **The deposit address is made first** when paying in the same transaction as `create` or into
  an invoice (`createAndFund`, `fundInvoice` and the one-tap builders do), so a fee payer (a
  service that pays Solana's costs for others) that checks every transfer's destination before it
  signs finds it made.

### The schedule, the stop and the arbiter

The arbiter and the schedule are off unless the creator sets them in `create`. From then on they
are in the escrow, for both sides to read before anyone works or pays, and they never change.

- **The arbiter** is any key but the payer's or the recipient's, and may sign any split. A party as
  arbiter could take everything alone; who holds any other key, the program cannot tell.
- **The schedule** is one to four windows, each `until` a time in unix seconds later than the one
  before, each `payerShare` from 0 to 10,000, and a default, `pay` or `refund`. The account holds
  the count, four windows with zeros past the count, and the default. The window in force is read
  from the chain's clock: the first whose `until` is still ahead. Nothing compares the windows with
  the clock at `create`, so a schedule already past opens; the app checks the dates before anyone
  pays.
- **A stop.** Either side may stop the escrow, once, before the end time. It moves no money; from
  then on neither `take_back` nor `end` runs, and the money leaves only by a side giving, both
  agreeing, or the arbiter if one was named. The end time is the one deadline: before it a stop, a
  mark and a take-back can land; from it on only the default and the late close. An escrow with no
  schedule takes a stop at any time while it is live, and the stop then changes only the receipt.

The program cannot tell whether the other side read the options. The app reads the escrow off the
chain and shows every option the person did not set (`optionsNotAgreed`) before they work or pay;
working or paying after that is the agreement. Before paying an invoice, it also checks that the
invoice names the person's own key as payer, and that its windows are still ahead. The default
pays the side it names only if nobody stopped.

### How money leaves

Every way out pays the whole balance and ends the escrow:

1. **A side gives.** `pay`: the payer, everything to the recipient. `refund`: the recipient,
   everything back to the payer. Receiving in full never needs the receiver's signature, so each
   side alone can always give, a stop included.
2. **The payer takes back** (`take_back`), inside a window whose `payerShare` is above 0, if nobody
   stopped: that share to the payer, the rest to the recipient. In a window of 0, giving
   everything to the recipient is `pay`.
3. **Both agree** (`agree`) on any split, both signing.
4. **The arbiter decides** (`decide`) any split.
5. **The default** (`end`): anyone, from the end time on, if the funding was marked and nobody
   stopped; everything to the side the schedule names.

Every split is stated as the payer's share in basis points, rounded down:
`⌊balance × share / 10,000⌋` to the payer, the rest to the recipient. Every way out pays each side
only at its standard token account for the mint (its associated token account), so no ending can
send money anywhere else. The program checks that account by its address alone, not by who holds it now, so a side
that hands its account to another key cannot block any way out. If the account does not exist yet,
whoever sends the way out makes it first (`makeStandardAccountIx`).

Three more instructions move money that is not the deal's:

- **`close_unfunded`:** either party closes an escrow that holds less than the amount, at any
  time, or, from the end time on, one nobody marked and nobody stopped. Whatever arrived goes back
  to the payer, and both rents to the sponsor. No receipt is kept: nothing was dealt.
- **`recover_late`:** money sent after the end goes back to the payer. Anyone may send it.
- **`sweep_rent`:** lamports above the receipt's rent-exempt minimum (SOL sent to the escrow's
  address, or what a cut in Solana's rent frees) go to the sponsor. Anyone may send it.

### The receipt

When an escrow ends, its deposit account closes and the escrow account stays at its address as
the receipt: the payer, the recipient, who opened it, the mint, the amount, the arbiter and the
schedule, who fronted the rent, when the money was there (the mark's time, or the ending's if
nobody marked it), whether a side stopped it and when, how it ended (`pay`, `refund`, `takeBack`,
`agree`, `decide` or `end`), when, and what each side got. A receipt never closes and never
changes, and its address never holds a second deal, so the address is what a review can name to
point at its deal; what a review holds is its market's
([markets](https://github.com/foundationforest/markets)).

Every change is also an event, so an index can read outcomes from the log: `Created` (with the
whole schedule), `Funded`, `Stopped`, `Ended`, `Closed`, `RecoveredLate`, `RentSwept`.

### Rent

Solana holds a deposit, its rent, in every account, and gives it back when the account closes.
Whoever fronts an escrow's rent signs `create` as the sponsor, is recorded, and gets every rent
back: the deposit account's at every ending, both rents at `close_unfunded`, and, by `sweep_rent`,
whatever a cut in Solana's rent frees above the receipt's minimum. Refunds arrive in SOL, to
that key. A fee payer may front it; what it charges for that is its own choice.

One rent goes elsewhere. A payment that arrives after an escrow ended makes its closed deposit
account again, and that payment is almost always the payer's own, so the payer paid that account's
rent: `recover_late` sends it to the payer, with the late money.

At Solana's 5,080 lamports a byte, the escrow account holds 304 bytes after its 8-byte
discriminator (2,235,200 lamports), and comes back whole only at `close_unfunded`; otherwise the
receipt keeps its minimum. A classic deposit account is 165 bytes; one for Open USD's extensions,
179 (1,559,560 lamports). It comes back to the sponsor at every ending.

### The state table

| From | Instruction | Signs | Needs | To |
|---|---|---|---|---|
| nothing | `create` | the payer or the recipient as creator, and whoever fronts the rent as sponsor | address `["escrow", sha256(terms)]`; payer and recipient differ; no zero keys; the arbiter, if any, neither party; neither party the escrow's own address or its deposit address; amount above zero; a schedule, if any, of one to four windows, each `until` later than the one before, each `payerShare` at most 10,000; a mint owned by the token program named, not wrapped SOL, no transfer fee, transferable; no escrow already at the address | open; the creator and the sponsor recorded |
| open | `mark_funded` | nobody | before the end time; the deposit account holds at least the amount | funded, `funded_at` = now |
| open, funded | `stop` | the payer or the recipient | nobody stopped yet; before the end time | unchanged: the stop, its side and its time recorded |
| open, funded | `pay` | the payer | the deposit account holds at least the amount | ended: the whole balance to the recipient |
| open, funded | `refund` | the recipient | the same | ended: the whole balance to the payer |
| open, funded | `take_back` | the payer | a schedule; nobody stopped; a window in force, whose `payerShare` is above 0; the same | ended: `⌊balance × payerShare / 10,000⌋` to the payer, the rest to the recipient |
| open, funded | `agree(payer_share)` | the payer and the recipient | `payer_share` ≤ 10,000; the same | ended: `⌊balance × payer_share / 10,000⌋` to the payer, the rest to the recipient |
| open, funded | `decide(payer_share)` | the arbiter | an arbiter was named; the same | ended: the same split |
| funded | `end` | nobody | a schedule; nobody stopped; now ≥ the end time; the same | ended: the whole balance to the side the default names |
| open, funded | `close_unfunded` | the payer or the recipient | the deposit account holds less than the amount; or open, nobody stopped, and now ≥ the end time | gone: what it held to the payer, both accounts closed, both rents to the sponsor |
| ended | `recover_late` | anyone; the sender makes the payer's standard account if missing | a later payment made the deposit account again | unchanged: the late money to the payer, that account's rent to the payer |
| anything but gone | `sweep_rent` | nobody | the escrow account holds more than its rent-exempt minimum | unchanged: the excess to the sponsor |
| ended | anything else | | | refused: `Ended` |

"Funded" in the Needs column is the live balance; the status `funded` is the mark. The end time is
the last window's `until`, read against the chain's clock; with no schedule there is no end time,
and a need that names it holds for `stop` and `mark_funded` and fails for the rest. Every ending
from open (nobody marked the funding) writes its own time into `funded_at`. A stop is not a status:
a stopped escrow is open or funded, and ends by any way out but `take_back` and `end`.

### Use it

- `termsFor(postTerms, deal)`, `optionsFromPost(postTerms)`: an escrow's terms from its options,
  `{ arbiter?, schedule? }` as an offer may carry them (the schedule in the format's own JSON), and
  the deal.
- `tokenOf(mint, account)`: the mint's token program and decimals, read from its account; it
  refuses what `create` refuses.
- `createIx`, `invoiceIx`, `createAndFund`, `fundInvoice`, `payInOneTap`, `payInvoiceInOneTap`:
  opening; opening, funding and marking; funding and marking an invoice; paying in and out in one
  transaction.
- `markFundedIx`, `payIx`, `refundIx`, `takeBackIx`, `stopIx`, `agreeIx`, `decideIx`, `endIx`,
  `closeUnfundedIx`, `recoverLateIx`, `sweepRentIx`: one builder for every other instruction.
- `keysFor`, `keysOf`: every account a way out names, from the terms or from the escrow read off
  the chain.
- `validateTerms`, `validateSchedule`: the program's own refusals, before anything is sent.
- `optionsNotAgreed`, `assertOptionsAgreed`: every arbiter and schedule a person did not set.
- `endTime`, `windowAt`, `canStop`, `canMark`, `canTakeBack`, `canEnd`, `split`: the end time, the
  window in force, whether a stop, a mark, a take-back or the default would land now, and what a
  split pays.
- `escrowAddress`, `termsHash`, `termsOf`, `vaultAddress`, `payerAccount`, `recipientAccount`,
  `makeDepositAddressIx`, `makeStandardAccountIx`: addresses (an escrow's from its terms), and the
  accounts a payment needs made first.
- `hookAccounts`, `payoutTransfers`: a transfer hook's accounts, through `@solana/spl-token`'s
  resolver. A transfer hook is a program a Token-2022 mint's maker can name, which runs on every
  transfer of that mint and can refuse it.
- `decodeEscrow`, `decodeEvents`: the receipt and the events. `decodeEvents` reads only events
  this program wrote, by the runtime's own invoke lines.

**What the app decides**, because the program does not know:

- **The options.** Check them before anyone works or pays
  ([The schedule, the stop and the arbiter](#the-schedule-the-stop-and-the-arbiter)), and an
  invoice's dates against the clock before paying it.
- **When to offer the stop, and what to say.** The program records nothing about why. `canStop`,
  `canTakeBack` and `canEnd` read the device's clock; the chain's decides, so a move sent in the
  last seconds may be refused.
- **Marking.** The side the default favours marks any payment it sees before the end time;
  `createAndFund` and `fundInvoice` mark for the payer.
- **Which dollars to offer,** and what to say about each one's maker ([Limits](#limits)). Know a
  dollar by its mint's address, never its name.
- **A hook's accounts.** For a mint whose hook names a program, resolve them before each
  transaction (`hookAccounts`), since the dollar's maker can change the program at any time, and
  pass them to each way out and to the payment in.
- **Who fronts the rent** ([Rent](#rent)).

### Run it, and what one escrow costs

```
cd escrows/solana/program && cargo build-sbf --arch v3             # Solana CLI 4.2.2 or later
cd escrows/solana/program/tests-litesvm && cargo test              # classic and Token-2022 mints
cd escrows/solana/program && cargo build-sbf --arch v0 && cd trident-tests \
  && TRIDENT_WITH_EXIT_CODE=1 cargo run --release --bin fuzz_escrow   # 99: an invariant broke
cd escrows/solana/client && npm ci && npm run check && npm test    # no chain needed
FOREST_DEVNET_SEED=<phrase> escrows/solana/devnet/deploy.sh        # devnet: deploy, or upgrade in place
cd escrows/solana/client && FOREST_DEVNET_KEYS=<dir> node scripts/devnet.ts
```

The LiteSVM tests run every case on a classic mint, and on a Token-2022 mint made with Open USD's
extensions: its hook naming no program and naming a test hook, each power its maker holds used,
and mints with one other extension each. One test sends every move in every state and checks each
answer, accepted or the exact error. They move the clock by hand and check the wire format against
a second copy written in `program/tests-litesvm/src/lib.rs`.

The fuzzer sends random flows against a model of every escrow and checks seventeen invariants
after every step (`program/trident-tests/fuzz_escrow/test_fuzz.rs` lists them);
`FOREST_FUZZ_ITERATIONS` sets its size. It needs the old program format, so it runs a v0 build.
Before the LiteSVM tests again, delete `program/target/deploy/forest_escrow.so` and build v3:
`cargo build-sbf` does not copy a build it already holds over the v0 one.

Measured under LiteSVM with the harness's keys; address derivations make each figure vary by up
to about 20,000 compute units with the keys.

| | Compute units | Bytes of 1,232 |
|---|---|---|
| `create`, classic mint | 33,394 | 595 |
| `create`, an arbiter and four windows | 38,578 | 673 |
| `stop` | 4,366 | 347 |
| `pay`, classic | 13,421 | 480 |
| `take_back`, classic | 22,322 | 513 |
| `agree`, classic | 22,483 | 612 |
| `end`, classic | 13,206 | 383 |
| one tap, classic | 47,764 | 702 |
| an invoice paid in one tap, classic | 16,495 | 527 |
| `create`, Open USD's extensions, no hook program | 49,400 | 595 |
| one tap, the same | 65,574 | 704 |
| one tap, a hook with two accounts | 97,205 | 872 |

### What cannot change

None of this can change once the program is deployed to Solana's mainnet; a new version is a new
program beside it. On devnet the program is still upgradable.

- **The account.** 304 bytes after the discriminator, laid out in `program/src/state.rs` (and
  written again in `program/tests-litesvm/src/lib.rs` and `client/src/program.ts`): version, id,
  payer, recipient, arbiter, mint, deposit account, sponsor, amount, creator, window count, four
  windows (each `until` and `payerShare`), default, created, funded, status, bump, ended, outcome,
  what the payer got, what the recipient got, stop, stopped at. `version` is 3: it says which
  program's rules an escrow follows, and a new program writes its own. The zero key means no
  arbiter; a window count of 0, no schedule; a zero time, not yet.
- **The addresses.** The escrow at `["escrow", sha256(terms)]`; the deposit account its associated
  token account for the mint, under the mint's own token program; each party paid only at its own
  associated token account, checked by address alone.
- **The rules,** as the state table says, and the order of checks in each handler, which decides
  the error a refused instruction returns. Every handler that needs a live escrow checks that
  first, as an allowlist of the live states (open, funded).
- **The instructions, events and errors.** Twelve instructions, seven events and 31 errors, their
  bytes and account lists. In every way out, the mint comes right after the deposit account, and
  the only accounts it names are the ones it pays. Any accounts a transaction adds after the
  instruction's own are passed on to each transfer, never as signers, for the mint's transfer
  hook.

On Solana's mainnet the upgrade authority is removed the day the program deploys:

```
solana program deploy --program-id <program-keypair.json> target/deploy/forest_escrow.so
solana program set-upgrade-authority <PROGRAM_ID> --final
solana program show <PROGRAM_ID>        # Authority: none
```

The source's program id, `FoRE3EscrowV3scheduLeWindowsPayRefund3333333`, is for local work; no
keypair for it exists. Each deploy uses its own.

### Devnet

On devnet the program is built as SBPF v3 and stays upgradable: its upgrade authority is the
devnet deploy key. `devnet/deploy.sh` builds a copy of the source with the devnet id put in, deploys a
fresh id or upgrades it in place, checks the deployed bytes against the build, and records
everything public in [`devnet/devnet.json`](devnet/devnet.json); its header holds the recipe for
every devnet key it needs. `client/scripts/devnet.ts` runs seven deals there, recorded in the same
file. In the classic test dollar (`testDollar`): an invoice paid in one tap; half taken back inside
a window; a stop, the default refused, then a 60/40 split both sign; the default sent from the end
time by a key that is neither party; and a plain transfer after the end time, the mark and the
default refused, closed back to the payer. In a Token-2022 dollar made with Open USD's extensions:
the one tap, and the stop then the split. The devnet keys labelled `buyer` and `seller` act as
payer and recipient, and `payer` as the sponsor: the labels are the key recipe's.

The program was upgraded in place from version 2. Its version 2 receipts stay at their addresses,
and this version refuses every instruction on them (`beforeSchedules` in the record). There is no
smoke test: read a receipt with `solana account <address> --url devnet`, and decode it with
`decodeEscrow`.

## Promises

- **Nothing in the escrow program lets anyone but the two sides, the arbiter or the schedule move
  the money.** Money leaves a funded escrow only by a side giving it to the other, a split both
  sign, the arbiter named at creation, or the schedule set at creation: the payer's take-back
  inside a window, or the default once the last window closes and nobody stopped.
- **Every way out pays the whole balance,** to the parties' standard token accounts and nowhere
  else.
- **An address holds only its own terms.** A payment to an escrow's address counts only toward a
  deal with exactly the terms the address was made from.
- **Each side alone can always give.** Nothing in the escrow stops it: while an escrow is live, the
  payer can pay the recipient and the recipient can refund the payer, whatever the options and
  whether or not anyone stopped.
- **A stop moves no money,** lands once per escrow, only before the end time; after it neither
  `take_back` nor `end` runs.
- **A receipt never closes and never changes,** and its address never holds a second deal.
- **Rent goes back to whoever fronted it:** every rent to the sponsor, at every ending, at
  `close_unfunded` and by `sweep_rent`; a deposit account a late payment made again, to the payer.
- **Nothing inside charges anything.** No admin, no config account, no pause, no fee.

## Limits

The limits every escrow shares, a stop with no arbiter among them, are in
[escrows](../README.md#limits). This one's own:

- **It trusts** the SPL Token and Token-2022 programs, the associated token program, and Anchor
  1.2; and the app, to show a person every option they did not agree to before they work or pay.
- **The dollar's maker keeps its powers over its dollar.** A maker like Open USD's can freeze
  balances or take them back, an escrow's deposit included, and nothing in the program can stop
  it.
- **Options nobody checked.** The program runs whatever options the creator set. A schedule that
  lets the payer take everything back until the work is done, or a one-minute schedule paying the
  creator's side, runs if the other side never read the escrow and never stopped it.
- **The default is not a promise.** Either side can stop the escrow until the second before the
  end time.
- **Money sent to an address before its escrow opens, or after a close,** waits there, and counts
  only toward an escrow opened with exactly those terms. Either party can open one, and close it
  if it holds less than the amount, which sends the money back to the payer.
- **A party whose standard account requires a memo blocks its own payouts:** the escrow sends none.
- **SOL sent to an escrow's address** goes to the sponsor by `sweep_rent`. **Money of another mint**
  sent there is lost to everyone.
- **A one-sided receipt is cheap:** a payer can pay one base unit to a recipient who signed
  nothing. The receipt records who created it.
- **Hook accounts are the client's to find;** a missing one fails the transfer and nothing moves.
  No dollar on devnet names a hook program: a hook program runs only under LiteSVM, as a builtin.
- **Tested, not audited.** The fuzzer runs an SBPF v0 build, since its runtime runs no v3 program,
  on a classic mint only, and its runtime checks no signatures. There is no local-validator test:
  the devnet run is the client's only run against a real runtime. No paid review.

The [security checklist](security-checklist.md) lists every known limit, with the test that pins
each.

## Who decides what

- **The standard:** the program's rules and the receipt, which cannot change once deployed to
  Solana's mainnet; a new version is a new program beside it.
- **An app, with the person:** the terms, the arbiter, the schedule, and which escrow to use.
- **A fee payer chooses** which transactions it pays for, and what it charges for fronting rent.

## FAQ

**Why can someone open an escrow without the other side signing?**
Asking the recipient to sign `create` would stop anyone paying a recipient who is offline, and
break paying in one tap. The receipt records who created it instead.
