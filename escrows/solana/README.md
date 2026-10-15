# escrow

Part of Forest's standard: [the top README](../../README.md). Down: the
[security checklist](security-checklist.md).

## What it is

A program Forest offers on Solana, and its client; use any escrow. An escrow holds an amount of
one mint, one kind of money such as a dollar, between two keys, a buyer and a seller, and lets it
out only when both sides agree or one side gives the money to the other, or by an arbiter or a
timer that were in its terms from the start. Every escrow that held the money leaves a receipt at
its address, for good: its account, saying how the deal ended.

It runs on devnet at `FA6ZodkyhMDj9yjzY27dk8JDCtcHnJx8mr45Mx9TfKg8`, still upgradable
([record](devnet/devnet.json)); nothing is on mainnet. On mainnet each version is to be sealed the
day it deploys, because money sits inside it and nobody, the Open Forest Foundation included, may
change the rules around money already there: a new version comes as a new program at a new
address, never an upgrade, and the old ones keep working.

- `program/`: the program (Anchor 1.2), its LiteSVM tests and its fuzzer.
- `client/`: builds every instruction and reads every account and event. It talks to no network
  of its own.
- `devnet/`: the deploy script and the public record of what runs on devnet.

## How it works

### A deal, start to end

A buyer pays a seller for an hour of maths.

1. **The offer.** The seller's offer, which it publishes to say what it sells, has a price, and an
   index, a service that reads what profiles publish and scores them, shows it. The buyer's app
   reads the offer and agrees the amount.
2. **Opening and paying in.** The buyer's app makes the terms (`termsFor`), then in one
   transaction opens the escrow (`create`) and pays the amount into it (`createAndFund`). Or the
   seller opens it first, as an invoice, and the buyer pays into it
   ([Two ways to open it](#two-ways-to-open-it)).
3. **The money waits.** Neither side can take it alone; each side can only give it to the other.
4. **The money leaves.** The buyer releases it to the seller once the hour is done; or the seller
   gives it back; or both sign a split; or the arbiter or the timer, if the terms named one,
   decides ([How money leaves](#how-money-leaves)).
5. **The receipt stays.** The escrow's account stays at its address, saying how the deal ended,
   and each side's review names that address as its evidence ([The receipt](#the-receipt)).

A buyer with nothing to wait for does steps 2 and 4 in one transaction: `payInOneTap`.

### The terms in the address

An escrow's terms are the buyer, the seller, the mint, the amount, the arbiter, the timer, and
an id. Its address is `["escrow", sha256(terms)]`, the terms at fixed lengths in the receipt's
order (`terms_hash` in `program/src/state.rs`). So:

- a payment sent to that address counts only toward a deal with exactly those terms;
- only the buyer or the seller can open it, and who opens it is not a term, so either lands at the
  same address; one the seller opens is an invoice;
- the id tells apart two deals with the same terms: the app picks a fresh 64-bit number for each
  (`randomId()`).

`create` names both keys, the mint, the amount and any options. The party opening it signs, and
so does whoever fronts the rent, the deposit Solana holds in every account and gives back when it
closes, recorded as the payer ([Rent](#rent)).

### Two ways to open it

`create` takes either party as its creator, so an escrow opens one of two ways:

- **The buyer opens it from an offer.** The buyer's app reads the seller's offer and names the
  seller's address, the amount (the offer's price, times the hours or days bought), the dollar
  (the price's mint) and the options (the arbiter and the timer in the offer's `terms`, if any):
  `termsFor`, then `createIx`. It usually pays in the same transaction (`createAndFund`).
- **The seller opens it for one buyer: an invoice.** The seller's app names the buyer, the amount,
  the dollar and the options (`invoiceIx`). The buyer pays into its address with a plain transfer,
  from anywhere ([Paying in](#paying-in)), or in one tap (`payInvoiceInOneTap`).

### Paying in

- **The mint** is one made by the classic SPL Token program or by Token-2022, but not wrapped SOL
  of either (SOL sent to its deposit account by a plain transfer would not count), a Token-2022
  mint with a transfer fee (it would take part of every payment, while every way out pays the
  whole balance), or one that cannot be transferred (it could never leave). A dollar, here, is
  such a mint made to track the US dollar, such as Open USD; what its maker can still do is in
  [Limits](#limits).
- **The deposit address** is the escrow's associated token account for the mint, so a payment
  sent "to the escrow's address" from anywhere lands there. Money arrives by a plain transfer,
  from anywhere; a payment in a Token-2022 mint must be a `transfer_checked`. Confidential
  transfers never reach a deposit account: turning them on needs a signature the escrow never
  gives. Interest-bearing and scaled dollars work: the escrow holds and pays raw base units,
  fixed at creation, and only what they display drifts.
- **Funded** is the live balance: the escrow is funded while its deposit account holds at least
  the amount. Every way out checks the balance itself; nothing needs to mark it first.
- **`mark_funded`**, sent by anyone, records when the amount was there. Only the timer needs it:
  the timer counts from the mark, so only the side the timer favours has a reason to send it.
- **The amount** is one payment: an app multiplies a price per hour or per day before `create`,
  one escrow per payment.
- **The deposit address is made first** when paying in the same transaction as `create`
  (`createAndFund` and the one-tap builders do), so a fee payer (a service that pays Solana's
  costs for others) that checks every transfer's destination before it signs finds it made.

### The arbiter and the timer

Both are off unless the creator sets them in `create`. From then on they are in the escrow, for
both sides to read before anyone works or pays, and they never change.

- **The arbiter** is any key but the buyer's or the seller's, and may sign any split. A party as
  arbiter could take everything alone; who holds any other key, the program cannot tell.
- **The timer** is a number of whole days, 1 to 65,535, after the funding is marked; from then
  anyone may send everything to the side it names.
- **An objection.** Either side may object, once, before the timer is due. It moves no money and
  turns the timer off for good: after it, money leaves only by the two sides agreeing, or by the
  arbiter if one was named. The timer's due time is the one deadline: before it only the
  objection can land, from it on only the timer, so the two never race. A timer nobody marked is
  never due, so an objection to it is never late; an escrow with no timer takes an objection too,
  which then changes only the receipt.

The program cannot tell whether the other side read the options. The app reads the escrow off the
chain and shows every option the person did not set (`optionsNotAgreed`) before they work or pay;
working or paying after that is the agreement. Before paying an invoice, it also checks that the
invoice names the person's own key as buyer. A timer pays the side it names only if the other
side stays silent.

### How money leaves

1. **Both agree.** The buyer releases everything to the seller, the seller releases everything
   back to the buyer, or both sign a split at any percentage. Receiving in full never needs the
   receiver's signature, so each side alone can give, and only together can they divide.
2. **The arbiter** signs any split.
3. **The timer**, once due and if nobody objected, sends everything to the side it names; anyone
   may send it.

Every way out pays the whole balance, and pays each side only at its standard token account for
the mint (its associated token account), so no ending can send money anywhere else. The program
checks that account by its address alone, not by who holds it now, so a side that hands its
account to another key cannot block any way out. If the account does not exist yet, whoever sends
the way out makes it first (`makeStandardAccountIx`).

Three more instructions move money that is not the deal's:

- **`close_unfunded`:** an escrow that never held the amount is closed by either party, at any
  time. Whatever arrived goes back to the buyer, and both rents to the payer. No receipt is kept:
  nothing was dealt.
- **`recover_late`:** money sent after the end goes back to the buyer. Anyone may send it.
- **`sweep_rent`:** lamports above the receipt's rent-exempt minimum (SOL sent to the escrow's
  address, or what a cut in Solana's rent frees) go to the payer. Anyone may send it.

### The receipt

When an escrow ends, its deposit account closes and the escrow account stays at its address as
the receipt: the buyer, the seller, who opened it, the mint, the amount, the arbiter and the
timer, who fronted the rent, when the money was there (the mark's time, or the ending's if nobody
marked it), whether a side objected and when, how it ended, when, and what each side got. A
receipt never closes and never changes, and its address never holds a second deal, so the address
is what a review names as its deal's evidence ([records/](../../records/README.md#folders)).

Every change is also an event, so an index can read outcomes from the log: `Created`, `Funded`,
`Objected`, `Ended`, `Closed`, `RecoveredLate`, `RentSwept`.

### Rent

Solana holds a deposit, its rent, in every account, and gives it back when the account closes.
Whoever fronts an escrow's rent signs `create` as payer, is recorded, and gets every rent back:
the deposit account's at every ending, both rents at `close_unfunded`, and, by `sweep_rent`,
whatever a cut in Solana's rent later frees above the receipt's minimum. Refunds arrive in SOL, to
that key. A fee payer may front it; what it charges for that is its own choice.

One rent goes elsewhere. A payment that arrives after an escrow ended makes its closed deposit
account again, and that payment is almost always the buyer's own, so the buyer paid that account's
rent: `recover_late` sends it to the buyer, with the late money.

At today's 5,080 lamports a byte, the escrow account is 305 bytes (2,199,640 lamports), and comes
back whole only if it never held the amount; otherwise the receipt keeps its minimum. A classic
deposit account is 165 bytes; one for Open USD's extensions, 179 (1,559,560 lamports). It comes
back to the payer at every ending.

### The state table

| From | Instruction | Signs | Needs | To |
|---|---|---|---|---|
| nothing | `create` | the buyer or the seller as creator, and whoever fronts the rent as payer | address `["escrow", sha256(terms)]`; buyer and seller differ; no zero keys; the arbiter, if any, neither party; neither party the escrow's own address or its deposit address; amount above zero; a timer, if any, of at least one day; a mint owned by the token program named, not wrapped SOL, no transfer fee, transferable; no escrow already at the address | open; the creator recorded, and the payer as rent recipient |
| open | `mark_funded` | nobody | the deposit account holds at least the amount | funded, `funded_at` = now |
| open, funded | `object` | the buyer or the seller | nobody objected yet; the timer, if it runs, not yet due | unchanged: the objection and its time recorded |
| open, funded | `release_to_seller` | the buyer | the deposit account holds at least the amount | ended: the whole balance to the seller |
| open, funded | `release_to_buyer` | the seller | the same | ended: the whole balance to the buyer |
| open, funded | `split(seller_bps)` | the buyer and the seller | the same; `seller_bps` ≤ 10,000 | ended: `⌊balance × seller_bps / 10,000⌋` to the seller, the rest to the buyer |
| open, funded | `arbitrate(seller_bps)` | the arbiter | an arbiter was named; the same | ended: the same split |
| funded | `timer_release` | nobody | a timer was set; nobody objected; now ≥ `funded_at` + days × 86,400 | ended: the whole balance to the side the timer names |
| open, funded | `close_unfunded` | the buyer or the seller | the deposit account holds less than the amount | gone: what it held to the buyer, both accounts closed, both rents to the payer |
| ended | `recover_late` | anyone; the sender makes the buyer's standard account if missing | a later payment made the deposit account again | unchanged: the late money to the buyer, that account's rent to the buyer |
| anything but gone | `sweep_rent` | nobody | the escrow account holds more than its rent-exempt minimum | unchanged: the excess to the payer |
| ended | anything else | | | refused: `Ended` |

"Funded" in the Needs column is the live balance, never the status. Every ending from open (nobody
marked the funding) writes its own time into `funded_at`. The objection is not a status: an
objected escrow is open or funded, and ends by any way out but the timer.

### Use it

- `termsFor(postTerms, deal)`, `optionsFromPost(postTerms)`: an escrow's terms from an offer's
  optional `terms` block ([offer schema](../../records/schemas/offer.json)) and the deal.
- `tokenOf(mint, account)`: the mint's token program and decimals, read from its account; it
  refuses what `create` refuses.
- `createIx`, `invoiceIx`, `createAndFund`, `payInOneTap`, `payInvoiceInOneTap`: opening; opening
  and funding; paying and releasing in one transaction.
- `markFundedIx`, `objectIx`, `releaseToSellerIx`, `releaseToBuyerIx`, `splitIx`, `arbitrateIx`,
  `timerReleaseIx`, `closeUnfundedIx`, `recoverLateIx`, `sweepRentIx`: every other instruction.
- `keysFor`, `keysOf`: every account a way out names, from the terms or from the escrow read off
  the chain.
- `optionsNotAgreed`, `assertOptionsAgreed`: every arbiter and timer a person did not set, and
  which side a timer favours.
- `timerDueAt`, `timerDue`, `canObject`: when the timer is due, and whether an objection would
  land now.
- `escrowAddress`, `termsHash`, `termsOf`, `vaultAddress`, `refundAddress`, `payoutAddress`,
  `makeDepositAddressIx`, `makeStandardAccountIx`, `makeRefundAddressIx`: addresses (an escrow's
  from its terms), and the accounts a payment needs made first.
- `hookAccounts`, `payoutTransfers`: a transfer hook's accounts, through `@solana/spl-token`'s
  resolver. A transfer hook is a program a Token-2022 mint's maker can name, which runs on every
  transfer of that mint and can refuse it.
- `decodeEscrow`, `decodeEvents`: the receipt and the events. `decodeEvents` reads only events
  this program wrote, by the runtime's own invoke lines.

**What the app decides**, because the program does not know:

- **The options.** Check them before anyone works or pays
  ([The arbiter and the timer](#the-arbiter-and-the-timer)).
- **When to offer the objection, and what to say.** The program records nothing about why.
  `canObject` reads the device's clock; the chain's decides, so one sent in the last seconds may
  be refused.
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
and mints with one other extension each. They move the clock by hand and check the wire format
against a second copy written in `program/tests-litesvm/src/lib.rs`.

The fuzzer sends random flows against a model of every escrow and checks fifteen invariants after
every step (`program/trident-tests/fuzz_escrow/test_fuzz.rs` lists them); `FOREST_FUZZ_ITERATIONS`
sets its size. It needs the old program format, so it runs a v0 build. Before the LiteSVM tests
again, delete `program/target/deploy/forest_escrow.so` and build v3: `cargo build-sbf` does not
copy a build it already holds over the v0 one.

Measured under LiteSVM with the harness's keys; address derivations make each figure vary by up
to about 20,000 compute units with the keys.

| | Compute units | Bytes of 1,232 |
|---|---|---|
| `create`, classic mint | 32,646 | 595 |
| `object` | 4,049 | 347 |
| `release_to_seller`, classic | 14,566 | 480 |
| `split`, classic | 19,146 | 612 |
| one tap, classic | 48,161 | 702 |
| an invoice paid in one tap, classic | 13,140 | 527 |
| `create`, Open USD's extensions, no hook program | 53,150 | 595 |
| one tap, the same | 62,969 | 704 |
| one tap, a hook with two accounts | 99,100 | 872 |

### What is sealed

None of this can change after the mainnet deploy; on devnet the program is still upgradable.

- **The account.** 297 bytes after the discriminator, laid out in `program/src/state.rs` (and
  written again in `program/tests-litesvm/src/lib.rs` and `client/src/program.ts`): version, id,
  buyer, seller, arbiter, mint, deposit account, rent recipient (the payer), amount, creator,
  timer days, timer side, created, funded, status, bump, ended, outcome, what the seller got, what
  the buyer got, payer, objection, objected at. `version` is 2: it says which program's rules an
  escrow follows, and a new program writes its own. The zero key means no arbiter; zero days, no
  timer; a zero time, not yet.
- **The addresses.** The escrow at `["escrow", sha256(terms)]`; the deposit account its associated
  token account for the mint, under the mint's own token program; each party paid only at its own
  associated token account, checked by address alone.
- **The rules,** as the state table says, and the order of checks in each handler, which decides
  the error a refused instruction returns. Every handler that needs a live escrow checks that
  first, as an allowlist of the live states (open, funded).
- **The instructions, events and errors.** Eleven instructions, seven events and 32 errors, their
  bytes and account lists. In every way out, the mint comes right after the deposit account, and
  the only accounts it names are the ones it pays. Any accounts a transaction adds after the
  instruction's own are passed on to each transfer, never as signers, for the mint's transfer
  hook.

On mainnet the program is sealed the day it deploys:

```
solana program deploy --program-id <program-keypair.json> target/deploy/forest_escrow.so
solana program set-upgrade-authority <PROGRAM_ID> --final
solana program show <PROGRAM_ID>        # Authority: none
```

The source's program id, `FoRE2EscrowV2objectsTimerFundedAtPayer222222`, is for local work; no
keypair for it exists. Each deploy uses its own.

### Devnet

On devnet the program is built as SBPF v3 and not sealed: its upgrade authority is the devnet
deploy key. `devnet/deploy.sh` builds a copy of the source with the devnet id put in, deploys a
fresh id or upgrades it in place, checks the deployed bytes against the build, and records
everything public in [`devnet/devnet.json`](devnet/devnet.json); its header holds the recipe for
every devnet key it needs. `client/scripts/devnet.ts` runs five deals there, recorded in the same
file: in the classic test dollar (`testDollar`), an invoice paid in one tap and an escrow with a
timer the buyer objected to, then split; the same two in a Token-2022 dollar made with Open USD's
extensions, and one more invoice in it. There is no smoke test: read a receipt with
`solana account <address> --url devnet`, and decode it with `decodeEscrow`.

## Promises

- **Nothing in the escrow program lets anyone but the two sides, the arbiter or the timer move the
  money.** Money leaves a funded escrow only by a release from the side giving it up, a split both
  sign, the arbiter named at creation, or the timer set at creation once due and while nobody has
  objected.
- **Every way out pays the whole balance,** to the parties' standard token accounts and nowhere
  else.
- **An address holds only its own terms.** A payment to an escrow's address counts only toward a
  deal with exactly the terms the address was made from.
- **Each side alone can always give.** Nothing in the escrow stops it: while an escrow is live, the
  buyer can release to the seller and the seller back to the buyer, whatever the options and
  whether or not anyone objected.
- **An objection moves no money,** lands once per escrow, and only before the timer is due; after it
  the timer never pays.
- **A receipt never closes and never changes,** and its address never holds a second deal.
- **Rent goes back to whoever fronted it:** every rent to the payer, at every ending, at
  `close_unfunded` and by `sweep_rent`; a deposit account a late payment made again, to the buyer.
- **Nothing inside charges anything.** No admin, no config account, no pause, no fee.

## Limits

- **It trusts** the SPL Token and Token-2022 programs, the associated token program, and Anchor
  1.2; and the app, to show a person every option they did not agree to before they work or pay.
- **The dollar's maker keeps its powers over its dollar.** A maker like Open USD's can freeze
  balances or take them back, an escrow's deposit included, and nothing in the program can stop
  it.
- **A deadlock holds the money.** With no arbiter, if neither side gives and they do not agree,
  the money stays in the escrow for good: after an objection, or with no timer at all. Nothing in
  the program can break it. A deal that may need a third view names an arbiter at the start.
- **Options nobody checked.** The program runs whatever options the creator set. A one-day timer
  to the creator's own side runs if the other side never read the escrow and never objected.
- **A timer is a default, not a promise.** Either side can turn it off the day before it is due.
- **Money sent to an address before its escrow opens, or after a close,** waits there, and counts
  only toward an escrow opened with exactly those terms. Either party can open one, and close it
  if it holds less than the amount, which sends the money back to the buyer.
- **A party whose standard account requires a memo blocks its own payouts:** the escrow sends none.
- **SOL sent to an escrow's address** goes to the payer by `sweep_rent`. **Money of another mint**
  sent there is lost to everyone.
- **A one-sided receipt is cheap:** a buyer can release one base unit to a seller who signed
  nothing. The receipt records who created it.
- **Hook accounts are the client's to find;** a missing one fails the transfer and nothing moves.
  No dollar on devnet names a hook program: a hook program runs only under LiteSVM, as a builtin.
- **Tested, not audited.** The fuzzer runs an SBPF v0 build, since its runtime runs no v3 program,
  on a classic mint only, and its runtime checks no signatures. There is no local-validator test:
  the devnet run is the client's only run against a real runtime. A Solana Pay link to an
  escrow's address is untried on a phone. No paid review.

The [security checklist](security-checklist.md) lists every known limit, with the test that pins
each.

## Who decides what

- **The standard:** the program's rules and the receipt, to be sealed on mainnet.
- **An app, with the person:** the terms, the arbiter, the timer's default, and which escrow to
  use.
- **A fee payer chooses** which transactions it pays for, and what it charges for fronting rent.

## FAQ

**We disagree and there is no arbiter. Why does the money stay?**
Nobody else can move it, Forest included: it stays until the two of you agree, or one of you
gives. A timer that ended the hold would reward whoever waits. If you want someone to decide,
choose an arbiter at the start.

**Why can someone open an escrow without the other side signing?**
Asking the seller to sign `create` would stop anyone paying a seller who is offline, and break
paying in one tap. The receipt records who created it instead.
