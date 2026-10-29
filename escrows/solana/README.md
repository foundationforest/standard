# solana

Part of [Forest's standard](../../README.md), under [escrows](../README.md). Down: the
[security checklist](security-checklist.md).

## What it is

The escrow program on Solana, and its client. An escrow holds an amount of one mint, one kind of
money such as a dollar, between a payer and a recipient, by the schedule and the moves
[escrows](../README.md) sets out, and leaves a receipt at its address for good: its account, saying
how the deal ended. This version, 4, runs on devnet at `38vLV7TMvJ9bvXT3cbRLEfHUy8WbvHWfjmiUALUyCm5J`
([record](devnet/devnet.json)), its upgrade authority, the key that could replace its code,
removed. On mainnet, Solana's network for real money, it cannot change once deployed either,
because money sits inside it and nobody, the Forest Foundation included, may change the
rules around money already there: a new version is a new program at a new address, and the old ones
keep working. `program/` holds the program (Anchor 1.2), its LiteSVM tests (a Solana runtime that
runs inside the test) and its fuzzer; `client/` builds every instruction and reads every account
and event, talking to no network of its own; `devnet/` holds the deploy script and its record.

## How it works

A deal: the payer's app reads an offer, whose body its market defines
([markets](https://github.com/foundationforest/markets)), opens the escrow and pays in; the money
waits under the schedule; it leaves by one of the moves; the receipt stays at the escrow's address,
for a review to point to. A payer with nothing to wait for pays in and out in one transaction
(`payInOneTap`).

### The terms in the address

An escrow's terms are the payer, the recipient, the mint, the amount, the arbiter, the schedule and
an id. Its address is `["escrow", sha256(terms)]`, the terms at fixed lengths in the receipt's
order, 186 bytes (`terms_hash` in `program/src/state.rs`), so a payment sent there counts only
toward a deal with exactly those terms. The id, a fresh 64-bit number for each deal (`randomId`),
tells apart two deals with the same terms.

`create` takes either party as its creator, and who opens it is not a term, so either lands at the
same address. The creator signs, and so does whoever fronts the rent, recorded as the sponsor
(Rent). It opens one of two ways:

- **The payer opens it from the offer's terms** (`termsFor`, then `createIx`), naming the
  recipient, the amount, the dollar and the options the offer carries, and usually pays and marks
  in the same transaction (`createAndFund`).
- **The recipient opens it for one payer, as an invoice** (`invoiceIx`). The payer pays into its
  address with a plain transfer, from anywhere, and marks it; `fundInvoice` does both in one
  transaction, and `payInvoiceInOneTap` pays it in and out. An invoice's windows are the
  recipient's dates, so a payer who pays late has less of each.

### Paying in

- **The mint** is one of the classic SPL Token program or of Token-2022, its newer program with
  extensions. `create` refuses wrapped SOL (`NativeMint`: a plain SOL transfer would not count), a
  transfer fee (`TransferFee`: it would take part of payments that must be whole) and a token that
  cannot be transferred (`NonTransferable`) (`program/src/errors.rs`). A dollar, here, is such a
  mint made to track the US dollar, such as Open USD; what its maker can still do is in Limits.
- **The deposit address** is the escrow's associated token account for the mint, the one standard
  account a key has for each mint, so a payment sent "to the escrow's address" from anywhere lands
  there. `transfer_checked` is the one transfer both token programs take for every mint, and the
  only one Token-2022 takes from an account with a transfer hook (a program the mint's maker names
  to run on every transfer). Confidential transfers never reach it: turning them on needs a
  signature the escrow never gives. Interest-bearing and scaled dollars work: the escrow holds and
  pays raw base units, fixed at creation.
- **Funded** is the live balance: the deposit account holds at least the amount, and every way out
  checks it.
- **`mark_funded`** records when the amount was there, since a plain transfer never calls the
  program. Anyone may send it, with no signature, once, while the amount is there and before the end
  time; only `end` needs it. `createAndFund` and `fundInvoice` mark in the payment's transaction, so
  one sent after the end time fails whole. A plain transfer that lands late is closed back to the
  payer from the end time on (`close_unfunded`).
- **The amount** is one payment: one escrow per payment.
- **The deposit address is made first** when paying in the same transaction as `create` or into an
  invoice, so a fee payer (a service that pays Solana's costs for others) that checks every
  transfer's destination before it signs finds it made.

### The schedule, the stop and the arbiter

Both options are off unless the creator sets them in `create`, and then never change.

- **The arbiter** is any key but the payer's or the recipient's, since a party as arbiter could take
  everything alone; who holds any other key, the program cannot tell.
- **The schedule** is held as a window count, four windows with zeros past the count, and the
  default. The window in force is read from the chain's clock. Nothing compares the windows with the
  clock at `create`, so a schedule already past opens; the app checks the dates before anyone pays.
- **The end time is the one deadline:** a stop, a mark and a take-back land only before it, the
  default and the late close only from it on, and giving, agreeing and deciding at any time. An
  escrow with no schedule takes a stop at any time while it is live, and the stop then changes only
  the receipt.

The program cannot tell whether the other side read the options. The app reads the escrow off the
chain and shows every option the person did not set (`optionsNotAgreed`) before they work or pay;
working or paying after that is the agreement. Before paying an invoice, it checks that the invoice
names the person's own key as payer, and that its windows are still ahead.

### How money leaves

The moves (`pay`, `refund`, `take_back`, `agree`, `decide`, `end`; the state table) each pay the
whole balance and end the escrow. Receiving in full never needs the receiver's signature, so each
side alone can always give, a stop included. A split gives the payer `⌊balance × share / 10,000⌋`
and the recipient the rest. Each side is paid only at its associated token account for the mint,
checked by its address alone, not by who holds it now, so no ending sends money elsewhere and a side
that hands its account to another key blocks nothing. Whoever sends a way out makes a missing
account first (`makeStandardAccountIx`).

Three more instructions move money that is not the deal's:

- **`close_unfunded`:** either party closes an escrow that holds less than the amount, at any time,
  or, from the end time on, one nobody marked and nobody stopped. What arrived goes back to the
  payer, both rents to the sponsor, and no receipt is kept: nothing was dealt.
- **`recover_late`:** anyone sends money that arrived after the end back to the payer.
- **`sweep_rent`:** anyone sends lamports (SOL's smallest unit) above the receipt's rent-exempt
  minimum, from SOL sent to the address or a cut in Solana's rent, to the sponsor.

### The receipt

When an escrow ends, its deposit account closes and the escrow account stays as the receipt: the
payer, the recipient, who opened it, the mint, the amount, the arbiter and the schedule, who fronted
the rent, when the money was there (the mark's time, or the ending's if nobody marked it), whether a
side stopped it and when, how it ended (`pay`, `refund`, `takeBack`, `agree`, `decide` or `end`),
when, and what each side got. It never closes or changes, and its address never holds a second deal,
so the address is what a review can name; what a review holds is its market's. Every change is also
an event, for an index to read outcomes from the log (`decodeEvents`, which reads only this
program's): `Created` (with the whole schedule), `Funded`, `Stopped`, `Ended`, `Closed`,
`RecoveredLate`, `RentSwept`.

### Rent

Solana holds a deposit, its rent, in every account, and gives it back when the account closes. The
sponsor gets it back, in SOL: the deposit account's at every ending, both rents at
`close_unfunded`, and, by `sweep_rent`, what a cut in Solana's rent frees above the minimum the
receipt keeps for good. A fee payer may front it, and charges for that as it chooses. A payment after
the end makes the deposit account again, almost always at the payer's cost, so `recover_late` sends
that rent to the payer with the late money.

At Solana's 5,080 lamports a byte, the escrow account holds 304 bytes after its 8-byte
discriminator, which names the account's kind (2,235,200 lamports), and comes back whole only at
`close_unfunded`. A classic deposit account is 165 bytes; one for Open USD's extensions, 179
(1,559,560 lamports).

### The state table

| From | Instruction | Signs | Needs | To |
|---|---|---|---|---|
| nothing | `create` | the payer or the recipient as creator, and whoever fronts the rent as sponsor | address `["escrow", sha256(terms)]`; payer and recipient differ; no zero keys; the arbiter, if any, neither party; neither party the escrow's own address or its deposit address; amount above zero; a schedule, if any, of one to four windows, each `until` later than the one before, each `payerShare` at most 10,000; a mint owned by the token program named, not wrapped SOL, no transfer fee, transferable; no escrow already at the address | open; the creator and the sponsor recorded |
| open | `mark_funded` | nobody | before the end time; the deposit account holds at least the amount | funded, `funded_at` = now |
| open, funded | `stop` | the payer or the recipient | nobody stopped yet; before the end time | unchanged: the stop, its side and its time recorded; from then on `end` does not run |
| open, funded | `pay` | the payer | the deposit account holds at least the amount | ended: the whole balance to the recipient |
| open, funded | `refund` | the recipient | the same | ended: the whole balance to the payer |
| open, funded | `take_back` | the payer | a schedule; a window in force, whose `payerShare` is above 0; the same | ended: `⌊balance × payerShare / 10,000⌋` to the payer, the rest to the recipient |
| open, funded | `agree(payer_share)` | the payer and the recipient | `payer_share` ≤ 10,000; the same | ended: `⌊balance × payer_share / 10,000⌋` to the payer, the rest to the recipient |
| open, funded | `decide(payer_share)` | the arbiter | an arbiter was named; the same | ended: the same split |
| funded | `end` | nobody | a schedule; nobody stopped; now ≥ the end time; the same | ended: the whole balance to the side the default names |
| open, funded | `close_unfunded` | the payer or the recipient | the deposit account holds less than the amount; or open, nobody stopped, and now ≥ the end time | gone: what it held to the payer, both accounts closed, both rents to the sponsor |
| ended | `recover_late` | anyone; the sender makes the payer's standard account if missing | a later payment made the deposit account again | unchanged: the late money to the payer, that account's rent to the payer |
| anything but gone | `sweep_rent` | nobody | the escrow account holds more than its rent-exempt minimum | unchanged: the excess to the sponsor |
| ended | anything else | | | refused: `Ended`; one that names the deposit account, closed at the ending, fails first with Anchor's `AccountNotInitialized`, unless a late payment made it again |

"Funded" in Needs is the live balance; the status `funded` is the mark. The end time is the last
window's `until`, against the chain's clock; with no schedule there is none, and a need that names it
holds for `stop` and `mark_funded` and fails for the rest. Every ending from open writes its own time
into `funded_at`. A stop is not a status: a stopped escrow is open or funded, and ends by any way out
but `end`.

### What cannot change

Once the program is deployed to mainnet, none of this changes; a new version is a new program
beside it, and on devnet too it goes to a new address.

- **The account:** 304 bytes after the discriminator: the receipt's fields, with the version, the
  id, the deposit account, when it was created, its status and its bump, laid out in
  `program/src/state.rs` (and again in
  `program/tests-litesvm/src/lib.rs` and `client/src/program.ts`). `version` is 4, saying which
  program's rules an escrow follows; it keeps version 3's layout byte for byte and changes one rule:
  a stop no longer turns off `take_back`. The zero key means no arbiter; a window count of 0, no
  schedule; a zero time, not yet.
- **The addresses:** the escrow at `["escrow", sha256(terms)]`; its deposit account its associated
  token account for the mint, under the mint's own token program; each party paid only at its own,
  checked by address alone.
- **The rules,** as the state table says, and the order of checks in each handler, which decides the
  error a refused instruction returns. Every handler that needs a live escrow checks that first, as
  an allowlist of the live states (open, funded).
- **The instructions, events and errors:** twelve, seven and 31, their bytes and account lists. In
  every way out, the mint comes right after the deposit account, and the only accounts it names are
  the ones it pays. Any accounts a transaction adds after the instruction's own pass on to each
  transfer, never as signers, for the mint's transfer hook.

On mainnet the upgrade authority is removed the day the program deploys:

```
solana program deploy --program-id <program-keypair.json> target/deploy/forest_escrow.so
solana program set-upgrade-authority <PROGRAM_ID> --final
solana program show <PROGRAM_ID>        # Authority: none
```

The source's program id, `FoRE3EscrowV3scheduLeWindowsPayRefund3333333`, is for local work; no
keypair for it exists, and each deploy uses its own.

### Devnet

On devnet the program is built as SBPF v3, a version of the format Solana runs programs in. Version 3
stays at `FA6ZodkyhMDj9yjzY27dk8JDCtcHnJx8mr45Mx9TfKg8`, its upgrade authority still its deploy key,
`2mz33wBK7FKRXoAi7LptGGTwVQJDbrSyrVwbYRCqwP3A`, from another phrase than version 4's (`earlier` in
the record). It was upgraded in place from version 2, whose receipts it refuses (`beforeSchedules`).
Version 4 accepts only accounts it owns, so it refuses every version 3 or 2 receipt, and version 3's
escrows keep version 3's rules there.

`devnet/deploy.sh` takes any phrase. It builds a copy of the source with the devnet id put in,
deploys a fresh id (one holding other bytes is refused), checks the deployed bytes against the build,
removes the upgrade authority, and records everything public in [`devnet/devnet.json`](devnet/devnet.json):
when the record names another program, that program's record (its keys, dollars, deals and
transactions) first moves into `earlier`, whole. Its header holds the recipe for every devnet key it
needs; the keys labelled `buyer` and `seller` act as payer and recipient, and `payer` as the sponsor.
`client/scripts/devnet.ts` runs seven deals there, recorded in the same file, in a classic test
dollar (`testDollar`) and a Token-2022 dollar made with Open USD's extensions (`openUsdShaped`),
each reused when the `payer` key holds its mint authority and made otherwise. There is no smoke test:
read a receipt with `solana account <address> --url devnet`, and decode it with `decodeEscrow`.

## Use it

```ts
import { createAndFund, decodeEscrow, keysOf, optionsNotAgreed, payIx, termsFor, tokenOf } from '@foundationforest/escrow-client'

// The payer's app: the terms from the offer, then one transaction that opens, pays in and marks.
const token = tokenOf(mint, mintAccount)                          // refuses what create refuses
const terms = termsFor(offer, { recipient, amount: 30_000_000n })  // 30 dollars, at 6 decimals
const open = createAndFund({ payer, sponsor, token, terms })      // instructions for one transaction

// Later, from the escrow read off the chain: any option the person did not set, then pay.
const escrow = decodeEscrow(escrowAccount.data)
optionsNotAgreed({ escrow, agreed: offer })                       // [] when the escrow is as agreed
const pay = payIx({ keys: keysOf(escrow, { tokenProgram: token.program }) })
```

The app decides what the program cannot know:

- **The options:** checked before anyone works or pays, and an invoice's dates before paying it;
  `validateTerms` and `validateSchedule` give the program's own refusals before anything is sent.
- **When to offer the stop, and what to say:** the program records nothing about why. `canStop`,
  `canMark`, `canTakeBack` and `canEnd` read the device's clock, but the chain's decides, so a move
  sent in the last seconds may be refused.
- **Marking:** the side the default favours marks any payment it sees before the end time;
  `createAndFund` and `fundInvoice` mark for the payer.
- **Which dollars to offer,** and what to say about each one's maker (Limits); a dollar is known by
  its mint's address, never its name.
- **A hook's accounts:** resolved before each transaction (`hookAccounts`), since the dollar's maker
  can change the hook's program at any time, and passed to each way out and to the payment in.
- **Who fronts the rent** (Rent).

## Run it

```
cd escrows/solana/program && cargo build-sbf --arch v3             # Solana CLI 4.2.2 or later
cd escrows/solana/program/tests-litesvm && cargo test              # classic and Token-2022 mints
cd escrows/solana/program && cargo build-sbf --arch v0 && cd trident-tests \
  && TRIDENT_WITH_EXIT_CODE=1 cargo run --release --bin fuzz_escrow   # 99: an invariant broke
npm ci && cd escrows/solana/client && npm run check && npm test    # no chain needed
FOREST_DEVNET_SEED=<phrase> escrows/solana/devnet/deploy.sh        # devnet: deploy at a new id
cd escrows/solana/client && FOREST_DEVNET_KEYS=<dir> node scripts/devnet.ts
```

The fuzzer needs the old program format, a v0 build, and `FOREST_FUZZ_ITERATIONS` sets its size;
before the LiteSVM tests again, delete `program/target/deploy/forest_escrow.so` and build v3, since
`cargo build-sbf` does not copy a build it already holds over the v0 one.

The LiteSVM tests send every move in every state, on a classic mint and on Token-2022 mints with
Open USD's extensions, and check each answer or its exact error; the fuzzer checks seventeen
invariants after every random step (`program/trident-tests/fuzz_escrow/test_fuzz.rs` lists them).

Measured under LiteSVM with the harness's keys; address derivations make each figure vary by up to
about 20,000 compute units:

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

## Promises

- **Nothing in the escrow program lets anyone but the two sides, the arbiter or the schedule move
  the money.** Money leaves a funded escrow only by a side giving it to the other, a split both
  sign, the arbiter named at creation, or the schedule set at creation: the payer's take-back inside
  a window, or the default once the last window closes and nobody stopped, though from the end time
  on either side may close an escrow nobody marked or stopped, back to the payer.
- **Every way out pays the whole balance,** to the parties' standard token accounts and nowhere
  else.
- **An address holds one deal.** A payment to an escrow's address counts only toward a deal with
  exactly the terms the address was made from, and its receipt never closes and never changes.
- **Each side alone can always give, and a stop moves no money.** While an escrow is live and holds
  its amount, the payer can pay the recipient and the recipient can refund the payer, whatever the
  options and whether or not anyone stopped. A stop lands once per escrow, only before the end time,
  and after it `end` does not run.
- **Nothing inside charges anything, and rent goes back to whoever fronted it.** No admin, no config
  account, no pause, no fee. Every rent goes to the sponsor, at every ending, at `close_unfunded`
  and by `sweep_rent`, but for the rent-exempt minimum a receipt keeps for good; a deposit account a
  late payment made again, to the payer.

## Limits

- It trusts the SPL Token and Token-2022 programs, the associated token program and Anchor 1.2, and
  the app, to show a person every option they did not agree to.
- The dollar's maker keeps its powers: a maker like Open USD's can freeze balances or take them
  back, an escrow's deposit included, and the program cannot stop it.
- Options nobody checked run: a take-back of everything until the work is done, or a one-minute
  schedule paying the creator's side, runs if the other side never read the escrow and never
  stopped it, since a stop holds back only the default.
- The default is not a promise: either side can stop the escrow until the second before the end
  time.
- Money sent to an address before its escrow opens, or after a close, waits there for an escrow
  with exactly those terms, which either party can open, and close back to the payer while it holds
  less than the amount.
- A side whose standard account requires a memo blocks a split, since the escrow sends no memo; a
  share of zero sends no transfer, so a full take-back or a full decision to one side is never
  blocked by the other's account.
- An escrow paid in more than one transfer can be closed by the recipient between them, back to the
  payer: fund in one transaction.
- SOL sent to an escrow's address goes to the sponsor by `sweep_rent`; money of another mint sent
  there is lost to everyone.
- A one-sided receipt is cheap: a payer can pay one base unit to a recipient who signed nothing, and
  the receipt records who created it.
- Hook accounts are the client's to find; a missing one fails the transfer, and nothing moves. No
  dollar on devnet names a hook program: one runs only under LiteSVM, as a builtin.
- Tested, not audited, and no paid review. The fuzzer runs a v0 build, since its runtime runs no v3
  program, on a classic mint only, and checks no signatures. The devnet run is the client's only run
  against a real runtime.
- The [security checklist](security-checklist.md) lists every known limit, with the test that pins
  each.

## FAQ

**Why can someone open an escrow without the other side signing?**
Asking the recipient to sign `create` would stop anyone paying a recipient who is offline, and break
paying in one tap. The receipt records who created it instead.
