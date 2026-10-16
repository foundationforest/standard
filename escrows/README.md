# escrows

Part of Forest's standard: [the top README](../README.md).

## What it is

On-chain lockboxes for payment, one directory for each blockchain. An escrow holds a deal's money
between two keys, a payer and a recipient, under a schedule set when it opens: what each side may
do alone, until when, and what happens at the end. One program runs every schedule, so a new kind
of deal is new parameters, never new code. An escrow that held the money leaves a receipt saying
how the deal ended.

- [`solana/`](solana/README.md): the escrow on Solana, on devnet.

## How it works

### The schedule

```
{ "windows": [ { "until": <unix seconds>, "payerShare": <0 to 10000> } ], "end": "pay" | "refund" }
```

- **`windows`** holds one to four windows, sorted by `until`, each later than the one before. The
  last `until` is the escrow's end time.
- **A window** runs from the `until` before it (the first, from the opening) up to, not including,
  its own `until`. At any second, the window in force is the first whose `until` is still ahead.
- **`payerShare`** is the share of the money the payer may take back alone during that window, in
  basis points: 10000 all of it, 5000 half, 0 none.
- **`end`** is the default: from the end time on, everything goes to the recipient (`pay`) or back
  to the payer (`refund`).

Beside the schedule, an escrow may name an **arbiter**: a key that is neither side's and may decide
any split. Both are optional, both are fixed when the escrow opens, and both are part of its
address, so the other side reads them before working or paying. An escrow with no schedule has no
take-back and no default.

Every time in a schedule is a date fixed when the escrow opens, so "3 days after payment" is exact
only when the payer opens and pays in one transaction; an invoice's windows are dates the recipient
chose.

Three schedules, in words:

- **Paid in a week unless stopped:** one window to a week from now, `payerShare` 0, `end` `pay`.
- **A ticket:** all back until a week before the event, half back until the day before, nothing
  back after that, paid a day after the event: three windows, 10000, 5000 and 0, `end` `pay`.
- **A deposit:** held until two weeks after a lease ends, then back to the payer unless the
  recipient stops it first: one window, `payerShare` 0, `end` `refund`.

### The moves

Seven moves, and every one that moves money pays the whole balance and ends the escrow.

1. **Generous moves, always.** A side can always give everything to the other, in any state, a
   stop included, since it needs nobody else's consent:
   - `pay`: the payer gives everything to the recipient;
   - `refund`: the recipient gives everything back to the payer.
2. **Selfish moves, by the schedule.** `takeBack`: the payer, inside a window whose share is above
   0, takes back that share; the rest goes to the recipient. In a window whose share is 0 there is
   nothing to take back: giving everything to the recipient is `pay`.
3. **Stop freezes.** `stop`: either side, once, before the end time. It moves no money. From then
   on neither `takeBack` nor `end` runs, and the money leaves only by a side giving, by
   `agree` (both sign any split), or by `decide` (the arbiter, if one was named, signs any split).
   Those two run in any state, stopped or not.
4. **A default at the end.** `end`: anyone, from the end time on, if nobody stopped: everything to
   the side `end` names.

The money counts toward the default only if it arrived before the end time. Anyone may mark an
escrow funded, once, while it holds the amount and before the end time, and `end` pays only a
marked escrow. From the end time on, either side may close an escrow that was never marked and
never stopped: everything goes back to the payer, and no receipt is kept. So whichever side the
default favours marks any payment it sees before the end time, and an app that pays marks in the
same transaction.

### Each chain's directory

- `program/`: the code that runs on that chain and holds the money, with its tests.
- `client/`: the library that builds its transactions and reads its accounts.
- `devnet/`: the deploy script and the public record of what runs on that chain's test network.

## Promises

Each escrow's promises are in its own README: [solana](solana/README.md#promises).

## Limits

- **One chain.** Only Solana has an escrow here, and only on devnet.
- **Without an arbiter, a stop can hold the money for good.** After a stop, or with no schedule at
  all, an escrow with no arbiter lets the money out only when one side gives it to the other or both
  agree on a split. Nothing else can move it. A deal that may need a third view names an arbiter at
  the start.
- **One escrow, one payment.** A rule about many payments at once, such as a floor on how many
  tickets must sell before any is paid, cannot be written as one escrow's schedule.
- Each escrow's other limits are in its own README: [solana](solana/README.md#limits).

## Who decides what

- **The standard:** the schedule's format and the moves.
- **Whoever opens an escrow** writes its schedule and names its arbiter; **the other side** reads
  both before working or paying, and the client lists every option it did not set, for the app to
  show.
- **A market** may suggest an offer field that carries a schedule
  ([markets](https://github.com/foundationforest/markets)).
- The rest is each escrow's README: [solana](solana/README.md#who-decides-what).

## FAQ

**We disagree and there is no arbiter. Why does the money stay?**
Nobody else can move it, Forest included: it stays until the two of you agree, or one of you gives.
A default that ended a stop would reward whoever waits. If you want someone to decide, choose an
arbiter at the start.

**Why can't a side stop after the end time?**
So that a stop and the default never race. Before the end time only a stop can freeze the escrow;
from it on, only the default can run. A side that wants to dispute does it inside the windows.

**Why can an escrow have no schedule?**
A payment made and given in the same transaction needs none, and a deal with no default should not
have one invented for it. Without a schedule, the money leaves by a side giving, both agreeing, or
the arbiter.
