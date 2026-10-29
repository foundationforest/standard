# escrows

Part of [Forest's standard](../README.md).

## What it is

A lockbox on chain that holds a deal's money between two keys, a payer and a recipient, under a
schedule set when it opens: what each side may do alone, until when, and what happens at the end.
One program runs every schedule, so a new kind of deal is new parameters, never new code, and an
escrow that held the money leaves a receipt saying how the deal ended. It is the one program in the
standard, since nobody runs it once it is deployed. Each chain has its own directory; only
[`solana/`](solana/README.md) has one, on devnet, Solana's test network.

## How it works

### The schedule

```
{ "windows": [ { "until": <unix seconds>, "payerShare": <0 to 10000> } ], "end": "pay" | "refund" }
```

- **`windows`** holds one to four windows, sorted by `until`, each later than the one before. The
  last `until` is the escrow's end time.
- **A window** runs from the `until` before it (the first, from the opening) up to, not including,
  its own. At any second, the window in force is the first whose `until` is still ahead.
- **`payerShare`** is the share of the money the payer may take back alone in that window, in basis
  points: 10000 all of it, 5000 half, 0 none.
- **`end`** is the default: from the end time on, everything goes to the recipient (`pay`) or back
  to the payer (`refund`).

Beside the schedule, an escrow may name an **arbiter**: a key that is neither side's and may decide
any split. Both are optional, fixed when the escrow opens and part of its address. Whoever opens it
writes them, and the other side reads them before working or paying; a market may suggest an offer
field that carries them ([markets](https://github.com/foundationforest/markets)). An escrow with no
schedule has no take-back and no default: a payment made and given at once needs none, and a deal
with no default should not have one invented for it. Every time is a date fixed at the opening, so
"3 days after payment" is exact only when the payer opens and pays in one transaction.

| Deal | Windows, with `payerShare` | `end` |
|---|---|---|
| Paid in a week unless stopped | one, to a week from now: 0 | `pay` |
| A ticket: all back until a week before the event, half back until the day before, paid a day after | three: 10000, 5000, 0 | `pay` |
| A deposit, held until two weeks after a lease ends, then back unless the recipient stops it | one: 0 | `refund` |

### The moves

Seven moves, and every one that moves money pays the whole balance and ends the escrow.

1. **Generous, always.** `pay`: the payer gives everything to the recipient. `refund`: the recipient
   gives everything back. Either runs once the escrow holds the deal's full amount, in any state, a
   stop included, since it needs nobody else's consent.
2. **Selfish, by the schedule.** `takeBack`: the payer, inside a window whose share is above 0,
   takes back that share; the rest goes to the recipient. In a window of 0, giving everything is
   `pay`.
3. **`stop`:** either side, once, before the end time. It moves no money, and from then on `end`
   does not run. `takeBack` still runs by its windows, which both sides agreed at the start: a stop
   disputes the ending by the clock, not a right given at the start.
4. **`agree`** (both sign any split) and **`decide`** (the arbiter, if one was named, signs any
   split), in any state, stopped or not.
5. **`end`:** anyone, from the end time on, if nobody stopped: everything to the side `end` names.
   A stop lands only before the end time and `end` only from it, so the two never race.

The money counts toward the default only if it arrived before the end time. Anyone may mark an
escrow funded, once, while it holds the amount and before the end time, and `end` pays only a
marked escrow. From the end time on, either side may close an escrow that was never marked and
never stopped: everything goes back to the payer, and no receipt is kept. So the side the default
favours marks any payment it sees before the end time, and an app that pays marks in the same
transaction.

## Use it

The ticket, for an event at the start of 1 June 2027 (unix `1811808000`):

```json
{ "windows": [
    { "until": 1811203200, "payerShare": 10000 },
    { "until": 1811721600, "payerShare": 5000 },
    { "until": 1811894400, "payerShare": 0 } ],
  "end": "pay" }
```

## Limits

- **One chain.** Only Solana has an escrow here, and only on devnet, so no real money moves through
  it.
- **Without an arbiter, a stop can hold the money for good** once the last take-back window has
  closed, and so can an escrow with no schedule at all: only a side giving or both agreeing moves it
  then. A deal that may need a third view names an arbiter at the start.
- **One escrow, one payment.** A rule about many payments at once, such as a floor on how many
  tickets must sell before any is paid, cannot be written as one escrow's schedule.

## FAQ

**We disagree and there is no arbiter. Why does the money stay?**
Nobody else can move it, Forest included: it stays until the two of you agree, or one of you gives.
A default that ended a stop would reward whoever waits. If you want someone to decide, choose an
arbiter at the start.
