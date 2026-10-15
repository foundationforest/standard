# escrows

Part of Forest's standard: [the top README](../README.md).

## What it is

On-chain lockboxes for payment, one folder for each blockchain. An escrow holds a deal's money
between a buyer and a seller, and lets it out only when one side gives it to the other or both
sides agree, or by an arbiter or a timer named at the start. It leaves a receipt saying how the
deal ended.

- [`solana/`](solana/README.md): the escrow on Solana, on devnet today.

## How it works

Each chain's folder holds:

- `program/`: the code that runs on that chain and holds the money, with its tests.
- `client/`: the library that builds its transactions and reads its accounts.
- `devnet/`: the deploy script and the public record of what runs on that chain's test network.

## Promises

Each escrow's promises are in its own README: [solana](solana/README.md#promises).

## Limits

- **One chain.** Only Solana has an escrow here, and only on devnet.
- Each escrow's other limits are in its own README: [solana](solana/README.md#limits).

## Who decides what

Each escrow's README says it: [solana](solana/README.md#who-decides-what).

## FAQ

**Why one folder for each chain?**
An escrow is a program, and a program runs on one chain. Another chain's escrow is its own program,
client and deploy, in a folder of its own beside `solana/`.
