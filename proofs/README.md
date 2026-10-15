# proofs

Part of Forest's standard: [the top README](../README.md).

## What it is

The zero-knowledge proofs a person's device makes and anyone can check. A zero-knowledge proof
shows that something is true of the person's secrets without showing the secrets.

- [`human/`](human/README.md): a profile's key and stamp come from a seed an issuer checked, for
  one label.
- [`reputation/`](reputation/README.md): a score across the person's profiles, from the tree an
  index publishes, without saying which profiles.

## How it works

Each proof has two parts:

- `circuit/`: the statement the proof proves, its devnet setup and its tests.
- `client/`: the library the person's device uses to make the proof, and anyone uses to check it.

The device makes a proof from the person's secret for one issuer, which `keys/` mixes from the
seed ([keys](../keys/README.md#the-issuer-secret)), so the secret never leaves the device.

## Promises

Each proof's promises are in its own README: [human](human/README.md#promises) and
[reputation](reputation/README.md#promises).

## Limits

- **Mid-move.** `human/` still holds the registry's circuit and client, and the registry's program
  is no longer in this repo. Its circuit, `person.circom`, is given the profile's main key and
  does not derive it from the seed, and both clients still read registry rows on Solana. Each
  one's README still describes that code, the program included.
- Each proof's other limits are in its own README: [human](human/README.md#limits) and
  [reputation](reputation/README.md#limits).

## Who decides what

Each proof's README says it: [human](human/README.md#who-decides-what) and
[reputation](reputation/README.md#who-decides-what).

## FAQ

**Why are both proofs in one folder?**
Both are made on the person's device from the issuer secret `keys/` gives, and both are checked by
anyone. They share pieces: `reputation/`'s client takes the stamp, the scope and the proof's
256-byte form from `human/`'s.
