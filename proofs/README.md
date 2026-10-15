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

The device makes a proof from the seed scalar, the one number `keys/` mixes from the seed for the
proofs ([keys](../keys/README.md#the-seed-scalar)), so the seed never leaves the device. Inside
both proofs, the profile's key is worked out from the seed scalar the way `keys/` mixes it, so a
proof holds only for a profile of the seed behind it.

## Promises

Each proof's promises are in its own README: [human](human/README.md#promises) and
[reputation](reputation/README.md#promises).

## Limits

Each proof's limits are in its own README: [human](human/README.md#limits) and
[reputation](reputation/README.md#limits).

## Who decides what

Each proof's README says it: [human](human/README.md#who-decides-what) and
[reputation](reputation/README.md#who-decides-what).

## FAQ

**Why are both proofs in one folder?**
Both are made on the person's device from the seed scalar `keys/` gives, and both are checked by
anyone. They share pieces: both take the stamp, the scope and the profile's key from `keys/`, and
`reputation/`'s client takes the proof's 256-byte form from `human/`'s.
