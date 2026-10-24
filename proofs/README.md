# proofs

Part of Forest's standard: [the top README](../README.md).

## What it is

The zero-knowledge proofs a person's device makes and anyone can check. A zero-knowledge proof
shows that something is true of the person's secrets without showing the secrets.

- [`stamp/`](stamp/README.md): a verifier signed a stamp to the seed behind a profile, and this is
  the profile's tag for its label at that verifier.
- [`reputation/`](reputation/README.md): a score across the person's profiles, from the tree an
  index publishes, without saying which profiles.

A profile record's proofs list takes any circuit name, and a reader skips the ones it does not
know: these two circuits are ours, and anyone can add one.

## How it works

Each proof has two parts:

- `circuit/`: the statement the proof proves, its setup and its tests.
- `client/`: the library the person's device uses to make the proof, and anyone uses to check it.

The device makes a proof from the seed scalar, the one number `keys/` mixes from the seed for the
proofs ([keys](../keys/README.md#the-seed-scalar)), so the seed never leaves the device. Inside
both proofs, the profile's key is worked out from the seed scalar the way `keys/` mixes it, so a
proof holds only for a profile of the seed behind it.

## Limits

- **Each circuit's setup was made by one party.** Whoever ran a circuit's `circuit/setup/setup.sh`
  could make a false proof for that circuit. A public setup ceremony is on the list.

## FAQ

**Why are both proofs in one directory?**
Both are made on the person's device from the seed scalar `keys/` gives, and both are checked by
anyone. They share pieces: both take the tag, the scope and the profile's key from `keys/`, and
`reputation/`'s client takes the proof's 256-byte form from `stamp/`'s.
