# reputation

Part of Forest's standard: [the top README](../../README.md). Up: [proofs](../README.md).

## What it is

The reputation proof lets a person carry a score from their profiles (their identities, one for
each label, the free text saying what a profile is for) to another one of theirs, such as a new
profile, without naming any of them. A profile's reviews are its own, and nothing public ties a
person's profiles together; the proof carries the score across without linking them, and only to
a profile of the person's own, so nobody can lend their score to someone else.
It has two uses:

- **Across profiles:** the weighted average of up to eight profiles the person picks, naming none
  of them: each profile's value in the index's tree, weighted by its weight.
- **One profile:** the value of one of their profiles, with its label shown and which profile
  hidden.

It is a zero-knowledge proof: it shows that this is true and nothing else. The person's app makes
it on the device from their seed scalar ([keys](../../keys/README.md#the-seed-scalar)), so the
seed never leaves the device, and any reader checks it, off chain. It is built with
circom 2.2.3, Groth16 on BN254, and the Poseidon and Merkle pieces Semaphore uses.

- `circuit/`: the circuit, its setup, and the tests that make proofs.
- `client/`: the tree an index builds, the proof an app makes, and the check any reader makes.

## How it works

### The tree an index publishes

An index, a service that reads records (what profiles publish) from hosts (the servers that keep
them) and scores profiles as it chooses ([records](../../records/README.md)), publishes its scores as
a tree. The tree is a standard: any index may publish one, and a proof names the root it used, the
one number the whole tree hashes down to. The circuit proves a weighted average over any tree of
`(stamp, scope, value, weight)` leaves an index signs; a proof means only what that index says
that root holds.

- **A leaf** is `Poseidon(stamp, scope, value, weight)`, circomlib's Poseidon with four inputs (the
  circuit and the client name the last two `score` and `count`):
  - `stamp`: the profile's stamp at an issuer ([keys](../../keys/README.md#stamps)), as its note
    proof shows it ([note](../note/README.md#the-note-and-the-note-proof)): an issuer signed a note
    to the seed behind the profile.
  - `scope`: the profile's label as a number, exactly as `keys/` makes it
    ([keys](../../keys/README.md#the-recipe)).
  - `value` and `weight`: each a whole number below 2^32 whose meaning is the index's. The
    circuit outputs the values' average, each weighted by its weight; any other aggregate is a new
    circuit.
- **One leaf per stamp.**
- **The tree** is Semaphore's lean incremental Merkle tree over Poseidon of pairs, with the leaves
  in the index's order: it hashes the leaves in pairs, level by level, up to one number, the root,
  so a short path shows that a leaf is in it. The circuit fixes its depth at 20, so a tree holds at
  most 1,048,576 leaves.
- **The index signs the root with a time,** as a record is signed: EdDSA-Poseidon on Baby Jubjub
  by the index's key, over SHA-256 of `0xff ‖ "forest/v1/reputation\n" ‖ root ‖ time`, shifted
  right one byte ([keys](../../keys/README.md#signatures)). The root is 32 big-endian bytes and
  the time 8 big-endian bytes of milliseconds since 1970. The bytes start with their own text, so
  the signature is never a record's, a message's or a pull's. The index's key is an address, and
  the signature 64 bytes, R8 packed then S.
- **How it publishes them is its own:** every leaf's four fields, in order, with the root, the time
  and the signature, in whatever format the index chooses.

### The reputation proof

[`circuit/reputation.circom`](circuit/reputation.circom), `Reputation(8, 20)`: eight slots,
each one profile, a leaf and its path to the root. The person fills the ones they want and leaves
the rest blank. Eight slots and a depth of 20 are parameters of this circuit: others are a new
circuit and a new setup.

| | Signals |
|---|---|
| Private | `seedScalar`, the number `keys/`'s `seedScalar` gives; for each slot, `used`, the issuer's name hash, the leaf's stamp, scope, value (`score`) and weight (`count`), and its path's length, position and siblings; `profileScope`, the scope of the label of the profile the proof is shown on |
| Public, in this order | `score`, the output, the weighted average; `root`; `profileX`, `profileY`, the key of the profile the proof is shown on; `scope`, the label shown, or 0 |

`profileX` and `profileY` are the key of the profile the proof is shown on, worked out inside the
proof from the same seed scalar as every counted profile's stamp, the way the note proof works it
out ([note](../note/README.md#the-note-and-the-note-proof)). So the proof holds only on a
profile of the person whose seed is behind the counted profiles: it cannot be lent to anyone else,
nor copied to another profile.

Inside the proof:

1. Each used slot's stamp is `Poseidon(scope, issuer secret)`, with the issuer secret
   `Poseidon(issuer tag, seedScalar, the slot's name hash)`. Only the person whose seed it is can
   count those profiles, and each slot may name its own issuer.
2. Each used slot's leaf is in the tree with that root. The root is never 0.
3. A blank slot is all zeros, and every value and weight is below 2^32.
4. No two used slots share a scope, so a profile counts once.
5. A shown scope is the scope of every used slot, so a shown label means exactly one profile.
6. The output is `floor(sum(value * weight) / sum(weight))`, over a weight of at least one. With
   one profile, it is that profile's value.
7. `Poseidon(profile tag, seedScalar, profileScope)` is split into its bits by `Num2Bits_strict`,
   and its lowest 250 bits times `Base8` must be `(profileX, profileY)`: the profile it is shown on
   is the person's own.

Which leaves, and how many, stays hidden. A path's position is one number: the Merkle piece,
zk-kit's `binary-merkle-root` 2.0.0, splits it into bits itself.

### The setup

A Groth16 proof needs a setup, made once for its circuit: whoever knows all of the setup's secret
randomness could make false proofs, so it is made in public by many people, and one honest one is
enough.

- **Phase 1** is public: PSE's Perpetual Powers of Tau, `ppot_0080_16.ptau`, pinned by SHA-256.
- **Phase 2** is one contribution, made once by `circuit/setup/setup.sh`
  ([proofs](../README.md#limits)).
- **What is committed:** `verification-key.json`, and
  [`setup.json`](circuit/setup/setup.json), which records the toolchain, phase 1, the
  contribution's hash, and every file's size and SHA-256.
- **What is not:** the proving key and the witness generator, used only to make a proof. They are
  in the GitHub release `reputation`, and `npm run fetch` refuses anything whose hash does not
  match `setup.json`.
- **The circuit does not change after its setup.** circom gives the same bytes every time, and
  `npm run compile` checks the compiled circuit against `setup.json`. The witness generator carries
  the source's line numbers, so even a line added to a comment fails that check. A change means a
  new setup and a new release.

### Use it

`client/src/` talks to no network: the caller passes the index's leaves, root, time and signature.
The stamp, the scope and the profile's key come from `keys/`, unchanged.

| Function | Gives |
|---|---|
| `buildTree(leaves)` | For an index: the root to sign. Refuses an empty tree, more than 2^20 leaves, a field out of range, or two leaves for one stamp |
| `signedBytes(root, time)` | The bytes an index signs |
| `proveReputation({ seedScalar, sources, leaves, profileLabel, show?, artifacts })` | The proof, on the device: one to eight of the person's profiles, each a `{ label, issuerName }` found in the leaves by its stamp at that issuer, shown on the profile with `profileLabel`; `show` shows the label, only with one |
| `verifyReputation({ proof, root, score, profile, label?, index, time, signature })` | Whether the index (its address or key) signed the root with that time (its 64-byte signature), and the proof holds for that score, shown label and `profile`, the address or key of the profile that shows it |
| `proofBytes(proof)`, `proofFromBytes(bytes)` | The proof as the 256 bytes a profile record carries ([records](../../records/README.md)), and back; `verifyReputation` takes either |
| `circuitInput({...})` | The circuit's input, for a caller that drives snarkjs itself |

```ts
import { seedScalar } from '@foundationforest/keys'
import { proveReputation, verifyReputation } from '@foundationforest/reputation'

// On the device: three profiles' score, from two issuers, shown on a new profile of the same seed.
const r = await proveReputation({
  seedScalar: await seedScalar(seed),
  sources: [
    { label: 'tutoring/seller', issuerName: 'issuer-a.example' },
    { label: 'tutoring/buyer', issuerName: 'issuer-a.example' },
    { label: 'cleaning/seller', issuerName: 'issuer-b.example' },
  ],
  leaves,                      // the index's published leaves, in its order
  profileLabel: 'tutoring/new', // the profile the proof is shown on
  artifacts: {
    wasm: 'proofs/reputation/circuit/setup/reputation.wasm',
    zkey: 'proofs/reputation/circuit/setup/reputation.zkey',
  },
})

// Any reader, with the index's key, the time and signature it published with the root, and the
// address of the profile that shows the proof:
const ok = await verifyReputation({ proof: r.proof, root: r.root, score: r.score, profile: address,
  index, time, signature })
```

### Run it

The toolchain: Node 22.18 or later; circom 2.2.3, the Linux binary from its GitHub release, whose
SHA-256 `setup.json` records; and, from the root's `package-lock.json`, snarkjs 0.7.5, circomlib
2.0.5 and `@zk-kit/binary-merkle-root.circom` 2.0.0.

```
npm ci && npm run build                   # at the root: every package; keys/ and both clients to dist/
cd proofs/reputation/client
npm run check && npm test                 # the tree, what an index signs, what the client refuses
cd proofs/reputation/circuit
npm run fetch                             # the release's files, hash-checked
npm run compile                           # circom 2.2.3 on PATH or in CIRCOM; checks setup.json
npm run check && npm test                 # proofs, and every way one must fail
setup/setup.sh                            # a new setup: new files, every hash new, a new release
```

The client's tests check the tree, the bytes an index signs, the inputs the client refuses, and that
the proof names `keys/`'s main key. The circuit's tests build a tree of made-up leaves around
`keys/`'s test person, prove with one profile and with three from two issuers, shown on another
profile of the person's own. A wrong seed scalar, a slot with the wrong issuer, a leaf not in the
tree, a profile counted twice (also as two issuers' leaves), a label shown with two profiles, and a
main key that is not the prover's for its label are refused; a changed output, root or time
fails to verify, and so does a proof shown on someone else's profile or on another of the
person's own.

### What one proof costs

Measured in Node 22 on a 4-core machine, with 8 slots at depth 20:

| | |
|---|---|
| Constraints | 47,846 |
| Building the tree | about 4.4 s for 5,008 leaves, about 0.9 ms a leaf |
| Making the proof | about 5.3 s more |
| Checking it | about 90 ms |
| The proof | about 725 bytes as snarkjs writes it |

## Promises

- A proof counts only profiles whose stamps come from the prover's own seed.
- A profile counts at most once in a proof.
- A proof lands only on a profile of the prover's own: its key comes from the same seed as the
  profiles it counts.
- A shown label means exactly one profile, under that label.
- The score is the weighted average of the values of the profiles counted, rounded down, and
  nothing else.
- Nothing else about those profiles is in the proof: not which leaves, nor how many, nor their
  issuers.

## Limits

- **In a small tree, the exact score, and the label when shown, can point at one leaf.** The tree
  is public: when few leaves have that score, and that label, the one left names the profile. The
  app should say so before a proof is shown.
- **One seed per proof.** A person with two seeds cannot count one seed's profiles on the other's.
- **The profile it lands on need not hold a note.** The proof shows that profile is the person's
  own, not that an issuer signed its seed a note; a reader that wants both reads its note proofs too
  ([note](../note/README.md)).
- **Building the tree takes time.** About twelve minutes for a million leaves at the speed above. An
  app that asks the index for its path instead tells the index which profiles are its.
- **Not audited.**

## Who decides what

- **The standard:** the leaf, the tree, what an index signs, and the circuit and its public
  signals.
- **An index:** each leaf's value and weight, and what they mean; which reviews count and how much;
  and when and where it publishes its tree.
- **A reader (an app, an index or a service):** which indexes it trusts, since a score is only as
  good as its index; how old a signed root may be; and what a score means to it.
- **The person, with their app:** whether to show a proof; which profiles count, up to eight: a
  proof says "these profiles of mine", never "all of them", so a low-scored one can be left out;
  and whether to show the label.

## FAQ

**Why at most eight profiles?** Each slot costs about 5,700 constraints, most of them its path's
Poseidon hashes. Eight covers two roles in each of four markets and keeps a proof to a few
seconds. More is a new circuit and a new setup.

**Why a depth of 20?** A million leaves per index tree. A deeper tree is a new circuit and a new
setup.

**Why does the proof not say the weights?** An index that wants the number of reviews behind a
profile to count puts it in the value. The weights only weigh one profile against another inside
the proof, and a second output would say more about the person than the average does.

**Why does each slot name its own issuer, and the proof none?** A person's profiles may hold notes
from different issuers, and one seed is behind them all, so the proof counts them together. Which
issuers' stamps a tree holds is the index's choice, made when it read each profile's note proofs,
so a reader trusts the index for it; naming the issuers would tell a reader more about the
person than the score does.

**Why is it checked off chain?** Nothing on chain needs a reputation, and a program that cannot
change could not take a better circuit. Whoever is shown a proof checks it.
