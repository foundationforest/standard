# reputation

Part of Forest's standard: [the top README](../../README.md). Up: [proofs](../README.md).

## What it is

The reputation proof lets a person prove they are trusted on their other profiles, without saying
which. A profile's reviews are its own, and nothing public ties a person's profiles together; the
proof carries a score from their profiles to another profile of their own, such as a new one,
without linking them, and only to a profile of the person's own, so nobody can lend their score to
someone else.

It shows one thing: the plain average of the scores of one to eight of the person's own profiles, in
the tree an index, a service that scores profiles, publishes, shown on another profile of theirs,
naming none of the profiles counted.

It is a zero-knowledge proof: it shows that this is true and nothing else. The person's app makes
it on the device from their seed scalar, the one number the proofs take from the seed
([keys](../../keys/README.md#the-seed-scalar)), so the seed never leaves the device, and any reader
checks it, off chain. It is built with circom 2.2.3, the circuit language; Groth16, a kind of proof
that is small and quick to check, on BN254, the curve the proofs are made on; and the Poseidon and
Merkle pieces Semaphore, a zero-knowledge identity library, uses.

- `circuit/`: the circuit, its setup, and the tests that make proofs.
- `client/`: the tree an index builds, the proof an app makes, and the check any reader makes.

## How it works

### The tree an index publishes

An index reads profiles' records from hosts and scores profiles as it chooses
([records](../../records/README.md)); it publishes its scores as a tree. The tree is a standard: any
index may publish one, and a proof names the root it used, the one number the whole tree hashes down
to. The circuit proves a plain average over any tree of `(key, score)` leaves an index signs; a
proof means only what that index says that root holds.

- **A leaf** is `Poseidon(x, y, score)`, circomlib's Poseidon with three inputs:
  - `x`, `y`: the profile's key, the point its address names, the key its records are signed with
    ([keys](../../keys/README.md#main-keys)).
  - `score`: a whole number below 2^32, meaning what the index says. The circuit outputs the plain
    average of the scores counted; any other aggregate is a new circuit.
- **One leaf per key.**
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
- **How it publishes them is its own:** every leaf's key and score, in order, with the root, the
  time and the signature, in whatever format the index chooses.

### The reputation proof

[`circuit/reputation.circom`](circuit/reputation.circom), `Reputation(8, 20)`: eight slots,
each one profile, a leaf and its path to the root. The person fills the ones they want and leaves
the rest blank. Eight slots and a depth of 20 are parameters of this circuit: others are a new
circuit and a new setup.

| | Signals |
|---|---|
| Private | `seedScalar`, the number `keys/`'s `seedScalar` gives; for each slot, `used`, the scope of its label, its score, and its path's length, position and siblings; `profileScope`, the scope of the label of the profile the proof is shown on |
| Public, in this order | `score`, the output, the plain average; `root`; `profileX`, `profileY`, the key of the profile the proof is shown on |

Every key in the proof, each counted profile's and the one it is shown on, is worked out inside it
from the same seed scalar, the way `keys/` mixes a main key and the verification works it out
([verification](../verification/README.md#the-stamp-and-the-verification)). So the proof counts only
the person's own profiles, and holds only on a profile of theirs: it cannot be lent to anyone else,
nor copied to another profile.

Inside the proof:

1. Each slot's key is the lowest 250 bits of `Poseidon(profile prefix, seedScalar, its scope)`,
   split into bits by `Num2Bits_strict`, times `Base8`.
2. Each used slot's leaf, `Poseidon(x, y, score)`, is in the tree with that root. The root is
   never 0.
3. A blank slot's score is 0, and every score is below 2^32.
4. No two used slots share a scope, so a profile counts once.
5. The output is `floor(sum of the used slots' scores / slots used)`, with at least one used. With
   one profile, it is that profile's score.
6. The key from `profileScope` the same way must be `(profileX, profileY)`: the profile it is shown
   on is the person's own.

Which leaves, and how many, stays hidden. A path's position is one number: the Merkle piece,
zk-kit's `binary-merkle-root` 2.0.0, splits it into bits itself.

### The setup

A Groth16 proof needs a setup, made once for its circuit: whoever knows all of the setup's secret
randomness could make false proofs, so it is made in public by many people, and one honest one is
enough.

- **Phase 1** is public: PSE's Perpetual Powers of Tau, `ppot_0080_16.ptau`, pinned by SHA-256.
- **Phase 2** is one contribution, made once by `circuit/setup/setup.sh`
  ([proofs](../README.md#limits)).
- **What is committed,** in `circuit/setup/`: the proving key, the witness generator (the program
  that works out a proof's private numbers), the verification key, and
  [`setup.json`](circuit/setup/setup.json), which records the toolchain, phase 1, the contribution's
  hash, and every file's size and SHA-256. `npm run fetch` checks the files against their hashes.
- **The circuit does not change after its setup.** circom gives the same bytes every time, and
  `npm run compile` checks the compiled circuit against `setup.json`. The witness generator carries
  the source's line numbers, so even a line added to a comment fails that check. A change means a
  new setup.

### Use it

`client/src/` talks to no network: the caller passes the index's leaves, root, time and signature.
The scope and the profile's key come from `keys/`, unchanged.

| Function | Gives |
|---|---|
| `buildTree(leaves)` | For an index: the root to sign, from leaves `{ profile, score }`, each profile its key as a point. Refuses an empty tree, more than 2^20 leaves, a field out of range, or two leaves for one key |
| `signedBytes(root, time)` | The bytes an index signs |
| `proveReputation({ seedScalar, labels, leaves, profileLabel, artifacts })` | The proof, on the device: one to eight of the person's profiles, by label, each found in the leaves by its key, shown on the profile with `profileLabel` |
| `checkReputation({ proof, root, score, profile, index, time, signature })` | Whether the index (its address or key) signed the root with that time (its 64-byte signature), and the proof holds for that score and `profile`, the address or key of the profile that shows it |
| `proofBytes(proof)`, `proofFromBytes(bytes)` | The proof as the 256 bytes a profile record carries ([records](../../records/README.md)), and back; `checkReputation` takes either |
| `circuitInput({...})` | The circuit's input, for a caller that drives snarkjs itself |

```ts
import { seedScalar } from '@foundationforest/keys'
import { checkReputation, proveReputation } from '@foundationforest/reputation'

// On the device: three profiles' score, shown on a new profile of the same seed.
const r = await proveReputation({
  seedScalar: await seedScalar(seed),
  labels: ['tutoring/seller', 'tutoring/buyer', 'cleaning/seller'],
  leaves,                      // the index's published leaves, in its order
  profileLabel: 'tutoring/new', // the profile the proof is shown on
  artifacts: {
    wasm: 'proofs/reputation/circuit/setup/reputation.wasm',
    zkey: 'proofs/reputation/circuit/setup/reputation.zkey',
  },
})

// Any reader, with the index's key, the time and signature it published with the root, and the
// address of the profile that shows the proof:
const ok = await checkReputation({ proof: r.proof, root: r.root, score: r.score, profile: address,
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
npm run fetch                             # the committed setup files, hash-checked
npm run compile                           # circom 2.2.3 on PATH or in CIRCOM; checks setup.json
npm run check && npm test                 # proofs, and every way one must fail
setup/setup.sh                            # a new setup: new keys, their hashes new
```

The client's tests check the tree, the bytes an index signs, the inputs the client refuses, and that
the proof names `keys/`'s main key. The circuit's tests build a tree of made-up profiles around
`keys/`'s test person and someone else, and prove with one profile and with three, shown on another
profile of the person's own. A wrong seed scalar, a leaf not in the tree, a blank slot with a score,
a profile counted twice, someone else's profile in a slot, a main key that is not the prover's for
its label, a root of 0 and no slot used are refused; a changed output, root or time fails its
check, and so does a proof shown on someone else's profile or on another of the person's own.

### What one proof costs

Measured in Node 22 on a 4-core machine, with 8 slots at depth 20:

| | |
|---|---|
| Constraints | 53,516 |
| Building the tree | about 4.3 s for 5,008 leaves, about 0.9 ms a leaf |
| Making the proof | about 4.8 s more |
| Checking it | about 30 ms |
| The proof | about 725 bytes as snarkjs writes it |

## Promises

- A proof counts only profiles whose keys come from the prover's own seed.
- A profile counts at most once in a proof.
- A proof lands only on a profile of the prover's own: its key comes from the same seed as the
  profiles it counts, so a person with two seeds cannot carry one seed's score to the other's, and
  that profile need not hold a stamp of its own: a reader that wants one reads its verifications
  ([verification](../verification/README.md)).
- The score is the plain average of the scores of the profiles counted, rounded down, and nothing
  else.
- Nothing else about those profiles is in the proof: not which leaves, nor how many, though in a
  small tree the exact score can point at one leaf.

## Limits

- **In a small tree, the exact score can point at one leaf.** The tree is public: when few leaves
  have that score, the one left names the profile. The app should say so before a proof is shown.
- **Building the tree takes time.** About fifteen minutes for a million leaves at the speed above.
  An app that asks the index for its path instead tells the index which profiles are its.
- **Not audited.**

## Who decides what

- **The standard:** the leaf, the tree, what an index signs, and the circuit and its public
  signals.
- **An index:** which profiles its tree holds, each one's score and what it means; which reviews
  count and how much; and when and where it publishes its tree.
- **A reader (an app, an index or a service):** which indexes it trusts, since a score is only as
  good as its index; how old a signed root may be; and what a score means to it.
- **The person, with their app:** whether to show a proof; and which profiles count, up to eight: a
  proof says "these profiles of mine", never "all of them", so a low-scored one can be left out.

## FAQ

**Why at most eight profiles?** Each slot costs about 6,500 constraints, most of them its path's
Poseidon hashes. Eight covers two roles in each of four markets and keeps a proof to a few
seconds. More is a new circuit and a new setup.

**Why a depth of 20?** A million leaves per index tree. A deeper tree is a new circuit and a new
setup.

**Why is it checked off chain?** Nothing on chain needs a reputation, and a program that cannot
change could not take a better circuit. Whoever is shown a proof checks it.
