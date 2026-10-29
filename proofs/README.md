# proofs

Part of [Forest's standard](../README.md).

## What it is

Two zero-knowledge proofs a person's device makes from the seed and anyone checks. A
zero-knowledge proof shows that something is true of a secret without showing the secret. **The
verification** shows that a verifier signed a stamp to the seed behind a profile; **the reputation
proof** shows, on one of the person's profiles, the plain average of the scores of one to eight of
their profiles in an index's tree, naming none. Each is one statement with its own circuit and its
own setup, in `verification/` and `reputation/`. Both are one package, `@foundationforest/proofs`,
since both are made on the device, checked by anyone, and share their pieces: `src/` is the one
client, which talks to no network.

## How it works

- The device makes a proof from the seed's number ([keys](../keys/README.md#the-recipe)), so the
  seed never leaves it. Inside both proofs, the profile's key is worked out from the seed as keys/
  mixes it, so a proof holds only for a profile of the seed behind it, and a second key for the same
  label has no proof.
- No chain is touched: a profile shows its proofs in its profile entry
  ([folders](../folders/README.md#proofs)), and whoever reads them checks them. The entry takes any
  circuit's proofs, and a reader skips one it does not know: these two are ours, and anyone can add
  one.
- Both are built with circom 2.2.3, the circuit language; Groth16, a kind of proof that is small and
  quick to check, on BN254; and the Poseidon and Merkle pieces of Semaphore, a zero-knowledge
  identity library.
- A circuit never changes after its setup. A new version is a new circuit under a new name, with a
  setup of its own, and a profile can show a proof of each.

### The stamp and the verification

```
device ── its stamp number for the verifier ──▶ verifier
verifier ── a stamp signed for that stamp number ──▶ device
device ── the verification, for one profile ──▶ its profile entry, for anyone to check
```

Anyone can sign stamps, and whoever does is a verifier. The main way is a verifier that checks one
human per seed and signs them one stamp (one is in
[services](https://github.com/foundationforest/services)); a school, a club or a license board
could sign stamps the same way. A verifier decides whom it signs for and how many stamps each gets;
a reader decides which verifiers count.

**The stamp** is *stamp number, facts, the verifier's name*, signed by the verifier:

- The stamp number is `Poseidon(the seed's number, name hash)`
  ([keys](../keys/README.md#the-recipe)). The device sends it once: the verifier learns nothing
  else mixed from the seed, and sees the same number each time for that person.
- The facts are one number below BN254's scalar order, whatever the verifier puts there, such as a
  hash of what it saw. The proof keeps them private.
- The verifier signs `Poseidon(name hash, stamp number, facts)` by EdDSA-Poseidon, with its service
  key on Baby Jubjub ([keys](../keys/README.md#service-keys)) (`signStamp`). It hashes the stamp
  itself, its name hash first, and never signs a raw number someone hands it, so nothing it signs
  for another purpose can pass as a stamp. Whoever holds its key can sign stamps for people who do
  not exist.
- The person keeps the stamp on their device as JSON, `{ stampNumber, facts, verifier,
  verifierName, signature: { r8: [x, y], s } }`, big numbers in decimal text and the verifier's key
  as its address (`stampToJson`, `stampFromJson`, which refuses these fields in any other shape).
  Fields the verifier adds beside them pass through unchanged, so the person keeps what `facts` was
  made from. A verifier that keeps what it signed may hand a stamp back by its stamp number.

**The verification** proves, showing neither the seed nor the stamp: *I know a seed and a stamp
this verifier signed under its name for the stamp number the seed gives at that name, and this
profile's key is the one the seed gives for this label.* A reader computes the scope and the name
hash itself from the label and the name, so a proof counts for one label at one verifier.

[`verification/verification.circom`](verification/verification.circom):

| | Signals |
|---|---|
| Private | `seed`, the seed's number; the stamp's `facts`; the verifier's signature, `R8x`, `R8y`, `S` |
| Public, in this order | `profileX`, `profileY`; `verifierX`, `verifierY`; `scope`; `verifierNameHash` |

1. The stamp number is `Poseidon(seed, verifierNameHash)`.
2. circomlib's `EdDSAPoseidonVerifier`, unchanged, checks that the verifier's key signed
   `Poseidon(verifierNameHash, stamp number, facts)`.
3. `Poseidon(seed, scope)` is split into bits by `Num2Bits_strict`, its lowest 250 go to circomlib's
   `EscalarMulFix(250, Base8)`, and the point must be `(profileX, profileY)`. The strict split
   matters: about a third of numbers below the field also have a 254-bit spelling, themselves plus
   the field's order, and plain `Num2Bits` would let a prover pick it and get a second key for the
   label.

`proveVerification` refuses a stamp for another seed or verifier name, or one its verifier did not
sign. `checkVerification` takes the verifier's key and the profile each as an address or a point.

### The tree an index publishes

An index reads profiles' entries, scores them as it chooses, and publishes its scores as a tree.
Any index may publish one; a proof names the root it used, and means only what that index says
that root holds.

- **A leaf** is `Poseidon(x, y, score)`: `x`, `y` the profile's key, the point its address names,
  and `score` a whole number below 2^32, meaning what the index says. One leaf per key.
- **The tree** is Semaphore's lean incremental Merkle tree over Poseidon of pairs, the leaves in the
  index's order, at depth 20: at most 1,048,576 leaves (`buildTree`, which refuses an empty tree,
  more leaves, a number out of range, or two leaves for one key).
- **The index signs the root with a time,** by its service key, over the canonical JSON of
  `{ "root", "time" }`, the root in decimal text and the time in whole milliseconds since 1970
  (`signedBytes`). Its fields say what it is, so the signature is never an entry's or a message's.
- **How it publishes** every leaf's key and score, in order, with the root, the time and the
  signature, is its own.

### The reputation proof

[`reputation/reputation.circom`](reputation/reputation.circom), `Reputation(8, 20)`: eight slots,
each a profile's leaf and its path to the root. The person fills the ones they want: a proof says
"these profiles of mine", never "all of them", so a low-scored one can be left out. Eight slots
and depth 20 are this circuit's; others are a new circuit and a new setup.

| | Signals |
|---|---|
| Private | `seed`; for each slot, `used`, its label's scope, its score, and its path's length, position and siblings; `profileScope`, the scope of the profile the proof is shown on |
| Public, in this order | `score`, the output; `root`; `profileX`, `profileY`, the key of the profile it is shown on |

1. Each slot's key is the lowest 250 bits of `Poseidon(seed, its scope)`, split by
   `Num2Bits_strict`, times `Base8`.
2. Each used slot's leaf, `Poseidon(x, y, score)`, is in the tree with that root, and the root is
   never 0.
3. A blank slot's score is 0, and every score is below 2^32.
4. No two used slots share a scope, so a profile counts once.
5. The output is `floor(sum of the used slots' scores / slots used)`, with at least one used.
6. The key from `profileScope`, made the same way, must be `(profileX, profileY)`.

Every key is worked out from the one seed, so the proof counts only the person's own profiles and
holds only on a profile of theirs: it cannot be lent to someone else, nor copied to another
profile. Which leaves, and how many, stays hidden; a path's position is one number, which zk-kit's
`binary-merkle-root` 2.0.0 splits into bits itself. `checkReputation` also checks the index's
signature over the root and the time; which indexes to trust, and how old a time to accept, is the
reader's.

### The setups

A Groth16 proof needs a setup, made once for its circuit: whoever knows all of its secret randomness
could make a false proof, so it is made in public by many people, and one honest one is enough.
Each circuit has its own, in its `setup/`.

- **Phase 1** is public: PSE's Perpetual Powers of Tau, `ppot_0080_16.ptau`, pinned by SHA-256, the
  same file for both.
- **Phase 2** is one contribution, made once by the circuit's `setup/setup.sh` (Limits).
- **Committed:** the proving key, the witness generator (the program that works out a proof's
  private numbers), the verification key, and `setup.json`
  ([verification](verification/setup/setup.json), [reputation](reputation/setup/setup.json)), which
  records the toolchain, phase 1, the contribution's hash, and every file's size and SHA-256.
- circom gives the same bytes every time, so `npm run compile` checks each compiled circuit against
  its `setup.json`. The witness generator carries the source's line numbers, so even a line added
  to a comment fails: a change means a new setup.

### What one proof costs

Measured in Node 22 on a 4-core machine:

| | The verification | The reputation proof, 8 slots at depth 20 |
|---|---|---|
| Constraints | 5,980 | 53,354 |
| Building the tree | none | about 4.1 s for 5,008 leaves, about 0.8 ms a leaf |
| Making the proof | about 0.8 s | about 4.9 s more |
| Checking it | about 25 ms | about 25 ms |
| The proof | about 725 bytes as snarkjs writes it, 256 as a profile carries it (`proofBytes`) | the same |

## Use it

```ts
import { checkReputation, checkVerification, proveReputation, proveVerification } from '@foundationforest/proofs'

const setup = (c: string) => ({ wasm: `proofs/${c}/setup/${c}.wasm`, zkey: `proofs/${c}/setup/${c}.zkey` })

// On the device: a verification for one profile, from the stamp a verifier signed for this seed.
const v = await proveVerification({ seed, stamp, label: 'tutoring/tutor', artifacts: setup('verification') })
// Any reader, from what the profile shows:
await checkVerification({ proof: v.proof, verifier: v.verifier, verifierName: v.verifierName, label: 'tutoring/tutor', profile: v.address }) // true

// Two profiles' score, from the leaves an index published, shown on a third profile of the same seed:
const r = await proveReputation({ seed, labels: ['tutoring/tutor', 'cleaning/cleaner'], leaves, profileLabel: 'tutoring/new', artifacts: setup('reputation') })
await checkReputation({ proof: r.proof, root: r.root, score: r.score, profile: r.address, index, time, signature }) // true
```

## Run it

Node 22.18 or later; circom 2.2.3, the Linux binary from its GitHub release, whose SHA-256 each
`setup.json` records; and, from the root's `package-lock.json`, snarkjs 0.7.5, circomlib 2.0.5 and
`@zk-kit/binary-merkle-root.circom` 2.0.0.

```
npm ci && npm run build        # at the root: every package; keys/ and proofs/ to dist/
cd proofs
npm run fetch                  # each setup's committed files, hash-checked
npm run compile                # circom 2.2.3 on PATH or in CIRCOM; checks each against its setup.json
npm run check && npm test
verification/setup/setup.sh    # a new setup for one circuit: new keys, new hashes
reputation/setup/setup.sh
```

`test/` makes and checks real proofs for keys/'s test person, checks that every way a proof must
fail does (another seed, verifier, name, label or profile; a forged or changed signature; a leaf
not in the tree; a profile counted twice; a changed output, root or time), and proves once with
Node's `Buffer` taken away, as a browser runs it.

## Promises

- **A verification holds only for the stamp behind it.** It holds only when the verifier with that
  key signed a stamp, under that name, for the stamp number the same seed gives at that name, and it
  counts for one label at one verifier: a reader derives the scope and the name hash itself.
- **One seed gives one key per label.** A proof holds only for the key the prover's seed gives for
  the label it shows, though a person with stamps on two seeds has a key for each under one label,
  and a reader that counts both counts that person twice: how many stamps a human gets is each
  verifier's.
- **A reputation proof stays with its person.** It counts only profiles whose keys come from the
  prover's own seed, each at most once, and lands only on a profile of the prover's own, so a
  person with two seeds cannot carry one seed's score to the other's. That profile need not hold a
  stamp of its own: a reader that wants one reads its verifications.
- **The score is the plain average** of the scores of the profiles counted, rounded down, and
  nothing else.
- **Nothing else is in either proof:** not the seed, the stamp or the person, nor which profiles
  were counted or how many, though a verification shows which verifier signed, since its key and
  name hash are public, and in a small tree the exact score can point at one leaf.

## Limits

- Each circuit's setup was made by one party: whoever ran its `setup/setup.sh` could make a false
  proof for that circuit. A public setup ceremony is planned.
- A verifier's name beside a proof is a claim; the key is the fact. Anyone can write any name, and
  a reader trusts keys.
- `facts` is a number the verifier fills, and nothing in the standard reads it.
- A leaked verifier key signs for anyone, and a proof carries no date. An index can note when it
  first saw each proof, so a reader may stop counting proofs under that key first seen after the
  leak.
- In a small tree, the exact score can point at one leaf; the app should say so before a proof is
  shown.
- Building the tree takes about fifteen minutes for a million leaves; an app that asks the index
  for its path instead tells the index which profiles are its.
- Not audited.

## FAQ

**What if I lose my seed?**
Your profiles' keys are gone with it. Whether a verifier signs a stamp to a new seed is that
verifier's choice.

**Can I hold stamps from more than one verifier?**
Yes. Each gives its own verification for the same profile, the profile shows them all, and each
reader decides which count and how much each weighs.

**Why at most eight profiles, in a tree of depth 20?**
Each slot costs about 6,500 constraints, most of them its path's Poseidon hashes; eight covers two
roles in each of four markets and keeps a proof to a few seconds. Depth 20 holds a million leaves.
More of either is a new circuit and a new setup.

**Why is the reputation proof checked off chain?**
Nothing on chain needs a reputation, and a program that cannot change could not take a better
circuit. Whoever is shown a proof checks it.
