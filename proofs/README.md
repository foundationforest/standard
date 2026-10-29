# proofs

Part of Forest's standard: [the top README](../README.md).

## What it is

The zero-knowledge proofs a person's device makes and anyone can check. A zero-knowledge proof
shows that something is true of the person's secrets without showing the secrets. There are two,
each one statement, with its own circuit and its own setup:

- **The verification:** what a profile shows to prove that a verifier, one who checks people and
  signs them stamps, signed a stamp to the seed behind it.
- **The reputation proof:** a score across the person's profiles, from the tree an index, a service
  that scores profiles, publishes, shown on another profile of theirs without saying which.

A profile entry's proofs list takes any circuit name, and a reader skips the ones it does not
know: these two circuits are ours, and anyone can add one.

Anyone can sign a stamp to a person's seed: whoever does is a verifier. The main use is a verifier
that checks one human per seed and signs them one stamp (one is in
[services](https://github.com/foundationforest/services)). A school, a club or a license board could
sign stamps the same way, and a reader decides which verifiers count. The stamp stays private on the
person's device; a verification is what each of their profiles shows: a proof that its seed holds a
stamp from that verifier, without the verifier learning the seed or any profile, and without a
reader learning the stamp. The verifier sees only the person's stamp number, a stable number for
that person at that verifier.

A profile's reviews are its own, and nothing public ties a person's profiles together. The
reputation proof carries a score from their profiles to another profile of their own, such as a new
one, without linking them, and only to a profile of the person's own, so nobody can lend their score
to someone else. It shows one thing: the plain average of the scores of one to eight of the
person's own profiles in an index's tree, naming none of the profiles counted.

The package, `@foundationforest/proofs`:

- `verification/`: the verification's circuit, `verification.circom`, and its setup.
- `reputation/`: the reputation proof's circuit, `reputation.circom`, and its setup.
- `src/`: the one client for both: the stamp a verifier signs, the tree an index builds, the proofs
  a device makes and the check any reader makes of each. It talks to no network.
- `scripts/` compiles each circuit and checks its setup's files; `test/` holds the tests.

## How it works

The device makes a proof from the seed, which goes in as its number
([keys](../keys/README.md#the-seeds-number)), so the seed never leaves the device. Inside both
proofs, the profile's key is worked out from the seed the way `keys/` mixes it, so a proof holds
only for a profile of the seed behind it, and one seed gives one valid key per label: a second key
for the same label has no proof. No chain is touched: a profile shows its proofs in its own profile
entry, and whoever reads them checks them. Both are built with circom 2.2.3, the circuit language;
Groth16, a kind of proof that is small and quick to check, on BN254, the curve the proofs are made
on; and the Poseidon and Merkle pieces Semaphore, a zero-knowledge identity library, uses.

A circuit never changes after its setup. A new version is a new circuit under a new name, with a
setup of its own, and a profile can show a proof of each.

### The stamp and the verification

```
device ── its stamp number for the verifier ──▶ verifier
verifier ── a stamp signed for that stamp number ──▶ device
device ── the verification, for one profile ──▶ the profile's entry, for anyone to check
```

**The stamp.** A verifier decides for itself whom it signs a stamp for, and signs one: *stamp
number, facts, its name*.

- The stamp number is `Poseidon(the seed's number, name hash)`, from the person's seed and the
  verifier's name ([keys](../keys/README.md#the-stamp-number)). The device sends it to the verifier
  once; the verifier never learns the seed or anything mixed from it but the stamp number.
- The facts are one number below the scalar order of BN254: whatever the verifier puts there, made
  as it chooses, such as a hash of what it saw. The proof keeps them private, so a reader learns
  nothing of them.
- The verifier signs `Poseidon(name hash, stamp number, facts)` with its key on Baby Jubjub, the
  curve the proofs' keys are on, a service key ([keys](../keys/README.md#service-keys)), by
  EdDSA-Poseidon over Poseidon (circomlib's), a hash made for proofs.
- The verifier's key is an address, as every key in the standard is: its point packed into 32 bytes,
  in base58. `keys/`'s `pointOf` gives x and y back.
- The person keeps the stamp on their device, as JSON: `{ stampNumber, facts, verifier,
  verifierName, signature: { r8: [x, y], s } }`, big numbers in decimal text, the verifier's key as
  its address (`stampToJson`, `stampFromJson`). Fields the verifier adds beside them pass through
  unchanged, so the person keeps what `facts` was made from. A verifier that keeps what it signed
  can hand a stamp back by its stamp number, so a lost stamp need not mean a new check; whether it
  does is the verifier's.
- **The verifier's key is the verifier's to keep.** Whoever holds it can sign stamps for people who
  do not exist. A verifier never signs a raw number someone hands it: it hashes the stamp itself,
  its name hash first, so nothing it signs for another purpose can pass as a stamp.

**The verification.** The device proves, showing neither the seed nor the stamp: *I know a seed and
a stamp this verifier signed under its name for the stamp number the seed gives at that name; this
profile's key is the one the seed gives for this label.*

- Public: the profile's key; the verifier's key; the label, as its scope; and the verifier's name,
  as its name hash.
- The scope is `keccak256("forest/profile/" ‖ label) >> 8` and the name hash
  `keccak256("forest/verifier/" ‖ name) >> 8` ([keys](../keys/README.md#the-recipe)). A reader
  computes both itself from the label and the name, so a proof counts for one label at one verifier.
- The profile's key is the lowest 250 bits of `Poseidon(the seed's number, scope)`, times Baby
  Jubjub's `Base8` ([keys](../keys/README.md#main-keys)). The stamp number and the profile's key
  come from the same seed, so a stamp counts only for profiles of the seed it was signed for.
- A profile shows the verification in its profile entry
  ([folders](../folders/README.md#proofs)), with the verifier's key and name.

[`verification/verification.circom`](verification/verification.circom):

| | Signals |
|---|---|
| Private | `seed`, the number `keys/`'s `seedNumber` gives; the stamp's `facts`; the verifier's signature, `R8x`, `R8y` and `S` |
| Public, in this order | `profileX`, `profileY`; `verifierX`, `verifierY`; `scope`; `verifierNameHash` |

Inside the proof:

1. The stamp number is `Poseidon(seed, verifierNameHash)`.
2. circomlib's `EdDSAPoseidonVerifier`, unchanged, checks that the verifier's key signed
   `Poseidon(verifierNameHash, stamp number, facts)`.
3. `Poseidon(seed, scope)` is split into its bits by `Num2Bits_strict`, its lowest 250 bits go to
   circomlib's `EscalarMulFix(250, Base8)`, and the point it gives must be `(profileX, profileY)`.
   The strict split matters: a number below the field also has the 254-bit spelling of itself plus
   the field's order, about a third of the time, and plain `Num2Bits` would let a prover pick it and
   get a second key for the label.

### The tree an index publishes

An index reads profiles' entries from hosts and scores profiles as it chooses
([folders](../folders/README.md)); it publishes its scores as a tree. The tree is a standard: any
index may publish one, and a proof names the root it used, the one number the whole tree hashes down
to. The circuit proves a plain average over any tree of `(key, score)` leaves an index signs; a
proof means only what that index says that root holds.

- **A leaf** is `Poseidon(x, y, score)`, circomlib's Poseidon with three inputs:
  - `x`, `y`: the profile's key, the point its address names, the key its entries are signed with
    ([keys](../keys/README.md#main-keys)).
  - `score`: a whole number below 2^32, meaning what the index says. The circuit outputs the plain
    average of the scores counted; any other aggregate is a new circuit.
- **One leaf per key.**
- **The tree** is Semaphore's lean incremental Merkle tree over Poseidon of pairs, with the leaves
  in the index's order: it hashes the leaves in pairs, level by level, up to one number, the root,
  so a short path shows that a leaf is in it. The circuit fixes its depth at 20, so a tree holds at
  most 1,048,576 leaves.
- **The index signs the root with a time,** as an entry is signed: EdDSA-Poseidon on Baby Jubjub
  by the index's key, a service key, over the canonical JSON of `{ "root", "time" }`, the root in
  decimal text and the time in whole milliseconds since 1970 ([keys](../keys/README.md#signatures)).
  Its fields say what it is, so the signature is never an entry's or a message's. The index's key is
  an address, and the signature 64 bytes, R8 packed then S.
- **How it publishes them is its own:** every leaf's key and score, in order, with the root, the
  time and the signature, in whatever format the index chooses.

### The reputation proof

[`reputation/reputation.circom`](reputation/reputation.circom), `Reputation(8, 20)`: eight slots,
each one profile, a leaf and its path to the root. The person fills the ones they want and leaves
the rest blank. Eight slots and a depth of 20 are parameters of this circuit: others are a new
circuit and a new setup.

| | Signals |
|---|---|
| Private | `seed`, the number `keys/`'s `seedNumber` gives; for each slot, `used`, the scope of its label, its score, and its path's length, position and siblings; `profileScope`, the scope of the label of the profile the proof is shown on |
| Public, in this order | `score`, the output, the plain average; `root`; `profileX`, `profileY`, the key of the profile the proof is shown on |

Every key in the proof, each counted profile's and the one it is shown on, is worked out inside it
from the same seed, the way `keys/` mixes a main key and the verification works it out. So the
proof counts only the person's own profiles, and holds only on a profile of theirs: it cannot be
lent to anyone else, nor copied to another profile.

Inside the proof:

1. Each slot's key is the lowest 250 bits of `Poseidon(seed, its scope)`, split into bits by
   `Num2Bits_strict`, times `Base8`.
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

### The setups

A Groth16 proof needs a setup, made once for its circuit: whoever knows all of the setup's secret
randomness could make a false proof, so it is made in public by many people, and one honest one is
enough. Each circuit has its own, in its own `setup/`, since a setup belongs to one circuit.

- **Phase 1** is public: PSE's Perpetual Powers of Tau, `ppot_0080_16.ptau`, pinned by SHA-256, the
  same file for both.
- **Phase 2** is one contribution, made once by the circuit's `setup/setup.sh` (Limits).
- **What is committed,** in each `setup/`: the proving key, the witness generator (the program that
  works out a proof's private numbers), the verification key, and `setup.json`
  ([verification](verification/setup/setup.json), [reputation](reputation/setup/setup.json)), which
  records the toolchain, phase 1, the contribution's hash, and every file's size and SHA-256. `npm
  run fetch` checks the files against their hashes.
- **A circuit does not change after its setup.** circom gives the same bytes every time, and `npm
  run compile` checks each compiled circuit against its `setup.json`. The witness generator carries
  the source's line numbers, so even a line added to a comment fails that check. A change means a
  new setup.

### Use it

The client (`src/`) talks to no network: the caller passes the seed, the stamp, the index's
leaves, root, time and signature, and the setups' files. The scope, the name hash, the stamp number
and the profile's key come from `keys/`, unchanged.

| Function | Gives |
|---|---|
| `signStamp(privateKey, stamp)`, `verifierKeyOf(privateKey)` | For a verifier: the signed stamp, and its key's address |
| `stampNumberOf(seedNumber, name)`, `stampHash(stamp)`, `stampSigned(stamp)` | The stamp number, what a verifier signs, and whether its verifier signed it under its name |
| `stampToJson(stamp)`, `stampFromJson(json)` | The stamp as JSON, as the person's device keeps it, and back; `stampFromJson` refuses the stamp's own fields in any other shape, a verifier key that is not an address or a name that is not text among them, passes the verifier's added fields through unchanged, and leaves the signature to `stampSigned` |
| `proveVerification({ seed, stamp, label, artifacts })` | The verification, on the device, for the profile the seed gives for `label`. Refuses a stamp for another seed or verifier name, or one its verifier did not sign |
| `checkVerification({ proof, verifier, verifierName, label, profile })` | Whether the proof holds for that verifier's key (its address or its point) and name, label, and profile (its address or its key) |
| `buildTree(leaves)` | For an index: the root to sign, from leaves `{ profile, score }`, each profile its key as a point. Refuses an empty tree, more than 2^20 leaves, a field out of range, or two leaves for one key |
| `signedBytes(root, time)` | The bytes an index signs: the canonical JSON of `{ root, time }` |
| `proveReputation({ seed, labels, leaves, profileLabel, artifacts })` | The reputation proof, on the device: one to eight of the person's profiles, by label, each found in the leaves by its key, shown on the profile with `profileLabel` |
| `checkReputation({ proof, root, score, profile, index, time, signature })` | Whether the index (its address or key) signed the root with that time (its 64-byte signature), and the proof holds for that score and `profile`, the address or key of the profile that shows it |
| `proofBytes(proof)`, `proofFromBytes(bytes)` | The proof as the 256 bytes a profile entry carries ([folders](../folders/README.md#proofs)), and back; both checks take either |
| `verificationInput({...})`, `reputationInput({...})` | Each circuit's input, for a caller that drives snarkjs itself |

```ts
import { checkReputation, checkVerification, proveReputation, proveVerification } from '@foundationforest/proofs'

// On the device: a verification for one profile, from a stamp a verifier signed.
const v = await proveVerification({
  seed,                         // the person's 32 bytes, which never leave the device
  stamp,                        // the stamp the verifier signed for this person, naming the verifier
  label: 'tutoring/seller',
  artifacts: { wasm: 'proofs/verification/setup/verification.wasm', zkey: 'proofs/verification/setup/verification.zkey' },
})
// v.address is mainKey(seed, 'tutoring/seller').address; the profile shows v.proof, and the
// verifier's key and name.

// On the device: three profiles' score, shown on a new profile of the same seed.
const r = await proveReputation({
  seed,
  labels: ['tutoring/seller', 'tutoring/buyer', 'cleaning/seller'],
  leaves,                       // the index's published leaves, in its order
  profileLabel: 'tutoring/new', // the profile the proof is shown on
  artifacts: { wasm: 'proofs/reputation/setup/reputation.wasm', zkey: 'proofs/reputation/setup/reputation.zkey' },
})

// Any reader, from what a profile shows, and for a reputation proof the index's key, and the time
// and signature it published with the root:
const one = await checkVerification({ proof, verifier, verifierName, label, profile: address })
const two = await checkReputation({ proof: r.proof, root: r.root, score: r.score, profile: address, index, time, signature })
```

### Run it

The toolchain: Node 22.18 or later; circom 2.2.3, the Linux binary from its GitHub release, whose
SHA-256 each `setup.json` records; and, from the root's `package-lock.json`, snarkjs 0.7.5,
circomlib 2.0.5 and `@zk-kit/binary-merkle-root.circom` 2.0.0.

```
npm ci && npm run build        # at the root: every package; keys/ and proofs/ to dist/
cd proofs
npm run fetch                  # each setup's committed files, hash-checked
npm run compile                # circom 2.2.3 on PATH or in CIRCOM; checks each against its setup.json
npm run check && npm test      # the stamp, the tree, the inputs, and proofs, and every way one must fail
verification/setup/setup.sh    # a new setup for one circuit: new keys, their hashes new
reputation/setup/setup.sh
```

- The stamp's tests check the stamp, what a verifier signs under its name and its JSON against
  `keys/` without proving, and that zk-kit's own check takes its signature.
- The verification's tests make a proof for `keys/`'s test person and check that it is for
  `keys/`'s main key, and that each of these fails: a wrong verifier key or name, a forged
  signature, the verifier's signature changed or without its name hash, facts the verifier did not
  sign, another person's seed, a label for another label, and a proof for another profile's key,
  whether the person's own other profile, someone else's, or a key of the prover's choosing. They
  also check that a stamp zk-kit signs passes circomlib's `EdDSAPoseidonVerifier`, and make and
  check one proof with Node's `Buffer` taken away from the client and keys/, as a browser runs them.
- The reputation proof's tests check the tree, the bytes an index signs, the inputs the client
  refuses, and that the proof names `keys/`'s main key. They build a tree of made-up profiles around
  `keys/`'s test person and someone else, and prove with one profile and with three, shown on
  another profile of the person's own. Another seed, a leaf not in the tree, a blank slot with a
  score, a profile counted twice, someone else's profile in a slot, a main key that is not the
  prover's for its label, a root of 0 and no slot used are refused; a changed output, root or time
  fails its check, and so does a proof shown on someone else's profile or on another of the
  person's own.

### What one proof costs

Measured in Node 22 on a 4-core machine; the reputation proof with 8 slots at depth 20:

| | The verification | The reputation proof |
|---|---|---|
| Constraints | 5,980 | 53,354 |
| Building the tree | none | about 4.1 s for 5,008 leaves, about 0.8 ms a leaf |
| Making the proof | about 0.8 s | about 4.9 s more |
| Checking it | about 25 ms | about 25 ms |
| The proof | about 725 bytes as snarkjs writes it, 256 as a profile carries it | the same |

## Promises

The verification:

- **The key shown signed a stamp for the seed behind this profile.** A proof holds only when the
  verifier with that key signed a stamp, under that name, for the stamp number the same seed gives
  at that name.
- **One seed gives one key per label.** A proof holds only for the key the prover's seed gives for
  the label it shows, though a person with stamps on two seeds has a key for each under one label,
  and a reader that counts both counts that person twice: how many stamps a human gets is each
  verifier's.
- A proof counts for one label at one verifier: a reader derives the scope and the name hash itself.
- Nothing else is in the proof: not the seed, not the stamp, not the person, though it shows which
  verifier signed the stamp, since its key and name hash are public.

The reputation proof:

- A proof counts only profiles whose keys come from the prover's own seed.
- A profile counts at most once in a proof.
- A proof lands only on a profile of the prover's own: its key comes from the same seed as the
  profiles it counts, so a person with two seeds cannot carry one seed's score to the other's, and
  that profile need not hold a stamp of its own: a reader that wants one reads its verifications.
- The score is the plain average of the scores of the profiles counted, rounded down, and nothing
  else.
- Nothing else about those profiles is in the proof: not which leaves, nor how many, though in a
  small tree the exact score can point at one leaf.

## Limits

- **Each circuit's setup, the one-time step its proofs depend on, was made by one party.** Whoever
  ran a circuit's `setup/setup.sh` could make a false proof for that circuit. A public setup
  ceremony is on the list.
- **A name on a profile entry is a claim; the key is the fact.** Anyone can write any verifier's
  name beside a proof; the proof holds for the verifier's key, and a reader trusts keys.
- **`facts` is a number the verifier fills, and nothing in the standard reads it.** The proof
  keeps it private.
- **A leaked verifier key signs for anyone.** Whoever holds it signs stamps for any stamp number,
  and a proof carries no date. An index can note when it first saw each proof, and a reader may
  then stop counting proofs under that key first seen after the leak.
- **In a small tree, the exact score can point at one leaf.** The tree is public: when few leaves
  have that score, the one left names the profile. The app should say so before a proof is shown.
- **Building the tree takes time.** About fifteen minutes for a million leaves at the speed above.
  An app that asks the index for its path instead tells the index which profiles are its.
- **Not audited.**

## Who decides what

- **The standard:** the stamp, the verification, the leaf, the tree, what an index signs, and each
  circuit and its public signals.
- **A verifier:** whom it signs stamps for, how many each gets, what its facts hold, what it adds
  beside them, whether it hands back a stamp it signed, and its name. The name is text the stamp
  number's recipe uses, so a verifier that changes its key keeps its people's stamp numbers.
- **An index:** which profiles its tree holds, each one's score and what it means; which reviews
  count and how much; and when and where it publishes its tree.
- **Each reader (an app, an index or a service):** which verifier keys count, and how much each
  weighs; which indexes it trusts, since a score is only as good as its index; how old a signed root
  may be; and what a score means to it.
- **The person, with their app:** which verifications to show on which profile, made on the
  device; whether to show a reputation proof; and which profiles count, up to eight: a proof says
  "these profiles of mine", never "all of them", so a low-scored one can be left out.

## FAQ

**What if I lose my seed?** Your profiles' keys are gone with it. Whether a verifier signs a stamp
to a new seed is that verifier's choice.

**Can I hold stamps from more than one verifier?** Yes. Each verifier's stamp gives its own
verification for the same profile, and the profile shows them all. Each reader decides which
verifiers it counts and how much each weighs.

**Why at most eight profiles?** Each slot costs about 6,500 constraints, most of them its path's
Poseidon hashes. Eight covers two roles in each of four markets and keeps a proof to a few
seconds. More is a new circuit and a new setup.

**Why a depth of 20?** A million leaves per index tree. A deeper tree is a new circuit and a new
setup.

**Why is the reputation proof checked off chain?** Nothing on chain needs a reputation, and a
program that cannot change could not take a better circuit. Whoever is shown a proof checks it.

**Why are both proofs one package?**
Both are made on the person's device from the seed, and both are checked by anyone. They share
pieces: both take the scope and the profile's key from `keys/`, and the proof's 256-byte form. Each
keeps its own circuit and its own setup, since a setup belongs to one circuit.
