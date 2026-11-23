# proofs

Part of [Forest's standard](../README.md).

## What it is

Three zero-knowledge proofs a person's device makes from the seed and anyone checks. A
zero-knowledge proof shows that something is true of a secret without showing the secret. **The
verification** shows that a verifier signed a stamp to the seed behind a profile; **the reputation
proof** shows, on one of the person's profiles, the plain average of the scores of one to eight of
their profiles in an index's tree, naming none; **the facts proof** shows facts the person chooses
from a stamp, to one reader, from one of their profiles. Each is one statement with its own circuit
and its own setup, in `verification/`, `reputation/` and `facts/`. All three are one package,
`@foundationforest/proofs`, since they share their pieces: `src/` is the one client, which talks to
no network.

## How it works

- The device makes a proof from the seed's number ([keys](../keys/README.md#the-recipe)), so the
  seed never leaves it. Inside every proof, the profile's key is worked out from the seed as keys/
  derives it, so a proof holds only for a profile of the seed behind it, and a second key for the
  same label has no proof.
- No chain is touched: a profile shows its verifications and reputation proofs in its profile entry
  ([folders](../folders/README.md#proofs)), and whoever reads them checks them. The entry takes any
  circuit's proofs, and a reader skips one it does not know: these two are ours, and anyone can add
  one. A facts proof goes to the one reader it is made for; the main way is in a message
  ([folders](../folders/README.md#the-inbox)).
- All three are built with circom 2.2.3, the circuit language; Groth16, a kind of proof that is
  small and quick to check, on BN254; and the Poseidon and Merkle pieces of Semaphore, a
  zero-knowledge identity library.
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
[services](https://github.com/foundationforest/services)). Others could too: a university could
stamp its graduates, a medical board its doctors, an event its ticket holders. A verifier decides
whom it signs for and how many stamps each gets; a reader decides which verifiers count.

**The stamp** is *stamp number, facts, the verifier's name*, signed by the verifier:

- The stamp number is `Poseidon(the seed's number, name hash)`
  ([keys](../keys/README.md#the-recipe)). The device sends it once: the verifier learns nothing
  else derived from the seed, and sees the same number each time for that person.
- The facts are one number below BN254's scalar order, whatever the verifier puts there. One that
  wants its people to show facts makes it from a list (Facts as a list, below); from any other
  number, no fact can be shown. Every proof keeps the number private.
- The verifier signs `Poseidon(name hash, stamp number, facts)` by EdDSA-Poseidon, with its service
  key on Baby Jubjub ([keys](../keys/README.md#service-keys)) (`signStamp`). It hashes the stamp
  itself, its name hash first, and never signs a raw number someone hands it, so nothing it signs
  for another purpose can pass as a stamp. Whoever holds its key can sign stamps for people who do
  not exist.
- The person keeps the stamp on their device as JSON, `{ stampNumber, facts, verifier,
  verifierName, signature: { r8: [x, y], s } }`, big numbers in decimal text and the verifier's key
  as its address (`stampToJson`, `stampFromJson`, which refuses these fields in any other shape).
  Fields the verifier adds beside them pass through unchanged, so the person keeps what `facts` was
  made from, a list of facts under `factList`. A verifier that keeps what it signed may hand a stamp
  back by its stamp number.

**Facts as a list.** A verifier that wants its people to show facts makes `facts` from a list
(`factsNumber`):

- **A fact** is a name, a value and a salt. The name and the value are text, and each enters as its
  number, as keys/ makes a text's number ([keys](../keys/README.md#the-recipe)), with nothing
  joined. The salt is a random number below BN254's scalar order, which the verifier draws for each
  fact (`newFact`), so the facts number says nothing to someone who can guess the rest of the list.
- **A leaf** is `Poseidon(name's number, value's number, salt)`. The list's leaves, in order, then
  0s, fill the 256 leaves of a tree of depth 8, each node `Poseidon(left, right)`; its root is the
  facts number. A list holds up to 256 facts.
- **The list sits beside the stamp** in its JSON, as `factList: [{ name, value, salt }]`, the salt
  in decimal text. The list is not signed; its root is. `factListOf` reads it, and refuses a list
  that does not make the stamp's facts.
- **Each verifier names its own facts** and publishes the names. The standard holds no shared list
  of names.

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

### The facts proof

[`facts/facts.circom`](facts/facts.circom), `Facts(8, 8)`: eight slots, each a fact the person
chooses to show from a stamp whose facts are a list (Facts as a list). It proves, showing neither
the seed, the stamp nor any fact it does not show: *a verifier signed a stamp for my seed; these
facts are in that stamp; this profile's key is the one my seed gives for this label; and I made
this for this reader at this time.* Eight slots show a document's usual facts in one proof, and
depth 8 holds every field our verifier reads off a document today, about 160 at most; others are a
new circuit and a new setup.

| | Signals |
|---|---|
| Private | `seed`; the stamp's `facts`; the verifier's signature, `R8x`, `R8y`, `S`; for each slot, its fact's salt and its path's position and siblings |
| Public, in this order | the verification's six; `madeFor`; `shown`, each slot's name's number and value's number, 0 and 0 when blank; `match` |

1. The verification's three steps, unchanged.
2. A slot whose name is 0 is blank, and its value is 0 too: no text's number is 0.
3. Every other slot's leaf, `Poseidon(name, value, salt)`, is in the tree whose root is `facts`, by
   a path of exactly 8 steps (zk-kit's `binary-merkle-root` 2.0.0, its length fixed at 8), so the
   facts in one proof come from one stamp.
4. `match` is `Poseidon(seed, scope, facts, madeFor)`.

- **Made for** is one number (`madeForOf`): the canonical JSON of `{ "time", "to" }`, made a
  number the way keys/ makes a text's number. The time is in whole milliseconds since 1970, as the
  index's signed root has it; `to` is any text the reader knows as itself, the main way its profile
  address. A proof checked for another reader or another time fails.
- **The match number** is the same for every proof made from one stamp, on one profile, for one
  made for, and different for any other. A proof shows up to eight facts; more go in several
  proofs made for one reader at one time, whose match numbers show they come from one stamp. The
  seed is in it so that only the person can work it out: the verifier knows every facts number it
  signed, and could otherwise match any proof to its stamp. The scope is in it so that two profiles
  never share one.
- **The JSON** a proof travels in, with the facts it shows (`factsProofToJson`,
  `factsProofFromJson`): `{ verifier, verifierName, label, profile, time, to, shown: [{ name,
  value }], match, proof }`, the match number in decimal text and the proof's 256 bytes in
  base64url without padding. Any other field is skipped.
- `proveFacts` refuses a stamp for another seed or verifier name, one its verifier did not sign,
  one whose list does not make its facts, and a fact the list does not hold, before proving
  anything. `checkFacts` takes what the reader expects: the verifier's key and name, the profile
  and its label, whom it knows itself as, and the oldest time it accepts. From the proof it takes
  only the facts it shows, its time and its match number.
- The standard reads no fact's meaning: comparing a face with a photo, or reading a date as an age,
  is an app's.

### The setups

A Groth16 proof needs a setup, made once for its circuit: whoever knows all of its secret randomness
could make a false proof, so a setup is best made in public by many people, where one honest one is
enough.
Each circuit has its own, in its `setup/`.

- **Phase 1** is public: PSE's Perpetual Powers of Tau, `ppot_0080_16.ptau`, pinned by SHA-256, the
  same file for all three.
- **Phase 2** is one contribution, made once by the circuit's `setup/setup.sh` (Limits).
- **Committed:** the proving key, the witness generator (the program that works out a proof's
  private numbers), the verification key, and `setup.json`
  ([verification](verification/setup/setup.json), [reputation](reputation/setup/setup.json),
  [facts](facts/setup/setup.json)), which records the toolchain, phase 1, the contribution's hash,
  and every file's size and SHA-256.
- circom gives the same bytes every time, so `npm run compile` checks each compiled circuit against
  its `setup.json`. The witness generator carries the source's line numbers, so even a line added
  to a comment fails: a change means a new setup.

### What one proof costs

Measured in Node 22.23 on a 4-core Intel Xeon at 2.30 GHz, each the median of five after the first
in a process, which takes about 0.2 to 0.3 s more:

| | The verification | The reputation proof, 8 slots at depth 20 | The facts proof, 8 slots at depth 8 |
|---|---|---|---|
| Constraints | 5,980 | 53,354 | 23,949 |
| Building the tree | none | about 1.2 s for 5,008 leaves, about 0.24 ms a leaf | about 70 ms for 256 facts |
| Making the proof | about 0.4 s | about 2.6 s more | about 1.3 s, the tree included |
| Checking it | about 12 ms | about 13 ms | about 9 ms |
| The proof | about 725 bytes as snarkjs writes it, 256 as a profile carries it (`proofBytes`) | the same | the same |

## Use it

```ts
import { checkFacts, checkReputation, checkVerification, factsProofFromJson, factsProofToJson, proveFacts, proveReputation, proveVerification } from '@foundationforest/proofs'

const setup = (c: string) => ({ wasm: `proofs/${c}/setup/${c}.wasm`, zkey: `proofs/${c}/setup/${c}.zkey` })

// On the device: a verification for one profile, from the stamp a verifier signed for this seed.
const v = await proveVerification({ seed, stamp, label: 'tutoring/tutor', artifacts: setup('verification') })
// Any reader, from what the profile shows:
await checkVerification({ proof: v.proof, verifier: v.verifier, verifierName: v.verifierName, label: 'tutoring/tutor', profile: v.address }) // true

// Two profiles' score, from the leaves an index published, shown on a third profile of the same seed:
const r = await proveReputation({ seed, labels: ['tutoring/tutor', 'cleaning/cleaner'], leaves, profileLabel: 'tutoring/new', artifacts: setup('reputation') })
await checkReputation({ proof: r.proof, root: r.root, score: r.score, profile: r.address, index, time, signature }) // true

// Two facts from the stamp, from one profile, made for one reader, sent as JSON:
const f = await proveFacts({ seed, stamp, label: 'tutoring/tutor', show: [{ name: 'given name', value: 'Ana' }, { name: 'nationality', value: 'ES' }], time: Date.now(), to: reader, artifacts: setup('facts') })
const json = factsProofToJson(f)
// The reader, which knows itself as `reader`, and accepts a proof up to ten minutes old:
await checkFacts({ proof: factsProofFromJson(json), verifier: f.verifier, verifierName: f.verifierName, label: 'tutoring/tutor', profile: f.profile, to: reader, oldest: Date.now() - 600_000 }) // true
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
```

A setup is made only for a new version, under a new name. Each script writes its setup in place,
with new keys and hashes, so run on these circuits it would stop every proof made so far from
checking:

```
verification/setup/setup.sh
reputation/setup/setup.sh
facts/setup/setup.sh
```

`test/` makes and checks real proofs for keys/'s test person, checks that every way a proof must
fail does (another seed, verifier, name, label or profile; a forged or changed signature; a leaf
not in the tree; a profile counted twice; a changed output, root or time; a fact the stamp does
not hold, a changed fact, another reader or time, a changed match number), and proves once with
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
  stamp of its own: a reader that wants one reads its verifications. **The score is the plain
  average** of the scores of the profiles counted, rounded down, and nothing else.
- **Nothing else is in a verification or a reputation proof:** not the seed, the stamp or the
  person, nor which profiles were counted or how many, though a verification shows which verifier
  signed, since its key and name hash are public, and in a small tree the exact score can point at
  one leaf.
- **A facts proof shows only what its verifier signed.** It holds only when the verifier with that
  key signed those facts, under that name, in a stamp for the seed behind that profile, and only for
  the reader and the time it was made for. It shows nothing of the stamp's other facts, the stamp,
  the seed or the person's other profiles, though it shows which verifier signed, and two of a
  person's profiles are linked by nothing in it but the facts they chose to show.

## Limits

- Each circuit's setup was made by one party, the Forest Foundation, which ran its
  `setup/setup.sh` and so could make a false proof for that circuit. A public setup ceremony is
  planned.
- A verifier's name beside a proof is a claim; the key is the fact. Anyone can write any name, and
  a reader trusts keys.
- A shown fact stays shown: the reader can keep it and pass the proof on, and the proof still names
  the reader it was made for.
- The time in made for is the maker's own word.
- The verifier knows every fact it signed.
- A person who loses the list beside a stamp can no longer show its facts, though its verification
  still holds.
- A leaked verifier key signs for anyone, and a proof carries no date but its maker's word. An
  index can note when it first saw each proof, so a reader may stop counting proofs under that key
  first seen after the leak.
- In a small tree, the exact score can point at one leaf; the app should say so before a proof is
  shown.
- Building the tree takes about four minutes for a million leaves; an app that asks the index for
  its path instead tells the index which profiles are its.
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

**Can I show I'm over 18 without showing my birth date?**
Not with the facts proof: it shows each fact whole. A proof about a fact without showing it would
be a circuit of its own.

**Why is the reputation proof checked off chain?**
Nothing on chain needs a reputation, and a program that cannot change could not take a better
circuit. Whoever is shown a proof checks it.

**What happens to today's proofs after the public setup ceremony?**
They keep checking as they do. The ceremony's setups come with new circuits under new names,
beside the old ones; apps make new proofs with them, and each index, when it chooses, stops
counting the old.
