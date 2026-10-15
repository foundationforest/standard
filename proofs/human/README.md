# human

Part of Forest's standard: [the top README](../../README.md). Up: [proofs](../README.md).

On devnet only: the circuit's setup was made by one party; a public setup ceremony comes before
mainnet. Nothing is on mainnet.

## What it is

The human proof, and the client a device uses to make it and anyone uses to check it. A proof says:
*an issuer checked the human behind this profile's seed, in this month; this is their stamp for
this label at this issuer; and this profile's key is the one that seed gives for this label.* A
profile is one of a person's identities, named by its main key; an issuer is anyone who checks
people and signs them a note, its signed word that it checked them; a label is free text saying
what the profile is for. It is a zero-knowledge proof, so it shows this without showing the note,
the seed or who the person is.

The proof derives the profile's key from the seed inside it, so one seed gives one valid profile
key per label: a second key for the same label has no proof. No chain is touched: a profile shows
its proofs in its own records, and whoever reads them checks them.

- `circuit/`: the circuit, its devnet setup and its tests.
- `client/`: the note an issuer signs, the proof and its check. It talks to no network.

## How it works

```
device ── its note number for the issuer ──▶ issuer
issuer ── checks a face once, signs a note ──▶ device
device ── the human proof, for one profile ──▶ the profile's records, for anyone to check
```

### The note and the human proof

**The note.** An issuer is anyone who signs notes for people. One that checks faces checks a
person's face once and signs them one note: *note number, face embedding, model name, month*.

- The note number comes from the person's seed and the issuer's name
  ([keys](../../keys/README.md#the-note-number)). The device sends it to the issuer once; the
  issuer never learns the seed or anything mixed from it but the note number.
- The embedding is the bytes the issuer's model gives for the face, and the model name says which
  model.
- The month is when the issuer checked the person, as the number `YYYYMM`, such as `202610`.
- Text and bytes enter a proof as `keccak256(…) >> 8`: their hash, one byte shorter, so it fits
  the proof's numbers.
- The issuer signs `Poseidon(tag, note number, keccak256(embedding) >> 8, keccak256(model) >> 8,
  month)` with its EdDSA key on Baby Jubjub, over Poseidon (circomlib's). The tag is
  `keccak256("forest/v1/note") >> 8`, always the same, so nothing an issuer signs for another
  purpose can pass as a note. The embedding and the model enter only as their hashes.
- The person keeps the note, in their vault (the folder a new device restores from,
  [records](../../records/README.md#the-vault)), as JSON:
  `{ noteNumber, embedding, model, month, issuer, signature: { r8: [x, y], s } }`, big numbers in
  decimal text, the month a number, the embedding in base64url, the issuer's key as 128 characters
  of lowercase hex, x then y (`noteToJson`, `noteFromJson`).
- **The issuer's key is the issuer's to keep.** Whoever holds it can sign notes for people who do
  not exist. An issuer signs only numbers it computed itself: a number someone hands it to sign
  could be a note.

**The human proof.** The device proves, showing neither the seed nor the note: *I know a seed
scalar and a note this issuer signed for the note number it gives at this issuer's name; my stamp
for this label at this issuer is this one; this profile's key is the one it gives for this label.*

- Public: the stamp; the profile's key; the issuer's key; the label, as its scope; the issuer's
  name, as its name hash; and the month.
- The scope is `keccak256("forest.foundation/label/v1/" ‖ label) >> 8` and the name hash
  `keccak256("forest/v1/issuer/" ‖ name) >> 8` ([keys](../../keys/README.md#the-recipe)). A reader
  computes both itself from the label and the name, so a proof counts for one label at one issuer.
- The stamp is `Poseidon(scope, issuer secret)` ([keys](../../keys/README.md#stamps)). It depends on
  the seed, the issuer's name and the label, not on the note, so a new note, in a new month or
  under a new key, gives the same stamp.
- The profile's key is the lowest 250 bits of `Poseidon(profile tag, seed scalar, scope)`, times
  Baby Jubjub's `Base8` ([keys](../../keys/README.md#main-keys)). The issuer secret behind the note
  and the profile's key come from the same seed scalar, so a note counts only for profiles of the
  seed it was signed for.
- A profile shows the proof in its profile record ([records](../../records/README.md#proofs)), with
  the issuer's key and name, the month and the stamp.

### The circuit and its setup

[`circuit/human.circom`](circuit/human.circom):

| | Signals |
|---|---|
| Private | `seedScalar`, the number `keys/`'s `seedScalar` gives; the note's embedding hash and model hash; the issuer's signature, `R8x`, `R8y` and `S` |
| Public, in this order | `stamp`, the output; `profileX`, `profileY`; `issuerX`, `issuerY`; `scope`; `issuerNameHash`; `month` |

Inside the proof:

1. The issuer secret is `Poseidon(issuer tag, seedScalar, issuerNameHash)`, and the note number
   `Poseidon(issuer secret)`.
2. circomlib's `EdDSAPoseidonVerifier`, unchanged, checks that the issuer's key signed
   `Poseidon(tag, note number, embedding, model, month)`, with the tag fixed in the circuit.
3. The stamp is `Poseidon(scope, issuer secret)`.
4. `Poseidon(profile tag, seedScalar, scope)` is split into its bits by `Num2Bits_strict`, its
   lowest 250 bits go to circomlib's `EscalarMulFix(250, Base8)`, and the point it gives must be
   `(profileX, profileY)`. The strict split matters: a number below the field also has the 254-bit
   spelling of itself plus the field's order, about a third of the time, and plain `Num2Bits`
   would let a prover pick it and get a second key for the label.

A proof of this kind (Groth16) needs a setup, made once for the circuit: whoever knows all of the
setup's secret randomness could forge proofs, so it is made in public by many people, and one
honest one is enough.

- **The setup is single-party.** Phase 1 is public, PSE's Perpetual Powers of Tau
  (`ppot_0080_16.ptau`); phase 2 is one contribution, so whoever ran `circuit/devnet/setup.sh`
  could forge a proof. Devnet only; a public setup ceremony comes before mainnet.
- **Its files are pinned.** All are small, so all are committed in `circuit/devnet/`, with their
  sizes and SHA-256 in [`setup.json`](circuit/devnet/setup.json). `npm run fetch` checks the
  hashes, and `npm run compile` checks the compiled circuit against `setup.json`.
- **It does not change.** `human.circom` is fixed by its setup: circom gives the same bytes every
  time, and the witness generator carries the source's line numbers, so even a line added to a
  comment fails `npm run compile`. A change means a new setup.

### Use it

The client (`client/src/`) talks to no network: the caller passes the seed scalar, the note and
the setup's files. The scope, the name hash, the stamp and the profile's key come from `keys/`,
unchanged.

| Function | Gives |
|---|---|
| `signNote(privateKey, note)`, `issuerKeyOf(privateKey)` | For an issuer: the signed note, and its key |
| `noteNumberOf(seedScalar, issuerName)`, `noteHash(note)`, `noteSigned(note)` | The note number, what an issuer signs, and whether its issuer signed it |
| `noteToJson(note)`, `noteFromJson(json)` | The note as JSON, as a vault keeps it, and back; `noteFromJson` refuses any other shape, and leaves the signature to `noteSigned` |
| `proveHuman({ seedScalar, issuerName, note, label, artifacts })` | The proof, on the device, for the profile the seed gives for `label`. Refuses a note for another seed or issuer name, or one its issuer did not sign |
| `verifyHuman({ proof, issuer, issuerName, label, profile, stamp, month })` | Whether the proof holds for that issuer's key and name, label, profile (its address or its key), stamp and month |
| `proofBytes(proof)`, `proofFromBytes(bytes)` | The proof as the 256 bytes a profile record carries, and back; `verifyHuman` takes either |
| `humanInput({...})` | The circuit's input, for a caller that drives snarkjs itself |
| `isMonth(value)` | Whether a value is a month, `YYYYMM` |

```ts
import { mainKey, seedScalar } from '@forest/keys'
import { proveHuman, verifyHuman } from '@forest/human'

// On the device:
const r = await proveHuman({
  seedScalar: await seedScalar(seed),
  issuerName: 'issuer-a.example',
  note,                         // the note the issuer signed for this person
  label: 'tutoring/seller',
  artifacts: { wasm: 'proofs/human/circuit/devnet/human.wasm', zkey: 'proofs/human/circuit/devnet/human.zkey' },
})
// r.address is mainKey(seed, 'tutoring/seller').address; the profile shows r.proof, r.stamp,
// the issuer's key and name, and the month.

// Any reader, from what the profile shows:
const ok = await verifyHuman({ proof, issuer, issuerName, label, profile: address, stamp, month })
```

### Run it

```
cd keys && npm ci                         # the client and the circuit's tests read keys/

cd proofs/human/client && npm ci
npm run check && npm test                 # the note, the input, the bytes, a proof with no Buffer

cd proofs/human/circuit && npm ci         # after proofs/human/client
npm run fetch                             # the committed setup files, hash-checked
npm run compile                           # circom 2.2.3 on PATH or in CIRCOM; checks setup.json
npm run check && npm test                 # a proof, and every way one must fail
devnet/setup.sh                           # a new setup: new files, every hash new
```

- The circuit's tests make a proof for `keys/`'s test person and check that it is for `keys/`'s main
  key and stamp, and that each of these fails: a wrong issuer key or name, a forged signature, the
  issuer's signature changed or without the tag, a month the issuer did not sign, another person's
  seed, a stamp or label for another label, and a proof for another profile's key, whether the
  person's own other profile, someone else's, or a key of the prover's choosing. They also check
  that a note signed with `keys/`'s `signWithScalar` passes circomlib's verifier.
- The client's tests check the note, its JSON and the circuit's input against `keys/` without
  proving, and make and check one proof with Node's `Buffer` taken away, as a browser runs it.

### What one proof costs

Measured in Node 22 on a 4-core machine:

| | |
|---|---|
| Constraints | 6,526 |
| Making the proof | about 1 s |
| Checking it | about 50 ms |
| The proof | about 725 bytes as snarkjs writes it, 256 as a profile carries it |

## Promises

- A proof holds only for a profile key the prover's seed gives for the label it shows: one seed,
  one profile key per label.
- A proof holds only when the issuer with that key signed, in that month, a note for the note
  number the same seed gives at that issuer's name.
- A proof counts for one label at one issuer: a reader derives the scope and the name hash itself.
- The stamp is the same for every proof of one seed, label and issuer, and says nothing else.
- Nothing else is in the proof: not the seed, not the note, not the person.

## Limits

- **It trusts the circuit's single-party setup.** Whoever ran `circuit/devnet/setup.sh` could
  forge a proof. Devnet only; a public setup ceremony comes before mainnet.
- **It trusts its pieces, used unchanged:** circom 2.2.3, circomlib 2.0.5's Poseidon,
  EdDSA-Poseidon verifier, bits and fixed-base multiplication, `snarkjs` 0.7.5 to make proofs and
  check them, and zk-kit's `@zk-kit/eddsa-poseidon` 1.0.4 to sign notes.
- **A proof is only as good as its issuer.** Anyone can sign notes with a key of their own. An
  issuer that checks faces is trusted to sign one note per real, distinct human; the proof cannot
  tell. A reader that trusts no issuer counts no proof.
- **One profile per seed per label, not per face.** A person who gets notes for two seeds, from two
  issuers, has two profile keys under one label. A reader that trusts both issuers counts both.
- **A leaked issuer key signs any month.** The month is the issuer's word, so a note forged with a
  leaked key can carry an old one. An index records when it first saw each proof, and a reader may
  stop counting proofs under that key first seen after the leak.
- **The proof shows the issuer.** Its key and name hash are public, so a reader learns which
  issuer checked the person.
- **Not audited.**

## Who decides what

- **The standard:** the note, the proof, the circuit and its public signals.
- **An issuer:** chooses whom it signs notes for, how it checks them, and its name.
- **An index or a reader:** chooses which issuers it counts, how much each weighs, and from when,
  by the month and by when it first saw a proof.
- **An app, with the person:** which proofs to show on which profile, made on the device.

## FAQ

**What if I lose my seed?** Your profiles' keys and stamps are gone with it, and an issuer that
checks faces will not sign your face a note for a new seed. The 24 words are the only backup.

**Can I be checked by more than one issuer?** Yes. Each issuer's note gives its own proof for the
same profile, with its own stamp, and the profile shows them all. An index decides which issuers it
counts and how much each weighs. The same issuer never gives a second stamp under one label: a new
note from it gives the same stamp.

**What if someone steals my seed, or I sell it?** Whoever holds the seed acts as every profile and
can make its proofs ([keys](../../keys/README.md#faq)). The note an issuer signed carries numbers
made from the person's face, its embedding, so a service that wants to can ask whoever shows the
note for a live face match against it.
