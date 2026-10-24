# note

Part of Forest's standard: [the top README](../../README.md). Up: [proofs](../README.md).

## What it is

The note proof, and the client a device uses to make it and anyone uses to check it. Anyone can
sign a note to a person's seed: whoever does is an issuer. The main use, and the one we build, is
an issuer that checks one human per seed and signs them one note; a school, a club or a license
board could sign notes the same way, and a reader decides which signers count. Any of the
person's profiles can then prove it holds such a note, without the issuer learning the seed or any
profile, and without a reader learning the note. The issuer sees only the person's note number, a
stable number for that person at that issuer.

A proof says: *the issuer with this key signed a note for the seed behind this profile; this is the
profile's tag for its label at that issuer; and this profile's key is the one that seed gives for
this label.* A profile is one of a person's identities, named by its main key; a label is any text
saying what the profile is for, `<market>/<role>` by the markets' convention. It is a
zero-knowledge proof, so it shows this without showing the note, the seed or who the person is.

The proof derives the profile's key from the seed inside it, so one seed gives one valid key per
label: a second key for the same label has no proof. No chain is touched: a profile shows its
proofs in its own records, and whoever reads them checks them.

- `circuit/`: the circuit, its setup and its tests.
- `client/`: the note an issuer signs, the proof and its check. It talks to no network.

## How it works

```
device ── its note number for the issuer ──▶ issuer
issuer ── a note signed for that note number ──▶ device
device ── the note proof, for one profile ──▶ the profile's records, for anyone to check
```

### The note and the note proof

**The note.** An issuer decides for itself whom it signs a note for, and signs one: *note number,
attributes*.

- The note number comes from the person's seed and the issuer's name
  ([keys](../../keys/README.md#the-note-number)). The device sends it to the issuer once; the
  issuer never learns the seed or anything mixed from it but the note number.
- The attributes are one number below BN254's scalar order: whatever the issuer puts there, made
  as it chooses, such as a hash of what it saw. The proof keeps them private, so a reader learns
  nothing of them.
- The issuer signs `Poseidon(prefix, note number, attributes)` with its EdDSA key on Baby Jubjub,
  over Poseidon (circomlib's). The prefix is `keccak256("forest/v1/note") >> 8`, always the same, so
  nothing an issuer signs for another purpose can pass as a note.
- The issuer's key is an address, as every key in the standard is: its point packed into 32 bytes,
  in base58. `keys/`'s `pointOf` gives x and y back.
- The person keeps the note, in their vault (the folder a new device restores from,
  [records](../../records/README.md#the-vault)), as JSON: `{ noteNumber, attributes, issuer,
  signature: { r8: [x, y], s } }`, big numbers in decimal text, the issuer's key as its address
  (`noteToJson`, `noteFromJson`). Fields the issuer adds beside them pass through unchanged, so the
  person keeps what `attributes` was made from.
- **The issuer's key is the issuer's to keep.** Whoever holds it can sign notes for people who do
  not exist. An issuer never signs a raw number someone hands it: it hashes the note itself, with
  the prefix, so nothing it signs for another purpose can pass as a note.

**The note proof.** The device proves, showing neither the seed nor the note: *I know a seed scalar
and a note this issuer signed for the note number it gives at this issuer's name; my tag for this
label at this issuer is this one; this profile's key is the one it gives for this label.*

- Public: the tag; the profile's key; the issuer's key; the label, as its scope; and the
  issuer's name, as its name hash.
- The scope is `keccak256("forest/v1/label/" ‖ label) >> 8` and the name hash
  `keccak256("forest/v1/issuer/" ‖ name) >> 8` ([keys](../../keys/README.md#the-recipe)). A reader
  computes both itself from the label and the name, so a proof counts for one label at one issuer.
- The tag is `Poseidon(scope, issuer secret)` ([keys](../../keys/README.md#tags)). It depends on
  the seed, the issuer's name and the label, not on the note, so a new note, with other attributes
  or under a new key, gives the same tag.
- The profile's key is the lowest 250 bits of `Poseidon(profile prefix, seed scalar, scope)`, times
  Baby Jubjub's `Base8` ([keys](../../keys/README.md#main-keys)). The issuer secret behind the note
  and the profile's key come from the same seed scalar, so a note counts only for profiles of the
  seed it was signed for.
- A profile shows the proof in its profile record ([records](../../records/README.md#proofs)), with
  the issuer's key and name and the tag.

### The circuit and its setup

[`circuit/note.circom`](circuit/note.circom):

| | Signals |
|---|---|
| Private | `seedScalar`, the number `keys/`'s `seedScalar` gives; the note's `attributes`; the issuer's signature, `R8x`, `R8y` and `S` |
| Public, in this order | `stamp`, the output, the tag, first, as snarkjs lists it; then `profileX`, `profileY`; `issuerX`, `issuerY`; `scope`; `issuerNameHash` |

The signals keep the names the circuit was set up with, since it keeps its bytes: `stamp` is the
tag.

Inside the proof:

1. The issuer secret is `Poseidon(issuer prefix, seedScalar, issuerNameHash)`, and the note number
   `Poseidon(issuer secret)`.
2. circomlib's `EdDSAPoseidonVerifier`, unchanged, checks that the issuer's key signed
   `Poseidon(prefix, note number, attributes)`, with the prefix fixed in the circuit. The circuit
   names its prefixes `NOTE_TAG`, `ISSUER_TAG` and `PROFILE_TAG`: it keeps its bytes, and its names
   with them.
3. The tag is `Poseidon(scope, issuer secret)`.
4. `Poseidon(profile prefix, seedScalar, scope)` is split into its bits by `Num2Bits_strict`, its
   lowest 250 bits go to circomlib's `EscalarMulFix(250, Base8)`, and the point it gives must be
   `(profileX, profileY)`. The strict split matters: a number below the field also has the 254-bit
   spelling of itself plus the field's order, about a third of the time, and plain `Num2Bits`
   would let a prover pick it and get a second key for the label.

A proof of this kind (Groth16) needs a setup, made once for the circuit: whoever knows all of the
setup's secret randomness could make a false proof, so it is made in public by many people, and one
honest one is enough.

- **Phase 1** is public, PSE's Perpetual Powers of Tau (`ppot_0080_16.ptau`); phase 2 is one
  contribution, made by `circuit/setup/setup.sh` ([proofs](../README.md#limits)).
- **Its files are pinned.** All are small, so all are committed in `circuit/setup/`, with their
  sizes and SHA-256 in [`setup.json`](circuit/setup/setup.json). `npm run fetch` checks the
  hashes, and `npm run compile` checks the compiled circuit against `setup.json`.
- **It does not change.** `note.circom` is fixed by its setup: circom gives the same bytes every
  time, and the witness generator carries the source's line numbers, so even a line added to a
  comment fails `npm run compile`. A change means a new setup.

### Use it

The client (`client/src/`) talks to no network: the caller passes the seed scalar, the note and
the setup's files. The scope, the name hash, the tag and the profile's key come from `keys/`,
unchanged.

| Function | Gives |
|---|---|
| `signNote(privateKey, note)`, `issuerKeyOf(privateKey)` | For an issuer: the signed note, and its key's address |
| `noteNumberOf(seedScalar, issuerName)`, `noteHash(note)`, `noteSigned(note)` | The note number, what an issuer signs, and whether its issuer signed it |
| `noteToJson(note)`, `noteFromJson(json)` | The note as JSON, as a vault keeps it, and back; `noteFromJson` refuses the note's own fields in any other shape, an issuer key that is not an address among them, passes the issuer's added fields through unchanged, and leaves the signature to `noteSigned` |
| `proveNote({ seedScalar, issuerName, note, label, artifacts })` | The proof, on the device, for the profile the seed gives for `label`. Refuses a note for another seed or issuer name, or one its issuer did not sign |
| `verifyNote({ proof, issuer, issuerName, label, profile, tag })` | Whether the proof holds for that issuer's key (its address or its point) and name, label, profile (its address or its key) and tag |
| `proofBytes(proof)`, `proofFromBytes(bytes)` | The proof as the 256 bytes a profile record carries, and back; `verifyNote` takes either |
| `noteInput({...})` | The circuit's input, for a caller that drives snarkjs itself |

```ts
import { mainKey, seedScalar } from '@foundationforest/keys'
import { proveNote, verifyNote } from '@foundationforest/note'

// On the device:
const r = await proveNote({
  seedScalar: await seedScalar(seed),
  issuerName: 'issuer-a.example',
  note,                         // the note the issuer signed for this person
  label: 'tutoring/seller',
  artifacts: {
    wasm: 'proofs/note/circuit/setup/note.wasm',
    zkey: 'proofs/note/circuit/setup/note.zkey',
  },
})
// r.address is mainKey(seed, 'tutoring/seller').address; the profile shows r.proof, r.tag,
// and the issuer's key and name.

// Any reader, from what the profile shows:
const ok = await verifyNote({ proof, issuer, issuerName, label, profile: address, tag })
```

### Run it

```
npm ci && npm run build                   # at the root: every package; keys/ and the client to dist/

cd proofs/note/client
npm run check && npm test                 # the note, the input, the bytes, a proof with no Buffer

cd proofs/note/circuit
npm run fetch                             # the committed setup files, hash-checked
npm run compile                           # circom 2.2.3 on PATH or in CIRCOM; checks setup.json
npm run check && npm test                 # a proof, and every way one must fail
setup/setup.sh                            # a new setup: new files, every hash new
```

- The circuit's tests make a proof for `keys/`'s test person and check that it is for `keys/`'s main
  key and tag, and that each of these fails: a wrong issuer key or name, a forged signature, the
  issuer's signature changed or without the prefix, attributes the issuer did not sign, another
  person's seed, a tag or label for another label, and a proof for another profile's key, whether
  the person's own other profile, someone else's, or a key of the prover's choosing. They also check
  that a note signed with `keys/`'s `signWithScalar` passes circomlib's verifier.
- The client's tests check the note, its JSON and the circuit's input against `keys/` without
  proving, and make and check one proof with Node's `Buffer` taken away, as a browser runs it.

### What one proof costs

Measured in Node 22 on a 4-core machine:

| | |
|---|---|
| Constraints | 6,466 |
| Making the proof | about 1 s |
| Checking it | about 50 ms |
| The proof | about 725 bytes as snarkjs writes it, 256 as a profile carries it |

## Promises

- **The key shown signed a note for the seed behind this profile.** A proof holds only when the
  issuer with that key signed a note for the note number the same seed gives at that issuer's name.
- **One seed gives one key per label.** A proof holds only for the key the prover's seed gives for
  the label it shows.
- A proof counts for one label at one issuer: a reader derives the scope and the name hash itself.
- The tag is the same for every proof of one seed, label and issuer, and says nothing else.
- Nothing else is in the proof: not the seed, not the note, not the person.

## Limits

- **A name on a profile record is a claim; the key is the fact.** Anyone can write any issuer's
  name beside a proof; the proof holds for the issuer's key, and a reader trusts keys.
- **`attributes` is a number the issuer fills, and nothing in the standard reads it.** The proof
  keeps it private.
- **One seed per label, and an issuer decides how many notes a human gets.** A person with notes
  for two seeds has two keys under one label, and a reader that counts both issuers counts both.
- **A leaked issuer key signs for anyone.** Whoever holds it signs notes for any note number, and a
  proof carries no date. An index records when it first saw each proof, and a reader may stop
  counting proofs under that key first seen after the leak.
- **The proof shows the issuer.** Its key and name hash are public, so a reader learns which
  issuer signed the person a note.
- **Not audited.**

## Who decides what

- **The standard:** the note, the proof, the circuit and its public signals.
- **An issuer:** whom it signs notes for, how many each gets, what its attributes hold, what it adds
  beside them, and its name. The name is text the tag recipe uses, so an issuer that changes its
  key keeps its people's tags.
- **Each reader:** which issuer keys count is its own list, and how much each weighs.
- **An app, with the person:** which proofs to show on which profile, made on the device.

## FAQ

**What if I lose my seed?** Your profiles' keys and tags are gone with it. Whether an issuer signs
a note to a new seed is that issuer's choice.

**Can I hold notes from more than one issuer?** Yes. Each issuer's note gives its own proof for the
same profile, with its own tag, and the profile shows them all. Each reader decides which issuers
it counts and how much each weighs. The same issuer never gives a second tag under one label: a
new note from it gives the same tag.
