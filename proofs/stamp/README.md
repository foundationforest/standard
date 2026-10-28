# stamp

Part of Forest's standard: [the top README](../../README.md). Up: [proofs](../README.md).

## What it is

The stamp proof, and the client a device uses to make it and anyone uses to check it. Anyone can
sign a stamp to a person's seed: whoever does is a verifier. The main use is a verifier that checks
one human per seed and signs them one stamp (one is in
[services](https://github.com/foundationforest/services)). A school, a club or a license board could
sign stamps the same way, and a reader decides which verifiers count. Any of the person's profiles
can then prove it holds such a stamp, without the verifier learning the seed or any profile, and
without a reader learning the stamp. The verifier sees only the person's stamp number, a stable
number for that person at that verifier.

A proof says: *the verifier with this key signed a stamp for the seed behind this profile; this is
the profile's tag for its label at that verifier; and this profile's key is the one that seed gives
for this label.* A profile is one of a person's identities, named by its main key; a label is any
text saying what the profile is for, `<market>/<role>` by the markets' convention; and a tag is the
number the profile is known by, at that verifier, in the score trees indexes publish. It is a
zero-knowledge proof, so it shows this without showing the stamp, the seed or who the person is.

The proof derives the profile's key from the seed inside it, so one seed gives one valid key per
label: a second key for the same label has no proof. No chain is touched: a profile shows its
proofs in its own records, and whoever reads them checks them.

- `circuit/`: the circuit, its setup and its tests.
- `client/`: the stamp a verifier signs, the proof and its check. It talks to no network.

## How it works

```
device ── its stamp number for the verifier ──▶ verifier
verifier ── a stamp signed for that stamp number ──▶ device
device ── the stamp proof, for one profile ──▶ the profile's records, for anyone to check
```

### The stamp and the stamp proof

**The stamp.** A verifier decides for itself whom it signs a stamp for, and signs one: *stamp
number, facts*.

- The stamp number comes from the person's seed and the verifier's name
  ([keys](../../keys/README.md#the-stamp-number)). The device sends it to the verifier once; the
  verifier never learns the seed or anything mixed from it but the stamp number.
- The facts are one number below the scalar order of BN254, the curve the proofs are made on:
  whatever the verifier puts there, made as it chooses, such as a hash of what it saw. The proof
  keeps them private, so a reader learns nothing of them.
- The verifier signs `Poseidon(prefix, stamp number, facts)` with its EdDSA key on Baby Jubjub, the
  curve the proofs' keys are on, over Poseidon (circomlib's), a hash made for proofs. The prefix is
  `keccak256("forest/v1/note") >> 8`, always the same.
- The verifier's key is an address, as every key in the standard is: its point packed into 32 bytes,
  in base58. `keys/`'s `pointOf` gives x and y back.
- The person keeps the stamp on their device, as JSON: `{ stampNumber, facts, verifier, signature:
  { r8: [x, y], s } }`, big numbers in decimal text, the verifier's key as its address
  (`stampToJson`, `stampFromJson`). Fields the verifier adds beside them pass through unchanged, so
  the person keeps what `facts` was made from. A verifier that keeps what it signed can hand a stamp
  back by its stamp number, so a lost stamp need not mean a new check; whether it does is the
  verifier's.
- **The verifier's key is the verifier's to keep.** Whoever holds it can sign stamps for people who
  do not exist. A verifier never signs a raw number someone hands it: it hashes the stamp itself,
  with the prefix, so nothing it signs for another purpose can pass as a stamp.

**The stamp proof.** The device proves, showing neither the seed nor the stamp: *I know a seed
scalar and a stamp this verifier signed for the stamp number it gives at this verifier's name; my
tag for this label at this verifier is this one; this profile's key is the one it gives for this
label.*

- Public: the tag; the profile's key; the verifier's key; the label, as its scope; and the
  verifier's name, as its name hash.
- The scope is `keccak256("forest/v1/label/" ‖ label) >> 8` and the name hash
  `keccak256("forest/v1/issuer/" ‖ name) >> 8` ([keys](../../keys/README.md#the-recipe)). A reader
  computes both itself from the label and the name, so a proof counts for one label at one verifier.
- The tag is `Poseidon(scope, verifier secret)` ([keys](../../keys/README.md#tags)). It depends on
  the seed, the verifier's name and the label, not on the stamp, so a new stamp, with other facts
  or under a new key, gives the same tag.
- The profile's key is the lowest 250 bits of `Poseidon(profile prefix, seed scalar, scope)`, times
  Baby Jubjub's `Base8` ([keys](../../keys/README.md#main-keys)). The verifier secret behind the
  stamp and the profile's key come from the same seed scalar, so a stamp counts only for profiles of
  the seed it was signed for.
- A profile shows the proof in its profile record ([records](../../records/README.md#proofs)), with
  the verifier's key and name and the tag.

### The circuit and its setup

[`circuit/note.circom`](circuit/note.circom):

| | Signals |
|---|---|
| Private | `seedScalar`, the number `keys/`'s `seedScalar` gives; the stamp's facts, `attributes`; the verifier's signature, `R8x`, `R8y` and `S` |
| Public, in this order | `stamp`, the output, the tag, first, as snarkjs lists it; then `profileX`, `profileY`; `issuerX`, `issuerY`; `scope`; `issuerNameHash` |

The signals keep the names the circuit was set up with, since it keeps its bytes: `stamp` is the
tag, `attributes` the stamp's facts, and `issuerX`, `issuerY` and `issuerNameHash` the verifier's
key and name hash.

Inside the proof:

1. The verifier secret is `Poseidon(verifier prefix, seedScalar, issuerNameHash)`, and the stamp
   number `Poseidon(verifier secret)`.
2. circomlib's `EdDSAPoseidonVerifier`, unchanged, checks that the verifier's key signed
   `Poseidon(prefix, stamp number, facts)`, with the prefix fixed in the circuit. The circuit
   names its prefixes `NOTE_TAG`, `ISSUER_TAG` and `PROFILE_TAG`: it keeps its bytes, and its names
   with them.
3. The tag is `Poseidon(scope, verifier secret)`.
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
- **Its files are pinned.** The proving key, the witness generator (the program that works out a
  proof's private numbers) and the verification key are small enough to commit, in `circuit/setup/`;
  [`setup.json`](circuit/setup/setup.json) holds their sizes and SHA-256, and the compiled
  circuit's. `npm run fetch` checks the hashes, and `npm run compile` checks the compiled circuit
  against `setup.json`.
- **It does not change.** `note.circom` is fixed by its setup: circom gives the same bytes every
  time, and the witness generator carries the source's line numbers, so even a line added to a
  comment fails `npm run compile`. A change means a new setup.

### Use it

The client (`client/src/`) talks to no network: the caller passes the seed scalar, the stamp and
the setup's files. The scope, the name hash, the tag and the profile's key come from `keys/`,
unchanged.

| Function | Gives |
|---|---|
| `signStamp(privateKey, stamp)`, `verifierKeyOf(privateKey)` | For a verifier: the signed stamp, and its key's address |
| `stampNumberOf(seedScalar, verifierName)`, `stampHash(stamp)`, `stampSigned(stamp)` | The stamp number, what a verifier signs, and whether its verifier signed it |
| `stampToJson(stamp)`, `stampFromJson(json)` | The stamp as JSON, as the person's device keeps it, and back; `stampFromJson` refuses the stamp's own fields in any other shape, a verifier key that is not an address among them, passes the verifier's added fields through unchanged, and leaves the signature to `stampSigned` |
| `proveStamp({ seedScalar, verifierName, stamp, label, artifacts })` | The proof, on the device, for the profile the seed gives for `label`. Refuses a stamp for another seed or verifier name, or one its verifier did not sign |
| `checkStamp({ proof, verifier, verifierName, label, profile, tag })` | Whether the proof holds for that verifier's key (its address or its point) and name, label, profile (its address or its key) and tag |
| `proofBytes(proof)`, `proofFromBytes(bytes)` | The proof as the 256 bytes a profile record carries, and back; `checkStamp` takes either |
| `stampInput({...})` | The circuit's input, for a caller that drives snarkjs itself |

```ts
import { mainKey, seedScalar } from '@foundationforest/keys'
import { checkStamp, proveStamp } from '@foundationforest/stamp'

// On the device:
const r = await proveStamp({
  seedScalar: await seedScalar(seed),
  verifierName: 'issuer-a.example',
  stamp,                        // the stamp the verifier signed for this person
  label: 'tutoring/seller',
  artifacts: {
    wasm: 'proofs/stamp/circuit/setup/note.wasm',
    zkey: 'proofs/stamp/circuit/setup/note.zkey',
  },
})
// r.address is mainKey(seed, 'tutoring/seller').address; the profile shows r.proof, r.tag,
// and the verifier's key and name.

// Any reader, from what the profile shows:
const ok = await checkStamp({ proof, verifier, verifierName, label, profile: address, tag })
```

### Run it

```
npm ci && npm run build                   # at the root: every package; keys/ and the client to dist/

cd proofs/stamp/client
npm run check && npm test                 # the stamp, the input, the bytes, a proof with no Buffer

cd proofs/stamp/circuit
npm run fetch                             # the committed setup files, hash-checked
npm run compile                           # circom 2.2.3 on PATH or in CIRCOM; checks setup.json
npm run check && npm test                 # a proof, and every way one must fail
setup/setup.sh                            # a new setup: new keys, their hashes new
```

- The circuit's tests make a proof for `keys/`'s test person and check that it is for `keys/`'s main
  key and tag, and that each of these fails: a wrong verifier key or name, a forged signature, the
  verifier's signature changed or without the prefix, facts the verifier did not sign, another
  person's seed, a tag or label for another label, and a proof for another profile's key, whether
  the person's own other profile, someone else's, or a key of the prover's choosing. They also check
  that a stamp signed with `keys/`'s `signWithScalar` passes circomlib's `EdDSAPoseidonVerifier`.
- The client's tests check the stamp, its JSON and the circuit's input against `keys/` without
  proving, and make and check one proof with Node's `Buffer` taken away from the client and keys/,
  as a browser runs them.

### What one proof costs

Measured in Node 22 on a 4-core machine:

| | |
|---|---|
| Constraints | 6,466 |
| Making the proof | about 1 s |
| Checking it | about 50 ms |
| The proof | about 725 bytes as snarkjs writes it, 256 as a profile carries it |

## Promises

- **The key shown signed a stamp for the seed behind this profile.** A proof holds only when the
  verifier with that key signed a stamp for the stamp number the same seed gives at that verifier's
  name.
- **One seed gives one key per label.** A proof holds only for the key the prover's seed gives for
  the label it shows, though a person with stamps on two seeds has a key for each under one label,
  and a reader that counts both counts that person twice: how many stamps a human gets is each
  verifier's.
- A proof counts for one label at one verifier: a reader derives the scope and the name hash itself.
- The tag is the same for every proof of one seed, label and verifier, and says nothing else.
- Nothing else is in the proof: not the seed, not the stamp, not the person, though it shows which
  verifier signed the stamp, since its key and name hash are public.

## Limits

- **A name on a profile record is a claim; the key is the fact.** Anyone can write any verifier's
  name beside a proof; the proof holds for the verifier's key, and a reader trusts keys.
- **`facts` is a number the verifier fills, and nothing in the standard reads it.** The proof
  keeps it private.
- **A leaked verifier key signs for anyone.** Whoever holds it signs stamps for any stamp number,
  and a proof carries no date. An index can record when it first saw each proof, and a reader may
  then stop counting proofs under that key first seen after the leak.
- **Not audited.**

## Who decides what

- **The standard:** the stamp, the proof, the circuit and its public signals.
- **A verifier:** whom it signs stamps for, how many each gets, what its facts hold, what it adds
  beside them, whether it hands back a stamp it signed, and its name. The name is text the tag
  recipe uses, so a verifier that changes its key keeps its people's tags.
- **Each reader:** which verifier keys count is its own list, and how much each weighs.
- **An app, with the person:** which proofs to show on which profile, made on the device.

## FAQ

**What if I lose my seed?** Your profiles' keys and tags are gone with it. Whether a verifier signs
a stamp to a new seed is that verifier's choice.

**Can I hold stamps from more than one verifier?** Yes. Each verifier's stamp gives its own proof
for the same profile, with its own tag, and the profile shows them all. Each reader decides which
verifiers it counts and how much each weighs. The same verifier never gives a second tag under one
label: a new stamp from it gives the same tag.
