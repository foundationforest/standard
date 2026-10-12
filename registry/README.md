# registry

Part of Forest's standard: [the top README](../README.md). Down: the
[security checklist](security-checklist.md).

On devnet: the program runs at `J4ES52YohsZhknYbsgmZwHpyNw14EjrrGZxHpcmcBmq4`, still upgradable
([record](devnet/devnet.json)). Nothing is on mainnet.

## What it is

A free public registry on Solana, and the client a device uses to add to it and read it. Each row
says: *this profile holds a note this issuer signed, under this label*. A profile is one of a
person's identities, named by its main key; a note is an issuer's signed word that it checked the
person; a label is free text saying what the profile is for. A zero-knowledge proof shows
it without showing the note, so a row does not say who the person is. A stamp, the number a person
has for one label at one issuer ([keys](../keys/README.md#stamps)), gets at most one row, and a row
is written once and never changes. The program holds nothing else: no fee, no coin, no treasury and
no admin. The only costs are Solana's own, the network fee and the row's deposit, paid by whoever
sends the transaction.

- `program/`: the program (Anchor 1.2) and its LiteSVM tests, the property test among them.
- `client/`: stamps, the person proof and its check, the two instructions, rows read back, and a
  tier (a number in the note whose meaning is the issuer's, such as which checks it made) checked
  against its row. It talks to no network of its own.
- `circuit/`: the person proof's circuit, its devnet setup and its tests.
- `devnet/`: the deploy script and the public record of what runs on devnet.

## How it works

```
issuer ── checks a face once, signs a note ──▶ the person's device
device ── the person proof, and the main key's signature ──▶ the program
program ── checks both, writes one row at the stamp's address ──▶ anyone reads it
```

### The note and the person proof

**The note.** An issuer is anyone who signs notes for people. One that checks faces checks a
person's face once and signs them one note: *note number, face embedding, model name, tier*.

- The note number comes from the person's secret for that issuer
  ([keys](../keys/README.md#the-note-number)). The device sends it to the issuer once; the issuer
  never learns the secret.
- The embedding is the bytes the issuer's model gives for the face, and the model name says which
  model. The tier is a number whose meaning is the issuer's.
- Text and bytes enter a proof as `keccak256(…) >> 8`: their hash, one byte shorter, so it fits
  the proof's numbers.
- The issuer signs `Poseidon(tag, note number, keccak256(embedding) >> 8, keccak256(model) >> 8,
  tier)` with its EdDSA key on Baby Jubjub, over Poseidon (circomlib's). The tag is
  `keccak256("forest/v1/note") >> 8`, always the same, so nothing an issuer signs for another
  purpose can pass as a note. The embedding and the model enter only as their hashes.
- The person keeps the note, in their vault (the folder a new device restores from,
  [records](../records/README.md#the-vault)), as JSON:
  `{ noteNumber, embedding, model, tier, issuer, signature: { r8: [x, y], s } }`, numbers in
  decimal text, the embedding in base64url, the issuer's key as 128 characters of lowercase hex
  (`noteToJson`, `noteFromJson`).

**The person proof.** To register, the device proves, showing neither the secret nor the note:
*I know an issuer secret and a note this issuer signed for its note number; my stamp for this
label is this one; this proof is for this main key.*

- Public: the issuer's key (two numbers), the label as its scope, the main key as its message, the
  stamp and the tier.
- The scope is `keccak256("forest.foundation/label/v1/" ‖ label) >> 8`, and the message
  `keccak256("forest.foundation/profile/v1/" ‖ main key) >> 8`. The program derives both itself,
  so a proof counts for one label and one profile, and a proof seen in flight cannot be landed
  under any other.
- The stamp is `Poseidon(scope, secret)` ([keys](../keys/README.md#stamps)). It depends on the
  secret and the label, not on the note, so a new note, with a new tier or under a new key, gives
  the same stamp.
- The same proof, attached to the profile later, shows its tier
  ([records](../records/README.md)).
- **The issuer's key is the issuer's to keep.** Whoever holds it can sign notes for people who do
  not exist. An issuer signs only numbers it computed itself: a number someone hands it to sign
  could be a note.

### The row

`register` carries the proof, signed by the main key. The program verifies the proof, requires
that signature, and writes the row at the address derived from the stamp, `["row", stamp]`.
Registered, the main key is that profile.

| Offset | Bytes | Field |
|---|---|---|
| 0 | 8 | discriminator, `sha256("account:Row")[..8]`: Anchor's mark for the account's type |
| 8 | 32 | profile: the main key, which signed |
| 40 | 32 | stamp: the proof's output, which the address comes from |
| 72 | 64 | issuer: its key on Baby Jubjub, x then y, each 32 bytes big-endian |
| 136 | 32 | payer: whoever paid the deposit |
| 168 | 8 | made: the chain's clock when the row was written, Unix seconds, i64 little-endian |
| 176 | 4 + n | label: u32 length, then UTF-8 |

- Every fixed field sits at a fixed offset and the label, at most 128 bytes, is last. So a row is
  `180 + label` bytes, and a reader finds every row of one profile with a filter at offset 8, of
  one issuer at offset 72, and of one label at offset 176 (`fetchRows`).
- The tier is checked and not kept: a profile shows its tier with the same proof attached to it,
  and a reader checks that proof against the row (`verifyTier`).
- Whoever signs as payer pays the deposit and is recorded, so a refund can find them: the person,
  an app, or a fee payer, a service that pays Solana's costs for others.
- A label is any text ([keys](../keys/README.md#main-keys)); the program does not care what it
  says.

### One row per stamp

A stamp is one person's, for one label, at one issuer, so there is at most one row per person, per
label, per issuer.

- A second row at the same stamp's address cannot exist: `register` refuses it.
- A row is never written again and never closes, since closing it would free the stamp for a
  second row.
- A new note from the same issuer gives the same stamp, so a second profile under one label needs
  a note from a second issuer.
- Rows are not numbered in order: a count shared across registrations would link a person's
  profiles.

### The leak date

The program checks no issuer: anyone can sign notes, and each reader decides which issuer keys it
trusts. A row's `made` comes from the chain's clock, never from the sender, so no row can be
backdated. So when an issuer's key leaks, a reader stops counting that key's rows made from the
leak on, and keeps counting the ones made before. Which date it takes, if any, is each reader's
choice.

### Instructions

| | What it does | Signs |
|---|---|---|
| `register(stamp, issuer, tier, proof, label)` | Verifies the proof with public inputs `[stamp, issuer x, issuer y, scope(label), message(profile), tier]`, then writes the row with the clock's time. A second row for the same stamp is refused | the main key and the payer (one key may be both) |
| `refund()` | Moves what a row holds above its current rent-exempt minimum, the deposit Solana requires for an account to stay, to the payer the row records. The row's data is untouched | nobody |

The program emits no events; readers read the rows.

### The circuit and its setup

[`circuit/person.circom`](circuit/person.circom):

| | Signals |
|---|---|
| Private | `secret`, the scalar `keys/`'s `issuerSecret` gives; the note's embedding hash and model hash; the issuer's signature, `R8x`, `R8y` and `S` |
| Public, in this order | `stamp`, the output; `issuerX`, `issuerY`; `scope`; `message`; `tier` |

Inside the proof: the note number is `Poseidon(secret)`; circomlib's `EdDSAPoseidonVerifier`,
unchanged, checks that the issuer's key signed `Poseidon(tag, note number, embedding, model,
tier)`, with the tag fixed in the circuit; the stamp is `Poseidon(scope, secret)`; and the message
is squared, as Semaphore does, so it cannot be changed in a proof.

A proof of this kind (Groth16) needs a setup, made once for the circuit: whoever knows all of the
setup's secret randomness could forge proofs, so it is made in public by many people, and one
honest one is enough.

- **The setup is single-party.** Phase 1 is public, PSE's Perpetual Powers of Tau
  (`ppot_0080_16.ptau`); phase 2 is one contribution, so whoever ran `circuit/devnet/setup.sh`
  could forge a proof. Devnet only; a public setup ceremony comes before mainnet.
- **Its files are pinned.** All are small, so all are committed in `circuit/devnet/`, with their
  sizes and SHA-256 in [`setup.json`](circuit/devnet/setup.json). `npm run fetch` checks the
  hashes, and `npm run compile` checks the compiled circuit against `setup.json`.
- **It does not change.** `person.circom` is fixed by its setup: a change means a new setup and a
  new program. The program has the verification key baked in as `program/src/verifying_key.rs`,
  written by `groth16-solana` 0.2.0's own converter (`circuit/scripts/parse_vk_to_rust.cjs`,
  copied unchanged, `npm run vk`); a test checks it is the converter's output for the committed
  key.

### Use it

The client (`client/src/`) talks to no network of its own: the caller passes the note, a recent
blockhash and a connection to Solana.

| Function | Gives |
|---|---|
| `stampOf(secret, label)`, `rowAddress(stamp)` | A row's stamp and address, before any proof: an app can check whether the row exists |
| `buildRegistration({...})` | Makes the person proof from the note, and returns the unsigned `register` transaction |
| `registerIx`, `refundIx` | The two instructions, by hand |
| `fetchRow(connection, stamp)`, `fetchRows(connection, { profile, issuer, label })`, `decodeRow(data)` | Rows read back and checked |
| `verifyTier(connection, { profile, issuer?, label?, stamp, tier, proof })` | Checks the tier a profile shows. A profile shows it as a `person` proof in its profile record, the record that holds its card ([records](../records/README.md#proofs)). This checks that person proof, as snarkjs writes it or as its 256 bytes, against the profile's row, and the issuer and label it shows against the row too, when given. Gives the row, so the reader can weigh its issuer and when it was made |
| `signNote(privateKey, note)`, `issuerKeyOf(privateKey)` | For an issuer: the signed note, and its key |
| `noteNumberOf(secret)`, `noteHash(note)`, `noteSigned(note)` | The note number, what an issuer signs, and whether its issuer signed it |
| `noteToJson(note)`, `noteFromJson(json)` | The note as JSON, as a vault keeps it, and back; `noteFromJson` refuses any other shape, and leaves the signature to `noteSigned` |
| `provePerson({ secret, note, label, profile, artifacts })` | The proof, on the device. Refuses a note for another secret, or one its issuer did not sign |
| `verifyPerson({ proof, issuer, label, profile, stamp, tier })` | Whether the proof holds for that issuer, label, main key, stamp and tier |
| `proofBytes(proof)`, `proofFromBytes(bytes)` | The proof as its 256 bytes, and back; both checks take either |
| `personInput({...})` | The circuit's input, for a caller that drives snarkjs itself |

```ts
import { issuerSecret } from '@forest/keys'
import { buildRegistration } from '@forest/registry-client'

const r = await buildRegistration({
  secret: (await issuerSecret(seed, name)).secret,
  note,                         // the note the issuer signed for this person
  label: 'tutoring/seller',
  profile,                      // the main key; it signs
  artifacts: { wasm: 'registry/circuit/devnet/person.wasm', zkey: 'registry/circuit/devnet/person.zkey' },
  payer, recentBlockhash,
})
// r.transaction: unsigned; the main key and the payer sign it, anyone sends it. r.row: its address.
// r.proof, r.stamp and r.tier: what the profile shows for its tier.
```

### Run it

```
cd keys && npm ci                 # the client and the circuit's tests read keys/

cd registry/client && npm ci
npm run check && npm test         # no chain
npm run test:validator            # starts solana-test-validator itself
npm run test:devnet               # read-only, against registry/devnet/devnet.json
npm run fixtures                  # remake the real proofs the Rust tests use

cd registry/circuit && npm ci     # after registry/client
npm run fetch                     # the committed setup files, hash-checked
npm run compile                   # circom 2.2.3 on PATH or in CIRCOM; checks setup.json
npm run check && npm test         # a proof, and every way one must fail
npm run vk                        # rewrite ../program/src/verifying_key.rs from the committed key
devnet/setup.sh                   # a new setup: new files, every hash new, a new program key

cd registry/program && cargo build-sbf --arch v3      # Solana CLI 4.2.2 or later
cd registry/program/tests-litesvm && cargo test       # the rules, the attacks, the property test
FOREST_FUZZ_ITERATIONS=1000 cargo test --release --test invariants -- --nocapture
```

- The circuit's tests make a proof for `keys/`'s test person and check that a wrong issuer key, a
  forged signature, the issuer's signature without the tag, a tier the issuer did not sign,
  another person's secret, a stamp for another label and a proof replayed for another main key all
  fail.
- The LiteSVM tests run against real person proofs committed in
  `program/tests-litesvm/fixtures/proofs.json`, which `npm run fixtures` makes with the committed
  setup, for `keys/`'s test person: two profiles from its test seed, and its secrets for `keys/`'s
  two test issuers. They check the wire format against a second copy written by hand in
  `program/tests-litesvm/src/lib.rs`.

Devnet: `FOREST_DEVNET_SEED=<phrase> registry/devnet/deploy.sh` builds a copy with the devnet
program id, deploys it, or upgrades it in place when it holds other bytes (the exact cost checked
first), and records it in `devnet/devnet.json`; the script's header holds the recipe for every
devnet key it needs. The source's own program id, `FoRRegistryRows…1111`, is a placeholder nobody
holds a key for; every deploy puts in its own. Then `FOREST_DEVNET_KEYS=<dir> node
scripts/devnet.ts` in `client/` has a stand-in issuer sign a note for `keys/`'s test person,
writes one row, shows the refusal of a second profile's row for the same stamp, and a refund, and
checks the tier the profile shows against its row; the record keeps that proof.

### What one row costs

Measured on devnet, from the row in `devnet/devnet.json` (`row`): a v0 transaction, two
signatures, no compute-budget instruction.

| | Bytes of 1,232 | Compute units of 200,000 |
|---|---|---|
| `register`, a 16-byte label | 620 | 132,511 |
| `refund` | | 3,164 |

- Verifying the proof is about 130,000 of those compute units. The circuit has 4,979 constraints;
  in Node, a proof takes about a second to make and 50 ms to check. It is 725 bytes as snarkjs
  writes it, 256 as a profile carries it, and 128 as `register` takes it, its points compressed.
- The deposit is the rent-exempt minimum for the row: its 196 bytes, plus the 128 Solana counts
  for every account, at 5,080 lamports a byte, the rate on devnet when it was made, is 1,645,920
  lamports (a lamport is a billionth of a SOL).
- The network fee is 5,000 lamports a signature. The program is 163,136 bytes.

### Sealed on mainnet

On mainnet the program is sealed the day it deploys: nothing in it can change, and a later version
is a new program at a new address whose rows start empty. On devnet it stays upgradable, for
testing. What a mainnet deploy seals:

- **The circuit and the verification key.** The person circuit, with the key of a public setup
  ceremony that comes before mainnet; on devnet, the single-party setup in `circuit/devnet/`.
  Public signals in the order stamp, issuer x, issuer y, scope, message, tier; `proof_a` negated in
  the program; points arriving compressed; every public input checked to be below BN254's scalar
  order.
- **The scope and the message,** as above. Their strings, `forest.foundation/label/v1/` and
  `forest.foundation/profile/v1/`, never change: the label's is in every row's address, through the
  stamp, and the profile's is in every proof.
- **The row's address and layout, the instruction bytes and the discriminators.** Written twice on
  purpose, in `client/src/program.ts` and `program/tests-litesvm/src/lib.rs`, and checked against
  each other and against what the program writes.
- **The rules.** One proof per `register`; one row per stamp; a label of at most 128 bytes; the
  main key's signature; the time from the clock; a row never written again; a refund of exactly
  the excess, to the recorded payer only.

```
solana program deploy --program-id <keypair> target/deploy/forest_registry.so
solana program set-upgrade-authority <program id> --final
solana program show <program id>          # Authority: none
```

## Promises

- At most one row per stamp. A stamp is one person's, for one label, at one issuer.
- Only the main key can put a row on its profile.
- A proof counts for one label and one profile: the program derives the scope from the label and
  the message from the profile, and verifies against them.
- A row is never written again after `register`, and never closes.
- `refund` moves only what a row holds above its rent-exempt minimum, and only to the payer it
  records.

## Limits

- **It trusts the person circuit's single-party setup.** Its verification key is baked into the
  program, and whoever ran `circuit/devnet/setup.sh` could forge a proof. Devnet only; a public
  setup ceremony comes before mainnet.
- **It trusts its pieces, used unchanged:** on chain, `groth16-solana` 0.2.0 and Solana's
  `alt_bn128` syscalls to verify, and Anchor 1.2; on the device, `snarkjs` 0.7.5 to make proofs and
  check them (`verifyPerson`, `verifyTier`), and zk-kit's `@zk-kit/eddsa-poseidon` 1.0.4 to sign
  notes.
- **A row is only as good as its issuer.** The program checks no issuer key, so anyone can sign
  notes with a key of their own and write rows with them. An issuer that checks faces is trusted to
  sign one note per real, distinct human; the program cannot tell. A reader that trusts no issuer
  counts no row.
- **A row made after its issuer's key leaked stays uncounted.** It still takes its stamp, and a
  note under the issuer's new key gives the same stamp, so the person that stamp belongs to cannot
  write a second row under that label with that issuer.
- **One row per issuer, not per face.** A person with notes from two issuers can hold two rows
  under one label, for two profiles. A reader that trusts both issuers counts both.
- **The refund goes to whoever paid.** When a fee payer paid the deposit, the refund is the fee
  payer's, not the person's.
- **Not audited.** The [security checklist](security-checklist.md) lists every rule and every known
  limit.

## Who decides what

- **The standard:** the row, the proof, and one row per stamp; to be sealed on mainnet.
- **An issuer:** chooses whom it signs notes for and how it checks them, and what its tiers mean.
- **Other services:** each chooses for itself which rows a fee payer pays for, and which issuers an
  index (a service that reads records and scores profiles) counts, and from when.
- **An app, with the person:** when to register, making the proof on the device, and showing the
  tier.

## FAQ

**What is `refund` for?** Solana is cutting its rent rate in steps, and only the program that owns
an account can move the difference out of it: at 696 lamports a byte, a 196-byte row's minimum
would be 225,504 lamports. `refund` sends what a row holds above the new minimum, or anything
someone sent the row, back to whoever paid for it. Anyone may send it: the amount and the
destination are read from the chain, never from the caller.

**What if I lose my seed?** The rows stay on the chain and nobody else can use them, but your issuer
secrets are gone, and an issuer that checks faces will not sign your face a note for a new seed.
The 24 words are the only backup.

**Can I be checked by more than one issuer?** Yes. Each issuer's note gives its own row for the same
profile, at its own stamp. An index decides which issuers it counts and how much each weighs, so
more issuers behind a profile give it more weight at an index that counts them. The same issuer
never gives a second row under one label: a new note from it gives the same stamp.

**What if someone steals my seed, or I sell it?** Whoever holds the seed acts as every profile and
can move their money ([keys](../keys/README.md#faq)). The note an issuer signed carries numbers
made from the person's face, its embedding, so a service that wants to can ask whoever shows the
note for a live face match against it. Today no service does, outside the foundation's issuer,
which matches a live face against a note only before it signs the same note at a higher tier. A
sold seed is the same case.
