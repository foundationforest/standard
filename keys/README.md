# keys

Part of Forest's standard: [the top README](../README.md).

## What it is

A person's keys in Forest: one seed, 24 random words, and the recipe that mixes every other key
from it, on the person's own device. Any app that follows this page gets the same keys from the
same seed, so a person is never tied to one app.

This README is the standard: the seed and the recipe are fixed, and the rules for apps are
defaults an app adopts, or says it doesn't. The library in `src/` follows it, and
`test/vectors.json` pins its answers.

## How it works

### The seed

- The seed is 32 random bytes, written as 24 English words (BIP39: the 32 bytes plus an 8-bit
  checksum). The words are the 32 bytes and nothing more: BIP39's own seed step (PBKDF2, with a
  passphrase) is not used.
- Case and spacing in the words do not matter. A word not on BIP39's list is refused, and the
  checksum catches all but about 1 in 256 other mistakes, such as a wrong word or two words
  swapped.
- Where the seed lives is the app's choice. By default it stays on the device, locked by the
  device's secure hardware: a phone's keychain (Apple's Keychain or Android's Keystore), or, in a
  browser, encrypted under a secret that hardware gives only after the person's face or
  fingerprint; the 24 words in the person's password manager are the backup.
- Whoever controls the app that holds the seed controls the seed, since the app can do whatever the
  seed can. A web app's code arrives from its server on each visit; an installed app's does not.

### The recipe

Every key below is mixed with HKDF-SHA256 (RFC 5869), a standard one-way mix of a secret and a
text: an empty salt, the text's UTF-8 bytes as its info, 32 bytes out. Only the text changes, and
each key is explained below, in the order it is needed. The table uses words from the rest of the
standard:

- **profile:** one of the person's identities, one for each label, a free text saying what the
  profile is for;
- **note:** what an issuer, anyone who checks people, signs for a person after checking them;
- **stamp:** the number that sets where one registry row sits; a row says in public that a profile
  holds a note;
- **vault:** a folder of the person's own on a host, which a new device restores from. A folder is
  the signed records kept under one key, and a host is a server that keeps folders.

| From | Mixed with (info) | Gives |
|---|---|---|
| the seed | `forest/v1/profile/<label>` | a main key: one profile's name, Solana address and signature |
| a main key's 32 private bytes | `forest/v1/read` | that profile's inbox key, which opens what is encrypted to it |
| the seed | `forest/v1/issuer/<issuer name>` | the person's secret for one issuer, which their note number and stamps come from |
| the seed | `forest/v1/vault` | the vault key: the main key of the person's vault, a folder of its own |

The info strings are part of every key, so they never change: a new string would give everyone
new keys.

### Day to day

By default, nothing mixed from the seed is stored, only the seed. When the person acts, the app
mixes the one key that action needs (a profile's main key from its label, its inbox key from that,
the issuer secret for a proof), uses it, and drops it; JavaScript cannot promise its bytes are
erased (Limits). The vault is not used day to day: a new device reads it to learn which profiles
exist, and the app writes it when what it holds changes, such as a new profile or a grant received
([records](../records/README.md#the-vault)).

### Main keys

A main key is one profile: it signs the profile's records (the signed statements in its folder)
and transactions, and its address is the profile's name.

- There is one per label. A label is free text saying what the profile is for, used exactly as
  given, as UTF-8, so `Tutoring/Seller` and `tutoring/seller` are two profiles. The recommended
  shape is `market/role`, such as `tutoring/seller`, with market names from
  [foundationforest/markets](https://github.com/foundationforest/markets).
- The 32 bytes are an ed25519 private key (RFC 8032), in the form Solana tooling takes for a
  keypair, so every main key is also a Solana account.
- Its address is the public key in base58 (the Bitcoin alphabet): the profile's name and its
  Solana address at once, so the two can never disagree.

### Inbox keys

A profile's inbox key opens what others encrypt to it: the messages in its inbox and its private
records ([records](../records/README.md)).

- It is mixed from the main key, not from the seed: whoever holds a main key can open what is
  encrypted to its profile, and nothing more. An inbox key gives no other profile, and no main key
  gives the seed.
- Its 32 bytes are used unchanged as an identity for age, a widely used encryption format, of
  age's post-quantum hybrid kind, `mlkem768x25519`: two keys at once, ML-KEM-768 and X25519, so
  what is encrypted to it stays closed unless both are broken. It is written
  `AGE-SECRET-KEY-PQ-1`, then bech32 of the bytes, in upper case; age expands it into the two
  private keys.
- Others encrypt to its public half, the recipient `age1pq1…`, which age computes from the
  identity. It is about 1,960 characters long. The profile publishes it; the address does not give
  it.
- The main key cannot do this job: ed25519 only signs, so nothing is ever encrypted to a main key.

### The issuer secret

An issuer is anyone who signs notes for people, such as one that checks a person's face once and
signs them a note ([registry](../proofs/human/README.md#the-note-and-the-person-proof)). For each
issuer, a person has one secret, mixed from their seed and the issuer's name.

- The name is the text the issuer publishes as its own, such as a domain, used exactly as given,
  as UTF-8. The secret comes from the name, not the issuer's key, so an issuer that changes its key
  changes no one's stamps.
- The proofs take the secret as a number, the scalar. (A zero-knowledge proof shows that something
  is true of a secret without showing the secret.) The 32 bytes become the scalar the way Semaphore
  v4 made its secret scalar (zk-kit's `deriveSecretScalar`, `@zk-kit/eddsa-poseidon` 1.0.4),
  restated here only so it can be checked:
  1. `h` = the first 32 bytes of BLAKE-512 of the 32 bytes.
  2. Prune: `h[0] &= 0xf8; h[31] &= 0x7f; h[31] |= 0x40`.
  3. The scalar = (`h` read little-endian, shifted right 3) mod `l`, the Baby Jubjub subgroup
     order.
- Nothing is stored: the app mixes the secret again from the seed whenever a proof needs it.

### The note number

The note number is what a person gives an issuer: Poseidon of the scalar, with one input.
Poseidon (circomlib's) is a hash made to be cheap inside a zero-knowledge proof. The device sends
the note number to the issuer once, and the issuer signs it in the person's note. The issuer never
learns the secret.

### Stamps

A stamp is the number a person's registry row sits at: `Poseidon(scope, scalar)`, one for each
label, where the scope is the label as a number, made the way the registry makes it
([registry](../proofs/human/README.md#the-note-and-the-person-proof)).

- The same person, issuer and label always give the same stamp, and nobody without the secret can
  work it out.
- Stamps for two labels, or for two issuers, cannot be matched to each other.

### The vault key

The vault is a folder of the person's own, on a host, that holds what a new device needs and the
seed cannot give back: the labels of their profiles, the grants they received (each a private
message that hands them an access key, a key that acts for one profile within limits), their
issuers' notes, and apps' settings ([records](../records/README.md#the-vault)). Its key is mixed
from the seed, so a new device finds the vault with the seed alone.

- It is a main key with no label: its address is the vault folder's name, and it signs the vault's
  records. No label gives it: a profile's text always starts `forest/v1/profile/`.
- Its inbox key, mixed from it by `forest/v1/read` as any main key's is, opens what the vault
  holds.
- Its address ties to no profile: one profile's keys say nothing about the vault's, and the vault's
  say nothing about any profile's.

### Access keys

A person hands out access keys, never a main key. An access key is one the owner's app makes at
random, not from the seed, and hands to an app, a server or an AI so it can act for one profile.
Each has one scope, the one kind of thing it may do:

- **write key:** signs records into the profile's folder, at the paths it is allowed (a path is
  where a record sits in the folder, such as `offer/maths`);
- **message key:** sends the profile's messages and pulls its inbox;
- **read key:** opens the private records and messages encrypted to it.

The profile's permissions record, a record in its folder that only the main key writes, lists
which access keys may act, and a grant hands one to whoever it is for
([records](../records/README.md)).

### Rules for apps that hold keys

1. The seed stays on the device, locked by its secure hardware; keys mixed from it are held in
   memory only for the action that needs them.
2. Every signature asks for the person's face or fingerprint and shows what is being signed; the
   person may relax this per action, and the default is never relaxed.
3. Nothing leaves the device but access keys and signatures.
4. Each app, server or AI the person lets act for them gets its own access key for each folder.
5. Proofs are made in the app, never delegated.
6. The app works with any host, and its host with any app.
7. A server that acts for you holds access keys with write, message or read scope.
8. The app that holds the seed is open source.
9. Keep a copy of every record signed; a host may drop one, and the copy puts it back.
10. Keep each grant, an access key handed to the person, in the vault.
11. Keep the issuer's note as safely as a key, in the vault.

### Use it

Everything is exported from `src/index.ts`. Everything that mixes is async.

| Function | Gives |
|---|---|
| `newSeed()` | A new seed: 32 random bytes |
| `exportWords(seed)`, `importWords(text)` | The 24 words, and the seed back from them |
| `mainKey(seed, label)` | The main key: `label`, `privateKey`, `publicKey`, `address` |
| `inboxKey(main.privateKey)` | The inbox key: age's `identity`, and the `recipient` others encrypt to |
| `issuerSecret(seed, name)` | The issuer's `secret`, its `scalar`, and the `noteNumber` |
| `vaultKey(seed)` | The vault key: `privateKey`, `publicKey`, `address`; `inboxKey` of its `privateKey` opens the vault |
| `hkdf(ikm, info)`, `INFO` | The mixer and its info strings |

```
cd keys
npm ci
npm test        # the pinned vectors, and each value recomputed without the library
npm run check   # type-check
npm run build   # dist/ for other packages
```

Node 22.18 or later runs the TypeScript directly.

### Test vectors

`test/vectors.json` pins, for the seed `00 01 … 1f`: its 24 words; the main keys for
`tutoring/seller` and `tutoring/buyer`, each with its inbox key; the issuer secrets, scalars and
note numbers for two issuers, `issuer-a.example` and `issuer-b.example`; and the vault key, with
its inbox key. `npm test` checks
each value and recomputes it without the library: HKDF from a second implementation, ed25519 from
`@noble/curves`, the hybrid recipient from `@noble/post-quantum`, age's bech32 by hand, an
encryption and an opening through age, and the scalar step by step without zk-kit.

## Promises

- **The same seed gives the same keys,** in any app, on any device, every time.
- **Nothing ties two profiles together.** Each label is its own mix: one profile's main key,
  address or inbox key says nothing about another's.
- **Nothing ties two issuers together.** Each issuer is its own mix, so the same person's note
  numbers for two issuers are unrelated, and two issuers comparing what they hold cannot match
  them.
- **No key gives the seed back.** Every mix is one way. A main key gives its inbox key, and
  nothing else.
- **Nothing leaves the device.** The library talks to no network and stores nothing.

## Limits

- **It trusts the device's secure hardware and the person's password manager** to keep the seed and
  the words, and show them to no one else.
- **It trusts its pieces, used unchanged:** Web Crypto (HKDF-SHA256, and its random source for new
  seeds), `@noble/curves` 2.4.0 (ed25519), `@scure/base` 2.4.0 (base58, bech32), `@scure/bip39`
  2.4.0, `age-encryption` 0.3.1 (whose hybrid runs on `@noble/post-quantum`),
  `@zk-kit/eddsa-poseidon` 1.0.4 and `poseidon-lite` 0.3.0.
- **An issuer's name is its own to keep unique.** Two issuers under one name get the same note
  number from each person, so they can match their people.
- **No recovery.** Lose the device and the words, and every profile and every stamp is gone.
  Nobody can reset them, because nobody else has them.
- **No rotation.** A profile's name is its key, so a leaked main key loses that profile for good
  (see the FAQ).
- **One profile per label per seed.** The same seed and label always give the same key.
- **Only the inbox key and read keys are post-quantum.** ed25519 and the proofs' curves fall to a
  large quantum computer (see the FAQ).
- **No wiping of memory.** JavaScript cannot promise that bytes are erased; an app closes the
  page, the library cannot.
- **Tested in Node only,** though the library is written to run in a browser too.

## Who decides what

- **The standard:** the 24 words, the recipe and its info strings.
- **An app, with the person:** which of the rules above it adopts; where the seed and keys live and
  how the face or fingerprint opens them; backups; how a read key reaches its reader.
- **A service:** nothing. No service holds a main key.

## FAQ

**Why 24 words?**
24 words are 256 random bits: nobody guesses them. A secret one provider keeps for you stays with
that provider; words go anywhere, so the seed works with any app on any device. The cost: whoever
gets the words gets every key.

**What if I give the words to the wrong app?**
Then that app has everything the seed opens, and nothing takes it back:
- every profile: a main key is mixed from the seed and a label, and labels are public, so it can
  mix the main key of every profile, sign as it and move its money;
- every inbox key, so it can open the person's private records and messages;
- every issuer secret, so it can use the person's stamps. Under a label where the person has no
  registry row yet, it can register that row for a profile of its own; the stamp is then taken, so
  this seed can never have a row there;
- the vault, with every grant the person received and their issuers' notes.

There is no rotation, so the only way out is a new seed and new profiles, moving the money first if
there is still time. Another app that asks for 24 words takes them as an ordinary recovery phrase
and shows unrelated accounts: they are not the person's profiles, but that app now holds the seed.
Give the words only to an app that follows the rules above.

**Why is one key a profile's name, its signature and its Solana address?**
So a registry row names the profile itself, with nothing to cross-check. The name is the key's
base58 address, not an identifier in some other format: one spelling names the profile in records,
on the registry and on Solana, and it needs no directory that could refuse, withhold or misorder
it.

**Why two mixers, HKDF and Poseidon?**
They work in different places. HKDF-SHA256 mixes every key from the seed, on the device: it is a
standard, built into every browser's Web Crypto, and well studied. Inside a zero-knowledge proof,
SHA-256 costs far more than Poseidon. The registry's circuit uses Poseidon to turn the issuer
secret into the note number and a stamp, so a proof can show that an issuer signed a note for the
note number, and give the stamp, without showing which note. So HKDF mixes up to the issuer
secret, outside the proof, and Poseidon takes it from there. Neither is ours; both are used
unchanged.

**What about quantum computers?**
Private records sit in public for years, so what they are encrypted to is post-quantum: a copy
taken today stays closed once quantum computers come. Signing does not need that yet, since a
signature can only be forged once such a computer exists. So only the inbox key and read keys are
post-quantum. A large enough quantum computer could:
- work out from a profile's address what signs for it, then sign as the profile and move its
  money;
- forge person proofs (the proof that registers a profile, showing an issuer signed the person a
  note) and reputation proofs (the proof that carries a score from a person's profiles to another
  of theirs), whose curves it breaks too.

It could not open private records, even ones copied today to open later:
- the inbox key is age's hybrid, so its recipient gives nothing away unless ML-KEM-768 breaks
  too;
- breaking an address gives ed25519's signing number, not the main key's 32 private bytes the
  inbox key is mixed from: ed25519 hashes those bytes with SHA-512 first, and SHA-512 holds.

Nor could it undo the mixes: HKDF-SHA256, and so the seed, holds. Quantum-safe main keys would
be a new version with new info strings, and since a name is a key, every profile would get a new
name.

**What if a main key leaks?**
Whoever has it is that profile: it can sign records as the profile, move its money, and mix its
inbox key to open its private records. It cannot reach the seed, another profile, or an issuer
secret. There is no rotation, because the name is the key, and nothing in Forest marks the profile
as leaked: the person stops using it. Its registry row stays with it, because rows never change.
The same seed and label always give the leaked key, and the stamp depends on the seed, the
issuer's name and the label, never on the profile. So with this seed, that label with that issuer
is gone for good.
