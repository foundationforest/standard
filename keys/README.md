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

Two mixers, each a standard one-way mix:

- **HKDF-SHA256** (RFC 5869), on the device: an empty salt, a text's UTF-8 bytes as its info, 32
  bytes out. Only the text changes.
- **Poseidon** (circomlib's), a hash made to be cheap inside a zero-knowledge proof (a proof that
  something is true of a secret without showing the secret). Every Poseidon mix starts with a fixed
  tag, so no mix can give another's number.

Text enters Poseidon as a number: `keccak256` of its UTF-8 bytes, shifted right one byte so it fits
the proofs' numbers. A label's number is its **scope**, `keccak256("forest.foundation/label/v1/" ‖
label) >> 8`; an issuer's name's is its **name hash**, `keccak256("forest/v1/issuer/" ‖ name) >>
8`; the three tags are `keccak256` of `forest/v1/issuer`, `forest/v1/profile` and `forest/v1/vault`,
`>> 8`.

The table uses words from the rest of the standard:

- **profile:** one of the person's identities, one for each label, a free text saying what the
  profile is for;
- **note:** what an issuer, anyone who checks people, signs for a person after checking them;
- **stamp:** the number an index's tree knows a profile by, one for each issuer that checked the
  person;
- **vault:** a folder of the person's own on a host, which a new device restores from. A folder is
  the signed records kept under one key, and a host is a server that keeps folders.

| From | Mixed with | Gives |
|---|---|---|
| the seed | HKDF, `forest/v1/seed` | the seed scalar, the one number the proofs take |
| the seed scalar | Poseidon, the profile tag and the label's scope | a main key: one profile's name and signature |
| the seed | HKDF, `forest/v1/profile/<label>` | that profile's secret, which its inbox key comes from |
| a profile's secret | HKDF, `forest/v1/read` | that profile's inbox key, which opens what is encrypted to it |
| the seed | HKDF, `forest/v1/pay/solana/<label>` | that profile's payment key, its Solana address |
| the seed scalar | Poseidon, the issuer tag and the issuer's name hash | the person's secret for one issuer, which their note number and stamps come from |
| the seed scalar | Poseidon, the vault tag | the vault key: the main key of the person's vault |
| the seed | HKDF, `forest/v1/vault` | the vault's secret, which its inbox key comes from |

The texts and tags are part of every key, so they never change: a new one would give everyone new
keys.

### Day to day

By default, nothing mixed from the seed is stored, only the seed. When the person acts, the app
mixes the one key that action needs (a profile's main key from its label, its inbox key, the seed
scalar for a proof), uses it, and drops it; JavaScript cannot promise its bytes are erased
(Limits). The vault is not used day to day: a new device reads it to learn which profiles exist,
and the app writes it when what it holds changes, such as a new profile or a grant received
([records](../records/README.md#the-vault)).

### The seed scalar

The seed scalar is the number the proofs take from the seed. Inside a proof, it ties a person's
notes and profiles together, and only Poseidon mixes of it ever leave, so nothing public links
them.

- It is HKDF of the seed with `forest/v1/seed`, made into a number the way Semaphore v4 made its
  secret scalar (zk-kit's `deriveSecretScalar`, `@zk-kit/eddsa-poseidon` 1.0.4), restated here
  only so it can be checked:
  1. `h` = the first 32 bytes of BLAKE-512 of the 32 bytes.
  2. Prune: `h[0] &= 0xf8; h[31] &= 0x7f; h[31] |= 0x40`.
  3. The scalar = (`h` read little-endian, shifted right 3) mod `l`, the Baby Jubjub subgroup
     order.
- Nothing is stored: the app mixes it again from the seed whenever a proof needs it.

### Main keys

A main key is one profile: it signs the profile's records (the signed statements in its folder),
and its address is the profile's name.

- There is one per label. A label is free text saying what the profile is for, used exactly as
  given, as UTF-8, so `Tutoring/Seller` and `tutoring/seller` are two profiles. The recommended
  shape is `market/role`, such as `tutoring/seller`, with market names from
  [foundationforest/markets](https://github.com/foundationforest/markets).
- Its scalar is the lowest 250 bits of `Poseidon(profile tag, seed scalar, scope)`. Baby Jubjub's
  subgroup order `l` is above 2^250, so every 250-bit number is already a scalar, and the human
  proof derives the same key from the same seed scalar with nothing to reduce
  ([proofs/human](../proofs/human/README.md)).
- Its public key is the scalar times Baby Jubjub's `Base8`, the point circomlib and zk-kit use.
- Its address is the public key packed into 32 bytes (y little-endian, with x's sign in the top
  bit, as circomlib and zk-kit pack it), in base58 (the Bitcoin alphabet): 43 or 44 characters. An
  address in any other spelling, or naming a point outside the prime-order subgroup, is refused.

### Signatures

A main key signs with EdDSA-Poseidon on Baby Jubjub, the signature circomlib's verifier checks
inside a proof, made from the scalar itself.

- The message is a field element, a number below BN254's scalar order.
- The nonce `r` is SHA-512 of `forest/v1/nonce`, the scalar and the message (each 32 bytes
  little-endian), read little-endian, mod `l`: the same message always gets the same signature,
  and no two messages share a nonce.
- `R8 = r · Base8`, `hm = Poseidon(R8x, R8y, Ax, Ay, message)`, and `S = r + 8 · hm · scalar mod
  l`. A signature holds when `S < l` and `S · Base8 = R8 + 8 · hm · A`, the equation zk-kit's
  `verifySignature` and circomlib's `EdDSAPoseidonVerifier` check.

### Inbox keys

A profile's inbox key opens what others encrypt to it: the messages in its inbox and its private
records ([records](../records/README.md)).

- It is mixed from the profile's secret, `hkdf(seed, "forest/v1/profile/<label>")`, not from the
  main key's scalar. A large quantum computer could work a scalar out of a public address; it
  could not work the secret out of anything public. An inbox key gives no other profile, and no
  inbox key gives the seed.
- Its 32 bytes are used unchanged as an identity for age, a widely used encryption format, of
  age's post-quantum hybrid kind, `mlkem768x25519`: two keys at once, ML-KEM-768 and X25519, so
  what is encrypted to it stays closed unless both are broken. It is written
  `AGE-SECRET-KEY-PQ-1`, then bech32 of the bytes, in upper case; age expands it into the two
  private keys.
- Others encrypt to its public half, the recipient `age1pq1…`, which age computes from the
  identity. It is about 1,960 characters long. The profile publishes it; the address does not give
  it.
- The main key cannot do this job: EdDSA only signs, so nothing is ever encrypted to a main key.

### Payment keys

A profile's payment key holds and moves its money on Solana. A main key, on Baby Jubjub, is not a
Solana account, so each profile has one of each.

- It is HKDF of the seed with `forest/v1/pay/solana/<label>`, the label used exactly as given: one
  per label, unrelated to the main key and to every other profile's.
- The 32 bytes are an ed25519 private key (RFC 8032), in the form Solana tooling takes for a
  keypair. Its address is the public key in base58: the profile's `pay` address.

### The issuer secret

An issuer is anyone who signs notes for people, such as one that checks a person's face once and
signs them a note ([proofs/human](../proofs/human/README.md#the-note-and-the-human-proof)). For each
issuer, a person has one secret: `Poseidon(issuer tag, seed scalar, name hash)`.

- The name is the text the issuer publishes as its own, such as a domain, used exactly as given,
  as UTF-8. The secret comes from the name, not the issuer's key, so an issuer that changes its key
  changes no one's stamps.
- Nothing is stored: the app mixes the secret again from the seed whenever it needs it.

### The note number

The note number is what a person gives an issuer: `Poseidon(issuer secret)`. The device sends it
to the issuer once, and the issuer signs it in the person's note. The issuer never learns the
secret, nor the seed scalar behind it.

### Stamps

A stamp is the number an index's tree knows one profile by, at one issuer:
`Poseidon(scope, issuer secret)`. The human proof shows it, and the reputation proof counts the
profiles whose stamps are the person's ([proofs](../proofs/README.md)).

- The same person, issuer and label always give the same stamp, and nobody without the secret can
  work it out.
- Stamps for two labels, or for two issuers, cannot be matched to each other.

### The vault key

The vault is a folder of the person's own, on a host, that holds what a new device needs and the
seed cannot give back: the labels of their profiles, the grants they received (each a private
message that hands them an access key, a key that acts for one profile within limits), their
issuers' notes, and apps' settings ([records](../records/README.md#the-vault)). Its key is mixed
from the seed, so a new device finds the vault with the seed alone.

- It is a main key with no label: its scalar is the lowest 250 bits of `Poseidon(vault tag, seed
  scalar)`, its address is the vault folder's name, and it signs the vault's records as a main key
  does. Its mix has its own tag and no scope, so no label gives it.
- Its inbox key is mixed from the vault's secret, `hkdf(seed, "forest/v1/vault")`, by
  `forest/v1/read` as a profile's is, and opens what the vault holds.
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

Everything is exported from `src/index.ts`. Everything that mixes from the seed is async; what
mixes from the seed scalar is not.

| Function | Gives |
|---|---|
| `newSeed()` | A new seed: 32 random bytes |
| `exportWords(seed)`, `importWords(text)` | The 24 words, and the seed back from them |
| `seedScalar(seed)` | The seed scalar |
| `mainKey(seed, label)` | The main key: `label`, `scope`, `scalar`, `publicKey`, `address`, and the profile's `secret` |
| `profileScalarOf(seedScalar, label)` | A main key's scalar, from the seed scalar |
| `inboxKey(secret)` | The inbox key, from a profile's `secret` or the vault's: age's `identity`, and the `recipient` others encrypt to |
| `payKey(seed, label)` | The payment key: `label`, `privateKey`, `publicKey`, `address` |
| `issuerSecret(seed, name)` | The issuer's `name`, its `nameHash`, the person's `scalar` for it, and the `noteNumber` |
| `issuerScalarOf(seedScalar, name)`, `stampOf(issuerScalar, label)` | The issuer secret from the seed scalar, and a stamp |
| `vaultKey(seed)`, `vaultScalarOf(seedScalar)` | The vault key: `scalar`, `publicKey`, `address`, `secret`; and its scalar |
| `signWithScalar(scalar, message)`, `verifyWithPublicKey(key or address, message, signature)` | A signature `{ R8, S }` on a field element, and its check |
| `publicKeyOf(scalar)`, `addressOf(publicKey)`, `pointOf(address)` | A public key, its address, and the key an address names |
| `scopeOf(label)`, `nameHashOf(name)`, `fieldHash(namespace, ...parts)`, `TAG` | Text as the proofs' numbers, and the three tags |
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

`test/vectors.json` pins, for the seed `00 01 … 1f`: its 24 words; its seed scalar; the three
tags; the main keys for `tutoring/seller` and `tutoring/buyer`, each with its secret and inbox key,
and their payment keys; for two issuers, `issuer-a.example` and `issuer-b.example`, the name hash,
the person's secret, the note number and a stamp for each label; the vault key, with its secret and
inbox key; and one signature by the `tutoring/seller` main key. `npm test` checks each value and
recomputes it without the library: HKDF and keccak from `@noble/hashes`, the seed scalar step by
step without zk-kit, Baby Jubjub's points from `@noble/curves`' own Edwards curves, the address
packed by hand, the signature's equation, ed25519 from `@noble/curves`, the hybrid recipient from
`@noble/post-quantum`, age's bech32 by hand, and an encryption and an opening through age. The
human proof's tests check the circuit derives the same main key and stamp
([proofs/human](../proofs/human/README.md)).

## Promises

- **The same seed gives the same keys,** in any app, on any device, every time.
- **Nothing ties two profiles together.** Each label is its own mix: one profile's main key,
  address, payment key or inbox key says nothing about another's.
- **Nothing ties two issuers together.** Each issuer is its own mix, so the same person's note
  numbers for two issuers are unrelated, and two issuers comparing what they hold cannot match
  them.
- **No key gives the seed back.** Every mix is one way. A profile's secret gives its inbox key, and
  nothing else.
- **Nothing leaves the device.** The library talks to no network and stores nothing.

## Limits

- **It trusts the device's secure hardware and the person's password manager** to keep the seed and
  the words, and show them to no one else.
- **It trusts its pieces, used unchanged:** Web Crypto (HKDF-SHA256, and its random source for new
  seeds), `@noble/hashes` 2.4.0 (keccak256, SHA-512), `@noble/curves` 2.4.0 (ed25519),
  `@scure/base` 2.4.0 (base58, bech32), `@scure/bip39` 2.4.0, `age-encryption` 0.3.1 (whose hybrid
  runs on `@noble/post-quantum`), `@zk-kit/baby-jubjub` 1.0.3, `@zk-kit/eddsa-poseidon` 1.0.4 and
  `poseidon-lite` 0.3.0.
- **An issuer's name is its own to keep unique.** Two issuers under one name get the same note
  number from each person, so they can match their people.
- **No recovery.** Lose the device and the words, and every profile and every stamp is gone.
  Nobody can reset them, because nobody else has them.
- **No rotation.** A profile's name is its key, so a leaked main key loses that profile for good
  (see the FAQ).
- **One profile per label per seed.** The same seed and label always give the same key.
- **Only the inbox key and read keys are post-quantum.** Baby Jubjub, ed25519 and the proofs'
  curves fall to a large quantum computer (see the FAQ).
- **No wiping of memory.** JavaScript cannot promise that bytes are erased; an app closes the
  page, the library cannot.
- **Tested in Node only,** though the library is written to run in a browser too.

## Who decides what

- **The standard:** the 24 words, the recipe, its info strings and its tags.
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
  mix the main key of every profile and sign as it, and every payment key and move its money;
- every inbox key, so it can open the person's private records and messages;
- the seed scalar, so it can make human proofs for the person's profiles with their notes, and
  reputation proofs from their scores;
- the vault, with every grant the person received and their issuers' notes.

There is no rotation, so the only way out is a new seed and new profiles, moving the money first if
there is still time. Another app that asks for 24 words takes them as an ordinary recovery phrase
and shows unrelated accounts: they are not the person's profiles, but that app now holds the seed.
Give the words only to an app that follows the rules above.

**Why is a main key on Baby Jubjub, with a payment key beside it?**
So a proof can derive it. The human proof shows that a profile's key comes from the same seed as
a note an issuer signed, and the reputation proof that a profile's key comes from the same seed as
the profiles it counts: both work the key out from the seed scalar inside the proof. Baby Jubjub
is the curve a proof does that on cheaply; ed25519 inside a proof costs far more. Solana's accounts
are ed25519, so the money sits under a payment key of its own, mixed from the seed apart from the
main key.

**Why two mixers, HKDF and Poseidon?**
They work in different places. HKDF-SHA256 mixes on the device, from the seed: it is a standard,
built into every browser's Web Crypto, and well studied. Inside a zero-knowledge proof, SHA-256
costs far more than Poseidon. So what a proof must work out (the issuer secret, the note number, a
stamp, a main key) is Poseidon of the seed scalar, and what no proof needs (the profiles' secrets,
the payment keys, the vault's secret) is HKDF of the seed. Neither is ours; both are used
unchanged.

**Why is the inbox key not mixed from the main key?**
Because the main key's scalar is not secret from a quantum computer. With ed25519, a main key's
32 private bytes were hashed before they became its scalar, so breaking the address gave the
scalar and not the bytes. A Baby Jubjub main key's scalar is the number a proof derives, and
breaking its address gives exactly that. An inbox key mixed from it would fall with it, and so
would every private record copied today. A profile's secret is HKDF of the seed, which no public
number gives.

**What about quantum computers?**
Private records sit in public for years, so what they are encrypted to is post-quantum: a copy
taken today stays closed once quantum computers come. Signing does not need that yet, since a
signature can only be forged once such a computer exists. So only the inbox key and read keys are
post-quantum. A large enough quantum computer could:
- work out from a profile's address its main key's scalar, then sign as the profile; and from its
  payment address its payment key, then move its money;
- forge human proofs (the proof that a profile's key comes from a seed an issuer checked) and
  reputation proofs (the proof that carries a score from a person's profiles to another of
  theirs), and issuers' notes, whose curves it breaks too.

It could not open private records, even ones copied today to open later:
- the inbox key is age's hybrid, so its recipient gives nothing away unless ML-KEM-768 breaks
  too;
- the inbox key comes from the profile's secret, which no public number gives.

Nor could it undo the mixes: HKDF-SHA256 and Poseidon, and so the seed and the seed scalar, hold.
Quantum-safe main keys would be a new version with new tags, and since a name is a key, every
profile would get a new name.

**What if a main key leaks?**
Whoever has it can sign records as the profile. It cannot reach the seed, the seed scalar, another
profile, the profile's payment key or its inbox key. There is no rotation, because the name is the
key, and nothing in Forest marks the profile as leaked: the person stops using it. The same seed
and label always give the leaked key, so with this seed, that label is gone for good.
