# keys

Part of Forest's standard: [the top README](../README.md).

## What it is

A person's keys in Forest: one seed, 32 random bytes, and the recipe that mixes every other key
from it, on the person's own device. Any app that follows this page gets the same keys from the
same seed, so a person is never tied to one app.

This README is the standard: the seed and the recipe are fixed. The library in `src/` follows it,
and `test/vectors.json` pins its answers.

## How it works

### The seed

- The seed is 32 random bytes.
- How an app makes, keeps and unlocks it is the app's. Nothing in the standard needs it to leave
  the device, or to be held longer than mixing keys from it takes.
- A seed can be spelled as 24 words, BIP39's for the 32 bytes and not its PBKDF2 seed step, by
  `exportWords` and `importWords`, for an app that wants them; the Forest app doesn't.
- Whoever controls the app that holds the seed controls the seed, since the app can do whatever the
  seed can. A web app's code arrives from its server on each visit; an installed app's does not.

### The recipe

Two mixers, each a standard one-way mix:

- **HKDF-SHA256** (RFC 5869), on the device: an empty salt, a text's UTF-8 bytes as its info, 32
  bytes out. Only the text changes.
- **Poseidon** (circomlib's), a hash made to be cheap inside a zero-knowledge proof (a proof that
  something is true of a secret without showing the secret). Every Poseidon mix starts with a fixed
  prefix, so no mix can give another's number.

Text enters Poseidon as a number: `keccak256` of its UTF-8 bytes, shifted right one byte so it fits
the proofs' numbers. A label's number is its **scope**,
`keccak256("forest/v1/label/" ‖ label) >> 8`; a verifier's name's is its **name hash**,
`keccak256("forest/v1/issuer/" ‖ name) >> 8`; the three prefixes are `keccak256` of
`forest/v1/issuer`, `forest/v1/profile` and `forest/v1/vault`, `>> 8`.

The table uses words from the rest of the standard:

- **profile:** one of the person's identities, one for each label, a free text saying what the
  profile is for;
- **stamp:** what a verifier, anyone who signs stamps, signs to a person's seed;
- **tag:** the number an index's tree knows a profile by, one for each verifier that signed the
  person a stamp;
- **vault:** a folder of the person's own on a host, which a new device restores from. A folder is
  the signed records kept under one key, and a host is a server that keeps folders.

| From | Mixed with | Gives |
|---|---|---|
| the seed | HKDF, `forest/v1/seed` | the seed scalar, the one number the proofs take |
| the seed scalar | Poseidon, the profile prefix and the label's scope | a main key: one profile's name and signature |
| the seed | HKDF, `forest/v1/profile/<label>` | that profile's secret, which its inbox key comes from |
| a profile's secret | HKDF, `forest/v1/inbox` | that profile's inbox key, which opens what is encrypted to it |
| the seed | HKDF, `forest/v1/pay/<type>/<label>` | that profile's pay key for one address type, `solana` or `evm`, and its address |
| the seed scalar | Poseidon, the verifier prefix and the verifier's name hash | the person's secret for one verifier, which their stamp number and tags come from |
| the seed scalar | Poseidon, the vault prefix | the vault key: the main key of the person's vault |
| the seed | HKDF, `forest/v1/vault` | the vault's secret, which its inbox key comes from |

The texts and prefixes are part of every key, so they never change: a new one would give everyone
new keys. That is why two of them still say issuer, a verifier's old name.

### Day to day

By default, nothing mixed from the seed is stored, only the seed. When the person acts, the app
mixes the one key that action needs (a profile's main key from its label, its inbox key, the seed
scalar for a proof), uses it, and drops it; JavaScript cannot promise its bytes are erased
(Limits). The vault is not used day to day: a new device reads it to learn which profiles exist,
and the app writes it when what it holds changes, such as a new profile
([records](../records/README.md#the-vault)).

### The seed scalar

The seed scalar is the number the proofs take from the seed. Inside a proof, it ties a person's
stamps and profiles together, and only Poseidon mixes of it ever leave, so nothing public links
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

- There is one per label. A label is any text, taken exactly as given, as UTF-8, so
  `Tutoring/Seller` and `tutoring/seller` are two profiles. Markets set the convention,
  `<market>/<role>`, such as `tutoring/seller`
  ([foundationforest/markets](https://github.com/foundationforest/markets)).
- Its scalar is the lowest 250 bits of `Poseidon(profile prefix, seed scalar, scope)`. Baby Jubjub's
  subgroup order `l` is above 2^250, so every 250-bit number is already a scalar, and the stamp
  proof derives the same key from the same seed scalar with nothing to reduce
  ([proofs/stamp](../proofs/stamp/README.md)).
- Its public key is the scalar times Baby Jubjub's `Base8`, the point circomlib and zk-kit use.
- Its address is the public key packed into 32 bytes (y little-endian, with x's sign in the top
  bit, as circomlib and zk-kit pack it), in base58 (the Bitcoin alphabet): 43 or 44 characters. An
  address in any other spelling, or naming a point outside the prime-order subgroup, is refused.

### Signatures

A main key signs with EdDSA-Poseidon on Baby Jubjub, the signature circomlib's
`EdDSAPoseidonVerifier` checks inside a proof, made from the scalar itself.

- The message is a field element, a number below BN254's scalar order.
- The nonce `r` is SHA-512 of `forest/v1/nonce`, the scalar and the message (each 32 bytes
  little-endian), read little-endian, mod `l`: the same message always gets the same signature,
  and no two messages share a nonce.
- `R8 = r · Base8`, `hm = Poseidon(R8x, R8y, Ax, Ay, message)`, and `S = r + 8 · hm · scalar mod
  l`. A signature holds when `S < l` and `S · Base8 = R8 + 8 · hm · A`, the equation zk-kit's
  `verifySignature` and circomlib's `EdDSAPoseidonVerifier` check. The key must be in the
  prime-order subgroup; R8 need not be checked for it, since the equation holds only when it is.
- Bytes are signed as one field element: SHA-256 of the bytes, read big-endian, shifted right one
  byte. Records, messages, pulls and blob requests ([records](../records/README.md)) and an index's
  roots ([proofs/reputation](../proofs/reputation/README.md)) are signed so, each over bytes of its
  own.
- A signature travels as 64 bytes, as zk-kit packs it: R8 packed as an address is, then S, 32
  bytes little-endian. Read back, R8 must be a point on the curve in its one spelling and S below
  `l`; anything else is refused.

### Inbox keys

A profile's inbox key opens what others encrypt to it: the messages in its inbox and its private
records ([records](../records/README.md)).

- It is mixed from the profile's secret, `hkdf(seed, "forest/v1/profile/<label>")`, by
  `forest/v1/inbox`, not from the main key's scalar, so no public number gives it. An inbox key
  gives no other profile, and no inbox key gives the seed.
- Its 32 bytes are used unchanged as an identity for age, a widely used encryption format, of
  age's post-quantum hybrid kind, `mlkem768x25519`: two keys at once, ML-KEM-768 and X25519, so
  what is encrypted to it stays closed unless both are broken. It is written `AGE-SECRET-KEY-PQ-1`,
  then bech32 of the bytes, in upper case; age expands it into the two private keys.
- Others encrypt to its public half, `encryptTo`, `age1pq1…`, which age computes from the identity.
  It is about 1,960 characters long. The profile publishes it; the address does not give it.
- The main key cannot do this job: EdDSA only signs, so nothing is ever encrypted to a main key.

### Pay keys

A profile's pay keys hold and move its money: one for each address type, `solana` and `evm`.
A main key, on Baby Jubjub, is no chain's account, so each profile has its main key and a payment
key of each type.

- Each is HKDF of the seed with `forest/v1/pay/<type>/<label>`, the label used exactly as given:
  one per type and label, unrelated to the main key, to the other type's and to every other
  profile's. The `solana` text is the one Forest has always mixed its Solana key with, so those
  addresses are as they were.
- `solana`: the 32 bytes are an ed25519 private key (RFC 8032), in the form Solana tooling takes
  for a keypair. Its address is the public key in base58.
- `evm`: the 32 bytes, read big-endian, are a secp256k1 private key; bytes that are no such key (0,
  or the curve's order or more, about a 2^-128 chance) are refused, never adjusted. Its address is
  the last 20 bytes of keccak256 of the uncompressed public key without its leading `04`, written in
  EIP-55's mixed-case checksum: that is its one spelling, and any other, all lower case included, is
  refused (`isEvmAddress`).
- The profile's `pay` is both addresses, `{ solana, evm }` (`payAddresses`).

### The verifier secret

A verifier is anyone who signs stamps to people's seeds
([proofs/stamp](../proofs/stamp/README.md#the-stamp-and-the-stamp-proof)). For each verifier, a
person has one secret: `Poseidon(verifier prefix, seed scalar, name hash)`.

- The name is the text the verifier publishes as its own, such as a domain, used exactly as given,
  as UTF-8. The secret comes from the name, not the verifier's key, so a verifier that changes its
  key changes no one's tags.
- Nothing is stored: the app mixes the secret again from the seed whenever it needs it.

### The stamp number

The stamp number is what a person gives a verifier: `Poseidon(verifier secret)`. The device sends it
to the verifier once, and the verifier signs it in the person's stamp. The verifier never learns the
secret, nor the seed scalar behind it.

### Tags

A tag is the number an index's tree knows one profile by, at one verifier:
`Poseidon(scope, verifier secret)`. The stamp proof shows it, and the reputation proof counts the
profiles whose tags are the person's ([proofs](../proofs/README.md)).

- The same person, verifier and label always give the same tag, and nobody without the secret can
  work it out.
- Tags for two labels, or for two verifiers, cannot be matched to each other.

### The vault key

The vault is one folder on a host, encrypted to the vault's own inbox key, holding what the seed
cannot recompute: which profiles exist, stamps, the person's permissions, and settings
([records](../records/README.md#the-vault)). Its keys are mixed from the seed, so a new device
finds the vault with the seed and one host's address.

- It is a main key with no label: its scalar is the lowest 250 bits of `Poseidon(vault prefix, seed
  scalar)`, its address is the vault folder's name, and it signs the vault's records as a main key
  does. Its mix has its own prefix and no scope, so no label gives it.
- Its inbox key is mixed from the vault's secret, `hkdf(seed, "forest/v1/vault")`, by
  `forest/v1/inbox` as a profile's is, and opens what the vault holds.
- Its address ties to no profile: one profile's keys say nothing about the vault's, and the vault's
  say nothing about any profile's.

### Service keys

A service key is the signing key of an index or a verifier: 32 random bytes the service makes for
itself, from no seed. No person's key is ever one.

- Its scalar is the 32 bytes made into a number by the seed scalar's steps 1 to 3 (zk-kit's
  `deriveSecretScalar`), as zk-kit makes an EdDSA-Poseidon key of 32 private bytes. It signs as a
  main key does, and its address is spelled as one is.
- An index signs its roots with one ([proofs/reputation](../proofs/reputation/README.md)), and a
  verifier's stamp key is made the same way ([proofs/stamp](../proofs/stamp/README.md)).

### Signers

A signer is a device the person owns that holds their seed, such as their phone or their laptop.
The seed lives only on signers, and no key is ever handed out: not a main key, not an inbox key,
and no key made for someone else.

Everyone else asks a signer:

- an AI app, through its connection: a relay carries what the AI asks to the signer, and the answer
  back. Anyone can run one; the main way is the connector, which AI apps call from their cloud.
- a person or a business, by a message to the person's inbox, signed by the main key of a profile
  of their own ([records](../records/README.md#inbox)).

The signer decides by the person's permissions, a list kept in their vault
([records](../records/README.md#permissions)). It never acts on a request no entry covers without
the person's yes; how it asks, a prompt or a message waiting in the inbox, is the app's. Whatever it
does, it signs with the profile's main key, so a host or a reader checks one key per profile.

A permission's `post` never covers a profile's profile record, its hosts record or the vault: a
signer always asks the person for those. The vault holds the permissions, so an AI allowed to post
there could raise its own limits; the profile record holds the pay addresses, which no reader can
check against the seed; and the hosts record says where the folder lives. An AI could change any of
them after reading an offer written to trick it.

### What an app that holds keys should know

The person decides what to do with their keys, and may expose or link them if they choose. This
is what an app that holds the seed, a signer, should know, and what ours does:

1. The seed stays on the person's own devices, behind each one's unlock. The main way, and the one
   the Forest app uses, is a passkey, the device's own unlock, so there is no password to keep; an
   OS keychain or a hardware key are others. The recipe is the same whichever is used.
2. The signer asks for the person's device unlock whenever the person acts with the seed: to sign
   with a main key or the vault key, or to make a proof. What others ask, it does only within the
   person's permissions, and it asks the person about the rest.
3. No key ever leaves a signer, to an app, a server, an AI or another person. What leaves is
   signatures, proofs, and what the person's permissions let others read.
4. An AI app asks through its connection, and a person or a business by a message signed by its
   own profile's main key; the signer acts on either only by the person's permissions.
5. Neither the AI app nor the connector ever receives the person's own profiles' addresses, keys
   or folders (hosts keep folders and indexes read addresses, by design). An AI asks in words; the
   signer picks the profile, signs and publishes straight to the host; answers carry no addresses.
6. Proofs are made on the signer, never delegated.
7. The app works with any host, and its host with any app.
8. The app that holds the seed is open source.
9. The app keeps a copy of every record it signs; a host may drop one, and the copy puts it back.
10. The app keeps the verifier's stamp as safely as a key, in the vault.

### Use it

Everything is exported from `src/index.ts`. Everything that mixes from the seed is async; what
mixes from the seed scalar is not.

| Function | Gives |
|---|---|
| `newSeed()` | A new seed: 32 random bytes |
| `exportWords(seed)`, `importWords(text)` | The seed spelled as words, and the seed back from them |
| `seedScalar(seed)` | The seed scalar |
| `mainKey(seed, label)` | The main key: `label`, `scope`, `scalar`, `publicKey`, `address`, and the profile's `secret` |
| `profileScalarOf(seedScalar, label)` | A main key's scalar, from the seed scalar |
| `inboxKey(secret)` | The inbox key, from a profile's `secret` or the vault's: age's `identity`, and `encryptTo`, what others encrypt to |
| `payKey(seed, label, type)`, `payAddresses(seed, label)`, `PAY_TYPES` | A pay key of one type: `label`, `type`, `privateKey`, `publicKey`, `address`; the profile's address of each type; and the types |
| `evmAddressOf(publicKey)`, `isEvmAddress(text)` | A secp256k1 key's EVM address, in EIP-55; and whether text is one, in that spelling |
| `verifierSecret(seed, name)` | The verifier's `name`, its `nameHash`, the person's `scalar` for it, and the `stampNumber` |
| `verifierScalarOf(seedScalar, name)`, `tagOf(verifierScalar, label)` | The verifier secret from the seed scalar, and a tag |
| `vaultKey(seed)`, `vaultScalarOf(seedScalar)` | The vault key: `scalar`, `publicKey`, `address`, `secret`; and its scalar |
| `serviceKey(secret)` | A service key from its 32 random bytes: `secret`, `scalar`, `publicKey`, `address` |
| `signWithScalar(scalar, message)`, `checkWithPublicKey(key or address, message, signature)` | A signature `{ R8, S }` on a field element, and its check |
| `signBytes(scalar, bytes)`, `checkBytes(key or address, bytes, signature)`, `bytesMessage(bytes)` | A signature over bytes, its check, and the field element it signs |
| `packSignature(signature)`, `unpackSignature(bytes)` | A signature's 64 bytes, and the signature back, or null |
| `publicKeyOf(scalar)`, `addressOf(publicKey)`, `pointOf(address)` | A public key, its address, and the key an address names |
| `packPoint(point)`, `unpackPoint(bytes)` | A point's 32 packed bytes, and the point back, or null |
| `scopeOf(label)`, `nameHashOf(name)`, `fieldHash(namespace, ...parts)`, `PREFIX` | Text as the proofs' numbers, and the three prefixes |
| `hkdf(ikm, info)`, `INFO` | The mixer and its info strings |

```
npm ci && npm run build   # at the root: every package; keys/ to dist/, for the packages that import it
cd keys
npm test        # the pinned vectors, and each value recomputed without the library
npm run check   # type-check
```

Node 22.18 or later runs the TypeScript directly.

### Test vectors

`test/vectors.json` pins, for the seed `00 01 … 1f`: its words; its seed scalar; the three prefixes;
the main keys for `tutoring/seller` and `tutoring/buyer`, each with its secret and inbox key, and
their pay keys of both types; for two verifiers, `issuer-a.example` and `issuer-b.example`, the name
hash, the person's secret, the stamp number and a tag for each label; the vault key, with its secret
and inbox key; one signature by the `tutoring/seller` main key; and a service key, from 32 bytes of
`0x2a`. `npm test` checks each value and recomputes it without the library: HKDF and keccak from
`@noble/hashes`, the seed scalar step by step without zk-kit, Baby Jubjub's points and signatures
from zk-kit (`@zk-kit/baby-jubjub`, `@zk-kit/eddsa-poseidon`), the address packed by hand, the
signature's equation, ed25519 from `@noble/curves`, secp256k1 from Node's own crypto with keccak256
and EIP-55 by hand, the hybrid key others encrypt to from `@noble/post-quantum`, age's bech32 by
hand, and an envelope encrypted and opened through age. The stamp proof's tests check the circuit
derives the same main key and tag ([proofs/stamp](../proofs/stamp/README.md)).

## Promises

- **The same seed gives the same keys,** in any app, on any device, every time.
- **Nothing ties two profiles together.** Each label is its own mix: one profile's main key,
  address, pay key or inbox key says nothing about another's.
- **Nothing ties two verifiers together.** Each verifier is its own mix, so the same person's stamp
  numbers for two verifiers are unrelated, and two verifiers comparing what they hold cannot match
  them.
- **No key gives the seed back.** Every mix is one way. A profile's secret gives its inbox key, and
  nothing else.
- **Nothing leaves the device.** The library talks to no network and stores nothing.

## Limits

- **It trusts the app that holds the seed** to keep it, and show it to no one else.
- **It trusts its pieces, used unchanged:** Web Crypto (HKDF-SHA256, and its random source for new
  seeds), `@noble/hashes` 2.4.0 (keccak256, SHA-256, SHA-512), `@noble/curves` 2.4.0 (ed25519,
  secp256k1, and the Edwards curve arithmetic Baby Jubjub runs on, with circomlib's numbers),
  `@scure/base` 2.4.0 (base58, bech32), `@scure/bip39` 2.4.0, `age-encryption` 0.3.1 (whose hybrid
  runs on `@noble/post-quantum`), `@zk-kit/eddsa-poseidon` 1.0.4 (`deriveSecretScalar`) and
  `poseidon-lite` 0.3.0.
- **A verifier's name is its own to keep unique.** Two verifiers under one name get the same stamp
  number from each person, so they can match their people.
- **No recovery.** Lose the seed, and every profile and every tag is gone. Nobody can reset
  them, because nobody else has them.
- **No rotation.** A profile's name is its key, so a leaked main key loses that profile for good
  (see the FAQ).
- **One profile per label per seed.** The same seed and label always give the same key.
- **Signatures are not post-quantum; envelopes are.**
- **No wiping of memory.** JavaScript cannot promise that bytes are erased; an app closes the
  page, the library cannot.
- **Tested in Node only,** though the library is written to run in a browser too.

## Who decides what

- **The standard:** the seed's 32 bytes, the recipe, its info strings and its prefixes.
- **An app, with the person:** how it makes, keeps and unlocks the seed, and backups.
- **A service:** nothing. No service holds a main key.

## FAQ

**What if the wrong app gets the seed?**
Then that app has everything the seed opens, and nothing takes it back:
- every profile: a main key is mixed from the seed and a label, and labels are public, so it can
  mix the main key of every profile and sign as it, and every pay key and move its money;
- every inbox key, so it can open the person's private records and messages;
- the seed scalar, so it can make stamp proofs for the person's profiles with their stamps, and
  reputation proofs from their scores;
- the vault, with their verifiers' stamps.

There is no rotation, so the only way out is a new seed and new profiles, moving the money first if
there is still time. An app that holds the seed is trusted with all of that.

**Why is a main key on Baby Jubjub, with pay keys beside it?**
So a proof can derive it. The stamp proof shows that a profile's key comes from the same seed as
a stamp a verifier signed, and the reputation proof that a profile's key comes from the same seed as
the profiles it counts: both work the key out from the seed scalar inside the proof. Baby Jubjub
is the curve a proof does that on cheaply; ed25519 inside a proof costs far more. Solana's accounts
are ed25519 and EVM chains' secp256k1, so the money sits under pay keys of their own, one for
each address type, mixed from the seed apart from the main key.

**Why are bytes signed as their SHA-256, and not their Poseidon?**
A record, a message or a pull is text of any length, and EdDSA-Poseidon signs one field element.
SHA-256 turns any bytes into 32, at native speed in every browser and in Node; Poseidon over long
text is slow in JavaScript, with no one standard way to feed it bytes. Shifted right one byte, the
32 bytes are a field element, as keccak256 of text already is in the recipe. No proof checks a
record's signature, so nothing asks for Poseidon there.

**Why two mixers, HKDF and Poseidon?** They work in different places. HKDF-SHA256 mixes on the
device, from the seed: it is a standard, built into every browser's Web Crypto, and well studied.
Inside a zero-knowledge proof, SHA-256 costs far more than Poseidon. So what a proof must work out
(the verifier secret, the stamp number, a tag, a main key) is Poseidon of the seed scalar, and what
no proof needs (the profiles' secrets, the pay keys, the vault's secret) is HKDF of the seed.
Neither is ours; both are used unchanged.

**What if a main key leaks?**
Whoever has it can sign records as the profile. It cannot reach the seed, the seed scalar, another
profile, the profile's pay key or its inbox key. There is no rotation, because the name is the
key, and nothing in Forest marks the profile as leaked: the person stops using it. The same seed
and label always give the leaked key, so with this seed, that label is gone for good.
