# keys

Part of Forest's standard: [the top README](../README.md).

## What it is

A person's keys in Forest: one seed, 32 random bytes, and the recipe that mixes every other key
from it, on the person's own device. Any app that follows this page gets the same keys from the
same seed, so a person is never tied to one app.

Every key is a pair: a signing half, which signs and whose address names the key, and an opening
half, which opens the envelopes locked to it. Access keys are the one kind of key not mixed from the
seed: they are random bytes, made to be handed out.

This README is the standard: the seed and the recipe are fixed. The library in `src/` follows it,
and `test/vectors.json` pins its answers.

## How it works

### The seed

- The seed is 32 random bytes.
- How an app makes, keeps and unlocks it is the app's. Nothing in the standard needs it to leave
  the device, or to be held longer than mixing keys from it takes.
- A seed can be spelled as 24 words, for an app that wants them (`exportWords`, `importWords`):
  the words of BIP39, the standard wallets spell a backup in, for the 32 bytes themselves, without
  BIP39's PBKDF2 step, which would hash the words into another seed.
- Whoever controls the app that holds the seed controls the seed, since the app can do whatever the
  seed can. A web app's code arrives from its server on each visit; an installed app's does not.

### The recipe

The recipe uses words from the rest of the standard:

- **profile:** one of the person's identities, one for each label, a free text saying what the
  profile is for;
- **folder:** the signed entries a profile keeps on hosts ([folders](../folders/README.md));
- **stamp:** what a verifier, anyone who signs stamps, signs to a person's seed.

Two mixers, each a standard one-way mix:

- **HKDF-SHA256** (RFC 5869), on the device: an empty salt, a text's UTF-8 bytes as its info, 32
  bytes out. Only the text changes.
- **Poseidon** (circomlib's, the circuit library the proofs use), a hash made to be cheap inside a
  zero-knowledge proof (a proof that something is true of a secret without showing the secret).
  Every Poseidon mix starts with a fixed prefix, so no mix can give another's number.

Text enters Poseidon as a number: `keccak256` (the hash Ethereum uses) of its UTF-8 bytes, read
big-endian and shifted right one byte so it fits the proofs' numbers (`fieldHash`). Text in parts, a
namespace then a label, is joined with nothing between the parts, no separator and no length, and
hashed once: text as UTF-8, bytes as they are. A label's number is its **scope**,
`keccak256("forest/v1/label/" ‖ label) >> 8`; a verifier's name's is its **name hash**,
`keccak256("forest/v1/issuer/" ‖ name) >> 8`; the two prefixes are `keccak256` of `forest/v1/issuer`
and `forest/v1/profile`, `>> 8`. The stamp's own prefix, which a verifier signs under, is in
[proofs/verification](../proofs/verification/README.md#the-stamp-and-the-verification).

| From | Mixed with | Gives |
|---|---|---|
| the seed | HKDF, `forest/v1/seed` | the seed scalar, the one number the proofs take |
| the seed scalar | Poseidon, the profile prefix and the label's scope | a main key's signing half: one profile's name and signature |
| the seed | HKDF, `forest/v1/profile/<label>` | that profile's secret, which its main key's opening half comes from |
| a key's secret | HKDF, `forest/v1/inbox` | that key's opening half, which opens what is locked to it |
| the seed | HKDF, `forest/v1/profiles` | the Profiles folder key's secret, which both its halves come from |
| the seed | HKDF, `forest/v1/pay/<type>/<label>` | that profile's pay key for one address type, `solana` or `evm`, and its address |
| the seed scalar | Poseidon, the verifier prefix and the verifier's name hash | the person's secret for one verifier, which their stamp number (what they give the verifier) comes from |

The texts and prefixes are part of every key, so they never change: a new one would give everyone
new keys. That is why two of them still say issuer, a verifier's old name, and one says inbox, the
word the recipe used before every key had an opening half.

### Day to day

By default, nothing mixed from the seed is stored, only the seed. When the person acts, the app
mixes the one key that action needs (a profile's main key from its label, its opening half, the
seed scalar for a proof), uses it, and drops it; JavaScript cannot promise its bytes are erased
(Limits).

### The seed scalar

The seed scalar is the number the proofs take from the seed. Inside a proof, it ties a person's
stamps and profiles together, and only Poseidon mixes of it ever leave, so nothing public links
them.

- It is HKDF of the seed with `forest/v1/seed`, made into a number the way Semaphore v4, a
  zero-knowledge identity library, made its secret scalar (zk-kit's `deriveSecretScalar`,
  `@zk-kit/eddsa-poseidon` 1.0.4), restated here only so it can be checked:
  1. `h` = the first 32 bytes of BLAKE-512 of the 32 bytes.
  2. Prune: `h[0] &= 0xf8; h[31] &= 0x7f; h[31] |= 0x40`.
  3. The scalar = (`h` read little-endian, shifted right 3) mod `l`, the subgroup order of Baby
     Jubjub, the curve the proofs' keys are on.
- Nothing is stored: the app mixes it again from the seed whenever a proof needs it.

### Main keys

A main key is one profile: its signing half signs the profile's entries (the signed statements in
its folder), and its address is the profile's name.

- There is one per label. A label is any text, taken exactly as given, as UTF-8, so
  `Tutoring/Seller` and `tutoring/seller` are two profiles. Markets set the convention,
  `<market>/<role>`, such as `tutoring/seller`
  ([foundationforest/markets](https://github.com/foundationforest/markets)).
- Its scalar is the lowest 250 bits of `Poseidon(profile prefix, seed scalar, scope)`. Baby Jubjub's
  subgroup order `l` is above 2^250, so every 250-bit number is already a scalar, and both proofs
  derive the same key from the same seed scalar with nothing to reduce
  ([proofs](../proofs/README.md)).
- Its public key is the scalar times Baby Jubjub's `Base8`, the point circomlib and zk-kit use.
- Its address is the public key packed into 32 bytes (y little-endian, with x's sign in the top bit,
  as circomlib and zk-kit pack it), in base58 (the Bitcoin alphabet): almost always 43 or 44
  characters. An address in any other spelling, or naming a point outside the prime-order subgroup,
  is refused.

### Signatures

A main key signs with EdDSA-Poseidon on Baby Jubjub, the signature circomlib's
`EdDSAPoseidonVerifier` checks inside a proof, made from the scalar itself.

- The message is a field element: a number below the scalar order of BN254, the curve the proofs
  are made on.
- The nonce `r` is SHA-512 of 79 bytes: the 15 bytes of `forest/v1/nonce` in UTF-8, as they are
  (no `0xff`, no newline, no length), then the scalar and the message, each 32 bytes
  little-endian. The 64 bytes out are read little-endian, mod `l`: the same message always gets the
  same signature, and no two messages share a nonce.
- `R8 = r · Base8`, `hm = Poseidon(R8x, R8y, Ax, Ay, message)`, and `S = r + 8 · hm · scalar mod
  l`. A signature holds when `S < l` and `S · Base8 = R8 + 8 · hm · A`, the equation zk-kit's
  `verifySignature` and circomlib's `EdDSAPoseidonVerifier` check. The key must be in the
  prime-order subgroup; R8 need not be checked for it, since the equation holds only when it is.
- Bytes are signed as one field element: SHA-256 of the bytes, read big-endian, shifted right one
  byte. Entries, messages and inbox deletes ([folders](../folders/README.md)) and an index's roots
  ([proofs/reputation](../proofs/reputation/README.md)) are signed so, each over bytes of its own.
- A signature travels as 64 bytes, as zk-kit packs it: R8 packed as an address is, then S, 32
  bytes little-endian. Read back, R8 must be a point on the curve in its one spelling and S below
  `l`; anything else is refused.

### Opening halves

Every key's opening half opens the envelopes locked to it: a folder's locked entries and the
messages in its inbox ([folders](../folders/README.md)). One recipe makes every one, from the key's
32-byte secret.

- It is HKDF of the secret with `forest/v1/inbox`. A main key's secret is the profile's secret,
  `hkdf(seed, "forest/v1/profile/<label>")`, not the main key's scalar, so no public number gives
  it. A main key's opening half gives no other profile's, and no opening half gives the seed.
- Its 32 bytes are used unchanged as an identity for age, a widely used encryption format, of age's
  post-quantum hybrid kind, `mlkem768x25519`: two keys at once, ML-KEM-768 and X25519, so what is
  locked to it stays closed unless both are broken. It is written `AGE-SECRET-KEY-PQ-1`, then
  bech32 (a checksummed text spelling) of the bytes, in upper case; age expands it into the two
  private keys.
- Envelopes are locked to its open key, `openKey`, `age1pq1…`, which age computes from the
  identity. It is about 1,960 characters long. A profile publishes its main key's in its profile
  entry; the address does not give it.
- A signing half cannot do this job: EdDSA only signs, so nothing is ever locked to an address.

### The Profiles folder key

The Profiles folder key signs the person's Profiles folder, the one folder that lists every profile
they made and every stamp they hold, each entry locked to its own opening half
([folders](../folders/README.md#the-profiles-folder)).

- Its secret is HKDF of the seed with `forest/v1/profiles`: the seed alone, with no label, no
  market and no stamp. No label gives that text, since a label's text begins `forest/v1/profile/`.
- Its signing half is made from the secret as a service key is (Service keys); its opening half as
  every one is.
- Only the person's devices mix it, from the seed, so only they open the folder's entries.

### Access keys

An access key is a key a profile hands out: to an AI app, a service or another person. The
profile's entry lists each one it hands out, with what it can do there
([folders](../folders/README.md#access-keys)).

- It is 32 random bytes, from no seed (`newAccessKey`). It is made to be handed out, so nothing in
  it comes from the seed: whoever holds it learns nothing of the seed or of any other key.
- Its signing half is made from the 32 bytes as a service key is; its opening half as every one is.
  Whoever holds the 32 bytes holds both halves (`accessKey`).

### Pay keys

A profile's pay keys hold and move its money: one for each address type, `solana` and `evm`.
A main key, on Baby Jubjub, is no chain's account, so each profile has its main key and a payment
key of each type.

- Each is HKDF of the seed with `forest/v1/pay/<type>/<label>`, the label used exactly as given:
  one per type and label, unrelated to the main key, to the other type's and to every other
  profile's. The `solana` text is the one Forest mixed its pay key with while Solana was its only
  type, so those addresses are as they were.
- `solana`: the 32 bytes are an ed25519 private key (RFC 8032, the signatures Solana uses), in the
  form Solana tooling takes for a keypair. Its address is the public key in base58.
- `evm`: the 32 bytes, read big-endian, are a secp256k1 private key (the curve EVM chains use);
  bytes that are no such key (0, or the curve's order or more, about a 2^-128 chance) are refused,
  never adjusted. Its address is the last 20 bytes of keccak256 of the uncompressed public key
  without its leading `04`, written in EIP-55's mixed-case checksum: that is its one spelling, and
  any other, all lower case included, is refused (`isEvmAddress`).
- A profile entry's `pay` lists any of them, each signed in `paySig`; `payAddresses` gives both,
  `{ solana, evm }`.
- Each pay key signs the address of the profile it pays, for the profile entry's `paySig`
  (`signPay`, `checkPaySig`), over `0xff` ‖ UTF-8(`forest/v1/pay\n`) ‖ UTF-8(the profile's
  address), in base64url without padding. `solana`: an Ed25519 signature (RFC 8032), 64 bytes,
  checked strictly, with no ZIP-215 leniency. `evm`: secp256k1 over keccak256 of the bytes, 65
  bytes, r ‖ s ‖ the recovery id (0 to 3, not Ethereum's 27 or 28), checked by recovering the key
  and comparing its EIP-55 address; a high s is not refused, since only the main key writes its
  profile entry. A reader checks them, so a profile cannot list an address that is not its own
  ([folders](../folders/README.md#the-profile-entry)).

### The verifier secret

A verifier is anyone who signs stamps to people's seeds
([proofs/verification](../proofs/verification/README.md#the-stamp-and-the-verification)). For each
verifier, a person has one secret: `Poseidon(verifier prefix, seed scalar, name hash)`.

- The name is the text the verifier publishes as its own, such as a domain, used exactly as given,
  as UTF-8. The secret comes from the name, not the verifier's key, so a verifier that changes its
  key changes no one's stamp number.
- Nothing is stored: the app mixes the secret again from the seed whenever it needs it.

### The stamp number

The stamp number is what a person gives a verifier: `Poseidon(verifier secret)`. The device sends it
to the verifier once, and the verifier signs it in the person's stamp. The verifier never learns the
secret, nor the seed scalar behind it.

### Service keys

A service key is the signing key of an index or a verifier: 32 random bytes the service makes for
itself, from no seed. The signing half of the Profiles folder key and of an access key is made the
same way.

- Its scalar is the 32 bytes made into a number by the seed scalar's steps 1 to 3 (zk-kit's
  `deriveSecretScalar`), as zk-kit makes an EdDSA-Poseidon key of 32 private bytes. It signs as a
  main key does, and its address is spelled as one is.
- An index signs its roots with one ([proofs/reputation](../proofs/reputation/README.md)), and a
  verifier's stamp key is made the same way
  ([proofs/verification](../proofs/verification/README.md)).

### Use it

Everything is exported from `src/index.ts`. Everything that mixes from the seed is async; what
mixes from the seed scalar is not.

| Function | Gives |
|---|---|
| `newSeed()` | A new seed: 32 random bytes |
| `exportWords(seed)`, `importWords(text)` | The seed spelled as words, and the seed back from them |
| `seedScalar(seed)` | The seed scalar |
| `mainKey(seed, label)` | The main key's signing half: `label`, `scope`, `scalar`, `publicKey`, `address`, and the profile's `secret` |
| `profileScalarOf(seedScalar, label)` | A main key's scalar, from the seed scalar |
| `openingHalf(secret)` | A key's opening half, from its `secret`: age's `identity`, and its `openKey`, what envelopes are locked to |
| `profilesKey(seed)` | The Profiles folder key, both halves: `secret`, `scalar`, `publicKey`, `address`, `identity`, `openKey` |
| `newAccessKey()`, `accessKey(secret)` | A new access key, both halves, as `profilesKey` gives them; and the one its 32 bytes give |
| `payKey(seed, label, type)`, `payAddresses(seed, label)`, `PAY_TYPES` | A pay key of one type: `label`, `type`, `privateKey`, `publicKey`, `address`; the profile's address of each type; and the types |
| `evmAddressOf(publicKey)`, `isEvmAddress(text)` | A secp256k1 key's EVM address, in EIP-55; and whether text is one, in that spelling |
| `signPay(payKey, profileAddress)`, `checkPaySig(type, payAddress, profileAddress, sig)` | A pay key's signature over its profile's address, for `paySig`; and whether one holds |
| `verifierSecret(seed, name)` | The verifier's `name`, its `nameHash`, the person's `scalar` for it, and the `stampNumber` |
| `verifierScalarOf(seedScalar, name)` | The verifier secret from the seed scalar |
| `serviceKey(secret)` | A service key from its 32 random bytes: `secret`, `scalar`, `publicKey`, `address` |
| `signWithScalar(scalar, message)`, `checkWithPublicKey(key or address, message, signature)` | A signature `{ R8, S }` on a field element, and its check |
| `signBytes(scalar, bytes)`, `checkBytes(key or address, bytes, signature)`, `bytesMessage(bytes)` | A signature over bytes, its check, and the field element it signs |
| `packSignature(signature)`, `unpackSignature(bytes)` | A signature's 64 bytes, and the signature back, or null |
| `publicKeyOf(scalar)`, `addressOf(publicKey)`, `pointOf(address)` | A public key, its address, and the key an address names |
| `packPoint(point)`, `unpackPoint(bytes)` | A point's 32 packed bytes, and the point back, or null |
| `scopeOf(label)`, `nameHashOf(name)`, `fieldHash(namespace, ...parts)`, `PREFIX` | Text as the proofs' numbers, and the two prefixes |
| `hkdf(ikm, info)`, `INFO` | The mixer and its info strings |

```
npm ci && npm run build   # at the root: every package; keys/ to dist/, for the packages that import it
cd keys
npm test        # the pinned vectors, and each but the words recomputed without the library
npm run check   # type-check
```

Node 22.18 or later runs the TypeScript directly.

### Test vectors

`test/vectors.json` pins, for the seed `00 01 … 1f`: its words; its seed scalar; the two prefixes;
the main keys for `tutoring/seller` and `tutoring/buyer`, each with its secret and its opening half,
and their pay keys of both types, each with its signature over its profile's address; the Profiles
folder key, both halves; for two verifiers, `issuer-a.example` and `issuer-b.example`, the name
hash, the person's secret and the stamp number; one signature by the `tutoring/seller` main key; a
service key, from 32 bytes of `0x2a`; and an access key, both halves, from 32 bytes of `0x2b`. `npm
test` checks each value and, but for the words, recomputes it without the library: HKDF and keccak
from `@noble/hashes`, the seed scalar step by step without zk-kit's `deriveSecretScalar`, Baby
Jubjub's points and signatures from zk-kit (`@zk-kit/baby-jubjub`, `@zk-kit/eddsa-poseidon`), the
address packed by hand, the signature's equation, its nonce byte by byte with Node's own SHA-512,
`fieldHash` byte by byte, ed25519 from `@noble/curves` and each Solana pay signature with Node's own
crypto, secp256k1 from Node's own crypto with keccak256 and EIP-55 by hand and each EVM pay
signature's key recovered by hand, each open key from `@noble/post-quantum`, age's bech32 from
`@scure/base`, each signing half made of 32 bytes from zk-kit's `derivePublicKey`, and an envelope
locked and opened through age. The verification's tests check the circuit derives the same main key
([proofs/verification](../proofs/verification/README.md)).

### What an app that holds keys should know

The person decides what to do with their keys. This is what an app that holds them should know:

1. The seed and the main keys stay on the person's own devices, behind each one's unlock. The main
   way is a passkey, the device's own unlock, so there is no password to keep; anyone can use an OS
   keychain or a hardware key instead. The recipe is the same whichever is used.
2. Access keys are made to be handed out. An AI app, a service or another person acts for a profile
   with an access key the profile lists, never with the seed or a main key.
3. Verifications and reputation proofs are made on the device, from the seed scalar, never
   delegated.

## Promises

- **The same seed gives the same keys,** in any app, on any device, every time.
- **Nothing ties two profiles together.** Each label is its own mix: one profile's main key,
  address, pay key or opening half says nothing about another's.
- **Nothing ties two verifiers together.** Each verifier is its own mix, so the same person's stamp
  numbers for two verifiers are unrelated, and two verifiers comparing what they hold cannot match
  them, as long as no two share a name: two under one name get the same stamp number from each
  person.
- **No key gives the seed back.** Every mix is one way. A profile's secret gives its main key's
  opening half and its folder's keyed ids ([folders](../folders/README.md#keyed-paths)), and nothing
  else.
- **Nothing leaves the device.** The library talks to no network and stores nothing.

## Limits

- **It trusts the app that holds the seed** to keep it, and show it to no one else.
- **It trusts its pieces, used unchanged:** Web Crypto (HKDF-SHA256, and its random source for new
  seeds), `@noble/hashes` 2.4.0 (keccak256, SHA-256, SHA-512), `@noble/curves` 2.4.0 (ed25519,
  secp256k1, and the Edwards curve arithmetic Baby Jubjub runs on, with circomlib's numbers),
  `@scure/base` 2.4.0 (base58, bech32), `@scure/bip39` 2.4.0, `age-encryption` 0.3.1 (whose hybrid
  runs on `@noble/post-quantum`), `@zk-kit/eddsa-poseidon` 1.0.4 (`deriveSecretScalar`) and
  `poseidon-lite` 0.3.0.
- **No recovery.** Lose the seed, and every profile is gone. Nobody can reset them, because nobody
  else has them.
- **No rotation.** A profile's name is its key, so a leaked main key loses that profile for good
  (see the FAQ).
- **One profile per label per seed.** The same seed and label always give the same key.
- **Signatures are not post-quantum; envelopes are.**
- **No wiping of memory.** JavaScript cannot promise that bytes are erased; an app closes the
  page, the library cannot.
- **Tested in Node only,** though the library is written to run in a browser too.

## Who decides what

- **The standard:** the seed's 32 bytes, the recipe, its info strings and its prefixes.
- **An app, with the person:** how it makes, keeps and unlocks the seed, and backups; which access
  keys it makes, and whom it hands them to.
- **A service:** nothing. No service holds a main key.

## FAQ

**What if the wrong app gets the seed?**
Then that app has everything the seed opens, and nothing takes it back:
- every profile: a main key is mixed from the seed and a label, and labels are public, so it can
  mix the main key of every profile and sign as it, and every pay key and move its money;
- every opening half, so it can open the person's locked entries and messages;
- the seed scalar, so it can make verifications for the person's profiles with their stamps, and
  reputation proofs from their scores.

There is no rotation, so the only way out is a new seed and new profiles, moving the money first if
there is still time. An app that holds the seed is trusted with all of that.

**Why is a main key on Baby Jubjub, with pay keys beside it?**
So a proof can derive it. The verification shows that a profile's key comes from the same seed as
a stamp a verifier signed, and the reputation proof that a profile's key comes from the same seed as
the profiles it counts: both work the key out from the seed scalar inside the proof. Baby Jubjub
is the curve a proof does that on cheaply; ed25519 inside a proof costs far more. Solana's accounts
are ed25519 and EVM chains' secp256k1, so the money sits under pay keys of their own, one for
each address type, mixed from the seed apart from the main key.

**Why are bytes signed as their SHA-256, and not their Poseidon?**
An entry or a message is text of any length, and EdDSA-Poseidon signs one field element.
SHA-256 turns any bytes into 32, at native speed in every browser and in Node; Poseidon over long
text is slow in JavaScript, with no one standard way to feed it bytes. Shifted right one byte, the
32 bytes are a field element, as keccak256 of text already is in the recipe. No proof checks an
entry's signature, so nothing asks for Poseidon there.

**Why two mixers, HKDF and Poseidon?** They work in different places. HKDF-SHA256 mixes on the
device, from the seed: it is a standard, built into every browser's Web Crypto, and well studied.
Inside a zero-knowledge proof, SHA-256 costs far more than Poseidon. So what a proof must work out
(the verifier secret, the stamp number, a main key) is Poseidon of the seed scalar, and what
no proof needs (the profiles' secrets, the opening halves, the Profiles folder key, the pay keys) is
HKDF of the seed or of a key's secret.
Neither is ours; both are used unchanged.

**What if a main key leaks?**
Whoever has it can sign entries as the profile. It cannot reach the seed, the seed scalar, another
profile, the profile's pay key or its opening half. There is no rotation, because the name is the
key, and nothing in Forest marks the profile as leaked: the person stops using it. The same seed
and label always give the leaked key, so with this seed, that label is gone for good.
