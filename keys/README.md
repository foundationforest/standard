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
  Every Poseidon mix of the seed takes the seed's number and a text's number, so no mix can give
  another's number.

Text enters Poseidon as a number: `keccak256` (the hash Ethereum uses) of its UTF-8 bytes, read
big-endian and shifted right one byte so it fits the proofs' numbers (`fieldHash`). The label or
the name is joined to its text with nothing between, no separator and no length, and hashed once. A
label's number is its **scope**, `keccak256("forest/profile/" ‖ label) >> 8`; a verifier's name's is
its **name hash**, `keccak256("forest/verifier/" ‖ name) >> 8`. The recipe is three texts:

| Text | Mixed with the seed by | Gives |
|---|---|---|
| `forest/profile/<label>` | Poseidon, the seed's number and the scope | a main key's signing half: one profile's name and signature |
| the same | HKDF of the seed | that profile's opening half, which opens what is locked to it |
| `forest/verifier/<name>` | Poseidon, the seed's number and the name hash | the person's stamp number at that verifier, what they give it |
| `forest/pay/<chain>/<label>` | HKDF of the seed | that profile's pay key on one chain, `solana` or `evm`, and its address |

The empty label gives the Profiles folder's keys, `forest/profile/` alone. The chain comes before
the label, so no label can spell another text.

### Day to day

By default, nothing mixed from the seed is stored, only the seed. When the person acts, the app
mixes the one key that action needs (a profile's main key from its label, its opening half, the
seed's number for a proof), uses it, and drops it; JavaScript cannot promise its bytes are erased
(Limits).

### The seed's number

The seed's number is the seed as the proofs take it: its 32 bytes read big-endian, mod the scalar
order of BN254, the curve the proofs are made on (`seedNumber`). Nothing else is done to it. Inside
a proof, it ties a person's stamps and profiles together, and only Poseidon mixes of it ever leave,
so nothing public links them.

- It is a proof's private input, and the seed is a handful of guesses from it (about five seeds
  share a number, 2^256 being about five times BN254's order), so a proof is made only on the
  device (What an app that holds keys should know).
- Nothing is stored: the app reads it from the seed whenever a proof needs it.

### Main keys

A main key is one profile: its signing half signs the profile's entries (the signed statements in
its folder), and its address is the profile's name.

- There is one per label. A label is any text, taken exactly as given, as UTF-8, so
  `Tutoring/Seller` and `tutoring/seller` are two profiles. Markets set the convention,
  `<market>/<role>`, such as `tutoring/seller`
  ([foundationforest/markets](https://github.com/foundationforest/markets)).
- Its scalar is the lowest 250 bits of `Poseidon(the seed's number, scope)`. Baby Jubjub's
  subgroup order `l` is above 2^250, so every 250-bit number is already a scalar, and both proofs
  derive the same key from the same seed with nothing to reduce ([proofs](../proofs/README.md)).
- Its public key is the scalar times Baby Jubjub's `Base8`, the point circomlib and zk-kit use.
- Its address is the public key packed into 32 bytes (y little-endian, with x's sign in the top bit,
  as circomlib and zk-kit pack it), in base58 (the Bitcoin alphabet): almost always 43 or 44
  characters. An address in any other spelling, or naming a point outside the prime-order subgroup,
  is refused.

### Signatures

A key signs with EdDSA-Poseidon on Baby Jubjub, the signature circomlib's `EdDSAPoseidonVerifier`
checks inside a proof, made from the scalar itself.

- The message is a field element: a number below the scalar order of BN254.
- The nonce `r` is SHA-512 of 64 bytes: the scalar and the message, each 32 bytes little-endian,
  and nothing else. The 64 bytes out are read little-endian, mod `l`: the same message always gets
  the same signature, and no two messages share a nonce.
- `R8 = r · Base8`, `hm = Poseidon(R8x, R8y, Ax, Ay, message)`, and `S = r + 8 · hm · scalar mod
  l`. A signature holds when `S < l` and `S · Base8 = R8 + 8 · hm · A`, the equation zk-kit's
  `verifySignature` and circomlib's `EdDSAPoseidonVerifier` check. The key must be in the
  prime-order subgroup; R8 need not be checked for it, since the equation holds only when it is.
- Signatures carry no words. A key signs the canonical JSON of what it signs, as one field element:
  SHA-256 of its UTF-8 bytes, read big-endian, shifted right one byte. Each signed thing says what
  it is by its own fields: an entry and a message ([folders](../folders/README.md)), and an index's
  root ([proofs](../proofs/README.md#the-tree-an-index-publishes)).
- A signature travels as 64 bytes, as zk-kit packs it: R8 packed as an address is, then S, 32
  bytes little-endian. Read back, R8 must be a point on the curve in its one spelling and S below
  `l`; anything else is refused.

### Opening halves

Every key's opening half opens the envelopes locked to it: a folder's locked entries and the
messages in its inbox ([folders](../folders/README.md)). Each is 32 secret bytes, used as they are.

- A main key's is HKDF of the seed with its profile's text, `forest/profile/<label>`, not the main
  key's scalar, so no public number gives it. A main key's opening half gives no other profile's,
  and no opening half gives the seed. An access key's is its last 32 random bytes.
- The 32 bytes are an identity for age, a widely used encryption format, of age's post-quantum
  hybrid kind, `mlkem768x25519`: two keys at once, ML-KEM-768 and X25519, so what is locked to it
  stays closed unless both are broken. It is written `AGE-SECRET-KEY-PQ-1`, then bech32 (a
  checksummed text spelling) of the bytes, in upper case; age expands it into the two private keys.
- Envelopes are locked to its open key, `openKey`, `age1pq1…`, which age computes from the
  identity. It is about 1,960 characters long. A profile publishes its main key's in its profile
  entry; the address does not give it.
- A signing half cannot do this job: EdDSA only signs, so nothing is ever locked to an address.

### The Profiles folder

The Profiles folder lists every profile the person made and every stamp they hold, each entry
locked to its own opening half ([folders](../folders/README.md#the-profiles-folder)).

- Its keys are the empty label's main key and opening half: the seed and `forest/profile/` alone,
  with no market and no stamp. No market's label is empty, so it is none of the person's profiles.
- Only the person's devices mix it, from the seed, so only they open the folder's entries.

### Access keys

An access key is a key a profile hands out: to an AI app, a service or another person. The
profile's entry lists each one it hands out, with what it can do there
([folders](../folders/README.md#access-keys)).

- It is two random secrets, 64 bytes, from no seed (`newAccessKey`): the first 32 sign, the last 32
  open. It is made to be handed out, so nothing in it comes from the seed: whoever holds it learns
  nothing of the seed or of any other key.
- Its signing half is made from the first 32 bytes as a service key is; its opening half is the
  last 32, as every one is. Nothing is derived from one half for the other. Whoever holds the 64
  bytes holds both halves (`accessKey`).

### Pay keys

A profile's pay keys hold and move its money: one for each chain, `solana` and `evm`. A main key, on
Baby Jubjub, is no chain's account, so each profile has its main key and a pay key on each chain.

- Each is HKDF of the seed with `forest/pay/<chain>/<label>`, the label used exactly as given: one
  per chain and label, unrelated to the main key, to the other chain's and to every other profile's.
- `solana`: the 32 bytes are an ed25519 private key (RFC 8032, the signatures Solana uses), in the
  form Solana tooling takes for a keypair. Its address is the public key in base58.
- `evm`: the 32 bytes, read big-endian, are a secp256k1 private key (the curve EVM chains use);
  bytes that are no such key (0, or the curve's order or more, about a 2^-128 chance) are refused,
  never adjusted. Its address is the last 20 bytes of keccak256 of the uncompressed public key
  without its leading `04`, written in EIP-55's mixed-case checksum: that is its one spelling, and
  any other, all lower case included, is refused (`isEvmAddress`).
- A profile entry's `pay` lists any of them, unsigned: the main key signs the profile entry that
  lists them ([folders](../folders/README.md#the-profile-entry)). `payAddresses` gives both,
  `{ solana, evm }`.

### The stamp number

A verifier is anyone who signs stamps to people's seeds
([proofs](../proofs/README.md#the-stamp-and-the-verification)). For each verifier, a person has one
stamp number: `Poseidon(the seed's number, name hash)`. The device sends it to the verifier once,
and the verifier signs it in the person's stamp. The verifier never learns the seed.

- The name is the text the verifier publishes as its own, such as a domain, used exactly as given,
  as UTF-8. The stamp number comes from the name, not the verifier's key, so a verifier that changes
  its key changes no one's stamp number.
- Nothing is stored: the app mixes it again from the seed whenever it needs it.

### Service keys

A service key is the signing key of an index or a verifier: 32 random bytes the service makes for
itself, from no seed. The signing half of an access key is made the same way.

- Its scalar is the lowest 250 bits of the 32 bytes read big-endian, as a main key's is the lowest
  250 bits of a Poseidon mix; bytes whose lowest 250 bits are 0 are no key. It signs as a main key
  does, and its address is spelled as one is.
- An index signs its roots with one ([proofs](../proofs/README.md#the-tree-an-index-publishes)), and
  a verifier signs its stamps with one ([proofs](../proofs/README.md#the-stamp-and-the-verification)).

### Use it

Everything is exported from `src/index.ts`. Everything that mixes with HKDF is async; what mixes
from the seed's number is not.

| Function | Gives |
|---|---|
| `newSeed()` | A new seed: 32 random bytes |
| `exportWords(seed)`, `importWords(text)` | The seed spelled as words, and the seed back from them |
| `seedNumber(seed)` | The seed's number |
| `mainKey(seed, label)` | The main key's signing half: `label`, `scope`, `scalar`, `publicKey`, `address`, and its opening `secret`; the empty label's is the Profiles folder's |
| `profileScalarOf(seedNumber, label)` | A main key's scalar, from the seed's number |
| `openingHalf(secret)` | A key's opening half, from its 32 secret bytes: age's `identity`, and its `openKey`, what envelopes are locked to |
| `newAccessKey()`, `accessKey(secret)` | A new access key, both halves: `secret` (its 64 bytes), `scalar`, `publicKey`, `address`, `identity`, `openKey`; and the one its 64 bytes give |
| `payKey(seed, label, chain)`, `payAddresses(seed, label)`, `PAY_CHAINS` | A pay key on one chain: `label`, `chain`, `privateKey`, `publicKey`, `address`; the profile's address on each chain; and the chains |
| `evmAddressOf(publicKey)`, `isEvmAddress(text)` | A secp256k1 key's EVM address, in EIP-55; and whether text is one, in that spelling |
| `stampNumberOf(seedNumber, name)` | The person's stamp number at the verifier with that name |
| `serviceKey(secret)` | A service key from its 32 random bytes: `secret`, `scalar`, `publicKey`, `address` |
| `signWithScalar(scalar, message)`, `checkWithPublicKey(key or address, message, signature)` | A signature `{ R8, S }` on a field element, and its check |
| `signBytes(scalar, bytes)`, `checkBytes(key or address, bytes, signature)`, `bytesMessage(bytes)` | A signature over bytes, its check, and the field element it signs |
| `packSignature(signature)`, `unpackSignature(bytes)` | A signature's 64 bytes, and the signature back, or null |
| `publicKeyOf(scalar)`, `addressOf(publicKey)`, `pointOf(address)` | A public key, its address, and the key an address names |
| `packPoint(point)`, `unpackPoint(bytes)` | A point's 32 packed bytes, and the point back, or null |
| `scopeOf(label)`, `nameHashOf(name)`, `fieldHash(text, ...parts)` | Text as the proofs' numbers |
| `hkdf(ikm, info)`, `TEXT` | The mixer and the three texts |

```
npm ci && npm run build   # at the root: every package; keys/ to dist/, for the packages that import it
cd keys
npm test        # the pinned vectors, and each but the words recomputed without the library
npm run check   # type-check
```

Node 22.18 or later runs the TypeScript directly.

### Test vectors

`test/vectors.json` pins, for the seed `00 01 … 1f`: its words; its number; the main keys for
`tutoring/seller`, `tutoring/buyer` and the empty label, the Profiles folder's, each with its text,
its scope, its Poseidon mix, its opening secret and its opening half; the pay keys of the first two
on both chains, each with its text; for two verifiers, `verifier-a.example` and
`verifier-b.example`, the text, the name hash and the stamp number; one signature by the
`tutoring/seller` main key; a service key, from 32 bytes of `0x2a`; and an access key, both halves,
from 32 bytes of `0x2b` then 32 of `0x2c`. `npm test` checks each value and, but for the words,
recomputes it without the library: HKDF and keccak from `@noble/hashes`, the seed's number by hand,
Baby Jubjub's points and signatures from zk-kit (`@zk-kit/baby-jubjub`, `@zk-kit/eddsa-poseidon`),
the address packed by hand, the signature's equation, its nonce byte by byte with Node's own
SHA-512, `fieldHash` byte by byte, ed25519 from `@noble/curves`, secp256k1 from Node's own crypto
with keccak256 and EIP-55 by hand, each open key from `@noble/post-quantum`, age's bech32 from
`@scure/base`, each signing half of random bytes by hand, and an envelope locked and opened through
age. The proofs' tests check both circuits derive the same main key ([proofs](../proofs/README.md)).

### What an app that holds keys should know

The person decides what to do with their keys. This is what an app that holds them should know:

1. The seed and the main keys stay on the person's own devices, behind each one's unlock. The main
   way is a passkey, the device's own unlock, so there is no password to keep; anyone can use an OS
   keychain or a hardware key instead. The recipe is the same whichever is used.
2. Access keys are made to be handed out. An AI app, a service or another person acts for a profile
   with an access key the profile lists, never with the seed or a main key.
3. Verifications and reputation proofs are made on the device, from the seed, never delegated.

## Promises

- **The same seed gives the same keys,** in any app, on any device, every time.
- **Nothing ties two profiles together.** Each label is its own mix: one profile's main key,
  address, pay key or opening half says nothing about another's.
- **Nothing ties two verifiers together.** Each verifier is its own mix, so the same person's stamp
  numbers for two verifiers are unrelated, and two verifiers comparing what they hold cannot match
  them, as long as no two share a name: two under one name get the same stamp number from each
  person.
- **No key gives the seed back.** Every mix is one way. A main key, an opening half, a stamp number
  or a pay key gives nothing of the seed, nor of any other key.
- **Nothing leaves the device.** The library talks to no network and stores nothing.

## Limits

- **It trusts the app that holds the seed** to keep it, and show it to no one else.
- **It trusts its pieces, used unchanged:** Web Crypto (HKDF-SHA256, and its random source for new
  seeds), `@noble/hashes` 2.4.0 (keccak256, SHA-256, SHA-512), `@noble/curves` 2.4.0 (ed25519,
  secp256k1, and the Edwards curve arithmetic Baby Jubjub runs on, with circomlib's numbers),
  `@scure/base` 2.4.0 (base58, bech32), `@scure/bip39` 2.4.0, `age-encryption` 0.3.1 (whose hybrid
  runs on `@noble/post-quantum`) and `poseidon-lite` 0.3.0.
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

- **The standard:** the seed's 32 bytes, the recipe and its three texts.
- **An app, with the person:** how it makes, keeps and unlocks the seed, and backups; which access
  keys it makes, and whom it hands them to.
- **A service:** nothing. No service holds a main key.

## FAQ

**What if the wrong app gets the seed?**
Then that app has everything the seed opens, and nothing takes it back:
- every profile: a main key is mixed from the seed and a label, and labels are public, so it can
  mix the main key of every profile and sign as it, and every pay key and move its money;
- every opening half, so it can open the person's locked entries and messages;
- the seed's number, so it can make verifications for the person's profiles with their stamps, and
  reputation proofs from their scores.

There is no rotation, so the only way out is a new seed and new profiles, moving the money first if
there is still time. An app that holds the seed is trusted with all of that.

**Why is a main key on Baby Jubjub, with pay keys beside it?**
So a proof can derive it. The verification shows that a profile's key comes from the same seed as
a stamp a verifier signed, and the reputation proof that a profile's key comes from the same seed as
the profiles it counts: both work the key out from the seed's number inside the proof. Baby Jubjub
is the curve a proof does that on cheaply; ed25519 inside a proof costs far more. Solana's accounts
are ed25519 and EVM chains' secp256k1, so the money sits under pay keys of their own, one on
each chain, mixed from the seed apart from the main key.

**Why are bytes signed as their SHA-256, and not their Poseidon?**
An entry or a message is text of any length, and EdDSA-Poseidon signs one field element.
SHA-256 turns any bytes into 32, at native speed in every browser and in Node; Poseidon over long
text is slow in JavaScript, with no one standard way to feed it bytes. Shifted right one byte, the
32 bytes are a field element, as keccak256 of text already is in the recipe. No proof checks an
entry's signature, so nothing asks for Poseidon there.

**Why two mixers, HKDF and Poseidon?** They work in different places. HKDF-SHA256 mixes on the
device, from the seed: it is a standard, built into every browser's Web Crypto, and well studied.
Inside a zero-knowledge proof, SHA-256 costs far more than Poseidon. So what a proof must work out
(the stamp number, a main key) is Poseidon of the seed's number, and what no proof needs (the
opening halves, the pay keys) is HKDF of the seed.
Neither is ours; both are used unchanged.

**What if a main key leaks?**
Whoever has it can sign entries as the profile. It cannot reach the seed, another profile, the
profile's pay key or its opening half. There is no rotation, because the name is the key, and
nothing in Forest marks the profile as leaked: the person stops using it. The same seed and label
always give the leaked key, so with this seed, that label is gone for good.
