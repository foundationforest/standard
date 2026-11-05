# keys

Part of [Forest's standard](../README.md).

## What it is

The recipe that makes every key from a person's seed, on their own device, and the access keys a
profile hands out, made from random bytes. Any app that follows it gets the same keys from the same
seed, so no one is tied to one app. A main key and an access key are each a pair: a signing key,
which signs and whose address names the whole key, and an encryption key, which opens the envelopes
locked to it. This README is the standard; the library in `src/` follows it, and
`test/vectors.json` pins its answers.

## How it works

### The seed

- 32 random bytes (`newSeed`). How an app makes, keeps and unlocks it is the app's: nothing here
  needs it to leave the device, or to be held longer than deriving a key takes.
- 24 words can spell it (`exportWords`, `importWords`): BIP39's words for the 32 bytes themselves,
  without BIP39's PBKDF2 step, which would hash the words into another seed.
- Whoever controls the app that holds the seed controls the seed. A web app's code arrives from its
  server on each visit; an installed app's does not.
- Nothing derived from the seed is stored: the app derives the one key an action needs, uses it,
  and drops it.

### The recipe

Two standard one-way functions, used unchanged:

- **HKDF-SHA256** (RFC 5869), for what no proof needs: an empty salt, a text's UTF-8 bytes as its
  info, 32 bytes out. Every browser's Web Crypto has it.
- **Poseidon** (circomlib's), for what a proof must work out: a hash that is cheap inside a
  zero-knowledge proof, where SHA-256 costs far more. Poseidon always takes the seed's number and a
  text's number, so nothing it derives gives another.

The **seed's number** is the seed as a proof takes it: its 32 bytes read big-endian, mod the scalar
order of BN254, the curve the proofs are made on (`seedNumber`). Inside a proof it ties a person's
stamps and profiles together, and only what Poseidon derives from it ever leaves. About five seeds
share each number, so a proof is made only on the device.

Text enters Poseidon as a number (`fieldHash`): keccak256 of its UTF-8 bytes, read big-endian,
shifted right one byte to fit. A label or a name is joined to its text with nothing between and
hashed once: a label's **scope** is `keccak256("forest/profile/" ‖ label) >> 8`, a verifier's
**name hash** `keccak256("forest/verifier/" ‖ name) >> 8`. The recipe is three texts:

| Text | Derived by | Gives |
|---|---|---|
| `forest/profile/<label>` | Poseidon, of the seed's number and the scope | the profile's main key |
| the same | HKDF, of the seed | the main key's encryption key |
| `forest/verifier/<name>` | Poseidon, of the seed's number and the name hash | the person's stamp number at that verifier |
| `forest/pay/<chain>/<label>` | HKDF, of the seed | the profile's pay key on `solana` or `evm` |

- **A label** is any text, used exactly as given, so `Tutoring/Seller` and `tutoring/seller` are two
  profiles; the main way is the markets' `<market>/<role>`
  ([markets](https://github.com/foundationforest/markets)). The chain comes before the label in a
  pay key's text, so no label can spell another text.
- **The empty label**, `forest/profile/` alone, gives the main key and encryption key of the
  Profiles folder, the locked list of every profile the person made and every stamp they hold
  ([folders](../folders/README.md#the-profiles-folder)). No market's label is empty, so it is none
  of the person's profiles, and only the person's devices derive it.
- **A verifier's name** is the text it publishes as its own, such as a domain, used exactly as
  given (`stampNumberOf`). The device sends its stamp number once, and the verifier signs it in the
  person's stamp without learning the seed
  ([proofs](../proofs/README.md#the-stamp-and-the-verification)); a verifier that changes its key
  changes no one's stamp number.

### Main keys

A main key is one profile: its address is the profile's name, and it signs the profile's entries.
It is on Baby Jubjub so that a proof can derive it from the seed's number cheaply, which ed25519
would not allow.

- Its scalar is the lowest 250 bits of `Poseidon(the seed's number, scope)`. Baby Jubjub's subgroup
  order `l` is above 2^250, so every 250-bit number is already a scalar, and both proofs derive the
  same key with nothing to reduce ([proofs](../proofs/README.md)).
- Its public key is the scalar times Baby Jubjub's `Base8`, the point circomlib and zk-kit use.
- Its address is the public key packed into 32 bytes (y little-endian, x's sign in the top bit, as
  circomlib and zk-kit pack it), in base58 (the Bitcoin alphabet), almost always 43 or 44
  characters. An address in any other spelling, or naming a point outside the prime-order subgroup,
  is refused.

### Signatures

Main keys, access keys and service keys sign from their scalar itself, with EdDSA-Poseidon on Baby
Jubjub, which circomlib's `EdDSAPoseidonVerifier` checks inside a proof.

- The message is one field element. Bytes are signed as their SHA-256, read big-endian, shifted
  right one byte (`signBytes`, `checkBytes`): fast on any bytes in every browser, and no proof
  checks an entry's signature. What a key signs is canonical JSON whose own fields say what it is,
  so signatures carry no words ([folders](../folders/README.md#entries)).
- The nonce `r` is SHA-512 of the scalar and the message, each 32 bytes little-endian, read
  little-endian mod `l`: a message always gets the same signature, and no two share a nonce.
- `R8 = r · Base8`, `hm = Poseidon(R8x, R8y, Ax, Ay, message)`, `S = r + 8 · hm · scalar mod l`. It
  holds when `S < l` and `S · Base8 = R8 + 8 · hm · A`, for a key in the prime-order subgroup; R8
  need not be checked for it, since the equation holds only when it is.
- It travels as 64 bytes, as zk-kit packs it: R8 packed as an address is, then S, little-endian. R8
  must read back as a point on the curve in its one spelling, and S below `l`.

### Encryption keys

- Each has a secret of 32 bytes, used as they are. A main key's is HKDF of the seed with its
  profile's text, not its scalar, so no public number gives it, and it gives no other key. An access
  key's is its last 32 random bytes.
- The bytes are an identity for age, a widely used encryption format, of its post-quantum hybrid
  kind `mlkem768x25519` (ML-KEM-768 and X25519 at once, so what is locked stays closed unless both
  are broken), written `AGE-SECRET-KEY-PQ-1` then bech32 of the bytes, in upper case
  (`openingHalf`).
- Envelopes are locked to its **public encryption key** (`openKey`), `age1pq1…`, which age computes
  from the identity, about 1,960 characters. A profile publishes its main key's in its profile
  entry; the address does not give it. Nothing is ever locked to an address: EdDSA only signs.

### Pay keys

Solana's keys are ed25519 and EVM chains' secp256k1, so a profile's money sits under a pay key on
each chain: HKDF of the seed with `forest/pay/<chain>/<label>`, unrelated to the main key and to
every other pay key (`payKey`, `payAddresses`).

- `solana`: the 32 bytes are an ed25519 private key (RFC 8032), in the form Solana tooling takes for
  a keypair; its address is the public key in base58.
- `evm`: the 32 bytes, read big-endian, are a secp256k1 private key; bytes that are none (0, or the
  curve's order or more, about a 2^-128 chance) are refused, never adjusted. Its address is the
  last 20 bytes of keccak256 of the uncompressed public key without its leading `04`, in EIP-55's
  mixed-case checksum, its one spelling: any other, all lower case included, is refused
  (`isEvmAddress`).
- A profile entry's `pay` lists any of them ([folders](../folders/README.md#the-profile-entry)).

### Access keys

An access key is a key a profile hands out, to an AI app, a service or another person, and lists
in its profile entry with what it can do ([folders](../folders/README.md#access-keys)). It is 64
random bytes from no seed (`newAccessKey`, `accessKey`): the first 32 make its signing key, as a
service key's bytes do, and the last 32 its encryption key. Neither is derived from the other, and
whoever holds it learns nothing of the seed or of any other key.

### Service keys

A service key is an index's or a verifier's own signing key: 32 random bytes from no seed
(`serviceKey`). Its scalar is the lowest 250 bits of the bytes read big-endian; bytes whose lowest
250 bits are 0 are no key. It signs as a main key does, and its address is spelled the same way.
An index signs its roots with one, and a verifier its stamps ([proofs](../proofs/README.md)).

### What an app that holds keys should know

The person decides what to do with their keys. An app that holds them should know:

1. The seed and the main keys stay on the person's own devices, behind each one's unlock. The main
   way is a passkey, the device's own unlock, so there is no password to keep; anyone can use an OS
   keychain or a hardware key instead. The recipe is the same whichever is used. Anyone can open
   one seed from several passkeys: each further passkey's secret is a backup, a seed of its own
   whose Profiles folder holds the first, locked ([folders](../folders/README.md#the-seed-entry)).
   That copy of the seed sits on hosts, and whoever holds any one of the passkeys holds the seed.
2. Access keys are made to be handed out. An AI app, a service or another person acts for a profile
   with an access key the profile lists, never with the seed or a main key.
3. Verifications and reputation proofs are made on the device, from the seed, never delegated.

## Use it

```ts
import { checkBytes, mainKey, newAccessKey, newSeed, openingHalf, payAddresses, signBytes } from '@foundationforest/keys'

const seed = newSeed()                                  // 32 random bytes, kept by the app
const me = await mainKey(seed, 'tutoring/tutor')        // me.address is the profile's name
const { openKey } = await openingHalf(me.secret)        // what envelopes to it are locked to
const pay = await payAddresses(seed, 'tutoring/tutor')  // { solana, evm }
const ai = await newAccessKey()                         // random; ai.secret goes to whoever it is for
const bytes = new TextEncoder().encode('hello')
checkBytes(me.address, bytes, signBytes(me.scalar, bytes)) // true
```

What is derived with HKDF is async; what is derived from the seed's number alone is not.

## Run it

```
npm ci && npm run build   # at the root: every package, keys/ first
cd keys
npm run check             # type-check
npm test                  # Node 22.18 or later
```

`test/` checks every value in `test/vectors.json`, for the seed `00 01 … 1f`, and recomputes all
but the words without the library.

## Promises

- **The same seed gives the same keys,** in any app, on any device, every time.
- **Nothing ties two profiles together.** Each profile's keys are derived with its own label's
  text: one profile's main key, address, pay key or encryption key says nothing about another's.
- **Nothing ties two verifiers together.** Each stamp number is derived with its verifier's own
  name, so a person's stamp numbers at two verifiers are unrelated, and two verifiers comparing what
  they hold cannot match them, as long as no two share a name: two under one name get the same
  stamp number from each person.
- **No key gives the seed back.** HKDF and Poseidon are both one way: a main key, an encryption key,
  a stamp number or a pay key gives nothing of the seed, nor of any other key.
- **Nothing leaves the device.** The library talks to no network and stores nothing.

## Limits

- It trusts the app that holds the seed to keep it, and show it to no one else.
- It trusts its pieces, used unchanged: Web Crypto (HKDF-SHA256, and its random source),
  `@noble/hashes` 2.4.0, `@noble/curves` 2.4.0 (ed25519, secp256k1, and the Edwards arithmetic
  Baby Jubjub runs on), `@scure/base` 2.4.0, `@scure/bip39` 2.4.0, `age-encryption` 0.3.1 (on
  `@noble/post-quantum`) and `poseidon-lite` 0.3.0.
- No recovery: lose the seed, and every profile is gone; nobody else has them to reset.
- No rotation: a profile's name is its key, so a leaked main key loses that profile for good,
  though it reaches no other key.
- One profile per label per seed: the same seed and label always give the same key.
- Signatures are not post-quantum; envelopes are.
- No wiping of memory: JavaScript cannot promise bytes are erased; an app closes the page, the
  library cannot.
- Money moved between two of a person's own profiles' pay addresses links them on chain.
- Tested in Node only, though written to run in a browser too.

## FAQ

**What if the wrong app gets the seed?**
It has everything the seed opens, and nothing takes it back: every profile's main key (labels are
public) and pay key, so it signs as each and moves its money; every encryption key, so it opens
the person's locked entries and messages; and the seed's number, so it makes proofs with their stamps
and scores. The only way out is a new seed and new profiles, moving the money first if there is
still time.
