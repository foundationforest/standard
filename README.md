# standard

Part of [Forest](https://github.com/foundationforest), open software for people to offer, pay and review each other through profiles they own. A person holds one secret seed on their device and gets one profile for each label they use, such as `tennis/seller`.

The standard is the only part of Forest everyone shares: the formats, recipes and checks every app, host, index and verifier must agree on, along with the libraries, circuits and escrow program that implement them.

- A **verifier** checks a person and signs a stamp to their seed: a person it stamped is verified.
- A **host** stores a profile's folder of signed records and its encrypted inbox.
- An **index** reads hosts and payment receipts, checks proofs, and scores profiles and offers.
- An **app** creates records and reads the network for the person. One that holds the person's seed, on a device they own, is a **signer**; an AI or another person acts for them by asking a signer, never with a key of their own.

One seed gives one profile per label; a verifier decides how many stamps each human gets; how many verifiers count is each index's.

Everything outside these rules lives in [markets](https://github.com/foundationforest/markets), [services](https://github.com/foundationforest/services) and [app](https://github.com/foundationforest/app), where anyone can run or propose their own copy.

## Why these parts

The standard holds formats (what bytes mean), recipes (how a number is derived) and checks (what a reader runs); meanings and choices live outside it. Every piece here is sorted by one test: what must two strangers' programs agree on for one profile, one deal and one reputation to work across the open internet?

Four things stay outside: what a stamp means is the reader's; what a record says is the market's; how a score is made is the index's; where a seed is kept is the app's.

- **Keys and proofs are fixed by math.** One seed and one label must always produce the same main key, and a zero-knowledge proof must show that a verifier signed a stamp to that seed without revealing the seed or linking the person's other profiles. Because the circuit derives the main key directly from the seed and label, one seed gives one valid main key per label. A second proof lets a person carry a score from their other profiles onto a new one without linking them.
- **Records and escrows are shared formats.** Records define how a folder is written, read and encrypted. Escrows hold money on chain when a deal needs payment locked in advance.

## The directories

A **label** is any text; markets set the convention, `<market>/<role>`, such as `plumbing/seller`, and each market defines its roles, its content paths and their bodies in [markets](https://github.com/foundationforest/markets). A **tag** is a number made from a person's seed for one label at one verifier, so an index's score tree can track the profile without linking it to others. Every profile has one **folder** kept on one or more hosts.

| Directory | What it is | What runs | Where |
|---|---|---|---|
| [`keys/`](keys/README.md) | The recipe that mixes every main key, pay address, inbox key and verifier secret from the person's seed | a library | on the person's device |
| [`proofs/`](proofs/README.md) | The zero-knowledge proofs a device makes and anyone can check: [`stamp/`](proofs/stamp/README.md) (proving a profile's key and tag come from a seed a verifier signed a stamp to) and [`reputation/`](proofs/reputation/README.md) (proving a score across hidden profiles from an index's tree) | circuits and client libraries | made on the device; checked by anyone in milliseconds |
| [`records/`](records/README.md) | How a profile speaks: versioned folder entries (`profile`, `hosts`, the market's content paths, and private records), all signed by its main key, the encrypted `inbox`, the blobs a folder holds (photos and videos its main key puts and deletes), and the reference host | a library and reference host | wherever an app, AI, host or index runs |
| [`escrows/`](escrows/README.md) | On-chain lockboxes that release money when a side gives it to the other, both sides agree, a chosen arbiter decides, or the schedule set at the start says so (one directory per chain; only [`solana/`](escrows/solana/README.md) has one) | an on-chain program and client library | on chain when a deal uses escrow |

## Who decides what

- **The standard** holds only what two strangers' programs must agree on to check keys, proofs, records and escrows.
- **A market** (in [markets](https://github.com/foundationforest/markets)) defines its roles, its content paths and their bodies, and may suggest an offer field that carries an escrow's terms.
- **A service** (verifier, host, index, fee payer) sets its own prices and choices. An index decides which verifiers it trusts, how many count, and how it weights evidence.
- **An app** chooses how it holds the seed and which services it uses by default, together with the person.
- **The person** decides which markets to enter, which AI, app or person may ask their signers to act for them, and for what, and when to carry a score across profiles.

## For builders

- **Check a profile.** Read the profile's record at `profile` from its folder on any host. It holds the profile's `market`, `role`, `inboxKey` (what others encrypt to), seed-derived `pay` addresses (`solana` and `evm`, one per address type) with `paySig`, each address signed by its own pay key so a profile cannot list an address that is not its own, and its `proofs` array. The array takes any circuit's proofs, and a reader skips the ones it does not know: `stamp` and `reputation` are ours, and anyone can add one. Check each `stamp` proof against the verifier's key to see which verifiers signed a stamp to the seed behind the profile.
- **Find a profile's folder.** A profile's address is the public half of its main key (`Baby Jubjub`). Ask any host you know for its records, and check its signed `hosts` record to see every host that mirrors the folder.
- **Act for a person.** Ask one of their signers, the devices that hold their seed: an AI app through its connection, a person or a business by a message signed by its own profile's main key. The signer acts by the profile's rules and signs with the profile's main key; no key is ever handed out (`keys/`, Signers).
- **Write offers and reviews.** Their paths and bodies are defined by the market the profile lives in ([markets](https://github.com/foundationforest/markets)); the standard names none of them. A photo or a video is a blob the folder holds, put and deleted by its keys; where a record points at one is the market's.

## Privacy

What Forest does:
- Nothing in a person's keys ties their profiles together. Each main key and each default pay address is mixed separately from the seed and label (`keys/`).
- A stamp proof shows which verifier signed the person a stamp, never who the person is, what the stamp holds, or which other profiles they hold (`proofs/stamp/`).
- Private records and inbox messages are encrypted to post-quantum `age` keys (`ML-KEM` hybrid) (`records/`).
- No blockchain is touched to create a seed, get a stamp, open a profile, post an offer, send a message or write a review. Only payments and escrows touch a chain.

What others can still see:
- Everything in a profile's public records (`profile`, `hosts` and the market's content paths) is open for any index or person to read.
- On-chain payments and escrow receipts are public on the payment chain. Moving money directly between two of your own profiles' `pay` addresses links them on chain.
- A host sees when a folder is written or read and the network address of the connection, unless a VPN or relay is used.
- The connector, a relay AI apps call from their cloud, holds no keys and sees what is asked; anyone can run their own. It sees each request in plain text and any token passed through it, so it can act as any connection it carries, within that connection's rules: that is why a rule has limits (`keys/`, Signers).
- A verifier sees the person's stamp number, a stable number for them at that verifier.

## Promises

- **Nothing in the standard needs the seed or a main key to leave the device.** `keys/` mixes every key from the seed on the device; everything else takes only what it mixes. What an app does with the seed is the app's (`keys/`, What an app that holds keys should know).
- **One seed, one profile per label.** The stamp circuit derives the main key inside the proof, making a second main key for the same seed and label mathematically invalid (`proofs/stamp/`).
- **Updates and deletes are just writes.** Every path holds its newest signed record; a record with a null body deletes the path (`records/`).
- **Nothing in the standard charges a fee.** There is no coin and no cut on deals.
- **Escrows have no admin key.** Once the program is on Solana's mainnet and can no longer change, nothing moves the money but a side giving, both agreeing, the arbiter, or the schedule; on devnet it can no longer be upgraded in place either, since nobody holds its upgrade authority, so a new version goes to a new address, as on mainnet (`escrows/`).

## Limits

- **The escrow runs on Solana's devnet,** so no real money moves through it (`escrows/`).
- **Both circuits' setups were made by one party** (`proofs/`).
- **No seed recovery.** Lose the seed and the profiles made from it are gone; nothing can give them back (`keys/`).
- **The connector can act as any connection it carries,** within that connection's rules: it sees each request in plain text and any token passed through it. Anyone can run their own (`keys/`, Signers).

## What it is built from

- **Keys, records and encryption:** Baby Jubjub EdDSA-Poseidon (main key, service key and stamp signatures), Ed25519 (Solana pay addresses), secp256k1 and keccak256 with EIP-55 (EVM pay addresses), RFC 8785 canonical JSON, and post-quantum `age` envelopes.
- **Proofs:** Circom, `circomlib` (Poseidon and Baby Jubjub), `zk-kit` and Semaphore's Lean Incremental Merkle Tree, Perpetual Powers of Tau, and `snarkjs` (Groth16).
- **Escrows:** Anchor and SPL Token on Solana (`escrows/solana/`).

## FAQ

**Who decides changes to the standard?**
The Open Forest Foundation checks changes in the open; anyone proposes by pull request. The escrow program cannot change once deployed to Solana's mainnet; a new version runs beside it.
