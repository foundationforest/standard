# standard

Part of [Forest](https://github.com/foundationforest), open software for people to offer, pay and review each other through profiles they own. A person holds one secret seed on their device and gets one profile for each label they use, such as `tennis/seller`.

The standard is the only part of Forest everyone shares: the rules and math every app, host, index and issuer must agree on, along with the libraries, circuits and escrow program that implement them.

- An **issuer** signs a note to a person's seed.
- A **host** stores a profile's folder of signed records and its sealed inbox.
- An **index** reads hosts and payment receipts, checks proofs, and scores profiles and offers.
- An **app** (or an AI acting through scoped access keys) creates records and reads the network for the person.

One seed gives one profile per label; an issuer decides how many notes each human gets; how many issuers count is each index's.

Everything outside these rules lives in [markets](https://github.com/foundationforest/markets), [services](https://github.com/foundationforest/services) and [app](https://github.com/foundationforest/app), where anyone can run or propose their own copy.

## Why these four

The standard holds formats (what bytes mean), recipes (how a number is derived) and checks (what a verifier runs); meanings and choices live outside it. Every piece here is sorted by one test: what must two strangers' programs agree on for one profile, one deal and one reputation to work across the open internet?

Four things stay outside: what a note means is the reader's; what a record says is the market's; how a score is made is the index's; where a seed is kept is the app's.

- **Keys and proofs are fixed by math.** One seed and one label must always produce the same main key, and a zero-knowledge proof must show that an issuer signed a note to that seed without revealing the seed or linking the person's other profiles. Because the circuit derives the main key directly from the seed and label, one seed gives one valid main key per label. A second proof lets a person carry a score from their other profiles onto a new one without linking them.
- **Records and escrows are shared formats.** Records define how a folder is written, read and sealed. Escrows hold money on chain when a deal needs payment locked in advance.

## The directories

A **label** is any text; markets set the convention, `<market>/<role>`, such as `plumbing/seller`, and each market defines its roles, its content paths and their bodies in [markets](https://github.com/foundationforest/markets). A **stamp** is a number made from a person's seed for one label at one issuer, so an index's score tree can track the profile without linking it to others. Every profile has one **folder** kept on one or more hosts; the **vault** is one more folder on a host, sealed to the vault's own inbox key, which only the person's seed gives, holding what the seed cannot recompute: which profiles exist, issuer notes and settings. A new device finds it with the seed and one host's address.

| Directory | What it is | What runs | Where |
|---|---|---|---|
| [`keys/`](keys/README.md) | The recipe that mixes every main key, payment address, inbox key and issuer secret from the person's seed | a library | on the person's device |
| [`proofs/`](proofs/README.md) | The zero-knowledge proofs a device makes and anyone can check: [`note/`](proofs/note/README.md) (proving a profile's key and stamp come from a seed an issuer signed a note to) and [`reputation/`](proofs/reputation/README.md) (proving a score across hidden profiles from an index's tree) | circuits and client libraries | made on the device; checked by anyone in milliseconds |
| [`records/`](records/README.md) | How a profile speaks: versioned folder entries (`profile`, `hosts`, `permissions`, the market's content paths, and private records), scoped `write` and `read` access keys for AI and apps, the sealed `inbox`, the `vault`, the blobs a folder holds (photos and videos its keys put and delete), and the reference host | a library and reference host | wherever an app, AI, host or index runs |
| [`escrows/`](escrows/README.md) | On-chain lockboxes that release money when a side gives it to the other, both sides agree, a chosen arbiter decides, or the schedule set at the start says so (one directory per chain; only [`solana/`](escrows/solana/README.md) has one) | an on-chain program and client library | on chain when a deal uses escrow |

## Who decides what

- **The standard** holds only what two strangers' programs must agree on to verify keys, proofs, records and escrows.
- **A market** (in [markets](https://github.com/foundationforest/markets)) defines its roles, its content paths and their bodies, and may suggest an offer field that carries an escrow's terms.
- **A service** (issuer, host, index, fee payer) sets its own prices and rules. An index decides which issuers it trusts, how many count, and how it weights evidence.
- **An app** chooses how it holds the seed and which services it uses by default, together with the person.
- **The person** decides which markets to enter, which AI or app gets scoped access keys, and when to carry a score across profiles.

## For builders

- **Verify a profile.** Read the profile's record at `profile` from its folder on any host. It holds the profile's `market`, `role`, `inboxKey` (what others seal to), seed-derived `pay` address, and its `proofs` array. The array takes any circuit's proofs, and a reader skips the ones it does not know: `note` and `reputation` are ours, and anyone can add one. Verify each `note` proof against the issuer's key to see which issuers signed a note to the seed behind the profile.
- **Find a profile's folder.** A profile's address is the public half of its main key (`Baby Jubjub`). Ask any host you know for its records, and check its signed `hosts` record to see every host that mirrors the folder.
- **Delegate to an AI.** The person's app writes scoped `write` and `read` keys into the folder's `permissions` record and hands the private halves to the AI. With a `write` key, the AI signs offers, reviews and outgoing messages without ever touching the person's seed or main key. With a `read` key, the AI pulls and opens the paths it was granted (such as `inbox`).
- **Write offers and reviews.** Their paths and bodies are defined by the market the profile lives in ([markets](https://github.com/foundationforest/markets)); the standard names none of them. A photo or a video is a blob the folder holds, put and deleted by its keys; where a record points at one is the market's.

## Privacy

What Forest does:
- Nothing in a person's keys ties their profiles together. Each main key and each default payment address is mixed separately from the seed and label (`keys/`).
- A note proof shows which issuer signed the person a note, never who the person is, what the note holds, or which other profiles they hold (`proofs/note/`).
- Private records and inbox messages are sealed to post-quantum `age` keys (`ML-KEM` hybrid) (`records/`).
- No blockchain is touched to create a seed, get an issuer note, open a profile, post an offer, send a message or write a review. Only payments and escrows touch a chain.

What others can still see:
- Everything in a profile's public records (`profile`, `hosts`, `permissions` and the market's content paths) is open for any index or person to read.
- On-chain payments and escrow receipts are public on the payment chain. Moving money directly between two of your own profiles' `pay` addresses links them on chain.
- A host sees when a folder is written or read and the network address of the connection, unless a VPN or relay is used.
- An issuer sees the person's note number, a stable number for them at that issuer.

## Promises

- **Nothing in the standard needs the seed or a main key to leave the device.** `keys/` mixes every key from the seed on the device; everything else takes only what it mixes. What an app does with the seed is the app's (`keys/`, What an app that holds keys should know).
- **One seed, one profile per label.** The note circuit derives the main key inside the proof, making a second main key for the same seed and label mathematically invalid (`proofs/note/`).
- **Updates and deletes are just writes.** Every path holds its newest signed record; a record with a null body deletes the path (`records/`).
- **Nothing in the standard charges a fee.** There is no coin and no cut on deals.
- **Escrows have no admin key.** Once the program is on Solana's mainnet and can no longer change, nothing moves the money but a side giving, both agreeing, the arbiter, or the schedule; on its devnet we can still upgrade it (`escrows/`).

## Limits

- **The escrow runs on Solana's devnet,** so no real money moves through it (`escrows/`).
- **Both circuits' setups were made by one party** (`proofs/`).
- **No seed recovery.** Lose the seed and the profiles made from it are gone; nothing can give them back (`keys/`).

## What it is built from

- **Keys, records and encryption:** Baby Jubjub EdDSA-Poseidon (main key, access key and note signatures), Ed25519 (Solana payment addresses), RFC 8785 canonical JSON, and post-quantum `age` envelopes.
- **Proofs:** Circom, `circomlib` (Poseidon and Baby Jubjub), `zk-kit` and Semaphore's Lean Incremental Merkle Tree, Perpetual Powers of Tau, and `snarkjs` (Groth16).
- **Escrows:** Anchor and SPL Token on Solana (`escrows/solana/`).

## FAQ

**Who decides changes to the standard?**
The Open Forest Foundation checks changes in the open; anyone proposes by pull request. The escrow program cannot change once deployed to Solana's mainnet; a new version runs beside it.
