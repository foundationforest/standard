# standard

Part of [Forest](https://github.com/foundationforest), open software for people to offer, pay and review each other through profiles they own. A person holds one secret seed on their device and gets one profile for each market and role they take part in, labelled `<market>/<role>`, such as `tennis/seller`.

The standard is the only part of Forest everyone shares: the rules and math every app, host, index and issuer must agree on, along with the libraries, circuits and escrow programs that implement them.

- An **issuer** checks once that a real, single human stands behind a seed and signs them a note.
- A **host** stores a profile's folder of signed records and its encrypted inbox.
- An **index** reads hosts and payment receipts, checks proofs, and scores profiles and offers.
- An **app** (or an AI acting through scoped access keys) creates records and reads the network for the person.

Everything outside these rules lives in [markets](https://github.com/foundationforest/markets), [services](https://github.com/foundationforest/services) and [app](https://github.com/foundationforest/app), where anyone can run or propose their own copy.

## Why these four

Every piece here is sorted by one test: what must two strangers' programs agree on for one profile, one deal and one reputation to work across the open internet?

- **Keys and proofs are fixed by math.** One seed and one label (`<market>/<role>`) must always produce the same profile key, and a zero-knowledge proof must show that an issuer checked the human behind that seed without revealing the seed or linking the person's other profiles. Because the circuit derives the profile key directly from the seed and label, one human can only ever produce one valid profile key per label. No blockchain registry is needed. A second proof lets a person carry a score from their other profiles onto a new one without linking them.
- **Records and escrows are shared formats.** Records define how a folder is written, read and encrypted. Escrows hold money on chain when a deal needs payment locked in advance.

## The folders

A **label** is `<market>/<role>`, such as `plumbing/seller`; the market defines its roles, offer fields and review fields in [markets](https://github.com/foundationforest/markets). A **stamp** is a number made from a person's seed for one label at one issuer, so an index's score tree can track the profile without linking it to others. Every profile has one **folder** kept on one or more hosts; the **vault** is one more folder on a host, encrypted to the vault's own inbox key, which only the person's seed gives, holding what the seed cannot recompute: which `<market>/<role>` profiles exist, issuer notes and settings.

| Folder | What it is | What runs | Where |
|---|---|---|---|
| [`keys/`](keys/README.md) | The recipe that mixes every profile key, payment address, encryption key and issuer secret from the person's seed | a library | on the person's device |
| [`proofs/`](proofs/README.md) | The zero-knowledge proofs a device makes and anyone can check: [`human/`](proofs/human/README.md) (proving a profile's key and stamp come from an issuer-checked seed) and [`reputation/`](proofs/reputation/README.md) (proving a score across hidden profiles from an index's tree) | circuits and client libraries | made on the device; checked by anyone in milliseconds |
| [`records/`](records/README.md) | How a profile speaks: versioned folder entries (`card`, `hosts`, `permissions`, `offer`, `review`, `private`), scoped `write` and `read` access keys for AI and apps, the encrypted `inbox`, the `vault`, blobs, and the reference host | a library and reference host | wherever an app, AI, host or index runs |
| [`escrows/`](escrows/README.md) | On-chain lockboxes that release money when the buyer approves, both sides agree, a chosen arbiter decides, or a timer expires ([`solana/`](escrows/solana/README.md) today, other chains later) | an on-chain program and client library | on chain when a deal uses escrow |

Each folder's README follows the same structure: What it is, How it works, Promises, Limits, Who decides what, FAQ.

## Who decides what

- **The standard** holds only what two strangers' programs must agree on to verify keys, proofs, records and escrows.
- **A market** (in [markets](https://github.com/foundationforest/markets)) defines its roles, its offers' fields and its reviews' fields, and may suggest an offer field that carries an escrow's terms.
- **A service** (issuer, host, index, fee payer) sets its own prices and policies. An index decides which issuers it trusts and how it weights evidence.
- **An app** chooses how it holds the seed and which services it uses by default, together with the person.
- **The person** decides which markets to enter, which AI or app gets scoped access keys, and when to link reputation across profiles.

## For builders

- **Verify a profile.** Read the profile's `card` record from its folder on any host. The `card` holds the profile's `market`, `role`, `inboxKey` encryption key, seed-derived `pay` address, and its `proofs` array. Verify each `human` proof against the issuer's public key to see which issuers stand behind the profile.
- **Find a profile's folder.** A profile's address is the public half of its main key (`Baby Jubjub`). Ask any host you know for its records, and check its signed `hosts` record to see every host that mirrors the folder.
- **Delegate to an AI.** The person's app writes scoped `write` and `read` keys into the folder's `permissions` record and hands the private halves to the AI. With a `write` key, the AI signs offers, reviews and outgoing messages without ever touching the person's seed or main key. With a `read` key, the AI pulls and decrypts the paths it was granted (such as `inbox`).
- **Write offers and reviews.** Their bodies are defined by the market the profile lives in ([markets](https://github.com/foundationforest/markets)); the standard names only `media`, the photos and videos a host keeps for a record.

## Privacy

What Forest does:
- Nothing in a person's keys ties their profiles together. Each profile key and each default payment address is mixed separately from the seed and label (`keys/`).
- A `human` proof shows which issuer signed the person a note, never who the person is, what the note holds, or which other profiles they hold (`proofs/human/`).
- Private records and inbox messages are encrypted to post-quantum `age` keys (`ML-KEM` hybrid), so copies taken today stay closed even against future quantum computers (`records/`).
- No blockchain is touched to create a seed, get an issuer note, open a profile, post an offer, send a message or write a review. Only payments and escrows touch a chain.

What others can still see:
- Everything in a profile's public records (`card`, `hosts`, `permissions`, `offer`, `review`) is open for any index or person to read.
- On-chain payments and escrow receipts are public on the payment chain. Moving money directly between two of your own profiles' `pay` addresses links them on chain.
- A host sees when a folder is written or read and the network address of the connection, unless a VPN or relay is used.
- An issuer that checks faces, or its provider (the company that runs the check), keeps the face to refuse verifying a second seed for the same human.

## Promises

- **The seed never leaves the device.** Neither the seed nor any profile main key is sent to any server (`keys/`).
- **One seed, one profile per label.** The `human` circuit derives the profile key inside the proof, making a second profile key for the same seed and label mathematically invalid (`proofs/human/`).
- **Updates and deletes are just writes.** Every record is versioned by ID; writing an empty tombstone deletes it from active view (`records/`).
- **Nothing in the standard charges a fee.** There is no protocol token and no protocol cut on deals.
- **Escrows have no admin key.** Once money enters an escrow, only the buyer, both sides together, the named arbiter or the timer set at the start can move it (`escrows/`).

## Limits

- **Test phase.** The circuits have not yet run their production multi-party setup ceremony, and the programs have not yet completed a security review.
- **No seed recovery.** Losing the seed loses the profiles derived from it, and the same human cannot verify a new seed at the same deduplicating issuer.
- **A host can withhold.** A host cannot forge or alter a signed record, but it can stop serving a folder; keeping a folder on more than one host covers for it.
- **Quantum signing migration.** Encryption is already post-quantum (`age`), while profile signatures and zero-knowledge proofs use elliptic curves (`Baby Jubjub` / `BN254`) and will require a key-migration proof before large quantum computers arrive.

## What it is built from

- **Keys, records and encryption:** Baby Jubjub EdDSA-Poseidon (profile, access key, and note signatures), Ed25519 (Solana payment addresses), RFC 8785 canonical JSON, and post-quantum `age` encryption.
- **Proofs:** Circom, `circomlib` (Poseidon and Baby Jubjub), `zk-kit` and Semaphore's Lean Incremental Merkle Tree, Perpetual Powers of Tau, and `snarkjs` (Groth16).
- **Escrows:** Anchor and SPL Token on Solana (`escrows/solana/`).
