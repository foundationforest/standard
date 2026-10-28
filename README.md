# standard

Part of [Forest](https://github.com/foundationforest), open software for people to offer, pay and review each other through profiles they own. A person holds one secret seed on their device and gets one profile for each label they use, a text such as `tennis/seller` naming the profile's market and its role there.

- A **verifier** checks a person and signs a stamp to their seed: a person it stamped is verified.
- A **host** stores profiles' folders and inboxes: a profile's folder holds the records it signs, small signed statements such as the one that shows the profile, or an offer, and its inbox holds the encrypted messages others leave it.
- An **index** reads hosts, checks proofs, and scores profiles and offers.
- An **app** creates records and reads the network for the person. One that holds the person's seed, on a device they own, is a **signer**; an AI or another person acts for them by asking a signer, never with a key of their own.

The standard is the only part of Forest everyone shares: the formats, recipes and checks every app, host, index and verifier must agree on, and the code that follows them: libraries, the circuits behind its proofs, and an escrow program, a lockbox that holds a deal's money on chain.

One seed gives one profile per label; a verifier decides how many stamps each human gets; how many verifiers count is each index's.

Everything outside the standard lives in [markets](https://github.com/foundationforest/markets), [services](https://github.com/foundationforest/services) and [app](https://github.com/foundationforest/app), where anyone can run or propose their own copy.

## Why these parts

The standard holds formats (what bytes mean), recipes (how a number is derived) and checks (what a reader runs); meanings and choices live outside it. Every piece here is sorted by one test: what must two strangers' programs agree on for one profile, one deal and one reputation to work across the open internet?

Four things stay outside: what a stamp means is the reader's; what a record says is the market's; how a score is made is the index's; where a seed is kept is the app's. A program someone runs, such as a host or a connector, is a product and lives outside the standard too; the escrow program is the one exception, since nobody runs it once it is deployed.

- **Keys and proofs are fixed by math.** One seed and one label must always produce the same main key, the key that signs as the profile, and a zero-knowledge proof must show that a verifier signed a stamp to that seed without revealing the seed or linking the person's other profiles. Because the circuit derives the main key directly from the seed and label, one seed gives one valid main key per label. A second proof lets a person carry a score from their other profiles onto a new one without linking them.
- **Records, signers and escrows are shared formats.** Records define how a folder is written, read and encrypted, and the plug every host fits. Signers define how anyone asks a person's app to act for them. Escrows hold money on chain when a deal needs payment locked in advance.

## The directories

A **label** is any text; markets set the convention, `<market>/<role>`, such as `plumbing/seller`, and each market defines its roles, its content paths (where its kinds of record, such as offers, sit in a folder) and their bodies in [markets](https://github.com/foundationforest/markets). A **tag** is a number made from a person's seed for one label at one verifier, so the tree of scores an index publishes can count the profile without linking it to others. Every profile has one **folder** kept on one or more hosts.

| Directory | What it is | What runs | Where |
|---|---|---|---|
| [`keys/`](keys/README.md) | The recipe that mixes every key from the person's seed: each profile's main key, its pay addresses (where it is paid), its inbox key (which opens what others encrypt to it), and the person's secret for each verifier | a library | on the person's device |
| [`proofs/`](proofs/README.md) | The zero-knowledge proofs a device makes and anyone can check: [`stamp/`](proofs/stamp/README.md) (proving a profile's key and tag come from a seed a verifier signed a stamp to) and [`reputation/`](proofs/reputation/README.md) (proving a score across hidden profiles from an index's tree) | circuits and client libraries | made on the device; checked by anyone in milliseconds |
| [`records/`](records/README.md) | How a profile speaks: the records in its folder, each signed by its main key and replaced by its next version (`profile`, `hosts`, the market's content paths, and private records, which only the readers chosen open), the encrypted `inbox`, the blobs a folder holds (photos and videos its main key puts and deletes), the plug every host fits, and the host check that shows a host fits it | a library | wherever an app, AI, host or index runs |
| [`signers/`](signers/README.md) | How anyone asks a person's app to act for them: the asks (read, write, pay) and their answers, how an AI app connects through a connector, and permissions, private records in each profile's folder saying who may ask for what | a library | on the person's device, and wherever a connector runs |
| [`escrows/`](escrows/README.md) | On-chain lockboxes that release money when a side gives it to the other, both sides agree, a chosen arbiter decides, or the schedule set at the start says so (one directory per chain; only [`solana/`](escrows/solana/README.md) has one) | an on-chain program and client library | on chain when a deal uses escrow |

## Who decides what

- **The standard** holds only what two strangers' programs must agree on to check keys, proofs, records and escrows, and to ask a person's app to act for them.
- **A market** (in [markets](https://github.com/foundationforest/markets)) defines its roles, its content paths and their bodies, and may suggest an offer field that carries an escrow's terms.
- **A service** (verifier, host, index, or fee payer, which pays a chain's fees for others) sets its own prices and choices. An index decides which verifiers it trusts, how many count, and how it weights evidence.
- **An app** chooses how it holds the seed and which services it uses by default, together with the person.
- **The person** decides which markets to enter, which AI, app or person may ask their signers to act for them, and for what, and when to carry a score across profiles.

## How it changes

Once people use Forest, what exists never changes: a recipe's strings, a circuit and its setup, an escrow program, a `v: 1` record, a `/v1/` request. A new version is a new thing beside the old, under a new name: a new string, a new circuit, a program at a new address, `v: 2`, `/v2/`. Readers skip what they do not know, so an old app keeps working beside a new one. Anyone proposes a change by pull request, and the Open Forest Foundation checks it in the open.

## For builders

- **Check a profile.** Read its profile record, the record at `profile` that shows it, from its folder on any host. It holds the profile's `market`, `role`, `inboxKey` (what others encrypt to), any of its seed-derived `pay` addresses (`solana`, `evm`) with `paySig`, each address signed by its own pay key, the key that holds that address's money, so a profile cannot list an address that is not its own, and its `proofs` array. The array takes any circuit's proofs, and a reader skips the ones it does not know: `stamp` and `reputation` are ours, and anyone can add one. Check each `stamp` proof against the verifier's key to see which verifiers signed a stamp to the seed behind the profile.
- **Find a profile's folder.** A profile's address is the public half of its main key, a key on Baby Jubjub, the curve the proofs work on. Ask any host you know for its records, and check its signed `hosts` record to see every host that mirrors the folder.
- **Act for a person.** Ask one of their signers, the devices that hold their seed: an AI app through its connection, which the person's app makes for it and a connector carries, a relay AI apps call from their cloud; a person or a business by a message signed by its own profile's main key. The signer acts by the profile's permissions, private records saying who may ask it to act and for what, and signs with the profile's main key; no key is ever handed out ([signers/](signers/README.md)).
- **Write offers and reviews.** Their paths and bodies are defined by the market the profile lives in ([markets](https://github.com/foundationforest/markets)); the standard names none of them. A photo or a video is a blob the folder holds, put and deleted by its keys; where a record points at one is the market's.

## Privacy

What Forest does:
- Nothing in a person's keys ties their profiles together. Each main key and each default pay address is mixed separately from the seed and label (`keys/`).
- A stamp proof shows which verifier signed the person a stamp, never who the person is, what the stamp holds, or which other profiles they hold (`proofs/stamp/`).
- Private records and inbox messages are encrypted with `age`, a widely used encryption format, in its post-quantum kind (`records/`).
- No blockchain is touched to create a seed, get a stamp, open a profile, post an offer, send a message or write a review. Only payments and escrows touch a chain.

What others can still see:
- Everything in a profile's public records (`profile`, `hosts` and the market's content paths) is open for any index or person to read.
- On-chain payments and escrow receipts are public on the payment chain. Moving money directly between two of your own profiles' `pay` addresses links them on chain.
- A connector holds none of the person's keys, but it sees each ask in plain text and any token passed through it, so it can act as any connection it carries, within that connection's permissions: that is why a permission has limits. Anyone can run their own (`signers/`).
- A verifier sees the person's stamp number, the number their device sends it to be stamped, the same each time for that person at that verifier.

## Promises

- **Nothing in the standard needs the seed or a main key to leave the device.** `keys/` mixes every key from the seed on the device; everything else takes only what it mixes. What an app does with the seed is the app's (`signers/`, What an app that holds keys should know).
- **One seed, one profile per label.** The stamp circuit derives the main key inside the proof, making a second main key for the same seed and label mathematically invalid, though a person with two seeds has a profile under the label for each (`proofs/stamp/`).
- **Updates and deletes are just writes.** Every path holds its newest signed record; a record with a null body deletes the path, though what was read before stays with whoever read it (`records/`).
- **Nothing in the standard charges a fee.** There is no coin and no cut on deals.
- **Escrows have no admin key.** Once the program holds real money and can no longer change, nothing moves the money but a side giving, both agreeing, the arbiter, or the schedule (`escrows/`).

## Limits

- **Each circuit's setup, made once before any proof, was made by one party,** who could make a false proof for it (`proofs/`).
- **No seed recovery.** Lose the seed and the profiles made from it are gone; nothing can give them back (`keys/`).

## What it is built from

- **Keys, records and encryption:** Baby Jubjub EdDSA-Poseidon (the signatures of main keys, of stamps, and of service keys, an index's or a verifier's own), Ed25519 (Solana pay addresses, and connection keys), secp256k1 and keccak256 with EIP-55 (EVM pay addresses), RFC 8785 canonical JSON, and post-quantum `age` envelopes.
- **Proofs:** Circom, `circomlib` (Poseidon and Baby Jubjub), `zk-kit` and Semaphore's Lean Incremental Merkle Tree, Perpetual Powers of Tau, and `snarkjs` (Groth16).
- **Escrows:** Anchor and SPL Token on Solana (`escrows/solana/`).
