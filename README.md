# standard

Part of [Forest](https://github.com/foundationforest), open software for people to offer, pay and review each other through profiles they own. The standard is the only part of Forest everyone shares: the formats, recipes and checks every app, host, index and verifier must agree on, and the code that follows them: libraries, the circuits behind its proofs, and an escrow program, a lockbox that holds a deal's money on chain.

## The picture

- **A person holds one seed,** 32 secret bytes on their own devices. From it come their Profiles folder, theirs alone, and one profile for each label they use, a text such as `tennis/seller` naming the profile's market and its role there (`<market>/<role>`).
- **Each profile has a main key, pay addresses, and access keys it hands out.** Every key is a pair: a signing half, whose address names it, and an opening half, which envelopes are locked to. The main key's address is the profile's name; the pay addresses are where it is paid; an access key is what an AI app, a service or another person acts for the profile with.
- **Each profile has one folder:** its profile entry, which shows it and lists its hosts, its open key and its access keys; its entries, of any shape, public or locked, photos included; and its inbox, the entries others leave it, always locked.
- **A verifier** checks a person and signs a stamp for their seed. The person keeps the stamp private, in their Profiles folder; a verification is what each of their profiles shows, a proof that its seed holds a stamp from that verifier, naming neither the person nor their other profiles.
- **A host** keeps folders and serves them to anyone. **An index** reads hosts, checks proofs, and scores profiles and offers. **An app** writes entries and reads the network for the person.

One seed gives one profile per label; a verifier decides how many stamps each human gets; how many verifiers count is each index's.

Everything outside the standard lives in [markets](https://github.com/foundationforest/markets), [services](https://github.com/foundationforest/services) and [app](https://github.com/foundationforest/app), where anyone can run or propose their own copy.

## Who enforces what

- **Writing: hosts and readers.** An entry counts only when the profile's main key signed it, or an access key its profile entry lists with `write`. Every host checks before it takes an entry, and every reader before it counts one, so a host can withhold an entry but never forge one ([folders/](folders/README.md)).
- **Reading: envelopes.** A locked entry or an inbox entry opens only for the keys it was locked to: the main key's, and each access key listed to read. No host or reader checks anything else ([folders/](folders/README.md#locked-entries)).
- **Messages: the recipient's app.** It checks each message's signature and its sender's profile entry, a verification, a market and a role among what it reads, and decides what to show ([folders/](folders/README.md#the-inbox)).
- **Paying: the chain.** A pay key signs a payment, and an escrow program holds a deal's money by its own rules ([escrows/](escrows/README.md)).

## Why these parts

The standard holds formats (what bytes mean), recipes (how a number is derived) and checks (what a reader runs); meanings and choices live outside it. Every piece here is sorted by one test: what must two strangers' programs agree on for one profile, one deal and one reputation to work across the open internet?

Four things stay outside: what a stamp means is the reader's; what an entry says is the market's; how a score is made is the index's; where a seed is kept is the app's. A program someone runs, such as a host or a connector, is a product and lives outside the standard too; the escrow program is the one exception, since nobody runs it once it is deployed.

- **Keys and proofs are fixed by math.** One seed and one label must always produce the same main key, and a zero-knowledge proof must show that a verifier signed a stamp to that seed without revealing the seed or linking the person's other profiles. Because the circuit derives the main key directly from the seed and label, one seed gives one valid main key per label. A second proof lets a person carry trust from their other profiles onto a new one, without saying which.
- **Folders and escrows are shared formats.** Folders define how an entry is written, read and locked, which keys count, and the plug every host fits. Escrows hold money on chain when a deal needs payment locked in advance.

## The directories

| Directory | What it is | What runs | Where |
|---|---|---|---|
| [`keys/`](keys/README.md) | The recipe that mixes every key from the person's seed, on three texts: each profile's main key and its opening half, the Profiles folder's among them, its pay addresses, and the person's stamp number at each verifier; and access keys, made from random bytes to be handed out | a library | on the person's device |
| [`proofs/`](proofs/README.md) | The zero-knowledge proofs a device makes and anyone can check, each its own circuit: [the verification](proofs/README.md#the-stamp-and-the-verification) (what a profile shows to prove its key comes from a seed a verifier signed a stamp to) and [the reputation proof](proofs/README.md#the-reputation-proof) (carrying trust from the person's other profiles, scored in an index's tree, without saying which) | circuits and a client library | made on the device; checked by anyone in milliseconds |
| [`folders/`](folders/README.md) | How a profile speaks: its folder's entries, each signed by its main key or an access key its profile entry lists, and replaced by its next version; locked entries, which only the keys chosen open; files, kept while an entry names them; the inbox; the Profiles folder; the plug every host fits, and the host check that shows a host fits it | a library | wherever an app, AI, host or index runs |
| [`escrows/`](escrows/README.md) | On-chain lockboxes that release money when a side gives it to the other, both sides agree, a chosen arbiter decides, or the schedule set at the start says so (one directory per chain; only [`solana/`](escrows/solana/README.md) has one) | an on-chain program and client library | on chain when a deal uses escrow |

## Who decides what

- **The standard** holds only what two strangers' programs must agree on to check keys, proofs, entries and escrows.
- **A market** (in [markets](https://github.com/foundationforest/markets)) defines its roles, its content paths (where its kinds of entry, such as offers, sit in a folder) and their bodies, and may suggest an offer field that carries an escrow's terms.
- **A service** (verifier, host, index, connector, or fee payer, which pays a chain's fees for others) sets its own prices and choices. An index decides which verifiers it trusts, how many count, and how it weights evidence.
- **An app** chooses how it holds the seed and which services it uses by default, together with the person.
- **The person** decides which markets to enter, which access keys each profile hands out, to whom and for what, when to remove one, and when to carry a score across profiles.

## How it changes

Once people use Forest, what exists never changes: a recipe's strings, a circuit and its setup, an escrow program, a `v: 1` entry, a `/v1/` request. A new version is a new thing beside the old, under a new name: a new string, a new circuit, a program at a new address, `v: 2`, `/v2/`. Readers skip what they do not know, so an old app keeps working beside a new one. Anyone proposes a change by pull request, and the Open Forest Foundation checks it in the open.

## For builders

- **Check a profile.** Read its profile entry, the entry at `profile` in its folder, from any host. It holds the profile's `market` and `role`, its `hosts`, its `openKey`, any of its seed-derived `pay` addresses, its `keys`, and its `proofs` array. The array takes any circuit's proofs, and a reader skips the ones it does not know: `verification` and `reputation` are ours, and anyone can add one. Check each `verification` against the verifier's key to see which verifiers signed a stamp to the seed behind the profile.
- **Find a profile's folder.** A profile's address is the public half of its main key, a key on Baby Jubjub, the curve the proofs work on. Ask any host you know for its folder, and follow the `hosts` its profile entry names to every host that holds it.
- **Act for a person.** Anyone can, with an access key the person's app hands them: the profile entry lists it with what it can do (`read`, `read-inbox`, `write`, `message`), every host and reader checks that, and removing it from the list stops it. The main way for an AI app is a connector in [services](https://github.com/foundationforest/services). The seed and the main keys stay on the person's devices ([keys/](keys/README.md#what-an-app-that-holds-keys-should-know)).
- **Write offers and reviews.** Their paths and bodies are defined by the market the profile lives in ([markets](https://github.com/foundationforest/markets)); the standard names none of them. A photo is an entry whose body is its file, the bytes kept by the folder's hosts while an entry names them.

## Privacy

What Forest does:
- Nothing in a person's keys ties their profiles together. Each main key, opening half and default pay address is mixed separately from the seed and label, and an access key is random bytes (`keys/`). The Profiles folder, which lists the person's profiles and stamps, is locked to its own opening half, at random paths that name nothing (`folders/`).
- A verification shows which verifier signed the person a stamp, never who the person is, what the stamp holds, or which other profiles they hold (`proofs/`).
- Locked entries and inbox entries are locked with `age`, a widely used encryption format, in its post-quantum kind; an inbox entry names only the folder it is for, its sender locked inside (`folders/`).
- No blockchain is touched to create a seed, get a stamp, open a profile, post an offer, send a message or write a review. Only payments and escrows touch a chain.

What others can still see:
- Everything in a profile's public entries (its profile entry and the market's content paths) is open for any index or person to read.
- A host sees whom each inbox entry is for, when it came and its size, though not who wrote it or what it says.
- Whoever holds an access key acts for the profile within what its profile entry lists, and opens what was locked to it while it was listed: that is why each key lists what it can do, and why removing it stops it (`folders/`).
- On-chain payments and escrow receipts are public on the payment chain. Moving money directly between two of your own profiles' `pay` addresses links them on chain.
- A verifier sees the person's stamp number, the number their device sends it to be stamped, the same each time for that person at that verifier.

## Promises

- **Nothing in the standard needs the seed or a main key to leave the device.** `keys/` mixes every key from the seed on the device; everything else takes only what it mixes, and an access key handed out holds nothing of the seed. What an app does with the seed is the app's (`keys/`, What an app that holds keys should know).
- **One seed, one profile per label.** The verification circuit derives the main key inside the proof, making a second main key for the same seed and label mathematically invalid, though a person with two seeds has a profile under the label for each (`proofs/`).
- **Updates and deletes are just writes.** Every path holds its newest entry that counts; an entry with a null body deletes the path, though what was read before stays with whoever read it (`folders/`).
- **Nothing in the standard charges a fee.** There is no coin and no cut on deals.
- **Escrows have no admin key.** Once the program holds real money and can no longer change, nothing moves the money but a side giving, both agreeing, the arbiter, or the schedule (`escrows/`).

## Limits

- **Each circuit's setup, made once before any proof, was made by one party,** who could make a false proof for it (`proofs/`).
- **No seed recovery.** Lose the seed and the profiles made from it are gone; nothing can give them back (`keys/`).

## What it is built from

- **Keys, entries and envelopes:** Baby Jubjub EdDSA-Poseidon (the signatures of main keys, access keys, stamps, and service keys, an index's or a verifier's own), Ed25519 (Solana pay addresses), secp256k1 and keccak256 with EIP-55 (EVM pay addresses), RFC 8785 canonical JSON, and post-quantum `age` envelopes.
- **Proofs:** Circom, `circomlib` (Poseidon and Baby Jubjub), `zk-kit` and Semaphore's Lean Incremental Merkle Tree, Perpetual Powers of Tau, and `snarkjs` (Groth16).
- **Escrows:** Anchor and SPL Token on Solana (`escrows/solana/`).
