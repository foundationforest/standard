# standard

Part of [Forest](https://github.com/foundationforest). The standard is the only part of Forest
everyone shares: the rules every app, host, index and issuer must agree on, with the programs and
libraries that follow them. Everything else, the
[services](https://github.com/foundationforest/services) the Open Forest Foundation runs and the
[app](https://github.com/foundationforest/app), lives in its own repo and can be replaced.

## Why these five

Every piece is sorted by one question: what if there were two of it?

- Two key recipes or two registries would mean two of you, so those are fixed.
- Records, reputation proofs and escrow are shared formats: anyone can offer another.
- Hosts, issuers, indexes and apps are not here: anyone runs one, and the foundation's are in
  services.

## The folders

A stamp is the number one person has for one label at one issuer, and the registry keeps one row
for each. The vault is the folder of their own on a host that a new device restores from.

| Folder | What it is | What runs | Where |
|---|---|---|---|
| [`keys/`](keys/README.md) | The seed, and the recipe that mixes every key from it | a library | on the person's device |
| [`registry/`](registry/README.md) | One row per stamp (one person, one label, one issuer), proven without saying who | a Solana program, a circuit and a client | the chain, devnet today |
| [`reputation/`](reputation/README.md) | The proof of a score across the person's profiles, and the tree an index publishes for it | a circuit and a client | made on the device, checked by anyone |
| [`records/`](records/README.md) | How a profile says things: folders, signed records, private records, permissions, the inbox, the vault, blobs, what every host must do, and a reference host | a library | wherever an app, host or index runs |
| [`escrow/`](escrow/README.md) | Money out when both sides agree, or by an arbiter or timer set at the start; this is one escrow, and anyone may use another | a program and a client | the chain, devnet today |

Each folder's README has the same shape, so a reader knows where a fact lives: What it is, How it
works (ending with how to use or run it), Promises, Limits, Who decides what, FAQ.

## Who decides what

The standard holds only what two strangers' programs must agree on. Everything else is a service's
own choice, an app's, or the person's.

- **The standard** is fixed: no service or app can change it.
- **A service** chooses for itself. The foundation's say what they choose, each in its own README in
  [services](https://github.com/foundationforest/services).
- **An app** chooses with the person.
- **The person** decides the rest.

## For builders

- **Find a profile's folder.** A profile's address is its name. Ask any host you know for its
  records; its hosts record, signed by the profile, names every host that keeps them, so read those
  too. The standard has no directory: a profile is found by its address, and an index keeps its own
  list of hosts to read ([records](records/README.md)).
- **Read a market.** Ask an index. Its answer is in that index's own format, not part of the
  standard; the [mcp folder in services](https://github.com/foundationforest/services/tree/main/mcp)
  reads the foundation's. You can also read the records yourself and weigh them your own way.
- **Pay Solana's fees for someone.** Whoever signs a transaction as payer pays its fee and any
  deposit a new account needs, and the programs do not care who that is. A fee payer is a service
  that pays for others; the foundation's is Kora, the Solana Foundation's open fee payer, and
  speaks its JSON-RPC ([services](https://github.com/foundationforest/services)).
- **Register a profile.** Get a note from an issuer (its signed word that it checked you once),
  then send the registry a proof made on the device; it writes one row
  ([registry](registry/README.md)).
- **Let an AI act for someone.** The person's app hands it access keys, which act for one profile
  within limits, never the main key that is the profile. The AI works through the
  [mcp folder in services](https://github.com/foundationforest/services/tree/main/mcp).

## Privacy

What Forest does:
- Nothing in a person's keys ties their profiles together: each is its own mix of the seed
  ([keys](keys/README.md)).
- A registry row says which issuer signed the person's note, never who the person is
  ([registry](registry/README.md)).
- Private records and messages are encrypted to post-quantum keys; hosts keep them and cannot open
  them ([records](records/README.md)).
- Never on chain: seeds, private keys, records, messages, blobs, issuers' notes, and the index.

What others can still see:
- On chain, everything: rows, escrows, receipts and money. Paying between your own profiles on
  chain links them.
- A ramp, a service that turns cash into dollars on chain and back, knows the profile it paid into.
- A host sees who wrote to whom and when, not what, and the network address of whoever reads or
  writes.
- An issuer that checks faces, or its provider, keeps the face to refuse it a second time.
- An AI run in the cloud shows its maker what you tell it.

What you can add:
- A VPN, so hosts and indexes do not see your network address.
- A model on your own device, so nothing you tell your AI leaves it
  ([mcp folder in services](https://github.com/foundationforest/services/tree/main/mcp)).

Planned, not built:
- A relay, so hosts and indexes do not see your network address, with no VPN.
- A privacy pool, so money moves between your own profiles without the chain linking them.

## Promises

- **Nothing needs the seed to leave the device.** Neither the seed nor a main key has to leave it,
  and where they live is the app's choice ([keys](keys/README.md)).
- **Private by default off chain.** Nothing ties your profiles together unless you link them, and
  nothing in the standard holds a person next to a profile.
- **Nothing inside charges.** The registry and the escrow take no fee, and the only costs are
  Solana's, paid by whoever sends the transaction.
- **Only the deal decides where money goes.** Nothing in the escrow program lets anyone but the two
  sides, the arbiter or the timer move the money ([escrow](escrow/README.md#promises)).
- **Anyone can take part.** Anyone can run a host, run an issuer, name a market or build an app, and
  everything needed to compete with the foundation is open.
- **Both programs are sealed on mainnet, for different reasons.** The registry because everyone
  shares it: a change would mean two registries, two of you. The escrow because money sits inside
  it: nobody, the foundation included, may change the rules around money already there. A new
  version of either is a new program at a new address, and several escrows may run at once, for
  other chains or other rules; a profile may use any.

## Limits

- **Devnet only.** Nothing is on mainnet and nothing is shipped; until mainnet the standard is a
  draft, and the devnet deploy key can still upgrade both programs.
- **Not audited.** Each program keeps a security checklist next to it, and no paid review has been
  done.
- **No recovery.** Lose the seed and every profile and stamp it gives is gone, and your face cannot
  get a note again from the same issuer; nobody else has it ([keys](keys/README.md)).
- **A host can withhold.** A host cannot forge or change a record, but it can stop serving a record,
  message or blob, and the app's copies and the profile's other hosts cover for it.
- **Not here:** recovery through an issuer, and an arbiter by default.

## FAQ

**Who decides which markets exist?**
Nobody. A label is free text saying what a profile is for, and the registry accepts any, so any
label is a market. The recommended shape is `market/role`, and the
[markets list](https://github.com/foundationforest/markets) recommends spellings so that one trade
does not split into ten names. It gates nothing in the standard: a market adds fields to records
and restricts no deal. Each index chooses which labels it counts; the foundation's counts the names
on the list.

**Why do the programs not judge evidence?**
A sealed program cannot learn new kinds of evidence, and an index can. So the programs never
interpret evidence; indexes weigh it.

**Can Forest take my money or my profile?**
Not through the standard. Forest never holds your seed or your main keys, the escrow has no admin,
and Forest arbitrates nothing: an arbiter is a key both sides saw at the start. The one place to
look is where the seed lives: whoever controls the app that holds it controls it, Forest's own app
included. A web app's code arrives from its server on each visit; an installed app's does not.

**Why is the app in its own repo?**
An app is the person's choice, one of many, so the standard must not look like one app. The app
that holds the seed is open source so anyone can check that nothing leaks, and it pins a version of
this repo, the way services does.

**What is it built from?**
Existing pieces, used unchanged: Ed25519, RFC 8785 canonical JSON, age, Semaphore's lean Merkle
tree, circomlib's Poseidon and EdDSA verifier and zk-kit's Merkle circuit on PSE's Perpetual Powers
of Tau, zk-kit's EdDSA-Poseidon, snarkjs, groth16-solana, Anchor, the SPL Token programs, and Kora,
in the foundation's fee payer. Forest writes only what does not exist yet.
