# standard

Forest lets people offer, deal with and review each other through profiles they own, with no platform in the middle. The standard is the one part everyone shares: the formats, recipes and checks that let any app, host, index or verifier work with any other. Everything else sits on top of it and can be replaced.

## The picture

- **Your seed.** 32 secret bytes, the one secret behind all your profiles, kept by your app; the main way is a passkey in the password manager you choose. Every key behind your profiles comes from it; access keys, handed out, are random.
- **Your profiles.** One for each role you play, such as `tutoring/tutor`. Each has a main key that signs what it says. Nothing public links one of your profiles to another, unless you link them yourself, with a contact you reuse or a payment between them.
- **Your folder.** Each profile has one, kept on hosts you choose: its profile entry, its listings and reviews, its photos, and an inbox where others leave you locked messages. Entries can be locked so that only the keys you choose can open them.
- **Your Profiles folder.** The private folder your seed opens: the list of every profile you made, your stamps and your backups, so any device you start on finds them.
- **Access keys.** Keys a profile hands out, to your AI for example, each allowed only what you switch on: read, read the inbox, write, send messages. End one, and each host that has the profile entry ending it takes nothing more it signs; what it wrote stays where it is.
- **Stamps.** A verifier checks something about you, most often that you are one real person, and signs a stamp to your seed. Your profiles can then prove they come from a stamped seed, without saying who you are or which other profiles are yours.

## The directories

| Directory | What it is | When it matters |
|---|---|---|
| `keys/` | The recipe that makes every key from your seed, and access keys | Whenever an app holds a seed |
| `proofs/` | Two proofs a device makes and anyone checks: that a profile comes from a stamped seed, and the trust it carries from your other profiles, naming none | When a profile shows it's verified, or carries trust |
| `folders/` | How a profile writes, locks and reads its entries; the inbox; files; the Profiles folder; and the host API every host answers | Everything a profile says |
| `escrows/` | A lockbox on chain that holds a deal's money by a schedule both sides agreed. On Solana, the one place the standard touches a chain | When payments come; no app offers them yet |

## What's not here

- What a listing, review, vouch or report holds: [markets](https://github.com/foundationforest/markets).
- The services we run (verifier, host, index, MCP server): [services](https://github.com/foundationforest/services).
- The app that holds your seed: [app](https://github.com/foundationforest/app).

Anyone can run or propose their own of each. Where a README here says **the main way**, it means what our own apps and services do: a convention, never a rule.

No rule says how hosts and indexes find each other: an index chooses which hosts it reads, and a host makes itself known.

## Who decides what

- **The standard:** only the formats, recipes and checks in these directories.
- **A market:** its roles, the kinds of entry it defines, such as listings and reviews, and their fields.
- **A verifier:** whom it stamps, how many stamps each person gets, and what its stamps hold.
- **A host:** which folders it takes and at what price, how long it keeps what was replaced, and its limits on size and spam.
- **An index:** which hosts it reads, which profiles it scores and how, and which verifiers count.
- **An app, with the person:** how the seed is kept, which hosts and services to use, which access keys to hand out and to whom, and which proofs and messages to show.
- **Each reader:** which verifiers and indexes it trusts, and how much.

## How it changes

From launch on, nothing here changes in place. A new version sits beside the old one under a new name, and readers skip what they don't know, so old and new apps keep working together. Anyone can propose a change by pull request, and the Forest Foundation reviews it in the open.

## For builders

- **To read Forest:** an index's JSON, such as [ours](https://index.forest.foundation/index.json), or a folder from any host, whose profile entry and proofs you check yourself: [folders/](folders/README.md).
- **To run a host:** answer the host API, then run its check against your address: [folders/](folders/README.md#hosts).
- **To build an app:** [keys/](keys/README.md), then [folders/](folders/README.md), then [proofs/](proofs/README.md).
- **To act for someone:** use an access key their profile lists.

Everything here is Apache-2.0 ([LICENSE](LICENSE)).

## Limits

- Each proof's one-time setup was made by one party, the Forest Foundation, which could fake proofs for it. A public setup ceremony is planned.
- There is no seed recovery. Lose the seed, and its profiles are gone.
