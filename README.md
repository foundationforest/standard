# standard

Forest lets people offer, deal with and review each other through profiles they own, with no platform in the middle. The standard is the one part everyone shares: the formats, recipes and checks that let any app, host, index or verifier work with any other. Everything else sits on top of it and can be replaced.

## The picture

- **Your seed.** 32 secret bytes that stay on your devices. Every key you have but an access key comes from it.
- **Your profiles.** One for each role you play, such as `tutoring/tutor`. Each has a main key that signs what it says. Nothing public links one of your profiles to another.
- **Your folder.** Each profile has one, kept on hosts you choose: its profile entry, its posts and reviews, its photos, and an inbox where others leave you locked messages. Entries can be locked so that only the keys you choose can open them.
- **Access keys.** Keys a profile hands out, to your AI for example, each allowed only what you switch on: read, read the inbox, write, send messages. Remove one and it stops counting everywhere at once.
- **Stamps.** A verifier checks something about you, most often that you are one real person, and signs a stamp to your seed. Your profiles can then prove they come from a stamped seed, without saying who you are or which other profiles are yours.

## The folders

| Folder | What it is | When it matters |
|---|---|---|
| `keys/` | The recipe that makes every key from your seed, and access keys | Whenever an app holds a seed |
| `proofs/` | Two proofs a device makes and anyone checks: that a profile comes from a stamped seed, and the trust it carries from your other profiles, naming none | When a profile shows it's verified, or carries trust |
| `folders/` | How a profile writes, locks and reads its entries; the inbox; files; the Profiles folder; and the plug every host fits | Everything a profile says |
| `escrows/` | A lockbox on chain that holds a deal's money by a schedule both sides agreed. On Solana, the one place the standard touches a chain | When payments come; no app offers them yet |

## What's not here

- What a post, review, vouch or report holds: [markets](https://github.com/foundationforest/markets).
- The services we run (verifier, host, index, mcp): [services](https://github.com/foundationforest/services).
- The app that holds your seed: [app](https://github.com/foundationforest/app).

Anyone can run or propose their own of each.

## Who decides what

- **The standard:** only the formats, recipes and checks in these folders.
- **A market:** its roles, the kinds of entry it defines, such as posts and reviews, and their fields.
- **A verifier:** whom it stamps, how many stamps each person gets, and what its stamps hold.
- **A host:** which folders it takes and at what price, how long it keeps what was replaced, and its limits on size and spam.
- **An index:** which hosts it reads, which profiles it scores and how, and which verifiers count.
- **An app, with the person:** how the seed is kept, which hosts and services to use, which access keys to hand out and to whom, and which proofs and messages to show.
- **Each reader:** which verifiers and indexes it trusts, and how much.

## How it changes

Once people use Forest, nothing here changes in place. A new version sits beside the old one under a new name, and readers skip what they don't know, so old and new apps keep working together. Anyone can propose a change by pull request, and the Forest Foundation reviews it in the open.

## For builders

- Every key comes from `keys/`. Start there.
- To read a profile: fetch its profile entry from any host, then check its proofs.
- To act for someone: use an access key their profile lists.
- To run a host: answer the seven requests in `folders/`, then run the host check against your address.

## Limits

- Each proof's one-time setup was made by one party, who could fake proofs for it. A public setup ceremony is planned.
- There is no seed recovery. Lose the seed, and its profiles are gone.
