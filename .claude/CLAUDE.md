This repo is `standard`: the standards every Forest app shares (keys, proofs, folders, escrows).
Read `README.md` and the README of the directory you work in before any task.

## Words

Use these words: seed, seed scalar, main key, signing half, opening half, open key, access key,
profile, Profiles folder, profile entry, entry, folder, address, label, scope, prefix, verifier,
verified, stamp, stamp number, facts, verification, reputation proof, check, host, plug, host
check, service key, connector, private, locked (an entry, to a key), envelope, message, inbox,
inbox entry, file, keyed path, pay address, pay key, escrow, receipt, deal, index, fee payer, app,
market, role. Plain words, no em-dashes.

- Never "record" for what a folder holds (it is an entry), "signer" (a chain's transaction signer
  keeps the chain's word, in escrows/), "permission", "inbox key" (it is the main key's opening
  half), "hosts record" (hosts are the profile entry's), "tag", "stamp proof" (it is a
  verification), "pull", "blob" or "letter".
- Check, never verify: a reader checks a proof or a signature. The tooling keeps its own names
  (snarkjs's verifier, `verification-key.json`), and prose calls that part the proof check.
- Never "account" for a person: a person has a seed and profiles.
- A string baked into a recipe or a circuit keeps its bytes even when its words are old
  (`forest/v1/issuer`, `forest/v1/note`, `forest/v1/inbox`): rename the code around it, never the
  string, and say why in a comment beside it.

The test for what goes in this repo: the standard holds formats (what bytes mean), recipes (how a
number is derived) and checks (what a reader runs); meanings and choices live outside it.
Use cases are phrased "anyone can; the main way is X", never "X is one option" and never "X is
the rule".

What an app that holds keys should know: `keys/README.md`. Never copy it here.

## How to work in this repo

- Work in plan mode. One task per session. Open a pull request; never push to main.
- The promises in each README change only when Carlos says so in a chat; never change one as a side
  effect of a task.
- Content shapes are never defined in this repo: what an offer, a review or a market holds is
  `foundationforest/markets`'s.
- The repo is `keys/`, `proofs/` (`verification/`, `reputation/`), `folders/`, `escrows/`
  (`solana/`), `README.md` and `LICENSE`, with `.github/`, `.claude/CLAUDE.md`, and the npm
  workspace's `package.json`, `package-lock.json` and `tsconfig.base.json`.
  The README is the standard.
- Keep the docs true in the same pull request: a change that makes a README wrong fixes it. A README
  says only what the code does. Devnet is named only inside escrows/, and only where something is
  configured for it.
- One README per level: the repo's, and one in each directory; each starts with what it is and how
  it works.
- Each piece's README ends Limits and FAQ, and Promises and Who decides what where it has them; a
  parent README carries a section only when it has content of its own, never a pointer to the
  directories below; the repo README has Who decides what after the sort.
- A question lives at the lowest level whose README explains the thing it is about.
- A FAQ is only for what the explanation does not answer; when a question shows the explanation is
  missing something, the explanation changes.
- When the plan is silent, choose the option that adds no rule and no text a person reads. Write
  its reason down: as a question in the FAQ of the directory it belongs to (the top README's for the
  whole repo) if it shapes Forest, otherwise in a comment beside the code. Ask only when the choice
  changes the escrow program or spends money.
- The escrow's `escrows/solana/devnet/deploy.sh` holds the key recipe it needs and writes its own
  `devnet.json` beside it. No private key and no phrase ever goes in the repo.
- Run what `.github/workflows/checks.yml` runs before you push (Node 22.18 or later; Solana CLI
  4.2.2; circom 2.2.3); the commands are there. A test that skips fails CI: the summary must say
  `# skipped 0`. `npm ci` at the root installs every package, and `npm run build` there builds keys,
  proofs, folders and escrows/solana/client to their `dist/`, in that order, so each is built before
  a package that imports it. Then, in each package, `npm run check` and `npm test`; in proofs, `npm
  run fetch` and `npm run compile` first.

The slower check, the escrow's fuzzer, runs nightly in CI; `escrows/solana/README.md` says how to
run it.
