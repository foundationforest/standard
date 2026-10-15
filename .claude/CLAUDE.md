This repo is `standard`: the standards every Forest app shares (keys, proofs, records, escrows).
Read `README.md` and the README of the directory you work in before any task.

## Words

Use these words: seed, seed scalar, main key, profile, address, label, scope, stamp, issuer, note,
note number, attributes, human proof, reputation proof, record, folder, host, access key, write key,
read key, permissions, private, envelope, inbox key, inbox, pull, vault, blob, escrow, receipt,
deal, index, fee payer, app, market, role, and sealed (for programs only).
Plain words, no em-dashes.

Rules for apps: `keys/README.md`, Rules for apps that hold keys. Never copy them here.

## How to work in this repo

- Work in plan mode. One task per session. Open a pull request; never push to main.
- The promises in each README change only when Carlos says so in a chat; never change one as a side
  effect of a task.
- Content shapes are never defined in this repo: what an offer, a review or a market holds is
  `foundationforest/markets`'s.
- The repo is `keys/`, `proofs/` (`human/`, `reputation/`), `records/`, `escrows/` (`solana/`),
  `README.md` and `LICENSE`, with `.github/` and `.claude/CLAUDE.md`. The README is the standard.
- Keep the docs true in the same pull request: a change that makes a README wrong fixes it. A README
  says only what the code does today. Say "on devnet" for what runs; never state anything as
  shipped.
- One README per level: the repo's, and one in each directory; each starts with what it is and how
  it works.
- Each piece's README ends Promises, Limits, Who decides what, FAQ; the repo README has Who decides
  what after the sort.
- A question lives at the lowest level whose README explains the thing it is about.
- A FAQ is only for what the explanation does not answer; when a question shows the explanation is
  missing something, the explanation changes.
- When the plan is silent, choose the option that adds no rule and no text a person reads. Write
  its reason down: as a question in the FAQ of the directory it belongs to (the top README's for the
  whole repo) if it shapes Forest, otherwise in a comment beside the code. Ask only when the choice
  changes a sealed program or spends money.
- Devnet: each program's `devnet/deploy.sh` holds the key recipe it needs and writes its own
  `devnet/devnet.json`. No private key and no phrase ever goes in the repo.
- Run what `.github/workflows/checks.yml` runs before you push (Node 22.18 or later; Solana CLI
  4.2.2; circom 2.2.3). A test that skips fails CI: the summary must say `# skipped 0`.

```
# Each package: install, type-check, tests that need no chain.
# keys first: records, proofs/human/client and proofs/reputation/client read it;
# proofs/human/client before proofs/reputation/client, which reads it; both before records,
# whose tests read them.
for d in keys proofs/human/client proofs/reputation/client records escrows/solana/client; do
  (cd "$d" && npm ci && npm run check && npm test)
done

# Each circuit, after keys and its client, which it reads: its setup's files, then the compile
# checked against them, then type-check and tests.
for c in proofs/reputation/circuit proofs/human/circuit; do
  (cd "$c" && npm ci && npm run fetch && npm run compile && npm run check && npm test)
done

# Each program: build as SBPF v3, then its LiteSVM tests against that build.
for p in escrows/solana/program; do
  (cd "$p" && cargo build-sbf --arch v3 && cd tests-litesvm && cargo test)
done
```

The slower check, the escrow's fuzzer, runs nightly in CI; `escrows/solana/README.md` says how to
run it.
