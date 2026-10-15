#!/usr/bin/env bash
# The reputation circuit's devnet setup. ONE party makes it: whoever runs this holds, for a moment,
# what it would take to make false proofs, so the files it writes are for devnet only. A public
# setup ceremony (many people contributing to the second phase, on the same first phase) comes
# before mainnet.
#
#   cd proofs/reputation/circuit && npm ci && devnet/setup.sh     # circom 2.2.3 on PATH, or in CIRCOM
#
# Phase 1 is public: PSE's Perpetual Powers of Tau, pinned below by SHA-256. Phase 2 is one
# contribution: 64 random bytes drawn inside Node, never on a command line, to which snarkjs adds
# 64 more of its own. The script writes here reputation.zkey and reputation.wasm (not committed:
# they go in the GitHub release named in setup.json), verification-key.json, and setup.json, which
# pins every file by SHA-256. Running it again makes a new key, and every hash in setup.json changes.
set -euo pipefail
cd "$(dirname "$0")/.."

PTAU=devnet/ppot_0080_16.ptau
PTAU_URL=https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_16.ptau
PTAU_SHA256=ed3622a7c79b0b49aadd134ebbc5b77df8c8c59bccebdfd0d9bf2c1a51561cf9
CIRCOM_LINUX_SHA256=85342c7ff332d948df7c0c50ecf201e6129349aef550ce873f3c811b79fe53a3
TAG=reputation-devnet-3

node scripts/compile.ts --new

[ -f "$PTAU" ] || curl -sSfL -o "$PTAU" "$PTAU_URL"
echo "$PTAU_SHA256  $PTAU" | sha256sum -c -

npx snarkjs groth16 setup build/reputation.r1cs "$PTAU" build/reputation_0000.zkey

CONTRIBUTION=$(node --input-type=module <<'EOF'
import { randomBytes } from 'node:crypto'
import { zKey } from 'snarkjs'
const hash = await zKey.contribute('build/reputation_0000.zkey', 'devnet/reputation.zkey', 'devnet, one party', randomBytes(64).toString('hex'))
console.log(Buffer.from(hash).toString('hex'))
process.exit(0) // snarkjs keeps worker threads alive
EOF
)
rm build/reputation_0000.zkey

npx snarkjs zkey verify build/reputation.r1cs "$PTAU" devnet/reputation.zkey
npx snarkjs zkey export verificationkey devnet/reputation.zkey devnet/verification-key.json
cp build/reputation_js/reputation.wasm devnet/reputation.wasm

CONTRIBUTION="$CONTRIBUTION" PTAU="$PTAU" PTAU_URL="$PTAU_URL" PTAU_SHA256="$PTAU_SHA256" \
CIRCOM_LINUX_SHA256="$CIRCOM_LINUX_SHA256" TAG="$TAG" node --input-type=module <<'EOF'
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync } from 'node:fs'
import { r1cs } from 'snarkjs'

const e = process.env
const pin = (path) => {
  const bytes = readFileSync(path)
  return { bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }
}
const lock = JSON.parse(readFileSync('package-lock.json', 'utf8')).packages
const version = (name) => lock[`node_modules/${name}`].version
const record = {
  note: "The reputation circuit's devnet setup. One party made it, so that party could make false proofs: devnet only. A public setup ceremony comes before mainnet. Made by devnet/setup.sh.",
  parties: 1,
  made: new Date().toISOString().slice(0, 10),
  circuit: { file: 'reputation.circom', slots: 8, depth: 20, constraints: (await r1cs.info('build/reputation.r1cs')).nConstraints },
  circom: { version: '2.2.3', linuxSha256: e.CIRCOM_LINUX_SHA256, flags: '--O2' },
  libraries: { snarkjs: version('snarkjs'), circomlib: version('circomlib'), '@zk-kit/binary-merkle-root.circom': version('@zk-kit/binary-merkle-root.circom') },
  phase1: { what: "PSE's Perpetual Powers of Tau, up to 2^16 constraints", url: e.PTAU_URL, sha256: e.PTAU_SHA256 },
  phase2: { contributions: 1, contributionHash: e.CONTRIBUTION },
  r1cs: pin('build/reputation.r1cs'),
  release: { tag: e.TAG, baseUrl: `https://github.com/foundationforest/standard/releases/download/${e.TAG}/` },
  files: { 'reputation.zkey': pin('devnet/reputation.zkey'), 'reputation.wasm': pin('devnet/reputation.wasm') },
  committed: { 'verification-key.json': pin('devnet/verification-key.json') },
}
writeFileSync('devnet/setup.json', JSON.stringify(record, null, 2) + '\n')
console.log(JSON.stringify(record, null, 2))
process.exit(0)
EOF
