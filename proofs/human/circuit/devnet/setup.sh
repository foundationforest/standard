#!/usr/bin/env bash
# The person circuit's devnet setup. ONE party makes it: whoever runs this holds, for a moment, what
# it would take to make false proofs, so the files it writes are for devnet only. A public setup
# ceremony (many people contributing to the second phase, on the same first phase) comes before
# mainnet.
#
#   cd proofs/human/circuit && npm ci && devnet/setup.sh     # circom 2.2.3 on PATH, or in CIRCOM
#
# Phase 1 is public: PSE's Perpetual Powers of Tau, the same file and SHA-256 as the reputation
# circuit's. Phase 2 is one contribution: 64 random bytes drawn inside Node, never on a command
# line, to which snarkjs adds 64 more of its own. The script writes here person.zkey,
# person.wasm and verification-key.json, all committed, and setup.json, which pins every file by
# SHA-256, and rewrites the program's key, ../program/src/verifying_key.rs, from the new one.
# Running it again makes a new key, every hash in setup.json changes, and so does the program.
set -euo pipefail
cd "$(dirname "$0")/.."

PTAU=devnet/ppot_0080_16.ptau
PTAU_URL=https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_16.ptau
PTAU_SHA256=ed3622a7c79b0b49aadd134ebbc5b77df8c8c59bccebdfd0d9bf2c1a51561cf9
CIRCOM_LINUX_SHA256=85342c7ff332d948df7c0c50ecf201e6129349aef550ce873f3c811b79fe53a3

node scripts/compile.ts --new

[ -f "$PTAU" ] || curl -sSfL -o "$PTAU" "$PTAU_URL"
echo "$PTAU_SHA256  $PTAU" | sha256sum -c -

npx snarkjs groth16 setup build/person.r1cs "$PTAU" build/person_0000.zkey

CONTRIBUTION=$(node --input-type=module <<'JS'
import { randomBytes } from 'node:crypto'
import { zKey } from 'snarkjs'
const hash = await zKey.contribute('build/person_0000.zkey', 'devnet/person.zkey', 'devnet, one party', randomBytes(64).toString('hex'))
console.log(Buffer.from(hash).toString('hex'))
process.exit(0) // snarkjs keeps worker threads alive
JS
)
rm build/person_0000.zkey

npx snarkjs zkey verify build/person.r1cs "$PTAU" devnet/person.zkey
npx snarkjs zkey export verificationkey devnet/person.zkey devnet/verification-key.json
node scripts/parse_vk_to_rust.cjs devnet/verification-key.json ../program/src
cp build/person_js/person.wasm devnet/person.wasm

CONTRIBUTION="$CONTRIBUTION" PTAU_URL="$PTAU_URL" PTAU_SHA256="$PTAU_SHA256" \
CIRCOM_LINUX_SHA256="$CIRCOM_LINUX_SHA256" node --input-type=module <<'JS'
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
  note: "The person circuit's devnet setup. One party made it, so that party could make false proofs: devnet only. A public setup ceremony comes before mainnet. Made by devnet/setup.sh.",
  parties: 1,
  made: new Date().toISOString().slice(0, 10),
  circuit: { file: 'person.circom', constraints: (await r1cs.info('build/person.r1cs')).nConstraints },
  circom: { version: '2.2.3', linuxSha256: e.CIRCOM_LINUX_SHA256, flags: '--O2' },
  libraries: { snarkjs: version('snarkjs'), circomlib: version('circomlib') },
  phase1: { what: "PSE's Perpetual Powers of Tau, up to 2^16 constraints", url: e.PTAU_URL, sha256: e.PTAU_SHA256 },
  phase2: { contributions: 1, contributionHash: e.CONTRIBUTION },
  r1cs: pin('build/person.r1cs'),
  files: {
    'person.zkey': pin('devnet/person.zkey'),
    'person.wasm': pin('devnet/person.wasm'),
    'verification-key.json': pin('devnet/verification-key.json'),
  },
}
writeFileSync('devnet/setup.json', JSON.stringify(record, null, 2) + '\n')
console.log(JSON.stringify(record, null, 2))
process.exit(0)
JS
