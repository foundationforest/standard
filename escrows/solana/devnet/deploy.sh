#!/usr/bin/env bash
# Build the escrow for devnet and deploy it at its own address, or upgrade it in place. The earlier
# escrow programs on devnet, named in this record's `earlier`, are never touched: their ids are only
# read.
#
#   FOREST_DEVNET_SEED=<the phrase> escrows/solana/devnet/deploy.sh
#
# 1. Keys. Every devnet key comes from one phrase, so any machine holding it gets the same keys and
#    the same program id. The recipe, reproducible with any language's standard library:
#
#      phrase = FOREST_DEVNET_SEED, Unicode NFKD, trimmed, runs of whitespace made one space
#      seed   = PBKDF2-HMAC-SHA256(phrase, salt = "forest-devnet:" + label, 600,000 iterations, 32 bytes)
#      key    = the ed25519 keypair whose secret seed is `seed` (Solana's Keypair.fromSeed)
#
#    One label per key: `deploy` (pays for the deploy and keeps the upgrade authority), `payer`
#    (pays every fee and deposit in escrows/solana/client/scripts/devnet.ts, as a fee payer would), `buyer`,
#    `seller`, and `escrow-v2-program-2`, the program id (the closed first deploy used
#    `escrow-v2-program`). The keypair files go to FOREST_DEVNET_KEYS (default
#    ~/.forest-devnet/keys), never under the repo: the directory mode 700, the files 600, and a file
#    holding another key is refused, not overwritten. Only public keys are printed, and the phrase
#    is in no file. The public keys must be the ones escrows/solana/devnet/devnet.json names in `keys` (a
#    missing record is started with them), and the id must be no program this record or
#    registry/devnet/devnet.json names.
# 2. Build. escrows/solana/program's Cargo.toml, Cargo.lock and src are copied into
#    escrows/solana/devnet/target/ (ignored), `declare_id!` alone is replaced with the devnet id, checked to
#    appear exactly once, and the copy is built for SBPF v3.
# 3. Deploy a fresh id, or upgrade it in place when it holds other bytes (the same bytes are left
#    as they are): the exact cost computed first, the way Solana CLI 4.2.2 spends it, refused
#    (exit 3) if the deploy key holds less. Writes go over RPC.
# 4. Check the deployed bytes are the built ones, and record everything public in
#    escrows/solana/devnet/devnet.json. The check needs the same toolchain: Solana CLI 4.2.2,
#    cargo-build-sbf 4.1.0, platform-tools v1.54.
#
# FOREST_DEVNET_RPC points the Solana CLI at another devnet RPC; the record always names the
# public one, so a keyed URL never lands in the repo. Devnet is not sealed: the upgrade authority
# stays on the deploy key, and whoever holds the phrase holds it. Sealing is the mainnet step
# (`--final`, in escrows/solana/README.md). A new phrase starts from nothing: its deploy key needs SOL sent
# by hand, and the deals need a classic test dollar, the parties' token accounts and the buyer's
# dollars, which no script here makes.

set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
out="$here/target"
record="$here/devnet.json"
registry="$root/registry/devnet/devnet.json"
keys="${FOREST_DEVNET_KEYS:-$HOME/.forest-devnet/keys}"
rpc="${FOREST_DEVNET_RPC:-https://api.devnet.solana.com}"
[ -n "${FOREST_DEVNET_SEED:-}" ] || { echo "FOREST_DEVNET_SEED is missing or empty" >&2; exit 1; }
case "$(realpath -m "$keys")/" in
  "$root"/*) echo "refusing: $keys is inside the repo" >&2; exit 1 ;;
esac
mkdir -p "$keys" "$out"
chmod 700 "$keys"

# 1. Keys.
label=escrow-v2-program-2
node - "$keys" "$record" "$registry" "$label" <<'JS'
const crypto = require('crypto')
const fs = require('fs')
const [dir, own, registry, idLabel] = process.argv.slice(2)
const phrase = process.env.FOREST_DEVNET_SEED.normalize('NFKD').trim().split(/\s+/).join(' ')
// An ed25519 private key as PKCS#8 DER is this fixed prefix and the 32-byte seed.
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex')
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
function base58(bytes) {
  let n = BigInt('0x' + Buffer.from(bytes).toString('hex'))
  let s = ''
  while (n > 0n) { s = ALPHABET[Number(n % 58n)] + s; n /= 58n }
  for (const b of bytes) { if (b) break; s = '1' + s }
  return s
}
const pk = {}
for (const label of ['deploy', 'payer', 'buyer', 'seller', idLabel]) {
  const seed = crypto.pbkdf2Sync(Buffer.from(phrase, 'utf8'), Buffer.from(`forest-devnet:${label}`, 'utf8'), 600_000, 32, 'sha256')
  const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: 'der', type: 'pkcs8' })
  const pub = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32)
  const file = `${dir}/${label}.json`
  const body = JSON.stringify([...seed, ...pub])
  if (fs.existsSync(file) && fs.readFileSync(file, 'utf8').trim() !== body) throw new Error(`${file} holds another key; move it away first`)
  fs.writeFileSync(file, body, { mode: 0o600 })
  fs.chmodSync(file, 0o600)
  pk[label] = base58(pub)
}
const keys = { deploy: pk.deploy, payer: pk.payer, buyer: pk.buyer, seller: pk.seller }
const record = fs.existsSync(own) ? JSON.parse(fs.readFileSync(own, 'utf8')) : null
if (record) {
  for (const [name, key] of Object.entries(keys)) {
    if (record.keys?.[name] !== key) throw new Error(`the phrase gives ${name} key ${key}, not ${record.keys?.[name]}: another phrase`)
  }
} else {
  fs.writeFileSync(own, JSON.stringify({
    note: 'The devnet deploy of the escrow. Public keys, addresses and signatures only. Every key comes from the devnet phrase by the recipe in escrows/solana/devnet/deploy.sh, which writes the keypairs outside the repo and checks them against `keys`; the program id\'s label is escrow-v2-program-2. Written by escrows/solana/devnet/deploy.sh and escrows/solana/client/scripts/devnet.ts.',
    cluster: 'devnet',
    rpc: 'https://api.devnet.solana.com',
    keys,
  }, null, 2) + '\n')
}
const id = pk[idLabel]
const other = fs.existsSync(registry) ? JSON.parse(fs.readFileSync(registry, 'utf8')) : {}
const taken = [...(record?.earlier ?? []).map((e) => e.escrow.programId), other.registry?.programId, ...(other.earlier ?? []).map((e) => e.registry.programId)]
if (taken.includes(id)) throw new Error('the id is one already deployed for another program or version')
console.log(`escrow program id ${id}, deploy key ${pk.deploy}, payer ${pk.payer}, buyer ${pk.buyer}, seller ${pk.seller}`)
JS
id=$(solana-keygen pubkey "$keys/$label.json")
cli=(--url "$rpc" --keypair "$keys/deploy.json")
deployer=$(solana-keygen pubkey "$keys/deploy.json")

# 2. Build.
rm -rf "$out/program"
mkdir -p "$out/program"
cp "$root/escrows/solana/program/Cargo.toml" "$root/escrows/solana/program/Cargo.lock" "$out/program/"
cp -r "$root/escrows/solana/program/src" "$out/program/src"
node - "$out/program/src/lib.rs" "$id" <<'JS'
const fs = require('fs')
const [file, id] = process.argv.slice(2)
const from = 'declare_id!("FoRE2EscrowV2objectsTimerFundedAtPayer222222");'
const to = `declare_id!("${id}");`
const text = fs.readFileSync(file, 'utf8')
if (text.split(from).length !== 2) throw new Error(`${file}: expected exactly one ${from}`)
fs.writeFileSync(file, text.replace(from, to))
JS
echo "the substitution, against the committed source:"
diff -u "$root/escrows/solana/program/src/lib.rs" "$out/program/src/lib.rs" | grep -E '^[-+][^-+]' || true
others=$(diff -rq "$root/escrows/solana/program/src" "$out/program/src" | grep -v '/lib.rs and ' || true)
[ -z "$others" ] || { echo "more than lib.rs differs: $others" >&2; exit 1; }
(cd "$out/program" && cargo build-sbf --arch v3 >"$out/build.log" 2>&1) || { tail -40 "$out/build.log"; exit 1; }
so="$out/forest_escrow.so"
cp "$out/program/target/deploy/forest_escrow.so" "$so"
rm -f "$out/program/target/deploy/"*-keypair.json
built=$(sha256sum <"$so" | cut -d' ' -f1)
echo "built $(wc -c <"$so") bytes, SBPF v$(node -e "process.stdout.write(String(require('fs').readFileSync(process.argv[1]).readUInt32LE(0x30)))" "$so"), sha256 $built"

# 3. Deploy, or upgrade in place. A fresh id is deployed; an id already holding these bytes is left
#    as it is; an id holding other bytes is upgraded at the same address, its program data extended
#    first if the build is longer (the CLI's auto-extend). Either way the cost is computed first
#    and refused (exit 3) if the deploy key holds less. An upgrade holds a buffer's rent while it
#    writes, which comes back at the upgrade; it spends the fees and any extension's rent.
mode=deploy
if solana program show "$id" "${cli[@]}" --output json >"$out/before.json" 2>/dev/null; then
  solana program dump "$id" "$out/before.so" "${cli[@]}" >/dev/null
  if [ "$(head -c "$(wc -c <"$so")" "$out/before.so" | sha256sum | cut -d' ' -f1)" = "$built" ]; then
    mode=none
    echo "already deployed at $id, these bytes"
  else
    mode=upgrade
    echo "deployed at $id with other bytes: upgrading in place"
  fi
fi
if [ "$mode" != none ]; then
  cost=$(node - "$rpc" "$so" "$mode" "$out/before.json" <<'JS'
const fs = require('fs')
const [rpc, so, mode, beforePath] = process.argv.slice(2)
const bytes = fs.readFileSync(so)
const CHUNK = 1012 // Solana CLI 4.2.2: 1,232 minus an empty write transaction's 219 bytes, minus 1
let writes = 0
for (let at = 0; at < bytes.length; at += CHUNK) if (bytes.subarray(at, Math.min(at + CHUNK, bytes.length)).some((b) => b !== 0)) writes++
async function rent(size) {
  const r = await fetch(rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getMinimumBalanceForRentExemption', params: [size] }) })
  const j = await r.json()
  if (typeof j.result !== 'number') throw new Error(`getMinimumBalanceForRentExemption(${size}): ${JSON.stringify(j)}`)
  return j.result
}
;(async () => {
  const programDataRent = await rent(45 + bytes.length)
  if (mode === 'deploy') {
    const programRent = await rent(36)
    const fees = 10_000 + 5_000 * writes + 10_000
    console.log(JSON.stringify({ bytes: bytes.length, programDataRent, programRent, writes, fees, total: programDataRent + programRent + fees, spend: programDataRent + programRent + fees }))
    return
  }
  // The buffer (37 bytes of header), made with the payer and the buffer key signing; the writes;
  // the upgrade. If the build is longer than the program data holds, Solana CLI 4.2.2 extends it
  // in the upgrade's own transaction by at least 10,240 bytes (on 2026-09-30 it added 10,240 for
  // 768 needed), and that rent stays in the program data, back only if the program is closed.
  const before = JSON.parse(fs.readFileSync(beforePath, 'utf8'))
  const bufferRent = await rent(37 + bytes.length)
  const extendBytes = bytes.length > before.dataLen ? Math.max(bytes.length - before.dataLen, 10_240) : 0
  const extend = extendBytes > 0 ? Math.max(0, (await rent(45 + before.dataLen + extendBytes)) - before.lamports) : 0
  const fees = 10_000 + 5_000 * writes + 5_000
  console.log(JSON.stringify({ bytes: bytes.length, previousBytes: before.dataLen, extendBytes, bufferRent, extendRent: extend, writes, fees, total: bufferRent + extend + fees, spend: extend + fees }))
})()
JS
)
  need=$(node -e "process.stdout.write(String(JSON.parse(process.argv[1]).total))" "$cost")
  spend=$(node -e "process.stdout.write(String(JSON.parse(process.argv[1]).spend))" "$cost")
  have=$(solana balance "$deployer" "${cli[@]}" --lamports | cut -d' ' -f1)
  echo "cost $cost; the deploy key holds $have lamports"
  [ "$have" -ge "$need" ] || { echo "the deploy key holds less than the $mode needs; nothing sent" >&2; exit 3; }
  if [ "$mode" = deploy ]; then
    solana program deploy "${cli[@]}" --upgrade-authority "$keys/deploy.json" --program-id "$keys/$label.json" \
      --use-rpc --output json "$so" >"$out/deploy.json"
  else
    solana program deploy "${cli[@]}" --upgrade-authority "$keys/deploy.json" --program-id "$id" \
      --use-rpc --output json "$so" >"$out/deploy.json"
  fi
  after=$(solana balance "$deployer" "${cli[@]}" --lamports | cut -d' ' -f1)
  printf '{"cost":%s,"balanceBefore":%s,"balanceAfter":%s}\n' "$cost" "$have" "$after" >"$out/spend.json"
  echo "spent $((have - after)) lamports; computed $spend"
fi

# 4. Check and record.
solana program show "$id" "${cli[@]}" --output json >"$out/show.json"
solana program dump "$id" "$out/dumped.so" "${cli[@]}" >/dev/null
deployed=$(head -c "$(wc -c <"$so")" "$out/dumped.so" | sha256sum | cut -d' ' -f1)
[ "$built" = "$deployed" ] || { echo "the deployed bytes are not the built ones" >&2; exit 1; }
echo "deployed bytes match the build ($built)"

node - "$record" "$out" "$id" "$built" "$so" "$mode" <<'JS'
const fs = require('fs')
const [recordPath, out, id, sha, so, mode] = process.argv.slice(2)
const record = JSON.parse(fs.readFileSync(recordPath, 'utf8'))
const show = JSON.parse(fs.readFileSync(`${out}/show.json`, 'utf8'))
const p = (record.escrow ??= {})
p.programId = id
p.programData = show.programdataAddress
p.upgradeAuthority = show.authority
p.lastDeploySlot = show.lastDeploySlot
p.soSha256 = sha
p.soBytes = fs.statSync(so).size
p.sbpfVersion = `v${fs.readFileSync(so).readUInt32LE(0x30)}`
if (mode !== 'none') {
  const d = JSON.parse(fs.readFileSync(`${out}/deploy.json`, 'utf8'))
  const s = JSON.parse(fs.readFileSync(`${out}/spend.json`, 'utf8'))
  const cost = { ...s.cost, balanceBefore: s.balanceBefore, balanceAfter: s.balanceAfter, spent: s.balanceBefore - s.balanceAfter }
  record.transactions ??= []
  if (mode === 'deploy') {
    p.deploySignature = d.signature
    p.deployCost = cost
    record.transactions.push({ program: 'escrow-v2', what: `deploy: the escrow (SBPF ${p.sbpfVersion}), upgrade authority kept on the deploy key`, signature: d.signature })
  } else {
    p.upgrades ??= []
    p.upgrades.push({ slot: show.lastDeploySlot, signature: d.signature, soSha256: sha, soBytes: p.soBytes, cost })
    record.transactions.push({ program: 'escrow-v2', what: `upgrade in place: the escrow, now ${p.soBytes} bytes (sha256 ${sha.slice(0, 16)}…), same address`, signature: d.signature })
  }
}
fs.writeFileSync(recordPath, JSON.stringify(record, null, 2) + '\n')
JS
echo "recorded in $record"
