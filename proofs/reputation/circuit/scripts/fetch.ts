// Fetch the devnet setup's proving key and witness generator, and check them against their hashes.
//
//   npm run fetch
//
// The verification key is committed (devnet/verification-key.json, a few kB). The proving key and
// the witness generator are about 30 MB and only ever used to make a proof, so they sit in a GitHub
// release, pinned by SHA-256 in devnet/setup.json. A file that does not match its hash is deleted
// rather than kept.

import { createHash } from 'node:crypto'
import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

type Entry = { bytes: number; sha256: string }

const devnet = join(dirname(fileURLToPath(import.meta.url)), '../devnet')
const setup = JSON.parse(readFileSync(join(devnet, 'setup.json'), 'utf8')) as {
  release: { baseUrl: string }
  files: Record<string, Entry>
  committed: Record<string, Entry>
}

const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex')

let failed = false
for (const [name, entry] of Object.entries(setup.files)) {
  const path = join(devnet, name)
  if (existsSync(path) && sha256(readFileSync(path)) === entry.sha256) {
    console.log(`${name}: already here and correct`)
    continue
  }
  const url = `${setup.release.baseUrl}${name}`
  process.stdout.write(`${name}: fetching ${url} ... `)
  const response = await fetch(url)
  if (!response.ok) {
    console.log(`HTTP ${response.status}`)
    failed = true
    continue
  }
  const bytes = Buffer.from(await response.arrayBuffer())
  const got = sha256(bytes)
  if (got !== entry.sha256) {
    console.log(`\n  WRONG HASH\n  want ${entry.sha256}\n  got  ${got}`)
    failed = true
    continue
  }
  writeFileSync(path, bytes)
  console.log(`${bytes.length} bytes, hash matches`)
}

for (const [name, entry] of Object.entries(setup.committed)) {
  const path = join(devnet, name)
  const got = existsSync(path) ? sha256(readFileSync(path)) : 'missing'
  if (got !== entry.sha256) {
    console.log(`${name}: WRONG, want ${entry.sha256}, got ${got}`)
    failed = true
  } else {
    console.log(`${name}: committed, hash matches`)
  }
}

if (failed) {
  for (const [name, entry] of Object.entries(setup.files)) {
    const path = join(devnet, name)
    if (existsSync(path) && sha256(readFileSync(path)) !== entry.sha256) unlinkSync(path)
  }
  process.exit(1)
}
