// Check the setup's files against their hashes.
//
//   npm run fetch
//
// The proving key, the witness generator and the verification key are a few MB together, so all of
// them are committed in setup/, pinned by SHA-256 in setup/setup.json. Nothing is downloaded: a
// file that does not match its hash fails, and is never used to prove.

import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

type Entry = { bytes: number; sha256: string }

const dir = join(dirname(fileURLToPath(import.meta.url)), '../setup')
const setup = JSON.parse(readFileSync(join(dir, 'setup.json'), 'utf8')) as { files: Record<string, Entry> }

let failed = false
for (const [name, entry] of Object.entries(setup.files)) {
  const path = join(dir, name)
  const got = existsSync(path) ? createHash('sha256').update(readFileSync(path)).digest('hex') : 'missing'
  if (got !== entry.sha256) {
    console.log(`${name}: WRONG, want ${entry.sha256}, got ${got}`)
    failed = true
  } else {
    console.log(`${name}: committed, hash matches`)
  }
}
if (failed) process.exit(1)
