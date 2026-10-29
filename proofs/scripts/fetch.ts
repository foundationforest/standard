// Check each circuit's setup files against their hashes.
//
//   npm run fetch
//
// Each circuit's proving key, witness generator and verification key are committed in its setup/,
// pinned by SHA-256 in its setup/setup.json. Nothing is downloaded: a file that does not match its
// hash fails, and is never used to prove.

import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

type Entry = { bytes: number; sha256: string }

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

let failed = false
for (const circuit of ['verification', 'reputation']) {
  const dir = join(root, circuit, 'setup')
  const setup = JSON.parse(readFileSync(join(dir, 'setup.json'), 'utf8')) as { files: Record<string, Entry> }
  for (const [name, entry] of Object.entries(setup.files)) {
    const path = join(dir, name)
    const got = existsSync(path) ? createHash('sha256').update(readFileSync(path)).digest('hex') : 'missing'
    if (got !== entry.sha256) {
      console.log(`${circuit}/setup/${name}: WRONG, want ${entry.sha256}, got ${got}`)
      failed = true
    } else {
      console.log(`${circuit}/setup/${name}: committed, hash matches`)
    }
  }
}
if (failed) process.exit(1)
