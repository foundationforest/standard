// Compile the circuit and check it is the one the devnet setup was made for.
//
//   npm run compile            # needs circom 2.2.3 on PATH, or its path in CIRCOM
//
// circom gives the same bytes every time for the same source, so the constraint system's and the
// witness generator's SHA-256 must equal the ones devnet/setup.json recorded. If they do not, the
// source changed and no longer matches the published files. The witness generator also carries the
// source's line numbers, for its error messages, so even a line added to a comment shows up here:
// person.circom does not change after its setup. `--new` only compiles, for setup.sh.

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const CIRCOM_VERSION = '2.2.3'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const circom = process.env.CIRCOM ?? 'circom'
const sha256 = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex')

const version = execFileSync(circom, ['--version'], { encoding: 'utf8' }).trim()
if (version !== `circom compiler ${CIRCOM_VERSION}`) {
  console.error(`need circom ${CIRCOM_VERSION}, found "${version}"`)
  process.exit(1)
}

mkdirSync(join(root, 'build'), { recursive: true })
execFileSync(
  circom,
  [
    'person.circom',
    '--O2',
    '--r1cs',
    '--wasm',
    '-l',
    'node_modules/circomlib/circuits',
    '-o',
    'build',
  ],
  { cwd: root, stdio: ['ignore', 'inherit', 'inherit'] },
)

const got = {
  r1cs: sha256(join(root, 'build/person.r1cs')),
  wasm: sha256(join(root, 'build/person_js/person.wasm')),
}
console.log(`person.r1cs: ${got.r1cs}\nperson.wasm: ${got.wasm}`)

if (!process.argv.includes('--new')) {
  const setup = JSON.parse(readFileSync(join(root, 'devnet/setup.json'), 'utf8'))
  const want = { r1cs: setup.r1cs.sha256, wasm: setup.files['person.wasm'].sha256 }
  if (got.r1cs !== want.r1cs || got.wasm !== want.wasm) {
    console.error(`not the circuit the setup was made for:\n  want r1cs ${want.r1cs}\n  want wasm ${want.wasm}`)
    process.exit(1)
  }
  console.log('the circuit the devnet setup was made for')
}
