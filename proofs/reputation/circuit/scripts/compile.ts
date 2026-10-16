// Compile the circuit and check it is the one the setup was made for.
//
//   npm run compile            # needs circom 2.2.3 on PATH, or its path in CIRCOM
//
// circom gives the same bytes every time for the same source, so the constraint system's and the
// witness generator's SHA-256 must equal the ones setup/setup.json recorded. If they do not, the
// source changed and no longer matches the published files. The witness generator also carries the
// source's line numbers, for its error messages, so even a line added to a comment shows up here:
// reputation.circom does not change after its setup. `--new` only compiles, for setup.sh.

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const CIRCOM_VERSION = '2.2.3'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const circom = process.env.CIRCOM ?? 'circom'
const sha256 = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex')
// A circuit library's directory, from this circuit's: npm installs it at the workspace's root.
const lib = (name: string, dir: string) =>
  relative(root, join(dirname(createRequire(import.meta.url).resolve(`${name}/package.json`)), dir))

const version = execFileSync(circom, ['--version'], { encoding: 'utf8' }).trim()
if (version !== `circom compiler ${CIRCOM_VERSION}`) {
  console.error(`need circom ${CIRCOM_VERSION}, found "${version}"`)
  process.exit(1)
}

mkdirSync(join(root, 'build'), { recursive: true })
execFileSync(
  circom,
  [
    'reputation.circom',
    '--O2',
    '--r1cs',
    '--wasm',
    '-l',
    lib('circomlib', 'circuits'),
    '-l',
    lib('@zk-kit/binary-merkle-root.circom', 'src'),
    '-o',
    'build',
  ],
  { cwd: root, stdio: ['ignore', 'inherit', 'inherit'] },
)

const got = {
  r1cs: sha256(join(root, 'build/reputation.r1cs')),
  wasm: sha256(join(root, 'build/reputation_js/reputation.wasm')),
}
console.log(`reputation.r1cs: ${got.r1cs}\nreputation.wasm: ${got.wasm}`)

if (!process.argv.includes('--new')) {
  const setup = JSON.parse(readFileSync(join(root, 'setup/setup.json'), 'utf8'))
  const want = { r1cs: setup.r1cs.sha256, wasm: setup.files['reputation.wasm'].sha256 }
  if (got.r1cs !== want.r1cs || got.wasm !== want.wasm) {
    console.error(`not the circuit the setup was made for:\n  want r1cs ${want.r1cs}\n  want wasm ${want.wasm}`)
    process.exit(1)
  }
  console.log('the circuit the setup was made for')
}
