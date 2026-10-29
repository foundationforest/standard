// Compile each circuit and check it is the one its setup was made for.
//
//   npm run compile                          # both; needs circom 2.2.3 on PATH, or its path in CIRCOM
//   node scripts/compile.ts verification     # one
//
// circom gives the same bytes every time for the same source, so the constraint system's and the
// witness generator's SHA-256 must equal the ones the circuit's setup/setup.json recorded. If they do
// not, the source changed and no longer matches the published files. The witness generator also
// carries the source's line numbers, for its error messages, so even a line added to a comment shows
// up here: a circuit does not change after its setup. `--new` only compiles, for setup.sh.

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const CIRCOM_VERSION = '2.2.3'

/** Each circuit, and the circuit libraries it includes: a package, and its directory of templates. */
const CIRCUITS: Record<string, Array<[string, string]>> = {
  verification: [['circomlib', 'circuits']],
  reputation: [['circomlib', 'circuits'], ['@zk-kit/binary-merkle-root.circom', 'src']],
}

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const circom = process.env.CIRCOM ?? 'circom'
const sha256 = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex')

const version = execFileSync(circom, ['--version'], { encoding: 'utf8' }).trim()
if (version !== `circom compiler ${CIRCOM_VERSION}`) {
  console.error(`need circom ${CIRCOM_VERSION}, found "${version}"`)
  process.exit(1)
}

const named = process.argv.slice(2).filter((a) => !a.startsWith('--'))
for (const name of named) {
  if (!(name in CIRCUITS)) {
    console.error(`no circuit ${name}: ${Object.keys(CIRCUITS).join(', ')}`)
    process.exit(1)
  }
}

let failed = false
for (const name of named.length ? named : Object.keys(CIRCUITS)) {
  // Compiled from the circuit's own directory, as its setup was.
  const dir = join(root, name)
  // A circuit library's directory, from the circuit's: npm installs it at the workspace's root.
  const lib = (pkg: string, sub: string) => relative(dir, join(dirname(createRequire(import.meta.url).resolve(`${pkg}/package.json`)), sub))
  mkdirSync(join(root, 'build'), { recursive: true })
  execFileSync(circom, [`${name}.circom`, '--O2', '--r1cs', '--wasm', ...CIRCUITS[name]!.flatMap(([pkg, sub]) => ['-l', lib(pkg, sub)]), '-o', relative(dir, join(root, 'build'))], {
    cwd: dir,
    stdio: ['ignore', 'inherit', 'inherit'],
  })

  const got = {
    r1cs: sha256(join(root, `build/${name}.r1cs`)),
    wasm: sha256(join(root, `build/${name}_js/${name}.wasm`)),
  }
  console.log(`${name}.r1cs: ${got.r1cs}\n${name}.wasm: ${got.wasm}`)

  if (!process.argv.includes('--new')) {
    const setup = JSON.parse(readFileSync(join(dir, 'setup/setup.json'), 'utf8'))
    const want = { r1cs: setup.r1cs.sha256, wasm: setup.files[`${name}.wasm`].sha256 }
    if (got.r1cs !== want.r1cs || got.wasm !== want.wasm) {
      console.error(`${name}: not the circuit the setup was made for:\n  want r1cs ${want.r1cs}\n  want wasm ${want.wasm}`)
      failed = true
    } else {
      console.log(`${name}: the circuit the setup was made for`)
    }
  }
}
if (failed) process.exit(1)
