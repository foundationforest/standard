// The host check, against a host's address: `npm run check-host -- https://host.example`. It
// writes to the host from two profiles of a new seed; SEED, 64 hex characters, gives instead a
// seed whose folders under check/a and check/b the host holds already, for a host that charges to
// join. Each check prints ok, unchecked (what the host refused by its own choice stopped it) or
// FAILED; it exits 1 if any failed.

import { hex } from '../src/bytes.ts'
import { checkHost } from '../src/check.ts'

const url = process.argv[2]
if (!url) {
  console.error('npm run check-host -- <the host’s address>')
  process.exit(2)
}
const results = await checkHost(url, process.env.SEED ? { seed: hex.decode(process.env.SEED) } : {})
for (const r of results) console.log(`${r.status === 'failed' ? 'FAILED' : r.status}: ${r.name}${r.why ? `. ${r.why}` : ''}`)
process.exit(results.some((r) => r.status === 'failed') ? 1 : 0)
