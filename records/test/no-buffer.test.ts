// The library as a browser runs it: with no Buffer. Node's global is taken away before the library
// loads; then a profile goes to two real hosts and is read back, by GET and by POST.

import assert from 'node:assert/strict'
import { test } from 'node:test'

// Node's own fetch (its built-in undici) reads the global Buffer, which a browser's fetch never
// needs, so Node's internals still see it. To everything else, this library and its dependencies
// included, Buffer is undefined.
const buffer = globalThis.Buffer
Object.defineProperty(globalThis, 'Buffer', { configurable: true, get: () => (/\(node:|at node:/.test(new Error().stack?.split('\n')[2] ?? '') ? buffer : undefined) })
const { publish, readProfile } = await import('../src/client.ts')
const { hostsRecord, ownerRecord } = await import('../src/write.ts')
const { T0, alice, offerBody, profileBody } = await import('./fixtures.ts')
const { startHost } = await import('./helpers.ts')

test('with no Buffer, a profile goes to two hosts and reads back whole, and no host fails', async () => {
  assert.equal(typeof Buffer, 'undefined')
  const [h1, h2] = await Promise.all([startHost({ now: () => T0 }), startHost({ now: () => T0 })])
  try {
    const urls = [h1.url, h2.url]
    const records = [hostsRecord(alice, urls, T0), ownerRecord(alice, 'profile', profileBody('calculus'), T0), ownerRecord(alice, 'offer/maths', offerBody('30'), T0)]
    for (const outcome of await publish(urls, records)) assert.ok(outcome.status === 200 && outcome.results.every((r) => r.ok), JSON.stringify(outcome))
    for (const post of [false, true]) {
      const v = await readProfile([h1.url], alice.address, T0, { post })
      assert.deepEqual(v.failed, [])
      assert.deepEqual(v.hosts, urls)
      assert.deepEqual([...v.current.keys()].sort(), ['hosts', 'offer/maths', 'profile'])
    }
  } finally {
    await Promise.all([h1.close(), h2.close()])
  }
})
