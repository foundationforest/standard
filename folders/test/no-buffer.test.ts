// The library as a browser runs it: with no Buffer. Node's global is taken away before the library
// loads; then a folder goes to two real hosts and is read back, one folder's and everyone's.

import assert from 'node:assert/strict'
import { test } from 'node:test'

// Node's own fetch (its built-in undici) reads the global Buffer, which a browser's fetch never
// needs, so Node's internals still see it. To everything else, this library and its dependencies
// included, Buffer is undefined.
const buffer = globalThis.Buffer
Object.defineProperty(globalThis, 'Buffer', { configurable: true, get: () => (/\(node:|at node:/.test(new Error().stack?.split('\n')[2] ?? '') ? buffer : undefined) })
const { readAll, readFolder, write } = await import('../src/client.ts')
const { entry } = await import('../src/write.ts')
const { T0, alice, asAccess, listed, offerBody, profileBody } = await import('./fixtures.ts')
const { startHost } = await import('./helpers.ts')

test('with no Buffer, a folder goes to two hosts and reads back whole, and no host fails', async () => {
  assert.equal(typeof Buffer, 'undefined')
  const [h1, h2] = await Promise.all([startHost({ now: () => T0 }), startHost({ now: () => T0 })])
  try {
    const urls = [h1.url, h2.url]
    const entries = [entry(alice, 'profile', profileBody('calculus', { hosts: urls, keys: [listed(['write'])] }), T0), entry(alice, 'offer/maths', offerBody('30'), T0), entry(asAccess, 'offer/physics', offerBody('35'), T0)]
    for (const outcome of await write(urls, entries)) assert.ok(outcome.status === 200 && outcome.results.every((r) => r.ok), JSON.stringify(outcome))
    const v = await readFolder([h1.url], alice.address, T0)
    assert.deepEqual(v.failed, [])
    assert.deepEqual(v.hosts, urls)
    assert.deepEqual([...v.current.keys()].sort(), ['offer/maths', 'offer/physics', 'profile'])
    assert.equal((await readAll(h2.url)).entries.length, 3)
  } finally {
    await Promise.all([h1.close(), h2.close()])
  }
})
