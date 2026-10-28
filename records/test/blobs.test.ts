// Blobs: bytes a folder holds. Its main key puts them with a signed request, and they stay until it
// deletes them, whatever the folder's records say. Here, the client's side, against the minimal host
// (host.ts); what a host checks on a put or a delete is the host check's (check.test.ts). A reader
// checks the hash, whatever host served them.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { deleteBlob, getBlob, publish, putBlob, readProfile } from '../src/client.ts'
import type { Key } from '../src/keys.ts'
import { type SignedBlobRequest, blobNameOf, blobRequest } from '../src/message.ts'
import { hostsRecord, ownerRecord } from '../src/write.ts'
import { MINUTE, T0, alice, offerBody } from './fixtures.ts'
import { Clock, startHost } from './helpers.ts'
import type { TestHost } from './host.ts'

const bytesOf = (seed: number, length = 2000) => Uint8Array.from({ length }, (_, i) => (i * 7 + seed * 13) & 255)
const nameOf = (bytes: Uint8Array) => blobNameOf(bytes, 'image/jpeg').sha256
const putOf = (key: Key, bytes: Uint8Array, type = 'image/jpeg', time = T0) => blobRequest(key, { action: 'put', ...blobNameOf(bytes, type) }, time) as SignedBlobRequest & { action: 'put' }
const deleteOf = (key: Key, bytes: Uint8Array, time = T0) => blobRequest(key, { action: 'delete', sha256: nameOf(bytes) }, time) as SignedBlobRequest & { action: 'delete' }
/** One host's answer, as its error code, or its message, or ok. */
const answer = (outcomes: Array<{ ok: boolean; error?: string; message?: string }>) => outcomes[0]!.error ?? outcomes[0]!.message ?? 'ok'
const put = async (h: TestHost, key: Key, bytes: Uint8Array, type = 'image/jpeg') => answer(await putBlob([h.url], putOf(key, bytes, type), bytes))
const del = async (h: TestHost, key: Key, bytes: Uint8Array) => answer(await deleteBlob([h.url], deleteOf(key, bytes)))

const photo = bytesOf(1)
const clip = bytesOf(2, 5000)

describe('blobs', () => {
  test('a folder’s main key puts bytes on its hosts; a reader follows a record’s reference to them, and gets their type', async () => {
    const h1 = await startHost({ now: () => T0 })
    const h2 = await startHost({ now: () => T0 })
    try {
      const hosts = [h1.url, h2.url]
      // Where a record points at a blob is the market's: here a field of its own, `files`.
      await publish(hosts, [hostsRecord(alice, hosts, T0), ownerRecord(alice, 'offer/photo', { ...offerBody('photo'), files: [blobNameOf(photo, 'image/jpeg')] }, T0)])
      assert.deepEqual((await putBlob(hosts, putOf(alice, photo), photo)).map((o) => [o.status, o.ok]), [[200, true], [200, true]])
      assert.deepEqual((await putBlob(hosts, putOf(alice, clip, 'video/mp4'), clip)).map((o) => o.ok), [true, true])
      assert.equal(await put(h1, alice, photo), 'already here')

      const view = await readProfile([h1.url], alice.address, T0)
      const named = (view.current.get('offer/photo')!.record.body!.files as Array<{ sha256: string }>)[0]!
      const got = await getBlob(view.hosts, named.sha256)
      assert.deepEqual([got!.bytes, got!.type], [photo, 'image/jpeg'])
      const res = await fetch(`${h2.url}/v1/blobs/${nameOf(clip)}`)
      assert.deepEqual([res.status, res.headers.get('content-type'), new Uint8Array(await res.arrayBuffer())], [200, 'video/mp4', clip])
    } finally {
      await h1.close()
      await h2.close()
    }
  })

  test('they stay whatever the records say: none need name them, and a record that did, replaced or deleted, changes nothing', async () => {
    const clock = new Clock(T0)
    const h = await startHost({ now: clock.now })
    try {
      assert.equal(await put(h, alice, clip, 'video/mp4'), 'ok', 'no record names it')
      await publish([h.url], [ownerRecord(alice, 'offer/a', { ...offerBody('a'), files: [blobNameOf(photo, 'image/jpeg')] }, T0)])
      assert.equal(await put(h, alice, photo), 'ok')
      await publish([h.url], [ownerRecord(alice, 'offer/a', offerBody('b'), clock.advance(MINUTE)), ownerRecord(alice, 'offer/a', null, clock.advance(MINUTE))])
      assert.ok(await h.getBlob(nameOf(photo)), 'the record that named it, replaced and deleted')
      assert.ok(await h.getBlob(nameOf(clip)))
      assert.equal(await del(h, alice, photo), 'ok', 'until the main key deletes them')
      assert.equal(await h.getBlob(nameOf(photo)), undefined)
    } finally {
      await h.close()
    }
  })

  test('a blob is named by its SHA-256 in lowercase hex, its type, type/subtype in lower case, and its size; which types and how large is each host’s', () => {
    const shape = (request: () => unknown) => assert.throws(request, (err: Error & { code?: string }) => err.code === 'shape')
    for (const type of ['image/png', 'image/gif', 'image/svg+xml', 'application/vnd.oasis.opendocument.text', 'a/' + 'b'.repeat(253)]) {
      assert.equal(putOf(alice, photo, type).mimeType, type)
    }
    for (const type of ['Image/PNG', 'image', 'image/', '/png', 'image/png; charset=x', 'image/p ng', '', 'a/' + 'b'.repeat(254)]) shape(() => putOf(alice, photo, type))
    const name = blobNameOf(photo, 'image/jpeg')
    shape(() => blobRequest(alice, { action: 'put', ...name, size: -1 }, T0))
    shape(() => blobRequest(alice, { action: 'put', ...name, size: 1.5 }, T0))
    shape(() => blobRequest(alice, { action: 'put', ...name, sha256: name.sha256.toUpperCase() }, T0))
    shape(() => blobRequest(alice, { action: 'delete', sha256: name.sha256.slice(1) }, T0))
    shape(() => blobRequest(alice, { action: 'put', ...name, ref: 'bafkrei…' } as never, T0))
    shape(() => blobRequest(alice, { action: 'delete', sha256: name.sha256, mimeType: 'image/jpeg' } as never, T0))
    assert.equal(putOf(alice, bytesOf(9, 0)).size, 0, 'empty bytes are a blob too')
  })

  test('a reader checks the hash: a host serving other bytes, or more than the reader takes, is skipped', async () => {
    const good = await startHost({ now: () => T0 })
    const bad = await startHost({ now: () => T0 })
    try {
      assert.deepEqual((await putBlob([good.url, bad.url], putOf(alice, photo), photo)).map((o) => o.ok), [true, true])
      bad.getBlob = async () => ({ type: 'image/jpeg', bytes: clip })
      assert.equal(await getBlob([bad.url], nameOf(photo)), null)
      assert.equal((await getBlob([bad.url, good.url], nameOf(photo)))!.host, good.url)
      assert.equal(await getBlob([good.url], nameOf(photo), { maxBytes: 100 }), null)
      assert.equal(await getBlob(['http://127.0.0.1:1', good.url], nameOf(photo)).then((g) => g!.host), good.url, 'a host that does not answer is skipped')
    } finally {
      await good.close()
      await bad.close()
    }
  })
})
