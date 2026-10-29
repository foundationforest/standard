// Files: bytes an entry names. A host takes them, uploaded by their hash, only while a current
// entry it holds names them, with their type and size; anyone fetches them by hash and checks it.
// Here, the client's side, against the minimal host (host.ts); what a host checks on an upload is
// the host check's (check.test.ts).

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { fetchFile, readFolder, upload, write } from '../src/client.ts'
import { type FileName, fileOf, filesOf } from '../src/files.ts'
import { entry } from '../src/write.ts'
import { T0, alice, asAccess, listed, profileBody } from './fixtures.ts'
import { startHost } from './helpers.ts'
import type { TestHost } from './host.ts'

const bytesOf = (seed: number, length = 2000) => Uint8Array.from({ length }, (_, i) => (i * 7 + seed * 13) & 255)
/** One host's answer, as its error code, or its message, or ok. */
const answer = (outcomes: Array<{ ok: boolean; error?: string; message?: string }>) => outcomes[0]!.error ?? outcomes[0]!.message ?? 'ok'
const up = async (h: TestHost, bytes: Uint8Array, type = 'image/jpeg') => answer(await upload([h.url], bytes, type))

const photo = bytesOf(1)
const clip = bytesOf(2, 5000)

describe('files', () => {
  test('a photo is an entry whose body is its file: its hosts take the bytes it names, and a reader follows the entry to them, with their type', async () => {
    const h1 = await startHost({ now: () => T0 })
    const h2 = await startHost({ now: () => T0 })
    try {
      const hosts = [h1.url, h2.url]
      const name = fileOf(photo, 'image/jpeg')
      await write(hosts, [entry(alice, 'profile', profileBody('photos', { hosts }), T0), entry(alice, 'photo/1', { files: [name] }, T0), entry(alice, 'offer/video', { about: 'a clip', files: [fileOf(clip, 'video/mp4')] }, T0)])
      assert.deepEqual((await upload(hosts, photo, 'image/jpeg')).map((o) => [o.status, o.ok]), [[200, true], [200, true]])
      assert.deepEqual((await upload(hosts, clip, 'video/mp4')).map((o) => o.ok), [true, true])
      assert.equal(await up(h1, photo), 'already here')

      const folder = await readFolder([h1.url], alice.address, T0)
      const named = filesOf(folder.current.get('photo/1')!.entry.body)[0]!
      const got = await fetchFile(folder.hosts, named.sha256)
      assert.deepEqual([got!.bytes, got!.type], [photo, 'image/jpeg'])
      const res = await fetch(`${h2.url}/v1/files/${fileOf(clip, 'video/mp4').sha256}`)
      assert.deepEqual([res.status, res.headers.get('content-type'), new Uint8Array(await res.arrayBuffer())], [200, 'video/mp4', clip])
    } finally {
      await h1.close()
      await h2.close()
    }
  })

  test('bytes no current entry names are refused [unnamed]: not before the entry, not after it is replaced or deleted, not named by a key no longer listed', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      assert.equal(await up(h, photo), 'unnamed', 'no entry names it yet')
      await write([h.url], [entry(alice, 'photo/1', { files: [fileOf(photo, 'image/jpeg')] }, T0), entry(alice, 'photo/1', null, T0 + 1)])
      assert.equal(await up(h, photo), 'unnamed', 'the entry that named it was deleted')
      // An access key's entry names it, while the profile entry lists the key with write; then not.
      const later = bytesOf(3, 10)
      await write([h.url], [entry(alice, 'profile', profileBody('photos', { hosts: [h.url], keys: [listed(['write'])] }), T0), entry(asAccess, 'photo/2', { files: [fileOf(clip, 'video/mp4'), fileOf(later, 'video/mp4')] }, T0)])
      assert.equal(await up(h, clip, 'video/mp4'), 'ok')
      await write([h.url], [entry(alice, 'profile', profileBody('photos', { hosts: [h.url] }), T0 + 2)])
      assert.equal(h.view(alice.address).current.get('photo/2'), undefined, 'the key’s entry no longer counts')
      assert.equal(await up(h, later, 'video/mp4'), 'unnamed', 'so what only it names is named by no current entry')
    } finally {
      await h.close()
    }
  })

  test('a file is named by its SHA-256 in lowercase hex, its type, type/subtype in lower case, and its size; bytes of another type or size are refused [shape]', async () => {
    for (const type of ['image/png', 'image/gif', 'image/svg+xml', 'application/vnd.oasis.opendocument.text', 'a/' + 'b'.repeat(253)]) assert.equal(fileOf(photo, type).type, type)
    for (const type of ['Image/PNG', 'image', 'image/', '/png', 'image/png; charset=x', 'image/p ng', '', 'a/' + 'b'.repeat(254)]) assert.throws(() => fileOf(photo, type), /type/)
    assert.equal(fileOf(bytesOf(9, 0), 'image/png').size, 0, 'empty bytes are a file too')
    const h = await startHost({ now: () => T0 })
    try {
      const name: FileName = fileOf(photo, 'image/jpeg')
      await write([h.url], [entry(alice, 'photo/1', { files: [name] }, T0)])
      assert.equal(await up(h, photo, 'image/png'), 'shape')
      const res = await fetch(`${h.url}/v1/files/${name.sha256}`, { method: 'PUT', headers: { 'content-type': 'image/jpeg' }, body: photo.subarray(1) })
      assert.equal(((await res.json()) as { error: string }).error, 'shape')
    } finally {
      await h.close()
    }
  })

  test('a reader checks the hash: a host serving other bytes, or more than the reader takes, is skipped', async () => {
    const good = await startHost({ now: () => T0 })
    const bad = await startHost({ now: () => T0 })
    try {
      const hosts = [good.url, bad.url]
      await write(hosts, [entry(alice, 'photo/1', { files: [fileOf(photo, 'image/jpeg')] }, T0)])
      assert.deepEqual((await upload(hosts, photo, 'image/jpeg')).map((o) => o.ok), [true, true])
      const name = fileOf(photo, 'image/jpeg').sha256
      bad.fetchFile = async () => ({ type: 'image/jpeg', bytes: clip })
      assert.equal(await fetchFile([bad.url], name), null)
      assert.equal((await fetchFile([bad.url, good.url], name))!.host, good.url)
      assert.equal(await fetchFile([good.url], name, { maxBytes: 100 }), null)
      assert.equal(await fetchFile(['http://127.0.0.1:1', good.url], name).then((g) => g!.host), good.url, 'a host that does not answer is skipped')
    } finally {
      await good.close()
      await bad.close()
    }
  })
})
