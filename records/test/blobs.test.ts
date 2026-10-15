// Blobs: bytes a record names by SHA-256, kept by the hosts that keep the record. Post the record,
// then the bytes. A host refuses bytes that do not hash to their name, bytes no current record
// names as that type, and what its own choice will not take; once no current record names them,
// it drops them after its keep days. A reader checks the hash, whatever host served them.

import assert from 'node:assert/strict'
import { connect } from 'node:net'
import { describe, test } from 'node:test'
import { sha256 } from '@noble/hashes/sha2.js'
import { hex } from '../src/bytes.ts'
import { getBlob, publish, putBlob, readProfile } from '../src/client.ts'
import type { Host } from '../src/host.ts'
import type { Body } from '../src/record.ts'
import { accessRecord, hostsRecord, ownerRecord, permissionsRecord } from '../src/write.ts'
import { DAY, T0, accessKey, alice, allow, bob, offerBody } from './fixtures.ts'
import { Clock, startHost } from './helpers.ts'

const bytesOf = (seed: number, length = 2000) => Uint8Array.from({ length }, (_, i) => (i * 7 + seed * 13) & 255)
const nameOf = (bytes: Uint8Array) => hex.encode(sha256(bytes))
const ref = (bytes: Uint8Array, mimeType: string) => ({ sha256: nameOf(bytes), mimeType, size: bytes.length })
const withMedia = (...media: Array<[Uint8Array, string]>): Body => ({ ...offerBody('30'), media: media.map(([b, t]) => ref(b, t)) })
/** An offer with one photo, at offer/photo. */
const withPhoto = (bytes: Uint8Array, mimeType = 'image/jpeg'): Body => withMedia([bytes, mimeType])
const put = async (h: Host, bytes: Uint8Array, type: string) => {
  const [outcome] = await putBlob([h.url], bytes, type)
  return outcome!.error ?? 'ok'
}

const photo = bytesOf(1)
const clip = bytesOf(2, 5000)

describe('blobs', () => {
  test('post the record, then its bytes; a reader gets them from the record’s hosts, with the type the record names', async () => {
    const h1 = await startHost({ now: () => T0 })
    const h2 = await startHost({ now: () => T0 })
    try {
      const hosts = [h1.url, h2.url]
      await publish(hosts, [hostsRecord(alice, hosts, T0), ownerRecord(alice, 'offer/photo', withPhoto(photo), T0), ownerRecord(alice, 'offer/maths', withMedia([clip, 'video/mp4']), T0)])
      assert.deepEqual((await putBlob(hosts, photo, 'image/jpeg')).map((o) => [o.status, o.ok]), [[200, true], [200, true]])
      assert.deepEqual((await putBlob(hosts, clip, 'video/mp4')).map((o) => o.ok), [true, true])
      assert.deepEqual((await putBlob([h1.url], photo, 'image/jpeg'))[0]!.message, 'already here')

      const view = await readProfile([h1.url], alice.address, T0)
      const named = (view.current.get('offer/photo')!.record.body!.media as Array<{ sha256: string }>)[0]!
      const got = await getBlob(view.hosts, named.sha256)
      assert.deepEqual([got!.bytes, got!.type], [photo, 'image/jpeg'])
      const res = await fetch(`${h2.url}/v1/blobs/${nameOf(clip)}`)
      assert.deepEqual([res.status, res.headers.get('content-type'), new Uint8Array(await res.arrayBuffer())], [200, 'video/mp4', clip])
    } finally {
      await h1.close()
      await h2.close()
    }
  })

  test('a host refuses bytes that do not hash to their name, bytes no current record names, and a type the record does not give them', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      const wrong = await fetch(`${h.url}/v1/blobs/${nameOf(photo)}`, { method: 'PUT', headers: { 'content-type': 'image/jpeg' }, body: clip })
      assert.deepEqual([wrong.status, ((await wrong.json()) as { error: string }).error], [400, 'hash'])
      assert.equal(await put(h, photo, 'image/jpeg'), 'unnamed', 'before its record')
      await publish([h.url], [ownerRecord(alice, 'offer/photo', withPhoto(photo), T0)])
      assert.equal(await put(h, photo, 'image/png'), 'unnamed', 'named as another type')
      assert.equal(await put(h, photo, 'image/jpeg'), 'ok', 'after its record')

      // Named only by a version that is no longer current: unnamed.
      await publish([h.url], [ownerRecord(alice, 'offer/a', withMedia([clip, 'video/mp4']), T0), ownerRecord(alice, 'offer/a', offerBody('30'), T0 + 1)])
      assert.equal(await put(h, clip, 'video/mp4'), 'unnamed')
      // Named by an access key's record the permissions record allows: named.
      await publish([h.url], [permissionsRecord(alice, [allow(accessKey, ['offer'])], T0), accessRecord(accessKey, alice.address, 'offer/b', withMedia([clip, 'video/mp4']), T0)])
      assert.equal(await put(h, clip, 'video/mp4'), 'ok')
    } finally {
      await h.close()
    }
  })

  test('size and type are the host’s: the reference host takes png, jpeg and mp4 up to 50,000,000 bytes; an operator chooses its own', async () => {
    const gif = bytesOf(3)
    const reference = await startHost({ now: () => T0 })
    const small = await startHost({ now: () => T0, maxBlobBytes: 1000, blobChoice: (blob) => (blob.type === 'video/mp4' ? 'no video here' : null) })
    try {
      for (const h of [reference, small]) await publish([h.url], [ownerRecord(alice, 'offer/photo', withPhoto(gif, 'image/gif'), T0), ownerRecord(alice, 'offer/a', withMedia([photo, 'image/png'], [bytesOf(4, 900), 'video/mp4'], [bytesOf(5, 900), 'image/gif']), T0)])
      assert.equal(await put(reference, gif, 'image/gif'), 'refused', 'a gif: not a type the shapes name')
      assert.equal(await put(reference, photo, 'image/png'), 'ok')
      const [over] = await putBlob([small.url], photo, 'image/png')
      assert.deepEqual([over!.status, over!.error], [413, 'refused'])
      assert.equal(await put(small, bytesOf(4, 900), 'video/mp4'), 'refused')
      assert.equal(await put(small, bytesOf(5, 900), 'image/gif'), 'ok', 'this operator takes gifs')

      // A declared size over the cap is answered at once, unread.
      const { port } = new URL(reference.url)
      const socket = connect(Number(port), '127.0.0.1')
      socket.write(`PUT /v1/blobs/${nameOf(photo)} HTTP/1.1\r\nhost: x\r\ncontent-type: image/png\r\ncontent-length: 50000001\r\n\r\n`)
      const answer = await new Promise<string>((resolve) => socket.once('data', (d) => resolve(String(d))))
      socket.destroy()
      assert.match(answer, /^HTTP\/1\.1 413/)
    } finally {
      await reference.close()
      await small.close()
    }
  })

  test('a host’s own choice sees the folders whose current records name the bytes, for rules by folder', async () => {
    const seen: string[][] = []
    const h = await startHost({
      now: () => T0,
      blobChoice: ({ folders }) => {
        seen.push(folders)
        return folders.includes(alice.address) ? null : 'only Alice’s folder here'
      },
    })
    try {
      const both = bytesOf(7)
      const bobs = bytesOf(8)
      await publish([h.url], [ownerRecord(alice, 'offer/photo', withPhoto(both), T0), ownerRecord(bob, 'offer/photo', withPhoto(both), T0), ownerRecord(bob, 'offer/a', withMedia([bobs, 'image/png']), T0)])
      assert.equal(await put(h, both, 'image/jpeg'), 'ok')
      assert.equal(await put(h, bobs, 'image/png'), 'refused')
      assert.deepEqual(seen, [[alice.address, bob.address].sort(), [bob.address]])
    } finally {
      await h.close()
    }
  })

  test('kept while a current record names it; once none does, it goes after keep days, unless named again first', async () => {
    const clock = new Clock(T0)
    const h = await startHost({ now: clock.now })
    try {
      const other = bytesOf(6)
      await publish([h.url], [ownerRecord(alice, 'offer/photo', withPhoto(photo), T0), ownerRecord(alice, 'offer/a', withMedia([photo, 'image/jpeg'], [other, 'image/png']), T0)])
      assert.deepEqual([await put(h, photo, 'image/jpeg'), await put(h, other, 'image/png')], ['ok', 'ok'])

      // One offer goes; the other still names the photo.
      await publish([h.url], [ownerRecord(alice, 'offer/photo', null, clock.advance(DAY))])
      await h.prune(clock.t + 31 * DAY)
      assert.ok(await h.getBlob(nameOf(photo)))

      // The offer goes: nothing names either any more. The other is named again before its keep days end.
      const gone = clock.advance(DAY)
      await publish([h.url], [ownerRecord(alice, 'offer/a', null, gone)])
      await publish([h.url], [ownerRecord(alice, 'offer/b', withMedia([other, 'image/png']), clock.advance(DAY))])
      await h.prune(gone + 29 * DAY)
      assert.ok(await h.getBlob(nameOf(photo)), 'within keep days')
      await h.prune(gone + 31 * DAY)
      assert.equal(await h.getBlob(nameOf(photo)), undefined)
      assert.equal((await fetch(`${h.url}/v1/blobs/${nameOf(photo)}`)).status, 404)
      assert.ok(await h.getBlob(nameOf(other)), 'named again')
    } finally {
      await h.close()
    }
  })

  test('GET is 404 for bytes not held; only a lowercase SHA-256 is a blob path; PUT and GET only', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      assert.equal((await fetch(`${h.url}/v1/blobs/${nameOf(photo)}`)).status, 404)
      assert.equal((await fetch(`${h.url}/v1/blobs/${nameOf(photo).toUpperCase()}`)).status, 404)
      assert.equal((await fetch(`${h.url}/v1/blobs/abc`, { method: 'PUT', body: photo })).status, 404)
      assert.equal((await fetch(`${h.url}/v1/blobs/${nameOf(photo)}`, { method: 'POST' })).status, 405)
    } finally {
      await h.close()
    }
  })

  test('a reader checks the hash: a host serving other bytes, or more than the reader takes, is skipped', async () => {
    const good = await startHost({ now: () => T0 })
    const bad = await startHost({ now: () => T0 })
    try {
      for (const h of [good, bad]) await publish([h.url], [ownerRecord(alice, 'offer/photo', withPhoto(photo), T0)])
      assert.deepEqual((await putBlob([good.url, bad.url], photo, 'image/jpeg')).map((o) => o.ok), [true, true])
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
