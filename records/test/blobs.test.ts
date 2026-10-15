// Blobs: bytes a folder holds. Its main key or a write key it lists puts them with a signed request,
// and they stay until a key that may deletes them, whatever the folder's records say. A host
// refuses bytes that do not hash to their name, or are not the type and size the request names, a
// request no key that may signed, and what its own choice will not take. A reader checks the hash,
// whatever host served them.

import assert from 'node:assert/strict'
import { connect } from 'node:net'
import { describe, test } from 'node:test'
import { canonical } from '../src/canonical.ts'
import { deleteBlob, getBlob, publish, putBlob, readProfile } from '../src/client.ts'
import type { Host } from '../src/host.ts'
import type { Key } from '../src/keys.ts'
import { type SignedBlobRequest, blobNameOf, blobRequest } from '../src/message.ts'
import { hostsRecord, ownerRecord, permissionsRecord } from '../src/write.ts'
import { DAY, MINUTE, T0, accessKey, alice, allow, bob, offerBody, pastKey, reader, stranger } from './fixtures.ts'
import { Clock, startHost } from './helpers.ts'

type Signer = Key | { key: Key; profile: string }
const bytesOf = (seed: number, length = 2000) => Uint8Array.from({ length }, (_, i) => (i * 7 + seed * 13) & 255)
const nameOf = (bytes: Uint8Array) => blobNameOf(bytes, 'image/jpeg').sha256
const putOf = (signer: Signer, bytes: Uint8Array, type = 'image/jpeg', time = T0) => blobRequest(signer, { action: 'put', ...blobNameOf(bytes, type) }, time) as SignedBlobRequest & { action: 'put' }
const deleteOf = (signer: Signer, bytes: Uint8Array, time = T0) => blobRequest(signer, { action: 'delete', sha256: nameOf(bytes) }, time) as SignedBlobRequest & { action: 'delete' }
/** One host's answer, as its error code, or its message, or ok. */
const answer = (outcomes: Array<{ ok: boolean; error?: string; message?: string }>) => outcomes[0]!.error ?? outcomes[0]!.message ?? 'ok'
const put = async (h: Host, signer: Signer, bytes: Uint8Array, type = 'image/jpeg') => answer(await putBlob([h.url], putOf(signer, bytes, type), bytes))
const del = async (h: Host, signer: Signer, bytes: Uint8Array) => answer(await deleteBlob([h.url], deleteOf(signer, bytes)))
/** A write key signing for Alice's folder. */
const as = (key: Key) => ({ key, profile: alice.address })

const photo = bytesOf(1)
const clip = bytesOf(2, 5000)

describe('blobs', () => {
  test('a folder’s keys put bytes on its hosts; a reader follows a record’s reference to them, and gets their type', async () => {
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
      await h.prune(clock.t + 365 * DAY)
      assert.ok(await h.getBlob(nameOf(photo)), 'past every keep day')
      assert.ok(await h.getBlob(nameOf(clip)))
    } finally {
      await h.close()
    }
  })

  test('the main key deletes any of its folder’s bytes; a write key, whatever its paths, the ones a write key put', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      await publish([h.url], [permissionsRecord(alice, [allow(accessKey, ['inbox'])], T0)])
      // The main key's bytes: only it deletes them, as the owner's records.
      assert.equal(await put(h, alice, photo), 'ok')
      assert.equal(await del(h, as(accessKey), photo), 'permission')
      assert.equal(await del(h, alice, photo), 'ok')
      assert.equal((await fetch(`${h.url}/v1/blobs/${nameOf(photo)}`)).status, 404)
      assert.equal(await del(h, alice, photo), 'not here')

      // A write key's bytes: a write key or the main key deletes them.
      assert.equal(await put(h, as(accessKey), clip, 'video/mp4'), 'ok')
      assert.equal(await del(h, as(accessKey), clip), 'ok')
      assert.equal(await put(h, as(accessKey), clip, 'video/mp4'), 'ok')
      assert.equal(await del(h, alice, clip), 'ok')

      // The main key putting what a write key put takes it over; a write key putting the main key's changes nothing.
      const both = bytesOf(3)
      assert.equal(await put(h, as(accessKey), both), 'ok')
      assert.equal(await put(h, alice, both), 'ok')
      assert.equal(await put(h, as(accessKey), both), 'already here')
      assert.equal(await del(h, as(accessKey), both), 'permission')
    } finally {
      await h.close()
    }
  })

  test('bytes two folders hold are stored once, and stay until the last of them deletes them', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      assert.deepEqual([await put(h, alice, photo), await put(h, bob, photo)], ['ok', 'ok'])
      assert.equal(await del(h, alice, photo), 'ok')
      assert.equal((await fetch(`${h.url}/v1/blobs/${nameOf(photo)}`)).status, 200, 'Bob holds them still')
      assert.equal(await del(h, alice, photo), 'not here')
      assert.equal(await del(h, bob, photo), 'ok')
      assert.equal(await h.getBlob(nameOf(photo)), undefined)
    } finally {
      await h.close()
    }
  })

  test('a request no key that may signed is refused: a key not listed, a past write key, a read key, another key’s signature', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      const past = stranger
      await publish([h.url], [permissionsRecord(alice, [allow(accessKey, ['offer']), pastKey(past, ['offer']), allow(reader, ['inbox'], 'read')], T0)])
      assert.equal(await put(h, as(bob), photo), 'permission', 'a key the folder does not list')
      assert.equal(await put(h, as(past), photo), 'permission', 'a past write key')
      assert.equal(await put(h, as(reader), photo), 'permission', 'a read key')
      assert.equal(await put(h, as(accessKey), photo), 'ok')
      assert.equal(await del(h, as(past), photo), 'permission')

      // Alice's request with Bob's profile in it: the signature is not Bob's main key's.
      const forged = { ...putOf(alice, clip), profile: bob.address }
      assert.equal(answer(await putBlob([h.url], forged, clip)), 'signature')
    } finally {
      await h.close()
    }
  })

  test('a request is checked against the bytes and the route: their hash, type and size, its action, its time', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      const send = async (request: SignedBlobRequest | null, bytes: Uint8Array | null, options: { method?: string; type?: string; name?: string } = {}) => {
        const headers: Record<string, string> = { 'content-type': options.type ?? 'image/jpeg' }
        if (request) headers['forest-blob'] = canonical(request)
        const res = await fetch(`${h.url}/v1/blobs/${options.name ?? nameOf(photo)}`, { method: options.method ?? 'PUT', headers, ...(bytes && { body: new Uint8Array(bytes) }) })
        return [res.status, ((await res.json()) as { error?: string }).error ?? 'ok']
      }
      assert.deepEqual(await send(null, photo), [400, 'shape'], 'no signed request')
      assert.deepEqual(await send(putOf(alice, photo), photo, { type: 'image/png' }), [400, 'shape'], 'another type than it names')
      assert.deepEqual(await send(putOf(alice, photo), photo.subarray(1)), [400, 'shape'], 'another size')
      assert.deepEqual(await send(putOf(alice, clip), photo, { name: nameOf(photo) }), [400, 'shape'], 'a request for other bytes')
      // Named by the right hash, type and size, but other bytes of that size: not what they claim.
      const lookalike = Uint8Array.from(photo, (b, i) => (i === 0 ? b ^ 1 : b))
      assert.deepEqual(await send(putOf(alice, photo), lookalike), [400, 'hash'])
      assert.deepEqual(await send(deleteOf(alice, photo), photo), [400, 'shape'], 'a delete sent as a put')
      assert.deepEqual(await send(putOf(alice, photo), null, { method: 'DELETE' }), [400, 'shape'], 'a put sent as a delete')
      assert.deepEqual(await send(putOf(alice, photo, 'image/jpeg', T0 + 11 * MINUTE), photo), [400, 'stale'])
      assert.deepEqual(await send(deleteOf(alice, photo, T0 - 11 * MINUTE), null, { method: 'DELETE' }), [400, 'stale'])
      assert.deepEqual(await send(putOf(alice, photo, 'image/jpeg', T0 + 9 * MINUTE), photo), [200, 'ok'], 'within ten minutes')
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

  test('size and type are the host’s: the reference host takes png, jpeg and mp4 up to 50,000,000 bytes; an operator chooses its own', async () => {
    const gif = bytesOf(3)
    const reference = await startHost({ now: () => T0 })
    const small = await startHost({ now: () => T0, maxBlobBytes: 1000, blobChoice: (blob) => (blob.type === 'video/mp4' ? 'no video here' : null) })
    try {
      assert.equal(await put(reference, alice, gif, 'image/gif'), 'refused', 'a gif')
      assert.equal(await put(reference, alice, photo, 'image/png'), 'ok')
      const [over] = await putBlob([small.url], putOf(alice, photo, 'image/png'), photo)
      assert.deepEqual([over!.status, over!.error], [413, 'refused'])
      assert.equal(await put(small, alice, bytesOf(4, 900), 'video/mp4'), 'refused')
      assert.equal(await put(small, alice, bytesOf(5, 900), 'image/gif'), 'ok', 'this operator takes gifs')

      // A declared size over the cap is answered at once, unread.
      const { port } = new URL(reference.url)
      const socket = connect(Number(port), '127.0.0.1')
      socket.write(`PUT /v1/blobs/${nameOf(photo)} HTTP/1.1\r\nhost: x\r\ncontent-type: image/png\r\nforest-blob: ${canonical(putOf(alice, photo, 'image/png'))}\r\ncontent-length: 50000001\r\n\r\n`)
      const reply = await new Promise<string>((resolve) => socket.once('data', (d) => resolve(String(d))))
      socket.destroy()
      assert.match(reply, /^HTTP\/1\.1 413/)
    } finally {
      await reference.close()
      await small.close()
    }
  })

  test('a host’s own choice sees the folder and what it holds there already, for rules by folder: a quota', async () => {
    const seen: Array<[string, number, number]> = []
    const h = await startHost({
      now: () => T0,
      blobChoice: (blob, stored) => {
        seen.push([blob.profile, stored.blobs, stored.bytes])
        return stored.blobs >= 1 ? 'one blob a folder here' : null
      },
    })
    try {
      assert.equal(await put(h, alice, photo), 'ok')
      assert.equal(await put(h, alice, photo), 'already here', 'not asked again')
      assert.equal(await put(h, alice, clip, 'video/mp4'), 'refused')
      assert.equal(await put(h, bob, clip, 'video/mp4'), 'ok')
      assert.deepEqual(seen, [[alice.address, 0, 0], [alice.address, 1, photo.length], [bob.address, 0, 0]])
    } finally {
      await h.close()
    }
  })

  test('GET is 404 for bytes not held; only a lowercase SHA-256 is a blob path; PUT, GET and DELETE only', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      assert.equal((await fetch(`${h.url}/v1/blobs/${nameOf(photo)}`)).status, 404)
      assert.equal((await fetch(`${h.url}/v1/blobs/${nameOf(photo).toUpperCase()}`)).status, 404)
      assert.equal((await fetch(`${h.url}/v1/blobs/abc`, { method: 'PUT', body: photo })).status, 404)
      const post = await fetch(`${h.url}/v1/blobs/${nameOf(photo)}`, { method: 'POST' })
      assert.deepEqual([post.status, post.headers.get('allow')], [405, 'GET, PUT, DELETE'])
    } finally {
      await h.close()
    }
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
