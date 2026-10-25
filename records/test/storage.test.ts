// The reference host's storage: a SQLite file per folder, host.sqlite for the log and the blob
// index, and the bytes on disk or in an S3-compatible bucket. None of it is the standard: the eight
// requests answer the same whatever the storage. Here: where things land, the feed across
// folders, removing a folder, a malformed address, rebuilding host.sqlite, a folder file of an
// older version, migrated, and one in another layout, refused, and the S3 driver.

import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { type IncomingMessage, createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { after, describe, test } from 'node:test'
import { inboxKey } from '@foundationforest/keys'
import { deleteBlob, deliver, getBlob, publish, pull, putBlob, readAll, readPage } from '../src/client.ts'
import { type BlobDriver, DAY, Host, rebuild } from '../src/host.ts'
import { blobNameOf, blobRequest, pullRequest } from '../src/message.ts'
import { message } from '../src/private.ts'
import type { Body } from '../src/record.ts'
import { s3Url, signS3 } from '../src/storage.ts'
import { ownerRecord } from '../src/write.ts'
import { MINUTE, T0, alice, aliceBuyer, bob, offerBody, profileBody, stranger } from './fixtures.ts'
import { Clock, startHost } from './helpers.ts'

const dirs: string[] = []
const scratch = () => {
  const dir = mkdtempSync(join(tmpdir(), 'forest-storage-'))
  dirs.push(dir)
  return dir
}
after(() => dirs.forEach((dir) => rmSync(dir, { recursive: true, force: true })))

const sha256Hex = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex')
const bytesOf = (seed: number, length = 2000) => Uint8Array.from({ length }, (_, i) => (i * 7 + seed * 13) & 255)
const photo = bytesOf(1)
const clip = bytesOf(2, 3000)
/** Bytes a folder's main key puts, or deletes, with a signed request at T0. */
const putAs = (key: typeof alice, bytes: Uint8Array, type: string, time = T0) => blobRequest(key, { action: 'put', ...blobNameOf(bytes, type) }, time) as Parameters<typeof putBlob>[1]
const deleteAs = (key: typeof alice, bytes: Uint8Array, time = T0) => blobRequest(key, { action: 'delete', sha256: sha256Hex(bytes) }, time) as Parameters<typeof deleteBlob>[1]
/** Alice's photo and Bob's clip, each put by its folder's main key. */
const putBoth = async (url: string) => [...(await putBlob([url], putAs(alice, photo, 'image/jpeg'), photo)), ...(await putBlob([url], putAs(bob, clip, 'video/mp4'), clip))].map((o) => o.ok)

const [aliceInbox, bobInbox] = await Promise.all([inboxKey(alice.secret), inboxKey(bob.secret)])
const aliceProfile: Body = { ...profileBody('calculus'), inboxKey: aliceInbox.encryptTo, inbox: { senders: 'anyone' } }
/** Alice's offer pointing at her photo, by a field of its own: where a record points at a blob is the market's. */
const photoOffer = ownerRecord(alice, 'offer/photo', { ...offerBody('5'), files: [blobNameOf(photo, 'image/jpeg')] }, T0)
const bobProfile: Body = { ...profileBody('chemistry'), role: 'buyer', inboxKey: bobInbox.encryptTo, inbox: { senders: 'anyone' } }
const withClip = (about: string): Body => ({ ...offerBody(about), files: [blobNameOf(clip, 'video/mp4')] })

/** Every page of the feed, as [cursor, ids]: what a crawler sees, number for number. */
async function pages(url: string, profile?: string) {
  const out: Array<[number, string[]]> = []
  for (let after = 0; ; ) {
    const page = await readPage(url, { after, ...(profile && { profile }) })
    if (page.cursor === after) return out
    out.push([page.cursor, page.records.map((c) => c.id)])
    after = page.cursor
  }
}

/** Read one SQLite file while the host runs. */
function query<T>(file: string, sql: string): T[] {
  const db = new DatabaseSync(file, { readOnly: true })
  try {
    return db.prepare(sql).all() as T[]
  } finally {
    db.close()
  }
}

describe('a file per folder', () => {
  test('two folders land in two files; host.sqlite holds the log and the blob index, and no record', async () => {
    const dir = scratch()
    const h = await startHost({ dir, now: () => T0 })
    try {
      const records = [ownerRecord(alice, 'profile', profileBody('calculus'), T0), ownerRecord(bob, 'profile', profileBody('chemistry'), T0), ownerRecord(alice, 'offer/a', offerBody('1'), T0)]
      await publish([h.url], records)
      assert.deepEqual(readdirSync(join(dir, 'folders')).sort(), [`${alice.address}.sqlite`, `${bob.address}.sqlite`].sort())
      const profiles = (address: string) => query<{ text: string }>(join(dir, 'folders', `${address}.sqlite`), 'SELECT text FROM records ORDER BY seq').map((r) => (JSON.parse(r.text) as { profile: string }).profile)
      assert.deepEqual(profiles(alice.address), [alice.address, alice.address])
      assert.deepEqual(profiles(bob.address), [bob.address])

      const host = join(dir, 'host.sqlite')
      assert.deepEqual(query<{ name: string }>(host, "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").map((t) => t.name), ['blobs', 'log', 'owners', 'sqlite_sequence'])
      assert.deepEqual(query<{ folder: string }>(host, 'SELECT folder FROM log ORDER BY seq').map((r) => r.folder), [alice.address, bob.address, alice.address])
      const shared = Buffer.concat([host, `${host}-wal`].filter(existsSync).map((f) => readFileSync(f)))
      for (const r of records) assert.ok(!shared.includes(r.sig), 'no record text in host.sqlite')
    } finally {
      await h.close()
    }
  })

  test('the feed orders every folder’s records by arrival, under one set of numbers', async () => {
    const clock = new Clock(T0)
    const h = await startHost({ now: clock.now, maxPageRecords: 2 })
    try {
      const order = [[alice, 'offer/1'], [bob, 'offer/1'], [alice, 'offer/2'], [bob, 'offer/2'], [alice, 'offer/3']] as const
      for (const [key, path] of order) await publish([h.url], [ownerRecord(key, path, offerBody('1'), clock.advance(1))])
      assert.deepEqual((await readAll(h.url)).records.map((c) => [c.record.profile, c.record.path]), order.map(([key, path]) => [key.address, path]))
      // Each number is the clock in microseconds, the record at T0 + i ms numbered (T0 + i) × 1000.
      const n = (i: number) => (T0 + i) * 1000
      assert.deepEqual((await pages(h.url)).map(([cursor, ids]) => [cursor, ids.length]), [[n(2), 2], [n(4), 2], [n(5), 1]])
      // A cursor from the feed works for one folder too.
      assert.deepEqual((await readPage(h.url, { after: n(2), profile: alice.address })).records.map((c) => c.record.path), ['offer/2', 'offer/3'])
      assert.deepEqual((await readPage(h.url, { after: n(2), profile: bob.address })).cursor, n(4))
    } finally {
      await h.close()
    }
  })

  test('deleting one folder’s file removes exactly that folder', async () => {
    const dir = scratch()
    const options = { dir, now: () => T0 }
    let h = await startHost(options)
    const reread = async () => ({ feed: await pages(h.url), bob: await pages(h.url, bob.address), bobInbox: await pull(h.url, pullRequest(bob, 0, T0)) })
    let was: Awaited<ReturnType<typeof reread>>
    try {
      await publish([h.url], [ownerRecord(alice, 'profile', aliceProfile, T0), photoOffer])
      await publish([h.url], [ownerRecord(bob, 'profile', bobProfile, T0)])
      await publish([h.url], [ownerRecord(alice, 'offer/a', offerBody('1'), T0)])
      await publish([h.url], [ownerRecord(bob, 'offer/b', withClip('2'), T0)])
      assert.deepEqual(await putBoth(h.url), [true, true])
      assert.ok((await putBlob([h.url], putAs(alice, clip, 'video/mp4'), clip))[0]!.ok, 'Alice holds the clip too')
      await deliver([h.url], [await message(bob, alice.address, { text: 'Tuesday?' }, T0, aliceProfile)])
      await deliver([h.url], [await message(alice, bob.address, { text: 'Tuesday.' }, T0, bobProfile)])
      was = await reread()
    } finally {
      await h.close()
    }

    rmSync(join(dir, 'folders', `${alice.address}.sqlite`))
    h = await startHost(options)
    try {
      // Alice's folder is gone: her records, her inbox.
      assert.deepEqual((await readAll(h.url, { profile: alice.address })).records, [])
      assert.deepEqual((await pull(h.url, pullRequest(alice, 0, T0))).messages, [])
      // Bob's is whole: the same records under the same numbers, and the same inbox.
      const now = await reread()
      const bobIds = new Set(was.bob.flatMap(([, ids]) => ids))
      assert.deepEqual(now.feed.flatMap(([, ids]) => ids), was.feed.flatMap(([, ids]) => ids).filter((id) => bobIds.has(id)))
      assert.deepEqual(now.bob, was.bob)
      assert.deepEqual([now.bobInbox.messages.map((m) => m.id), now.bobInbox.cursor], [was.bobInbox.messages.map((m) => m.id), was.bobInbox.cursor])

      // The next prune drops what host.sqlite said of her, and the bytes only she held.
      assert.ok(await h.getBlob(sha256Hex(photo)), 'until the next prune')
      await h.prune(T0)
      const host = join(dir, 'host.sqlite')
      assert.deepEqual(query<{ folder: string }>(host, 'SELECT DISTINCT folder FROM log UNION SELECT folder FROM owners').map((r) => r.folder), [bob.address])
      assert.equal(await h.getBlob(sha256Hex(photo)), undefined)
      assert.ok(await h.getBlob(sha256Hex(clip)), 'Bob holds it still')
    } finally {
      await h.close()
    }
  })

  test('a profile that is no address touches no file', async () => {
    const dir = scratch()
    const h = await startHost({ dir, now: () => T0 })
    try {
      await publish([h.url], [ownerRecord(alice, 'profile', profileBody('calculus'), T0)])
      const files = () => readdirSync(dir, { recursive: true }).map(String).sort()
      const was = files()
      const zeroKey = '1'.repeat(32) // 32 zero bytes: one spelling, but a key of small order
      for (const profile of ['../x', 'not-an-address', `${alice.address}/../../host`, `1${alice.address}`, zeroKey, bob.address]) {
        const res = await fetch(`${h.url}/v1/records?profile=${encodeURIComponent(profile)}`)
        assert.deepEqual([res.status, await res.text(), res.headers.get('forest-cursor')], [200, '', '0'], profile)
      }
      assert.deepEqual(files(), was, 'no file made, opened by name or moved')
    } finally {
      await h.close()
    }
  })
})

describe('host.sqlite holds nothing that exists only there', () => {
  test('numbers come from the clock: a rebuilt host.sqlite, or a folder’s file made again, never gives one again', async () => {
    const dir = scratch()
    const clock = new Clock(T0)
    const options = { dir, now: clock.now }
    let h = await startHost(options)
    let given: number
    let inboxCursor: number
    try {
      await publish([h.url], [ownerRecord(bob, 'profile', bobProfile, T0), ownerRecord(alice, 'profile', aliceProfile, T0)])
      await deliver([h.url], [await message(bob, alice.address, { text: 'Tuesday?' }, T0, aliceProfile)])
      given = (await readPage(h.url)).cursor
      inboxCursor = (await pull(h.url, pullRequest(alice, 0, T0))).cursor
      assert.deepEqual([given, inboxCursor], [T0 * 1000 + 1, T0 * 1000], 'the clock in microseconds, then one more')
    } finally {
      await h.close()
    }

    // Alice's folder goes, and host.sqlite with it: rebuilt from Bob's folder alone, the highest
    // number the log knows is Bob's. A millisecond later is enough to give no number twice.
    rmSync(join(dir, 'folders', `${alice.address}.sqlite`))
    for (const suffix of ['', '-wal', '-shm']) rmSync(join(dir, `host.sqlite${suffix}`), { force: true })
    clock.advance(1)
    await rebuild(dir, { kind: 'disk' })
    h = await startHost(options)
    try {
      await publish([h.url], [ownerRecord(alice, 'profile', aliceProfile, clock.t)])
      await deliver([h.url], [await message(bob, alice.address, { text: 'Still Tuesday?' }, clock.t, aliceProfile)])
      const page = await readPage(h.url, { after: given })
      assert.deepEqual([page.records.length, page.cursor], [1, clock.t * 1000], 'a reader holding the old cursor still gets the new record')
      assert.equal((await pull(h.url, pullRequest(alice, inboxCursor, clock.t))).messages.length, 1, 'and the inbox’s old cursor, the new message')
    } finally {
      await h.close()
    }
  })

  test('delete it and rebuild: the same feed, the same numbers, the same blobs, each held by the same folders', async () => {
    const dir = scratch()
    const clock = new Clock(T0)
    const options = { dir, now: clock.now, maxPageRecords: 2 }
    let h = await startHost(options)
    let was: Array<[number, string[]]>
    try {
      await publish([h.url], [ownerRecord(alice, 'profile', aliceProfile, T0), photoOffer, ownerRecord(alice, 'offer/a', withClip('1'), T0)])
      await publish([h.url], [ownerRecord(bob, 'profile', bobProfile, T0)])
      assert.deepEqual(await putBoth(h.url), [true, true])
      was = await pages(h.url)
    } finally {
      await h.close()
    }

    for (const suffix of ['', '-wal', '-shm']) rmSync(join(dir, `host.sqlite${suffix}`), { force: true })
    assert.throws(() => new Host(options), /rebuild/, 'a host does not start without it: new records would take numbers already given')
    clock.advance(MINUTE)
    await rebuild(dir, { kind: 'disk' })
    h = await startHost(options)
    try {
      assert.deepEqual(await pages(h.url), was)
      assert.deepEqual(await getBlob([h.url], sha256Hex(photo)).then((g) => [g!.type, g!.bytes]), ['image/jpeg', photo])
      assert.deepEqual((await putBlob([h.url], putAs(alice, photo, 'image/jpeg'), photo))[0]!.message, 'already here')
      // New records go on past the numbers given before, from the clock.
      const last = was.at(-1)![0]
      await publish([h.url], [ownerRecord(bob, 'offer/b', offerBody('3'), clock.t)])
      assert.equal((await readPage(h.url, { after: last })).cursor, clock.t * 1000)
      assert.ok(clock.t * 1000 > last)
      // Each folder still holds its own: a prune keeps both, and the clip goes when Bob deletes it.
      await h.prune(clock.t + 365 * DAY)
      assert.ok(await h.getBlob(sha256Hex(photo)))
      assert.ok((await deleteBlob([h.url], deleteAs(bob, clip)))[0]!.ok)
      assert.equal(await h.getBlob(sha256Hex(clip)), undefined)
    } finally {
      await h.close()
    }
  })
})

/**
 * Make a folder file version 1 again, its blobs table as version 1 had it: `by` said who put each
 * blob, here a write key; and with the table of senders versions 1 and 2 kept for inboxes that took
 * one message from each. `more` runs after.
 */
function toVersion1(file: string, more = '') {
  const db = new DatabaseSync(file)
  db.exec(`
    CREATE TEMP TABLE held AS SELECT * FROM blobs;
    DROP TABLE blobs;
    CREATE TABLE blobs (
      sha256 TEXT PRIMARY KEY,
      type TEXT NOT NULL,
      size INTEGER NOT NULL,
      by TEXT,
      arrived INTEGER NOT NULL
    ) WITHOUT ROWID;
    INSERT INTO blobs SELECT sha256, type, size, '${stranger.address}', arrived FROM held;
    CREATE TABLE once (sender TEXT PRIMARY KEY) WITHOUT ROWID;
    INSERT INTO once VALUES ('${stranger.address}');
    PRAGMA user_version = 1;
    ${more}
  `)
  db.close()
}

/** A folder file's version, its blobs table's columns, and whether it has the table of senders. */
const shapeOf = (file: string) => [
  query<{ user_version: number }>(file, 'PRAGMA user_version')[0]!.user_version,
  query<{ name: string }>(file, `SELECT name FROM pragma_table_info('blobs')`).map((c) => c.name),
  query(file, `SELECT name FROM sqlite_master WHERE name = 'once'`).length === 1,
]

describe('a folder file of an older version', () => {
  test('is migrated when it opens: version 1 loses the column that said who put each blob, then version 2 its table of senders, and it keeps its records and blobs', async () => {
    const dir = scratch()
    const options = { dir, now: () => T0 }
    let h = await startHost(options)
    let was: Array<[number, string[]]>
    try {
      await publish([h.url], [ownerRecord(alice, 'profile', aliceProfile, T0), photoOffer])
      assert.ok((await putBlob([h.url], putAs(alice, photo, 'image/jpeg'), photo))[0]!.ok)
      was = await pages(h.url)
    } finally {
      await h.close()
    }
    const file = join(dir, 'folders', `${alice.address}.sqlite`)
    toVersion1(file)
    assert.deepEqual(shapeOf(file), [1, ['sha256', 'type', 'size', 'by', 'arrived'], true])
    h = await startHost(options)
    try {
      assert.deepEqual(await pages(h.url), was)
      assert.equal((await putBlob([h.url], putAs(alice, photo, 'image/jpeg'), photo))[0]!.message, 'already here')
      assert.ok((await deleteBlob([h.url], deleteAs(alice, photo)))[0]!.ok, 'her main key deletes a blob a write key put')
      assert.equal(await h.getBlob(sha256Hex(photo)), undefined)
    } finally {
      await h.close()
    }
    assert.deepEqual(shapeOf(file), [3, ['sha256', 'type', 'size', 'arrived'], false])
  })
})

describe('a folder file in another layout', () => {
  test('is refused by name and left as it was, on open and by a rebuild: one from before folders held blobs, and one a step does not bring to this layout', async () => {
    const dir = scratch()
    const h = await startHost({ dir, now: () => T0 })
    await publish([h.url], [ownerRecord(alice, 'profile', aliceProfile, T0), ownerRecord(bob, 'profile', bobProfile, T0)])
    await h.close()
    const aliceFile = join(dir, 'folders', `${alice.address}.sqlite`)
    const bobFile = join(dir, 'folders', `${bob.address}.sqlite`)
    // Alice's says version 1, with no blobs table: its step fails.
    const db = new DatabaseSync(aliceFile)
    db.exec('DROP TABLE blobs; PRAGMA user_version = 1')
    db.close()
    // Bob's is version 1 with a table no version had: its step runs, and what comes out is not this layout.
    toVersion1(bobFile, 'CREATE TABLE extra (x)')
    const refused = (file: string) => ({ message: `${file} is not a folder file in this host's layout` })
    const again = new Host({ dir, now: () => T0 })
    try {
      assert.throws(() => again.view(alice.address), refused(aliceFile))
      assert.throws(() => again.view(bob.address), refused(bobFile))
      assert.equal(again.view(aliceBuyer.address).current.size, 0, 'another folder is untouched')
    } finally {
      await again.close()
    }
    await assert.rejects(rebuild(dir), /is not a folder file in this host's layout/)
    assert.deepEqual([shapeOf(aliceFile), shapeOf(bobFile)], [[1, [], false], [1, ['sha256', 'type', 'size', 'by', 'arrived'], true]])
  })
})

describe('the S3 driver', () => {
  const credentials = { accessKeyId: 'FORESTTESTKEY', secretAccessKey: 'forest-test-secret' }

  /**
   * A local S3 stand-in, path-style: it checks each request's SigV4 signature and payload hash,
   * keeps objects in memory with their content-type, and lists one key a page.
   */
  async function s3Stub() {
    const objects = new Map<string, { type: string; bytes: Uint8Array }>()
    const server = createServer(async (req: IncomingMessage, res) => {
      const chunks: Buffer[] = []
      for await (const chunk of req) chunks.push(chunk as Buffer)
      const body = Buffer.concat(chunks)
      const url = new URL(req.url!, `http://${req.headers.host}`)
      const auth = req.headers.authorization ?? ''
      const signed = (/SignedHeaders=([^,]+)/.exec(auth)?.[1] ?? '').split(';').filter((n) => !['host', 'x-amz-content-sha256', 'x-amz-date'].includes(n))
      const payloadHash = String(req.headers['x-amz-content-sha256'])
      const expected = signS3({ method: req.method!, url, headers: Object.fromEntries(signed.map((n) => [n, String(req.headers[n])])), payloadHash, amzDate: String(req.headers['x-amz-date']) }, credentials).authorization
      if (auth !== expected || payloadHash !== sha256Hex(body)) return void res.writeHead(403).end('<Error><Code>SignatureDoesNotMatch</Code></Error>')
      const [, bucket, key] = url.pathname.split('/')
      if (bucket !== 'forest') return void res.writeHead(404).end('<Error><Code>NoSuchBucket</Code></Error>')
      if (!key && req.method === 'GET') {
        const keys = [...objects.keys()].sort()
        const at = Number(url.searchParams.get('continuation-token') ?? 0)
        const more = at + 1 < keys.length
        const page = keys.slice(at, at + 1).map((k) => `<Contents><Key>${k}</Key></Contents>`).join('')
        return void res.writeHead(200, { 'content-type': 'application/xml' }).end(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><IsTruncated>${more}</IsTruncated>${page}${more ? `<NextContinuationToken>${at + 1}</NextContinuationToken>` : ''}</ListBucketResult>`)
      }
      const held = objects.get(key!)
      if (req.method === 'PUT') {
        objects.set(key!, { type: String(req.headers['content-type']), bytes: new Uint8Array(body) })
        return void res.writeHead(200).end()
      }
      if (req.method === 'DELETE') {
        objects.delete(key!)
        return void res.writeHead(204).end()
      }
      if (!held) return void res.writeHead(404).end('<Error><Code>NoSuchKey</Code></Error>')
      res.writeHead(200, { 'content-type': held.type, 'content-length': held.bytes.length }).end(req.method === 'HEAD' ? undefined : held.bytes)
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    return { objects, url: `http://127.0.0.1:${(server.address() as { port: number }).port}`, close: () => new Promise((resolve) => server.close(resolve)) }
  }

  test('blobs go to a bucket: put, get, 404, deleted; a rebuild lists them back', async () => {
    const stub = await s3Stub()
    const dir = scratch()
    const clock = new Clock(T0)
    const driver: BlobDriver = { kind: 's3', endpoint: stub.url, bucket: 'forest', ...credentials }
    const options = { dir, now: clock.now, blobs: driver }
    let h = await startHost(options)
    try {
      await publish([h.url], [ownerRecord(alice, 'profile', aliceProfile, T0), photoOffer, ownerRecord(alice, 'offer/a', withClip('1'), T0)])
      assert.deepEqual(await putBoth(h.url), [true, true])
      assert.deepEqual([...stub.objects].map(([k, o]) => [k, o.type]).sort(), [[sha256Hex(photo), 'image/jpeg'], [sha256Hex(clip), 'video/mp4']].sort())
      assert.ok(!existsSync(join(dir, 'blobs')), 'nothing on disk')
      assert.deepEqual(await getBlob([h.url], sha256Hex(clip)).then((g) => [g!.type, g!.bytes]), ['video/mp4', clip])
      assert.equal((await fetch(`${h.url}/v1/blobs/${sha256Hex(bytesOf(9))}`)).status, 404)

      // Bob deletes the clip: it leaves the bucket. He puts it again: it is back.
      assert.ok((await deleteBlob([h.url], deleteAs(bob, clip)))[0]!.ok)
      assert.deepEqual([...stub.objects.keys()], [sha256Hex(photo)])
      assert.ok((await putBlob([h.url], putAs(bob, clip, 'video/mp4'), clip))[0]!.ok)
    } finally {
      await h.close()
    }

    rmSync(join(dir, 'host.sqlite'))
    await rebuild(dir, driver)
    h = await startHost(options)
    try {
      assert.deepEqual(await getBlob([h.url], sha256Hex(clip)).then((g) => [g!.type, g!.bytes]), ['video/mp4', clip], 'listed back, page by page')
      assert.deepEqual((await putBlob([h.url], putAs(alice, photo, 'image/jpeg'), photo))[0]!.message, 'already here')
      assert.deepEqual((await putBlob([h.url], putAs(bob, clip, 'video/mp4'), clip))[0]!.message, 'already here')
    } finally {
      await h.close()
    }

    // The stub checks signatures: a wrong secret is refused, and the host answers 500.
    const wrong = await startHost({ now: () => T0, blobs: { ...driver, secretAccessKey: 'wrong' } })
    try {
      assert.equal((await putBlob([wrong.url], putAs(alice, photo, 'image/jpeg'), photo))[0]!.status, 500)
    } finally {
      await wrong.close()
      await stub.close()
    }
  })

  test('path-style by default, virtual-hosted on request; signed as AWS’s own examples are', () => {
    const endpoint = 'https://s3.amazonaws.com'
    assert.equal(s3Url({ endpoint, bucket: 'examplebucket' }, 'test.txt').href, 'https://s3.amazonaws.com/examplebucket/test.txt')
    const url = (key: string) => s3Url({ endpoint, bucket: 'examplebucket', style: 'virtual' }, key)
    assert.equal(url('test.txt').href, 'https://examplebucket.s3.amazonaws.com/test.txt')

    // AWS's Signature Version 4 examples for S3: GET an object, PUT one, list a bucket.
    const aws = { accessKeyId: 'AKIAIOSFODNN7EXAMPLE', secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' }
    const empty = sha256Hex('')
    const signature = (method: string, u: URL, headers: Record<string, string>, payloadHash: string) => /Signature=([0-9a-f]+)/.exec(signS3({ method, url: u, headers, payloadHash, amzDate: '20130524T000000Z' }, aws).authorization!)![1]
    assert.equal(signature('GET', url('test.txt'), { range: 'bytes=0-9' }, empty), 'f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41')
    assert.equal(signature('PUT', url('test$file.text'), { date: 'Fri, 24 May 2013 00:00:00 GMT', 'x-amz-storage-class': 'REDUCED_REDUNDANCY' }, sha256Hex('Welcome to Amazon S3.')), '98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd')
    const list = url('')
    list.searchParams.set('max-keys', '2')
    list.searchParams.set('prefix', 'J')
    assert.equal(signature('GET', list, {}, empty), '34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7')
  })
})
