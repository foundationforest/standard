// The client end to end over HTTP, against the minimal host (host.ts): two hosts, a profile
// writing, readers reading both, updates, deletes, moving hosts, hosts that misbehave, and the
// payment a write carries. What a host itself must do is the host check's (check.test.ts).

import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { after, before, describe, test } from 'node:test'
import { sha256 } from '@noble/hashes/sha2.js'
import { hex, utf8 } from '../src/bytes.ts'
import { MAX_LINE_READ, type Payment, leave, readAll, readFolder, readInbox, readPage, upload, write } from '../src/client.ts'
import { type SignedEntry, checkEntry, encodeEntry } from '../src/entry.ts'
import { fileOf } from '../src/files.ts'
import { encodeInbox } from '../src/inbox.ts'
import { inboxEntry } from '../src/locked.ts'
import { liveContent } from '../src/view.ts'
import { entry, nextTime } from '../src/write.ts'
import { DAY, MINUTE, T0, alice, aliceBuyer, bob, offerBody, profileBody, reviewBody, sizedEntry } from './fixtures.ts'
import { Clock, startHost } from './helpers.ts'
import type { TestHost } from './host.ts'

const errors = async (host: TestHost, entries: SignedEntry[]) => (await write([host.url], entries))[0]!.results.map((r) => r.error ?? 'ok')
/** A profile entry naming these hosts. */
const profileAt = (key: typeof alice, hosts: string[], time: number, subject = 'maths') => entry(key, 'profile', { ...profileBody(subject), hosts }, time)

describe('two hosts, readers', () => {
  const clock = new Clock(T0)
  let h1: TestHost
  let h2: TestHost
  before(async () => {
    h1 = await startHost({ now: clock.now })
    h2 = await startHost({ now: clock.now })
  })
  after(async () => {
    await h1.close()
    await h2.close()
  })

  test('write a profile, an offer and a review to two hosts; a reader that knows one host finds the other', async () => {
    const urls = [h1.url, h2.url]
    const entries: SignedEntry[] = [profileAt(alice, urls, T0, 'calculus'), entry(alice, 'offer/maths', offerBody('30'), T0), profileAt(bob, urls, T0), entry(bob, 'review/1', reviewBody(alice.address), T0)]
    for (const outcome of await write(urls, entries)) {
      assert.equal(outcome.status, 200)
      assert.ok(outcome.results.every((r) => r.ok), JSON.stringify(outcome.results))
    }
    // Host 2 alone gets one more offer: a reader that starts at host 1 still sees it.
    await write([h2.url], [entry(alice, 'offer/physics', offerBody('35'), T0)])
    const v = await readFolder([h1.url], alice.address, clock.t)
    assert.deepEqual([...liveContent(v).keys()].sort(), ['offer/maths', 'offer/physics', 'profile'])
    const review = (await readFolder([h1.url], bob.address, clock.t)).current.get('review/1')!
    assert.equal((review.entry.body as { about: string }).about, alice.address)
  })

  test('an update and a delete reach readers from either host', async () => {
    clock.advance(MINUTE)
    const known = await readFolder([h1.url], alice.address, clock.t)
    // Only host 2 gets the update; only host 1 gets the delete of the offer.
    await write([h2.url], [entry(alice, 'offer/maths', offerBody('35'), nextTime(clock.t, known, 'offer/maths'))])
    await write([h1.url], [entry(alice, 'offer/physics', null, nextTime(clock.t, known, 'offer/physics'))])
    const v = await readFolder([h1.url, h2.url], alice.address, clock.t)
    assert.equal((v.current.get('offer/maths')!.entry.body as { about: string }).about, '35')
    assert.equal(v.current.get('offer/physics')!.entry.body, null)
    assert.ok((await readAll(h1.url, { profile: alice.address })).entries.some((c) => c.entry.path === 'offer/physics' && c.entry.body === null), 'a delete is an entry like any other')
  })

  test('a host keeps only the newest: an older version is refused when it arrives', async () => {
    const results = await errors(h1, [entry(alice, 'offer/maths', offerBody('1'), T0 - 1), entry(alice, 'offer/maths', offerBody('30'), T0)])
    assert.deepEqual(results, ['older', 'ok'], 'the second is already there')
  })
})

describe('reading', () => {
  test('one folder’s by POST, everyone’s by GET, after a cursor; in the order taken', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      await write([h.url], [profileAt(alice, [h.url], T0), entry(alice, 'offer/a', offerBody('0'), T0)])
      await write([h.url], [profileAt(bob, [h.url], T0), entry(bob, 'offer/b', offerBody('b'), T0)])
      await write([h.url], [entry(alice, 'offer/c', offerBody('1'), T0)])
      assert.deepEqual((await readAll(h.url)).entries.map((c) => c.entry.profile), [alice.address, alice.address, bob.address, bob.address, alice.address])
      assert.deepEqual((await readAll(h.url, { profile: alice.address })).entries.map((c) => c.entry.path), ['profile', 'offer/a', 'offer/c'])
      // This host numbers what it takes 1, 2, 3, …: the second entry taken is 2.
      const second = 2
      const since = await readPage(h.url, { after: second })
      assert.deepEqual(since.entries.map((c) => c.entry.path), ['profile', 'offer/b', 'offer/c'])
      assert.deepEqual((await readPage(h.url, { after: second, profile: alice.address })).entries.map((c) => c.entry.path), ['offer/c'])
      assert.equal((await readPage(h.url, { after: since.cursor })).entries.length, 0, 'nothing new since the cursor')
    } finally {
      await h.close()
    }
  })

  test('a folder is read by POST: its address is in the body, never in a URL', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      await write([h.url], [profileAt(alice, [h.url], T0)])
      const urls: string[] = []
      const counting: typeof fetch = (input, init) => (urls.push(String(input)), fetch(input, init))
      await readAll(h.url, { profile: alice.address, fetch: counting })
      assert.deepEqual((await readFolder([h.url], alice.address, T0, { fetch: counting })).hosts, [h.url])
      const to = await inboxEntry(bob, alice.address, { text: 'hi' }, T0, profileBody('maths'))
      await leave([h.url], [to])
      await readInbox(h.url, alice.address, { fetch: counting })
      assert.ok(urls.length && urls.every((u) => !u.includes(alice.address)), urls.join(' '))
      // The host answers a read with a field it does not know, or no folder, 400.
      for (const body of ['{}', JSON.stringify({ profile: alice.address, more: 1 }), JSON.stringify({ profile: alice.address, after: -1 })]) {
        assert.equal((await fetch(`${h.url}/v1/entries/read`, { method: 'POST', body })).status, 400, body)
      }
    } finally {
      await h.close()
    }
  })
})

describe('a folder copies whole', () => {
  test('to a fresh host, the profile entry, then every entry, and reads the same there', async () => {
    const clock = new Clock(T0)
    const old = await startHost({ now: clock.now })
    const fresh = await startHost({ now: clock.now })
    try {
      await write([old.url], [profileAt(alice, [old.url, fresh.url], T0)])
      await write([old.url], [entry(alice, 'offer/w', offerBody('9'), T0 + 1), entry(alice, 'offer/x', offerBody('3'), T0 + 2), entry(alice, 'offer/w', null, T0 + 3)])
      clock.advance(DAY)
      const there = await readFolder([old.url], alice.address, clock.t)
      const folder = [...there.current.values()].map((c) => c.entry)
      for (const part of [folder.filter((e) => e.path === 'profile'), folder.filter((e) => e.path !== 'profile')]) {
        const [outcome] = await write([fresh.url], part)
        assert.ok(outcome!.results.every((r) => r.ok), JSON.stringify(outcome!.results))
      }
      const here = await readFolder([fresh.url], alice.address, clock.t)
      const ids = (v: typeof here) => [...v.current.values()].map((c) => c.id).sort()
      assert.deepEqual(ids(here), ids(there))
      assert.deepEqual([...here.current.keys()].sort(), ['offer/w', 'offer/x', 'profile'])
      assert.equal(here.current.get('offer/w')!.entry.body, null, 'a delete copies as the delete it is')
    } finally {
      await old.close()
      await fresh.close()
    }
  })
})

describe('a host that closes, or blocks a reader', () => {
  test('costs nothing lasting: readers use the other host; the app writes its copies to a new one; the folder is the same, entry for entry', async () => {
    const clock = new Clock(T0)
    const one = await startHost({ now: clock.now })
    const two = await startHost({ now: clock.now })
    const three = await startHost({ now: clock.now })
    try {
      // The app writes every entry to every host the profile entry names, and keeps its own copies.
      const copies: SignedEntry[] = [entry(aliceBuyer, 'offer/wanted', offerBody('25'), T0), entry(aliceBuyer, 'offer/other', offerBody('5'), T0)]
      await write([one.url, two.url], [profileAt(aliceBuyer, [one.url, two.url], T0, 'algebra'), ...copies])
      const ids = (v: { current: Map<string, { id: string; entry: SignedEntry }> }) => [...v.current.values()].filter((c) => c.entry.path !== 'profile').map((c) => c.id).sort()
      const was = ids(await readFolder([one.url], aliceBuyer.address, clock.t))

      // Host one blocks every read, then closes.
      one.read = () => {
        throw new Error('blocked')
      }
      assert.deepEqual(ids(await readFolder([one.url, two.url], aliceBuyer.address, clock.t)), was)
      await one.close()

      // The app replaces it: a profile entry naming the new host, then its copies there.
      clock.advance(MINUTE)
      await write([two.url, three.url], [profileAt(aliceBuyer, [two.url, three.url], clock.t, 'algebra')])
      const [outcome] = await write([three.url], copies)
      assert.ok(outcome!.results.every((r) => r.ok), JSON.stringify(outcome!.results))

      const after = await readFolder([three.url], aliceBuyer.address, clock.t)
      assert.deepEqual(ids(after), was)
      assert.deepEqual(after.hosts, [two.url, three.url])
    } finally {
      await two.close()
      await three.close()
    }
  })

  test('to leave a host, write a profile entry that no longer names it, to every host: a reader that still asks the old one is pointed on', async () => {
    const old = await startHost({ now: () => T0 })
    const kept = await startHost({ now: () => T0 })
    try {
      const both = [old.url, kept.url]
      await write(both, [profileAt(alice, both, T0), entry(alice, 'offer/a', offerBody('1'), T0)])
      await write(both, [profileAt(alice, [kept.url], T0 + 1)])

      // The old host may keep its copies; the reader follows the profile entry it finds there.
      const viaOld = await readFolder([old.url], alice.address, T0 + MINUTE)
      assert.deepEqual(viaOld.hosts, [kept.url])
      assert.ok(viaOld.current.get('offer/a'))
      const viaKept = await readFolder(viaOld.hosts, alice.address, T0 + MINUTE)
      assert.deepEqual(viaKept.hosts, [kept.url])
      assert.ok(viaKept.current.get('offer/a'))
    } finally {
      await old.close()
      await kept.close()
    }
  })
})

describe('hosts that misbehave', () => {
  test('a host that withholds an update, rolls back, or serves forged lines cannot change what a reader shows', async () => {
    const honest = await startHost({ now: () => T0 })
    const bad = await startHost({ now: () => T0 })
    try {
      const urls = [honest.url, bad.url]
      await write(urls, [profileAt(alice, urls, T0), entry(alice, 'offer/maths', offerBody('30'), T0)])
      const newer = entry(alice, 'offer/maths', offerBody('45'), T0 + MINUTE)
      await write([honest.url], [newer]) // the bad host "missed" it

      // The bad host also serves a forged version: same fields, price changed, old signature.
      const forgedLine = encodeEntry({ ...newer, body: offerBody('4500') })
      const serve = bad.read.bind(bad)
      bad.read = (options) => {
        const out = serve(options)
        return out.lines.length ? { lines: [...out.lines, forgedLine], cursor: out.cursor } : out
      }
      assert.equal((await readPage(bad.url)).refused.length, 1)
      const v = await readFolder([bad.url], alice.address, T0 + 2 * MINUTE)
      assert.equal(v.current.get('offer/maths')!.id, checkEntry(newer).id)
    } finally {
      await honest.close()
      await bad.close()
    }
  })

  test('a host that fails is skipped, and the reader is told which and why', async () => {
    const [up, down] = await Promise.all([startHost({ now: () => T0 }), startHost({ now: () => T0 })])
    await down.close()
    try {
      await write([up.url], [profileAt(alice, [up.url], T0)])
      const v = await readFolder([down.url, up.url], alice.address, T0)
      assert.ok(v.current.has('profile'), 'the host that answered still counts')
      assert.deepEqual(v.failed.map((f) => f.host), [down.url])
      assert.ok(v.failed[0]!.error.length > 0)
    } finally {
      await up.close()
    }
  })
})

describe('limits: each host’s own batch and page; each reader’s own size; 60 seconds a read', () => {
  const bytes = (lines: string[]) => lines.reduce((n, l) => n + Buffer.byteLength(l) + 1, 0)

  test('a host chooses its page: a reader follows the cursor whatever the size, and a page always holds one entry', async () => {
    for (const page of [2, 1]) {
      const h = await startHost({ now: () => T0 })
      h.page = page
      try {
        await write([h.url], Array.from({ length: 5 }, (_, i) => entry(alice, `offer/${i}`, offerBody('1'), T0)))
        assert.equal(h.read().lines.length, page)
        assert.equal((await readAll(h.url)).entries.length, 5, String(page))
      } finally {
        await h.close()
      }
    }
  })

  test('a reader takes a page of any length, and refuses a line longer than it takes without holding it', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      const atCap = encodeEntry(sizedEntry(alice, 'stamp/a', MAX_LINE_READ))
      h.read = () => ({ lines: Array(100).fill(atCap), cursor: 1 })
      const page = await readPage(h.url)
      assert.ok(bytes(Array(100).fill(atCap)) > 6_000_000)
      assert.equal(page.entries.length, 100)
      h.read = () => ({ lines: ['x'.repeat(5_000_000), atCap], cursor: 2 })
      const long = await readPage(h.url)
      assert.deepEqual([long.entries.length, long.refused], [1, [{ line: '', reason: 'size' }]])
    } finally {
      await h.close()
    }
  })

  test('a reader ignores a line longer than it takes: 65,536 bytes unless told otherwise', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      const atCap = sizedEntry(alice, 'stamp/a', MAX_LINE_READ)
      const over = sizedEntry(alice, 'stamp/b', MAX_LINE_READ + 1, 1)
      await write([h.url], [atCap, over])
      const page = await readPage(h.url)
      assert.deepEqual(page.entries.map((c) => c.id), [checkEntry(atCap).id])
      assert.deepEqual(page.refused.map((r) => r.reason), ['size'])
      assert.equal((await readPage(h.url, { maxBytes: 200_000 })).entries.length, 2)
    } finally {
      await h.close()
    }
  })

  test('a reader gives up on a host that stalls, before its answer or during it', async () => {
    const stall = createServer((req, res) => {
      if (req.url!.includes('after=1')) res.writeHead(200, { 'forest-cursor': '1' }).write('{')
    })
    await new Promise<void>((resolve) => stall.listen(0, '127.0.0.1', resolve))
    const url = `http://127.0.0.1:${(stall.address() as { port: number }).port}`
    try {
      await assert.rejects(readPage(url, { timeout: 200 }), { name: 'TimeoutError' })
      await assert.rejects(readPage(url, { after: 1, timeout: 200 }), { name: 'TimeoutError' })
    } finally {
      stall.closeAllConnections()
      await new Promise((resolve) => stall.close(resolve))
    }
  })

  test('a read ends with an error on a cursor that is not a whole number or does not move forward, and the whole read is bounded', async () => {
    const line = encodeEntry(entry(alice, 'offer/a', offerBody('1'), T0)) + '\n'
    let cursor = 'x'
    let forward = 0
    const odd = createServer((req, res) => {
      const at = req.method === 'POST' ? String(++forward) : cursor
      req.resume()
      res.writeHead(200, { 'content-type': 'application/x-ndjson', 'forest-cursor': at }).end(line)
    })
    await new Promise<void>((resolve) => odd.listen(0, '127.0.0.1', resolve))
    const url = `http://127.0.0.1:${(odd.address() as { port: number }).port}`
    try {
      for (const c of ['x', '', '-1', '1.5', '01', '1e3', String(2 ** 53)]) {
        cursor = c
        await assert.rejects(readAll(url), /not a whole number/, JSON.stringify(c))
      }
      cursor = '0'
      await assert.rejects(readAll(url), /does not move forward/, 'a page of lines that leaves the cursor where it was')
      // A host whose cursor moves forward forever: the whole read, every page of it, ends at its timeout.
      await assert.rejects(readAll(url, { profile: alice.address, timeout: 300 }), { name: 'TimeoutError' })
      assert.ok(forward > 1, 'more than one page was read')
    } finally {
      odd.closeAllConnections()
      await new Promise((resolve) => odd.close(resolve))
    }
  })

  test('a write reads the status first: a 413, whatever its body, or one batch result splits the request, and no other status is parsed', async () => {
    const h = await startHost({ now: () => T0 })
    const asked: number[] = []
    const front = createServer(async (req, res) => {
      const chunks: Buffer[] = []
      for await (const chunk of req) chunks.push(chunk as Buffer)
      const body = Buffer.concat(chunks).toString()
      const lines = body.split('\n').filter((l) => l)
      asked.push(lines.length)
      if (req.url === '/broken/v1/entries') return void res.writeHead(502, { 'content-type': 'text/html' }).end('<html>bad gateway</html>')
      // A host that takes one line a request: by its status, or by one batch result.
      if (lines.length > 1 && req.url === '/batch/v1/entries') return void res.writeHead(200, { 'content-type': 'application/x-ndjson' }).end('{"i":0,"ok":false,"error":"batch","message":"one line a request"}\n')
      if (lines.length > 1) return void res.writeHead(413, { 'content-type': 'text/html' }).end('<html>too large</html>')
      const out = await fetch(`${h.url}/v1/entries`, { method: 'POST', body })
      res.writeHead(out.status, { 'content-type': 'application/x-ndjson' }).end(await out.text())
    })
    await new Promise<void>((resolve) => front.listen(0, '127.0.0.1', resolve))
    const url = `http://127.0.0.1:${(front.address() as { port: number }).port}`
    try {
      const entries = ['offer/a', 'offer/b', 'offer/c'].map((path) => entry(alice, path, offerBody('1'), T0))
      const [outcome] = await write([url], entries)
      assert.deepEqual(outcome!.results.map((r) => [r.i, r.ok]), [[0, true], [1, true], [2, true]])
      assert.deepEqual(asked, [3, 2, 1, 1, 1], 'in halves, down to one line')
      asked.length = 0
      const more = ['offer/d', 'offer/e', 'offer/f'].map((path) => entry(alice, path, offerBody('1'), T0))
      const [batched] = await write([`${url}/batch`], [entry(alice, 'offer/a', offerBody('1'), T0 - 1), ...more])
      assert.deepEqual(batched!.results.map((r) => [r.i, r.error ?? 'ok']), [[0, 'older'], [1, 'ok'], [2, 'ok'], [3, 'ok']], 'each result at its place in the request')
      assert.deepEqual(asked, [4, 2, 1, 1, 2, 1, 1])
      const [broken] = await write([`${url}/broken`], entries.slice(0, 1))
      assert.deepEqual([broken!.status, broken!.results, broken!.error], [502, [], undefined])
    } finally {
      await new Promise((resolve) => front.close(resolve))
      await h.close()
    }
  })

  test('a reader reads through the fetch it is given, and may refuse redirects', async () => {
    const h = await startHost({ now: () => T0 })
    const away = createServer((req, res) => res.writeHead(307, { location: `${h.url}${req.url}` }).end())
    await new Promise<void>((resolve) => away.listen(0, '127.0.0.1', resolve))
    const url = `http://127.0.0.1:${(away.address() as { port: number }).port}`
    try {
      await write([h.url], [profileAt(alice, [h.url], T0)])
      assert.equal((await readPage(url)).entries.length, 1, 'followed unless told')
      await assert.rejects(readPage(url, { redirect: 'error' }))
      await assert.rejects(readAll(url, { redirect: 'error' }))
      assert.equal((await readFolder([url], alice.address, T0, { redirect: 'error' })).current.size, 0, 'a host that redirects is skipped')

      // The caller's fetch: one that refuses some addresses, say.
      const asked: string[] = []
      const counting: typeof fetch = (input, init) => {
        asked.push(String(input))
        return fetch(input, init)
      }
      await readPage(h.url, { fetch: counting })
      await readAll(h.url, { fetch: counting, profile: alice.address })
      await readFolder([h.url], alice.address, T0, { fetch: counting })
      assert.deepEqual(asked.map((u) => new URL(u).pathname), ['/v1/entries', '/v1/entries/read', '/v1/entries/read', '/v1/entries/read', '/v1/entries/read'])
      await assert.rejects(readPage(h.url, { fetch: async () => Promise.reject(new Error('a private address')) }), /a private address/)
    } finally {
      away.closeAllConnections()
      await new Promise((resolve) => away.close(resolve))
      await h.close()
    }
  })

  test('writing, leaving, listing and uploading go through the fetch given too, and may refuse redirects', async () => {
    const h = await startHost({ now: () => T0 })
    const away = createServer((req, res) => res.writeHead(307, { location: `${h.url}${req.url}` }).end())
    await new Promise<void>((resolve) => away.listen(0, '127.0.0.1', resolve))
    const url = `http://127.0.0.1:${(away.address() as { port: number }).port}`
    const profile = profileAt(alice, [h.url], T0)
    const left = await inboxEntry(bob, alice.address, { text: 'hi' }, T0, profileBody('maths'))
    const photo = Uint8Array.from({ length: 100 }, (_, i) => i)
    const name = fileOf(photo, 'image/png')
    try {
      const asked: string[] = []
      const counting: typeof fetch = (input, init) => {
        asked.push(String(input))
        return fetch(input, init)
      }
      await write([h.url], [profile, entry(alice, 'photo/1', { files: [name] }, T0)], { fetch: counting })
      await leave([h.url], [left], { fetch: counting })
      await readInbox(h.url, alice.address, { fetch: counting })
      await upload([h.url], photo, 'image/png', { fetch: counting })
      assert.deepEqual(asked.map((u) => new URL(u).pathname), ['/v1/entries', '/v1/inbox', '/v1/inbox/read', `/v1/files/${name.sha256}`])

      assert.equal((await write([url], [profile], { redirect: 'error' }))[0]!.status, 0, 'a host that redirects takes nothing')
      assert.equal((await leave([url], [left], { redirect: 'error' }))[0]!.status, 0)
      await assert.rejects(readInbox(url, alice.address, { redirect: 'error' }))
      assert.equal((await upload([url], photo, 'image/png', { redirect: 'error' }))[0]!.status, 0)
      assert.equal((await write([url], [profile]))[0]!.status, 200, 'followed unless told')
      // An upload is sent again whole, its payment with it: the host checks the hash before it says it holds the bytes.
      const paid: Array<string | undefined> = []
      const take = h.upload.bind(h)
      h.upload = async (file, type, bytes, payment) => (paid.push(payment), take(file, type, bytes))
      assert.deepEqual((await upload([url], photo, 'image/png', { payment: (host) => `paid ${host}` })).map((o) => [o.status, o.ok]), [[200, true]], 'followed unless told')
      assert.deepEqual(paid, [`paid ${url}`])
    } finally {
      away.closeAllConnections()
      await new Promise((resolve) => away.close(resolve))
      await h.close()
    }
  })
})

describe('payment: the forest-payment header a write carries', () => {
  /** A request's body, as the client sends it: each line and a newline. */
  const bodyOf = (lines: string[]) => utf8(lines.map((l) => l + '\n').join(''))
  /** A payment that names its host and the hash of the bytes it was given: another for each host and each request. */
  const payment: Payment = (host, body) => `${host} ${hex.encode(sha256(body))}`

  test('each write, inbox entry and upload carries what the payment gives that host for that request; with none, or none given, no header', async () => {
    const hosts = [await startHost({ now: () => T0 }), await startHost({ now: () => T0 })]
    const urls = hosts.map((h) => h.url)
    /** What each host was handed: the request, and its header. */
    const got = new Map<string, Array<[string, string | undefined]>>()
    for (const h of hosts) {
      const seen: Array<[string, string | undefined]> = []
      got.set(h.url, seen)
      const [accept, leaveIt, uploadIt] = [h.accept.bind(h), h.leave.bind(h), h.upload.bind(h)]
      h.accept = async (lines, paid) => (seen.push(['entries', paid]), accept(lines))
      h.leave = async (lines, paid) => (seen.push(['inbox', paid]), leaveIt(lines))
      h.upload = async (name, type, bytes, paid) => (seen.push(['file', paid]), uploadIt(name, type, bytes))
    }
    try {
      const photo = Uint8Array.from({ length: 100 }, (_, i) => i)
      const name = fileOf(photo, 'image/png')
      const entries = [profileAt(alice, urls, T0), entry(alice, 'photo/1', { files: [name] }, T0)]
      const left = await inboxEntry(bob, alice.address, { text: 'hi' }, T0, profileBody('maths'))
      for (const outcome of await write(urls, entries, { payment })) assert.ok(outcome.results.every((r) => r.ok), JSON.stringify(outcome))
      await leave(urls, [left], { payment })
      assert.ok((await upload(urls, photo, 'image/png', { payment })).every((o) => o.ok))
      await write(urls, [entry(alice, 'photo/2', { files: [name] }, T0)])
      await leave(urls, [await inboxEntry(bob, alice.address, { text: 'again' }, T0, profileBody('maths'))])
      await upload(urls, photo, 'image/png')
      await write(urls, [entry(alice, 'photo/3', { files: [name] }, T0)], { payment: () => undefined })
      for (const url of urls) {
        assert.deepEqual(got.get(url), [
          ['entries', `${url} ${hex.encode(sha256(bodyOf(entries.map(encodeEntry))))}`],
          ['inbox', `${url} ${hex.encode(sha256(bodyOf([encodeInbox(left)])))}`],
          ['file', `${url} ${name.sha256}`],
          ['entries', undefined],
          ['inbox', undefined],
          ['file', undefined],
          ['entries', undefined],
        ])
      }
    } finally {
      for (const h of hosts) await h.close()
    }
  })

  test('a batch sent again in halves pays for each request it sends, with that request’s bytes', async () => {
    const h = await startHost({ now: () => T0 })
    const given: string[] = []
    const accept = h.accept.bind(h)
    // A host that takes one line a request, and is handed each request's payment.
    h.accept = async (lines, paid) => {
      given.push(paid ?? 'none')
      return lines.length > 1 ? [{ i: 0, ok: false, error: 'batch', message: 'one line a request' }] : accept(lines)
    }
    try {
      const entries = ['offer/a', 'offer/b'].map((path) => entry(alice, path, offerBody('1'), T0))
      const [outcome] = await write([h.url], entries, { payment })
      assert.ok(outcome!.results.every((r) => r.ok), JSON.stringify(outcome))
      const lines = entries.map(encodeEntry)
      assert.deepEqual(given, [lines, lines.slice(0, 1), lines.slice(1)].map((l) => `${h.url} ${hex.encode(sha256(bodyOf(l)))}`))
    } finally {
      await h.close()
    }
  })
})
