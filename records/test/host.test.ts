// End to end over HTTP: two hosts, a profile publishing, readers reading both, updates, deletes,
// pruning, moving hosts, and hosts that misbehave.

import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { connect } from 'node:net'
import { after, before, describe, test } from 'node:test'
import { MAX_LINE_READ, deliver, publish, pull, readAll, readPage, readProfile } from '../src/client.ts'
import { pullRequest, signMessage } from '../src/message.ts'
import { DAY, DEFAULT_MAX_LINE_BYTES, DEFAULT_MAX_PAGE_BYTES, type Host } from '../src/host.ts'
import { type SignedRecord, checkRecord, encodeRecord, signAs, signingInput } from '../src/record.ts'
import { liveContent } from '../src/view.ts'
import { hostsRecord, nextTime, ownerRecord } from '../src/write.ts'
import { MINUTE, T0, alice, aliceBuyer, bob, offerBody, profileBody, reviewBody, sizedRecord, stranger } from './fixtures.ts'
import { Clock, startHost } from './helpers.ts'

const errors = async (host: Host, records: SignedRecord[]) => (await publish([host.url], records))[0]!.results.map((r) => r.error ?? 'ok')

describe('two hosts, readers', () => {
  const clock = new Clock(T0)
  let h1: Host
  let h2: Host
  before(async () => {
    h1 = await startHost({ now: clock.now })
    h2 = await startHost({ now: clock.now })
  })
  after(async () => {
    await h1.close()
    await h2.close()
  })

  test('publish a profile, an offer and a review to two hosts; a reader that knows one host finds the other', async () => {
    const urls = [h1.url, h2.url]
    const records: SignedRecord[] = [
      hostsRecord(alice, urls, T0),
      ownerRecord(alice, 'profile', profileBody('calculus'), T0),
      ownerRecord(alice, 'offer/maths', offerBody('30'), T0),
      hostsRecord(bob, urls, T0),
      ownerRecord(bob, 'review/1', reviewBody(alice.address), T0),
    ]
    for (const outcome of await publish(urls, records)) {
      assert.equal(outcome.status, 200)
      assert.ok(outcome.results.every((r) => r.ok), JSON.stringify(outcome.results))
    }
    // Host 2 alone gets one more offer: a reader that starts at host 1 still sees it.
    await publish([h2.url], [ownerRecord(alice, 'offer/physics', offerBody('35'), T0)])
    const v = await readProfile([h1.url], alice.address, clock.t)
    assert.deepEqual([...liveContent(v).keys()].sort(), ['offer/maths', 'offer/physics', 'profile'])
    const review = (await readProfile([h1.url], bob.address, clock.t)).current.get('review/1')!
    assert.equal((review.record.body as { about: string }).about, alice.address)
  })

  test('an update and a delete reach readers from either host; what they replaced goes after keep days', async () => {
    clock.advance(MINUTE)
    const known = await readProfile([h1.url], alice.address, clock.t)
    // Only host 2 gets the update; only host 1 gets the delete of the profile record.
    await publish([h2.url], [ownerRecord(alice, 'offer/maths', offerBody('35'), nextTime(clock.t, known, 'offer/maths'))])
    await publish([h1.url], [ownerRecord(alice, 'profile', null, nextTime(clock.t, known, 'profile'))])
    const v = await readProfile([h1.url, h2.url], alice.address, clock.t)
    assert.equal((v.current.get('offer/maths')!.record.body as { about: string }).about, '35')
    assert.equal(v.current.get('profile')!.record.body, null)

    // Host 2 keeps the replaced offer for its keep days (30 by default), then forgets it.
    const was = h2.count(alice.address)
    assert.equal(await h2.prune(clock.t + 29 * DAY), 0)
    assert.equal(await h2.prune(clock.t + 31 * DAY), 1)
    assert.equal(h2.count(alice.address), was - 1)
    // A delete is current: it is never pruned, so the profile record stays deleted.
    await h1.prune(clock.t + 31 * DAY)
    assert.ok((await readAll(h1.url, { profile: alice.address })).records.some((c) => c.record.path === 'profile' && c.record.body === null))
  })

  test('a host keeps only the newest: an older version is refused when it arrives', async () => {
    const results = await errors(h1, [ownerRecord(alice, 'offer/maths', offerBody('1'), T0 - 1), ownerRecord(alice, 'offer/maths', offerBody('30'), T0)])
    assert.deepEqual(results, ['older', 'ok'], 'the second is already there')
  })
})

describe('keep days are the host’s', () => {
  test('a host with keep days 0 forgets a replaced version at its next prune', async () => {
    const h = await startHost({ now: () => T0, keepDays: 0 })
    try {
      await publish([h.url], [ownerRecord(alice, 'offer/a', offerBody('1'), T0), ownerRecord(alice, 'offer/a', offerBody('2'), T0 + 1)])
      assert.equal(await h.prune(T0), 1)
      assert.deepEqual((await readAll(h.url)).records.map((c) => c.record.time), [T0 + 1])
    } finally {
      await h.close()
    }
  })
})

describe('the socket', () => {
  test('GET by profile, after a cursor, or both; in the order taken', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      await publish([h.url], [hostsRecord(alice, [h.url], T0), ownerRecord(alice, 'profile', profileBody('calculus'), T0)])
      await publish([h.url], [hostsRecord(bob, [h.url], T0), ownerRecord(bob, 'profile', profileBody('chemistry'), T0)])
      await publish([h.url], [ownerRecord(alice, 'offer/a', offerBody('1'), T0)])
      assert.deepEqual((await readAll(h.url)).records.map((c) => c.record.profile), [alice.address, alice.address, bob.address, bob.address, alice.address])
      assert.deepEqual((await readAll(h.url, { profile: alice.address })).records.map((c) => c.record.path), ['hosts', 'profile', 'offer/a'])
      // Numbers come from the clock, in microseconds: the second record taken at T0 is T0 × 1000 + 1.
      const second = T0 * 1000 + 1
      const since = await readPage(h.url, { after: second })
      assert.deepEqual(since.records.map((c) => c.record.path), ['hosts', 'profile', 'offer/a'])
      assert.deepEqual((await readPage(h.url, { after: second, profile: alice.address })).records.map((c) => c.record.path), ['offer/a'])
      assert.equal((await readPage(h.url, { after: since.cursor })).records.length, 0, 'nothing new since the cursor')
    } finally {
      await h.close()
    }
  })

  test('POST /v1/records/read: the profile and the cursor in the body, the same answer as the GET', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      await publish([h.url], [hostsRecord(alice, [h.url], T0), ownerRecord(alice, 'profile', profileBody('calculus'), T0), ownerRecord(bob, 'profile', profileBody('chemistry'), T0)])
      const answer = async (res: Response) => [res.status, res.headers.get('forest-cursor'), await res.text()]
      const posted = async (body: string) => answer(await fetch(`${h.url}/v1/records/read`, { method: 'POST', body }))
      const got = async (query: string) => answer(await fetch(`${h.url}/v1/records?${query}`))
      assert.deepEqual(await posted('{}'), await got(''))
      assert.deepEqual(await posted(JSON.stringify({ profile: alice.address })), await got(`profile=${alice.address}`))
      assert.deepEqual(await posted(JSON.stringify({ profile: alice.address, after: T0 * 1000 })), await got(`profile=${alice.address}&after=${T0 * 1000}`))
      assert.deepEqual(await posted(JSON.stringify({ profile: 'not-an-address' })), await got('profile=not-an-address'))
      for (const bad of ['', 'nope', '[]', '{"after":-1}', '{"after":1.5}', '{"after":"1"}', '{"profile":5}', '{"more":1}']) assert.equal((await posted(bad))[0], 400, bad)
      assert.equal((await posted(JSON.stringify({ profile: 'x'.repeat(2000) })))[0], 413)
      assert.equal((await fetch(`${h.url}/v1/records/read`)).status, 405, 'the GET form is /v1/records')

      // The library reads the same records with post: true, and no URL it asks names the profile.
      const urls: string[] = []
      const real = globalThis.fetch
      globalThis.fetch = (input, init) => (urls.push(String(input)), real(input, init))
      let inBody: Awaited<ReturnType<typeof readAll>>
      try {
        inBody = await readAll(h.url, { profile: alice.address, post: true })
        assert.deepEqual((await readProfile([h.url], alice.address, T0, { post: true })).hosts, [h.url])
      } finally {
        globalThis.fetch = real
      }
      assert.deepEqual(inBody.records, (await readAll(h.url, { profile: alice.address })).records)
      assert.ok(urls.length && urls.every((u) => !u.includes(alice.address)), urls.join(' '))
    } finally {
      await h.close()
    }
  })

  test('only /v1/records, only GET and POST, and a cursor is a whole number', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      assert.equal((await fetch(`${h.url}/v1/entries`)).status, 404)
      assert.equal((await fetch(`${h.url}/v1/records`, { method: 'PUT' })).status, 405)
      for (const after of ['-1', '1.5', 'x']) assert.equal((await fetch(`${h.url}/v1/records?after=${after}`)).status, 400, after)
      const many = Array.from({ length: 101 }, (_, i) => encodeRecord(ownerRecord(alice, `offer/${i}`, offerBody('1'), T0)))
      assert.deepEqual(await h.accept(many), [{ i: 0, ok: false, error: 'batch', message: 'at most 100 records a request' }])
    } finally {
      await h.close()
    }
  })

  test('a request target that is no path, such as //, is answered 400, and the host goes on', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      const { port } = new URL(h.url)
      const socket = connect(Number(port), '127.0.0.1')
      socket.write('GET // HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n')
      const answer = await new Promise<string>((resolve) => {
        let got = ''
        socket.on('data', (d) => (got += d))
        socket.on('close', () => resolve(got))
      })
      assert.match(answer, /^HTTP\/1\.1 400/)
      assert.equal((await fetch(`${h.url}/v1/records`)).status, 200)
    } finally {
      await h.close()
    }
  })

  test('a host is open: it takes a profile whose hosts record does not name it, or that has none', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      assert.deepEqual(await errors(h, [hostsRecord(alice, ['https://elsewhere.example'], T0), ownerRecord(alice, 'profile', profileBody('maths'), T0), ownerRecord(bob, 'profile', profileBody('physics'), T0)]), ['ok', 'ok', 'ok'])
    } finally {
      await h.close()
    }
  })
})

describe('a folder copies whole', () => {
  test('to a fresh host, hosts record, then every record, and reads the same there', async () => {
    const clock = new Clock(T0)
    const old = await startHost({ now: clock.now })
    const fresh = await startHost({ now: clock.now })
    try {
      await publish([old.url], [hostsRecord(alice, [old.url, fresh.url], T0), ownerRecord(alice, 'profile', profileBody('maths'), T0)])
      await publish([old.url], [ownerRecord(alice, 'offer/w', offerBody('9'), T0 + 1), ownerRecord(alice, 'offer/x', offerBody('3'), T0 + 2), ownerRecord(alice, 'offer/w', null, T0 + 3)])
      clock.advance(DAY)
      const there = await readProfile([old.url], alice.address, clock.t)
      const folder = [...there.current.values()].map((c) => c.record)
      for (const part of [folder.filter((r) => r.path === 'hosts'), folder.filter((r) => r.path !== 'hosts')]) {
        const [outcome] = await publish([fresh.url], part)
        assert.ok(outcome!.results.every((r) => r.ok), JSON.stringify(outcome!.results))
      }
      const here = await readProfile([fresh.url], alice.address, clock.t)
      const ids = (v: typeof here) => [...v.current.values()].map((c) => c.id).sort()
      assert.deepEqual(ids(here), ids(there))
      assert.deepEqual([...here.current.keys()].sort(), ['hosts', 'offer/w', 'offer/x', 'profile'])
      assert.equal(here.current.get('offer/w')!.record.body, null, 'a delete copies as the delete it is')
    } finally {
      await old.close()
      await fresh.close()
    }
  })
})

describe('a host that closes, or blocks a reader', () => {
  test('costs nothing lasting: readers use the other host; the app posts its copies to a new one; the profile is the same, record for record', async () => {
    const clock = new Clock(T0)
    const one = await startHost({ now: clock.now })
    const two = await startHost({ now: clock.now })
    const three = await startHost({ now: clock.now })
    try {
      // The app posts every record to every host in the hosts record, and keeps its own copies.
      const copies: SignedRecord[] = [hostsRecord(aliceBuyer, [one.url, two.url], T0), ownerRecord(aliceBuyer, 'profile', profileBody('algebra'), T0), ownerRecord(aliceBuyer, 'offer/wanted', offerBody('25'), T0)]
      await publish([one.url, two.url], copies)
      const ids = (v: { current: Map<string, { id: string; record: SignedRecord }> }) => [...v.current.values()].filter((c) => c.record.path !== 'hosts').map((c) => c.id).sort()
      const was = ids(await readProfile([one.url], aliceBuyer.address, clock.t))

      // Host one blocks every read, then closes.
      one.read = () => {
        throw new Error('blocked')
      }
      assert.deepEqual(ids(await readProfile([one.url, two.url], aliceBuyer.address, clock.t)), was)
      await one.close()

      // The app replaces it: a hosts record naming the new host, then its copies there.
      clock.advance(MINUTE)
      const moved = hostsRecord(aliceBuyer, [two.url, three.url], clock.t)
      await publish([two.url, three.url], [moved])
      const [outcome] = await publish([three.url], copies)
      assert.ok(outcome!.results.every((r) => r.ok || r.error === 'older'), JSON.stringify(outcome!.results))

      const after = await readProfile([three.url], aliceBuyer.address, clock.t)
      assert.deepEqual(ids(after), was)
      assert.deepEqual(after.hosts, [two.url, three.url])
    } finally {
      await two.close()
      await three.close()
    }
  })

  test('to leave a host, post a hosts record that no longer names it, to every host: a reader that still asks the old one is pointed on', async () => {
    const old = await startHost({ now: () => T0 })
    const kept = await startHost({ now: () => T0 })
    try {
      const both = [old.url, kept.url]
      await publish(both, [hostsRecord(alice, both, T0), ownerRecord(alice, 'profile', profileBody('maths'), T0)])
      await publish(both, [hostsRecord(alice, [kept.url], T0 + 1)])

      // The old host may keep its copies; the reader follows the hosts record it finds there.
      const viaOld = await readProfile([old.url], alice.address, T0 + MINUTE)
      assert.deepEqual(viaOld.hosts, [kept.url])
      assert.ok(viaOld.current.get('profile'))
      const viaKept = await readProfile(viaOld.hosts, alice.address, T0 + MINUTE)
      assert.deepEqual(viaKept.hosts, [kept.url])
      assert.ok(viaKept.current.get('profile'))
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
      await publish(urls, [hostsRecord(alice, urls, T0), ownerRecord(alice, 'offer/maths', offerBody('30'), T0)])
      const newer = ownerRecord(alice, 'offer/maths', offerBody('45'), T0 + MINUTE)
      await publish([honest.url], [newer]) // the bad host "missed" it

      // The bad host also serves a forged version: same fields, price changed, old signature.
      const forgedLine = encodeRecord({ ...newer, body: offerBody('4500') })
      const serve = bad.read.bind(bad)
      bad.read = (options) => {
        const out = serve(options)
        return out.lines.length ? { lines: [...out.lines, forgedLine], cursor: out.cursor } : out
      }
      assert.equal((await readPage(bad.url)).refused.length, 1)
      const v = await readProfile([bad.url], alice.address, T0 + 2 * MINUTE)
      assert.equal(v.current.get('offer/maths')!.id, checkRecord(newer).id)
    } finally {
      await honest.close()
      await bad.close()
    }
  })

  test('a host refuses what does not check: forged, signed by a key that is not the main key, dated ahead, not canonical', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      const good = ownerRecord(alice, 'offer/a', offerBody('1'), T0)
      const unsigned = { v: 1 as const, profile: alice.address, path: 'offer/c', time: T0, body: offerBody('1') }
      const results = await h.accept([
        encodeRecord({ ...good, body: offerBody('2') }),
        encodeRecord({ ...unsigned, sig: signAs(stranger, stranger.address, signingInput(unsigned)) }),
        encodeRecord(ownerRecord(alice, 'offer/b', offerBody('1'), T0 + 11 * MINUTE)),
        JSON.stringify(good, null, 1),
        encodeRecord(good),
      ])
      assert.deepEqual(results.map((r) => r.error ?? 'ok'), ['signature', 'signature', 'future', 'canonical', 'ok'])
    } finally {
      await h.close()
    }
  })

  test('a host that fails is skipped, and the reader is told which and why', async () => {
    const [up, down] = await Promise.all([startHost({ now: () => T0 }), startHost({ now: () => T0 })])
    await down.close()
    try {
      await publish([up.url], [hostsRecord(alice, [up.url], T0), ownerRecord(alice, 'profile', profileBody('maths'), T0)])
      const v = await readProfile([down.url, up.url], alice.address, T0)
      assert.ok(v.current.has('profile'), 'the host that answered still counts')
      assert.deepEqual(v.failed.map((f) => f.host), [down.url])
      assert.ok(v.failed[0]!.error.length > 0)
    } finally {
      await up.close()
    }
  })
})

describe('limits: each host’s own size, batch and page; each reader’s own size; 60 seconds a read', () => {
  const bytes = (lines: string[]) => lines.reduce((n, l) => n + Buffer.byteLength(l) + 1, 0)

  test('the reference host ends a page before 4 MB; a reader still gets every record, page by page', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      const full = Array.from({ length: 66 }, (_, i) => sizedRecord(alice, `note/${i}`, DEFAULT_MAX_LINE_BYTES))
      const [outcome] = await publish([h.url], full)
      assert.ok(outcome!.results.every((r) => r.ok), JSON.stringify(outcome!.results.filter((r) => !r.ok)))
      const first = h.read()
      assert.ok(bytes(first.lines) <= DEFAULT_MAX_PAGE_BYTES)
      assert.ok(bytes(first.lines) + DEFAULT_MAX_LINE_BYTES + 1 > DEFAULT_MAX_PAGE_BYTES, 'the next record would not have fit')
      assert.ok(first.lines.length < 66)
      assert.equal((await readAll(h.url)).records.length, 66)
    } finally {
      await h.close()
    }
  })

  test('a host chooses its batch: a client sends a request it finds too big again in halves, and every record lands', async () => {
    const h = await startHost({ now: () => T0, maxBatch: 3 })
    try {
      const records = Array.from({ length: 10 }, (_, i) => ownerRecord(alice, `offer/${i}`, offerBody('1'), T0))
      assert.deepEqual(await h.accept(records.map(encodeRecord)), [{ i: 0, ok: false, error: 'batch', message: 'at most 3 records a request' }])
      const [outcome] = await publish([h.url], [ownerRecord(alice, 'offer/0', offerBody('1'), T0 - 1), ...records])
      assert.equal(outcome!.status, 200)
      assert.deepEqual(outcome!.results.map((r) => r.i), [...Array(11).keys()], 'each result at its place in the request')
      assert.deepEqual(outcome!.results.map((r) => r.error ?? 'ok'), ['ok', ...Array(10).fill('ok')])
      assert.equal(h.view(alice.address).current.size, 10, 'the newer offer/0 replaced the older')
    } finally {
      await h.close()
    }
  })

  test('a host chooses its page: a reader follows the cursor whatever the size, and a page always holds one record', async () => {
    for (const options of [{ maxPageRecords: 2 }, { maxPageBytes: 10 }]) {
      const h = await startHost({ now: () => T0, ...options })
      try {
        await publish([h.url], Array.from({ length: 5 }, (_, i) => ownerRecord(alice, `offer/${i}`, offerBody('1'), T0)))
        assert.ok(h.read().lines.length <= 2 && h.read().lines.length >= 1, JSON.stringify(options))
        assert.equal((await readAll(h.url)).records.length, 5, JSON.stringify(options))
      } finally {
        await h.close()
      }
    }
  })

  test('a reader takes a page of any length, and refuses a line longer than it takes without holding it', async () => {
    const h = await startHost({ now: () => T0 })
    try {
      const atCap = encodeRecord(sizedRecord(alice, 'note/a', MAX_LINE_READ))
      h.read = () => ({ lines: Array(100).fill(atCap), cursor: 1 })
      const page = await readPage(h.url)
      assert.ok(bytes(Array(100).fill(atCap)) > 6_000_000)
      assert.equal(page.records.length, 100)
      h.read = () => ({ lines: ['x'.repeat(5_000_000), atCap], cursor: 2 })
      const long = await readPage(h.url)
      assert.deepEqual([long.records.length, long.refused], [1, [{ line: '', reason: 'size' }]])
    } finally {
      await h.close()
    }
  })

  test('size is a host’s own choice: the reference host takes records of up to 65,536 bytes in UTF-8, unless its operator says otherwise', async () => {
    const atCap = sizedRecord(alice, 'note/a', DEFAULT_MAX_LINE_BYTES)
    // One more byte, from one two-byte character: still 65,536 characters, now 65,537 bytes.
    const over = sizedRecord(alice, 'note/b', DEFAULT_MAX_LINE_BYTES + 1, 1)
    assert.deepEqual([encodeRecord(over).length, Buffer.byteLength(encodeRecord(over))], [DEFAULT_MAX_LINE_BYTES, DEFAULT_MAX_LINE_BYTES + 1])
    const h = await startHost({ now: () => T0 })
    const roomy = await startHost({ now: () => T0, maxLineBytes: 200_000 })
    try {
      assert.deepEqual(await errors(h, [atCap, over]), ['ok', 'size'])
      assert.deepEqual(await errors(roomy, [over]), ['ok'])
    } finally {
      await h.close()
      await roomy.close()
    }
  })

  test('a reader ignores a line longer than it takes: 65,536 bytes unless told otherwise', async () => {
    const h = await startHost({ now: () => T0, maxLineBytes: 200_000 })
    try {
      const atCap = sizedRecord(alice, 'note/a', MAX_LINE_READ)
      const over = sizedRecord(alice, 'note/b', MAX_LINE_READ + 1, 1)
      await publish([h.url], [atCap, over])
      const page = await readPage(h.url)
      assert.deepEqual(page.records.map((c) => c.id), [checkRecord(atCap).id])
      assert.deepEqual(page.refused.map((r) => r.reason), ['size'])
      assert.equal((await readPage(h.url, { maxBytes: 200_000 })).records.length, 2)
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
    const line = encodeRecord(ownerRecord(alice, 'offer/a', offerBody('1'), T0)) + '\n'
    let cursor = 'x'
    let forward = 0
    const odd = createServer((req, res) => {
      const at = req.url!.includes('forward') ? String(++forward) : cursor
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
      await assert.rejects(readAll(url, { profile: 'forward', timeout: 300 }), { name: 'TimeoutError' })
      assert.ok(forward > 1, 'more than one page was read')
    } finally {
      odd.closeAllConnections()
      await new Promise((resolve) => odd.close(resolve))
    }
  })

  test('a publish reads the status first: a 413 splits the batch whatever its body, and no other status is parsed', async () => {
    const h = await startHost({ now: () => T0 })
    const asked: number[] = []
    const front = createServer(async (req, res) => {
      const chunks: Buffer[] = []
      for await (const chunk of req) chunks.push(chunk as Buffer)
      const body = Buffer.concat(chunks).toString()
      const lines = body.split('\n').filter((l) => l)
      asked.push(lines.length)
      if (req.url === '/broken/v1/records') return void res.writeHead(502, { 'content-type': 'text/html' }).end('<html>bad gateway</html>')
      if (lines.length > 1) return void res.writeHead(413, { 'content-type': 'text/html' }).end('<html>too large</html>')
      const out = await fetch(`${h.url}/v1/records`, { method: 'POST', body })
      res.writeHead(out.status, { 'content-type': 'application/x-ndjson' }).end(await out.text())
    })
    await new Promise<void>((resolve) => front.listen(0, '127.0.0.1', resolve))
    const url = `http://127.0.0.1:${(front.address() as { port: number }).port}`
    try {
      const records = ['offer/a', 'offer/b', 'offer/c'].map((path) => ownerRecord(alice, path, offerBody('1'), T0))
      const [outcome] = await publish([url], records)
      assert.deepEqual(outcome!.results.map((r) => [r.i, r.ok]), [[0, true], [1, true], [2, true]])
      assert.deepEqual(asked, [3, 2, 1, 1, 1], 'in halves, down to one line')
      const [broken] = await publish([`${url}/broken`], records.slice(0, 1))
      assert.deepEqual([broken!.status, broken!.results, broken!.error], [502, [], undefined])
    } finally {
      await new Promise((resolve) => front.close(resolve))
      await h.close()
    }
  })

  test('a reader reads through the fetch it is given, and may refuse redirects', async () => {
    const h = await startHost({ now: () => T0 })
    const away = createServer((req, res) => res.writeHead(302, { location: `${h.url}${req.url}` }).end())
    await new Promise<void>((resolve) => away.listen(0, '127.0.0.1', resolve))
    const url = `http://127.0.0.1:${(away.address() as { port: number }).port}`
    try {
      await publish([h.url], [ownerRecord(alice, 'profile', profileBody('maths'), T0)])
      assert.equal((await readPage(url)).records.length, 1, 'followed unless told')
      await assert.rejects(readPage(url, { redirect: 'error' }))
      await assert.rejects(readAll(url, { redirect: 'error' }))
      assert.equal((await readProfile([url], alice.address, T0, { redirect: 'error' })).current.size, 0, 'a host that redirects is skipped')

      // The caller's fetch: one that refuses some addresses, say.
      const asked: string[] = []
      const counting: typeof fetch = (input, init) => {
        asked.push(String(input))
        return fetch(input, init)
      }
      await readPage(h.url, { fetch: counting })
      await readAll(h.url, { fetch: counting, post: true })
      await readProfile([h.url], alice.address, T0, { fetch: counting })
      assert.deepEqual(asked.map((u) => new URL(u).pathname), ['/v1/records', '/v1/records/read', '/v1/records/read', '/v1/records', '/v1/records'])
      await assert.rejects(readPage(h.url, { fetch: async () => Promise.reject(new Error('a private address')) }), /a private address/)
    } finally {
      away.closeAllConnections()
      await new Promise((resolve) => away.close(resolve))
      await h.close()
    }
  })

  test('publishing, delivering and pulling go through the fetch given too, and may refuse redirects', async () => {
    const h = await startHost({ now: () => T0 })
    const away = createServer((req, res) => res.writeHead(307, { location: `${h.url}${req.url}` }).end())
    await new Promise<void>((resolve) => away.listen(0, '127.0.0.1', resolve))
    const url = `http://127.0.0.1:${(away.address() as { port: number }).port}`
    const profile = ownerRecord(alice, 'profile', profileBody('maths'), T0)
    const note = signMessage(bob, alice.address, { private: 'YWdl' }, T0)
    try {
      const asked: string[] = []
      const counting: typeof fetch = (input, init) => {
        asked.push(String(input))
        return fetch(input, init)
      }
      await publish([h.url], [profile], { fetch: counting })
      await deliver([h.url], [note], { fetch: counting })
      await pull(h.url, pullRequest(alice, 0, T0), { fetch: counting })
      assert.deepEqual(asked.map((u) => new URL(u).pathname), ['/v1/records', '/v1/inbox', '/v1/inbox/pull'])

      assert.equal((await publish([url], [profile], { redirect: 'error' }))[0]!.status, 0, 'a host that redirects takes nothing')
      assert.equal((await deliver([url], [note], { redirect: 'error' }))[0]!.status, 0)
      await assert.rejects(pull(url, pullRequest(alice, 0, T0), { redirect: 'error' }))
      assert.equal((await publish([url], [profile]))[0]!.status, 200, 'followed unless told')
    } finally {
      away.closeAllConnections()
      await new Promise((resolve) => away.close(resolve))
      await h.close()
    }
  })

  test('a host drops a request still arriving after its timeout, with 408', async () => {
    const h = await startHost({ now: () => T0, timeout: 200 })
    try {
      const { port } = new URL(h.url)
      const socket = connect(Number(port), '127.0.0.1')
      socket.write('POST /v1/records HTTP/1.1\r\nhost: x\r\ncontent-length: 100\r\n\r\n{"v"')
      const answer = await new Promise<string>((resolve) => {
        let got = ''
        socket.on('data', (d) => (got += d))
        socket.on('close', () => resolve(got))
      })
      assert.match(answer, /^HTTP\/1\.1 408/)
    } finally {
      await h.close()
    }
  })
})
