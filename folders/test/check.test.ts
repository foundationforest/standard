// The host check, run against the minimal host (host.ts): every check passes. Against a host that
// charges to join or for every write, or takes only small lines, as the plug lets a host choose,
// nothing fails, and given a seed whose folders it holds, or the payment it asks for, every check
// runs. Against hosts that break the plug, the check says which promise broke.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { mainKey } from '@foundationforest/keys'
import { utf8 } from '../src/bytes.ts'
import { CHECK_LABELS, type HostCheck, checkHost } from '../src/check.ts'
import { type Payment, type Result, write } from '../src/client.ts'
import { decodeEntry } from '../src/entry.ts'
import { entry } from '../src/write.ts'
import { startHost } from './helpers.ts'
import type { TestHost } from './host.ts'

const statuses = (results: HostCheck[]) => results.map((r) => `${r.status}: ${r.name}${r.why ? `. ${r.why}` : ''}`)
const failed = (results: HostCheck[]) => results.filter((r) => r.status === 'failed').map((r) => r.name)

/** What the charging host below takes as paid: its own business, here one word. */
const PAID = 'paid'
const pay: Payment = () => PAID
/**
 * A host that charges for every write, as the plug lets it: by its own choice, so never for a
 * profile entry of a folder it holds, unless `always`, which breaks the plug.
 */
function charge(h: TestHost, always = false) {
  const [accept, leave, upload] = [h.accept.bind(h), h.leave.bind(h), h.upload.bind(h)]
  const unpaid = { ok: false, error: 'refused', message: 'pay this host' }
  h.accept = async (lines, payment) => {
    const out: Result[] = []
    for (const [i, line] of lines.entries()) {
      let free = true
      try {
        const { profile, path } = decodeEntry(line).entry
        free = !always && path === 'profile' && h.view(profile).current.has('profile')
      } catch {
        // What does not check is refused by the plug, before any choice.
      }
      out.push(payment === PAID || free ? { ...(await accept([line]))[0]!, i } : { i, ...unpaid })
    }
    return out
  }
  h.leave = async (lines, payment) => (payment === PAID ? leave(lines) : lines.map((_, i) => ({ i, ...unpaid })))
  h.upload = async (name, type, bytes, payment) => (payment === PAID ? upload(name, type, bytes) : unpaid)
}

describe('the host check', () => {
  test('the minimal host passes every check, and passes again with the same seed, its folders now held', async () => {
    const h = await startHost()
    try {
      const seed = crypto.getRandomValues(new Uint8Array(32))
      for (let run = 0; run < 2; run++) {
        const results = await checkHost(h.url, { seed })
        assert.equal(results.length, 9)
        assert.ok(results.every((r) => r.status === 'ok'), statuses(results).join('\n'))
      }
      assert.deepEqual(failed(await checkHost(h.url.replace('http', 'ftp'))), ['the host is an origin'])
    } finally {
      await h.close()
    }
  })

  test('a host that charges to join fails nothing; given a seed whose folders it holds, every check runs', async () => {
    const h = await startHost()
    const paid = new Set<string>()
    const held = new Set<string>()
    const accept = h.accept.bind(h)
    // Its own choice, as the plug lets it: a folder joins only once paid, and entries go only to a folder it holds.
    h.accept = async (lines) => {
      const out = []
      for (const [i, line] of lines.entries()) {
        let profile = ''
        let path = ''
        try {
          ;({ profile, path } = decodeEntry(line).entry)
        } catch {
          // What does not check is refused by the plug, before any choice.
        }
        if (profile && !held.has(profile) && !(path === 'profile' && paid.has(profile))) out.push({ i, ok: false, error: 'refused', message: 'pay to join this host' })
        else {
          const [r] = await accept([line])
          if (r!.ok && path === 'profile') held.add(profile)
          out.push({ ...r!, i })
        }
      }
      return out
    }
    try {
      const fresh = await checkHost(h.url)
      assert.deepEqual(failed(fresh), [], statuses(fresh).join('\n'))
      assert.equal(fresh[0]!.status, 'unchecked', 'the folder was not let in')

      const seed = crypto.getRandomValues(new Uint8Array(32))
      for (const label of CHECK_LABELS) {
        const key = await mainKey(seed, label)
        paid.add(key.address)
        await write([h.url], [entry(key, 'profile', { hosts: [h.url] }, Date.now() - 1000)])
      }
      paid.clear()
      const results = await checkHost(h.url, { seed })
      assert.ok(results.every((r) => r.status === 'ok'), statuses(results).join('\n'))
    } finally {
      await h.close()
    }
  })

  test('a host that charges for every write fails nothing; given its payment, every check runs, from a new seed', async () => {
    const h = await startHost()
    charge(h)
    try {
      const unpaid = await checkHost(h.url)
      assert.deepEqual(failed(unpaid), [], statuses(unpaid).join('\n'))
      assert.equal(unpaid[0]!.status, 'unchecked', 'the folder was let in unpaid')
      const paid = await checkHost(h.url, { payment: pay })
      assert.ok(paid.every((r) => r.status === 'ok'), statuses(paid).join('\n'))
    } finally {
      await h.close()
    }
  })

  test('a host that charges for a profile entry of a folder it holds fails the check that a person can always move, even given its payment', async () => {
    const h = await startHost()
    charge(h, true)
    try {
      assert.deepEqual(failed(await checkHost(h.url, { payment: pay })), ['takes a newer profile entry for a folder it holds, so a person can always move'])
    } finally {
      await h.close()
    }
  })

  test('a host that takes only small entries and inbox entries fails nothing', async () => {
    const h = await startHost()
    const CAP = 1000
    const capped = (take: (lines: string[]) => Promise<Result[]>) => async (lines: string[]) => {
      const out: Result[] = []
      for (const [i, line] of lines.entries()) out.push(utf8(line).length > CAP ? { i, ok: false, error: 'size', message: `at most ${CAP} bytes` } : { ...(await take([line]))[0]!, i })
      return out
    }
    h.accept = capped(h.accept.bind(h))
    h.leave = capped(h.leave.bind(h))
    try {
      const results = await checkHost(h.url)
      assert.deepEqual(failed(results), [], statuses(results).join('\n'))
      assert.ok(results.some((r) => r.status === 'unchecked' && /size/.test(r.why ?? '')), 'a profile entry with its open key is larger than the cap')
    } finally {
      await h.close()
    }
  })

  const broken: Array<[string, (h: TestHost) => void, string]> = [
    ['serves entries out of the order taken', (h) => {
      const read = h.read.bind(h)
      h.read = (options) => {
        const out = read(options)
        return { ...out, lines: out.lines.reverse() }
      }
    }, 'takes a folder’s profile entry and entries, and serves them, one folder’s and everyone’s, in the order taken'],
    ['takes an older version at a path', (h) => {
      const accept = h.accept.bind(h)
      h.accept = async (lines) => (await accept(lines)).map((r) => (r.error === 'older' ? { i: r.i, id: r.id, ok: true } : r))
    }, 'keeps the newest at a path: refuses an older version, and takes the same entry again'],
    ['refuses a newer profile entry for a folder it holds', (h) => {
      const accept = h.accept.bind(h)
      let joined = new Set<string>()
      h.accept = async (lines) => {
        const out = await accept(lines)
        return out.map((r, i) => {
          const e = JSON.parse(lines[i]!)
          if (e.path !== 'profile' || !r.ok || e.body?.market !== 'check' || e.body?.role !== 'b') return r
          if (joined.has(e.profile)) return { i: r.i, id: r.id, ok: false, error: 'refused', message: 'no moving' }
          joined = new Set([...joined, e.profile])
          return r
        })
      }
    }, 'takes a newer profile entry for a folder it holds, so a person can always move'],
    ['takes an entry by any access key', (h) => {
      const accept = h.accept.bind(h)
      h.accept = async (lines) => (await accept(lines)).map((r) => (r.error === 'unlisted' ? { i: r.i, id: r.id, ok: true } : r))
    }, 'takes an entry by an access key the profile entry lists with write, refuses one it does not, and stops counting it once the key is removed'],
    ['takes an inbox entry for a folder with no openKey', (h) => {
      const leave = h.leave.bind(h)
      h.leave = async (lines) => (await leave(lines)).map((r) => (r.error === 'no_inbox' ? { i: r.i, id: r.id, ok: true } : r))
    }, 'takes an inbox entry for a folder whose profile entry has openKey, and refuses each check in the plug’s order'],
    ['lists an inbox out of the order it arrived', (h) => {
      const readInbox = h.readInbox.bind(h)
      h.readInbox = (to, after) => {
        const out = readInbox(to, after)
        return { ...out, lines: out.lines.reverse() }
      }
    }, 'lists a folder’s inbox to anyone, after a cursor, in arrival order'],
    ['takes bytes no entry names', (h) => {
      const upload = h.upload.bind(h)
      h.upload = async (name, type, bytes) => {
        const out = await upload(name, type, bytes)
        return out.error === 'unnamed' ? { ok: true } : out
      }
    }, 'takes a file’s bytes only while a current entry names them, serves them with their type, and refuses bytes that do not match'],
  ]
  for (const [what, breakIt, check] of broken) {
    test(`a host that ${what} fails the check for it`, async () => {
      const h = await startHost()
      breakIt(h)
      try {
        assert.deepEqual(failed(await checkHost(h.url)), [check])
      } finally {
        await h.close()
      }
    })
  }
})
