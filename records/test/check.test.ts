// The host check, run against the minimal host (host.ts): every check passes. Against a host that
// charges to join, or takes only small lines, as the plug lets a host choose, nothing fails, and
// given a seed whose folders it holds, every check runs. Against hosts that break the plug, the check says which
// promise broke.

import assert from 'node:assert/strict'
import { describe, test } from 'node:test'
import { mainKey } from '@foundationforest/keys'
import { utf8 } from '../src/bytes.ts'
import { CHECK_LABELS, type HostCheck, checkHost } from '../src/check.ts'
import { type Result, publish } from '../src/client.ts'
import { decodeRecord } from '../src/record.ts'
import { hostsRecord } from '../src/write.ts'
import { startHost } from './helpers.ts'
import type { TestHost } from './host.ts'

const statuses = (results: HostCheck[]) => results.map((r) => `${r.status}: ${r.name}${r.why ? `. ${r.why}` : ''}`)
const failed = (results: HostCheck[]) => results.filter((r) => r.status === 'failed').map((r) => r.name)

describe('the host check', () => {
  test('the minimal host passes every check, and passes again with the same seed, its folders now held', async () => {
    const h = await startHost()
    try {
      const seed = crypto.getRandomValues(new Uint8Array(32))
      for (let run = 0; run < 2; run++) {
        const results = await checkHost(h.url, { seed })
        assert.ok(results.length >= 9)
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
    // Its own choice, as the plug lets it: a folder joins only once paid, and content goes only to a folder it holds.
    h.accept = async (lines) => {
      const out = []
      for (const [i, line] of lines.entries()) {
        let profile = ''
        let path = ''
        try {
          ;({ profile, path } = decodeRecord(line).record)
        } catch {
          // What does not check is refused by the plug, before any choice.
        }
        if (profile && !held.has(profile) && !(path === 'hosts' && paid.has(profile))) out.push({ i, ok: false, error: 'refused', message: 'pay to join this host' })
        else {
          const [r] = await accept([line])
          if (r!.ok && path === 'hosts') held.add(profile)
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
        await publish([h.url], [hostsRecord(key, [h.url], Date.now() - 1000)])
      }
      paid.clear()
      const results = await checkHost(h.url, { seed })
      assert.ok(results.every((r) => r.status === 'ok'), statuses(results).join('\n'))
    } finally {
      await h.close()
    }
  })

  test('a host that takes only small records and messages fails nothing', async () => {
    const h = await startHost()
    const CAP = 1000
    const capped = (take: (lines: string[]) => Promise<Result[]>) => async (lines: string[]) => {
      const out: Result[] = []
      for (const [i, line] of lines.entries()) out.push(utf8(line).length > CAP ? { i, ok: false, error: 'size', message: `at most ${CAP} bytes` } : { ...(await take([line]))[0]!, i })
      return out
    }
    h.accept = capped(h.accept.bind(h))
    h.deliver = capped(h.deliver.bind(h))
    try {
      const results = await checkHost(h.url)
      assert.deepEqual(failed(results), [], statuses(results).join('\n'))
      assert.ok(results.some((r) => r.status === 'unchecked' && /size/.test(r.why ?? '')), 'a profile record with its inbox key is larger than the cap')
    } finally {
      await h.close()
    }
  })

  const broken: Array<[string, (h: TestHost) => void, string]> = [
    ['serves records out of the order taken', (h) => {
      const read = h.read.bind(h)
      h.read = (options) => {
        const out = read(options)
        return { ...out, lines: out.lines.reverse() }
      }
    }, 'takes a folder’s records, and serves them by GET and by POST, in the order taken'],
    ['takes an older version at a path', (h) => {
      const accept = h.accept.bind(h)
      h.accept = async (lines) => (await accept(lines)).map((r) => (r.error === 'older' ? { i: r.i, id: r.id, ok: true } : r))
    }, 'keeps the newest at a path: refuses an older version, and takes the same record again'],
    ['refuses a newer hosts record for a folder it holds', (h) => {
      const accept = h.accept.bind(h)
      let joined = new Set<string>()
      h.accept = async (lines) => {
        const out = await accept(lines)
        return out.map((r, i) => {
          const record = JSON.parse(lines[i]!)
          if (record.path !== 'hosts' || !r.ok) return r
          if (joined.has(record.profile)) return { i: r.i, id: r.id, ok: false, error: 'refused', message: 'no moving' }
          joined = new Set([...joined, record.profile])
          return r
        })
      }
    }, 'takes a newer hosts record for a folder it holds, so a person can always move'],
    ['serves a pull signed long ago', (h) => {
      const pull = h.pull.bind(h)
      h.pull = (text) => pull(text, JSON.parse(text).time)
    }, 'serves a profile’s messages to its main key only, after a cursor, in arrival order'],
    ['takes a message larger than the inbox’s maxBytes', (h) => {
      const deliver = h.deliver.bind(h)
      h.deliver = async (lines) => (await deliver(lines)).map((r) => (r.error === 'too_big' ? { i: r.i, id: r.id, ok: true } : r))
    }, 'takes a message to an inbox, and refuses each check in the plug’s order'],
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
