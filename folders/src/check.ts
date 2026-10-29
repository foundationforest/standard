// The host check: a test any host runs against its own address, to show it fits the plug
// (README.md, Hosts). It writes to the host from two profiles of one seed, under the labels in
// CHECK_LABELS, and an access key it makes, and checks each answer against the plug: taking an
// entry in, access keys, reading, taking an inbox entry in and listing it, and taking a file in.
//
// A refusal the plug lets a host make by its own choice is no failure: the first profile entry of a
// folder it does not hold yet, an entry, an inbox entry or a file it does not take, a size it does
// not take. What such a refusal stops is reported unchecked, with why. To check it all on a host
// that charges to join or caps sizes, give a seed whose folders under CHECK_LABELS the host holds
// already.

import { mainKey, newAccessKey, openingHalf, serviceKey } from '@foundationforest/keys'
import { hex } from './bytes.ts'
import { canonical } from './canonical.ts'
import { type Result, readAll, readInbox, readPage, upload } from './client.ts'
import { type Body, MAX_FUTURE_MS, type SignedEntry, encodeEntry, entryId, signAs, signingInput, unsignedOf } from './entry.ts'
import { fileOf } from './files.ts'
import { type InboxEntry, encodeInbox, inboxId } from './inbox.ts'
import { inboxEntry } from './locked.ts'
import { normalizeOrigin } from './profile.ts'
import { entry } from './write.ts'

/** The labels of the check's two profiles: a seed's folders under them are what it writes to. */
export const CHECK_LABELS = ['check/a', 'check/b'] as const

export type HostCheck = { name: string; status: 'ok' | 'failed' | 'unchecked'; why?: string }
export type CheckOptions = {
  /** A seed whose folders under CHECK_LABELS the host holds already; a new one each run when omitted. */
  seed?: Uint8Array
  /** The media type of the file the check uploads: `image/png` when omitted. */
  type?: string
}

/** What the host refused by its own choice, as the plug lets it: the check stops there, unchecked. */
class Unchecked extends Error {}
/** The codes a host may answer by its own choice. */
const OWN_CHOICE = ['refused', 'size', 'batch']
const MINUTE = 60_000

function expect(ok: boolean, why: string): asserts ok {
  if (!ok) throw new Error(why)
}

/** Each check, run against the host at `url`, in order. */
export async function checkHost(url: string, options: CheckOptions = {}): Promise<HostCheck[]> {
  const host = normalizeOrigin(url)
  if (!host) return [{ name: 'the host is an origin', status: 'failed', why: `${url} is no origin, https (http only on loopback)` }]
  const seed = options.seed ?? crypto.getRandomValues(new Uint8Array(32))
  const [a, b] = await Promise.all(CHECK_LABELS.map((label) => mainKey(seed, label)))
  const [aOpening, bOpening] = await Promise.all([openingHalf(a!.secret), openingHalf(b!.secret)])
  // An access key a's profile entry lists: it can write and read-inbox, while the check lets it.
  const access = await newAccessKey()
  const listed = (can: string[]) => ({ key: access.address, open: access.openKey, can })
  const aProfile = (keys: Body[] = [listed(['write', 'read-inbox'])]): Body => ({ market: 'check', role: 'a', hosts: [host], openKey: aOpening.openKey, keys })
  const bProfile = (openKey = true): Body => ({ market: 'check', role: 'b', hosts: [host], ...(openKey && { openKey: bOpening.openKey }) })
  const asAccess = { profile: a!.address, key: access }
  const type = options.type ?? 'image/png'
  /** Times that only go forward, and past anything the host holds for these folders. */
  let last = 0
  const time = () => (last = Math.max(Date.now(), last + 1))
  /** Whether the host holds both folders. */
  let holds = false

  const results: HostCheck[] = []
  const run = async (name: string, check: () => Promise<void>) => {
    try {
      await check()
      results.push({ name, status: 'ok' })
    } catch (err) {
      results.push({ name, status: err instanceof Unchecked ? 'unchecked' : 'failed', why: (err as Error).message })
    }
  }
  const needsFolders = () => {
    if (!holds) throw new Unchecked('the host holds no folder of this seed: give the check a seed whose folders it holds')
  }

  /** One line, alone in a request: the host's one result for it. A 413 is a size the host does not take. */
  const send = async (path: string, line: string): Promise<Result> => {
    const res = await fetch(`${host}${path}`, { method: 'POST', headers: { 'content-type': 'application/x-ndjson' }, body: line + '\n' })
    if (res.status === 413) {
      await res.body?.cancel()
      return { i: 0, ok: false, error: 'size' }
    }
    expect(res.status === 200, `POST ${path} answered ${res.status}`)
    const answers = (await res.text()).split('\n').filter((l) => l).map((l) => JSON.parse(l) as Result)
    expect(answers.length === 1 && answers[0]!.i === 0, `POST ${path} gave ${answers.length} results for one line`)
    return answers[0]!
  }
  /** A line the host takes, or refuses by its own choice, which stops the check unchecked. */
  const take = async (path: string, line: string, what: string) => {
    const r = await send(path, line)
    if (r.ok) return r
    if (OWN_CHOICE.includes(r.error ?? '')) throw new Unchecked(`the host refused ${what} by its own choice: ${r.error}${r.message ? `, ${r.message}` : ''}`)
    throw new Error(`the host refused ${what}: ${r.error}${r.message ? `, ${r.message}` : ''}`)
  }
  /** Lines the host refuses, each with its code, in the plug's order. */
  const refuses = async (path: string, cases: Array<[line: string, code: string, what: string]>) => {
    for (const [line, code, what] of cases) {
      const r = await send(path, line)
      if (r.error === 'size' && code !== 'size') throw new Unchecked(`the host refused ${what} for its size, by its own choice, before the check it is for`)
      expect(!r.ok && r.error === code, `${what}: answered ${r.ok ? 'ok' : r.error}, not ${code}`)
    }
  }
  const takeEntry = (e: SignedEntry, what: string) => take('/v1/entries', encodeEntry(e), what)
  const takeInbox = (e: InboxEntry, what: string) => take('/v1/inbox', encodeInbox(e), what)
  const idOf = (e: SignedEntry) => entryId(unsignedOf(e))
  const ids = async (profile: string) => (await readAll(host, { profile })).entries.map((c) => c.id)

  await run('takes a folder’s profile entry and entries, and serves them, one folder’s and everyone’s, in the order taken', async () => {
    for (const key of [a!, b!]) for (const c of (await readAll(host, { profile: key.address })).entries) last = Math.max(last, c.entry.time)
    const written = [entry(a!, 'profile', aProfile(), time()), entry(a!, 'check/one', { check: 'one' }, time())]
    await takeEntry(written[0]!, 'a folder’s profile entry')
    await takeEntry(written[1]!, 'an entry')
    await takeEntry(entry(b!, 'profile', bProfile(), time()), 'a folder’s profile entry')
    holds = true
    const one = await readAll(host, { profile: a!.address })
    expect(one.refused.length === 0, `the folder’s read served ${one.refused.length} lines that do not check`)
    expect(one.entries.every((c) => c.entry.profile === a!.address), 'one folder’s read served another’s entries')
    expect(JSON.stringify(one.entries.slice(-2).map((c) => c.id)) === JSON.stringify(written.map(idOf)), 'the folder’s read did not serve the entries last taken, in the order taken')
    let after = one.cursor - 1
    for (let pages = 0; ; pages++) {
      // Everyone's after a cursor: the last entry taken is there, on some page.
      const page = await readPage(host, { after: Math.max(after, 0) })
      if (page.entries.some((c) => c.id === idOf(written[1]!))) break
      expect(page.entries.length + page.refused.length > 0 && pages < 100, 'everyone’s entries did not include the last one taken')
      after = page.cursor
    }
  })

  await run('refuses an entry that does not check, each with its code', async () => {
    needsFolders()
    const good = entry(a!, 'check/two', { check: 'two' }, time())
    const profile = entry(a!, 'profile', aProfile(), good.time)
    await refuses('/v1/entries', [
      [canonical(good).replace('{', '{ '), 'canonical', 'an entry that is not canonical text'],
      [canonical({ ...good, more: 1 }), 'shape', 'an entry with a field the standard does not name'],
      [canonical({ ...good, v: 2 }), 'version', 'an entry of v 2'],
      [canonical({ ...good, profile: 'x' }), 'key', 'an entry whose profile is no address'],
      [canonical({ ...good, path: 'Check/two' }), 'path', 'an entry at a path with a capital'],
      [canonical({ ...good, time: -1 }), 'time', 'an entry dated before 1970'],
      [canonical({ ...good, body: 'text' }), 'body', 'an entry whose body is text'],
      [canonical({ ...profile, body: { ...profile.body, hosts: [] } }), 'profile', 'a profile entry naming no host'],
      [canonical({ ...good, body: { files: [{ sha256: 'x', type, size: 1 }] } }), 'files', 'an entry naming a file by no hash'],
      [canonical({ ...good, body: { check: 'forged' } }), 'signature', 'an entry changed after it was signed'],
      [encodeEntry(entry(a!, 'check/two', { check: 'two' }, Date.now() + MAX_FUTURE_MS + MINUTE)), 'future', 'an entry dated eleven minutes ahead'],
    ])
  })

  await run('keeps the newest at a path: refuses an older version, and takes the same entry again', async () => {
    needsFolders()
    const newer = entry(a!, 'check/three', { check: 'newer' }, time())
    await takeEntry(newer, 'an entry')
    await refuses('/v1/entries', [[encodeEntry(entry(a!, 'check/three', { check: 'older' }, newer.time - 1)), 'older', 'an older version at a path']])
    const again = await send('/v1/entries', encodeEntry(newer))
    expect(again.ok, `the same entry again: answered ${again.error}`)
  })

  await run('takes a newer profile entry for a folder it holds, so a person can always move', async () => {
    needsFolders()
    for (const hosts of [[host, 'https://elsewhere.example'], [host]]) {
      const r = await send('/v1/entries', encodeEntry(entry(b!, 'profile', { ...bProfile(), hosts }, time())))
      if (r.error === 'size') throw new Unchecked('the host refused a profile entry for its size')
      expect(r.ok, `a newer profile entry for a folder it holds: answered ${r.error}`)
    }
  })

  await run('takes an entry by an access key the profile entry lists with write, refuses one it does not, and stops counting it once the key is removed', async () => {
    needsFolders()
    await takeEntry(entry(a!, 'profile', aProfile(), time()), 'a profile entry')
    const byKey = entry(asAccess, 'check/key', { check: 'by the access key' }, time())
    await takeEntry(byKey, 'an entry by a listed access key')
    const stranger = serviceKey(crypto.getRandomValues(new Uint8Array(32)))
    // A profile entry by the access key, signed by hand: entry() itself refuses to make one.
    const unsigned = { v: 1 as const, profile: a!.address, path: 'profile', time: time(), body: aProfile(), key: access.address }
    await refuses('/v1/entries', [
      [encodeEntry(entry({ profile: a!.address, key: stranger }, 'check/key', { check: 'unlisted' }, time())), 'unlisted', 'an entry by a key the profile entry does not list'],
      [canonical({ ...unsigned, sig: signAs(access, access.address, signingInput(unsigned)) }), 'unlisted', 'a profile entry by an access key'],
    ])
    await takeEntry(entry(a!, 'profile', aProfile([listed(['read-inbox'])]), time()), 'a profile entry')
    await refuses('/v1/entries', [[encodeEntry(entry(asAccess, 'check/key', { check: 'no longer' }, time())), 'unlisted', 'an entry by a key listed without write']])
    // The key's entry no longer counts: the main key's older entry at its path is current.
    const older = entry(a!, 'check/key', { check: 'by the main key' }, byKey.time - 1)
    await takeEntry(older, 'an entry at the path of an entry by a removed key, older than it')
    await takeEntry(entry(a!, 'profile', aProfile(), time()), 'a profile entry')
  })

  await run('reads after a cursor, one folder’s, and ends with an empty page at the cursor asked with', async () => {
    needsFolders()
    const { cursor } = await readAll(host, { profile: a!.address })
    const empty = await readPage(host, { profile: a!.address, after: cursor })
    expect(empty.entries.length === 0 && empty.refused.length === 0, 'a page after the last entry was not empty')
    expect(empty.cursor === cursor, `an empty page gave the cursor ${empty.cursor}, not the one asked with, ${cursor}`)
    const next = entry(a!, 'check/four', { check: 'four' }, time())
    await takeEntry(next, 'an entry')
    const since = await readPage(host, { profile: a!.address, after: cursor })
    expect(JSON.stringify(since.entries.map((c) => c.id)) === JSON.stringify([idOf(next)]), 'the folder’s read after the cursor did not serve the one entry taken since')
    expect((await ids(a!.address)).includes(idOf(next)), 'the folder’s whole read did not serve it')
  })

  const fromB = (text: string, at = time()) => inboxEntry(b!, a!.address, { text }, at, aProfile(), host)

  await run('takes an inbox entry for a folder whose profile entry has openKey, and refuses each check in the plug’s order', async () => {
    needsFolders()
    const one = await fromB('one')
    await refuses('/v1/inbox', [
      ['not json', 'canonical', 'an inbox entry that is not JSON'],
      [canonical({ ...one, from: b!.address }), 'shape', 'an inbox entry with a field outside its envelope'],
      [canonical({ ...one, v: 2 }), 'version', 'an inbox entry of v 2'],
      [canonical({ ...one, to: 'x' }), 'key', 'an inbox entry to no address'],
      [canonical({ ...one, private: one.private + '!' }), 'shape', 'an inbox entry whose envelope is not base64url'],
    ])
    await takeInbox(one, 'an inbox entry')
    await refuses('/v1/inbox', [[encodeInbox(one), 'duplicate', 'the same inbox entry again']])
    await takeEntry(entry(b!, 'profile', bProfile(false), time()), 'a profile entry with no openKey')
    const nobody = serviceKey(crypto.getRandomValues(new Uint8Array(32))).address
    // Inbox entries for other folders: each another envelope, so neither is a duplicate.
    const toB = await fromB('to b')
    const toNobody = await fromB('to nobody')
    await refuses('/v1/inbox', [
      [encodeInbox({ ...toB, to: b!.address }), 'no_inbox', 'an inbox entry for a folder whose profile entry has no openKey'],
      [encodeInbox({ ...toNobody, to: nobody }), 'no_inbox', 'an inbox entry for a folder it does not hold'],
    ])
    await takeEntry(entry(b!, 'profile', bProfile(), time()), 'a profile entry')
  })

  await run('lists a folder’s inbox to anyone, after a cursor, in arrival order', async () => {
    needsFolders()
    const first = await fromB('first')
    const second = await fromB('second')
    await takeInbox(first, 'an inbox entry')
    await takeInbox(second, 'an inbox entry')
    const listed = async () => {
      const out: string[] = []
      let cursor = 0
      for (let pages = 0; ; pages++) {
        expect(pages < 1000, 'an inbox listing that never ends')
        const page = await readInbox(host, a!.address, { after: cursor })
        expect(page.refused.length === 0, `the inbox listing served ${page.refused.length} lines that do not check, or to another folder`)
        out.push(...page.entries.map((e) => e.id))
        if (!page.entries.length) {
          expect(page.cursor === cursor, 'an empty page did not give the cursor asked with')
          return { ids: out, cursor }
        }
        expect(page.cursor > cursor, 'a page did not move the cursor forward')
        cursor = page.cursor
      }
    }
    const { ids: all, cursor } = await listed()
    const at = all.indexOf(inboxId(first))
    expect(at >= 0 && all.indexOf(inboxId(second)) > at, 'the inbox entries left were not listed in the order they arrived')
    const third = await fromB('third')
    await takeInbox(third, 'an inbox entry')
    const since = await readInbox(host, a!.address, { after: cursor })
    expect(JSON.stringify(since.entries.map((e) => e.id)) === JSON.stringify([inboxId(third)]), 'a listing after the cursor did not serve the one inbox entry since')
    expect(!(await readInbox(host, b!.address)).entries.some((e) => all.includes(e.id)), 'another folder’s inbox listed this folder’s entries')
  })

  await run('takes a file’s bytes only while a current entry names them, serves them with their type, and refuses bytes that do not match', async () => {
    needsFolders()
    const bytes = crypto.getRandomValues(new Uint8Array(64))
    const name = fileOf(bytes, type)
    const said = async (body: Uint8Array, change: { type?: string; sha256?: string } = {}) => {
      const res = await fetch(`${host}/v1/files/${change.sha256 ?? name.sha256}`, { method: 'PUT', headers: { 'content-type': change.type ?? type }, body: new Uint8Array(body) })
      if (res.status === 413) throw new Unchecked('the host refused a file for its size, by its own choice')
      const answer = (await res.json().catch(() => ({}))) as { ok?: boolean; error?: string; message?: string }
      if (!answer.ok && OWN_CHOICE.includes(answer.error ?? '')) throw new Unchecked(`the host refused a file by its own choice: ${answer.error}`)
      return answer.ok ? (answer.message ?? 'ok') : `${res.status} ${answer.error}`
    }
    const fetched = async (sha256: string) => {
      const res = await fetch(`${host}/v1/files/${sha256}`)
      return { status: res.status, type: res.headers.get('content-type'), bytes: new Uint8Array(await res.arrayBuffer()) }
    }
    expect((await fetched(name.sha256)).status === 404, 'bytes it does not hold were not 404')
    expect((await said(bytes)) === '400 unnamed', 'bytes no current entry names were not refused 400 unnamed')
    await takeEntry(entry(a!, 'check/photo', { files: [name] }, time()), 'an entry naming a file')
    const flipped = Uint8Array.from(bytes, (v, i) => (i === 0 ? v ^ 1 : v))
    for (const [answer, want, what] of [
      [await said(bytes, { type: type === 'image/png' ? 'image/jpeg' : 'image/png' }), '400 shape', 'bytes of another type than the entry names'],
      [await said(bytes.subarray(1)), '400 shape', 'bytes of another size than the entry names'],
      [await said(flipped), '400 hash', 'bytes that do not hash to their name'],
      [await said(bytes), 'ok', 'the bytes a current entry names'],
      [await said(bytes), 'already here', 'the same bytes again'],
    ] as const) expect(answer === want, `${what}: answered ${answer}, not ${want}`)
    const got = await fetched(name.sha256)
    expect(got.status === 200 && got.type === type && hex.encode(got.bytes) === hex.encode(bytes), 'the bytes were not served back, with their type')
  })

  return results
}
