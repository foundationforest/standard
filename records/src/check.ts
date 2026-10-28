// The host check: a test any host runs against its own address, to show it fits the plug
// (README.md, Hosts). It writes to the host from two profiles of one seed, under the labels in
// CHECK_LABELS, and checks each answer against the plug: taking a record in, reading, taking a
// message in, pulling, and taking and deleting a blob.
//
// A refusal the plug lets a host make by its own choice is no failure: the first hosts record of a
// folder it does not hold yet, a content record, a message or a blob it does not take, a size it
// does not take. What such a refusal stops is reported unchecked, with why. To check it all on a
// host that charges to join or caps sizes, give a seed whose folders under CHECK_LABELS the host
// holds already.

import { inboxKey, mainKey, serviceKey } from '@foundationforest/keys'
import { concat, hex, utf8 } from './bytes.ts'
import { canonical } from './canonical.ts'
import { type Result, deleteBlob, pull, putBlob, readAll, readPage } from './client.ts'
import type { Key } from './keys.ts'
import { type SignedBlobRequest, type SignedMessage, blobNameOf, blobRequest, blobSigningInput, encodeMessage, messageId, pullRequest, unsignedMessageOf } from './message.ts'
import { message } from './private.ts'
import { type Body, type SignedRecord, MAX_FUTURE_MS, encodeRecord, normalizeOrigin, recordId, signAs, unsignedOf } from './record.ts'
import { hostsRecord, ownerRecord } from './write.ts'

/** The labels of the check's two profiles: a seed's folders under them are what it writes to. */
export const CHECK_LABELS = ['check/a', 'check/b'] as const

export type HostCheck = { name: string; status: 'ok' | 'failed' | 'unchecked'; why?: string }
export type CheckOptions = {
  /** A seed whose folders under CHECK_LABELS the host holds already; a new one each run when omitted. */
  seed?: Uint8Array
  /** The media type of the blob the check puts: `image/png` when omitted. */
  mimeType?: string
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
  const [aInbox, bInbox] = await Promise.all([inboxKey(a!.secret), inboxKey(b!.secret)])
  const aProfile: Body = { market: 'check', role: 'a', inboxKey: aInbox.encryptTo, inbox: {} }
  const bProfile = (inbox: Body): Body => ({ market: 'check', role: 'b', inboxKey: bInbox.encryptTo, inbox })
  const mimeType = options.mimeType ?? 'image/png'
  /** Times that only go forward, and past anything the host holds for these folders. */
  let last = 0
  const time = () => (last = Math.max(Date.now(), last + 1))
  /** Whether the host holds both folders, and each profile record declares its inbox. */
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
    if (r.ok) return
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
  const takeRecord = (record: SignedRecord, what: string) => take('/v1/records', encodeRecord(record), what)
  const takeMessage = (m: SignedMessage, what: string) => take('/v1/inbox', encodeMessage(m), what)
  const idOf = (record: SignedRecord) => recordId(unsignedOf(record))
  const pullId = (m: SignedMessage) => messageId(unsignedMessageOf(m))

  await run('takes a folder’s records, and serves them by GET and by POST, in the order taken', async () => {
    for (const key of [a!, b!]) for (const c of (await readAll(host, { profile: key.address, post: true })).records) last = Math.max(last, c.record.time)
    const written = [hostsRecord(a!, [host], time()), ownerRecord(a!, 'profile', aProfile, time()), ownerRecord(a!, 'check/one', { check: 'one' }, time())]
    await takeRecord(written[0]!, 'a folder’s hosts record')
    for (const record of written.slice(1)) await takeRecord(record, `the content record at ${record.path}`)
    await takeRecord(hostsRecord(b!, [host], time()), 'a folder’s hosts record')
    await takeRecord(ownerRecord(b!, 'profile', bProfile({}), time()), 'a profile record')
    holds = true
    const got = await readAll(host, { profile: a!.address })
    const posted = await readAll(host, { profile: a!.address, post: true })
    expect(got.refused.length === 0, `GET served ${got.refused.length} lines that do not check`)
    expect(got.records.every((c) => c.record.profile === a!.address), 'GET for one profile served another’s records')
    expect(JSON.stringify(got.records.slice(-3).map((c) => c.id)) === JSON.stringify(written.map(idOf)), 'GET did not serve the records last taken, in the order taken')
    expect(JSON.stringify(posted.records.map((c) => c.id)) === JSON.stringify(got.records.map((c) => c.id)), 'POST /v1/records/read did not give the GET’s answer')
  })

  await run('refuses a record that does not check, each with its code', async () => {
    needsFolders()
    const good = ownerRecord(a!, 'check/two', { check: 'two' }, time())
    await refuses('/v1/records', [
      [canonical(good).replace('{', '{ '), 'canonical', 'a record that is not canonical text'],
      [canonical({ ...good, more: 1 }), 'shape', 'a record with a field the standard does not name'],
      [canonical({ ...good, v: 2 }), 'version', 'a record of v 2'],
      [canonical({ ...good, profile: 'x' }), 'key', 'a record whose profile is no address'],
      [canonical({ ...good, path: 'Check/two' }), 'path', 'a record at a path with a capital'],
      [canonical({ ...good, time: -1 }), 'time', 'a record dated before 1970'],
      [canonical({ ...good, body: 'text' }), 'body', 'a record whose body is text'],
      [canonical({ ...hostsRecord(a!, [host], good.time), body: { urls: [] } }), 'hosts', 'a hosts record naming no host'],
      [canonical({ ...good, body: { check: 'forged' } }), 'signature', 'a record changed after it was signed'],
      [encodeRecord(ownerRecord(a!, 'check/two', { check: 'two' }, Date.now() + MAX_FUTURE_MS + MINUTE)), 'future', 'a record dated eleven minutes ahead'],
    ])
  })

  await run('keeps the newest at a path: refuses an older version, and takes the same record again', async () => {
    needsFolders()
    const newer = ownerRecord(a!, 'check/three', { check: 'newer' }, time())
    await takeRecord(newer, 'a content record')
    await refuses('/v1/records', [[encodeRecord(ownerRecord(a!, 'check/three', { check: 'older' }, newer.time - 1)), 'older', 'an older version at a path']])
    const again = await send('/v1/records', encodeRecord(newer))
    expect(again.ok, `the same record again: answered ${again.error}`)
  })

  await run('takes a newer hosts record for a folder it holds, so a person can always move', async () => {
    needsFolders()
    for (const urls of [[host, 'https://elsewhere.example'], [host]]) {
      const r = await send('/v1/records', encodeRecord(hostsRecord(a!, urls, time())))
      if (r.error === 'size') throw new Unchecked('the host refused a hosts record for its size')
      expect(r.ok, `a newer hosts record for a folder it holds: answered ${r.error}`)
    }
  })

  await run('reads after a cursor, one profile’s if asked, and ends with an empty page at the cursor asked with', async () => {
    needsFolders()
    const { cursor } = await readAll(host, { profile: a!.address })
    const empty = await readPage(host, { profile: a!.address, after: cursor })
    expect(empty.records.length === 0 && empty.refused.length === 0, 'a page after the last record was not empty')
    expect(empty.cursor === cursor, `an empty page gave the cursor ${empty.cursor}, not the one asked with, ${cursor}`)
    const next = ownerRecord(a!, 'check/four', { check: 'four' }, time())
    await takeRecord(next, 'a content record')
    for (const post of [false, true]) {
      const since = await readPage(host, { profile: a!.address, after: cursor, post })
      expect(JSON.stringify(since.records.map((c) => c.id)) === JSON.stringify([idOf(next)]), `${post ? 'POST' : 'GET'} after the cursor did not serve the one record taken since`)
    }
    // Every profile's, after the same cursor: the record taken since is there, on some page.
    let after = cursor
    for (let pages = 0; ; pages++) {
      const page = await readPage(host, { after })
      if (page.records.some((c) => c.id === idOf(next))) break
      expect(page.records.length + page.refused.length > 0 && pages < 100, 'every profile’s records after the cursor did not include the one taken since')
      expect(page.cursor > after, 'a page of records did not move the cursor forward')
      after = page.cursor
    }
  })

  // The messages: from b to a, a's inbox open to anyone; b's inbox with maxBytes.
  const toB = (from: Key, text: string, at = time()) => message({ from, host }, b!.address, { text }, at, bProfile({}))

  await run('takes a message to an inbox, and refuses each check in the plug’s order', async () => {
    needsFolders()
    const small = await toB(a!, 'small')
    const big = await toB(a!, 'x'.repeat(200))
    const self = await toB(b!, 'x'.repeat(200))
    const maxBytes = utf8(encodeMessage(small)).length
    await takeRecord(ownerRecord(b!, 'profile', bProfile({ maxBytes }), time()), 'a profile record')
    const nobody = serviceKey(crypto.getRandomValues(new Uint8Array(32))).address
    const later = await toB(a!, 'later', Date.now() + MAX_FUTURE_MS + MINUTE)
    const toNobody = { ...(await toB(a!, 'nobody')), to: nobody }
    await refuses('/v1/inbox', [
      ['not json', 'canonical', 'a message that is not JSON'],
      [canonical({ ...small, path: 'x' }), 'shape', 'a message with a field the standard does not name'],
      [encodeMessage({ ...small, body: { ...small.body, text: 'x' } } as never), 'body', 'a message whose body holds more than its envelope'],
      [encodeMessage(later), 'future', 'a message dated eleven minutes ahead'],
    ])
    await takeMessage(small, 'a message')
    await refuses('/v1/inbox', [
      [encodeMessage(small), 'duplicate', 'the same message again'],
      [encodeMessage(toNobody), 'no_inbox', 'a message to a profile with no profile record here, and a signature that does not hold'],
      [encodeMessage({ ...small, time: small.time + 1 }), 'signature', 'a message changed after it was signed'],
      [encodeMessage(big), 'too_big', 'a message larger than the inbox’s maxBytes'],
    ])
    await takeMessage(self, 'a message from the profile it is to, larger than its maxBytes')
    await takeRecord(ownerRecord(b!, 'profile', bProfile({ senders: 'anyone' }), time()), 'a profile record')
    await refuses('/v1/inbox', [[encodeMessage(await toB(a!, 'unread')), 'no_inbox', 'a message to an inbox with a field the host does not know']])
    await takeRecord(ownerRecord(b!, 'profile', bProfile({}), time()), 'a profile record')
  })

  await run('serves a profile’s messages to its main key only, after a cursor, in arrival order', async () => {
    needsFolders()
    const toA = (text: string) => message({ from: b!, host }, a!.address, { text }, time(), aProfile)
    const first = await toA('first')
    const second = await toA('second')
    await takeMessage(first, 'a message')
    await takeMessage(second, 'a message')
    let cursor = 0
    const ids: string[] = []
    for (let pages = 0; ; pages++) {
      expect(pages < 1000, 'a pull that never ends')
      const page = await pull(host, pullRequest(a!, cursor, Date.now()))
      expect(page.refused.length === 0, `a pull served ${page.refused.length} lines that do not check, or to another profile`)
      ids.push(...page.messages.map((m) => m.id))
      if (!page.messages.length) {
        expect(page.cursor === cursor, 'an empty pull did not give the cursor asked with')
        break
      }
      expect(page.cursor > cursor, 'a pull did not move the cursor forward')
      cursor = page.cursor
    }
    const one = ids.indexOf(pullId(first))
    expect(one >= 0 && ids.indexOf(pullId(second)) > one, 'the messages delivered were not served in the order they arrived')
    const third = await toA('third')
    await takeMessage(third, 'a message')
    const since = await pull(host, pullRequest(a!, cursor, Date.now()))
    expect(JSON.stringify(since.messages.map((m) => m.id)) === JSON.stringify([pullId(third)]), 'a pull after the cursor did not serve the one message since')
    const theirs = await pull(host, pullRequest(b!, 0, Date.now()))
    expect(!theirs.messages.some((m) => ids.includes(m.id)), 'another profile’s pull served this profile’s messages')
    const refusedWith = (request: object) => fetch(`${host}/v1/inbox/pull`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: canonical(request as never) }).then(async (res) => `${res.status} ${((await res.json().catch(() => ({}))) as { error?: string }).error}`)
    expect((await refusedWith({ ...pullRequest(b!, 0, Date.now()), profile: a!.address })) === '400 signature', 'a pull another key signed was not refused 400 signature')
    expect((await refusedWith(pullRequest(a!, 0, Date.now() - MAX_FUTURE_MS - MINUTE))) === '400 stale', 'a pull signed eleven minutes ago was not refused 400 stale')
  })

  const blobOf = () => {
    const bytes = crypto.getRandomValues(new Uint8Array(64))
    return { bytes, name: blobNameOf(bytes, mimeType) }
  }
  const putOf = (key: Key, name: ReturnType<typeof blobNameOf>, at = Date.now()) => blobRequest(key, { action: 'put', ...name }, at) as SignedBlobRequest & { action: 'put' }
  const deleteOf = (key: Key, sha256: string) => blobRequest(key, { action: 'delete', sha256 }, Date.now()) as SignedBlobRequest & { action: 'delete' }
  /** One host's answer to a blob request: its message, or its error, or ok. */
  const said = (outcomes: Array<{ ok: boolean; status: number; error?: string; message?: string }>) => {
    const [o] = outcomes
    if (o!.status === 413 || (!o!.ok && OWN_CHOICE.includes(o!.error ?? ''))) throw new Unchecked(`the host refused a blob by its own choice: ${o!.error ?? o!.status}`)
    return o!.ok ? (o!.message ?? 'ok') : `${o!.error}`
  }
  const fetched = async (sha256: string) => {
    const res = await fetch(`${host}/v1/blobs/${sha256}`)
    return { status: res.status, type: res.headers.get('content-type'), bytes: new Uint8Array(await res.arrayBuffer()) }
  }

  await run('takes the bytes a folder’s main key puts, serves them with their type, and deletes them once no folder holds them', async () => {
    const { bytes, name } = blobOf()
    expect((await fetched(name.sha256)).status === 404, 'bytes it does not hold were not 404')
    expect(said(await putBlob([host], putOf(a!, name), bytes)) === 'ok', 'a put was not taken')
    expect(said(await putBlob([host], putOf(a!, name), bytes)) === 'already here', 'the same put again was not already here')
    const got = await fetched(name.sha256)
    expect(got.status === 200 && got.type === mimeType && hex.encode(got.bytes) === hex.encode(bytes), 'the bytes were not served back, with their type')
    expect(said(await putBlob([host], putOf(b!, name), bytes)) === 'ok', 'a second folder’s put of the same bytes was not taken')
    expect(said(await deleteBlob([host], deleteOf(a!, name.sha256))) === 'ok', 'a delete was not taken')
    expect((await fetched(name.sha256)).status === 200, 'bytes another folder holds were deleted')
    expect(said(await deleteBlob([host], deleteOf(a!, name.sha256))) === 'not here', 'a delete of bytes the folder no longer holds was not not here')
    expect(said(await deleteBlob([host], deleteOf(b!, name.sha256))) === 'ok', 'the last folder’s delete was not taken')
    expect((await fetched(name.sha256)).status === 404, 'bytes no folder holds were still served')
  })

  await run('refuses a blob request that does not check, each with its code', async () => {
    const { bytes, name } = blobOf()
    const put = putOf(a!, name)
    const { sig: _sig, ...unsigned } = put
    const posing = { ...unsigned, sig: signAs(b!, b!.address, blobSigningInput(unsigned)) }
    const send = async (request: SignedBlobRequest | null, body: Uint8Array, change: { type?: string; sha256?: string; method?: string } = {}) => {
      const headers: Record<string, string> = { 'content-type': change.type ?? mimeType }
      if (request) headers['forest-blob'] = canonical(request)
      const res = await fetch(`${host}/v1/blobs/${change.sha256 ?? name.sha256}`, { method: change.method ?? 'PUT', headers, body: new Uint8Array(body) })
      if (res.status === 413) throw new Unchecked('the host refused a blob for its size, by its own choice')
      return `${res.status} ${((await res.json().catch(() => ({}))) as { error?: string }).error}`
    }
    const flipped = concat(Uint8Array.of(bytes[0]! ^ 1), bytes.subarray(1))
    const cases: Array<[() => Promise<string>, string, string]> = [
      [() => send(null, bytes), '400 shape', 'a put with no signed request'],
      [() => send(posing, bytes), '400 signature', 'a put signed by a key that is not the folder’s main key'],
      [() => send(putOf(a!, name, Date.now() - MAX_FUTURE_MS - MINUTE), bytes), '400 stale', 'a put signed eleven minutes ago'],
      [() => send(deleteOf(a!, name.sha256), bytes), '400 shape', 'a delete sent as a put'],
      [() => send(put, bytes, { sha256: blobNameOf(flipped, mimeType).sha256 }), '400 shape', 'a put for other bytes than the path names'],
      [() => send(put, bytes, { type: mimeType === 'image/png' ? 'image/jpeg' : 'image/png' }), '400 shape', 'bytes of another type than the put names'],
      [() => send(put, bytes.subarray(1)), '400 shape', 'bytes of another size than the put names'],
      [() => send(put, flipped), '400 hash', 'bytes that do not hash to their name'],
    ]
    for (const [answer, want, what] of cases) {
      const got = await answer()
      expect(got === want, `${what}: answered ${got}, not ${want}`)
    }
  })

  return results
}
