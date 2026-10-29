// Talking to hosts over HTTP: write entries and read them back; leave inbox entries, list and
// delete them; upload and fetch files. Every entry and inbox entry read is checked here, and every
// file's bytes hashed, whatever host they came from: a reader trusts no host.
//
// How many lines a request or a page holds is each host's choice, and this handles any: a request
// a host finds too big is sent again in halves, and a page is read line by line, however long. How
// large an entry, an inbox entry or a file to take is each host's own choice, and each reader's:
// this ignores what is larger than it is told to take, MAX_LINE_READ and MAX_FILE_READ unless told
// otherwise.

import { sha256 } from '@noble/hashes/sha2.js'
import { concat, hex } from './bytes.ts'
import { type Checked, type SignedEntry, decodeEntry, encodeEntry } from './entry.ts'
import { FolderError } from './fail.ts'
import { fileOf } from './files.ts'
import { type CheckedInbox, type InboxEntry, type SignedDelete, decodeInbox, encodeDelete, encodeInbox } from './inbox.ts'
import { type View, viewFolder } from './view.ts'

/** A host's answer to one line of a request: its place in the request, the id, and why not if not taken. */
export type Result = { i: number; id?: string; ok: boolean; error?: string; message?: string }
/** What to read: after a cursor, one folder's if asked. */
export type ReadOptions = { after?: number; profile?: string }
export type PublishOutcome = { host: string; status: number; results: Result[]; error?: string }

/** A read that has not finished by then is given up. */
export const READ_TIMEOUT_MS = 60_000
/** The largest entry or inbox entry, as canonical text, a reader takes unless told otherwise. */
export const MAX_LINE_READ = 65_536
/** The largest file a reader takes unless told otherwise: a short video. */
export const MAX_FILE_READ = 50_000_000

/** How to reach a host: `fetch` and `redirect` as a read takes them (ReadHow). */
export type Reach = Pick<ReadHow, 'fetch' | 'redirect'>

/** Write entries to each host: each of the hosts the folder's profile entry names. A host that fails does not stop the others. */
export async function write(hosts: string[], entries: SignedEntry[], how: Reach = {}): Promise<PublishOutcome[]> {
  return post(hosts, '/v1/entries', entries.map(encodeEntry), how)
}

/** Leave inbox entries with each host: each of the hosts the profile entry of the folder they are to names. */
export async function leave(hosts: string[], entries: InboxEntry[], how: Reach = {}): Promise<PublishOutcome[]> {
  return post(hosts, '/v1/inbox', entries.map(encodeInbox), how)
}

/** Send inbox deletes to each host: each of the hosts the folder's profile entry names. */
export async function deleteInbox(hosts: string[], deletes: SignedDelete[], how: Reach = {}): Promise<PublishOutcome[]> {
  return post(hosts, '/v1/inbox/delete', deletes.map(encodeDelete), how)
}

async function post(hosts: string[], path: string, lines: string[], how: Reach): Promise<PublishOutcome[]> {
  return Promise.all(
    hosts.map(async (host): Promise<PublishOutcome> => {
      try {
        return { host, ...(await postLines(`${host}${path}`, lines, how)) }
      } catch (err) {
        return { host, status: 0, results: [], error: (err as Error).message }
      }
    }),
  )
}

/**
 * One request; if the host finds it too big (413, whatever its body, or one `batch` refusal), each
 * half again, down to one line. The status is read first: a body is parsed only from a 200.
 */
async function postLines(url: string, lines: string[], how: Reach): Promise<{ status: number; results: Result[] }> {
  const res = await (how.fetch ?? fetch)(url, { method: 'POST', headers: { 'content-type': 'application/x-ndjson' }, body: lines.map((l) => l + '\n').join(''), ...(how.redirect && { redirect: how.redirect }) })
  let results: Result[] = []
  if (res.status === 200) {
    results = (await res.text())
      .split('\n')
      .filter((l) => l)
      .map((l) => JSON.parse(l) as Result)
  } else {
    await res.body?.cancel()
  }
  const tooBig = res.status === 413 || (results.length === 1 && results[0]!.error === 'batch')
  if (!tooBig || lines.length < 2) return { status: res.status, results }
  const half = Math.ceil(lines.length / 2)
  const first = await postLines(url, lines.slice(0, half), how)
  const second = await postLines(url, lines.slice(half), how)
  return { status: first.status !== 200 ? first.status : second.status, results: [...first.results, ...second.results.map((r) => ({ ...r, i: r.i + half }))] }
}

export type Page = { entries: Checked[]; cursor: number; refused: Array<{ line: string; reason: string }> }

/**
 * How to read: `maxBytes` is the longest line taken (MAX_LINE_READ when omitted); `timeout` is in
 * ms for the whole read, every page of it (READ_TIMEOUT_MS when omitted). `fetch` is the caller's
 * own (one that refuses private addresses, say), and `redirect` goes to it as fetch takes it:
 * `error` refuses a host that redirects. The global fetch, following redirects, when omitted.
 */
export type ReadHow = { maxBytes?: number; timeout?: number; fetch?: typeof fetch; redirect?: RequestRedirect }

/**
 * One page of what a host stores, after a cursor, in the order it took them, each entry checked:
 * one folder's (POST /v1/entries/read, its address in the body, not the URL) when `profile` is
 * given, else every folder's (GET /v1/entries). A page may be any length; a line longer than
 * `maxBytes` is refused unread. It throws on a page not read within `timeout` ms, and on a cursor
 * that is not a whole number from 0.
 */
export async function readPage(host: string, options: ReadOptions & ReadHow & { signal?: AbortSignal } = {}): Promise<Page> {
  const how = { signal: options.signal ?? AbortSignal.timeout(options.timeout ?? READ_TIMEOUT_MS), ...(options.redirect && { redirect: options.redirect }) }
  const get = options.fetch ?? fetch
  const after = options.after ?? 0
  const res = options.profile !== undefined
    ? await get(`${host}/v1/entries/read`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ profile: options.profile, after }), ...how })
    : await get(`${host}/v1/entries?after=${after}`, how)
  if (!res.ok) throw new Error(`${host} answered ${res.status}`)
  const cursor = cursorOf(res, host)
  const entries: Checked[] = []
  const refused: Page['refused'] = []
  for await (const line of readLines(res, options.maxBytes ?? MAX_LINE_READ)) {
    try {
      if (line === null) throw new FolderError('size', 'longer than this reader takes')
      entries.push(decodeEntry(line))
    } catch (err) {
      refused.push({ line: line ?? '', reason: err instanceof FolderError ? err.code : 'invalid' })
    }
  }
  return { entries, cursor, refused }
}

/**
 * A response's lines, as they arrive, so a page of any length is read without holding more than a
 * line. A line over `max` bytes is not held: it comes out as null.
 */
async function* readLines(res: Response, max: number): AsyncGenerator<string | null> {
  if (!res.body) return
  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let parts: Uint8Array[] = []
  let size = 0
  let over = false
  const take = (piece: Uint8Array) => {
    if (over) return
    if (size + piece.length > max) {
      over = true
      parts = []
    } else {
      parts.push(piece)
      size += piece.length
    }
  }
  const finish = (): string | null | undefined => {
    const line = over ? null : size ? decoder.decode(concat(...parts)) : undefined
    parts = []
    size = 0
    over = false
    return line
  }
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    let start = 0
    for (let at = value.indexOf(10); at !== -1; at = value.indexOf(10, start)) {
      take(value.subarray(start, at))
      const line = finish()
      if (line !== undefined) yield line
      start = at + 1
    }
    take(value.subarray(start))
  }
  const last = finish()
  if (last !== undefined) yield last
}

/**
 * A page's `forest-cursor`: a whole number from 0, in its one decimal spelling. Anything else ends
 * the read with an error.
 */
function cursorOf(res: Response, host: string): number {
  const text = res.headers.get('forest-cursor') ?? '0'
  const cursor = Number(text)
  if (!/^(0|[1-9][0-9]*)$/.test(text) || !Number.isSafeInteger(cursor)) throw new Error(`${host} gave a cursor that is not a whole number: ${JSON.stringify(text)}`)
  return cursor
}

/**
 * Everything a host stores (for one folder, if asked), page by page, all within `timeout` ms. A
 * page that holds lines must move the cursor forward, and an empty one ends the read; a host whose
 * cursor stands still or goes back ends it with an error.
 */
export async function readAll(host: string, options: Omit<ReadOptions, 'after'> & ReadHow = {}): Promise<Page> {
  const signal = AbortSignal.timeout(options.timeout ?? READ_TIMEOUT_MS)
  const out: Page = { entries: [], cursor: 0, refused: [] }
  for (;;) {
    const page = await readPage(host, { ...options, after: out.cursor, signal })
    out.entries.push(...page.entries)
    out.refused.push(...page.refused)
    const lines = page.entries.length + page.refused.length
    if (!lines && page.cursor === out.cursor) return out
    if (page.cursor <= out.cursor) throw new Error(`${host} gave a cursor that does not move forward: ${page.cursor} after ${out.cursor}`)
    out.cursor = page.cursor
  }
}

/**
 * A folder as its hosts show it: the hosts given, then every host its current profile entry names,
 * until no new one turns up. A host that fails is skipped, so the others still count, and listed in
 * `failed` with why.
 */
export async function readFolder(hosts: string[], profile: string, now: number, how: ReadHow = {}): Promise<View & { failed: Array<{ host: string; error: string }> }> {
  const read = new Set<string>()
  const found: Checked[] = []
  const failed: Array<{ host: string; error: string }> = []
  for (let next = hosts; next.length; ) {
    for (const host of next) {
      read.add(host)
      try {
        found.push(...(await readAll(host, { ...how, profile })).entries)
      } catch (err) {
        failed.push({ host, error: (err as Error).message })
      }
    }
    next = viewFolder(profile, found, now).hosts.filter((h) => !read.has(h))
  }
  return { ...viewFolder(profile, found, now), failed }
}

export type InboxPage = { entries: CheckedInbox[]; cursor: number; refused: Array<{ line: string; reason: string }> }

/**
 * One page of a folder's inbox on one host (POST /v1/inbox/read): the inbox entries left for `to`
 * after the cursor, in the order they arrived. Anyone may list an inbox; only the envelopes protect
 * it. Each is checked, and one not to that folder, or longer than `maxBytes` (MAX_LINE_READ when
 * omitted), is refused. It throws on a page not read within `timeout` ms. `fetch` and `redirect`
 * are as for a read.
 */
export async function readInbox(host: string, to: string, options: { after?: number } & ReadHow = {}): Promise<InboxPage> {
  const res = await (options.fetch ?? fetch)(`${host}/v1/inbox/read`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ to, after: options.after ?? 0 }), signal: AbortSignal.timeout(options.timeout ?? READ_TIMEOUT_MS), ...(options.redirect && { redirect: options.redirect }) })
  if (!res.ok) throw new Error(`${host} answered ${res.status}`)
  const cursor = cursorOf(res, host)
  const entries: CheckedInbox[] = []
  const refused: InboxPage['refused'] = []
  for await (const line of readLines(res, options.maxBytes ?? MAX_LINE_READ)) {
    try {
      if (line === null) throw new FolderError('size', 'longer than this reader takes')
      const checked = decodeInbox(line)
      if (checked.entry.to !== to) throw new FolderError('to', 'not to this folder')
      entries.push(checked)
    } catch (err) {
      refused.push({ line: line ?? '', reason: err instanceof FolderError ? err.code : 'invalid' })
    }
  }
  return { entries, cursor, refused }
}

export type FileOutcome = { host: string; status: number; ok: boolean; error?: string; message?: string }

/**
 * Upload a file's bytes to each of a folder's hosts (PUT /v1/files/<sha256>), as `type`. A host
 * takes them only while a current entry it holds names them, by their hash, type and size
 * (fileOf): write that entry first.
 */
export async function upload(hosts: string[], bytes: Uint8Array, type: string, how: Reach = {}): Promise<FileOutcome[]> {
  const name = fileOf(bytes, type)
  return Promise.all(
    hosts.map(async (host): Promise<FileOutcome> => {
      try {
        const res = await (how.fetch ?? fetch)(`${host}/v1/files/${name.sha256}`, { method: 'PUT', headers: { 'content-type': type }, body: new Uint8Array(bytes), ...(how.redirect && { redirect: how.redirect }) })
        const answer = (await res.json().catch(() => ({ ok: false }))) as Omit<FileOutcome, 'host' | 'status'>
        return { host, status: res.status, ...answer, ok: res.ok && answer.ok }
      } catch (err) {
        return { host, status: 0, ok: false, error: 'unreachable', message: (err as Error).message }
      }
    }),
  )
}

/**
 * The bytes named by `sha256`, from the first of a folder's hosts that serves bytes with that hash;
 * null if none does. A host that serves other bytes, or more than `maxBytes` (MAX_FILE_READ when
 * omitted), is skipped.
 */
export async function fetchFile(hosts: string[], name: string, options: { maxBytes?: number; timeout?: number } & Reach = {}): Promise<{ host: string; bytes: Uint8Array; type: string } | null> {
  for (const host of hosts) {
    try {
      const res = await (options.fetch ?? fetch)(`${host}/v1/files/${name}`, { signal: AbortSignal.timeout(options.timeout ?? READ_TIMEOUT_MS), ...(options.redirect && { redirect: options.redirect }) })
      if (!res.ok) {
        await res.body?.cancel()
        continue
      }
      const bytes = await readBytes(res, options.maxBytes ?? MAX_FILE_READ)
      if (bytes && hex.encode(sha256(bytes)) === name) return { host, bytes, type: res.headers.get('content-type') ?? '' }
    } catch {
      // The next host.
    }
  }
  return null
}
/** A response's bytes, or null as soon as they pass `max`. */
async function readBytes(res: Response, max: number): Promise<Uint8Array | null> {
  if (!res.body) return new Uint8Array()
  const reader = res.body.getReader()
  const parts: Uint8Array[] = []
  let size = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) return concat(...parts)
    size += value.length
    if (size > max) {
      await reader.cancel()
      return null
    }
    parts.push(value)
  }
}
