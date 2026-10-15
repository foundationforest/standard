// Talking to hosts over HTTP: publish records and read them back; deliver messages and pull your
// own; put, get and delete blobs. Every record and message read is checked here, and every blob's bytes
// hashed, whatever host they came from: a reader trusts no host.
//
// How many lines a request or a page holds is each host's choice, and this handles any: a request
// a host finds too big is sent again in halves, and a page is read line by line, however long. How
// large a record, a message or a blob to take is each host's own choice, and each reader's: this
// ignores what is larger than it is told to take, MAX_LINE_READ and MAX_BLOB_READ unless told
// otherwise.

import { sha256 } from '@noble/hashes/sha2.js'
import { concat, hex } from './bytes.ts'
import { canonical } from './canonical.ts'
import type { ReadOptions, Result } from './host.ts'
import { type CheckedMessage, type SignedBlobRequest, type SignedMessage, type SignedPull, decodeMessage, encodeMessage } from './message.ts'
import { type Checked, RecordError, type SignedRecord, decodeRecord, encodeRecord } from './record.ts'
import { type View, viewProfile } from './view.ts'

export type PublishOutcome = { host: string; status: number; results: Result[]; error?: string }

/** A read that has not finished by then is given up. */
export const READ_TIMEOUT_MS = 60_000
/** The largest record or message, as canonical text, a reader takes unless told otherwise: the most the reference host takes. */
export const MAX_LINE_READ = 65_536
/** The largest blob a reader takes unless told otherwise: the most the reference host takes. */
export const MAX_BLOB_READ = 50_000_000

/** How to reach a host: `fetch` and `redirect` as a read takes them (ReadHow). */
export type Reach = Pick<ReadHow, 'fetch' | 'redirect'>

/** Send records to each host. A host that fails does not stop the others. */
export async function publish(hosts: string[], records: SignedRecord[], how: Reach = {}): Promise<PublishOutcome[]> {
  return post(hosts, '/v1/records', records.map(encodeRecord), how)
}

/** Deliver messages to each host: each of the recipient's hosts, as its hosts record names them. */
export async function deliver(hosts: string[], messages: SignedMessage[], how: Reach = {}): Promise<PublishOutcome[]> {
  return post(hosts, '/v1/inbox', messages.map(encodeMessage), how)
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

/** One request; if the host finds it too big (413, or one `batch` refusal), each half again, down to one line. */
async function postLines(url: string, lines: string[], how: Reach): Promise<{ status: number; results: Result[] }> {
  const res = await (how.fetch ?? fetch)(url, { method: 'POST', headers: { 'content-type': 'application/x-ndjson' }, body: lines.map((l) => l + '\n').join(''), ...(how.redirect && { redirect: how.redirect }) })
  const results = (await res.text())
    .split('\n')
    .filter((l) => l)
    .map((l) => JSON.parse(l) as Result)
  const tooBig = res.status === 413 || (results.length === 1 && results[0]!.error === 'batch')
  if (!tooBig || lines.length < 2) return { status: res.status, results }
  const half = Math.ceil(lines.length / 2)
  const first = await postLines(url, lines.slice(0, half), how)
  const second = await postLines(url, lines.slice(half), how)
  return { status: first.status !== 200 ? first.status : second.status, results: [...first.results, ...second.results.map((r) => ({ ...r, i: r.i + half }))] }
}

export type Page = { records: Checked[]; cursor: number; refused: Array<{ line: string; reason: string }> }

/**
 * How to read: `post` puts the profile and the cursor in the body (POST /v1/records/read) rather
 * than the URL, for reading your own profiles; `maxBytes` is the longest line taken (MAX_LINE_READ
 * when omitted); `timeout` is in ms (READ_TIMEOUT_MS when omitted). `fetch` is the caller's own
 * (one that refuses private addresses, say), and `redirect` goes to it as fetch takes it: `error`
 * refuses a host that redirects. The global fetch, following redirects, when omitted.
 */
export type ReadHow = { post?: boolean; maxBytes?: number; timeout?: number; fetch?: typeof fetch; redirect?: RequestRedirect }

/**
 * One page of what a host stores, after a cursor, in the order it took them, each record checked.
 * A page may be any length; a line longer than `maxBytes` is refused unread. It throws on a page
 * not read within `timeout` ms.
 */
export async function readPage(host: string, options: ReadOptions & ReadHow = {}): Promise<Page> {
  const how = { signal: AbortSignal.timeout(options.timeout ?? READ_TIMEOUT_MS), ...(options.redirect && { redirect: options.redirect }) }
  const get = options.fetch ?? fetch
  const asked = { ...(options.profile !== undefined && { profile: options.profile }), ...(options.after !== undefined && { after: options.after }) }
  const res = options.post
    ? await get(`${host}/v1/records/read`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(asked), ...how })
    : await get(`${host}/v1/records?${new URLSearchParams(Object.entries(asked).map(([k, v]) => [k, String(v)]))}`, how)
  if (!res.ok) throw new Error(`${host} answered ${res.status}`)
  const cursor = Number.parseInt(res.headers.get('forest-cursor') ?? '0', 10)
  const records: Checked[] = []
  const refused: Page['refused'] = []
  for await (const line of readLines(res, options.maxBytes ?? MAX_LINE_READ)) {
    try {
      if (line === null) throw new RecordError('size', 'longer than this reader takes')
      records.push(decodeRecord(line))
    } catch (err) {
      refused.push({ line: line ?? '', reason: err instanceof RecordError ? err.code : 'invalid' })
    }
  }
  return { records, cursor, refused }
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

/** Everything a host stores (for one profile, if asked), page by page. */
export async function readAll(host: string, options: Omit<ReadOptions, 'after'> & ReadHow = {}): Promise<Page> {
  const out: Page = { records: [], cursor: 0, refused: [] }
  for (;;) {
    const page = await readPage(host, { ...options, after: out.cursor })
    out.records.push(...page.records)
    out.refused.push(...page.refused)
    if (page.cursor === out.cursor) return out
    out.cursor = page.cursor
  }
}

/**
 * A profile as its hosts show it: the hosts given, then every host its current hosts record names,
 * until no new one turns up. A host that fails is skipped, so the others still count, and listed in
 * `failed` with why.
 */
export async function readProfile(hosts: string[], profile: string, now: number, how: ReadHow = {}): Promise<View & { failed: Array<{ host: string; error: string }> }> {
  const read = new Set<string>()
  const found: Checked[] = []
  const failed: Array<{ host: string; error: string }> = []
  for (let next = hosts; next.length; ) {
    for (const host of next) {
      read.add(host)
      try {
        found.push(...(await readAll(host, { ...how, profile })).records)
      } catch (err) {
        failed.push({ host, error: (err as Error).message })
      }
    }
    next = viewProfile(profile, found, now).hosts.filter((h) => !read.has(h))
  }
  return { ...viewProfile(profile, found, now), failed }
}

export type MessagePage = { messages: CheckedMessage[]; cursor: number; refused: Array<{ line: string; reason: string }> }

/**
 * One page of a profile's inbox on one host. `request` is pullRequest(owner, after, now): the
 * profile's main key, or one of its read keys, signs each pull. Each message is checked, and one
 * not to that profile, or longer than `maxBytes` (MAX_LINE_READ when omitted), is refused. It throws
 * a RecordError with the host's code (stale, signature, permission, ...) when the host refuses the
 * pull, and on a page not read within `timeout` ms. `fetch` and `redirect` are as for a read.
 */
export async function pull(host: string, request: SignedPull, options: { maxBytes?: number; timeout?: number } & Reach = {}): Promise<MessagePage> {
  const res = await (options.fetch ?? fetch)(`${host}/v1/inbox/pull`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: canonical(request), signal: AbortSignal.timeout(options.timeout ?? READ_TIMEOUT_MS), ...(options.redirect && { redirect: options.redirect }) })
  if (!res.ok) {
    const why = (await res.json().catch(() => ({}))) as { error?: string; message?: string }
    throw new RecordError(why.error ?? 'host', `${host} answered ${res.status}${why.message ? `: ${why.message}` : ''}`)
  }
  const cursor = Number.parseInt(res.headers.get('forest-cursor') ?? '0', 10)
  const messages: CheckedMessage[] = []
  const refused: MessagePage['refused'] = []
  for await (const line of readLines(res, options.maxBytes ?? MAX_LINE_READ)) {
    try {
      if (line === null) throw new RecordError('size', 'longer than this reader takes')
      const checked = decodeMessage(line)
      if (checked.message.to !== request.profile) throw new RecordError('to', 'not to this profile')
      messages.push(checked)
    } catch (err) {
      refused.push({ line: line ?? '', reason: err instanceof RecordError ? err.code : 'invalid' })
    }
  }
  return { messages, cursor, refused }
}

export type BlobOutcome = { host: string; status: number; ok: boolean; error?: string; message?: string }

/** One signed blob request to each host, the bytes with a put; each host's answer. */
async function sendBlob(hosts: string[], request: SignedBlobRequest, bytes?: Uint8Array): Promise<BlobOutcome[]> {
  return Promise.all(
    hosts.map(async (host): Promise<BlobOutcome> => {
      try {
        const headers: Record<string, string> = { 'forest-blob': canonical(request) }
        if (request.action === 'put') headers['content-type'] = request.mimeType
        const res = await fetch(`${host}/v1/blobs/${request.sha256}`, { method: request.action === 'put' ? 'PUT' : 'DELETE', headers, ...(bytes && { body: new Uint8Array(bytes) }) })
        const answer = (await res.json().catch(() => ({ ok: false }))) as Omit<BlobOutcome, 'host' | 'status'>
        return { host, status: res.status, ...answer, ok: res.ok && answer.ok }
      } catch (err) {
        return { host, status: 0, ok: false, error: 'unreachable', message: (err as Error).message }
      }
    }),
  )
}

/**
 * Put bytes in a folder on each of its hosts: `request` is the signed put (blobRequest) that names
 * them, by their hash, type and size (blobNameOf). The same request goes to every host.
 */
export function putBlob(hosts: string[], request: SignedBlobRequest & { action: 'put' }, bytes: Uint8Array): Promise<BlobOutcome[]> {
  return sendBlob(hosts, request, bytes)
}

/** Delete bytes from a folder on each of its hosts: `request` is the signed delete (blobRequest). */
export function deleteBlob(hosts: string[], request: SignedBlobRequest & { action: 'delete' }): Promise<BlobOutcome[]> {
  return sendBlob(hosts, request)
}

/**
 * The bytes named by `sha256`, from the first of a folder's hosts that serves bytes with that hash;
 * null if none does. A host that serves other bytes, or more than `maxBytes`
 * (MAX_BLOB_READ when omitted), is skipped.
 */
export async function getBlob(hosts: string[], name: string, options: { maxBytes?: number; timeout?: number } = {}): Promise<{ host: string; bytes: Uint8Array; type: string } | null> {
  for (const host of hosts) {
    try {
      const res = await fetch(`${host}/v1/blobs/${name}`, { signal: AbortSignal.timeout(options.timeout ?? READ_TIMEOUT_MS) })
      if (!res.ok) {
        await res.body?.cancel()
        continue
      }
      const bytes = await readBytes(res, options.maxBytes ?? MAX_BLOB_READ)
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
