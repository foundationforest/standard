// A minimal host, for records' own tests only and never exported: the plug (README.md, Hosts) and
// nothing more. It holds what it takes in memory and chooses nothing of its own: it takes any size
// and any number of lines, refuses nothing by its own choice, keeps every record and message it
// took, and answers a page whole unless a test sets `page`. The host check runs against it
// (check.test.ts). A host someone runs, with its storage and its choices, is a product, and lives
// outside the standard.

import { type IncomingMessage, type Server, type ServerResponse, createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { sha256 } from '@noble/hashes/sha2.js'
import { hex, utf8 } from '../src/bytes.ts'
import type { ReadOptions, Result } from '../src/client.ts'
import { type CheckedMessage, type SignedBlobRequest, checkBlobRequest, checkMessage, checkPull, inboxOf, readMessage } from '../src/message.ts'
import { type Checked, MAX_FUTURE_MS, RecordError, type SignedRecord, decodeRecord } from '../src/record.ts'
import { type View, viewProfile } from '../src/view.ts'

type Row = { seq: number; profile: string; id: string; text: string }
type Answer = Omit<Result, 'i'>
type Page = { lines: string[]; cursor: number }

const BLOB_PATH = /^\/v1\/blobs\/([0-9a-f]{64})$/

const refusal = (err: unknown): Answer => ({ ok: false, error: err instanceof RecordError ? err.code : 'invalid', message: (err as Error).message })

export class TestHost {
  /** Where it listens, once it does. */
  url = ''
  /** How many lines a page holds: every one, unless a test says otherwise. */
  page = Infinity
  private readonly now: () => number
  private readonly records: Row[] = []
  /** Messages, each with the profile it is to. */
  private readonly messages: Row[] = []
  private readonly blobs = new Map<string, { type: string; bytes: Uint8Array; folders: Set<string> }>()
  private seq = 0
  private server?: Server

  constructor(options: { now?: () => number } = {}) {
    this.now = options.now ?? Date.now
  }

  // ------------------------------------------------------------------------------------------
  // Records: Taking a record in, in the plug's order.

  async accept(lines: string[]): Promise<Result[]> {
    const now = this.now()
    return lines.map((line, i) => ({ i, ...this.acceptOne(line, now) }))
  }

  private acceptOne(line: string, now: number): Answer {
    let c: Checked
    try {
      c = decodeRecord(line)
    } catch (err) {
      return refusal(err)
    }
    if (c.record.time > now + MAX_FUTURE_MS) return { id: c.id, ok: false, error: 'future', message: 'dated more than ten minutes ahead' }
    if (this.records.some((r) => r.id === c.id)) return { id: c.id, ok: true, message: 'already here' }
    if (viewProfile(c.record.profile, [...this.stored(c.record.profile), c], now).current.get(c.record.path)?.id !== c.id) {
      return { id: c.id, ok: false, error: 'older', message: 'a newer version is already here' }
    }
    this.records.push({ seq: ++this.seq, profile: c.record.profile, id: c.id, text: line })
    return { id: c.id, ok: true }
  }

  /** Records in the order taken, after a cursor, one profile's if asked. */
  read(options: ReadOptions = {}): Page {
    const after = options.after ?? 0
    return this.paged(this.records.filter((r) => r.seq > after && (options.profile === undefined || r.profile === options.profile)), after)
  }

  private paged(rows: Row[], after: number): Page {
    const page = rows.slice(0, this.page)
    return { lines: page.map((r) => r.text), cursor: page.at(-1)?.seq ?? after }
  }

  private stored(profile: string): Checked[] {
    return this.records.filter((r) => r.profile === profile).map((r) => ({ id: r.id, record: JSON.parse(r.text) as SignedRecord }))
  }

  /** This host's view of a profile, from what it holds. */
  view(profile: string, now = this.now()): View {
    return viewProfile(profile, this.stored(profile), now)
  }

  /** Every record's and message's text: all a host operator could see. */
  dump(): string[] {
    return [...this.records, ...this.messages].map((r) => r.text)
  }

  // ------------------------------------------------------------------------------------------
  // Messages: Taking a message in, in the plug's order.

  async deliver(lines: string[]): Promise<Result[]> {
    const now = this.now()
    return lines.map((line, i) => ({ i, ...this.deliverOne(line, now) }))
  }

  private deliverOne(line: string, now: number): Answer {
    let c: CheckedMessage
    try {
      c = readMessage(line)
    } catch (err) {
      return refusal(err)
    }
    const { message: m, id } = c
    const refuse = (error: string, message: string): Answer => ({ id, ok: false, error, message })
    if (m.time > now + MAX_FUTURE_MS) return refuse('future', 'dated more than ten minutes ahead')
    if (this.messages.some((r) => r.profile === m.to && r.id === id)) return refuse('duplicate', 'this message is already here')
    const inbox = inboxOf(this.view(m.to, now).current.get('profile')?.record.body)
    if (inbox === null || inbox === 'unsupported') return refuse('no_inbox', 'the profile record here declares no inbox this host can read')
    if (!checkMessage(c)) return refuse('signature', 'the signature does not hold')
    if (m.from !== m.to && inbox.maxBytes !== undefined && utf8(line).length > inbox.maxBytes) return refuse('too_big', `this inbox takes messages of at most ${inbox.maxBytes} bytes`)
    this.messages.push({ seq: ++this.seq, profile: m.to, id, text: line })
    return { id, ok: true }
  }

  /** A pull, checked at this host's clock, then that profile's messages after the cursor. Throws RecordError. */
  pull(text: string, now = this.now()): Page {
    const request = checkPull(text, now)
    return this.paged(this.messages.filter((r) => r.profile === request.profile && r.seq > request.after), request.after)
  }

  // ------------------------------------------------------------------------------------------
  // Blobs: Taking a blob in, and Deleting a blob.

  private checkBlob(text: string, action: 'put' | 'delete', name: string): SignedBlobRequest {
    const request = checkBlobRequest(text, this.now())
    if (request.action !== action) throw new RecordError('shape', `this is a ${action} request`)
    if (request.sha256 !== name) throw new RecordError('shape', 'the request names other bytes')
    return request
  }

  async putBlob(name: string, type: string, request: string, bytes: Uint8Array): Promise<Answer> {
    let put: SignedBlobRequest & { action: 'put' }
    try {
      put = this.checkBlob(request, 'put', name) as SignedBlobRequest & { action: 'put' }
    } catch (err) {
      return refusal(err)
    }
    if (put.mimeType !== type || put.size !== bytes.length) return { ok: false, error: 'shape', message: 'the bytes are not the type and size the request names' }
    if (hex.encode(sha256(bytes)) !== name) return { ok: false, error: 'hash', message: 'the bytes do not hash to their name' }
    const held = this.blobs.get(name)
    if (held?.folders.has(put.profile)) return { ok: true, message: 'already here' }
    if (held) held.folders.add(put.profile)
    else this.blobs.set(name, { type, bytes, folders: new Set([put.profile]) })
    return { ok: true }
  }

  async deleteBlob(name: string, request: string): Promise<Answer> {
    let ask: SignedBlobRequest
    try {
      ask = this.checkBlob(request, 'delete', name)
    } catch (err) {
      return refusal(err)
    }
    const held = this.blobs.get(name)
    if (!held?.folders.delete(ask.profile)) return { ok: true, message: 'not here' }
    if (!held.folders.size) this.blobs.delete(name)
    return { ok: true }
  }

  async getBlob(name: string): Promise<{ type: string; bytes: Uint8Array } | undefined> {
    return this.blobs.get(name)
  }

  // ------------------------------------------------------------------------------------------
  // HTTP

  async listen(): Promise<string> {
    this.server = createServer((req, res) => {
      this.handle(req, res).catch(() => {
        if (!res.headersSent) res.writeHead(500).end()
      })
    })
    await new Promise<void>((resolve) => this.server!.listen(0, '127.0.0.1', resolve))
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`
    return this.url
  }

  async close(): Promise<void> {
    if (!this.server) return
    this.server.closeAllConnections()
    await new Promise<void>((resolve) => this.server!.close(() => resolve()))
  }

  private async handle(req: IncomingMessage, res: ServerResponse) {
    const url = URL.parse(req.url ?? '/', 'http://host.invalid')
    if (!url) return void res.writeHead(400).end()
    const blob = BLOB_PATH.exec(url.pathname)?.[1]
    const methods = url.pathname === '/v1/records' ? ['GET', 'POST'] : ['/v1/records/read', '/v1/inbox', '/v1/inbox/pull'].includes(url.pathname) ? ['POST'] : blob ? ['GET', 'PUT', 'DELETE'] : []
    if (!methods.length) return void res.writeHead(404).end()
    if (!methods.includes(req.method ?? '')) return void res.writeHead(405, { allow: methods.join(', ') }).end()
    const body = await readBody(req)

    if (blob && req.method === 'GET') {
      const held = await this.getBlob(blob)
      if (!held) return void res.writeHead(404).end()
      return void res.writeHead(200, { 'content-type': held.type, 'content-length': held.bytes.length }).end(held.bytes)
    }
    if (blob) {
      const request = req.headers['forest-blob']
      if (typeof request !== 'string') return sendJson(res, 400, { ok: false, error: 'shape', message: 'a blob request is signed, in the header forest-blob' })
      const answer = req.method === 'DELETE' ? await this.deleteBlob(blob, request) : await this.putBlob(blob, (req.headers['content-type'] ?? '').trim(), request, body)
      return sendJson(res, answer.ok ? 200 : 400, answer)
    }
    if (url.pathname === '/v1/inbox/pull') {
      try {
        return sendLines(res, this.pull(text(body)))
      } catch (err) {
        if (!(err instanceof RecordError)) throw err
        return sendJson(res, 400, { ok: false, error: err.code, message: err.message })
      }
    }
    if (req.method === 'GET' || url.pathname === '/v1/records/read') {
      let asked: ReadOptions | undefined
      if (req.method === 'GET') {
        const after = url.searchParams.get('after')
        asked = { after: after === null ? 0 : Number(after), profile: url.searchParams.get('profile') ?? undefined }
      } else asked = readAsk(text(body))
      if (!asked || !Number.isSafeInteger(asked.after) || asked.after! < 0) return void res.writeHead(400).end()
      return sendLines(res, this.read(asked))
    }
    const lines = text(body).split('\n').filter((l) => l.length > 0)
    const results = url.pathname === '/v1/inbox' ? await this.deliver(lines) : await this.accept(lines)
    res.writeHead(200, { 'content-type': 'application/x-ndjson' }).end(results.map((r) => JSON.stringify(r) + '\n').join(''))
  }
}

/** A read request's body: `{ profile?, after? }` and nothing else, or undefined. */
function readAsk(body: string): ReadOptions | undefined {
  let value: unknown
  try {
    value = JSON.parse(body)
  } catch {
    return undefined
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  const { profile, after = 0, ...rest } = value as { [key: string]: unknown }
  if (Object.keys(rest).length || (profile !== undefined && typeof profile !== 'string') || typeof after !== 'number') return undefined
  return { after, profile }
}

function sendJson(res: ServerResponse, status: number, value: object) {
  res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(value))
}

function sendLines(res: ServerResponse, out: Page) {
  res.writeHead(200, { 'content-type': 'application/x-ndjson', 'forest-cursor': String(out.cursor) }).end(out.lines.map((l) => l + '\n').join(''))
}

/** A body as text: bytes that are not UTF-8 become U+FFFD and a byte order mark stays, so a line that has one is refused. */
const text = (body: Uint8Array) => new TextDecoder('utf-8', { ignoreBOM: true }).decode(body)

async function readBody(req: IncomingMessage): Promise<Uint8Array> {
  const chunks: Uint8Array[] = []
  for await (const chunk of req) chunks.push(chunk as Uint8Array)
  const body = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0))
  let at = 0
  for (const chunk of chunks) {
    body.set(chunk, at)
    at += chunk.length
  }
  return body
}
