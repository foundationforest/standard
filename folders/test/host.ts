// A minimal host, for folders' own tests only and never exported: the plug (README.md, Hosts) and
// nothing more. It holds what it takes in memory and chooses nothing of its own: it takes any size
// and any number of lines, refuses nothing by its own choice, keeps every entry, inbox entry and
// file it took, and answers a page whole unless a test sets `page`. Each write is given its
// request's `forest-payment` header, which this host ignores: a test that charges reads it. The
// host check runs against it (check.test.ts). A host someone runs, with its storage and its
// choices, is a product, and lives outside the standard.

import { type IncomingMessage, type Server, type ServerResponse, createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { sha256 } from '@noble/hashes/sha2.js'
import { hex } from '../src/bytes.ts'
import type { Result } from '../src/client.ts'
import { type Checked, MAX_FUTURE_MS, PROFILE_PATH, type SignedEntry, decodeEntry } from '../src/entry.ts'
import { FolderError } from '../src/fail.ts'
import { filesOf, isMediaType } from '../src/files.ts'
import { type CheckedInbox, decodeInbox } from '../src/inbox.ts'
import { canDo, openKeyOf } from '../src/profile.ts'
import { type View, liveContent, viewFolder } from '../src/view.ts'

type Row = { seq: number; profile: string; id: string; text: string }
type Answer = Omit<Result, 'i'>
type Page = { lines: string[]; cursor: number }

const FILE_PATH = /^\/v1\/files\/([0-9a-f]{64})$/

const refusal = (err: unknown): Answer => ({ ok: false, error: err instanceof FolderError ? err.code : 'invalid', message: (err as Error).message })

export class TestHost {
  /** Where it listens, once it does. */
  url = ''
  /** How many lines a page holds: every one, unless a test says otherwise. */
  page = Infinity
  private readonly now: () => number
  private readonly entries: Row[] = []
  /** Inbox entries, each with the folder it is to. */
  private readonly inbox: Row[] = []
  private readonly files = new Map<string, { type: string; bytes: Uint8Array }>()
  private seq = 0
  private server?: Server

  constructor(options: { now?: () => number } = {}) {
    this.now = options.now ?? Date.now
  }

  // ------------------------------------------------------------------------------------------
  // Entries: Taking an entry in, in the plug's order.

  async accept(lines: string[], payment?: string): Promise<Result[]> {
    const now = this.now()
    return lines.map((line, i) => ({ i, ...this.acceptOne(line, now) }))
  }

  private acceptOne(line: string, now: number): Answer {
    let c: Checked
    try {
      c = decodeEntry(line)
    } catch (err) {
      return refusal(err)
    }
    const { profile, key, path } = c.entry
    if (c.entry.time > now + MAX_FUTURE_MS) return { id: c.id, ok: false, error: 'future', message: 'dated more than ten minutes ahead' }
    const view = this.view(profile, now)
    if (key !== undefined && !canDo(view.current.get(PROFILE_PATH)?.entry.body, key, 'write')) return { id: c.id, ok: false, error: 'unlisted', message: 'the profile entry here lists no such key with write' }
    if (this.entries.some((r) => r.id === c.id)) return { id: c.id, ok: true, message: 'already here' }
    if (viewFolder(profile, [...this.stored(profile), c], now).current.get(path)?.id !== c.id) {
      return { id: c.id, ok: false, error: 'older', message: 'a newer version is already here' }
    }
    this.entries.push({ seq: ++this.seq, profile, id: c.id, text: line })
    return { id: c.id, ok: true }
  }

  /** Entries in the order taken, after a cursor, one folder's if asked. */
  read(options: { after?: number; profile?: string } = {}): Page {
    const after = options.after ?? 0
    return this.paged(this.entries.filter((r) => r.seq > after && (options.profile === undefined || r.profile === options.profile)), after)
  }

  private paged(rows: Row[], after: number): Page {
    const page = rows.slice(0, this.page)
    return { lines: page.map((r) => r.text), cursor: page.at(-1)?.seq ?? after }
  }

  private stored(profile: string): Checked[] {
    return this.entries.filter((r) => r.profile === profile).map((r) => ({ id: r.id, entry: JSON.parse(r.text) as SignedEntry }))
  }

  /** This host's view of a folder, from what it holds. */
  view(profile: string, now = this.now()): View {
    return viewFolder(profile, this.stored(profile), now)
  }

  /** Every entry's and inbox entry's text: all a host operator could see. */
  dump(): string[] {
    return [...this.entries, ...this.inbox].map((r) => r.text)
  }

  // ------------------------------------------------------------------------------------------
  // The inbox: Taking an inbox entry in, and Deleting one, in the plug's order.

  async leave(lines: string[], payment?: string): Promise<Result[]> {
    const now = this.now()
    return lines.map((line, i) => ({ i, ...this.leaveOne(line, now) }))
  }

  private leaveOne(line: string, now: number): Answer {
    let c: CheckedInbox
    try {
      c = decodeInbox(line)
    } catch (err) {
      return refusal(err)
    }
    const { entry: e, id } = c
    const refuse = (error: string, message: string): Answer => ({ id, ok: false, error, message })
    if (this.inbox.some((r) => r.id === id)) return refuse('duplicate', 'this inbox entry is already here')
    if (!openKeyOf(this.view(e.to, now).current.get(PROFILE_PATH)?.entry.body)) return refuse('no_inbox', 'the profile entry here has no openKey: the folder takes no inbox entries')
    this.inbox.push({ seq: ++this.seq, profile: e.to, id, text: line })
    return { id, ok: true }
  }

  /** A folder's inbox entries after the cursor, in the order they arrived: to anyone. */
  readInbox(to: string, after = 0): Page {
    return this.paged(this.inbox.filter((r) => r.profile === to && r.seq > after), after)
  }

  // ------------------------------------------------------------------------------------------
  // Files: Taking a file in.

  /** Whether a current entry in a folder this host holds names this file. */
  private named(sha256: string, type?: string, size?: number): boolean {
    const now = this.now()
    for (const profile of new Set(this.entries.map((r) => r.profile))) {
      for (const c of liveContent(this.view(profile, now)).values()) {
        if (filesOf(c.entry.body).some((f) => f.sha256 === sha256 && (type === undefined || (f.type === type && f.size === size)))) return true
      }
    }
    return false
  }

  async upload(name: string, type: string, bytes: Uint8Array, payment?: string): Promise<Answer> {
    if (!isMediaType(type)) return { ok: false, error: 'shape', message: 'content-type is a media type, type/subtype in lower case' }
    if (!this.named(name)) return { ok: false, error: 'unnamed', message: 'no current entry here names these bytes' }
    if (!this.named(name, type, bytes.length)) return { ok: false, error: 'shape', message: 'no current entry here names these bytes with this type and size' }
    if (hex.encode(sha256(bytes)) !== name) return { ok: false, error: 'hash', message: 'the bytes do not hash to their name' }
    if (this.files.has(name)) return { ok: true, message: 'already here' }
    this.files.set(name, { type, bytes })
    return { ok: true }
  }

  async fetchFile(name: string): Promise<{ type: string; bytes: Uint8Array } | undefined> {
    return this.files.get(name)
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
    const file = FILE_PATH.exec(url.pathname)?.[1]
    const posts = ['/v1/entries', '/v1/entries/read', '/v1/inbox', '/v1/inbox/read']
    const methods = url.pathname === '/v1/entries' ? ['GET', 'POST'] : posts.includes(url.pathname) ? ['POST'] : file ? ['GET', 'PUT'] : []
    if (!methods.length) return void res.writeHead(404).end()
    if (!methods.includes(req.method ?? '')) return void res.writeHead(405, { allow: methods.join(', ') }).end()
    const body = await readBody(req)
    const payment = req.headers['forest-payment'] as string | undefined

    if (file && req.method === 'GET') {
      const held = await this.fetchFile(file)
      if (!held) return void res.writeHead(404).end()
      return void res.writeHead(200, { 'content-type': held.type, 'content-length': held.bytes.length }).end(held.bytes)
    }
    if (file) {
      const answer = await this.upload(file, (req.headers['content-type'] ?? '').trim(), body, payment)
      return sendJson(res, answer.ok ? 200 : 400, answer)
    }
    if (req.method === 'GET') {
      const after = url.searchParams.get('after')
      const asked = after === null ? 0 : Number(after)
      if (!Number.isSafeInteger(asked) || asked < 0) return void res.writeHead(400).end()
      return sendLines(res, this.read({ after: asked }))
    }
    if (url.pathname === '/v1/entries/read' || url.pathname === '/v1/inbox/read') {
      const field = url.pathname === '/v1/entries/read' ? 'profile' : 'to'
      const asked = readAsk(text(body), field)
      if (!asked) return void res.writeHead(400).end()
      return sendLines(res, field === 'profile' ? this.read({ profile: asked.folder, after: asked.after }) : this.readInbox(asked.folder, asked.after))
    }
    const lines = text(body).split('\n').filter((l) => l.length > 0)
    const results = url.pathname === '/v1/inbox' ? await this.leave(lines, payment) : await this.accept(lines, payment)
    res.writeHead(200, { 'content-type': 'application/x-ndjson' }).end(results.map((r) => JSON.stringify(r) + '\n').join(''))
  }
}

/** A read request's body: `{ <field>, after? }` and nothing else, or undefined. */
function readAsk(body: string, field: 'profile' | 'to'): { folder: string; after: number } | undefined {
  let value: unknown
  try {
    value = JSON.parse(body)
  } catch {
    return undefined
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  const { [field]: folder, after = 0, ...rest } = value as { [key: string]: unknown }
  if (Object.keys(rest).length || typeof folder !== 'string' || !Number.isSafeInteger(after) || (after as number) < 0) return undefined
  return { folder, after: after as number }
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
