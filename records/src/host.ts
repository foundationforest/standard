// A host: plain HTTP, a SQLite file per folder, and a blob store (storage.ts). It holds no keys,
// has no accounts and asks for no login: a record's signature is its only credential, a pull's is
// the recipient's main key's or read key's, and a blob request's the folder's main key's or a write
// key's. It is open: it takes signed records for any profile and serves them to anyone; it takes
// messages for any profile whose card here declares an inbox, and serves them only to that
// profile's main key and read keys; it takes the bytes a folder's keys put, and serves them to
// anyone. It never reads an offer's or a review's body: the bodies it reads are the hosts and
// permissions records', and the card's inbox and proofs. Given readSender, it reads a sender's
// records from one of the sender's hosts: its permissions, to take a message a write key signed,
// and its card, for an inbox with an issuer's rule, whose human proofs it checks with verifyHuman.
// It keeps the newest version at each path; versions that stop being newest, and messages, go
// after `keepDays`. A folder's blobs stay until its keys delete them.
//
//   POST /v1/records                      NDJSON of canonical records; one NDJSON result each
//   GET  /v1/records?profile=&after=      NDJSON of stored records in the order taken;
//                                         header forest-cursor: the last sequence number
//   POST /v1/records/read                 the same, asked by { profile?, after? } in the body
//   POST /v1/inbox                        NDJSON of canonical messages; one NDJSON result each
//   POST /v1/inbox/pull                   a signed pull request; NDJSON of that profile's messages
//                                         after the cursor, in arrival order; header forest-cursor
//   PUT    /v1/blobs/<sha256>             raw bytes, content-type their type; header forest-blob:
//                                         the signed put request
//   GET    /v1/blobs/<sha256>             the bytes, with the type they came in with
//   DELETE /v1/blobs/<sha256>             header forest-blob: the signed delete request
//
// How large a record, a message or a blob it takes, and how many lines a request or a page holds,
// is this host's own choice (maxLineBytes, maxBlobBytes, maxBatch, maxPageRecords, maxPageBytes); a
// client handles any size. It logs nothing about who asks. Where it keeps things is storage.ts's
// business, and only storage.ts's.

import { type IncomingMessage, type Server, type ServerResponse, createServer } from 'node:http'
import type { AddressInfo } from 'node:net'
import { sha256 } from '@noble/hashes/sha2.js'
import { hex, utf8 } from './bytes.ts'
import { READ_TIMEOUT_MS } from './client.ts'
import { publicKeyFromAddress } from './keys.ts'
import { type CheckedMessage, type Inbox, type SignedBlobRequest, type SignedMessage, checkBlobRequest, checkPull, inboxOf, readMessage, verifyMessage } from './message.ts'
import { type HumanCheck, humanCheck, proofsOf } from './proofs.ts'
import { type Checked, MAX_FUTURE_MS, RecordError, type SignedRecord, decodeRecord, encodeRecord, isControlPath } from './record.ts'
import { type BlobDriver, type Row, Storage } from './storage.ts'
import { type View, allowsArrival, allowsInbox, viewProfile } from './view.ts'

export { type BlobDriver, type S3Options, rebuild } from './storage.ts'

export const DAY = 86_400_000
/** The largest record or message it takes, as canonical text in bytes, unless the operator says otherwise. */
export const DEFAULT_MAX_LINE_BYTES = 65_536
/** Records or messages a request carries, unless the operator says otherwise. */
export const DEFAULT_MAX_BATCH = 100
/** Records or messages a page holds, unless the operator says otherwise. */
export const DEFAULT_MAX_PAGE_RECORDS = 1000
/** Bytes a page holds, unless the operator says otherwise. A page always holds at least one line. */
export const DEFAULT_MAX_PAGE_BYTES = 4 * 1024 * 1024
/** Days a replaced version or a message is kept, unless the operator says otherwise. */
export const DEFAULT_KEEP_DAYS = 30
/** The largest blob it reads, unless the operator says otherwise: a short video. */
export const DEFAULT_MAX_BLOB_BYTES = 50_000_000
/** The blob types it takes, unless the operator says otherwise: photos and short videos. */
export const DEFAULT_BLOB_TYPES = ['image/png', 'image/jpeg', 'video/mp4']
/** A pull request is about 200 bytes, and a read request under 100. */
const MAX_ASK_BYTES = 1024
const BLOB_PATH = /^\/v1\/blobs\/([0-9a-f]{64})$/
/** A blob request is about 300 bytes. */
const MAX_BLOB_REQUEST_BYTES = 1024

/**
 * A host's own choice for content records: null takes the record, a reason refuses it. It is
 * never asked about a hosts or permissions record, so a person can always move and always remove
 * an access key.
 */
export type RecordChoice = (record: SignedRecord, stored: { records: number; bytes: number }) => string | null | Promise<string | null>
/** A host's own choice for messages, from the message and what it holds for that recipient. */
export type MessageChoice = (message: SignedMessage, stored: { messages: number; bytes: number }) => string | null | Promise<string | null>
/**
 * A host's own choice for blobs, past its size cap: bytes a folder puts here, from what the folder
 * holds here already, so a rule may go by folder: a quota, say.
 */
export type BlobChoice = (blob: { sha256: string; type: string; size: number; profile: string }, stored: { blobs: number; bytes: number }) => string | null | Promise<string | null>

export const defaultBlobChoice: BlobChoice = (blob) => (DEFAULT_BLOB_TYPES.includes(blob.type) ? null : `this host takes ${DEFAULT_BLOB_TYPES.join(', ')}`)

export type HostOptions = {
  /**
   * The data directory: `folders/` (a SQLite file per folder), `host.sqlite` (the log and the blob
   * index) and, for the disk driver, `blobs/`. A fresh temporary one, removed on close, when omitted.
   */
  dir?: string
  /** Where blob bytes go: on disk in the data directory, or an S3-compatible bucket. Disk when omitted. */
  blobs?: BlobDriver
  now?: () => number
  /** The operator's choice; DEFAULT_KEEP_DAYS when omitted. */
  keepDays?: number
  /** The largest record or message it takes, as canonical text in bytes; DEFAULT_MAX_LINE_BYTES when omitted. */
  maxLineBytes?: number
  recordChoice?: RecordChoice
  /** Milliseconds a request may take to arrive in full; past that it gets 408. READ_TIMEOUT_MS when omitted. */
  timeout?: number
  /** Records or messages a request may carry; DEFAULT_MAX_BATCH when omitted. */
  maxBatch?: number
  /** Records or messages a page holds at most; DEFAULT_MAX_PAGE_RECORDS when omitted. */
  maxPageRecords?: number
  /** Bytes a page holds at most, though always one line; DEFAULT_MAX_PAGE_BYTES when omitted. */
  maxPageBytes?: number
  /**
   * A profile's records, each checked, as one of its hosts serves them: what readAll gives. Used to
   * take a message a write key signed, and one to an inbox with an issuer's rule: the sender's
   * hosts, permissions and profile records come from the host the message names, never from the
   * message. Without it, the host takes no such message. It is read again for each request; keeping
   * it longer is the operator's choice, made here.
   */
  readSender?: (host: string, profile: string) => Promise<Iterable<Checked>>
  /**
   * Whether a human proof holds: proofs/human/client's verifyHuman, given a sender's card's proof as
   * humanCheck makes it. Used for an inbox with an issuer's rule. Without it, the host takes
   * messages only for inboxes open to anyone.
   */
  verifyHuman?: (input: HumanCheck) => Promise<boolean>
  messageChoice?: MessageChoice
  /** The largest blob it reads; DEFAULT_MAX_BLOB_BYTES when omitted. */
  maxBlobBytes?: number
  /** defaultBlobChoice when omitted. */
  blobChoice?: BlobChoice
}

export type Result = { i: number; id?: string; ok: boolean; error?: string; message?: string }
export type ReadOptions = { after?: number; profile?: string }
type Answer = Omit<Result, 'i'>

export class Host {
  /** Where it listens, once it does. */
  url = ''
  readonly keepDays: number
  readonly maxLineBytes: number
  readonly maxBatch: number
  readonly maxPageRecords: number
  readonly maxPageBytes: number
  readonly maxBlobBytes: number
  private readonly storage: Storage
  private readonly now: () => number
  private readonly recordChoice?: RecordChoice
  private readonly messageChoice?: MessageChoice
  private readonly blobChoice: BlobChoice
  private readonly readSender?: HostOptions['readSender']
  private readonly verifyHuman?: HostOptions['verifyHuman']
  private readonly timeout: number
  private server?: Server
  private pruning?: NodeJS.Timeout

  constructor(options: HostOptions = {}) {
    this.now = options.now ?? Date.now
    this.keepDays = options.keepDays ?? DEFAULT_KEEP_DAYS
    this.maxLineBytes = options.maxLineBytes ?? DEFAULT_MAX_LINE_BYTES
    this.maxBatch = options.maxBatch ?? DEFAULT_MAX_BATCH
    this.maxPageRecords = options.maxPageRecords ?? DEFAULT_MAX_PAGE_RECORDS
    this.maxPageBytes = options.maxPageBytes ?? DEFAULT_MAX_PAGE_BYTES
    this.maxBlobBytes = options.maxBlobBytes ?? DEFAULT_MAX_BLOB_BYTES
    this.recordChoice = options.recordChoice
    this.messageChoice = options.messageChoice
    this.blobChoice = options.blobChoice ?? defaultBlobChoice
    this.readSender = options.readSender
    this.verifyHuman = options.verifyHuman
    this.timeout = options.timeout ?? READ_TIMEOUT_MS
    this.storage = new Storage(options.dir, options.blobs)
  }

  // ------------------------------------------------------------------------------------------
  // Records

  /** Take a request's records (wire text), check each, store what is newest at its path. */
  async accept(lines: string[]): Promise<Result[]> {
    if (lines.length > this.maxBatch) return [{ i: 0, ok: false, error: 'batch', message: `at most ${this.maxBatch} records a request` }]
    const now = this.now()
    const results: Result[] = []
    const decoded: Array<{ i: number; checked: Checked }> = []
    lines.forEach((line, i) => {
      try {
        if (this.tooBig(line)) throw new RecordError('size', `this host takes records of at most ${this.maxLineBytes} bytes`)
        const checked = decodeRecord(line)
        if (checked.record.time > now + MAX_FUTURE_MS) results.push({ i, id: checked.id, ok: false, error: 'future', message: 'dated more than ten minutes ahead' })
        else decoded.push({ i, checked })
      } catch (err) {
        results.push({ i, ok: false, error: err instanceof RecordError ? err.code : 'invalid', message: (err as Error).message })
      }
    })
    // Hosts and permissions records first, so access keys' records sent with their permissions in
    // one request are checked against them; the rest in the order sent.
    const control = (c: Checked) => Number(isControlPath(c.record.path))
    decoded.sort((a, b) => control(b.checked) - control(a.checked) || a.i - b.i)
    for (const { i, checked } of decoded) results.push({ i, id: checked.id, ...(await this.acceptOne(checked, now)) })
    return results.sort((a, b) => a.i - b.i)
  }

  private async acceptOne(c: Checked, now: number): Promise<Omit<Result, 'i' | 'id'>> {
    const { record } = c
    if (this.storage.hasRecord(record.profile, c.id)) return { ok: true, message: 'already here' }
    // Kept only if it becomes the newest at its path, with the protocol's own rules.
    const view = viewProfile(record.profile, [...this.stored(record.profile), c], now)
    if (view.current.get(record.path)?.id !== c.id) {
      const reason = view.ignored.get(c.id)
      if (reason === 'owner-wins') return { ok: false, error: 'permission', message: 'the owner wrote at this path' }
      if (reason === 'not-allowed') return { ok: false, error: 'permission', message: 'the permissions record does not allow this access key here' }
      return { ok: false, error: 'older', message: 'a newer version is already here' }
    }
    // A reader counts a past write key's records, since it is still listed; a host takes none.
    if (record.by !== undefined && !allowsArrival(view.access, record)) return { ok: false, error: 'permission', message: 'this access key is past' }
    if (this.recordChoice && !isControlPath(record.path)) {
      const refused = await this.recordChoice(record, this.storage.recordTotals(record.profile))
      if (refused) return { ok: false, error: 'refused', message: refused }
    }
    // From here on, no wait: its own choice may have let other requests store records for this
    // profile, so what is current is worked out again. What is current is kept; what stopped being
    // current gets a date, and goes `keepDays` later.
    if (this.storage.hasRecord(record.profile, c.id)) return { ok: true, message: 'already here' }
    const settled = [...viewProfile(record.profile, [...this.stored(record.profile), c], now).current.values()]
    this.storage.addRecord(record.profile, c.id, encodeRecord(record), now, new Set(settled.map((s) => s.id)))
    return { ok: true }
  }

  /**
   * Delete what stopped being the newest at its path, the messages that arrived, and the bytes no
   * current record has named, more than `keepDays` ago. Returns how many it deleted.
   */
  prune(now = this.now()): Promise<number> {
    return this.storage.prune(now - this.keepDays * DAY)
  }

  /**
   * Stored records in the order taken, as canonical text, after a cursor, for one profile if
   * asked: at most maxPageRecords, and a page ends before a line that would take it past
   * maxPageBytes, though it always holds one.
   */
  read(options: ReadOptions = {}): { lines: string[]; cursor: number } {
    const after = options.after ?? 0
    // A profile that is no address has no folder: nothing to read, and no file to look for.
    if (options.profile !== undefined && !publicKeyFromAddress(options.profile)) return { lines: [], cursor: after }
    return this.page(this.storage.recordsAfter(after, options.profile), after)
  }

  private page(rows: Iterable<Row>, after: number): { lines: string[]; cursor: number } {
    const lines: string[] = []
    let cursor = after
    let size = 0
    for (const row of rows) {
      if (lines.length >= this.maxPageRecords) break
      size += row.bytes + 1
      if (size > this.maxPageBytes && lines.length) break
      lines.push(row.text)
      cursor = row.seq
    }
    return { lines, cursor }
  }

  /** Whether a line is larger than this host takes. Its length in UTF-16 units is never more than its bytes, so huge text is refused unencoded. */
  private tooBig(line: string): boolean {
    return line.length > this.maxLineBytes || utf8(line).length > this.maxLineBytes
  }

  /** This host's view of a profile, from what it stores. */
  view(profile: string, now = this.now()): View {
    return viewProfile(profile, this.stored(profile), now)
  }

  /** A profile's stored records. They were checked on the way in. */
  private stored(profile: string): Checked[] {
    return this.storage.records(profile).map((r) => ({ id: r.id, record: JSON.parse(r.text) as SignedRecord }))
  }

  count(profile?: string): number {
    return this.storage.count(profile)
  }

  /** Every stored record's and message's text: what a host operator can see on its own disk. */
  dump(): string[] {
    return this.storage.dump()
  }

  // ------------------------------------------------------------------------------------------
  // Messages

  /** Take a request's messages (wire text), check each in the standard's order, store what passes. */
  async deliver(lines: string[]): Promise<Result[]> {
    if (lines.length > this.maxBatch) return [{ i: 0, ok: false, error: 'batch', message: `at most ${this.maxBatch} messages a request` }]
    const now = this.now()
    const inboxes = new Map<string, Inbox | null | 'unsupported'>()
    const senders = new Map<string, View>()
    const results: Result[] = []
    for (const [i, line] of lines.entries()) results.push({ i, ...(await this.deliverOne(line, now, inboxes, senders)) })
    return results
  }

  private async deliverOne(line: string, now: number, inboxes: Map<string, Inbox | null | 'unsupported'>, senders: Map<string, View>): Promise<Answer> {
    if (this.tooBig(line)) return { ok: false, error: 'size', message: `this host takes messages of at most ${this.maxLineBytes} bytes` }
    let c: CheckedMessage
    try {
      c = readMessage(line)
    } catch (err) {
      return { ok: false, error: err instanceof RecordError ? err.code : 'invalid', message: (err as Error).message }
    }
    const { message: m, id } = c
    const refuse = (error: string, message: string): Answer => ({ id, ok: false, error, message })
    if (m.time > now + MAX_FUTURE_MS) return refuse('future', 'dated more than ten minutes ahead')
    if (this.storage.hasMessage(m.to, id)) return refuse('duplicate', 'this message is already here')
    let inbox = inboxes.get(m.to)
    if (inbox === undefined) inboxes.set(m.to, (inbox = inboxOf(this.view(m.to, now).current.get('profile')?.record.body)))
    if (inbox === null) return refuse('no_inbox', 'the profile record here declares no inbox')
    if (!verifyMessage(c)) return refuse('signature', 'the signature does not verify')
    // from's own records, read from the host the message names, once a check needs them.
    const readSenderView = async (): Promise<View | Answer> => {
      if (!this.readSender) return refuse('rule_unsupported', 'this host does not read senders’ records')
      const at = `${m.from} ${m.host}`
      let sender = senders.get(at)
      if (!sender) {
        try {
          senders.set(at, (sender = viewProfile(m.from, await this.readSender(m.host!, m.from), now)))
        } catch (err) {
          return refuse('lookup', `could not read the sender’s records, try again: ${(err as Error).message}`)
        }
      }
      if (!sender.hosts.includes(m.host!)) return refuse('permission', 'host is not one of the hosts from’s hosts record names')
      return sender
    }
    if (m.key !== undefined) {
      // A write key: from's own hosts and permissions records list it for the inbox.
      const sender = await readSenderView()
      if (!('access' in sender)) return sender
      if (!allowsInbox(sender.access, m.key, 'write')) return refuse('permission', 'from’s permissions record does not list key as a write key for the inbox')
    }
    // An inbox's rules are for others: a message whose sender is the recipient skips them.
    const rules = m.from === m.to ? undefined : inbox
    if (rules === 'unsupported') return refuse('rule_unsupported', 'this host does not know the inbox’s rule')
    if (rules && rules.senders !== 'anyone') {
      // An issuer's rule: from's card, read from the host the message names, carries a human proof
      // from that issuer that holds.
      if (!this.verifyHuman) return refuse('rule_unsupported', 'this host checks no human proof')
      if (m.host === undefined) return refuse('sender', 'a message to this inbox names host, one of from’s hosts, where its card is read')
      const sender = await readSenderView()
      if (!('access' in sender)) return sender
      const issuer = rules.senders.issuer
      const checks = proofsOf(sender.current.get('profile')?.record.body)
        .filter((p) => p.issuer === issuer)
        .map((p) => humanCheck(p, m.from))
        .filter((p): p is HumanCheck => p !== null)
      let held = false
      try {
        for (const check of checks) if ((held = await this.verifyHuman(check))) break
      } catch (err) {
        return refuse('lookup', `the human proof could not be checked, try again: ${(err as Error).message}`)
      }
      if (!held) return refuse('sender', 'from’s card carries no human proof from the inbox’s issuer that holds')
    }
    if (rules?.once && this.storage.hasOnce(m.to, m.from)) return refuse('once', 'this inbox takes one message from each sender')
    if (rules?.maxBytes !== undefined && utf8(line).length > rules.maxBytes) return refuse('too_big', `this inbox takes messages of at most ${rules.maxBytes} bytes`)
    if (this.messageChoice) {
      const refused = await this.messageChoice(m, this.storage.messageTotals(m.to))
      if (refused) return refuse('refused', refused)
    }
    // Checked again here, with no wait in between: another request may have taken the same id or
    // pair during a lookup or its own choice.
    if (rules?.once && !this.storage.addOnce(m.to, m.from)) return refuse('once', 'this inbox takes one message from each sender')
    if (!this.storage.addMessage(m.to, id, line, now)) return refuse('duplicate', 'this message is already here')
    return { id, ok: true }
  }

  /**
   * A pull (wire text): checked at this host's clock; one a read key signed also needs this host's
   * current permissions record for the profile to list it as a read key for the inbox
   * [permission]. Then a page of that profile's messages after the cursor, in arrival order, paged
   * as records are. Throws RecordError.
   */
  pull(text: string, now = this.now()): { lines: string[]; cursor: number } {
    const request = checkPull(text, now)
    if (request.key !== undefined && !allowsInbox(this.view(request.profile, now).access, request.key, 'read')) {
      throw new RecordError('permission', 'the profile’s permissions record here does not list key as a read key for the inbox')
    }
    return this.page(this.storage.messagesAfter(request.profile, request.after), request.after)
  }

  // ------------------------------------------------------------------------------------------
  // Blobs

  /**
   * A blob request off the wire, for the bytes at `name`: checked at this host's clock
   * (checkBlobRequest), then the action asked for and the bytes it names [shape]. One a write key
   * signed also needs this host's current permissions record for the profile to list it with scope
   * write, whatever its paths [permission]. Throws RecordError.
   */
  private checkBlob(text: string, action: 'put' | 'delete', name: string, now: number): SignedBlobRequest {
    if (utf8(text).length > MAX_BLOB_REQUEST_BYTES) throw new RecordError('size', `a blob request is at most ${MAX_BLOB_REQUEST_BYTES} bytes`)
    const request = checkBlobRequest(text, now)
    if (request.action !== action) throw new RecordError('shape', `this is a ${action} request`)
    if (request.sha256 !== name) throw new RecordError('shape', 'the request names other bytes')
    if (request.key !== undefined && !this.view(request.profile, now).access.some((k) => k.key === request.key && k.scope === 'write')) {
      throw new RecordError('permission', 'the profile’s permissions record here does not list key as a write key')
    }
    return request
  }

  /**
   * Put bytes in a folder: the signed put request (checkBlob) names them by their hash, type and
   * size [shape], and they hash to it [hash]. Bytes the folder holds already are `already here`.
   * Otherwise this host must take their size and type [refused]. Bytes another folder holds are
   * stored once.
   */
  async putBlob(name: string, type: string, request: string, bytes: Uint8Array): Promise<Answer> {
    const now = this.now()
    let put: SignedBlobRequest & { action: 'put' }
    try {
      put = this.checkBlob(request, 'put', name, now) as SignedBlobRequest & { action: 'put' }
    } catch (err) {
      if (!(err instanceof RecordError)) throw err
      return { ok: false, error: err.code, message: err.message }
    }
    if (put.mimeType !== type || put.size !== bytes.length) return { ok: false, error: 'shape', message: 'the bytes are not the type and size the request names' }
    if (hex.encode(sha256(bytes)) !== name) return { ok: false, error: 'hash', message: 'the bytes do not hash to their name' }
    const by = put.key ?? null
    const held = this.storage.blobOf(put.profile, name)
    // The main key takes over bytes a write key put, so only it deletes them from then on.
    if (held && (held.by === null || by !== null)) return { ok: true, message: 'already here' }
    if (!held) {
      const refused = bytes.length > this.maxBlobBytes ? `at most ${this.maxBlobBytes} bytes` : await this.blobChoice({ sha256: name, type, size: bytes.length, profile: put.profile }, this.storage.blobTotals(put.profile))
      if (refused) return { ok: false, error: 'refused', message: refused }
    }
    await this.storage.putBlob(put.profile, name, type, bytes.length, by, bytes, now)
    return { ok: true }
  }

  /**
   * Delete bytes from a folder: the signed delete request (checkBlob). Bytes the main key put go
   * only at its request [permission], as the owner's records do. Bytes the folder does not hold are
   * `not here`. Once no folder holds them, they leave the store.
   */
  async deleteBlob(name: string, request: string): Promise<Answer> {
    const now = this.now()
    let ask: SignedBlobRequest
    try {
      ask = this.checkBlob(request, 'delete', name, now)
    } catch (err) {
      if (!(err instanceof RecordError)) throw err
      return { ok: false, error: err.code, message: err.message }
    }
    const held = this.storage.blobOf(ask.profile, name)
    if (!held) return { ok: true, message: 'not here' }
    if (held.by === null && ask.key !== undefined) return { ok: false, error: 'permission', message: 'the main key put these bytes: only it deletes them' }
    await this.storage.deleteBlob(ask.profile, name)
    return { ok: true }
  }

  /** Held bytes and their type, or undefined. */
  getBlob(name: string): Promise<{ type: string; bytes: Uint8Array } | undefined> {
    return this.storage.getBlob(name)
  }

  // ------------------------------------------------------------------------------------------
  // HTTP

  /** Listen on loopback unless told otherwise, and prune every hour. Returns the url. */
  async listen(port = 0, hostname = '127.0.0.1'): Promise<string> {
    // Node looks for requests past the timeout every 30 seconds by default; every second keeps it near.
    this.server = createServer({ requestTimeout: this.timeout, connectionsCheckingInterval: 1000 }, (req, res) => {
      this.handle(req, res).catch(() => {
        if (!res.headersSent) res.writeHead(500).end()
      })
    })
    await new Promise<void>((resolve) => this.server!.listen(port, hostname, resolve))
    this.pruning = setInterval(() => void this.prune().catch(() => {}), DAY / 24).unref()
    this.url = `http://${hostname.includes(':') ? `[${hostname}]` : hostname}:${(this.server.address() as AddressInfo).port}`
    return this.url
  }

  async close(): Promise<void> {
    clearInterval(this.pruning)
    if (this.server) await new Promise<void>((resolve) => this.server!.close(() => resolve()))
    this.storage.close()
  }

  private async handle(req: IncomingMessage, res: ServerResponse) {
    res.setHeader('access-control-allow-origin', '*')
    // A target that is no path, such as //, is the asker's mistake.
    const url = URL.parse(req.url ?? '/', 'http://host.invalid')
    if (!url) {
      res.writeHead(400).end()
      return
    }
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { 'access-control-allow-methods': 'GET, POST, PUT, DELETE', 'access-control-allow-headers': 'content-type, forest-blob' }).end()
      return
    }
    const blob = BLOB_PATH.exec(url.pathname)?.[1]
    const methods = url.pathname === '/v1/records' ? ['GET', 'POST'] : ['/v1/records/read', '/v1/inbox', '/v1/inbox/pull'].includes(url.pathname) ? ['POST'] : blob ? ['GET', 'PUT', 'DELETE'] : []
    if (!methods.length) {
      res.writeHead(404).end()
      return
    }
    if (!methods.includes(req.method ?? '')) {
      res.writeHead(405, { allow: methods.join(', ') }).end()
      return
    }

    if (blob && req.method === 'GET') {
      const held = await this.getBlob(blob)
      if (!held) res.writeHead(404).end()
      else res.writeHead(200, { 'content-type': held.type, 'content-length': held.bytes.length }).end(held.bytes)
      return
    }
    if (blob) {
      const request = req.headers['forest-blob']
      if (typeof request !== 'string') {
        req.resume()
        return sendJson(res, 400, { ok: false, error: 'shape', message: 'a blob request is signed, in the header forest-blob' })
      }
      if (req.method === 'DELETE') {
        req.resume()
        const answer = await this.deleteBlob(blob, request)
        return sendJson(res, answer.ok ? 200 : 400, answer)
      }
      const tooBig = { ok: false, error: 'refused', message: `at most ${this.maxBlobBytes} bytes` }
      if (Number(req.headers['content-length'] ?? 0) > this.maxBlobBytes) return sendJson(res, 413, tooBig)
      const bytes = await readBody(req, this.maxBlobBytes)
      if (bytes === null) return sendJson(res, 413, tooBig)
      const answer = await this.putBlob(blob, (req.headers['content-type'] ?? '').trim(), request, bytes)
      return sendJson(res, answer.ok ? 200 : 400, answer)
    }

    if (url.pathname === '/v1/inbox/pull') {
      const body = await readBody(req, MAX_ASK_BYTES)
      if (body === null) return sendJson(res, 413, { ok: false, error: 'size', message: `a pull request is at most ${MAX_ASK_BYTES} bytes` })
      let out: { lines: string[]; cursor: number }
      try {
        out = this.pull(bodyText.decode(body))
      } catch (err) {
        if (!(err instanceof RecordError)) throw err
        return sendJson(res, 400, { ok: false, error: err.code, message: err.message })
      }
      return sendLines(res, out)
    }

    // A read, by GET with the profile and cursor in the URL, or by POST with them in the body, which
    // front doors do not log: the same answer.
    if (req.method === 'GET' || url.pathname === '/v1/records/read') {
      let asked: ReadOptions | undefined
      if (req.method === 'GET') {
        const after = url.searchParams.get('after')
        asked = { after: after === null ? 0 : Number(after), profile: url.searchParams.get('profile') ?? undefined }
      } else {
        const body = await readBody(req, MAX_ASK_BYTES)
        if (body === null) {
          res.writeHead(413).end()
          return
        }
        asked = readAsk(bodyText.decode(body))
      }
      if (!asked || !Number.isSafeInteger(asked.after) || asked.after! < 0) {
        res.writeHead(400).end()
        return
      }
      return sendLines(res, this.read(asked))
    }

    // POST /v1/records or /v1/inbox: NDJSON in, one NDJSON result a line out.
    const inbox = url.pathname === '/v1/inbox'
    const body = await readBody(req, this.maxBatch * (this.maxLineBytes + 1))
    if (body === null) {
      res.writeHead(413).end()
      return
    }
    const lines = bodyText.decode(body).split('\n').filter((l) => l.length > 0)
    const results = inbox ? await this.deliver(lines) : await this.accept(lines)
    res.writeHead(200, { 'content-type': 'application/x-ndjson' })
    res.end(results.map((r) => JSON.stringify(r) + '\n').join(''))
  }
}

/** A read request's body: `{ profile?, after? }` and nothing else, or undefined. */
function readAsk(text: string): ReadOptions | undefined {
  let value: unknown
  try {
    value = JSON.parse(text)
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

function sendLines(res: ServerResponse, out: { lines: string[]; cursor: number }) {
  res.writeHead(200, { 'content-type': 'application/x-ndjson', 'forest-cursor': String(out.cursor), 'access-control-expose-headers': 'forest-cursor' })
  res.end(out.lines.map((l) => l + '\n').join(''))
}

/** A body as text: bytes that are not UTF-8 become U+FFFD and a byte order mark stays, so a line that has one is refused. */
const bodyText = new TextDecoder('utf-8', { ignoreBOM: true })

async function readBody(req: IncomingMessage, max: number): Promise<Uint8Array | null> {
  const chunks: Uint8Array[] = []
  let size = 0
  for await (const chunk of req) {
    size += (chunk as Uint8Array).length
    if (size > max) return null
    chunks.push(chunk as Uint8Array)
  }
  // Copied here, not concat(...chunks): a slow client can send more pieces than a call takes arguments.
  const body = new Uint8Array(size)
  let at = 0
  for (const chunk of chunks) {
    body.set(chunk, at)
    at += chunk.length
  }
  return body
}
