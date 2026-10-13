// The reference host's storage, all of it in this one module: a SQLite file per folder, one shared
// SQLite file for what crosses folders, and a blob store with two drivers.
//
//   <dir>/folders/<address>.sqlite   one folder: its records (current, and replaced within keep
//                                    days), the messages to its inbox, and its once pairs
//   <dir>/host.sqlite                the log, numbering every record across folders in the order
//                                    taken, and the blob index: which folders' current records
//                                    name which bytes, and which bytes are held
//   <dir>/blobs/<sha256>             the bytes, with <sha256>.type beside them (the disk driver);
//                                    or <sha256> in an S3-compatible bucket, typed by content-type
//
// host.sqlite holds nothing that exists only there: rebuild(dir) makes it again from the folder
// files and the blob store. A folder is its file: with the host stopped, deleting the file removes
// the folder, and the host drops what host.sqlite says of it at its next prune.

import { createHash, createHmac, randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { readFile, readdir, rename, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync, type StatementSync } from 'node:sqlite'
import { base58, utf8 } from './bytes.ts'
import type { Body } from './record.ts'

/** Folder files kept open at once; the least recently used closes first, so many folders never run out of file handles. */
const OPEN_FOLDERS = 128
const HASH = /^[0-9a-f]{64}$/
/** Milliseconds an S3 request may take. */
const S3_TIMEOUT_MS = 60_000

export type Row = { seq: number; text: string; bytes: number }
export type BlobName = { sha256: string; type: string }
export type Blob = { type: string; bytes: Uint8Array }

/** Where blob bytes go: the one setting. */
export type BlobDriver = { kind: 'disk' } | ({ kind: 's3' } & S3Options)

export type S3Options = {
  /** The service's origin, such as `https://s3.example.com`. */
  endpoint: string
  bucket: string
  /**
   * The region SigV4 signs for. Many S3-compatible services take any value; `us-east-1` when
   * omitted, the one they expect when none is set.
   */
  region?: string
  accessKeyId: string
  secretAccessKey: string
  /** `path` (`<endpoint>/<bucket>/<key>`) when omitted, or `virtual` (`<bucket>.<endpoint host>/<key>`): services differ. */
  style?: 'path' | 'virtual'
}

/** Bytes by SHA-256, each with the type it came in as. */
export interface BlobStore {
  put(sha256: string, type: string, bytes: Uint8Array): Promise<void>
  get(sha256: string): Promise<Blob | undefined>
  delete(sha256: string): Promise<void>
  /** Every hash held, with its type. */
  list(): AsyncIterable<BlobName>
}

/** The bytes a record's body names: its photo, and each of its media. */
export function blobNames(body: Body | null): BlobName[] {
  if (!body) return []
  const refs = [body.photo, ...(Array.isArray(body.media) ? body.media : [])]
  const names: BlobName[] = []
  for (const ref of refs) {
    if (ref === null || typeof ref !== 'object' || Array.isArray(ref)) continue
    if (typeof ref.sha256 === 'string' && HASH.test(ref.sha256) && typeof ref.mimeType === 'string') names.push({ sha256: ref.sha256, type: ref.mimeType })
  }
  return names
}

// ------------------------------------------------------------------------------------------
// The two kinds of SQLite file

/** One SQLite file, its statements prepared once. */
class Db {
  readonly db: DatabaseSync
  private readonly statements = new Map<string, StatementSync>()
  constructor(file: string, options: { readOnly?: boolean } = {}) {
    this.db = new DatabaseSync(file, options)
  }
  q(sql: string): StatementSync {
    let statement = this.statements.get(sql)
    if (!statement) this.statements.set(sql, (statement = this.db.prepare(sql)))
    return statement
  }
  /** A statement of its own, for iterating while others run. */
  fresh(sql: string): StatementSync {
    return this.db.prepare(sql)
  }
  tx<T>(run: () => T): T {
    this.db.exec('BEGIN')
    try {
      const out = run()
      this.db.exec('COMMIT')
      return out
    } catch (err) {
      this.db.exec('ROLLBACK')
      throw err
    }
  }
  close() {
    this.statements.clear()
    this.db.close()
  }
}

// A folder file keeps SQLite's default rollback journal, not WAL: no -wal file is left beside it
// that could come back into a new file after the folder is deleted.
const FOLDER_SCHEMA = `
  CREATE TABLE records (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,   -- the log's number; AUTOINCREMENT keeps the highest it ever took
    id TEXT NOT NULL UNIQUE,
    text TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    arrived INTEGER NOT NULL,   -- this host's clock
    older_since INTEGER         -- this host's clock when it stopped being the newest at its path
  );
  CREATE TABLE messages (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    text TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    arrived INTEGER NOT NULL   -- this host's clock
  );
  -- Who has written to this inbox while it takes one message from each sender. Recorded only while
  -- the inbox says so, so who wrote to whom is not kept past the messages for other inboxes. Kept
  -- for as long as the folder is: this host never deletes a current record.
  CREATE TABLE once (sender TEXT PRIMARY KEY) WITHOUT ROWID;
  PRAGMA user_version = 1;
`

const HOST_SCHEMA = `
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    folder TEXT NOT NULL,
    id TEXT NOT NULL,
    arrived INTEGER NOT NULL   -- this host's clock
  );
  CREATE INDEX IF NOT EXISTS log_by_folder ON log (folder);
  CREATE TABLE IF NOT EXISTS names (   -- the bytes each folder's current records name, by hash and type
    sha256 TEXT NOT NULL,
    type TEXT NOT NULL,
    folder TEXT NOT NULL,
    PRIMARY KEY (sha256, type, folder)
  ) WITHOUT ROWID;
  CREATE INDEX IF NOT EXISTS names_by_folder ON names (folder);
  CREATE TABLE IF NOT EXISTS blobs (   -- the bytes held; the store keeps them and their type
    sha256 TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    unnamed_since INTEGER   -- this host's clock when no current record named it any more
  ) WITHOUT ROWID;
`

/**
 * A folder's file is opened only for an address with one spelling: base58 of 32 bytes that
 * encodes back to the same text. So a file name is never a string from a request. The host
 * checks each address fully (publicKeyFromAddress) before it gets here; this is the last guard.
 */
function folderFile(dir: string, address: string): string {
  let ok = false
  try {
    const key = base58.decode(address)
    ok = key.length === 32 && base58.encode(key) === address
  } catch {
    // Not base58.
  }
  if (!ok) throw new Error(`not an address: ${JSON.stringify(address)}`)
  return join(dir, 'folders', `${address}.sqlite`)
}

/**
 * A new number in `table`: the larger of the last it gave plus 1, and the clock in microseconds.
 * So a rebuilt host.sqlite, or a folder's file made again, never gives a number a reader or an
 * inbox's cursor may already hold, unless the clock is set back, or numbers ran ahead of it by the
 * host taking more than one a microsecond.
 */
function nextNumber(db: Db, table: string, now: number): number {
  const last = (db.q('SELECT seq FROM sqlite_sequence WHERE name = ?').get(table) as { seq: number } | undefined)?.seq ?? 0
  return Math.max(last + 1, now * 1000)
}

function openFolder(file: string): Db {
  const folder = new Db(file)
  if ((folder.db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version === 0) folder.db.exec(FOLDER_SCHEMA)
  return folder
}

/** The addresses with a folder file in `dir`. */
function foldersIn(dir: string): string[] {
  const at = join(dir, 'folders')
  if (!existsSync(at)) return []
  return readdirSync(at)
    .filter((f) => f.endsWith('.sqlite'))
    .map((f) => f.slice(0, -'.sqlite'.length))
}

// ------------------------------------------------------------------------------------------
// Storage

export class Storage {
  readonly dir: string
  private readonly host: Db
  private readonly blobs: BlobStore
  private readonly temporary: boolean
  /** Open folder files, least recently used first. */
  private readonly open = new Map<string, Db>()
  /** One blob operation at a time per hash, so a prune never deletes bytes a put is adding. */
  private readonly blobQueue = new Map<string, Promise<unknown>>()

  /** `dir` omitted: a fresh temporary directory, removed on close. */
  constructor(dir: string | undefined, driver: BlobDriver = { kind: 'disk' }) {
    this.temporary = dir === undefined
    this.dir = dir ?? mkdtempSync(join(tmpdir(), 'forest-host-'))
    try {
      const file = join(this.dir, 'host.sqlite')
      // Without host.sqlite, new records would take numbers the folders already hold.
      if (!existsSync(file) && foldersIn(this.dir).length) throw new Error(`${file} is missing: rebuild(dir) makes it again from the folder files`)
      mkdirSync(join(this.dir, 'folders'), { recursive: true })
      this.host = new Db(file)
      this.host.db.exec(HOST_SCHEMA)
      this.blobs = blobStore(this.dir, driver)
    } catch (err) {
      if (this.temporary) rmSync(this.dir, { recursive: true, force: true })
      throw err
    }
  }

  /** A folder's file: opened if it exists, made if `make`, else undefined. */
  private folder(address: string, make = false): Db | undefined {
    const held = this.open.get(address)
    if (held) {
      this.open.delete(address)
      this.open.set(address, held)
      return held
    }
    const file = folderFile(this.dir, address)
    if (!make && !existsSync(file)) return undefined
    const folder = openFolder(file)
    this.open.set(address, folder)
    for (const [old, db] of this.open) {
      if (this.open.size <= OPEN_FOLDERS) break
      db.close()
      this.open.delete(old)
    }
    return folder
  }

  /** The addresses with a folder file. */
  folders(): string[] {
    return foldersIn(this.dir)
  }

  close() {
    for (const db of this.open.values()) db.close()
    this.open.clear()
    this.host.close()
    if (this.temporary) rmSync(this.dir, { recursive: true, force: true })
  }

  // ----------------------------------------------------------------------------------------
  // Records

  hasRecord(folder: string, id: string): boolean {
    return this.folder(folder)?.q('SELECT 1 FROM records WHERE id = ?').get(id) !== undefined
  }

  /** A folder's records in the order taken. */
  records(folder: string): Array<{ id: string; text: string }> {
    return (this.folder(folder)?.q('SELECT id, text FROM records ORDER BY seq').all() ?? []) as Array<{ id: string; text: string }>
  }

  recordTotals(folder: string): { records: number; bytes: number } {
    return (this.folder(folder)?.q('SELECT COUNT(*) AS records, COALESCE(SUM(bytes), 0) AS bytes FROM records').get() ?? { records: 0, bytes: 0 }) as { records: number; bytes: number }
  }

  /**
   * Store a record, then mark which of the folder's records are current: those in `current`.
   * What stopped being current gets a date, and goes keep days later. The log takes it first, under
   * a number from the clock, so a crash in between leaves a number that points to nothing, which
   * reads skip; never a record the log does not list.
   */
  addRecord(address: string, id: string, text: string, now: number, current: Set<string>) {
    const seq = nextNumber(this.host, 'log', now)
    this.host.q('INSERT INTO log (seq, folder, id, arrived) VALUES (?, ?, ?, ?)').run(seq, address, id, now)
    const folder = this.folder(address, true)!
    folder.tx(() => {
      folder.q('INSERT INTO records (seq, id, text, bytes, arrived) VALUES (?, ?, ?, ?, ?)').run(seq, id, text, utf8(text).length, now)
      for (const row of folder.q('SELECT id, older_since FROM records').all() as Array<{ id: string; older_since: number | null }>) {
        if (current.has(row.id) && row.older_since !== null) folder.q('UPDATE records SET older_since = NULL WHERE id = ?').run(row.id)
        else if (!current.has(row.id) && row.older_since === null) folder.q('UPDATE records SET older_since = ? WHERE id = ?').run(now, row.id)
      }
    })
  }

  /**
   * Records after a cursor, in the order taken: one folder's, from its file; or every folder's,
   * by the log, skipping a number whose folder or record is gone.
   */
  *recordsAfter(after: number, folder?: string): Generator<Row> {
    if (folder !== undefined) {
      const db = this.folder(folder)
      if (db) yield* db.fresh('SELECT seq, text, bytes FROM records WHERE seq > ? ORDER BY seq').iterate(after) as Iterable<Row>
      return
    }
    for (const entry of this.host.fresh('SELECT seq, folder FROM log WHERE seq > ? ORDER BY seq').iterate(after) as Iterable<{ seq: number; folder: string }>) {
      const row = this.folder(entry.folder)?.q('SELECT text, bytes FROM records WHERE seq = ?').get(entry.seq) as { text: string; bytes: number } | undefined
      if (row) yield { seq: entry.seq, ...row }
    }
  }

  count(folder?: string): number {
    const one = (address: string) => (this.folder(address)?.q('SELECT COUNT(*) AS n FROM records').get() as { n: number } | undefined)?.n ?? 0
    return folder === undefined ? this.folders().reduce((n, address) => n + one(address), 0) : one(folder)
  }

  /** Every stored record's and message's text. */
  dump(): string[] {
    return this.folders().flatMap((address) => (this.folder(address)!.q('SELECT text FROM records UNION ALL SELECT text FROM messages').all() as Array<{ text: string }>).map((r) => r.text))
  }

  // ----------------------------------------------------------------------------------------
  // Messages

  hasMessage(folder: string, id: string): boolean {
    return this.folder(folder)?.q('SELECT 1 FROM messages WHERE id = ?').get(id) !== undefined
  }

  messageTotals(folder: string): { messages: number; bytes: number } {
    return (this.folder(folder)?.q('SELECT COUNT(*) AS messages, COALESCE(SUM(bytes), 0) AS bytes FROM messages').get() ?? { messages: 0, bytes: 0 }) as { messages: number; bytes: number }
  }

  /** False when that id is here already. Its number comes from the clock, as a record's does. */
  addMessage(folder: string, id: string, text: string, now: number): boolean {
    const db = this.folder(folder, true)!
    return db.q('INSERT OR IGNORE INTO messages (seq, id, text, bytes, arrived) VALUES (?, ?, ?, ?, ?)').run(nextNumber(db, 'messages', now), id, text, utf8(text).length, now).changes > 0
  }

  /** A folder's messages after a cursor, in arrival order. */
  *messagesAfter(folder: string, after: number): Generator<Row> {
    const db = this.folder(folder)
    if (db) yield* db.fresh('SELECT seq, text, bytes FROM messages WHERE seq > ? ORDER BY seq').iterate(after) as Iterable<Row>
  }

  hasOnce(folder: string, sender: string): boolean {
    return this.folder(folder)?.q('SELECT 1 FROM once WHERE sender = ?').get(sender) !== undefined
  }

  /** False when that sender is here already. */
  addOnce(folder: string, sender: string): boolean {
    return this.folder(folder, true)!.q('INSERT OR IGNORE INTO once (sender) VALUES (?)').run(sender).changes > 0
  }

  // ----------------------------------------------------------------------------------------
  // Blobs

  /**
   * Say which bytes a folder's current records name. Bytes no folder names any more get a date,
   * and go keep days later; bytes named again lose it.
   */
  setNames(folder: string, names: BlobName[], now: number) {
    const key = (n: BlobName) => `${n.sha256} ${n.type}`
    const want = new Map(names.map((n) => [key(n), n]))
    const had = new Map((this.host.q('SELECT sha256, type FROM names WHERE folder = ?').all(folder) as BlobName[]).map((n) => [key(n), n]))
    const gone = [...had].filter(([k]) => !want.has(k)).map(([, n]) => n)
    const added = [...want].filter(([k]) => !had.has(k)).map(([, n]) => n)
    if (!gone.length && !added.length) return
    this.host.tx(() => {
      for (const n of gone) this.host.q('DELETE FROM names WHERE sha256 = ? AND type = ? AND folder = ?').run(n.sha256, n.type, folder)
      for (const n of added) this.host.q('INSERT INTO names (sha256, type, folder) VALUES (?, ?, ?)').run(n.sha256, n.type, folder)
      for (const sha256 of new Set([...gone, ...added].map((n) => n.sha256))) {
        this.host.q('UPDATE blobs SET unnamed_since = CASE WHEN EXISTS (SELECT 1 FROM names n WHERE n.sha256 = blobs.sha256 AND n.type = blobs.type) THEN NULL ELSE COALESCE(unnamed_since, ?) END WHERE sha256 = ?').run(now, sha256)
      }
    })
  }

  /** The folders, each still with its file, whose current records name these bytes as this type, in order. */
  namedBy(sha256: string, type: string): string[] {
    const folders = this.host.q('SELECT folder FROM names WHERE sha256 = ? AND type = ? ORDER BY folder').all(sha256, type) as Array<{ folder: string }>
    return folders.map((f) => f.folder).filter((f) => this.folder(f) !== undefined)
  }

  holdsBlob(sha256: string): boolean {
    return this.host.q('SELECT 1 FROM blobs WHERE sha256 = ?').get(sha256) !== undefined
  }

  async putBlob(sha256: string, type: string, bytes: Uint8Array, now: number): Promise<void> {
    await this.oneAtATime(sha256, async () => {
      await this.blobs.put(sha256, type, bytes)
      this.host.q('INSERT OR IGNORE INTO blobs (sha256, type, unnamed_since) VALUES (?, ?, CASE WHEN EXISTS (SELECT 1 FROM names WHERE sha256 = ? AND type = ?) THEN NULL ELSE ? END)').run(sha256, type, sha256, type, now)
    })
  }

  getBlob(sha256: string): Promise<Blob | undefined> {
    return this.blobs.get(sha256)
  }

  private oneAtATime<T>(sha256: string, run: () => Promise<T>): Promise<T> {
    const out = (this.blobQueue.get(sha256) ?? Promise.resolve()).then(run, run)
    const settled = out.then(
      () => undefined,
      () => undefined,
    )
    this.blobQueue.set(sha256, settled)
    void settled.then(() => {
      if (this.blobQueue.get(sha256) === settled) this.blobQueue.delete(sha256)
    })
    return out
  }

  // ----------------------------------------------------------------------------------------
  // Keeping

  /**
   * Delete what stopped being current, the messages that arrived, and the bytes no current record
   * has named, at or before `before`; and what host.sqlite says of folders whose file is gone.
   * Returns how many records, messages and blobs it deleted.
   */
  async prune(before: number, now: number): Promise<number> {
    let deleted = 0
    const onDisk = new Set(this.folders())
    for (const address of onDisk) {
      const folder = this.folder(address)!
      const old = folder.q('SELECT seq FROM records WHERE older_since IS NOT NULL AND older_since <= ?').all(before) as Array<{ seq: number }>
      // The log first: a crash in between leaves old records the next prune deletes, never a
      // number that points to nothing.
      if (old.length) this.host.tx(() => old.forEach((r) => this.host.q('DELETE FROM log WHERE seq = ?').run(r.seq)))
      deleted += Number(folder.q('DELETE FROM records WHERE older_since IS NOT NULL AND older_since <= ?').run(before).changes)
      deleted += Number(folder.q('DELETE FROM messages WHERE arrived <= ?').run(before).changes)
    }
    const listed = this.host.q('SELECT folder FROM log UNION SELECT folder FROM names').all() as Array<{ folder: string }>
    for (const { folder } of listed.filter((f) => !onDisk.has(f.folder))) {
      this.host.q('DELETE FROM log WHERE folder = ?').run(folder)
      this.setNames(folder, [], now)
    }
    for (const { sha256 } of this.host.q('SELECT sha256 FROM blobs WHERE unnamed_since IS NOT NULL AND unnamed_since <= ?').all(before) as Array<{ sha256: string }>) {
      await this.oneAtATime(sha256, async () => {
        // Named again while waiting its turn: kept.
        if (this.host.q('SELECT 1 FROM blobs WHERE sha256 = ? AND unnamed_since IS NOT NULL AND unnamed_since <= ?').get(sha256, before) === undefined) return
        await this.blobs.delete(sha256)
        this.host.q('DELETE FROM blobs WHERE sha256 = ?').run(sha256)
        deleted++
      })
    }
    return deleted
  }
}

// ------------------------------------------------------------------------------------------
// Rebuild and import

/**
 * Make host.sqlite again from what is outside it: the log from each folder's records and their
 * numbers, the names from its current records, the blobs from the store. Bytes no current record
 * names are dated `now`, which only keeps them longer. The log goes on from the highest number any
 * folder file ever took, and a new number is never below the clock (nextNumber), so one held only
 * by a folder whose file was deleted is not given again.
 */
export async function rebuild(dir: string, driver: BlobDriver = { kind: 'disk' }, now = Date.now()): Promise<void> {
  for (const suffix of ['', '-wal', '-shm']) rmSync(join(dir, `host.sqlite${suffix}`), { force: true })
  const host = new Db(join(dir, 'host.sqlite'))
  try {
    host.db.exec(HOST_SCHEMA)
    let top = 0
    host.tx(() => {
      for (const address of foldersIn(dir)) {
        const folder = openFolder(folderFile(dir, address))
        try {
          for (const r of folder.q('SELECT seq, id, text, arrived, older_since FROM records ORDER BY seq').all() as Array<{ seq: number; id: string; text: string; arrived: number; older_since: number | null }>) {
            host.q('INSERT INTO log (seq, folder, id, arrived) VALUES (?, ?, ?, ?)').run(r.seq, address, r.id, r.arrived)
            if (r.older_since !== null) continue
            for (const n of blobNames((JSON.parse(r.text) as { body: Body | null }).body)) host.q('INSERT OR IGNORE INTO names (sha256, type, folder) VALUES (?, ?, ?)').run(n.sha256, n.type, address)
          }
          const taken = folder.q("SELECT seq FROM sqlite_sequence WHERE name = 'records'").get() as { seq: number } | undefined
          top = Math.max(top, taken?.seq ?? 0)
        } finally {
          folder.close()
        }
      }
      host.q("DELETE FROM sqlite_sequence WHERE name = 'log'").run()
      host.q("INSERT INTO sqlite_sequence (name, seq) VALUES ('log', ?)").run(top)
    })
    const named = host.q('SELECT 1 FROM names WHERE sha256 = ? AND type = ?')
    for await (const blob of blobStore(dir, driver).list()) {
      host.q('INSERT OR IGNORE INTO blobs (sha256, type, unnamed_since) VALUES (?, ?, ?)').run(blob.sha256, blob.type, named.get(blob.sha256, blob.type) ? null : now)
    }
  } finally {
    host.close()
  }
}

/** For the one-time import from a single-file host: a folder's file, made if missing, to write rows into directly. */
export function folderForImport(dir: string, address: string): DatabaseSync {
  mkdirSync(join(dir, 'folders'), { recursive: true })
  return openFolder(folderFile(dir, address)).db
}

export function blobStore(dir: string, driver: BlobDriver): BlobStore {
  return driver.kind === 's3' ? s3Blobs(driver) : diskBlobs(join(dir, 'blobs'))
}

// ------------------------------------------------------------------------------------------
// Disk: <dir>/<sha256> holds the bytes, <dir>/<sha256>.type their type. Each is written to a
// temporary name, then renamed, so a reader never sees half a file.

function diskBlobs(dir: string): BlobStore {
  mkdirSync(dir, { recursive: true })
  const at = (sha256: string) => {
    if (!HASH.test(sha256)) throw new Error('not a SHA-256')
    return join(dir, sha256)
  }
  const write = async (file: string, data: Uint8Array | string) => {
    const temporary = `${file}.${randomBytes(6).toString('hex')}.tmp`
    await writeFile(temporary, data)
    await rename(temporary, file)
  }
  const missing = (err: unknown) => (err as NodeJS.ErrnoException).code === 'ENOENT'
  return {
    async put(sha256, type, bytes) {
      await write(`${at(sha256)}.type`, type)
      await write(at(sha256), bytes)
    },
    async get(sha256) {
      try {
        const bytes = new Uint8Array(await readFile(at(sha256)))
        return { type: await readFile(`${at(sha256)}.type`, 'utf8'), bytes }
      } catch (err) {
        if (missing(err)) return undefined
        throw err
      }
    },
    async delete(sha256) {
      await rm(at(sha256), { force: true })
      await rm(`${at(sha256)}.type`, { force: true })
    },
    async *list() {
      for (const name of await readdir(dir)) {
        if (!HASH.test(name)) continue
        try {
          yield { sha256: name, type: await readFile(`${at(name)}.type`, 'utf8') }
        } catch (err) {
          if (!missing(err)) throw err
        }
      }
    },
  }
}

// ------------------------------------------------------------------------------------------
// S3: any S3-compatible service, each request signed with AWS Signature Version 4 by hand.

/** Where an object, or the bucket itself when `key` is empty, lives. */
export function s3Url(options: Pick<S3Options, 'endpoint' | 'bucket' | 'style'>, key: string): URL {
  const endpoint = new URL(options.endpoint)
  if (options.style === 'virtual') return new URL(`${endpoint.protocol}//${options.bucket}.${endpoint.host}/${key}`)
  return new URL(`${endpoint.origin}/${options.bucket}/${key}`)
}

const sha256Hex = (data: Uint8Array | string) => createHash('sha256').update(data).digest('hex')
const hmac = (key: Uint8Array | string, data: string) => createHmac('sha256', key).update(data).digest()
/** RFC 3986's unreserved characters stay; everything else is percent-encoded, as SigV4 asks. */
const uriEncode = (text: string) => encodeURIComponent(text).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)

/**
 * The headers that sign a request: SigV4 over `host`, every header given, and the payload's
 * SHA-256. `amzDate` is `YYYYMMDDTHHMMSSZ`.
 */
export function signS3(request: { method: string; url: URL; headers: Record<string, string>; payloadHash: string; amzDate: string }, credentials: Pick<S3Options, 'accessKeyId' | 'secretAccessKey' | 'region'>): Record<string, string> {
  const region = credentials.region ?? 'us-east-1'
  const headers: Record<string, string> = { ...request.headers, host: request.url.host, 'x-amz-content-sha256': request.payloadHash, 'x-amz-date': request.amzDate }
  const names = Object.keys(headers).map((n) => n.toLowerCase()).sort()
  const lower = Object.fromEntries(Object.entries(headers).map(([n, v]) => [n.toLowerCase(), v.trim().replace(/\s+/g, ' ')]))
  const path = request.url.pathname.split('/').map((segment) => uriEncode(decodeURIComponent(segment))).join('/')
  const query = [...request.url.searchParams].map(([k, v]) => [uriEncode(k), uriEncode(v)]).sort(([a], [b]) => (a! < b! ? -1 : a! > b! ? 1 : 0)).map(([k, v]) => `${k}=${v}`).join('&')
  const canonical = [request.method, path, query, ...names.map((n) => `${n}:${lower[n]}`), '', names.join(';'), request.payloadHash].join('\n')
  const day = request.amzDate.slice(0, 8)
  const scope = `${day}/${region}/s3/aws4_request`
  const toSign = ['AWS4-HMAC-SHA256', request.amzDate, scope, sha256Hex(canonical)].join('\n')
  const key = hmac(hmac(hmac(hmac(`AWS4${credentials.secretAccessKey}`, day), region), 's3'), 'aws4_request')
  const signature = createHmac('sha256', key).update(toSign).digest('hex')
  return { ...headers, authorization: `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${scope}, SignedHeaders=${names.join(';')}, Signature=${signature}` }
}

function s3Blobs(options: S3Options): BlobStore {
  const send = async (method: string, url: URL, body?: Uint8Array, headers: Record<string, string> = {}) => {
    const amzDate = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '')
    const signed = signS3({ method, url, headers, payloadHash: sha256Hex(body ?? new Uint8Array()), amzDate }, options)
    delete signed.host
    return fetch(url, { method, headers: signed, ...(body && { body: new Uint8Array(body) }), signal: AbortSignal.timeout(S3_TIMEOUT_MS) })
  }
  const object = (sha256: string) => {
    if (!HASH.test(sha256)) throw new Error('not a SHA-256')
    return s3Url(options, sha256)
  }
  const fail = async (what: string, res: Response): Promise<never> => {
    throw new Error(`S3 ${what}: ${res.status} ${(await res.text()).slice(0, 200)}`)
  }
  const typeOf = async (sha256: string) => {
    const res = await send('HEAD', object(sha256))
    if (res.status === 404) return undefined
    if (!res.ok) return fail('HEAD', res)
    return res.headers.get('content-type') ?? 'application/octet-stream'
  }
  return {
    async put(sha256, type, bytes) {
      const res = await send('PUT', object(sha256), bytes, { 'content-type': type })
      if (!res.ok) await fail('PUT', res)
    },
    async get(sha256) {
      const res = await send('GET', object(sha256))
      if (res.status === 404) return undefined
      if (!res.ok) return fail('GET', res)
      return { type: res.headers.get('content-type') ?? 'application/octet-stream', bytes: new Uint8Array(await res.arrayBuffer()) }
    },
    async delete(sha256) {
      const res = await send('DELETE', object(sha256))
      if (!res.ok && res.status !== 404) await fail('DELETE', res)
    },
    async *list() {
      for (let token: string | undefined; ; ) {
        const url = s3Url(options, '')
        url.searchParams.set('list-type', '2')
        if (token !== undefined) url.searchParams.set('continuation-token', token)
        const res = await send('GET', url)
        if (!res.ok) await fail('list', res)
        const xml = await res.text()
        for (const [, key] of xml.matchAll(/<Key>([^<]*)<\/Key>/g)) {
          if (!HASH.test(key!)) continue
          const type = await typeOf(key!)
          if (type !== undefined) yield { sha256: key!, type }
        }
        const next = /<NextContinuationToken>([^<]*)<\/NextContinuationToken>/.exec(xml)?.[1]
        if (!/<IsTruncated>true<\/IsTruncated>/.test(xml) || next === undefined) return
        token = next.replace(/&(amp|lt|gt|quot|apos);/g, (_, e: string) => ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" })[e]!)
      }
    },
  }
}
