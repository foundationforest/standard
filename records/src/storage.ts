// The reference host's storage, all of it in this one module: a SQLite file per folder, one shared
// SQLite file for what crosses folders, and a blob store with two drivers.
//
//   <dir>/folders/<address>.sqlite   one folder: its records (current, and replaced within keep
//                                    days), the messages to its inbox, and the blobs it holds
//   <dir>/host.sqlite                the log, numbering every record across folders in the order
//                                    taken, and the blob index: which folders hold which bytes,
//                                    and which bytes are stored
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

/** Folder files kept open at once; the least recently used closes first, so many folders never run out of file handles. */
const OPEN_FOLDERS = 128
const HASH = /^[0-9a-f]{64}$/
/** Milliseconds an S3 request may take. */
const S3_TIMEOUT_MS = 60_000

export type Row = { seq: number; text: string; bytes: number }
export type Stored = { sha256: string; type: string }
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
  list(): AsyncIterable<Stored>
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

/**
 * The version of the layout FOLDER_SCHEMA makes. A change to that layout raises it, and adds to
 * STEPS what turns a file of the version before into this one.
 */
const VERSION = 3

/**
 * What turns a folder file of each older version into the next. Version 1's blobs said who put
 * each one, the main key or a write key; only the main key puts a folder's blobs now, so a blob a
 * write key put is the folder's like any other. Version 2 kept who had written to an inbox that took
 * one message from each sender; no inbox says that now, so the table goes.
 */
const STEPS: Record<number, string> = {
  1: 'ALTER TABLE blobs DROP COLUMN by',
  2: 'DROP TABLE once',
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
  -- The bytes this folder holds, by hash: put by its main key, and kept until it deletes them.
  CREATE TABLE blobs (
    sha256 TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    size INTEGER NOT NULL,
    arrived INTEGER NOT NULL   -- this host's clock
  ) WITHOUT ROWID;
  PRAGMA user_version = ${VERSION};
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
  CREATE TABLE IF NOT EXISTS owners (   -- which folders hold which bytes, as their files say
    sha256 TEXT NOT NULL,
    folder TEXT NOT NULL,
    PRIMARY KEY (sha256, folder)
  ) WITHOUT ROWID;
  CREATE INDEX IF NOT EXISTS owners_by_folder ON owners (folder);
  CREATE TABLE IF NOT EXISTS blobs (   -- the bytes stored; the store keeps them and their type
    sha256 TEXT PRIMARY KEY,
    type TEXT NOT NULL
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

const versionOf = (db: DatabaseSync) => (db.prepare('PRAGMA user_version').get() as { user_version: number }).user_version

/**
 * A SQLite file's layout: its version, each table's columns and each index's name. Not the text
 * that made them, so a comment changed in FOLDER_SCHEMA changes no layout.
 */
function layoutOf(db: DatabaseSync): string {
  const columns = db.prepare(`SELECT m.name AS tbl, p.name, p.type, p."notnull", p.pk FROM sqlite_master m JOIN pragma_table_info(m.name) p WHERE m.type = 'table' ORDER BY m.name, p.cid`).all()
  const indexes = db.prepare(`SELECT name, tbl_name FROM sqlite_master WHERE type = 'index' ORDER BY name`).all()
  return JSON.stringify({ user_version: versionOf(db), columns, indexes })
}

/** The layout of a new file, and of a folder file as FOLDER_SCHEMA makes it. */
const [NEW_LAYOUT, FOLDER_LAYOUT] = ['', FOLDER_SCHEMA].map((schema) => {
  const db = new DatabaseSync(':memory:')
  try {
    db.exec(schema)
    return layoutOf(db)
  } finally {
    db.close()
  }
})

/**
 * A folder's file, its tables made the first time it opens. A file of an older version is migrated
 * in one transaction, by each step from its version to this one. A file with no step for its
 * version, a step that fails, or a result in any layout but this host's is refused and left as it
 * was, so a file from a newer host is never changed.
 */
function openFolder(file: string): Db {
  const folder = new Db(file)
  try {
    const layout = layoutOf(folder.db)
    if (layout === NEW_LAYOUT) folder.db.exec(FOLDER_SCHEMA)
    else if (layout !== FOLDER_LAYOUT) {
      const refused = (cause?: unknown) => new Error(`${file} is not a folder file in this host's layout`, { cause })
      folder.tx(() => {
        for (let version = versionOf(folder.db); version < VERSION; version++) {
          const step = STEPS[version]
          if (step === undefined) throw refused()
          try {
            folder.db.exec(`${step}; PRAGMA user_version = ${version + 1}`)
          } catch (cause) {
            throw refused(cause)
          }
        }
        if (layoutOf(folder.db) !== FOLDER_LAYOUT) throw refused()
      })
    }
    return folder
  } catch (err) {
    folder.close()
    throw err
  }
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
  /** One blob operation at a time per hash, so a delete or a prune never deletes bytes a put is adding. */
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

  // ----------------------------------------------------------------------------------------
  // Blobs

  /** Whether a folder holds these bytes. */
  holdsBlob(folder: string, sha256: string): boolean {
    return this.folder(folder)?.q('SELECT 1 FROM blobs WHERE sha256 = ?').get(sha256) !== undefined
  }

  blobTotals(folder: string): { blobs: number; bytes: number } {
    return (this.folder(folder)?.q('SELECT COUNT(*) AS blobs, COALESCE(SUM(size), 0) AS bytes FROM blobs').get() ?? { blobs: 0, bytes: 0 }) as { blobs: number; bytes: number }
  }

  /**
   * Put bytes in a folder. The bytes are stored once, whichever folders hold them. host.sqlite's
   * index first: a crash in between keeps bytes until the next prune puts the index right, and
   * never deletes bytes a folder holds.
   */
  putBlob(folder: string, sha256: string, type: string, size: number, bytes: Uint8Array, now: number): Promise<void> {
    return this.oneAtATime(sha256, async () => {
      if (this.host.q('SELECT 1 FROM blobs WHERE sha256 = ?').get(sha256) === undefined) {
        await this.blobs.put(sha256, type, bytes)
        this.host.q('INSERT OR IGNORE INTO blobs (sha256, type) VALUES (?, ?)').run(sha256, type)
      }
      this.host.q('INSERT OR IGNORE INTO owners (sha256, folder) VALUES (?, ?)').run(sha256, folder)
      this.folder(folder, true)!.q('INSERT OR IGNORE INTO blobs (sha256, type, size, arrived) VALUES (?, ?, ?, ?)').run(sha256, type, size, now)
    })
  }

  /**
   * Delete bytes from a folder; once no folder holds them, from the store. The folder's file first,
   * then the index, then the store: a crash in between leaves bytes the next prune deletes.
   */
  deleteBlob(folder: string, sha256: string): Promise<'deleted' | 'not here'> {
    return this.oneAtATime(sha256, async () => {
      if (!this.holdsBlob(folder, sha256)) return 'not here'
      this.folder(folder)!.q('DELETE FROM blobs WHERE sha256 = ?').run(sha256)
      this.host.q('DELETE FROM owners WHERE sha256 = ? AND folder = ?').run(sha256, folder)
      if (this.host.q('SELECT 1 FROM owners WHERE sha256 = ?').get(sha256) !== undefined) return 'deleted'
      this.host.q('DELETE FROM blobs WHERE sha256 = ?').run(sha256)
      await this.blobs.delete(sha256)
      return 'deleted'
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
   * Delete what stopped being current and the messages that arrived, at or before `before`; what
   * host.sqlite says of folders whose file is gone; and the bytes no folder holds any more. Returns
   * how many records, messages and blobs it deleted.
   */
  async prune(before: number): Promise<number> {
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
      // The index follows the folder's file, which is the truth of what it holds.
      const holds = folder.q('SELECT sha256 FROM blobs').all() as Array<{ sha256: string }>
      this.host.tx(() => {
        this.host.q('DELETE FROM owners WHERE folder = ?').run(address)
        for (const { sha256 } of holds) this.host.q('INSERT INTO owners (sha256, folder) VALUES (?, ?)').run(sha256, address)
      })
    }
    const listed = this.host.q('SELECT folder FROM log UNION SELECT folder FROM owners').all() as Array<{ folder: string }>
    for (const { folder } of listed.filter((f) => !onDisk.has(f.folder))) {
      this.host.tx(() => {
        this.host.q('DELETE FROM log WHERE folder = ?').run(folder)
        this.host.q('DELETE FROM owners WHERE folder = ?').run(folder)
      })
    }
    const unheld = 'SELECT sha256 FROM blobs WHERE NOT EXISTS (SELECT 1 FROM owners o WHERE o.sha256 = blobs.sha256)'
    for (const { sha256 } of this.host.q(unheld).all() as Array<{ sha256: string }>) {
      await this.oneAtATime(sha256, async () => {
        // Put again while waiting its turn: kept.
        if (this.host.q('SELECT 1 FROM owners WHERE sha256 = ?').get(sha256) !== undefined) return
        this.host.q('DELETE FROM blobs WHERE sha256 = ?').run(sha256)
        await this.blobs.delete(sha256)
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
 * numbers, which folders hold which bytes from each folder's blobs, the stored bytes from the
 * store. Bytes no folder holds stay listed, and go at the next prune. The log goes on from the
 * highest number any folder file ever took, and a new number is never below the clock
 * (nextNumber), so one held only by a folder whose file was deleted is not given again.
 */
export async function rebuild(dir: string, driver: BlobDriver = { kind: 'disk' }): Promise<void> {
  for (const suffix of ['', '-wal', '-shm']) rmSync(join(dir, `host.sqlite${suffix}`), { force: true })
  const host = new Db(join(dir, 'host.sqlite'))
  try {
    host.db.exec(HOST_SCHEMA)
    let top = 0
    host.tx(() => {
      for (const address of foldersIn(dir)) {
        const folder = openFolder(folderFile(dir, address))
        try {
          for (const r of folder.q('SELECT seq, id, arrived FROM records ORDER BY seq').all() as Array<{ seq: number; id: string; arrived: number }>) {
            host.q('INSERT INTO log (seq, folder, id, arrived) VALUES (?, ?, ?, ?)').run(r.seq, address, r.id, r.arrived)
          }
          for (const b of folder.q('SELECT sha256 FROM blobs').all() as Array<{ sha256: string }>) {
            host.q('INSERT INTO owners (sha256, folder) VALUES (?, ?)').run(b.sha256, address)
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
    for await (const blob of blobStore(dir, driver).list()) {
      host.q('INSERT OR IGNORE INTO blobs (sha256, type) VALUES (?, ?)').run(blob.sha256, blob.type)
    }
  } finally {
    host.close()
  }
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
