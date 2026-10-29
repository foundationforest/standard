// Files: bytes an entry names, such as a photo. Any public entry's body may carry
//
//   files: [{ sha256, type, size }, …]
//
// and the folder's hosts keep the bytes, uploaded by their hash, while a current entry names them.
// Anyone fetches them by hash and checks it. A photo is an entry whose body is its file.

import { sha256 } from '@noble/hashes/sha2.js'
import { hex } from './bytes.ts'
import type { Json } from './canonical.ts'
import { fail } from './fail.ts'

/** A file's name: what a stranger needs to fetch it from a folder's hosts and check it. */
export type FileName = {
  /** SHA-256 of the bytes, lowercase hex. */
  sha256: string
  /** The bytes' media type, type/subtype in lower case, such as image/jpeg. */
  type: string
  /** How many bytes. */
  size: number
}

const SHA256 = /^[0-9a-f]{64}$/
/** A media type, type/subtype in lower case, at most 255 characters: what a host serves back as content-type. */
export const MEDIA_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/
const FIELDS = ['sha256', 'type', 'size']
const isObject = (v: unknown): v is { [key: string]: unknown } => v !== null && typeof v === 'object' && !Array.isArray(v)

/** Whether text is a media type a file can carry. */
export function isMediaType(type: unknown): type is string {
  return typeof type === 'string' && type.length <= 255 && MEDIA_TYPE.test(type)
}

/** A file's name, from its bytes and their media type. */
export function fileOf(bytes: Uint8Array, type: string): FileName {
  const name = { sha256: hex.encode(sha256(bytes)), type, size: bytes.length }
  checkFiles([name])
  return name
}

/** A body's `files`: a list of file names, each exactly `{ sha256, type, size }`. Throws FolderError with code `files`. */
export function checkFiles(value: unknown): asserts value is FileName[] {
  if (!Array.isArray(value)) fail('files', 'files is a list')
  for (const file of value as unknown[]) {
    if (!isObject(file) || Object.keys(file).some((f) => !FIELDS.includes(f))) fail('files', 'a file is { sha256, type, size } and nothing else')
    if (typeof file.sha256 !== 'string' || !SHA256.test(file.sha256)) fail('files', 'sha256 is 64 characters of lowercase hex')
    if (!isMediaType(file.type)) fail('files', 'type is type/subtype in lower case, at most 255 characters')
    if (!Number.isSafeInteger(file.size) || (file.size as number) < 0) fail('files', 'size is a whole number of bytes')
  }
}

/** The files a body names: none for a delete, a locked body or a body with no `files`. */
export function filesOf(body: { [key: string]: Json } | null | undefined): FileName[] {
  const files = body?.files
  if (!Array.isArray(files)) return []
  try {
    checkFiles(files)
    return files
  } catch {
    return []
  }
}
