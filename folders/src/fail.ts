// The one error every check throws: a code a host answers with, and why.

import type { Code } from './codes.ts'

export class FolderError extends Error {
  readonly code: Code
  constructor(code: Code, message: string) {
    super(message)
    this.name = 'FolderError'
    this.code = code
  }
}

export function fail(code: Code, message: string): never {
  throw new FolderError(code, message)
}
