// The one error every check throws: a code a host answers with, and why.

export class FolderError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.name = 'FolderError'
    this.code = code
  }
}

export function fail(code: string, message: string): never {
  throw new FolderError(code, message)
}
