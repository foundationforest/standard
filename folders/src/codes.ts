// Every error code README.md marks in brackets: what a check throws in FolderError, and what a host
// answers a refusal with. Each is listed once, under the README section that first marks it, in the
// README's order. No imports, so an app, a browser's included, takes this file alone.

export const CODES = [
  // The profile entry
  'profile',
  // Access keys
  'unlisted',
  // Locked entries: a reader's, never a host's answer
  'locked',
  // Files
  'files',
  // The inbox: a reader's, never a host's answer
  'to',
  // Hosts
  'batch',
  'refused',
  // Hosts, taking an entry in
  'size',
  'canonical',
  'shape',
  'version',
  'key',
  'path',
  'time',
  'body',
  'signature',
  'future',
  'older',
  // Hosts, taking an inbox entry in
  'duplicate',
  'no_inbox',
  // Hosts, taking a file in
  'unnamed',
  'hash',
] as const

export type Code = (typeof CODES)[number]
