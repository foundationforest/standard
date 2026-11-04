// The codes src/codes.ts lists, as the entry exports them, are exactly the ones README.md marks in
// brackets, each once.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { CODES } from '../src/index.ts'

test('CODES is every code the README marks in brackets, each once', () => {
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8')
  // A mark is one code or a comma list in brackets, across line breaks; a link's text is not one.
  const marks = [...readme.matchAll(/\[(`[a-z_]+`(?:,\s+`[a-z_]+`)*)\](?!\()/g)]
  const marked = new Set(marks.flatMap((m) => [...m[1]!.matchAll(/`([a-z_]+)`/g)].map((c) => c[1]!)))
  assert.equal(new Set(CODES).size, CODES.length, 'a code is listed twice')
  assert.deepEqual([...CODES].sort(), [...marked].sort())
})
