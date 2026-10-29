// The one canonical text of a value: RFC 8785 (JCS), by the RFC author's library, over a
// narrowed JSON so every implementation agrees byte for byte:
//   - strings with no lone surrogates;
//   - whole numbers only, within ±(2^53 - 1) (money and coordinates are decimal text);
//   - object keys ASCII `[a-z][a-zA-Z0-9]{0,63}`, so UTF-16 and UTF-8 key orders are the same;
//   - plain objects and arrays, nested at most MAX_DEPTH deep.

import canonicalize from 'canonicalize'

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

export const MAX_DEPTH = 16
export const KEY = /^[a-z][a-zA-Z0-9]{0,63}$/

export class CanonicalError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CanonicalError'
  }
}

export function checkValue(value: unknown, depth = 0): asserts value is Json {
  if (depth > MAX_DEPTH) throw new CanonicalError('nested too deep')
  if (value === null || typeof value === 'boolean') return
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new CanonicalError('numbers are whole and within 2^53')
    return
  }
  if (typeof value === 'string') {
    if (!value.isWellFormed()) throw new CanonicalError('text has a lone surrogate')
    return
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      if (!(i in value)) throw new CanonicalError('arrays have no holes')
      checkValue(value[i], depth + 1)
    }
    return
  }
  if (typeof value === 'object') {
    const proto = Object.getPrototypeOf(value)
    if (proto !== Object.prototype && proto !== null) throw new CanonicalError('only plain objects')
    for (const [key, inner] of Object.entries(value)) {
      if (!KEY.test(key)) throw new CanonicalError(`key ${JSON.stringify(key)} is not [a-z][a-zA-Z0-9]{0,63}`)
      checkValue(inner, depth + 1)
    }
    return
  }
  throw new CanonicalError(`${typeof value} is not a JSON value`)
}

/** The canonical text of a value in the narrowed JSON. */
export function canonical(value: unknown): string {
  checkValue(value)
  const text = canonicalize(value)
  if (typeof text !== 'string') throw new CanonicalError('not serializable')
  return text
}

/**
 * Parse text that must already be canonical. Re-serializing what was parsed must give the same
 * text back, which refuses duplicate keys, other key orders, whitespace, other escapes and
 * other number spellings: every reader sees exactly the value that was signed.
 */
export function parseCanonical(text: string): Json {
  let value: unknown
  try {
    value = JSON.parse(text)
  } catch {
    throw new CanonicalError('not JSON')
  }
  if (canonical(value) !== text) throw new CanonicalError('not in canonical form')
  return value as Json
}
