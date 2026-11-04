// Small byte helpers shared by every module. Encodings come from @scure/base, unchanged.

import { base58, base64urlnopad, hex } from '@scure/base'

export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text)

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

export { base58, base64urlnopad as b64u, hex }
