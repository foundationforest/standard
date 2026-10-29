// Small byte helpers shared by every module. Encodings come from @scure/base, unchanged.

import { base58, base64urlnopad, hex } from '@scure/base'

export const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text)
export const fromUtf8 = (bytes: Uint8Array): string => new TextDecoder('utf-8', { fatal: true }).decode(bytes)

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

export { base58, base64urlnopad as b64u, hex }
