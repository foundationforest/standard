// HKDF-SHA256 over Web Crypto, and the fixed strings every key hangs on.
// None of these strings is secret. They keep one mix apart from another, so no
// key can be turned into any other key. Changing any of them gives other keys:
// it is a new version, never an edit to this one.

/** HKDF info strings: what the seed (or a profile's secret) is mixed with. */
export const INFO = {
  /** The seed scalar, the number the circuits take, mixed from the seed. */
  seed: 'forest/v1/seed',
  /** A profile's secret, which its inbox key is mixed from. The label is used exactly as given. */
  profile: (label: string) => `forest/v1/profile/${label}`,
  /** An inbox key, mixed from a profile's secret or the vault's. */
  inbox: 'forest/v1/inbox',
  /**
   * A profile's pay key for one address type, mixed from the seed. The label is used exactly as
   * given. For solana this is, byte for byte, the string the standard mixed its one pay key
   * with before evm was added, so every Solana address stays as it was.
   */
  pay: (type: 'solana' | 'evm', label: string) => `forest/v1/pay/${type}/${label}`,
  /** The vault's secret, which its inbox key is mixed from. */
  vault: 'forest/v1/vault',
} as const

/** The seed is 32 bytes. */
export const SEED_LENGTH = 32

/**
 * HKDF-SHA256 (RFC 5869) with an empty salt: extract from `ikm`, then expand
 * with `info` to `length` bytes. Web Crypto, unchanged.
 */
export async function hkdf(ikm: Uint8Array, info: string, length = 32): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', copy(ikm), 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(info) },
    key,
    length * 8,
  )
  return new Uint8Array(bits)
}

export function utf8(text: string): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(text)
}

/** A copy in its own plain ArrayBuffer, the shape Web Crypto's types accept. */
export function copy(view: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(view)
}

export function assertBytes(name: string, value: unknown, length: number): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`${name} must be ${length} bytes`)
  }
}

/**
 * Text that has one UTF-8 spelling. A string with a lone surrogate has none: the encoder would
 * swap it for U+FFFD, and two different strings would give one key.
 */
export function assertText(name: string, value: unknown): asserts value is string {
  if (typeof value !== 'string' || new TextDecoder().decode(utf8(value)) !== value) {
    throw new Error(`${name} must be text`)
  }
}
