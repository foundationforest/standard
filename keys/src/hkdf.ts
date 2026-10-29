// HKDF-SHA256 over Web Crypto, and the three texts every key hangs on. None of them is secret. Each
// says what it mixes, so no key can be turned into any other key. A text's bytes are part of every
// key made with it: changing one gives other keys.

/**
 * The texts the seed is mixed with. A label or a name is used exactly as given. A text enters HKDF
 * as its UTF-8 bytes, and Poseidon as its number (field.ts).
 */
export const TEXT = {
  /** A profile: its main key's signing half, from the text's number, and its opening half, by HKDF. The empty label is the Profiles folder. */
  profile: (label: string) => `forest/profile/${label}`,
  /** The person's stamp number at a verifier, from the text's number. */
  verifier: (name: string) => `forest/verifier/${name}`,
  /** A profile's pay key on one chain, by HKDF. The chain comes before the label, so no label spells another text. */
  pay: (chain: 'solana' | 'evm', label: string) => `forest/pay/${chain}/${label}`,
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
