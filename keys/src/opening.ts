// The opening half of a key: what envelopes are locked to. Every key's is 32 secret bytes, used
// unchanged as age's post-quantum hybrid identity: a main key's is mixed from the seed with its
// profile's text, an access key's is its second 32 random bytes. See README.md, "Opening halves".

import { bech32 } from '@scure/base'
import { identityToRecipient } from 'age-encryption'
import { assertBytes } from './hkdf.ts'

/**
 * The opening half of a key: age's post-quantum hybrid identity, ML-KEM-768 with X25519
 * (mlkem768x25519), and its open key.
 */
export type OpeningHalf = {
  /** age's hybrid identity, `AGE-SECRET-KEY-PQ-1…`: it opens what is locked to the open key. */
  identity: string
  /** What envelopes are locked to, `age1pq1…`. The key's address does not give it. */
  openKey: string
}

/**
 * The opening half, from its 32 secret bytes, used unchanged as age's hybrid identity (its seed,
 * which age expands into the ML-KEM-768 and X25519 keys); age's own library computes the open key
 * (identityToRecipient).
 */
export async function openingHalf(secret: Uint8Array): Promise<OpeningHalf> {
  assertBytes('secret', secret, 32)
  const identity = bech32.encodeFromBytes('AGE-SECRET-KEY-PQ-', secret).toUpperCase()
  return { identity, openKey: await identityToRecipient(identity) }
}
