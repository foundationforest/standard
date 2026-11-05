// A key's encryption key: what envelopes are locked to. Every key's secret is 32 bytes, used
// unchanged as age's post-quantum hybrid identity: a main key's is derived from the seed with its
// profile's text, an access key's is its second 32 random bytes. See README.md, "Encryption keys".

import { bech32 } from '@scure/base'
import { identityToRecipient } from 'age-encryption'
import { assertBytes } from './hkdf.ts'

/**
 * A key's encryption key: age's post-quantum hybrid identity, ML-KEM-768 with X25519
 * (mlkem768x25519), and its public encryption key.
 */
export type OpeningHalf = {
  /** age's hybrid identity, `AGE-SECRET-KEY-PQ-1…`: it opens what is locked to the public encryption key. */
  identity: string
  /** What envelopes are locked to, `age1pq1…`. The key's address does not give it. */
  openKey: string
}

/**
 * The encryption key, from its 32 secret bytes, used unchanged as age's hybrid identity (its seed,
 * which age expands into the ML-KEM-768 and X25519 keys); age's own library computes the public
 * encryption key (identityToRecipient).
 */
export async function openingHalf(secret: Uint8Array): Promise<OpeningHalf> {
  assertBytes('secret', secret, 32)
  const identity = bech32.encodeFromBytes('AGE-SECRET-KEY-PQ-', secret).toUpperCase()
  return { identity, openKey: await identityToRecipient(identity) }
}
