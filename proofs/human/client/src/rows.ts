// Reading rows, and checking a tier a profile shows: through whatever connection the caller passes
// (its own RPC, an app's, an index's). Nothing here opens a network of its own.

import type { Commitment, Connection, PublicKey } from '@solana/web3.js'

import type { SnarkjsProof } from './compress.ts'
import { fromBytes32 } from './field.ts'
import { verifyPerson, type IssuerKey } from './person.ts'
import { PROGRAM_ID, ROW_DISCRIMINATOR, ROW_OFFSET, decodeRow, issuerKeyBytes, keyBytes, rowAddress, type Row } from './program.ts'

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

/** Base58, for RPC filters, which take their bytes in base58. */
export function base58(bytes: Uint8Array): string {
  let n = 0n
  for (const b of bytes) n = n * 256n + BigInt(b)
  let s = ''
  while (n > 0n) {
    s = ALPHABET[Number(n % 58n)] + s
    n /= 58n
  }
  for (const b of bytes) {
    if (b !== 0) break
    s = '1' + s
  }
  return s
}

/** The row at `stamp`, or null if there is none. */
export async function fetchRow(
  connection: Pick<Connection, 'getAccountInfo'>,
  stamp: bigint | Uint8Array,
  options: { programId?: PublicKey; commitment?: Commitment } = {},
): Promise<Row | null> {
  const programId = options.programId ?? PROGRAM_ID
  const info = await connection.getAccountInfo(rowAddress(stamp, programId), options.commitment ?? 'confirmed')
  if (!info) return null
  if (!info.owner.equals(programId)) throw new Error("the account at that stamp is not the registry's")
  return decodeRow(new Uint8Array(info.data))
}

/**
 * Every row, or every row of one profile, one issuer or one label: each a filter on the row's
 * bytes at a fixed offset, so the RPC does the filtering.
 */
export async function fetchRows(
  connection: Pick<Connection, 'getProgramAccounts'>,
  options: { profile?: PublicKey; issuer?: IssuerKey; label?: string; programId?: PublicKey; commitment?: Commitment } = {},
): Promise<{ address: PublicKey; row: Row }[]> {
  const programId = options.programId ?? PROGRAM_ID
  const filters: { memcmp: { offset: number; bytes: string } }[] = [{ memcmp: { offset: 0, bytes: base58(ROW_DISCRIMINATOR) } }]
  if (options.profile) filters.push({ memcmp: { offset: ROW_OFFSET.profile, bytes: base58(keyBytes(options.profile)) } })
  if (options.issuer) filters.push({ memcmp: { offset: ROW_OFFSET.issuer, bytes: base58(issuerKeyBytes(options.issuer)) } })
  if (options.label !== undefined) {
    // The label's length and its bytes, so `tutoring/seller` never matches `tutoring/sellers`. An
    // RPC compares at most 128 bytes, so a longer label is cut there and checked exactly below.
    const label = new TextEncoder().encode(options.label)
    const prefix = new Uint8Array(4 + label.length)
    new DataView(prefix.buffer).setUint32(0, label.length, true)
    prefix.set(label, 4)
    filters.push({ memcmp: { offset: ROW_OFFSET.label, bytes: base58(prefix.subarray(0, 128)) } })
  }
  const accounts = await connection.getProgramAccounts(programId, { commitment: options.commitment ?? 'confirmed', filters })
  return accounts
    .map(({ pubkey, account }) => ({ address: pubkey, row: decodeRow(new Uint8Array(account.data)) }))
    .filter(({ row }) => options.label === undefined || row.label === options.label)
}

/**
 * The tier a profile shows, checked: the person proof attached to it (records/'s `proofs`, circuit
 * `person`), against its row. The row at the proof's stamp must name this main key, and the issuer
 * and label the profile shows, when given, so a reader that trusts the issuer a profile shows never
 * compares it with the row itself; the proof must hold for the row's issuer and label, this main
 * key, the stamp and the tier. Gives the row, so the reader can weigh its issuer and when it was
 * made; null when anything fails. Which issuers count, and from when, is the reader's choice.
 */
export async function verifyTier(
  connection: Pick<Connection, 'getAccountInfo'>,
  input: {
    /** The main key of the profile that shows the proof. */
    profile: PublicKey | Uint8Array
    /** The issuer the profile shows: its key, or its 64 bytes as a row holds them. */
    issuer?: IssuerKey | Uint8Array
    /** The label the profile shows. */
    label?: string
    stamp: bigint | Uint8Array
    tier: bigint
    /** The proof as snarkjs writes it, `provePerson`'s `proof`, or its 256 bytes as a profile shows it (`proofBytes`). */
    proof: SnarkjsProof | Uint8Array
  },
  options: { programId?: PublicKey; commitment?: Commitment } = {},
): Promise<Row | null> {
  const stamp = typeof input.stamp === 'bigint' ? input.stamp : fromBytes32(input.stamp)
  const row = await fetchRow(connection, stamp, options)
  if (!row || row.stamp !== stamp) return null
  const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i])
  const profile = keyBytes(input.profile)
  if (!same(keyBytes(row.profile), profile)) return null
  if (input.label !== undefined && input.label !== row.label) return null
  if (input.issuer !== undefined && !same(input.issuer instanceof Uint8Array ? input.issuer : issuerKeyBytes(input.issuer), issuerKeyBytes(row.issuer))) return null
  const holds = await verifyPerson({ proof: input.proof, issuer: row.issuer, label: row.label, profile, stamp, tier: input.tier })
  return holds ? row : null
}
