// The wire format: the address, the discriminators, the instruction bytes and the row's bytes.
//
// Everything here is sealed with the program. These bytes are what clients and indexes read and
// write forever, so this file is written out by hand rather than generated: a reader can check it
// against `registry/program/src/` line by line, and the Rust tests encode the same bytes
// independently against the committed wire vectors, so a drift on either side fails a test.

import { sha256 } from '@noble/hashes/sha2.js'
import { concatBytes } from '@noble/hashes/utils.js'
import { PublicKey, SystemProgram, TransactionInstruction, type AccountMeta } from '@solana/web3.js'

import { fromBytes32, toBytes32 } from './field.ts'
import type { CompressedProof } from './compress.ts'
import type { IssuerKey } from './person.ts'

/**
 * The program id in the source: a placeholder nobody holds a key for. A deploy substitutes its own
 * (devnet: `registry/devnet/devnet.json`); every builder takes `programId`.
 */
export const PROGRAM_ID = new PublicKey('FoRRegistryRowsFreeNoFeeNoAdmin1111111111111')

/** The longest label, in bytes. */
export const MAX_LABEL = 128

export const ROW_SEED = new TextEncoder().encode('row')

/** Anchor's discriminator: the first eight bytes of `sha256("<namespace>:<name>")`. */
export function discriminator(namespace: string, name: string): Uint8Array {
  return sha256(new TextEncoder().encode(`${namespace}:${name}`)).slice(0, 8)
}

export const ROW_DISCRIMINATOR = discriminator('account', 'Row')

/** Where each field of a row starts, discriminator included. The label is last. */
export const ROW_OFFSET = { profile: 8, stamp: 40, issuer: 72, payer: 136, made: 168, label: 176 } as const

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4)
  new DataView(b.buffer).setUint32(0, n, true)
  return b
}

/**
 * Instruction data as web3.js takes it. Its type says Buffer, but web3.js reads the data only as
 * bytes; making a Buffer here would need Node's global, which a browser does not have.
 */
const instructionData = (bytes: Uint8Array): Buffer => bytes as Buffer

const bytes32 = (v: bigint | Uint8Array): Uint8Array => {
  const b = typeof v === 'bigint' ? toBytes32(v) : v
  if (b.length !== 32) throw new RangeError('expected 32 bytes')
  return b
}

export const keyBytes = (k: PublicKey | Uint8Array): Uint8Array => bytes32(k instanceof PublicKey ? k.toBytes() : k)

/** An issuer's key as a row holds it: x, then y, each 32 bytes big-endian. */
export function issuerKeyBytes(issuer: IssuerKey): Uint8Array {
  if (issuer.length !== 2) throw new RangeError("an issuer's key is two numbers")
  return concatBytes(bytes32(issuer[0]), bytes32(issuer[1]))
}

/** A row's size in bytes, discriminator included, for a label of `labelBytes` bytes. It never changes. */
export function rowSpace(labelBytes: number): number {
  return ROW_OFFSET.label + 4 + labelBytes
}

/** A row's address: derived from its stamp, so one stamp has at most one row. */
export function rowAddress(stamp: bigint | Uint8Array, programId: PublicKey = PROGRAM_ID): PublicKey {
  return PublicKey.findProgramAddressSync([ROW_SEED, bytes32(stamp)], programId)[0]
}

const ro = (pubkey: PublicKey, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: false })
const rw = (pubkey: PublicKey, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: true })

/**
 * Write a row. The main key signs; the payer signs, pays the row's deposit and is recorded for
 * refunds. They may be one key.
 *
 * Data: discriminator, stamp (32), issuer's key (x 32, y 32), tier (32), proof (a 32, b 64, c 32),
 * label (u32 length, UTF-8). No time: the program sets it. Accounts: the row, the profile, the
 * payer, the system program.
 */
export function registerIx(args: {
  profile: PublicKey
  label: string
  stamp: bigint | Uint8Array
  issuer: IssuerKey
  tier: bigint | Uint8Array
  proof: CompressedProof
  payer: PublicKey
  programId?: PublicKey
}): TransactionInstruction {
  const programId = args.programId ?? PROGRAM_ID
  const label = new TextEncoder().encode(args.label)
  if (label.length > MAX_LABEL) throw new RangeError(`a label is at most ${MAX_LABEL} bytes`)
  const p = args.proof
  if (p.a.length !== 32 || p.b.length !== 64 || p.c.length !== 32) throw new RangeError('a compressed proof is 32, 64 and 32 bytes')
  return new TransactionInstruction({
    programId,
    keys: [
      rw(rowAddress(args.stamp, programId)),
      ro(args.profile, true),
      rw(args.payer, true),
      ro(SystemProgram.programId),
    ],
    data: instructionData(
      concatBytes(
        discriminator('global', 'register'),
        bytes32(args.stamp),
        issuerKeyBytes(args.issuer),
        bytes32(args.tier),
        p.a,
        p.b,
        p.c,
        u32le(label.length),
        label,
      ),
    ),
  })
}

/**
 * Move what the row holds above its rent-exempt minimum to `payer`, which must be the payer the
 * row records. Nobody signs but whoever sends the transaction.
 *
 * Data: the discriminator alone. Accounts: the row, the recorded payer.
 */
export function refundIx(args: { row: PublicKey; payer: PublicKey; programId?: PublicKey }): TransactionInstruction {
  return new TransactionInstruction({
    programId: args.programId ?? PROGRAM_ID,
    keys: [rw(args.row), rw(args.payer)],
    data: instructionData(discriminator('global', 'refund')),
  })
}

export type Row = {
  /** The main key, which signed `register`: registered, it is this profile. */
  profile: PublicKey
  /** The stamp the proof gave: the row's address comes from it. */
  stamp: bigint
  /** The key of the issuer whose note the proof showed. */
  issuer: IssuerKey
  /** Who paid the deposit; refunds go here. */
  payer: PublicKey
  /** When the program wrote the row: Unix seconds, from the chain's clock. */
  made: number
  label: string
}

/** A row's bytes, read back. Refuses anything that is not exactly a row. */
export function decodeRow(data: Uint8Array): Row {
  if (data.length < rowSpace(0) || !ROW_DISCRIMINATOR.every((v, i) => data[i] === v)) throw new RangeError('not a row')
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const labelLength = view.getUint32(ROW_OFFSET.label, true)
  if (labelLength > MAX_LABEL || data.length !== rowSpace(labelLength)) throw new RangeError('not a row: label')
  const o = ROW_OFFSET
  const at = (offset: number) => fromBytes32(data.subarray(offset, offset + 32))
  return {
    profile: new PublicKey(data.subarray(o.profile, o.profile + 32)),
    stamp: at(o.stamp),
    issuer: [at(o.issuer), at(o.issuer + 32)],
    payer: new PublicKey(data.subarray(o.payer, o.payer + 32)),
    made: Number(view.getBigInt64(o.made, true)),
    label: new TextDecoder('utf-8', { fatal: true }).decode(data.subarray(o.label + 4)),
  }
}
