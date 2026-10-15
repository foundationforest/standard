// The Forest registry client: everything a device needs to turn a note an issuer signed into a
// row, and to read rows back. It talks to no network of its own. The caller passes in the note and
// a recent blockhash; the main key and the payer sign, and anyone sends.
//
// One row, one proof, one transaction: `register`. A row never changes after it.
//
// Nothing here is in production.

import {
  ComputeBudgetProgram,
  PublicKey,
  TransactionMessage,
  VersionedTransaction,
  type TransactionInstruction,
} from '@solana/web3.js'

import { compressProof, type CompressedProof } from './compress.ts'
import { provePerson, type Artifacts, type PersonProof, type SignedNote } from './person.ts'
import { MAX_LABEL, PROGRAM_ID, registerIx, rowAddress } from './program.ts'

export * from './field.ts'
export * from './compress.ts'
export * from './stamp.ts'
export * from './program.ts'
export * from './rows.ts'
export * from './person.ts'

export type Registration = PersonProof & {
  /** The proof, points compressed the way the program reads them. */
  compressed: CompressedProof
  /** The row's address. */
  row: PublicKey
  instruction: TransactionInstruction
  /** Unsigned: `register`, needing the main key's signature and the payer's. */
  transaction: VersionedTransaction
}

/**
 * A row for one profile under one label, from a note an issuer signed for the person. The person
 * proof is made on the device; it refuses a note for another secret, or one its issuer did not
 * sign, before proving anything.
 */
export async function buildRegistration(input: {
  /** The 32 bytes `keys/`'s `issuerSecret(seed, name)` returns. */
  secret: Uint8Array
  /** The note the issuer signed for this person. */
  note: SignedNote
  label: string
  /** The main key. It signs the transaction; registered, it is this profile. */
  profile: PublicKey
  /** The person circuit's proving files (`registry/circuit/devnet/`). */
  artifacts: Artifacts
  /** Pays the row's deposit and the transaction's fee, and signs it. May be the profile. */
  payer: PublicKey
  recentBlockhash: string
  /** Leave unset for no compute-budget instruction. */
  computeUnitLimit?: number
  programId?: PublicKey
}): Promise<Registration> {
  const programId = input.programId ?? PROGRAM_ID
  if (new TextEncoder().encode(input.label).length > MAX_LABEL) throw new RangeError(`a label is at most ${MAX_LABEL} bytes`)
  const p = await provePerson(input)
  const compressed = compressProof(p.proof)
  const instruction = registerIx({
    profile: input.profile,
    label: input.label,
    stamp: p.stamp,
    issuer: p.issuer,
    tier: p.tier,
    proof: compressed,
    payer: input.payer,
    programId,
  })
  const instructions =
    input.computeUnitLimit === undefined ? [instruction] : [ComputeBudgetProgram.setComputeUnitLimit({ units: input.computeUnitLimit }), instruction]
  const transaction = new VersionedTransaction(
    new TransactionMessage({ payerKey: input.payer, recentBlockhash: input.recentBlockhash, instructions }).compileToV0Message(),
  )
  return { ...p, compressed, row: rowAddress(p.stamp, programId), instruction, transaction }
}
