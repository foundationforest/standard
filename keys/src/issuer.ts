// The person's secret for one issuer: a Poseidon mix of the seed scalar and the issuer's name. An
// issuer is anyone who signs notes for people, such as one that checks faces.
//
// The name, not the issuer's key: an issuer that changes its key changes no one's note number or
// stamps. A different secret at each issuer, so no two issuers share a number for one person: two
// issuers comparing what they hold find nothing in common.

import { poseidon1 } from 'poseidon-lite/poseidon1'
import { poseidon2 } from 'poseidon-lite/poseidon2'
import { poseidon3 } from 'poseidon-lite/poseidon3'
import { TAG, isFieldElement, nameHashOf, scopeOf } from './field.ts'
import { SEED_LENGTH, assertBytes, assertText } from './hkdf.ts'
import { seedScalar } from './scalar.ts'

export type IssuerSecret = {
  name: string
  /** The name as a number, `nameHashOf(name)`. */
  nameHash: bigint
  /** The secret: `Poseidon(issuer tag, seed scalar, name hash)`. */
  scalar: bigint
  /** The note number, `Poseidon(scalar)`. The issuer signs it in the person's note. */
  noteNumber: bigint
}

/** The person's secret for an issuer, from the seed scalar. The note circuit computes the same. */
export function issuerScalarOf(seed: bigint, name: string): bigint {
  if (!isFieldElement(seed)) throw new RangeError('a seed scalar is a field element')
  return poseidon3([TAG.issuer, seed, nameHashOf(name)])
}

/** The person's stamp for a label at an issuer: `Poseidon(scope, issuer secret)`. */
export function stampOf(issuerScalar: bigint, label: string): bigint {
  if (!isFieldElement(issuerScalar)) throw new RangeError('an issuer secret is a field element')
  return poseidon2([scopeOf(label), issuerScalar])
}

/**
 * The person's secret for the issuer named `name`, and their note number for it. The name is the
 * text the issuer publishes as its own, used exactly as given.
 */
export async function issuerSecret(seed: Uint8Array, name: string): Promise<IssuerSecret> {
  assertBytes('seed', seed, SEED_LENGTH)
  assertText('issuer name', name)
  const scalar = issuerScalarOf(await seedScalar(seed), name)
  return { name, nameHash: nameHashOf(name), scalar, noteNumber: poseidon1([scalar]) }
}
