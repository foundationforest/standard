// The person's secret for one verifier: a Poseidon mix of the seed scalar and the verifier's name.
// A verifier is anyone who signs stamps for people, such as one that checks faces.
//
// The name, not the verifier's key: a verifier that changes its key changes no one's stamp number.
// A different secret at each verifier, so no two verifiers share a number for one person: two
// verifiers comparing what they hold find nothing in common.

import { poseidon1 } from 'poseidon-lite/poseidon1'
import { poseidon3 } from 'poseidon-lite/poseidon3'
import { PREFIX, isFieldElement, nameHashOf } from './field.ts'
import { SEED_LENGTH, assertBytes, assertText } from './hkdf.ts'
import { seedScalar } from './scalar.ts'

export type VerifierSecret = {
  name: string
  /** The name as a number, `nameHashOf(name)`. */
  nameHash: bigint
  /** The secret: `Poseidon(verifier prefix, seed scalar, name hash)`. */
  scalar: bigint
  /** The stamp number, `Poseidon(scalar)`. The verifier signs it in the person's stamp. */
  stampNumber: bigint
}

/** The person's secret for a verifier, from the seed scalar. The verification circuit computes the same. */
export function verifierScalarOf(seed: bigint, name: string): bigint {
  if (!isFieldElement(seed)) throw new RangeError('a seed scalar is a field element')
  return poseidon3([PREFIX.verifier, seed, nameHashOf(name)])
}

/**
 * The person's secret for the verifier named `name`, and their stamp number for it. The name is the
 * text the verifier publishes as its own, used exactly as given.
 */
export async function verifierSecret(seed: Uint8Array, name: string): Promise<VerifierSecret> {
  assertBytes('seed', seed, SEED_LENGTH)
  assertText('verifier name', name)
  const scalar = verifierScalarOf(await seedScalar(seed), name)
  return { name, nameHash: nameHashOf(name), scalar, stampNumber: poseidon1([scalar]) }
}
