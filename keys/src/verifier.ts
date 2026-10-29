// The person's stamp number at one verifier: a Poseidon mix of the seed's number and the verifier's
// name hash. A verifier is anyone who signs stamps for people, such as one that checks faces.
//
// The name, not the verifier's key: a verifier that changes its key changes no one's stamp number.
// A different number at each verifier, so no two verifiers share a number for one person: two
// verifiers comparing what they hold find nothing in common.

import { poseidon2 } from 'poseidon-lite/poseidon2'
import { isFieldElement, nameHashOf } from './field.ts'

/**
 * The person's stamp number at the verifier named `name`, from the seed's number:
 * `Poseidon(the seed's number, name hash)`. The name is the text the verifier publishes as its own,
 * used exactly as given. The verifier signs it in the person's stamp; the verification circuit
 * computes the same.
 */
export function stampNumberOf(seed: bigint, name: string): bigint {
  if (!isFieldElement(seed)) throw new RangeError("the seed's number is a field element")
  return poseidon2([seed, nameHashOf(name)])
}
