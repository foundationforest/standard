// Stamps: what makes one row per person per issuer per label true.
//
// A person's secret for one issuer comes from their seed and the issuer's name (`keys/`'s
// `issuerSecret`). Their stamp for a label is `Poseidon(scope, scalar)`: the same every time for
// one person at one issuer under one label, unguessable for anyone else, and saying nothing about
// who they are. The person proof gives it as its output, and a row sits at an address derived from
// it, so a second row for it cannot exist.
//
// Deriving a stamp needs only the secret and the label, so an app can check whether a row already
// exists before making a proof.

import { deriveSecretScalar } from '@zk-kit/eddsa-poseidon'
import { poseidon2 } from 'poseidon-lite/poseidon2'

import { scopeOf } from './field.ts'

/** The secret as the circuits take it, from the 32 bytes `keys/`'s `issuerSecret` returns: its `scalar`. */
export function scalarOf(secret: Uint8Array): bigint {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) throw new Error('an issuer secret is 32 bytes')
  return deriveSecretScalar(secret)
}

/** The person's stamp for this label: `Poseidon(scope, scalar)`, the number a row sits at. */
export function stampOf(secret: Uint8Array, label: string): bigint {
  return poseidon2([scopeOf(label), scalarOf(secret)])
}
