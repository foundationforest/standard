// The verification (../README.md, The stamp and the verification): what a profile shows, the proof
// that its seed holds a stamp from a verifier.
//
// The person proves on the device, from the seed scalar and the stamp: "this verifier signed a
// stamp for the stamp number my seed gives at it, and this profile's key is the one my seed gives
// for this label". Public: the profile's key, the verifier's key, the label's scope and the
// verifier's name hash.

import { groth16 } from 'snarkjs'

import { type Point, addressOf, pointOf, profileScalarOf, publicKeyOf } from '@foundationforest/keys'
import { type SnarkjsProof, proofFromBytes } from './bytes.ts'
import { isFieldElement, nameHashOf, scopeOf } from './field.ts'
import { type SignedStamp, type VerifierKey, stampNumberOf, stampSigned } from './stamp.ts'
import { VERIFICATION_KEY } from './verification-key.ts'

/** The setup's proving files (each circuit's `setup/`): paths on Node, or the bytes in a browser. */
export type Artifacts = {
  wasm: string | Uint8Array
  zkey: string | Uint8Array
}

export type Verification = {
  /** The profile's key, which the seed gives for this label. */
  profile: Point
  /** The profile's address: its key packed, in base58. */
  address: string
  verifier: VerifierKey
  verifierName: string
  nameHash: bigint
  scope: bigint
  /** The proof as snarkjs wrote it. */
  proof: SnarkjsProof
  /** In the circuit's order: profile x, profile y, verifier x, verifier y, scope, name hash. */
  publicSignals: string[]
}

/**
 * The circuit's input, and the public signals it must give. `proveVerification` proves it; it is
 * exported for a caller that drives snarkjs itself.
 */
export function verificationInput(input: {
  /** The seed scalar: `keys/`'s `seedScalar(seed)`. */
  seedScalar: bigint
  /** The name the verifier publishes as its own, as `keys/`'s `verifierSecret` took it. */
  verifierName: string
  stamp: SignedStamp
  /** The profile's label. The proof is for the key the seed gives for it, and for no other. */
  label: string
}): { input: Record<string, unknown>; publicSignals: bigint[] } {
  const { stamp, seedScalar } = input
  if (!isFieldElement(seedScalar)) throw new RangeError('a seed scalar is a field element')
  if (!isFieldElement(stamp.facts)) throw new RangeError('facts are a field element')
  const [verifierX, verifierY] = pointOf(stamp.verifier)
  const nameHash = nameHashOf(input.verifierName)
  const scope = scopeOf(input.label)
  const profile = publicKeyOf(profileScalarOf(seedScalar, input.label))
  return {
    input: {
      seedScalar,
      facts: stamp.facts,
      R8x: stamp.signature.R8[0],
      R8y: stamp.signature.R8[1],
      S: stamp.signature.S,
      profileX: profile[0],
      profileY: profile[1],
      verifierX,
      verifierY,
      scope,
      verifierNameHash: nameHash,
    },
    publicSignals: [profile[0], profile[1], verifierX, verifierY, scope, nameHash],
  }
}

/**
 * Make the verification, on the device. Refuses a stamp for another seed or verifier name, or one
 * its verifier did not sign, before proving anything.
 */
export async function proveVerification(input: Parameters<typeof verificationInput>[0] & { artifacts: Artifacts }): Promise<Verification> {
  if (input.stamp.stampNumber !== stampNumberOf(input.seedScalar, input.verifierName)) throw new Error('this stamp is not for this seed at this verifier')
  if (!stampSigned(input.stamp)) throw new Error("the verifier's signature is not on this stamp")
  const { input: signals, publicSignals: want } = verificationInput(input)
  const { proof, publicSignals } = (await groth16.fullProve(signals, input.artifacts.wasm, input.artifacts.zkey)) as {
    proof: SnarkjsProof
    publicSignals: string[]
  }
  // The circuit's order: profile x, profile y, verifier x, verifier y, scope, name hash. Checked so
  // a change in the circuit or the setup files shows up here, and not as a proof every reader
  // refuses.
  if (publicSignals.length !== 6 || publicSignals.some((s, i) => BigInt(s) !== want[i])) {
    throw new Error('the proof carries other public signals than the ones asked for')
  }
  const [px, py, vx, vy, scope, nameHash] = want as [bigint, bigint, bigint, bigint, bigint, bigint]
  const profile: Point = [px, py]
  return {
    profile,
    address: addressOf(profile),
    verifier: addressOf([vx, vy]),
    verifierName: input.verifierName,
    nameHash,
    scope,
    proof,
    publicSignals,
  }
}

/**
 * Does this proof hold: did the verifier with this key and this name sign a stamp for whoever holds
 * the seed behind this profile's key for this label? The scope and the name hash are derived from
 * the label and the name, and the proof is checked with the committed verification key. Which
 * verifiers to trust is the reader's choice. Anything that is not a good proof for these inputs is
 * false.
 */
export async function checkVerification(input: {
  /** The proof as snarkjs writes it, `proveVerification`'s `proof`, or its 256 bytes (`proofBytes`). */
  proof: SnarkjsProof | Uint8Array
  /** The verifier's key: its address, or its point. */
  verifier: VerifierKey | Point
  verifierName: string
  label: string
  /** The profile the proof is for: its address, or its key. */
  profile: string | Point
}): Promise<boolean> {
  try {
    const profile = typeof input.profile === 'string' ? pointOf(input.profile) : pointOf(addressOf(input.profile))
    const verifier = typeof input.verifier === 'string' ? pointOf(input.verifier) : pointOf(addressOf(input.verifier))
    const values = [profile[0], profile[1], verifier[0], verifier[1], scopeOf(input.label), nameHashOf(input.verifierName)]
    const proof = input.proof instanceof Uint8Array ? proofFromBytes(input.proof) : input.proof
    return await groth16.verify(VERIFICATION_KEY, values.map(String), proof)
  } catch {
    return false
  }
}
