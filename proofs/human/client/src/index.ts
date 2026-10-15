// The human proof's client: everything a device needs to turn a note an issuer signed into a human
// proof for one of the person's profiles, everything an issuer needs to sign notes, and the check
// any reader makes. It talks to no network: the caller passes in the seed scalar, the note and the
// setup's files.
//
// Nothing here is in production: the circuit's setup is devnet only (../README.md).

export * from './field.ts'
export * from './bytes.ts'
export * from './human.ts'
