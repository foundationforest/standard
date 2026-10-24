// The stamp proof's client: everything a device needs to turn a stamp a verifier signed into a
// stamp proof for one of the person's profiles, everything a verifier needs to sign stamps, and the
// check any reader makes. It talks to no network: the caller passes in the seed scalar, the stamp
// and the setup's files.

export * from './field.ts'
export * from './bytes.ts'
export * from './stamp.ts'
