// The Forest escrow client: build every instruction, build an escrow's terms from a post's terms
// and the deal's own choices, show a person any option they did not set before they work or pay,
// tell which window is in force and whether a stop, a take-back or the default can land, and decode
// the escrow account and its events. It talks to no network of its own: the caller reads accounts
// and sends transactions.

export * from './program.ts'
export * from './terms.ts'
