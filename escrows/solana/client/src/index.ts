// The Forest escrow client, v2: build every instruction, build an escrow's terms from a post's
// terms and the deal's own choices, show a person any option they did not set before they work or
// pay, tell when a timer is due and whether an objection can still land, and decode the escrow
// account and its events. It talks to no network of its own: the caller reads accounts and sends
// transactions.
//
// Nothing here is shipped.

export * from './program.ts'
export * from './terms.ts'
