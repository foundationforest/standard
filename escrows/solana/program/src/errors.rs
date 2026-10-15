use anchor_lang::prelude::*;

#[error_code]
pub enum EscrowError {
    #[msg("the buyer and the seller must be different keys")]
    SameParty,
    #[msg("a party or the arbiter cannot be the zero key")]
    EmptyKey,
    #[msg("only the buyer or the seller can open an escrow")]
    NotAParty,
    #[msg("the amount must be above zero")]
    AmountZero,
    #[msg("a timer runs for at least one day")]
    TimerZero,
    #[msg("wrapped SOL is not accepted: a plain SOL transfer to its deposit account would not count")]
    NativeMint,
    #[msg("the deposit account holds less than the amount")]
    NotFunded,
    #[msg("the deposit account holds the amount: this escrow ends by one of its ways out, not by close_unfunded")]
    StillFunded,
    #[msg("the funding was already marked")]
    AlreadyFunded,
    #[msg("this escrow has ended; its account is the receipt and nothing more happens to it")]
    Ended,
    #[msg("this escrow has not ended; money there is part of the deal")]
    NotEnded,
    #[msg("only the buyer can do this")]
    NotTheBuyer,
    #[msg("only the seller can do this")]
    NotTheSeller,
    #[msg("no arbiter was named at creation")]
    NoArbiter,
    #[msg("only the arbiter named at creation can arbitrate")]
    NotTheArbiter,
    #[msg("no timer was set at creation")]
    NoTimer,
    #[msg("the funding has not been marked: send mark_funded first; the timer counts from it")]
    FundingNotMarked,
    #[msg("the timer is not due yet")]
    TimerNotDue,
    #[msg("a time does not fit in a unix time")]
    TimeOverflow,
    #[msg("a split is between 0 and 10,000 basis points")]
    BadSplit,
    #[msg("only the buyer or the seller can close an escrow that never held the amount")]
    NotACloser,
    #[msg("the buyer is paid only at its standard token account for the escrow's mint")]
    NotTheRefundAddress,
    #[msg("the seller is paid only at its standard token account for the escrow's mint")]
    NotTheSellersAccount,
    #[msg("the escrow account holds no more than its rent-exempt minimum")]
    NothingToSweep,
    #[msg("neither party can be the escrow's own address or its deposit address")]
    PartyIsTheEscrow,
    // v2 from here on, so every code above keeps v1's number.
    #[msg("only the buyer or the seller can object")]
    NotAnObjector,
    #[msg("a party has already objected; an escrow takes one objection")]
    AlreadyObjected,
    #[msg("the timer is due: an objection had to come before it")]
    TimerDue,
    #[msg("a party objected: the timer is off; the money moves only by the parties agreeing or by the arbiter")]
    Objected,
    // Both token programs from here on.
    #[msg("a token with a transfer fee is not accepted: the fee would take part of every payment in and out")]
    TransferFee,
    #[msg("a token that cannot be transferred is not accepted: nothing could be paid into the escrow, and nothing minted into it could leave")]
    NonTransferable,
    // Terms in the address from here on.
    #[msg("the arbiter cannot be the buyer or the seller: a party as arbiter could take everything alone")]
    ArbiterIsAParty,
}
