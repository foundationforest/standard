use anchor_lang::prelude::*;

#[error_code]
pub enum EscrowError {
    #[msg("the payer and the recipient must be different keys")]
    SameParty,
    #[msg("a party or the arbiter cannot be the zero key")]
    EmptyKey,
    #[msg("only the payer or the recipient can do this")]
    NotAParty,
    #[msg("the amount must be above zero")]
    AmountZero,
    #[msg("wrapped SOL is not accepted: a plain SOL transfer to its deposit account would not count")]
    NativeMint,
    #[msg("the deposit account holds less than the amount")]
    NotFunded,
    #[msg("the deposit account holds the amount: this escrow ends by one of its moves, not by close_unfunded, unless its schedule ended before anyone marked it funded")]
    StillFunded,
    #[msg("the funding was already marked")]
    AlreadyFunded,
    #[msg("this escrow has ended; its account is the receipt and nothing more happens to it")]
    Ended,
    #[msg("this escrow has not ended; money there is part of the deal")]
    NotEnded,
    #[msg("only the payer can do this")]
    NotThePayer,
    #[msg("only the recipient can do this")]
    NotTheRecipient,
    #[msg("no arbiter was named at creation")]
    NoArbiter,
    #[msg("only the arbiter named at creation can decide")]
    NotTheArbiter,
    #[msg("a share is between 0 and 10,000 basis points, and a take-back's is above 0: giving everything to the recipient is pay")]
    BadShare,
    #[msg("nobody marked the funding before the end time: end pays only a marked escrow")]
    FundingNotMarked,
    #[msg("the payer is paid only at its standard token account for the escrow's mint")]
    NotThePayersAccount,
    #[msg("the recipient is paid only at its standard token account for the escrow's mint")]
    NotTheRecipientsAccount,
    #[msg("the escrow account holds no more than its rent-exempt minimum")]
    NothingToSweep,
    #[msg("neither party can be the escrow's own address or its deposit address")]
    PartyIsTheEscrow,
    #[msg("a party has already stopped this escrow; it takes one stop")]
    AlreadyStopped,
    #[msg("a party stopped this escrow: the schedule is off; the money moves only by a side giving, both agreeing, or the arbiter")]
    Stopped,
    #[msg("a token with a transfer fee is not accepted: the fee would take part of every payment in and out")]
    TransferFee,
    #[msg("a token that cannot be transferred is not accepted: nothing could be paid into the escrow, and nothing minted into it could leave")]
    NonTransferable,
    #[msg("the arbiter cannot be the payer or the recipient: a party as arbiter could take everything alone")]
    ArbiterIsAParty,
    #[msg("a schedule has at least one window")]
    ScheduleEmpty,
    #[msg("a schedule has at most four windows")]
    TooManyWindows,
    #[msg("each window's until must be later than the one before")]
    WindowsOutOfOrder,
    #[msg("this escrow has no schedule")]
    NoSchedule,
    #[msg("the schedule's end time has passed")]
    ScheduleOver,
    #[msg("the schedule's end time has not come")]
    ScheduleNotOver,
}
