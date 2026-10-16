//! The one account, and the size it keeps forever.
//!
//! The layout is sealed with the program: clients and indexes read these bytes for as long as
//! the program lives. Nothing may grow, shrink or be reordered in v3. v3 is not v2's layout with
//! more after it: the schedule takes the timer's place, and the parties are the payer and the
//! recipient.

use anchor_lang::prelude::*;

/// One hundred percent, in basis points.
pub const BPS: u16 = 10_000;
/// The most windows a schedule holds. Four keep every receipt at 304 bytes, seven more than v2's.
pub const MAX_WINDOWS: usize = 4;

/// One of the two parties. Stored as one byte: payer 0, recipient 1.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Payer,
    Recipient,
}

/// One window of a schedule: from the `until` before it (the first, from the opening) up to, not
/// including, its own `until`, in unix seconds, the payer may take back `payer_share` basis points
/// of the balance alone.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    pub until: i64,
    pub payer_share: u16,
}

/// The default from the end time on: everything to the recipient, or back to the payer. Stored as
/// one byte: pay 0, refund 1.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    Pay,
    Refund,
}

/// A schedule, as `create` takes it: one to four windows, each `until` later than the one before,
/// and the default. The last `until` is the end time.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct Schedule {
    pub windows: Vec<Window>,
    pub end: End,
}

/// Where an escrow is. `Ended` is stored too: an ended escrow's account is never closed, so its
/// address is a permanent receipt that holds the final state and can never be reused.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Created; the funding has not been marked. The deposit account may already hold the amount.
    Open,
    /// `mark_funded` saw the deposit account holding the amount, at `funded_at`, before the end time.
    Funded,
    /// Paid out. `outcome`, `funded_at`, `ended_at`, `to_payer` and `to_recipient` say how. Nothing
    /// more happens to it but late money going back to the payer and rent above the minimum to the
    /// sponsor.
    Ended,
}

/// How an escrow ended: the move that ended it. In the account once it has, and in `Ended`.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The payer gave everything to the recipient.
    Pay,
    /// The recipient gave everything back to the payer.
    Refund,
    /// The payer took back the share of the window in force; the rest went to the recipient.
    TakeBack,
    /// Both signed a split.
    Agree,
    /// The arbiter named at creation signed a split.
    Decide,
    /// The end time had come, nobody had stopped it, and someone sent the default.
    End,
}

/// Whether a party stopped the escrow, and which. Stored as one byte: none 0, the payer 1, the
/// recipient 2. Its own byte, never read from a time: a zero clock must not read as "nobody stopped".
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    None,
    Payer,
    Recipient,
}

/// One escrow. Address: `["escrow", terms_hash]`, made from every term (`terms_hash`), so a
/// payment sent to it counts only toward a deal with exactly those terms; only the payer or the
/// recipient can open it. Never closed once it has ended: its deposit account closes and its rent
/// goes back, and this account stays as the receipt. Only an escrow whose funding was never marked
/// and that holds less than the amount, or whose schedule ended before anyone marked it, is closed
/// (`close_unfunded`).
#[account]
pub struct Escrow {
    /// `crate::VERSION`: which program's rules an escrow follows.
    pub version: u8,
    /// Chosen at creation; it tells apart two deals with the same terms. The app picks it at
    /// random.
    pub id: u64,
    pub payer: Pubkey,
    pub recipient: Pubkey,
    /// The zero key when no arbiter was named.
    pub arbiter: Pubkey,
    /// A mint of the classic SPL Token program or of Token-2022; whichever owns it is the token
    /// program every instruction here names. Not stored: a mint's owner never changes.
    pub mint: Pubkey,
    /// The deposit account: this escrow's associated token account for `mint`, under the mint's
    /// token program. Derivable from the escrow address and the mint, and recorded so a reader
    /// need not derive it.
    pub vault: Pubkey,
    /// The key that signed `create` as sponsor and fronted both rents. Every rent goes back here:
    /// the deposit account's at every ending, both at `close_unfunded`, and rent above the escrow
    /// account's minimum, which Solana's rent cuts free, by `sweep_rent`.
    pub sponsor: Pubkey,
    /// The agreed amount, in the mint's base units. The escrow is funded once the deposit account
    /// holds at least this much; every way out then pays out the whole balance, whatever it is.
    pub amount: u64,
    /// Who opened it: the payer, or the recipient (an invoice).
    pub creator: Side,
    /// How many of `windows` the schedule uses: 0 for no schedule.
    pub window_count: u8,
    /// The schedule's windows, then zeros: the unused ones are all zero.
    pub windows: [Window; MAX_WINDOWS],
    /// The default from the end time on. Stored as `Pay` when there is no schedule.
    pub end: End,
    pub created_at: i64,
    /// When the program first saw the deposit account holding the amount: `mark_funded`'s time,
    /// or, if nobody marked it, the ending's. 0 until one of them runs. `end` pays only an escrow
    /// marked before the end time.
    pub funded_at: i64,
    pub status: Status,
    pub bump: u8,
    /// When it ended, or 0 while it has not.
    pub ended_at: i64,
    /// How it ended. Meaningful only when `status` is `Ended`; stored as 0 before.
    pub outcome: Outcome,
    /// What the payer and the recipient were paid at the end. `to_payer + to_recipient` is what the
    /// deposit account held. Zero before the end.
    pub to_payer: u64,
    pub to_recipient: u64,
    /// Which party stopped the escrow, if one did. Once one has, neither `take_back` nor `end` runs.
    pub stop: Stop,
    /// When the stop was made, or 0. Read only for the record: `stop` says whether.
    pub stopped_at: i64,
}

impl Escrow {
    /// version 0, id 1..9, payer 9..41, recipient 41..73, arbiter 73..105, mint 105..137,
    /// vault 137..169, sponsor 169..201, amount 201..209, creator 209, window_count 210,
    /// windows 211..251 (each: until 8, payer_share 2), end 251, created_at 252..260,
    /// funded_at 260..268, status 268, bump 269, ended_at 270..278, outcome 278,
    /// to_payer 279..287, to_recipient 287..295, stop 295, stopped_at 296..304.
    pub const LEN: usize = 1 + 8 + 32 * 6 + 8 + 1 + 1 + 10 * MAX_WINDOWS + 1 + 8 + 8 + 1 + 1 + 8 + 1 + 8 + 8 + 1 + 8;

    pub fn has_arbiter(&self) -> bool {
        self.arbiter != Pubkey::default()
    }

    pub fn stopped(&self) -> bool {
        self.stop != Stop::None
    }

    /// Open or funded: the only states any way out, `mark_funded`, `stop` or `close_unfunded`
    /// runs from. An allowlist, so a state added later is refused by default.
    pub fn live(&self) -> bool {
        matches!(self.status, Status::Open | Status::Funded)
    }

    /// The schedule's windows: none when there is no schedule.
    pub fn schedule(&self) -> &[Window] {
        &self.windows[..usize::from(self.window_count).min(MAX_WINDOWS)]
    }

    /// The end time: the last window's `until`. `None` with no schedule. The one deadline in the
    /// program: `stop`, `mark_funded` and `take_back` run only before it, `end` only from it on, so
    /// a stop and the default never race.
    pub fn end_time(&self) -> Option<i64> {
        self.schedule().last().map(|w| w.until)
    }

    /// The window in force at `now`: the first whose `until` is still ahead. `None` from the end
    /// time on, and with no schedule.
    pub fn window_at(&self, now: i64) -> Option<Window> {
        self.schedule().iter().copied().find(|w| now < w.until)
    }

    /// The seed of this escrow's address, rebuilt from the terms it stores: what every signature
    /// the escrow makes uses.
    pub fn terms_hash(&self) -> [u8; 32] {
        terms_hash(self.id, &self.payer, &self.recipient, &self.arbiter, &self.mint, self.amount, self.window_count, &self.windows, self.end)
    }

    /// The payer's standard token account for the mint, under the mint's token program: the one
    /// account any payout to the payer lands in. Computed from two keys fixed at creation and the
    /// program that owns the mint (every caller has checked `token_program` is it), so nothing more
    /// is stored, and nobody who sends an instruction can name another.
    pub fn payer_account(&self, token_program: &Pubkey) -> Pubkey {
        anchor_spl::associated_token::get_associated_token_address_with_program_id(&self.payer, &self.mint, token_program)
    }

    /// The recipient's standard token account for the mint, the one account any payout to the
    /// recipient lands in. The same rule as the payer's.
    pub fn recipient_account(&self, token_program: &Pubkey) -> Pubkey {
        anchor_spl::associated_token::get_associated_token_address_with_program_id(&self.recipient, &self.mint, token_program)
    }
}

/// The seed an escrow's address is made from: SHA-256 of all its terms, each at a fixed length,
/// in the receipt's own order: id (8 bytes, little-endian), payer, recipient, arbiter (the zero key
/// for none) and mint (32 bytes each), amount (8, little-endian), the window count (1), four
/// windows (each `until`, 8 bytes, and `payer_share`, 2, little-endian; zeros past the count) and
/// the default (1 byte: pay 0, refund 1; pay when there is no schedule): 186 bytes. `create` refuses
/// the zero key as arbiter and a schedule with no windows, so no two sets of terms it accepts are
/// hashed from the same bytes. The creator and the sponsor are not terms: either party may open the
/// same terms, and they land at the same address.
#[allow(clippy::too_many_arguments)]
pub fn terms_hash(id: u64, payer: &Pubkey, recipient: &Pubkey, arbiter: &Pubkey, mint: &Pubkey, amount: u64, window_count: u8, windows: &[Window; MAX_WINDOWS], end: End) -> [u8; 32] {
    let mut schedule = [0u8; 1 + 10 * MAX_WINDOWS + 1];
    schedule[0] = window_count;
    for (i, w) in windows.iter().enumerate() {
        schedule[1 + 10 * i..9 + 10 * i].copy_from_slice(&w.until.to_le_bytes());
        schedule[9 + 10 * i..11 + 10 * i].copy_from_slice(&w.payer_share.to_le_bytes());
    }
    schedule[1 + 10 * MAX_WINDOWS] = match end {
        End::Pay => 0,
        End::Refund => 1,
    };
    solana_sha256_hasher::hashv(&[&id.to_le_bytes(), payer.as_ref(), recipient.as_ref(), arbiter.as_ref(), mint.as_ref(), &amount.to_le_bytes(), &schedule]).to_bytes()
}

/// `amount × bps / 10,000`, rounded down, in 128 bits so nothing overflows. `bps` is at most
/// 10,000 (checked by every caller), so the result is at most `amount` and fits back in 64 bits.
pub fn share(amount: u64, bps: u16) -> u64 {
    ((u128::from(amount) * u128::from(bps)) / u128::from(BPS)) as u64
}
