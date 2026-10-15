//! The one account, and the size it keeps forever.
//!
//! The layout is sealed with the program: clients and indexes read these bytes for as long as
//! the program lives. Nothing may grow, shrink or be reordered in v2. The first 256 bytes are
//! v1's, field for field; v2 appends the payer and the objection after them.

use anchor_lang::prelude::*;

use crate::errors::EscrowError;

/// One hundred percent, in basis points.
pub const BPS: u16 = 10_000;
pub const SECONDS_PER_DAY: i64 = 86_400;

/// One of the two parties. Stored as one byte: buyer 0, seller 1.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Buyer,
    Seller,
}

/// The optional timer, as `create` takes it: this many whole days after the funding is marked,
/// anyone may send everything to `to`, unless a party objected first.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timer {
    pub days: u16,
    pub to: Side,
}

/// Where an escrow is. `Ended` is stored too: an ended escrow's account is never closed, so its
/// address is a permanent receipt that holds the final state and can never be reused.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Created; the funding has not been marked. The deposit account may already hold the amount.
    Open,
    /// `mark_funded` saw the deposit account holding the amount, at `funded_at`.
    Funded,
    /// Paid out. `outcome`, `funded_at`, `ended_at`, `to_seller` and `to_buyer` say how. Nothing
    /// more happens to it but late money going back to the buyer and rent above the minimum to
    /// the payer.
    Ended,
}

/// How an escrow ended: in the account once it has, and in the `Ended` event.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The buyer signed: everything to the seller.
    ReleasedToSeller,
    /// The seller signed: everything to the buyer.
    ReleasedToBuyer,
    /// Both signed a split.
    Split,
    /// The arbiter named at creation signed a split.
    Arbitrated,
    /// The timer set at creation was due, and someone sent everything to the side it names.
    TimerReleased,
}

/// Whether a party objected, and which. Stored as one byte: none 0, the buyer 1, the seller 2.
/// Its own byte, never read from a time: a zero clock must not read as "nobody objected".
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Objection {
    None,
    Buyer,
    Seller,
}

/// One escrow. Address: `["escrow", terms_hash]`, made from every term (`terms_hash`), so a
/// payment sent to it counts only toward a deal with exactly those terms; only the buyer or the
/// seller can open it. Never closed once it has ended: its deposit account closes and its rent
/// goes back, and this account stays as the receipt. Only an escrow that never held the amount is
/// closed (`close_unfunded`).
#[account]
pub struct Escrow {
    /// `crate::VERSION`. A v3 is a new program; this says which program's rules a record followed.
    pub version: u8,
    /// Chosen at creation; it tells apart two deals with the same terms. The app picks it at
    /// random.
    pub id: u64,
    pub buyer: Pubkey,
    pub seller: Pubkey,
    /// The zero key when no arbiter was named.
    pub arbiter: Pubkey,
    /// A mint of the classic SPL Token program or of Token-2022; whichever owns it is the token
    /// program every instruction here names. Not stored: a mint's owner never changes.
    pub mint: Pubkey,
    /// The deposit account: this escrow's associated token account for `mint`, under the mint's
    /// token program. Derivable from the escrow address and the mint, and recorded so a reader
    /// need not derive it.
    pub vault: Pubkey,
    /// Where every rent goes back: the deposit account's at every ending, and both at
    /// `close_unfunded`. The payer's key, the same as `payer`, kept in v1's place so the layout
    /// does not move.
    pub rent_recipient: Pubkey,
    /// The agreed amount, in the mint's base units. The escrow is funded once the deposit account
    /// holds at least this much; every way out then pays out the whole balance, whatever it is.
    pub amount: u64,
    /// Who opened it: the buyer, or the seller (an invoice).
    pub creator: Side,
    /// The timer's days, or 0 for no timer.
    pub timer_days: u16,
    /// The side the timer pays. Meaningless when `timer_days` is 0, and then stored as `Buyer`.
    pub timer_to: Side,
    pub created_at: i64,
    /// When the program first saw the deposit account holding the amount: `mark_funded`'s time,
    /// or, if nobody marked it, the ending's. 0 until one of them runs. The timer counts from the
    /// mark and from nothing else.
    pub funded_at: i64,
    pub status: Status,
    pub bump: u8,
    /// When it ended, or 0 while it has not.
    pub ended_at: i64,
    /// How it ended. Meaningful only when `status` is `Ended`; stored as 0 before.
    pub outcome: Outcome,
    /// What the seller and the buyer were paid at the end. `to_seller + to_buyer` is what the
    /// deposit account held. Zero before the end.
    pub to_seller: u64,
    pub to_buyer: u64,
    // ---- v2 from here on; everything above is v1's layout, byte for byte. ----
    /// The key that signed `create` as payer and fronted both rents. Every rent goes back here:
    /// through `rent_recipient`, and rent above the escrow account's minimum, which Solana's rent
    /// cuts free, by `sweep_rent`.
    pub payer: Pubkey,
    /// Which party objected, if one did. Once one has, the timer never runs.
    pub objection: Objection,
    /// When the objection was made, or 0. Read only for the record: `objection` says whether.
    pub objected_at: i64,
}

impl Escrow {
    /// version 0, id 1..9, buyer 9..41, seller 41..73, arbiter 73..105, mint 105..137,
    /// vault 137..169, rent_recipient 169..201, amount 201..209, creator 209, timer_days 210..212,
    /// timer_to 212, created_at 213..221, funded_at 221..229, status 229, bump 230,
    /// ended_at 231..239, outcome 239, to_seller 240..248, to_buyer 248..256, payer 256..288,
    /// objection 288, objected_at 289..297.
    pub const LEN: usize = 1 + 8 + 32 * 6 + 8 + 1 + 2 + 1 + 8 + 8 + 1 + 1 + 8 + 1 + 8 + 8 + 32 + 1 + 8;

    pub fn has_arbiter(&self) -> bool {
        self.arbiter != Pubkey::default()
    }

    pub fn has_timer(&self) -> bool {
        self.timer_days != 0
    }

    pub fn objected(&self) -> bool {
        self.objection != Objection::None
    }

    /// Open or funded: the only states any way out, `mark_funded`, `object` or `close_unfunded`
    /// runs from. An allowlist, so a state added later is refused by default.
    pub fn live(&self) -> bool {
        matches!(self.status, Status::Open | Status::Funded)
    }

    /// The seed of this escrow's address, rebuilt from the terms it stores: what every signature
    /// the escrow makes uses.
    pub fn terms_hash(&self) -> [u8; 32] {
        terms_hash(self.id, &self.buyer, &self.seller, &self.arbiter, &self.mint, self.amount, self.timer_days, self.timer_to)
    }

    /// The buyer's refund address: the buyer's associated token account for the mint, under the
    /// mint's token program, the one account any payout to the buyer lands in. Computed from two
    /// keys fixed at creation and the program that owns the mint (every caller has checked
    /// `token_program` is it), so nothing more is stored, and nobody who sends an instruction
    /// can name another.
    pub fn refund_address(&self, token_program: &Pubkey) -> Pubkey {
        anchor_spl::associated_token::get_associated_token_address_with_program_id(&self.buyer, &self.mint, token_program)
    }

    /// The seller's payout address: the seller's associated token account for the mint, the one
    /// account any payout to the seller lands in. The same rule as the buyer's.
    pub fn payout_address(&self, token_program: &Pubkey) -> Pubkey {
        anchor_spl::associated_token::get_associated_token_address_with_program_id(&self.seller, &self.mint, token_program)
    }

    /// When the timer is due: `timer_days` whole days after the funding was marked. `None` with no
    /// timer or unless the status is `Funded`. The one time gate in the program: `timer_release`
    /// runs from this second on, and `object` only before it. It reads the status, never a zero
    /// `funded_at`, to tell whether the funding was marked. It does not read the objection: each
    /// caller checks that itself, with its own error.
    pub fn timer_due(&self) -> Result<Option<i64>> {
        if !self.has_timer() || self.status != Status::Funded {
            return Ok(None);
        }
        let due = self
            .funded_at
            .checked_add(i64::from(self.timer_days) * SECONDS_PER_DAY)
            .ok_or_else(|| error!(EscrowError::TimeOverflow))?;
        Ok(Some(due))
    }
}

/// The seed an escrow's address is made from: SHA-256 of all its terms, each at a fixed length,
/// in the receipt's own order: id (8 bytes, little-endian), buyer, seller, arbiter (the zero key
/// for none) and mint (32 bytes each), amount (8, little-endian), the timer's days (2,
/// little-endian; 0 for none) and its side (1 byte: buyer 0, seller 1; the buyer's when there is
/// no timer). `create` refuses the zero key as arbiter and a timer of 0 days, so no two sets of
/// terms it accepts are hashed from the same bytes. The creator and the payer are not terms:
/// either party may open the same terms, and they land at the same address.
#[allow(clippy::too_many_arguments)]
pub fn terms_hash(id: u64, buyer: &Pubkey, seller: &Pubkey, arbiter: &Pubkey, mint: &Pubkey, amount: u64, timer_days: u16, timer_to: Side) -> [u8; 32] {
    let side = [match timer_to {
        Side::Buyer => 0u8,
        Side::Seller => 1,
    }];
    solana_sha256_hasher::hashv(&[
        &id.to_le_bytes(),
        buyer.as_ref(),
        seller.as_ref(),
        arbiter.as_ref(),
        mint.as_ref(),
        &amount.to_le_bytes(),
        &timer_days.to_le_bytes(),
        &side,
    ])
    .to_bytes()
}

/// `amount × bps / 10,000`, rounded down, in 128 bits so nothing overflows. `bps` is at most
/// 10,000 (checked by every caller), so the result is at most `amount` and fits back in 64 bits.
pub fn share(amount: u64, bps: u16) -> u64 {
    ((u128::from(amount) * u128::from(bps)) / u128::from(BPS)) as u64
}
