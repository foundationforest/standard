//! The harness, and the escrow's wire format (v2) written out a second time.
//!
//! Nothing here imports the program crate. The instruction bytes, the account layout, the event
//! layouts and the discriminators are written by hand, the way an outside client has to write
//! them, so a test passing means the sealed format really is what `src/lib.rs` and
//! `escrow/client` both say it is. A drift on either side fails a test instead of passing quietly.
//!
//! The classic suite runs on a six-decimal classic mint (`Harness::new`). `token_2022.rs` builds a
//! Token-2022 mint with Open USD's extensions and a transfer hook for the same harness
//! (`Harness::open_usd`); the free functions here default to the classic token program, and each
//! has an `_under` twin that names the token program.

pub mod token_2022;
pub use token_2022::*;

use std::path::PathBuf;
use std::sync::Mutex;

use litesvm::LiteSVM;
use sha2::{Digest, Sha256};
use solana_account::Account;
use solana_address::Address;
use solana_clock::Clock;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_rent::Rent;
use solana_signer::Signer;
use solana_transaction::Transaction;

pub const PROGRAM_ID: Address = solana_address::address!("FoRE2EscrowV2objectsTimerFundedAtPayer222222");
pub const TOKEN_PROGRAM: Address = solana_address::address!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
pub const TOKEN_2022_PROGRAM: Address = solana_address::address!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");
pub const ATA_PROGRAM: Address = solana_address::address!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
pub const SYSTEM_PROGRAM: Address = solana_address::address!("11111111111111111111111111111111");
pub const NATIVE_MINT: Address = solana_address::address!("So11111111111111111111111111111111111111112");
pub const NATIVE_MINT_2022: Address = solana_address::address!("9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP");

pub const VERSION: u8 = 2;
/// The escrow account: Anchor's eight-byte discriminator and 297 bytes of state (v1's 256, then
/// the payer, the objection and its time).
pub const ESCROW_LEN: usize = 8 + 297;
pub const BPS: u16 = 10_000;
pub const DAY: i64 = 86_400;

/// `amount × bps / 10,000`, rounded down. Written a second time here, by hand.
pub fn share(amount: u64, bps: u16) -> u64 {
    ((u128::from(amount) * u128::from(bps)) / u128::from(BPS)) as u64
}

// ---------------------------------------------------------------------------------------------
// The wire format.
// ---------------------------------------------------------------------------------------------

pub fn discriminator(namespace: &str, name: &str) -> [u8; 8] {
    let digest = Sha256::digest(format!("{namespace}:{name}").as_bytes());
    digest[..8].try_into().unwrap()
}

/// The seed of an escrow's address: SHA-256 of all its terms, each at a fixed length, in the
/// receipt's order. id (8, little-endian), buyer, seller, arbiter (the zero key for none), mint
/// (32 each), amount (8, little-endian), timer days (2, little-endian; 0 for none), timer side
/// (1: buyer 0, seller 1; the buyer's for no timer). Written here a second time, by hand.
pub fn terms_hash(t: &Terms, buyer: &Address, mint: &Address) -> [u8; 32] {
    let arbiter = t.arbiter.unwrap_or_default();
    let (days, to) = t.timer.map_or((0u16, Side::Buyer), |timer| (timer.days, timer.to));
    let mut h = Sha256::new();
    h.update(t.id.to_le_bytes());
    h.update(buyer.as_ref());
    h.update(t.seller.as_ref());
    h.update(arbiter.as_ref());
    h.update(mint.as_ref());
    h.update(t.amount.to_le_bytes());
    h.update(days.to_le_bytes());
    h.update([to as u8]);
    h.finalize().into()
}

/// The escrow's address: `["escrow", terms_hash]`. Every term is in it, so a payment to it counts
/// only toward a deal with exactly those terms. Who opens it is not a term.
pub fn escrow_address(t: &Terms, buyer: &Address, mint: &Address) -> Address {
    Address::find_program_address(&[b"escrow", &terms_hash(t, buyer, mint)], &PROGRAM_ID).0
}

/// An associated token account: the standard address of `owner`'s account for a classic `mint`.
pub fn ata_address(owner: &Address, mint: &Address) -> Address {
    ata_address_under(owner, mint, &TOKEN_PROGRAM)
}

/// The same under a named token program: the address depends on it.
pub fn ata_address_under(owner: &Address, mint: &Address, token_program: &Address) -> Address {
    Address::find_program_address(&[owner.as_ref(), token_program.as_ref(), mint.as_ref()], &ATA_PROGRAM).0
}

/// The deposit account: the escrow's associated token account for the mint.
pub fn vault_address(escrow: &Address, mint: &Address) -> Address {
    ata_address(escrow, mint)
}

/// The buyer's refund address: the buyer's associated token account for the mint. The only
/// account any payout to the buyer lands in.
pub fn refund_address(buyer: &Address, mint: &Address) -> Address {
    ata_address(buyer, mint)
}

/// The seller's payout address: the seller's associated token account for the mint. The only
/// account any payout to the seller lands in.
pub fn payout_address(seller: &Address, mint: &Address) -> Address {
    ata_address(seller, mint)
}

/// A party, as one byte: buyer 0, seller 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Buyer = 0,
    Seller = 1,
}

pub fn side_of(byte: u8) -> Side {
    match byte {
        0 => Side::Buyer,
        1 => Side::Seller,
        other => panic!("side byte {other}"),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timer {
    pub days: u16,
    pub to: Side,
}

#[derive(Clone, Debug)]
pub struct Terms {
    pub id: u64,
    pub seller: Address,
    pub amount: u64,
    pub arbiter: Option<Address>,
    pub timer: Option<Timer>,
}

/// The buyer, the key that fronts the rent (a fee payer, or anyone) and the mint. Who signs as
/// creator, `create_ix_by` takes; it is not in the address.
pub struct CreateAccounts {
    pub buyer: Address,
    pub payer: Address,
    pub mint: Address,
}

/// id u64, buyer, seller, amount u64, arbiter as an `Option` (0, or 1 then the key), timer as an
/// `Option` (0, or 1 then days u16 and the side as one byte).
pub fn create_args_bytes(t: &Terms, buyer: &Address) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&t.id.to_le_bytes());
    data.extend_from_slice(buyer.as_ref());
    data.extend_from_slice(t.seller.as_ref());
    data.extend_from_slice(&t.amount.to_le_bytes());
    match t.arbiter {
        Some(k) => {
            data.push(1);
            data.extend_from_slice(k.as_ref());
        }
        None => data.push(0),
    }
    match t.timer {
        Some(timer) => {
            data.push(1);
            data.extend_from_slice(&timer.days.to_le_bytes());
            data.push(timer.to as u8);
        }
        None => data.push(0),
    }
    data
}

/// `create` opened by the buyer.
pub fn create_ix(t: &Terms, a: &CreateAccounts) -> Instruction {
    create_ix_by(t, a, a.buyer)
}

/// `create` opened by the seller: an invoice.
pub fn invoice_ix(t: &Terms, a: &CreateAccounts) -> Instruction {
    create_ix_by(t, a, t.seller)
}

/// `create` with `creator` in the signer slot: escrow, vault, creator, payer, mint, token
/// program, associated token program, system program. The escrow's address is its terms'.
pub fn create_ix_by(t: &Terms, a: &CreateAccounts, creator: Address) -> Instruction {
    create_ix_under(t, a, creator, TOKEN_PROGRAM)
}

/// `create` under a named token program: the one that owns the mint. The deposit address is
/// derived under it.
pub fn create_ix_under(t: &Terms, a: &CreateAccounts, creator: Address, token_program: Address) -> Instruction {
    let escrow = escrow_address(t, &a.buyer, &a.mint);
    let mut data = discriminator("global", "create").to_vec();
    data.extend_from_slice(&create_args_bytes(t, &a.buyer));
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(escrow, false),
            AccountMeta::new(ata_address_under(&escrow, &a.mint, &token_program), false),
            AccountMeta::new_readonly(creator, true),
            AccountMeta::new(a.payer, true),
            AccountMeta::new_readonly(a.mint, false),
            AccountMeta::new_readonly(token_program, false),
            AccountMeta::new_readonly(ATA_PROGRAM, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
        data,
    }
}

/// `mark_funded`: escrow, vault. No signer beyond the transaction's fee payer.
pub fn mark_funded_ix(escrow: Address, vault: Address) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![AccountMeta::new(escrow, false), AccountMeta::new_readonly(vault, false)],
        data: discriminator("global", "mark_funded").to_vec(),
    }
}

/// The accounts the ways out touch. Each instruction takes the ones it pays, in this order:
/// escrow, vault, mint, buyer_tokens, seller_tokens, rent_recipient, token program, then its
/// signers, then any accounts a transfer hook needs. `buyer_tokens` and `seller_tokens` must be
/// the parties' standard token accounts, `rent_recipient` the payer, and `token_program` the
/// mint's owner; tests put other accounts there to see them refused.
#[derive(Clone, Copy, Debug)]
pub struct Accounts {
    pub escrow: Address,
    pub vault: Address,
    pub mint: Address,
    pub buyer_tokens: Address,
    pub seller_tokens: Address,
    pub rent_recipient: Address,
    pub token_program: Address,
}

fn ix(name: &str, metas: Vec<AccountMeta>, args: &[u8]) -> Instruction {
    let mut data = discriminator("global", name).to_vec();
    data.extend_from_slice(args);
    Instruction { program_id: PROGRAM_ID, accounts: metas, data }
}

/// `release_to_seller`: escrow, vault, mint, seller_tokens, rent_recipient, token program, buyer
/// (signs).
pub fn release_to_seller_ix(s: &Accounts, buyer: Address) -> Instruction {
    ix(
        "release_to_seller",
        vec![
            AccountMeta::new(s.escrow, false),
            AccountMeta::new(s.vault, false),
            AccountMeta::new_readonly(s.mint, false),
            AccountMeta::new(s.seller_tokens, false),
            AccountMeta::new(s.rent_recipient, false),
            AccountMeta::new_readonly(s.token_program, false),
            AccountMeta::new_readonly(buyer, true),
        ],
        &[],
    )
}

/// `release_to_buyer`: escrow, vault, mint, buyer_tokens, rent_recipient, token program, seller
/// (signs).
pub fn release_to_buyer_ix(s: &Accounts, seller: Address) -> Instruction {
    ix(
        "release_to_buyer",
        vec![
            AccountMeta::new(s.escrow, false),
            AccountMeta::new(s.vault, false),
            AccountMeta::new_readonly(s.mint, false),
            AccountMeta::new(s.buyer_tokens, false),
            AccountMeta::new(s.rent_recipient, false),
            AccountMeta::new_readonly(s.token_program, false),
            AccountMeta::new_readonly(seller, true),
        ],
        &[],
    )
}

fn both_metas(s: &Accounts) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(s.escrow, false),
        AccountMeta::new(s.vault, false),
        AccountMeta::new_readonly(s.mint, false),
        AccountMeta::new(s.buyer_tokens, false),
        AccountMeta::new(s.seller_tokens, false),
        AccountMeta::new(s.rent_recipient, false),
        AccountMeta::new_readonly(s.token_program, false),
    ]
}

/// `split(seller_bps)`: escrow, vault, mint, buyer_tokens, seller_tokens, rent_recipient, token
/// program, buyer and seller (both sign).
pub fn split_ix(s: &Accounts, buyer: Address, seller: Address, seller_bps: u16) -> Instruction {
    let mut metas = both_metas(s);
    metas.push(AccountMeta::new_readonly(buyer, true));
    metas.push(AccountMeta::new_readonly(seller, true));
    ix("split", metas, &seller_bps.to_le_bytes())
}

/// `arbitrate(seller_bps)`: the same accounts as `split`, and the arbiter signs.
pub fn arbitrate_ix(s: &Accounts, arbiter: Address, seller_bps: u16) -> Instruction {
    let mut metas = both_metas(s);
    metas.push(AccountMeta::new_readonly(arbiter, true));
    ix("arbitrate", metas, &seller_bps.to_le_bytes())
}

/// `timer_release`: escrow, vault, mint, to (the named side's standard account), rent_recipient,
/// token program. No signer beyond the transaction's fee payer.
pub fn timer_release_ix(escrow: Address, vault: Address, mint: Address, to: Address, rent_recipient: Address) -> Instruction {
    timer_release_ix_under(escrow, vault, mint, to, rent_recipient, TOKEN_PROGRAM)
}

pub fn timer_release_ix_under(escrow: Address, vault: Address, mint: Address, to: Address, rent_recipient: Address, token_program: Address) -> Instruction {
    ix(
        "timer_release",
        vec![
            AccountMeta::new(escrow, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(to, false),
            AccountMeta::new(rent_recipient, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        &[],
    )
}

/// `close_unfunded`: escrow, vault, mint, buyer_tokens, rent_recipient, token program, closer
/// (signs).
pub fn close_unfunded_ix(s: &Accounts, closer: Address) -> Instruction {
    ix(
        "close_unfunded",
        vec![
            AccountMeta::new(s.escrow, false),
            AccountMeta::new(s.vault, false),
            AccountMeta::new_readonly(s.mint, false),
            AccountMeta::new(s.buyer_tokens, false),
            AccountMeta::new(s.rent_recipient, false),
            AccountMeta::new_readonly(s.token_program, false),
            AccountMeta::new_readonly(closer, true),
        ],
        &[],
    )
}

/// `recover_late`: escrow, vault, buyer, refund, mint, caller (signs, pays for the refund account
/// if it has to be made), token program, associated token program, system program.
pub fn recover_late_ix(escrow: Address, vault: Address, buyer: Address, mint: Address, caller: Address) -> Instruction {
    recover_late_ix_to(escrow, vault, buyer, refund_address(&buyer, &mint), mint, caller)
}

/// `recover_late` naming any refund account: for tests that try another one.
pub fn recover_late_ix_to(escrow: Address, vault: Address, buyer: Address, refund: Address, mint: Address, caller: Address) -> Instruction {
    recover_late_ix_under(escrow, vault, buyer, refund, mint, caller, TOKEN_PROGRAM)
}

pub fn recover_late_ix_under(escrow: Address, vault: Address, buyer: Address, refund: Address, mint: Address, caller: Address, token_program: Address) -> Instruction {
    ix(
        "recover_late",
        vec![
            AccountMeta::new_readonly(escrow, false),
            AccountMeta::new(vault, false),
            AccountMeta::new(buyer, false),
            AccountMeta::new(refund, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(caller, true),
            AccountMeta::new_readonly(token_program, false),
            AccountMeta::new_readonly(ATA_PROGRAM, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
        &[],
    )
}

/// `sweep_rent`: escrow, payer (the key that fronted the rent). No signer beyond the transaction's
/// fee payer.
pub fn sweep_rent_ix(escrow: Address, payer: Address) -> Instruction {
    ix("sweep_rent", vec![AccountMeta::new(escrow, false), AccountMeta::new(payer, false)], &[])
}

/// `object`: escrow, party (signs). No data.
pub fn object_ix(escrow: Address, party: Address) -> Instruction {
    ix("object", vec![AccountMeta::new(escrow, false), AccountMeta::new_readonly(party, true)], &[])
}

/// A plain SPL Token transfer, the way any wallet app funds the deposit account: instruction 3,
/// amount u64; source, destination, owner.
pub fn spl_transfer_ix(from: Address, to: Address, owner: Address, amount: u64) -> Instruction {
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: TOKEN_PROGRAM,
        accounts: vec![
            AccountMeta::new(from, false),
            AccountMeta::new(to, false),
            AccountMeta::new_readonly(owner, true),
        ],
        data,
    }
}

/// A `transfer_checked` (instruction 12, amount u64, decimals u8): source, mint, destination,
/// owner. The only transfer a Token-2022 account with a transfer hook extension accepts.
pub fn spl_transfer_checked_ix(from: Address, mint: Address, to: Address, owner: Address, amount: u64, decimals: u8, token_program: Address) -> Instruction {
    let mut data = vec![12u8];
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id: token_program,
        accounts: vec![
            AccountMeta::new(from, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(to, false),
            AccountMeta::new_readonly(owner, true),
        ],
        data,
    }
}

/// The associated token program's `CreateIdempotent` (instruction 1): what a wallet app sends
/// before paying an address whose token account does not exist. Payer, account, owner, mint,
/// system, token. Returns the account's address too.
pub fn create_ata_idempotent_ix(payer: Address, owner: Address, mint: Address) -> (Instruction, Address) {
    create_ata_idempotent_ix_under(payer, owner, mint, TOKEN_PROGRAM)
}

pub fn create_ata_idempotent_ix_under(payer: Address, owner: Address, mint: Address, token_program: Address) -> (Instruction, Address) {
    let ata = ata_address_under(&owner, &mint, &token_program);
    let ix = Instruction {
        program_id: ATA_PROGRAM,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(ata, false),
            AccountMeta::new_readonly(owner, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(token_program, false),
        ],
        data: vec![1],
    };
    (ix, ata)
}

/// A plain SOL transfer: the system program's instruction 2.
pub fn sol_transfer_ix(from: Address, to: Address, lamports: u64) -> Instruction {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction {
        program_id: SYSTEM_PROGRAM,
        accounts: vec![AccountMeta::new(from, true), AccountMeta::new(to, false)],
        data,
    }
}

/// The Rent sysvar at a given rate. The rent-exempt minimum of an account of `n` bytes is then
/// `(128 + n) × lamports_per_byte`.
pub fn rent_at(lamports_per_byte: u64) -> Rent {
    let mut rent = Rent::default();
    rent.lamports_per_byte = lamports_per_byte;
    rent
}

/// Lamports per byte where SIMD-0437's cuts end.
pub const RENT_FINAL: u64 = 696;

// ---------------------------------------------------------------------------------------------
// The account layout, read back out of the raw bytes.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Open = 0,
    Funded = 1,
    Ended = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    ReleasedToSeller = 0,
    ReleasedToBuyer = 1,
    Split = 2,
    Arbitrated = 3,
    TimerReleased = 4,
}

pub fn outcome_of(byte: u8) -> Outcome {
    match byte {
        0 => Outcome::ReleasedToSeller,
        1 => Outcome::ReleasedToBuyer,
        2 => Outcome::Split,
        3 => Outcome::Arbitrated,
        4 => Outcome::TimerReleased,
        other => panic!("outcome byte {other}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowView {
    pub version: u8,
    pub id: u64,
    pub buyer: Address,
    pub seller: Address,
    /// The zero key when none.
    pub arbiter: Address,
    pub mint: Address,
    pub vault: Address,
    /// The payer's key: every rent goes back here.
    pub rent_recipient: Address,
    pub amount: u64,
    pub creator: Side,
    /// `None` when `timer_days` is 0.
    pub timer: Option<Timer>,
    pub created_at: i64,
    /// The mark's time, or the ending's if nobody marked it; 0 until one of them.
    pub funded_at: i64,
    pub status: Status,
    pub bump: u8,
    /// 0 until it ends.
    pub ended_at: i64,
    /// `None` until it ends.
    pub outcome: Option<Outcome>,
    pub to_seller: u64,
    pub to_buyer: u64,
    /// The key that fronted the rent: every sweep goes here.
    pub payer: Address,
    /// Which side objected, or `None`.
    pub objection: Option<Side>,
    /// 0 unless a side objected.
    pub objected_at: i64,
}

/// version 0, id 1..9, buyer 9..41, seller 41..73, arbiter 73..105, mint 105..137, vault 137..169,
/// rent_recipient 169..201, amount 201..209, creator 209, timer_days 210..212, timer_to 212,
/// created_at 213..221, funded_at 221..229, status 229, bump 230, ended_at 231..239, outcome 239,
/// to_seller 240..248, to_buyer 248..256, payer 256..288, objection 288 (none 0, buyer 1,
/// seller 2), objected_at 289..297.
pub fn read_escrow(data: &[u8]) -> EscrowView {
    assert_eq!(data.len(), ESCROW_LEN);
    assert_eq!(data[..8], discriminator("account", "Escrow"));
    let b = &data[8..];
    let key = |at: usize| Address::try_from(&b[at..at + 32]).unwrap();
    let u64_at = |at: usize| u64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let i64_at = |at: usize| i64::from_le_bytes(b[at..at + 8].try_into().unwrap());
    let timer_days = u16::from_le_bytes(b[210..212].try_into().unwrap());
    let timer_to = side_of(b[212]);
    let status = match b[229] {
        0 => Status::Open,
        1 => Status::Funded,
        2 => Status::Ended,
        other => panic!("status byte {other}"),
    };
    EscrowView {
        version: b[0],
        id: u64_at(1),
        buyer: key(9),
        seller: key(41),
        arbiter: key(73),
        mint: key(105),
        vault: key(137),
        rent_recipient: key(169),
        amount: u64_at(201),
        creator: side_of(b[209]),
        timer: if timer_days == 0 {
            assert_eq!(timer_to, Side::Buyer, "no timer is stored as buyer");
            None
        } else {
            Some(Timer { days: timer_days, to: timer_to })
        },
        created_at: i64_at(213),
        funded_at: i64_at(221),
        status,
        bump: b[230],
        ended_at: i64_at(231),
        outcome: if status == Status::Ended { Some(outcome_of(b[239])) } else { None },
        to_seller: u64_at(240),
        to_buyer: u64_at(248),
        payer: key(256),
        objection: match b[288] {
            0 => None,
            1 => Some(Side::Buyer),
            2 => Some(Side::Seller),
            other => panic!("objection byte {other}"),
        },
        objected_at: i64_at(289),
    }
}

pub fn token_amount(data: &[u8]) -> u64 {
    u64::from_le_bytes(data[64..72].try_into().unwrap())
}

// ---------------------------------------------------------------------------------------------
// Events, decoded from the `Program data:` lines Anchor writes.
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Created {
        escrow: Address,
        version: u8,
        id: u64,
        buyer: Address,
        seller: Address,
        creator: Side,
        arbiter: Address,
        mint: Address,
        vault: Address,
        rent_recipient: Address,
        amount: u64,
        timer_days: u16,
        timer_to: Side,
        created_at: i64,
        payer: Address,
    },
    Funded { escrow: Address, balance: u64, funded_at: i64 },
    Ended {
        escrow: Address,
        outcome: Outcome,
        amount: u64,
        balance: u64,
        to_seller: u64,
        to_buyer: u64,
        ended_at: i64,
        rent_recipient: Address,
        rent_lamports: u64,
        funded_at: i64,
    },
    Closed { escrow: Address, closed_by: Address, to_buyer: u64, rent_recipient: Address, rent_lamports: u64 },
    RecoveredLate { escrow: Address, to_buyer: u64, rent_lamports: u64 },
    RentSwept { escrow: Address, payer: Address, lamports: u64, left: u64 },
    Objected { escrow: Address, by: Side, objected_at: i64 },
}

impl Event {
    pub fn name(&self) -> &'static str {
        match self {
            Event::Created { .. } => "Created",
            Event::Funded { .. } => "Funded",
            Event::Ended { .. } => "Ended",
            Event::Closed { .. } => "Closed",
            Event::RecoveredLate { .. } => "RecoveredLate",
            Event::RentSwept { .. } => "RentSwept",
            Event::Objected { .. } => "Objected",
        }
    }
}

struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> u8 {
        let v = self.b[self.at];
        self.at += 1;
        v
    }
    fn u16(&mut self) -> u16 {
        let v = u16::from_le_bytes(self.b[self.at..self.at + 2].try_into().unwrap());
        self.at += 2;
        v
    }
    fn u64(&mut self) -> u64 {
        let v = u64::from_le_bytes(self.b[self.at..self.at + 8].try_into().unwrap());
        self.at += 8;
        v
    }
    fn i64(&mut self) -> i64 {
        self.u64() as i64
    }
    fn key(&mut self) -> Address {
        let v = Address::try_from(&self.b[self.at..self.at + 32]).unwrap();
        self.at += 32;
        v
    }
    fn done(&self) {
        assert_eq!(self.at, self.b.len(), "an event has trailing bytes");
    }
}

const EVENT_NAMES: [&str; 7] = ["Created", "Funded", "Ended", "Closed", "RecoveredLate", "RentSwept", "Objected"];

pub fn events(logs: &[String]) -> Vec<Event> {
    let mut out = Vec::new();
    for line in logs {
        let Some(payload) = line.strip_prefix("Program data: ") else { continue };
        let Ok(bytes) = base64_decode(payload) else { continue };
        if bytes.len() < 8 {
            continue;
        }
        let Some(name) = EVENT_NAMES.iter().find(|n| discriminator("event", n) == bytes[..8]) else {
            continue;
        };
        let mut c = Cursor { b: &bytes[8..], at: 0 };
        let escrow = c.key();
        let event = match *name {
            "Created" => Event::Created {
                escrow,
                version: c.u8(),
                id: c.u64(),
                buyer: c.key(),
                seller: c.key(),
                creator: side_of(c.u8()),
                arbiter: c.key(),
                mint: c.key(),
                vault: c.key(),
                rent_recipient: c.key(),
                amount: c.u64(),
                timer_days: c.u16(),
                timer_to: side_of(c.u8()),
                created_at: c.i64(),
                payer: c.key(),
            },
            "Funded" => Event::Funded { escrow, balance: c.u64(), funded_at: c.i64() },
            "Ended" => Event::Ended {
                escrow,
                outcome: outcome_of(c.u8()),
                amount: c.u64(),
                balance: c.u64(),
                to_seller: c.u64(),
                to_buyer: c.u64(),
                ended_at: c.i64(),
                rent_recipient: c.key(),
                rent_lamports: c.u64(),
                funded_at: c.i64(),
            },
            "Closed" => Event::Closed {
                escrow,
                closed_by: c.key(),
                to_buyer: c.u64(),
                rent_recipient: c.key(),
                rent_lamports: c.u64(),
            },
            "RecoveredLate" => Event::RecoveredLate { escrow, to_buyer: c.u64(), rent_lamports: c.u64() },
            "RentSwept" => Event::RentSwept { escrow, payer: c.key(), lamports: c.u64(), left: c.u64() },
            "Objected" => Event::Objected { escrow, by: side_of(c.u8()), objected_at: c.i64() },
            _ => unreachable!(),
        };
        c.done();
        out.push(event);
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for ch in s.bytes() {
        if ch == b'=' {
            break;
        }
        let Some(v) = TABLE.iter().position(|c| *c == ch) else { return Err(()) };
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

/// The `Ended` event in a list: outcome, balance, to the seller, to the buyer, rent returned.
pub fn ended(events: &[Event]) -> (Outcome, u64, u64, u64, u64) {
    let Some(Event::Ended { outcome, balance, to_seller, to_buyer, rent_lamports, .. }) =
        events.iter().find(|e| e.name() == "Ended")
    else {
        panic!("no Ended event in {events:?}")
    };
    (*outcome, *balance, *to_seller, *to_buyer, *rent_lamports)
}

pub fn names(events: &[Event]) -> Vec<&'static str> {
    events.iter().map(|e| e.name()).collect()
}

// ---------------------------------------------------------------------------------------------
// Compute units, gathered across a test run and printed by `zz_cu_summary`.
// ---------------------------------------------------------------------------------------------

pub static CU_RESULTS: Mutex<Vec<(String, u64, usize)>> = Mutex::new(Vec::new());

pub fn record_cu(label: &str, cu: u64, bytes: usize) {
    CU_RESULTS.lock().unwrap().push((label.to_string(), cu, bytes));
}

pub fn print_cu_summary() {
    let results = CU_RESULTS.lock().unwrap();
    if results.is_empty() {
        println!("no compute units recorded (run with --test-threads=1 so the summary runs last)");
        return;
    }
    println!("\n== compute units and bytes, a legacy transaction with a compute-budget instruction ==");
    for (label, cu, bytes) in results.iter() {
        println!(
            "   {label:<52} {cu:>7} compute units ({:.1}% of 1,400,000)   {bytes:>4} bytes ({:.0}% of 1,232)",
            *cu as f64 / 1_400_000.0 * 100.0,
            *bytes as f64 / 1232.0 * 100.0
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The harness.
// ---------------------------------------------------------------------------------------------

pub fn spl_mint_account(decimals: u8, owner: Address) -> Account {
    let mut d = vec![0u8; 82];
    d[44] = decimals;
    d[45] = 1; // is_initialized
    Account { lamports: 1_461_600, data: d, owner, executable: false, rent_epoch: 0 }
}

pub fn spl_token_account(mint: &Address, owner: &Address, amount: u64) -> Account {
    let mut d = vec![0u8; 165];
    d[..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1; // state: Initialized
    Account { lamports: 2_039_280, data: d, owner: TOKEN_PROGRAM, executable: false, rent_epoch: 0 }
}

/// Ten dollars at six decimals: what the buyer starts with.
pub const BUYER_START: u64 = 10_000_000;
/// 1.00 at six decimals: the standard deal's amount.
pub const AMOUNT: u64 = 1_000_000;
/// A Monday noon, in unix seconds, where every test's clock starts.
pub const T0: i64 = 1_800_000_000;

pub struct Harness {
    pub svm: LiteSVM,
    /// The transaction fee payer, and the key that fronts every rent: a fee payer service's role.
    /// Every rent comes back to it.
    pub payer: Keypair,
    pub buyer: Keypair,
    pub seller: Keypair,
    pub arbiter: Keypair,
    /// A six-decimal mint: classic (`new`), or Token-2022 with Open USD's extensions (`open_usd`).
    pub mint: Address,
    /// The program that owns the mint.
    pub token_program: Address,
    pub decimals: u8,
    /// The token's maker, for a Token-2022 mint: the keys behind its authorities.
    pub issuer: Option<Issuer>,
    /// The account the buyer pays from: one it owns, but not its standard account. Payouts never
    /// land here; they land at the refund address (`refund()`), which the harness makes empty.
    pub buyer_tokens: Address,
    /// The seller's standard account for the mint, empty and ready: the only account a payout to
    /// the seller lands in.
    pub seller_tokens: Address,
    /// Another token account the seller holds for the mint, not its standard one. Never paid.
    pub seller_other: Address,
}

/// The escrow program loaded, and the four keys funded: what both harnesses start from.
fn bare() -> (LiteSVM, Keypair, Keypair, Keypair, Keypair) {
    let so = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/forest_escrow.so");
    let bytes = std::fs::read(&so).unwrap_or_else(|e| {
        panic!("{}: {e}. Build it first: `cargo build-sbf` in escrow/program.", so.display())
    });
    let mut svm = LiteSVM::new();
    svm.add_program(PROGRAM_ID, &bytes).unwrap();

    let payer = Keypair::new();
    let buyer = Keypair::new();
    let seller = Keypair::new();
    let arbiter = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
    svm.airdrop(&buyer.pubkey(), 10_000_000_000).unwrap();
    svm.airdrop(&seller.pubkey(), 10_000_000_000).unwrap();
    svm.airdrop(&arbiter.pubkey(), 1_000_000_000).unwrap();
    (svm, payer, buyer, seller, arbiter)
}

impl Harness {
    /// A six-decimal classic SPL Token mint, its accounts written straight into the ledger.
    pub fn new() -> Self {
        let (mut svm, payer, buyer, seller, arbiter) = bare();
        let mint = Address::new_unique();
        svm.set_account(mint, spl_mint_account(6, TOKEN_PROGRAM)).unwrap();
        let buyer_tokens = Address::new_unique();
        svm.set_account(buyer_tokens, spl_token_account(&mint, &buyer.pubkey(), BUYER_START)).unwrap();
        // The buyer's refund address, its standard account for the mint, empty and ready.
        svm.set_account(refund_address(&buyer.pubkey(), &mint), spl_token_account(&mint, &buyer.pubkey(), 0)).unwrap();
        let seller_tokens = payout_address(&seller.pubkey(), &mint);
        svm.set_account(seller_tokens, spl_token_account(&mint, &seller.pubkey(), 0)).unwrap();
        let seller_other = Address::new_unique();
        svm.set_account(seller_other, spl_token_account(&mint, &seller.pubkey(), 0)).unwrap();

        let mut h = Harness {
            svm,
            payer,
            buyer,
            seller,
            arbiter,
            mint,
            token_program: TOKEN_PROGRAM,
            decimals: 6,
            issuer: None,
            buyer_tokens,
            seller_tokens,
            seller_other,
        };
        h.set_time(T0);
        h
    }

    /// A Token-2022 mint with every extension Open USD has on mainnet, made by Token-2022's own
    /// instructions (`token_2022.rs`), and the same accounts as `new`: the buyer's non-standard
    /// account holding ten dollars, both parties' standard accounts empty, a second seller account.
    /// `hook` sets the transfer hook's program: none, as Open USD has it, or the test hook.
    pub fn open_usd(hook: HookProgram) -> Self {
        let (svm, payer, buyer, seller, arbiter) = bare();
        let mut h = Harness {
            svm,
            payer,
            buyer,
            seller,
            arbiter,
            mint: Address::default(),
            token_program: TOKEN_2022_PROGRAM,
            decimals: 6,
            issuer: None,
            buyer_tokens: Address::default(),
            seller_tokens: Address::default(),
            seller_other: Address::default(),
        };
        h.set_time(T0);
        token_2022::make_open_usd(&mut h, hook);
        h
    }

    // -- time --

    pub fn now(&self) -> i64 {
        self.svm.get_sysvar::<Clock>().unix_timestamp
    }

    pub fn set_time(&mut self, unix: i64) {
        let mut clock = self.svm.get_sysvar::<Clock>();
        clock.unix_timestamp = unix;
        clock.slot += 1;
        self.svm.set_sysvar(&clock);
    }

    pub fn advance(&mut self, seconds: i64) {
        let now = self.now();
        self.set_time(now + seconds);
    }

    // -- sending --

    pub fn send(&mut self, ixs: &[Instruction], signers: &[&Keypair]) -> Result<litesvm::types::TransactionMetadata, String> {
        self.svm.expire_blockhash();
        let mut keys: Vec<&Keypair> = vec![&self.payer];
        keys.extend_from_slice(signers);
        let msg = Message::new(ixs, Some(&self.payer.pubkey()));
        let tx = Transaction::new(&keys, msg, self.svm.latest_blockhash());
        self.send_tx(tx)
    }

    pub fn send_tx(&mut self, tx: Transaction) -> Result<litesvm::types::TransactionMetadata, String> {
        let result = match self.svm.send_transaction(tx) {
            Ok(meta) => Ok(meta),
            Err(e) => Err(format!("{:?}\n{}", e.err, e.meta.logs.join("\n"))),
        };
        self.svm.expire_blockhash();
        result
    }

    /// Sends `ixs` behind a compute-budget instruction, and returns the compute units the
    /// transaction used and its size on the wire. Panics if it fails.
    pub fn measure(&mut self, what: &str, ixs: &[Instruction], signers: &[&Keypair]) -> (u64, usize, Vec<Event>) {
        let mut all = vec![solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(200_000)];
        all.extend_from_slice(ixs);
        self.svm.expire_blockhash();
        let msg = Message::new(&all, Some(&self.payer.pubkey()));
        let mut keys: Vec<&Keypair> = vec![&self.payer];
        keys.extend_from_slice(signers);
        let tx = Transaction::new(&keys, msg, self.svm.latest_blockhash());
        let bytes = bincode::serialize(&tx).unwrap().len();
        let meta = self.send_tx(tx).unwrap_or_else(|e| panic!("{what}: {e}"));
        let cu = meta.compute_units_consumed;
        assert!(bytes <= 1232, "{what}: {bytes} bytes does not fit one transaction");
        assert!(cu < 200_000, "{what}: {cu} compute units");
        record_cu(what, cu, bytes);
        (cu, bytes, events(&meta.logs))
    }

    // -- the standard deal --

    /// Terms with every option off: 1.00 of the mint, no arbiter, no timer.
    pub fn terms(&self, id: u64) -> Terms {
        Terms { id, seller: self.seller.pubkey(), amount: AMOUNT, arbiter: None, timer: None }
    }

    pub fn create_accounts(&self) -> CreateAccounts {
        CreateAccounts { buyer: self.buyer.pubkey(), payer: self.payer.pubkey(), mint: self.mint }
    }

    /// `create` by `creator`, under the harness's token program.
    pub fn create_ix(&self, t: &Terms, creator: Address) -> Instruction {
        create_ix_under(t, &self.create_accounts(), creator, self.token_program)
    }

    /// The address of an escrow with these terms, the harness's buyer and its mint.
    pub fn address(&self, t: &Terms) -> Address {
        escrow_address(t, &self.buyer.pubkey(), &self.mint)
    }

    /// `create`, signed by the buyer and the payer. Returns the escrow address.
    pub fn create(&mut self, t: &Terms) -> Result<(Address, litesvm::types::TransactionMetadata), String> {
        let buyer = self.buyer.insecure_clone();
        let meta = self.send(&[self.create_ix(t, buyer.pubkey())], &[&buyer])?;
        Ok((self.address(t), meta))
    }

    /// `create`, opened by the seller as an invoice, signed by the seller and the payer. Returns
    /// the escrow address: the same as the buyer's with the same terms.
    pub fn invoice(&mut self, t: &Terms) -> Result<(Address, litesvm::types::TransactionMetadata), String> {
        let seller = self.seller.insecure_clone();
        let meta = self.send(&[self.create_ix(t, seller.pubkey())], &[&seller])?;
        Ok((self.address(t), meta))
    }

    /// The buyer's transfer of `amount` into the deposit account: a plain transfer for the classic
    /// mint, the way any wallet app pays; a `transfer_checked` carrying the hook's accounts for
    /// Token-2022, the only transfer its accounts take.
    pub fn fund_ix(&self, escrow: &Address, amount: u64) -> Instruction {
        let vault = self.vault(escrow);
        if self.token_program == TOKEN_PROGRAM {
            return spl_transfer_ix(self.buyer_tokens, vault, self.buyer.pubkey(), amount);
        }
        let ix = spl_transfer_checked_ix(self.buyer_tokens, self.mint, vault, self.buyer.pubkey(), amount, self.decimals, self.token_program);
        self.with_hook(ix, self.buyer_tokens, &[vault], self.buyer.pubkey())
    }

    /// A plain transfer from the buyer's token account into the deposit account.
    pub fn fund(&mut self, escrow: &Address, amount: u64) {
        let ix = self.fund_ix(escrow, amount);
        let buyer = self.buyer.insecure_clone();
        self.send(&[ix], &[&buyer]).expect("fund");
    }

    pub fn mark_funded(&mut self, escrow: &Address) -> Result<litesvm::types::TransactionMetadata, String> {
        let vault = self.vault(escrow);
        self.send(&[mark_funded_ix(*escrow, vault)], &[])
    }

    /// Created by the buyer and funded with exactly the amount by a plain transfer, at the current
    /// time. Not marked: no way out needs it.
    pub fn funded(&mut self, t: &Terms) -> Address {
        let (escrow, _) = self.create(t).expect("create");
        self.fund(&escrow, t.amount);
        escrow
    }

    /// The same, and marked funded.
    pub fn marked(&mut self, t: &Terms) -> Address {
        let escrow = self.funded(t);
        self.mark_funded(&escrow).expect("mark_funded");
        escrow
    }

    /// The escrow's deposit address for the harness's mint.
    pub fn vault(&self, escrow: &Address) -> Address {
        ata_address_under(escrow, &self.mint, &self.token_program)
    }

    /// The buyer's refund address for the harness's mint.
    pub fn refund(&self) -> Address {
        ata_address_under(&self.buyer.pubkey(), &self.mint, &self.token_program)
    }

    /// What the buyer holds across the account it pays from and its refund address.
    pub fn buyer_total(&self) -> u64 {
        self.balance(&self.buyer_tokens) + if self.exists(&self.refund()) { self.balance(&self.refund()) } else { 0 }
    }

    /// Take away the buyer's (empty) refund address, as a buyer who closed it would, so a test can
    /// see it made again, or see it is not needed.
    pub fn drop_refund(&mut self) {
        let refund = self.refund();
        assert_eq!(self.balance(&refund), 0, "only an empty account can be closed");
        self.svm.set_account(refund, Account::default()).unwrap();
        assert!(!self.exists(&refund));
    }

    /// `recover_late`, sent and paid for by `caller`.
    pub fn recover_late(&mut self, escrow: &Address, caller: &Keypair) -> Result<litesvm::types::TransactionMetadata, String> {
        let vault = self.vault(escrow);
        let ix = recover_late_ix_under(*escrow, vault, self.buyer.pubkey(), self.refund(), self.mint, caller.pubkey(), self.token_program);
        let ix = self.with_hook(ix, vault, &[self.refund()], *escrow);
        self.send(&[ix], &[caller])
    }

    /// `sweep_rent` to the escrow's recorded payer, with nobody but the fee payer signing.
    pub fn sweep(&mut self, escrow: &Address) -> Result<litesvm::types::TransactionMetadata, String> {
        let to = self.escrow(escrow).payer;
        self.send(&[sweep_rent_ix(*escrow, to)], &[])
    }

    /// `object`, signed by `party`.
    pub fn object(&mut self, escrow: &Address, party: &Keypair) -> Result<litesvm::types::TransactionMetadata, String> {
        self.send(&[object_ix(*escrow, party.pubkey())], &[party])
    }

    /// The accounts a way out names, all the right ones: the parties' standard accounts and the
    /// rent recipient the escrow records (the harness's payer, for an escrow not made yet).
    pub fn accounts(&self, escrow: &Address) -> Accounts {
        let rent_recipient = match self.svm.get_account(escrow) {
            Some(a) if a.lamports > 0 && a.data.len() == ESCROW_LEN => read_escrow(&a.data).rent_recipient,
            _ => self.payer.pubkey(),
        };
        Accounts {
            escrow: *escrow,
            vault: self.vault(escrow),
            mint: self.mint,
            buyer_tokens: self.refund(),
            seller_tokens: self.seller_tokens,
            rent_recipient,
            token_program: self.token_program,
        }
    }

    /// `ix`, one of the escrow's ways out or a wallet app's transfer, with the accounts the mint's
    /// transfer hook needs appended for a transfer from `source` to each of `destinations` by
    /// `authority`, resolved from the ledger by `spl-transfer-hook-interface`'s own client code,
    /// the way an app resolves them. Unchanged when the mint names no hook program.
    pub fn with_hook(&self, mut ix: Instruction, source: Address, destinations: &[Address], authority: Address) -> Instruction {
        let Some(hook) = token_2022::hook_program_of(&self.svm, &self.mint) else { return ix };
        for destination in destinations {
            token_2022::resolve_hook_accounts(&self.svm, &mut ix, &hook, &source, &self.mint, destination, &authority);
        }
        ix
    }

    // -- the ways out, signed by the right keys --

    pub fn release_to_seller_ix(&self, escrow: &Address) -> Instruction {
        let s = self.accounts(escrow);
        self.with_hook(release_to_seller_ix(&s, self.buyer.pubkey()), s.vault, &[s.seller_tokens], *escrow)
    }

    pub fn release_to_seller(&mut self, escrow: &Address) -> Result<litesvm::types::TransactionMetadata, String> {
        let buyer = self.buyer.insecure_clone();
        let ix = self.release_to_seller_ix(escrow);
        self.send(&[ix], &[&buyer])
    }

    pub fn release_to_buyer(&mut self, escrow: &Address) -> Result<litesvm::types::TransactionMetadata, String> {
        let seller = self.seller.insecure_clone();
        let s = self.accounts(escrow);
        let ix = self.with_hook(release_to_buyer_ix(&s, seller.pubkey()), s.vault, &[s.buyer_tokens], *escrow);
        self.send(&[ix], &[&seller])
    }

    pub fn split(&mut self, escrow: &Address, seller_bps: u16) -> Result<litesvm::types::TransactionMetadata, String> {
        let buyer = self.buyer.insecure_clone();
        let seller = self.seller.insecure_clone();
        let s = self.accounts(escrow);
        let ix = self.with_hook(split_ix(&s, buyer.pubkey(), seller.pubkey(), seller_bps), s.vault, &[s.seller_tokens, s.buyer_tokens], *escrow);
        self.send(&[ix], &[&buyer, &seller])
    }

    pub fn arbitrate(&mut self, escrow: &Address, seller_bps: u16) -> Result<litesvm::types::TransactionMetadata, String> {
        let arbiter = self.arbiter.insecure_clone();
        let s = self.accounts(escrow);
        let ix = self.with_hook(arbitrate_ix(&s, arbiter.pubkey(), seller_bps), s.vault, &[s.seller_tokens, s.buyer_tokens], *escrow);
        self.send(&[ix], &[&arbiter])
    }

    /// `timer_release`, naming the standard account of the side `to`.
    pub fn timer_release(&mut self, escrow: &Address, to: Side) -> Result<litesvm::types::TransactionMetadata, String> {
        let account = match to {
            Side::Buyer => self.refund(),
            Side::Seller => self.seller_tokens,
        };
        let s = self.accounts(escrow);
        let ix = timer_release_ix_under(*escrow, s.vault, s.mint, account, s.rent_recipient, s.token_program);
        let ix = self.with_hook(ix, s.vault, &[account], *escrow);
        self.send(&[ix], &[])
    }

    pub fn close_unfunded(&mut self, escrow: &Address, closer: &Keypair) -> Result<litesvm::types::TransactionMetadata, String> {
        let s = self.accounts(escrow);
        let ix = self.with_hook(close_unfunded_ix(&s, closer.pubkey()), s.vault, &[s.buyer_tokens], *escrow);
        self.send(&[ix], &[closer])
    }

    // -- reading --

    pub fn account(&self, address: &Address) -> Account {
        self.svm.get_account(address).unwrap_or_else(|| panic!("no account at {address}"))
    }

    pub fn escrow(&self, address: &Address) -> EscrowView {
        read_escrow(&self.account(address).data)
    }

    pub fn balance(&self, token_account: &Address) -> u64 {
        token_amount(&self.account(token_account).data)
    }

    pub fn vault_balance(&self, escrow: &Address) -> u64 {
        self.balance(&self.vault(escrow))
    }

    pub fn lamports(&self, address: &Address) -> u64 {
        self.svm.get_account(address).map(|a| a.lamports).unwrap_or(0)
    }

    pub fn exists(&self, address: &Address) -> bool {
        self.svm.get_account(address).map(|a| a.lamports > 0).unwrap_or(false)
    }

    /// Closed for good: no lamports, no data, and owned by the system program (or gone entirely).
    pub fn assert_closed(&self, address: &Address, what: &str) {
        if let Some(a) = self.svm.get_account(address) {
            assert_eq!(a.lamports, 0, "{what}: lamports");
            assert!(a.data.is_empty(), "{what}: data");
            assert_eq!(a.owner, SYSTEM_PROGRAM, "{what}: owner");
        }
    }

    /// Anyone at all, with some SOL to pay for what it makes.
    pub fn someone(&mut self) -> Keypair {
        let k = Keypair::new();
        self.svm.airdrop(&k.pubkey(), 1_000_000_000).unwrap();
        k
    }
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}
