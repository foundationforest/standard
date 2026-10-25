// ============================================================
// Program:    Forest escrow
// Framework:  Anchor 1.2
// Testing:    LiteSVM
// Risk level: Medium by the safe-solana-builder table; treated as Critical, because it is
//             sealed at deploy and holds other people's money
// Template:   Frank Castle's safe-solana-builder
// Security:   see escrows/solana/security-checklist.md
// ============================================================

//! The Forest escrow.
//!
//! Money in, then a schedule that says what each side may do alone and what happens at the end.
//! One program for every kind of deal: the schedule is a parameter, never code. An amount of a
//! token held between two keys, the payer and the recipient. The token is any mint of the classic
//! SPL Token program or of Token-2022, but for wrapped SOL and a Token-2022 mint with a transfer
//! fee or that cannot be transferred. Each escrow has its own deposit account, funded by a plain
//! transfer from anywhere; the escrow counts as funded when that account holds at least the agreed
//! amount.
//!
//! The moves (`escrows/README.md` has the format they read):
//! - generous, always: `pay` (the payer gives everything to the recipient) and `refund` (the
//!   recipient gives everything back), in every live state, a stop included;
//! - selfish, by the schedule: `take_back`, the payer taking back the share of the window in
//!   force, the rest to the recipient;
//! - `stop`, by either side, once, before the end time: it moves nothing, and from then on `end`
//!   does not run; `take_back` still runs by the windows, which both sides agreed at the start;
//! - `agree` (both sign any split) and `decide` (the arbiter named at creation signs any split), in
//!   every live state;
//! - `end`, by anyone, from the end time on, if the funding was marked before it and nobody
//!   stopped: everything to the side the schedule's default names.
//!
//! The schedule and the arbiter are each off unless the creator sets them at creation. The end
//! time, the last window's `until`, is the one deadline: `stop`, `mark_funded` and `take_back` run
//! only before it, `end` only from it on.
//!
//! When an escrow ends, its deposit account closes and the escrow account stays, with the outcome
//! and the amounts in it: its address is a permanent receipt, and never holds a second deal. Money
//! paid to it after the end goes back to the payer, and rent above the minimum goes back to the
//! sponsor who fronted it; neither changes the receipt. An escrow that never held the amount, or
//! whose schedule ended before anyone marked it funded, is closed instead, both accounts and both
//! rents, everything it holds back to the payer.
//!
//! The escrow's address comes from a hash of all its terms (`state::terms_hash`), so a payment
//! sent to it counts only toward a deal with exactly those terms, and only the payer or the
//! recipient can open it. The arbiter is never a party. Each party is paid only at its standard
//! token account for the mint. Every rent goes back to the sponsor who fronted it.
//!
//! Every payment out is a `transfer_checked` under the mint's own token program, carrying the
//! transaction's remaining accounts: whatever a transfer hook the mint names needs, which the
//! client resolves. They reach the token program without any signature. What a mint's issuer can
//! do (freeze, pause, a permanent delegate, a hook that refuses) is the issuer's, not the
//! program's: `escrows/solana/README.md` lists it.
//!
//! This program is to be sealed on mainnet: the upgrade authority removed at deploy, so nothing
//! here can be patched there. There is no admin, no config account, no pause and no fee.
//!
//! Nothing is shipped.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::AccountMeta;
use anchor_lang::solana_program::program::invoke_signed;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token_interface::spl_token_2022::extension::{BaseStateWithExtensions, ExtensionType, StateWithExtensions};
use anchor_spl::token_interface::{self, spl_token_2022, CloseAccount, Mint, TokenAccount, TokenInterface};

pub mod errors;
pub mod state;

use errors::EscrowError;
use state::*;

// Version 3's id for local work, kept as it is: no keypair for it exists, each deploy puts its own
// id in its place (`escrows/solana/devnet/deploy.sh` replaces this exact line), and clients and
// tests name it.
declare_id!("FoRE3EscrowV3scheduLeWindowsPayRefund3333333");

/// Written into every escrow: which program's rules it follows. v2 had a timer and buyer and
/// seller; v3 has the schedule and the payer and the recipient; v4 keeps v3's account and lets a
/// stop turn off only `end`, so the payer's take-back runs by its windows, stop or no stop.
pub const VERSION: u8 = 4;
pub const ESCROW_SEED: &[u8] = b"escrow";
/// Wrapped SOL. A classic SPL Token mint, and refused at `create`: SOL sent to its deposit account
/// by a plain transfer counts only after someone syncs it, and whatever arrives after the last sync
/// would leave with the deposit account's rent rather than with the deal.
pub const NATIVE_MINT: Pubkey = pubkey!("So11111111111111111111111111111111111111112");
/// Token-2022's wrapped SOL, refused for the same reason.
pub const NATIVE_MINT_2022: Pubkey = pubkey!("9pan9bMn5HatX4EJdBwg9VgCa7Uz5HL8N1m5D3NdXejP");

/// What `create` carries. Sealed: clients build these bytes forever.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct CreateArgs {
    /// Tells apart two deals with the same terms. The app picks it at random.
    pub id: u64,
    /// Whose money it is.
    pub payer: Pubkey,
    pub recipient: Pubkey,
    /// In the mint's base units: what the deal is for, and what funds it.
    pub amount: u64,
    /// Off unless set. Any key but the zero key, the payer's and the recipient's.
    pub arbiter: Option<Pubkey>,
    /// Off unless set. One to four windows, each `until` later than the one before.
    pub schedule: Option<Schedule>,
}

impl CreateArgs {
    /// The options as the account stores them: the zero key for no arbiter; for no schedule, no
    /// windows and the default `Pay`. A schedule `create` refuses (more than four windows) keeps
    /// its count and its first four windows here, so its address is still one hash; it never
    /// opens. `create` writes exactly these, and the address is made from them, so every signature
    /// the escrow makes later rebuilds the same seed from the account.
    fn options(&self) -> (Pubkey, u8, [Window; MAX_WINDOWS], End) {
        let arbiter = self.arbiter.unwrap_or_default();
        let mut windows = [Window::default(); MAX_WINDOWS];
        let Some(schedule) = &self.schedule else {
            return (arbiter, 0, windows, End::Pay);
        };
        for (slot, w) in windows.iter_mut().zip(&schedule.windows) {
            *slot = *w;
        }
        let count = u8::try_from(schedule.windows.len()).unwrap_or(u8::MAX);
        (arbiter, count, windows, schedule.end)
    }

    /// The seed of the address `create` lands at: `state::terms_hash` of these terms and the mint.
    /// Computed here from what `create` carries; nobody passes a hash in.
    pub fn terms_hash(&self, mint: &Pubkey) -> [u8; 32] {
        let (arbiter, count, windows, end) = self.options();
        terms_hash(self.id, &self.payer, &self.recipient, &arbiter, mint, self.amount, count, &windows, end)
    }
}

/// A schedule's own rules: one to four windows, each share at most 10,000, each `until` later
/// than the one before. A schedule with no windows is refused rather than read as none, so each
/// set of terms has one encoding. Nothing here compares a time with the clock: a schedule whose
/// windows have passed opens, and the app checks the dates before anyone pays.
fn check_schedule(schedule: &Schedule) -> Result<()> {
    let windows = &schedule.windows;
    require!(!windows.is_empty(), EscrowError::ScheduleEmpty);
    require!(windows.len() <= MAX_WINDOWS, EscrowError::TooManyWindows);
    for w in windows {
        require!(w.payer_share <= BPS, EscrowError::BadShare);
    }
    for pair in windows.windows(2) {
        require!(pair[0].until < pair[1].until, EscrowError::WindowsOutOfOrder);
    }
    Ok(())
}

#[program]
pub mod forest_escrow {
    use super::*;

    /// Open an escrow. The payer or the recipient signs as its creator (an escrow the recipient
    /// opens is an invoice). The address comes from a hash of every term, so only a party to those
    /// terms can open an escrow there, and either may. Whoever pays the rent signs too, and is
    /// recorded as the sponsor: every rent goes back to it.
    ///
    /// The deposit account is the escrow's associated token account for the mint, made by the
    /// associated token program under the mint's own token program, with whatever account
    /// extensions the mint requires. So any wallet that can send this token "to an address" lands
    /// it here: the address to send to is the escrow's own. If that account already exists,
    /// because money arrived before this landed, it is adopted, and what it holds is part of the
    /// deal.
    pub fn create(ctx: Context<Create>, args: CreateArgs) -> Result<()> {
        // Every argument is checked before anything is written.
        let payer = args.payer;
        require_keys_neq!(args.recipient, payer, EscrowError::SameParty);
        require_keys_neq!(payer, Pubkey::default(), EscrowError::EmptyKey);
        require_keys_neq!(args.recipient, Pubkey::default(), EscrowError::EmptyKey);
        // Neither party may be the escrow itself or its deposit account. Neither can ever sign, so
        // a party named as either could never give, agree or be paid: the escrow's standard
        // account is the deposit account itself, and the deposit account's is a token account no
        // key can move anything out of. Since the address is a hash of both parties, a party equal
        // to it would need a SHA-256 fixed point: this cannot fire, and stays as v1 wrote it.
        let escrow_key = ctx.accounts.escrow.key();
        let vault_key = ctx.accounts.vault.key();
        for party in [payer, args.recipient] {
            require!(party != escrow_key && party != vault_key, EscrowError::PartyIsTheEscrow);
        }
        let creator_key = ctx.accounts.creator.key();
        let creator = if creator_key == payer {
            Side::Payer
        } else if creator_key == args.recipient {
            Side::Recipient
        } else {
            return err!(EscrowError::NotAParty);
        };
        if let Some(key) = args.arbiter {
            // The zero key means "none" in the account, so it cannot also be a named arbiter.
            require_keys_neq!(key, Pubkey::default(), EscrowError::EmptyKey);
            // A party as arbiter could decide any split alone, and so take everything. Which key
            // a third arbiter belongs to, the program cannot tell.
            require!(key != payer && key != args.recipient, EscrowError::ArbiterIsAParty);
        }
        require_keys_neq!(ctx.accounts.mint.key(), NATIVE_MINT, EscrowError::NativeMint);
        require_keys_neq!(ctx.accounts.mint.key(), NATIVE_MINT_2022, EscrowError::NativeMint);
        refuse_extensions(&ctx.accounts.mint)?;
        require!(args.amount > 0, EscrowError::AmountZero);
        if let Some(schedule) = &args.schedule {
            check_schedule(schedule)?;
        }
        // Stored exactly as the address was made from them.
        let (arbiter, window_count, windows, end) = args.options();

        let now = Clock::get()?.unix_timestamp;
        let escrow = &mut ctx.accounts.escrow;
        escrow.version = VERSION;
        escrow.id = args.id;
        escrow.payer = payer;
        escrow.recipient = args.recipient;
        escrow.arbiter = arbiter;
        escrow.mint = ctx.accounts.mint.key();
        escrow.vault = ctx.accounts.vault.key();
        escrow.sponsor = ctx.accounts.sponsor.key();
        escrow.amount = args.amount;
        escrow.creator = creator;
        escrow.window_count = window_count;
        escrow.windows = windows;
        escrow.end = end;
        escrow.created_at = now;
        escrow.funded_at = 0;
        escrow.status = Status::Open;
        escrow.bump = ctx.bumps.escrow;
        escrow.ended_at = 0;
        escrow.outcome = Outcome::Pay; // meaningless until the status is Ended
        escrow.to_payer = 0;
        escrow.to_recipient = 0;
        escrow.stop = Stop::None;
        escrow.stopped_at = 0;

        emit!(Created {
            escrow: escrow.key(),
            version: VERSION,
            id: args.id,
            payer,
            recipient: args.recipient,
            creator,
            arbiter,
            mint: escrow.mint,
            vault: escrow.vault,
            sponsor: escrow.sponsor,
            amount: args.amount,
            window_count,
            windows,
            end,
            created_at: now,
        });
        Ok(())
    }

    /// Record that the deposit account holds the amount. Anyone may send it, with no signature,
    /// once, and only before the end time: it records what the chain already shows.
    ///
    /// It records the time and nothing else. `end` pays only a marked escrow, so money that arrives
    /// after the end time never counts toward the default: from then on nobody can mark it, and an
    /// escrow never marked goes back to the payer by `close_unfunded`. No other way out needs the
    /// mark, since each checks the balance itself, and an ending nobody marked records its own time
    /// as the funding time.
    pub fn mark_funded(ctx: Context<MarkFunded>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        require!(escrow.live(), EscrowError::Ended);
        require!(escrow.status == Status::Open, EscrowError::AlreadyFunded);
        let now = Clock::get()?.unix_timestamp;
        if let Some(end_time) = escrow.end_time() {
            require!(now < end_time, EscrowError::ScheduleOver);
        }
        let balance = ctx.accounts.vault.amount;
        require!(balance >= escrow.amount, EscrowError::NotFunded);
        escrow.funded_at = now;
        escrow.status = Status::Funded;
        emit!(Funded { escrow: escrow.key(), balance, funded_at: now });
        Ok(())
    }

    /// A party stops the escrow. The payer or the recipient signs; once per escrow, by either, at
    /// any time while it is live and before its end time. It moves no money. From then on `end`
    /// does not run, nor the late close of money nobody marked: the money moves by a side giving
    /// (`pay`, `refund`), the payer's take-back inside a window, both agreeing, or the arbiter if one
    /// was named. `close_unfunded` still closes an escrow that holds less than the amount, and
    /// `recover_late` is unchanged.
    ///
    /// "Before the end time" is `end_time`, the same deadline `end` reads: before it only a stop can
    /// land, from it on only the default, so the two never race. An escrow with no schedule can be
    /// stopped at any time before it ends: the stop is then on the receipt and nothing else.
    pub fn stop(ctx: Context<StopIt>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        require!(escrow.live(), EscrowError::Ended);
        let who = ctx.accounts.party.key();
        let by = if who == escrow.payer {
            Side::Payer
        } else if who == escrow.recipient {
            Side::Recipient
        } else {
            return err!(EscrowError::NotAParty);
        };
        require!(!escrow.stopped(), EscrowError::AlreadyStopped);
        let now = Clock::get()?.unix_timestamp;
        if let Some(end_time) = escrow.end_time() {
            require!(now < end_time, EscrowError::ScheduleOver);
        }
        escrow.stop = match by {
            Side::Payer => Stop::Payer,
            Side::Recipient => Stop::Recipient,
        };
        escrow.stopped_at = now;
        emit!(Stopped { escrow: escrow.key(), by, stopped_at: now });
        Ok(())
    }

    /// The payer gives: everything the deposit account holds, to the recipient. In every live
    /// state, a stop included.
    pub fn pay<'info>(ctx: Context<'info, Pay<'info>>) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.escrow.live(), EscrowError::Ended);
        require_keys_eq!(a.payer.key(), a.escrow.payer, EscrowError::NotThePayer);
        let balance = funded_balance(&a.escrow, &a.vault)?;
        let out = Out { escrow: &a.escrow, vault: &a.vault, mint: &a.mint, token_program: &a.token_program, hook_accounts: ctx.remaining_accounts };
        let rent = pay_out(&out, &[(a.recipient_tokens.to_account_info(), balance)], &a.sponsor)?;
        finish(&mut ctx.accounts.escrow, Outcome::Pay, balance, 0, balance, rent)
    }

    /// The recipient gives: everything the deposit account holds, back to the payer. In every live
    /// state, a stop included.
    pub fn refund<'info>(ctx: Context<'info, Refund<'info>>) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.escrow.live(), EscrowError::Ended);
        require_keys_eq!(a.recipient.key(), a.escrow.recipient, EscrowError::NotTheRecipient);
        let balance = funded_balance(&a.escrow, &a.vault)?;
        let out = Out { escrow: &a.escrow, vault: &a.vault, mint: &a.mint, token_program: &a.token_program, hook_accounts: ctx.remaining_accounts };
        let rent = pay_out(&out, &[(a.payer_tokens.to_account_info(), balance)], &a.sponsor)?;
        finish(&mut ctx.accounts.escrow, Outcome::Refund, balance, balance, 0, rent)
    }

    /// The payer takes back, alone, the share of the window in force: that many basis points of the
    /// balance, rounded down, to the payer, the rest to the recipient. Only inside a window, and
    /// only where the share is above 0: in a window of 0, giving everything to the recipient is
    /// `pay`, so each ending has one move. A stop changes nothing here: the windows are what both
    /// sides agreed at the start, and a stop disputes only the ending by the clock.
    pub fn take_back<'info>(ctx: Context<'info, TakeBack<'info>>) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.escrow.live(), EscrowError::Ended);
        require_keys_eq!(a.payer.key(), a.escrow.payer, EscrowError::NotThePayer);
        require!(a.escrow.end_time().is_some(), EscrowError::NoSchedule);
        let now = Clock::get()?.unix_timestamp;
        let window = a.escrow.window_at(now).ok_or_else(|| error!(EscrowError::ScheduleOver))?;
        require!(window.payer_share > 0, EscrowError::BadShare);
        let balance = funded_balance(&a.escrow, &a.vault)?;
        let (to_payer, to_recipient) = divide(balance, window.payer_share)?;
        let payouts = [(a.payer_tokens.to_account_info(), to_payer), (a.recipient_tokens.to_account_info(), to_recipient)];
        let out = Out { escrow: &a.escrow, vault: &a.vault, mint: &a.mint, token_program: &a.token_program, hook_accounts: ctx.remaining_accounts };
        let rent = pay_out(&out, &payouts, &a.sponsor)?;
        finish(&mut ctx.accounts.escrow, Outcome::TakeBack, balance, to_payer, to_recipient, rent)
    }

    /// Both sign any split: `payer_share` of the balance to the payer, rounded down, the rest to
    /// the recipient. In every live state, a stop included. Every split in the program is stated as
    /// the payer's share, the way a schedule's windows state it.
    pub fn agree<'info>(ctx: Context<'info, Agree<'info>>, payer_share: u16) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.escrow.live(), EscrowError::Ended);
        require_keys_eq!(a.payer.key(), a.escrow.payer, EscrowError::NotThePayer);
        require_keys_eq!(a.recipient.key(), a.escrow.recipient, EscrowError::NotTheRecipient);
        require!(payer_share <= BPS, EscrowError::BadShare);
        let balance = funded_balance(&a.escrow, &a.vault)?;
        let (to_payer, to_recipient) = divide(balance, payer_share)?;
        let payouts = [(a.payer_tokens.to_account_info(), to_payer), (a.recipient_tokens.to_account_info(), to_recipient)];
        let out = Out { escrow: &a.escrow, vault: &a.vault, mint: &a.mint, token_program: &a.token_program, hook_accounts: ctx.remaining_accounts };
        let rent = pay_out(&out, &payouts, &a.sponsor)?;
        finish(&mut ctx.accounts.escrow, Outcome::Agree, balance, to_payer, to_recipient, rent)
    }

    /// The arbiter named at creation signs any split, the same way both parties can. Only if one
    /// was named; in every live state, a stop included.
    pub fn decide<'info>(ctx: Context<'info, Decide<'info>>, payer_share: u16) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.escrow.live(), EscrowError::Ended);
        require!(a.escrow.has_arbiter(), EscrowError::NoArbiter);
        require_keys_eq!(a.arbiter.key(), a.escrow.arbiter, EscrowError::NotTheArbiter);
        require!(payer_share <= BPS, EscrowError::BadShare);
        let balance = funded_balance(&a.escrow, &a.vault)?;
        let (to_payer, to_recipient) = divide(balance, payer_share)?;
        let payouts = [(a.payer_tokens.to_account_info(), to_payer), (a.recipient_tokens.to_account_info(), to_recipient)];
        let out = Out { escrow: &a.escrow, vault: &a.vault, mint: &a.mint, token_program: &a.token_program, hook_accounts: ctx.remaining_accounts };
        let rent = pay_out(&out, &payouts, &a.sponsor)?;
        finish(&mut ctx.accounts.escrow, Outcome::Decide, balance, to_payer, to_recipient, rent)
    }

    /// The default: from the end time on, anyone may send everything to the side the schedule's
    /// `end` names. Only with a schedule, only if nobody stopped, and only if the funding was
    /// marked, which can happen only before the end time: money that arrived after it never counts
    /// toward the default.
    pub fn end<'info>(ctx: Context<'info, EndIt<'info>>) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.escrow.live(), EscrowError::Ended);
        let end_time = a.escrow.end_time().ok_or_else(|| error!(EscrowError::NoSchedule))?;
        require!(!a.escrow.stopped(), EscrowError::Stopped);
        require!(a.escrow.status == Status::Funded, EscrowError::FundingNotMarked);
        let now = Clock::get()?.unix_timestamp;
        require!(now >= end_time, EscrowError::ScheduleNotOver);
        let balance = funded_balance(&a.escrow, &a.vault)?;
        // Anyone sends this, so the account it pays is checked against the side the default
        // names: that side's standard token account for the mint, by address, as on every way out.
        let to = a.to.to_account_info();
        let token_program = a.token_program.key();
        let (to_payer, to_recipient) = match a.escrow.end {
            End::Refund => {
                require_keys_eq!(to.key(), a.escrow.payer_account(&token_program), EscrowError::NotThePayersAccount);
                (balance, 0)
            }
            End::Pay => {
                require_keys_eq!(to.key(), a.escrow.recipient_account(&token_program), EscrowError::NotTheRecipientsAccount);
                (0, balance)
            }
        };
        let out = Out { escrow: &a.escrow, vault: &a.vault, mint: &a.mint, token_program: &a.token_program, hook_accounts: ctx.remaining_accounts };
        let rent = pay_out(&out, &[(to, balance)], &a.sponsor)?;
        finish(&mut ctx.accounts.escrow, Outcome::End, balance, to_payer, to_recipient, rent)
    }

    /// Close an escrow that is not the deal's to end. Whatever the deposit account holds goes back
    /// to the payer, both accounts close, and both rents go back to the sponsor who fronted them:
    /// there is no receipt to keep. The payer or the recipient may do this:
    /// - at any time, while the deposit account holds less than the amount: nothing was dealt;
    /// - from the end time on, if nobody marked the funding and nobody stopped: the money arrived
    ///   too late to count, or nobody said it was there before the end, so it goes back to whoever
    ///   paid it in.
    ///
    /// A marked escrow that holds the amount, or a stopped one, cannot be closed this way.
    pub fn close_unfunded<'info>(ctx: Context<'info, CloseUnfunded<'info>>) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.escrow.live(), EscrowError::Ended);
        let closer = a.closer.key();
        require!(closer == a.escrow.payer || closer == a.escrow.recipient, EscrowError::NotAParty);
        let balance = a.vault.amount;
        let now = Clock::get()?.unix_timestamp;
        let unmarked_past_the_end = a.escrow.status == Status::Open && !a.escrow.stopped() && a.escrow.end_time().is_some_and(|end_time| now >= end_time);
        require!(balance < a.escrow.amount || unmarked_past_the_end, EscrowError::StillFunded);
        let out = Out { escrow: &a.escrow, vault: &a.vault, mint: &a.mint, token_program: &a.token_program, hook_accounts: ctx.remaining_accounts };
        let vault_rent = pay_out(&out, &[(a.payer_tokens.to_account_info(), balance)], &a.sponsor)?;
        // Anchor closes the escrow account to the sponsor after this returns (`close`).
        let escrow_rent = a.escrow.to_account_info().lamports();
        emit!(Closed {
            escrow: a.escrow.key(),
            closed_by: closer,
            to_payer: balance,
            sponsor: a.escrow.sponsor,
            // Two accounts' lamports cannot add up past the total supply of SOL, far below u64::MAX.
            rent_lamports: vault_rent.saturating_add(escrow_rent),
        });
        Ok(())
    }

    /// Money that arrives after the end goes back to the payer. Anyone may send this, on an escrow
    /// that has ended: whatever sits at its deposit address, which a later payment made again,
    /// goes to the payer's standard account for the mint, which the caller makes first, at the
    /// caller's cost, if it does not exist. The deposit account closes again and its rent goes to
    /// the payer, whose wallet almost always made it: this rent was not fronted at creation, so it
    /// is not the sponsor's. The receipt does not change: it says what the deal was, and this was
    /// not part of it.
    pub fn recover_late<'info>(ctx: Context<'info, RecoverLate<'info>>) -> Result<()> {
        let escrow = &ctx.accounts.escrow;
        require!(escrow.status == Status::Ended, EscrowError::NotEnded);
        let late = ctx.accounts.vault.amount;

        let terms = escrow.terms_hash();
        let bump = [escrow.bump];
        let seeds: &[&[u8]] = &[ESCROW_SEED, &terms, &bump];
        let signer: &[&[&[u8]]] = &[seeds];
        if late > 0 {
            let out = Out {
                escrow,
                vault: &ctx.accounts.vault,
                mint: &ctx.accounts.mint,
                token_program: &ctx.accounts.token_program,
                hook_accounts: ctx.remaining_accounts,
            };
            transfer_out(&out, ctx.accounts.payer_tokens.to_account_info(), late, signer)?;
        }
        let rent = ctx.accounts.vault.to_account_info().lamports();
        token_interface::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            CloseAccount {
                account: ctx.accounts.vault.to_account_info(),
                destination: ctx.accounts.payer.to_account_info(),
                authority: escrow.to_account_info(),
            },
            signer,
        ))?;
        emit!(RecoveredLate { escrow: escrow.key(), to_payer: late, rent_lamports: rent });
        Ok(())
    }

    /// Move the lamports the escrow account holds above the current rent-exempt minimum to the
    /// sponsor recorded at creation: the key that fronted the rent.
    ///
    /// Solana is part way through a cut to the rent rate, and receipts are never closed, so each
    /// one would keep the difference forever: only an instruction in this program can move it.
    /// Anyone may call it, on an escrow in any state: the only possible destination is the
    /// sponsor, and the account keeps exactly its minimum. SOL sent to the escrow's address leaves
    /// the same way.
    pub fn sweep_rent(ctx: Context<SweepRent>) -> Result<()> {
        let account = ctx.accounts.escrow.to_account_info();

        // The registry's check, in full, so it can never take more than the excess:
        //
        //   rent    = Rent::get()                      read at runtime, every time; never a constant,
        //                                              because the rate changing is why this exists
        //   minimum = rent.minimum_balance(data_len)   for this account's own size, which never changes
        //   excess  = lamports - minimum               saturating, so an account already at or below
        //                                              the minimum yields zero and the call fails
        //   require excess > 0
        //   account.lamports -= excess                 subtract; never assign a computed total
        //   sponsor.lamports += excess                 the recorded sponsor; never a caller's choice
        //   assert account.lamports == minimum         still exactly rent exempt
        //
        // The account's bytes are not changed, it is never grown, realloc'd or closed, and no
        // signer is required.
        let rent = Rent::get()?;
        let minimum = rent.minimum_balance(account.data_len());
        let lamports = account.lamports();
        let excess = lamports.saturating_sub(minimum);
        require!(excess > 0, EscrowError::NothingToSweep);

        **account.try_borrow_mut_lamports()? -= excess;
        **ctx.accounts.sponsor.try_borrow_mut_lamports()? += excess;
        require_eq!(account.lamports(), minimum, EscrowError::NothingToSweep);

        emit!(RentSwept { escrow: account.key(), sponsor: ctx.accounts.sponsor.key(), lamports: excess, left: minimum });
        Ok(())
    }
}

/// The deposit account's balance, which must be at least the amount. Funded is always this live
/// balance, never a flag: the ways out check it themselves, so a one-tap payment needs no
/// `mark_funded`. Only this program can move money out of the deposit account, and only by ending
/// the escrow, so once it holds the amount it holds it until the end; the one exception is a
/// mint's permanent delegate (Token-2022), an issuer's power, which can take it out at any time.
/// An escrow that no longer holds the amount then ends only by `close_unfunded`, or once the
/// amount is back.
fn funded_balance(escrow: &Escrow, vault: &InterfaceAccount<TokenAccount>) -> Result<u64> {
    let balance = vault.amount;
    require!(balance >= escrow.amount, EscrowError::NotFunded);
    Ok(balance)
}

/// A split of the whole balance: `payer_share` of it to the payer, rounded down, and the rest to
/// the recipient. The two always add up to the balance.
fn divide(balance: u64, payer_share: u16) -> Result<(u64, u64)> {
    let to_payer = share(balance, payer_share);
    let to_recipient = balance.checked_sub(to_payer).ok_or_else(|| error!(EscrowError::BadShare))?;
    Ok((to_payer, to_recipient))
}

/// Refuse the two Token-2022 mints an escrow cannot hold. One with a transfer fee, or a
/// confidential one: every way out pays the whole balance and each side must receive what was
/// agreed; a fee withheld on the way in and again on the way out breaks both, and its rate can be
/// raised after creation. One that cannot be transferred: nothing could be paid in, and what its
/// issuer minted into a deposit account could never leave, so the escrow and both rents would be
/// stuck. Every other extension is the issuer's to have. A mint's extensions are fixed when it is
/// made, so checking once, here, is enough. A classic mint has no extensions.
fn refuse_extensions(mint: &InterfaceAccount<Mint>) -> Result<()> {
    let info = mint.to_account_info();
    if *info.owner != spl_token_2022::ID {
        return Ok(());
    }
    let data = info.try_borrow_data()?;
    let state = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&data)?;
    let types = state.get_extension_types()?;
    for fee in [ExtensionType::TransferFeeConfig, ExtensionType::ConfidentialTransferFeeConfig] {
        require!(!types.contains(&fee), EscrowError::TransferFee);
    }
    require!(!types.contains(&ExtensionType::NonTransferable), EscrowError::NonTransferable);
    Ok(())
}

/// What every payment out of a deposit account needs: the escrow that signs for it, the deposit
/// account, the mint, its token program (checked by every caller to be the mint's owner), and the
/// accounts a transfer hook needs (the instruction's remaining accounts, unchecked here: see
/// `transfer_out`).
struct Out<'a, 'info> {
    escrow: &'a Account<'info, Escrow>,
    vault: &'a InterfaceAccount<'info, TokenAccount>,
    mint: &'a InterfaceAccount<'info, Mint>,
    token_program: &'a Interface<'info, TokenInterface>,
    hook_accounts: &'a [AccountInfo<'info>],
}

/// One `transfer_checked` of `amount` from the deposit account to `to`, the escrow signing, under
/// the mint's token program and with the mint's decimals.
///
/// Anchor's `transfer_checked` passes only the four accounts it names, so a mint with a transfer
/// hook would refuse it. This builds the same instruction and appends the hook accounts after
/// them: the token program finds the hook's validation account and the accounts it lists there
/// by address, and passes those on to the hook; the classic token program ignores them. The
/// client resolves them; nothing here trusts them. Each goes on as it came, writable or not, and
/// never as a signer: a signature in this transaction (a party's, a fee payer's) never reaches
/// the token program or a hook through this call. The escrow's own signature reaches the token
/// program as the authority, and Token-2022 passes it to a hook as a plain account.
fn transfer_out<'info>(out: &Out<'_, 'info>, to: AccountInfo<'info>, amount: u64, signer: &[&[&[u8]]]) -> Result<()> {
    let from = out.vault.to_account_info();
    let mint = out.mint.to_account_info();
    let authority = out.escrow.to_account_info();
    let mut ix = spl_token_2022::instruction::transfer_checked(
        &out.token_program.key(),
        from.key,
        mint.key,
        to.key,
        authority.key,
        &[],
        amount,
        out.mint.decimals,
    )?;
    let mut infos = Vec::with_capacity(4 + out.hook_accounts.len());
    infos.extend([from, mint, to, authority]);
    for account in out.hook_accounts {
        ix.accounts.push(AccountMeta { pubkey: *account.key, is_signer: false, is_writable: account.is_writable });
        infos.push(account.clone());
    }
    invoke_signed(&ix, &infos, signer)?;
    Ok(())
}

/// Pays each `(account, amount)` from the deposit account, skipping zeros, then closes the
/// deposit account with its rent to the sponsor. Returns the rent returned.
///
/// The amounts are the whole balance, split by the caller. Nothing here re-checks their sum: the
/// token program refuses a transfer above what the deposit account holds, and refuses to close it
/// while anything is left, so an ending that does not pay out exactly the balance reverts whole.
fn pay_out<'info>(out: &Out<'_, 'info>, payouts: &[(AccountInfo<'info>, u64)], sponsor: &UncheckedAccount<'info>) -> Result<u64> {
    let terms = out.escrow.terms_hash();
    let bump = [out.escrow.bump];
    let seeds: &[&[u8]] = &[ESCROW_SEED, &terms, &bump];
    let signer: &[&[&[u8]]] = &[seeds];

    for (to, amount) in payouts {
        if *amount == 0 {
            continue;
        }
        transfer_out(out, to.clone(), *amount, signer)?;
    }
    let rent = out.vault.to_account_info().lamports();
    token_interface::close_account(CpiContext::new_with_signer(
        out.token_program.key(),
        CloseAccount {
            account: out.vault.to_account_info(),
            destination: sponsor.to_account_info(),
            authority: out.escrow.to_account_info(),
        },
        signer,
    ))?;
    Ok(rent)
}

/// Every ending of an escrow that held the amount, after its payout: write the outcome into the
/// escrow account, which stays as the receipt, and emit it. One place, so every way out leaves the
/// same kind of receipt (the skill's "every path to a terminal state runs the same cleanup").
///
/// If nobody marked the funding, the ending is the first time the program saw the amount there,
/// so it records its own time as the funding time: every receipt says when the money was there.
/// It reads the status, never a zero `funded_at`, to tell whether the funding was marked.
fn finish(escrow: &mut Account<Escrow>, outcome: Outcome, balance: u64, to_payer: u64, to_recipient: u64, rent_lamports: u64) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    if escrow.status == Status::Open {
        escrow.funded_at = now;
    }
    escrow.status = Status::Ended;
    escrow.ended_at = now;
    escrow.outcome = outcome;
    escrow.to_payer = to_payer;
    escrow.to_recipient = to_recipient;
    emit!(Ended {
        escrow: escrow.key(),
        outcome,
        amount: escrow.amount,
        balance,
        to_payer,
        to_recipient,
        ended_at: now,
        sponsor: escrow.sponsor,
        rent_lamports,
        funded_at: escrow.funded_at,
    });
    Ok(())
}

#[derive(Accounts)]
#[instruction(args: CreateArgs)]
pub struct Create<'info> {
    /// At `["escrow", terms_hash]`, the hash computed here from the arguments and the mint
    /// (`CreateArgs::terms_hash`). Fails if it already exists, including as an ended escrow's
    /// receipt: an address that ever held a deal never holds another.
    #[account(
        init,
        payer = sponsor,
        space = 8 + Escrow::LEN,
        seeds = [ESCROW_SEED, &args.terms_hash(&mint.key())],
        bump
    )]
    pub escrow: Account<'info, Escrow>,
    /// The deposit account: the escrow's associated token account for the mint, under the mint's
    /// token program. Adopted if it already exists. Only the associated token program can make an
    /// account at this address, and only as a token account of that program for this mint held by
    /// the escrow, whose authority only this program can use; so an account found here can differ
    /// only in its balance, which is part of the deal. Made here, the associated token program
    /// gives it the account extensions the mint requires.
    #[account(
        init_if_needed,
        payer = sponsor,
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The payer, proposing; or the recipient, invoicing. Checked in the handler to be one of the
    /// two parties the terms name; recorded as the creator, and nothing more.
    pub creator: Signer<'info>,
    /// Fronts the rent of both accounts: either party, or any key paying for them, such as a fee
    /// payer. Recorded as the sponsor: every rent goes back to it.
    #[account(mut)]
    pub sponsor: Signer<'info>,
    /// A mint of the classic SPL Token program or of Token-2022, owned by `token_program`. Wrapped
    /// SOL of either program is refused by name, and a Token-2022 mint with a transfer fee or that
    /// cannot be transferred by its extensions (`refuse_extensions`).
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// The classic SPL Token program or Token-2022: whichever owns the mint.
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// `mark_funded`. No signer: anyone may send it.
#[derive(Accounts)]
pub struct MarkFunded<'info> {
    #[account(mut, has_one = vault)]
    pub escrow: Account<'info, Escrow>,
    pub vault: InterfaceAccount<'info, TokenAccount>,
}

/// A party stops the escrow: `stop`. Names no token account: it moves nothing.
#[derive(Accounts)]
pub struct StopIt<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
    /// The payer or the recipient; checked in the handler.
    pub party: Signer<'info>,
}

// Every instruction below that pays out names the mint, which `transfer_checked` needs, and the
// token program that owns it; each party's standard account is derived under that program. Any
// accounts after the named ones are forwarded to every transfer, for a transfer hook
// (`transfer_out`).

/// The payer gives. Names only the recipient's account: the payer is paid nothing.
#[derive(Accounts)]
pub struct Pay<'info> {
    #[account(mut, has_one = vault, has_one = mint, has_one = sponsor)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: the recipient's standard token account for the mint, by address, and no other
    /// account; the same rule as the payer's (see `Refund`).
    #[account(mut, address = escrow.recipient_account(&token_program.key()) @ EscrowError::NotTheRecipientsAccount)]
    pub recipient_tokens: UncheckedAccount<'info>,
    /// CHECK: the sponsor's key, recorded at creation, checked by `has_one`. It only receives
    /// lamports.
    #[account(mut)]
    pub sponsor: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    /// Checked against the escrow's payer in the handler.
    pub payer: Signer<'info>,
}

/// The recipient gives. Names only the payer's account: the recipient is paid nothing.
#[derive(Accounts)]
pub struct Refund<'info> {
    #[account(mut, has_one = vault, has_one = mint, has_one = sponsor)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: the payer's standard token account for the mint, by address, and no other account.
    /// Checked by address alone, not by who holds it now, so a payer who hands it to another key
    /// cannot block an ending. The token program checks the rest when it is paid: an initialized
    /// token account of that program for the same mint, not frozen.
    #[account(mut, address = escrow.payer_account(&token_program.key()) @ EscrowError::NotThePayersAccount)]
    pub payer_tokens: UncheckedAccount<'info>,
    /// CHECK: the sponsor's key, recorded at creation, checked by `has_one`. It only receives
    /// lamports.
    #[account(mut)]
    pub sponsor: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    /// Checked against the escrow's recipient in the handler.
    pub recipient: Signer<'info>,
}

/// The payer takes back its window's share. Both accounts, as a split names them; the payer signs.
#[derive(Accounts)]
pub struct TakeBack<'info> {
    #[account(mut, has_one = vault, has_one = mint, has_one = sponsor)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: the payer's standard token account for the mint, by address, and no other account;
    /// see `Refund`.
    #[account(mut, address = escrow.payer_account(&token_program.key()) @ EscrowError::NotThePayersAccount)]
    pub payer_tokens: UncheckedAccount<'info>,
    /// CHECK: the recipient's standard token account for the mint, by address, and no other
    /// account; see `Refund`. It needs to exist only if the recipient's share is above zero.
    #[account(mut, address = escrow.recipient_account(&token_program.key()) @ EscrowError::NotTheRecipientsAccount)]
    pub recipient_tokens: UncheckedAccount<'info>,
    /// CHECK: the sponsor's key, recorded at creation, checked by `has_one`. It only receives
    /// lamports.
    #[account(mut)]
    pub sponsor: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    /// Checked against the escrow's payer in the handler.
    pub payer: Signer<'info>,
}

/// Both parties sign a split.
#[derive(Accounts)]
pub struct Agree<'info> {
    #[account(mut, has_one = vault, has_one = mint, has_one = sponsor)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: the payer's standard token account for the mint, by address, and no other account;
    /// see `Refund`. It needs to exist only if the payer's share is above zero.
    #[account(mut, address = escrow.payer_account(&token_program.key()) @ EscrowError::NotThePayersAccount)]
    pub payer_tokens: UncheckedAccount<'info>,
    /// CHECK: the recipient's standard token account for the mint, by address, and no other
    /// account; see `Refund`. It needs to exist only if the recipient's share is above zero.
    #[account(mut, address = escrow.recipient_account(&token_program.key()) @ EscrowError::NotTheRecipientsAccount)]
    pub recipient_tokens: UncheckedAccount<'info>,
    /// CHECK: the sponsor's key, recorded at creation, checked by `has_one`. It only receives
    /// lamports.
    #[account(mut)]
    pub sponsor: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    /// Checked against the escrow's payer in the handler.
    pub payer: Signer<'info>,
    /// Checked against the escrow's recipient in the handler.
    pub recipient: Signer<'info>,
}

/// The arbiter named at creation signs a split. The same accounts as `Agree`, one signer.
#[derive(Accounts)]
pub struct Decide<'info> {
    #[account(mut, has_one = vault, has_one = mint, has_one = sponsor)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: the payer's standard token account for the mint, by address, and no other account;
    /// see `Refund`. It needs to exist only if the payer's share is above zero.
    #[account(mut, address = escrow.payer_account(&token_program.key()) @ EscrowError::NotThePayersAccount)]
    pub payer_tokens: UncheckedAccount<'info>,
    /// CHECK: the recipient's standard token account for the mint, by address, and no other
    /// account; see `Refund`. It needs to exist only if the recipient's share is above zero.
    #[account(mut, address = escrow.recipient_account(&token_program.key()) @ EscrowError::NotTheRecipientsAccount)]
    pub recipient_tokens: UncheckedAccount<'info>,
    /// CHECK: the sponsor's key, recorded at creation, checked by `has_one`. It only receives
    /// lamports.
    #[account(mut)]
    pub sponsor: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    /// Checked against the escrow's arbiter in the handler.
    pub arbiter: Signer<'info>,
}

/// The default pays one side, so it names one account. No signer: anyone may send it.
#[derive(Accounts)]
pub struct EndIt<'info> {
    #[account(mut, has_one = vault, has_one = mint, has_one = sponsor)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: checked in the handler, by address, against the side the default names: that side's
    /// standard token account for the mint. The token program checks the rest when it is paid.
    #[account(mut)]
    pub to: UncheckedAccount<'info>,
    /// CHECK: the sponsor's key, recorded at creation, checked by `has_one`. It only receives
    /// lamports.
    #[account(mut)]
    pub sponsor: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

/// Closing an escrow that is not the deal's to end. The only instruction that closes an escrow
/// account, and only this kind. It pays the recipient nothing and names no recipient account.
#[derive(Accounts)]
pub struct CloseUnfunded<'info> {
    #[account(mut, close = sponsor, has_one = vault, has_one = mint, has_one = sponsor)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: the payer's standard token account for the mint, by address, and no other account;
    /// see `Refund`. It needs to exist only if the deposit account holds anything, so an escrow
    /// nobody paid closes without anyone making the payer an account.
    #[account(mut, address = escrow.payer_account(&token_program.key()) @ EscrowError::NotThePayersAccount)]
    pub payer_tokens: UncheckedAccount<'info>,
    /// CHECK: the sponsor's key, recorded at creation, checked by `has_one`. It only receives
    /// lamports.
    #[account(mut)]
    pub sponsor: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    /// The payer or the recipient; checked in the handler.
    pub closer: Signer<'info>,
}

/// Late money back to the payer: `recover_late`. The escrow is read only, because the receipt does
/// not change.
#[derive(Accounts)]
pub struct RecoverLate<'info> {
    #[account(has_one = vault, has_one = payer, has_one = mint)]
    pub escrow: Account<'info, Escrow>,
    /// The deposit address, made again by a payment that came after the end. If nothing made it
    /// again, there is nothing to recover and this fails to load.
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: the payer recorded at creation, checked by `has_one`. It owns the standard account
    /// paid here and receives the deposit account's rent.
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
    /// The payer's standard account: its associated token account for the mint, under the mint's
    /// token program, and no other account. Made here, at the caller's cost, if it does not exist.
    #[account(
        init_if_needed,
        payer = caller,
        associated_token::mint = mint,
        associated_token::authority = payer,
        associated_token::token_program = token_program,
    )]
    pub payer_tokens: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// Anyone. Pays for the payer's standard account if it has to be made.
    #[account(mut)]
    pub caller: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// Rent above the minimum back to the sponsor: `sweep_rent`. No signer.
#[derive(Accounts)]
pub struct SweepRent<'info> {
    #[account(mut, has_one = sponsor)]
    pub escrow: Account<'info, Escrow>,
    /// CHECK: the key that fronted the rent, recorded at creation, checked by `has_one`. It only
    /// receives lamports.
    #[account(mut)]
    pub sponsor: UncheckedAccount<'info>,
}

// ---------------------------------------------------------------------------------------------
// Events. Every state change, with amounts, so an index can read outcomes from the log alone.
// ---------------------------------------------------------------------------------------------

#[event]
pub struct Created {
    pub escrow: Pubkey,
    pub version: u8,
    pub id: u64,
    pub payer: Pubkey,
    pub recipient: Pubkey,
    /// Who opened it. The recipient, for an invoice.
    pub creator: Side,
    /// The zero key when none.
    pub arbiter: Pubkey,
    pub mint: Pubkey,
    pub vault: Pubkey,
    /// The key that fronted the rent; every rent goes back to it.
    pub sponsor: Pubkey,
    pub amount: u64,
    /// 0 when there is no schedule.
    pub window_count: u8,
    /// The schedule's windows, then zeros.
    pub windows: [Window; MAX_WINDOWS],
    /// `Pay` when there is no schedule.
    pub end: End,
    pub created_at: i64,
}

/// `mark_funded` saw the deposit account holding the amount, before the end time.
#[event]
pub struct Funded {
    pub escrow: Pubkey,
    pub balance: u64,
    pub funded_at: i64,
}

/// A party stopped the escrow. From here on `end` does not run; the receipt keeps who and when.
#[event]
pub struct Stopped {
    pub escrow: Pubkey,
    pub by: Side,
    pub stopped_at: i64,
}

/// Every ending of an escrow that held the amount. `outcome` is the move that ended it; `balance`
/// is what the deposit account held; `to_payer + to_recipient == balance`. The deposit account's
/// rent went back to the sponsor; the escrow account stays, holding the same numbers, as the
/// receipt. `funded_at` is the mark's time, or `ended_at` when nobody marked it.
#[event]
pub struct Ended {
    pub escrow: Pubkey,
    pub outcome: Outcome,
    pub amount: u64,
    pub balance: u64,
    pub to_payer: u64,
    pub to_recipient: u64,
    pub ended_at: i64,
    pub sponsor: Pubkey,
    pub rent_lamports: u64,
    pub funded_at: i64,
}

/// An escrow closed without a receipt: one that never held the amount, or one whose schedule ended
/// before anyone marked it funded. Whatever the deposit account held went back to the payer; both
/// accounts are gone and both rents went back to the sponsor.
#[event]
pub struct Closed {
    pub escrow: Pubkey,
    pub closed_by: Pubkey,
    pub to_payer: u64,
    pub sponsor: Pubkey,
    pub rent_lamports: u64,
}

/// Money that arrived after the end went back to the payer's standard account, and the deposit
/// account closed again with its rent to the payer. The receipt did not change.
#[event]
pub struct RecoveredLate {
    pub escrow: Pubkey,
    pub to_payer: u64,
    pub rent_lamports: u64,
}

/// Lamports above the escrow account's rent-exempt minimum went to the sponsor; `left` is the
/// minimum it still holds.
#[event]
pub struct RentSwept {
    pub escrow: Pubkey,
    /// The key that fronted the rent, recorded at creation: where the lamports went.
    pub sponsor: Pubkey,
    pub lamports: u64,
    pub left: u64,
}

/// Compile-time proof that the sealed size is what `state.rs` says it is.
const _: () = {
    assert!(Escrow::LEN == 304);
    assert!(BPS == 10_000);
    assert!(MAX_WINDOWS == 4);
};
