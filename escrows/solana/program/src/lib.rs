// ============================================================
// Program:    Forest escrow
// Framework:  Anchor 1.2
// Testing:    LiteSVM
// Risk level: Medium by the safe-solana-builder table; treated as Critical, because it is
//             sealed at deploy and holds other people's money
// Template:   Frank Castle's safe-solana-builder
// Security:   see escrow/security-checklist.md
// ============================================================

//! The Forest escrow.
//!
//! Money in, and out only when the two sides agree. One shape. An amount of a token held between
//! two keys, buyer and seller. The token is any mint of the classic SPL Token program or of
//! Token-2022, but for wrapped SOL and a Token-2022 mint with a transfer fee or that cannot be
//! transferred. Each escrow has its own deposit account, funded by a
//! plain transfer from anywhere; the escrow counts as funded when that account holds at least the
//! agreed amount. Once funded it has three ways out: the buyer releases everything to the
//! seller, the seller releases everything to the buyer, or both sign a split. Receiving in full
//! never needs the receiver's signature, so each side alone can give, and only together can they
//! divide. Every way out pays out the whole balance, whatever it is.
//!
//! Two options, each off unless the creator turns it on at creation: an arbiter key that may sign
//! any split, and a timer that, a number of days after the funding is marked, lets anyone send
//! everything to the side it names. There is no other clock.
//!
//! Either party may object, once per escrow, at any time before the timer is due. After an
//! objection the timer never runs: the money moves only by the parties agreeing (a release or a
//! split) or by the arbiter, if one was named. The receipt records who objected and when.
//!
//! When an escrow ends, its deposit account closes and the escrow account stays, with the outcome
//! and the amounts in it: its address is a permanent receipt, and never holds a second deal. The
//! receipt records when the money was there (the mark, or else the ending) and when it ended.
//! Money paid to it after the end goes back to the buyer, and rent above the minimum goes back to
//! the payer who fronted it; neither changes the receipt. An escrow that never held the amount is
//! closed instead, both accounts and both rents.
//!
//! The escrow's address comes from a hash of all its terms (`state::terms_hash`), so a payment
//! sent to it counts only toward a deal with exactly those terms, and only the buyer or the seller
//! can open it. The arbiter is never a party. Each party is paid only at its standard token
//! account for the mint. Every rent goes back to the payer who fronted it.
//!
//! Every payment out is a `transfer_checked` under the mint's own token program, carrying the
//! transaction's remaining accounts: whatever a transfer hook the mint names needs, which the
//! client resolves. They reach the token program without any signature. What a mint's issuer can
//! do (freeze, pause, a permanent delegate, a hook that refuses) is the issuer's, not the
//! program's: `escrow/README.md` lists it.
//!
//! This program is sealed per version. The upgrade authority is removed at deploy, so nothing
//! here can be patched: read `escrow/README.md` for what is sealed and what the app decides.
//! There is no admin, no config account, no pause and no fee. v1, an earlier program no longer in
//! this repo, stays at its own address; each escrow follows the program it was opened in.
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

declare_id!("FoRE2EscrowV2objectsTimerFundedAtPayer222222");

/// Written into every escrow. A v3 is a new program at a new address.
pub const VERSION: u8 = 2;
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
    pub buyer: Pubkey,
    pub seller: Pubkey,
    /// In the mint's base units: what the deal is for, and what funds it.
    pub amount: u64,
    /// Off unless set. Any key but the zero key, the buyer's and the seller's.
    pub arbiter: Option<Pubkey>,
    /// Off unless set. At least one day.
    pub timer: Option<Timer>,
}

impl CreateArgs {
    /// The two options as the account stores them: the zero key for no arbiter, 0 days and the
    /// buyer's side for no timer. `create` writes exactly these, and the address is made from
    /// them, so every signature the escrow makes later rebuilds the same seed from the account.
    fn options(&self) -> (Pubkey, u16, Side) {
        let arbiter = self.arbiter.unwrap_or_default();
        let (days, to) = self.timer.map_or((0, Side::Buyer), |t| (t.days, t.to));
        (arbiter, days, to)
    }

    /// The seed of the address `create` lands at: `state::terms_hash` of these terms and the mint.
    /// Computed here from what `create` carries; nobody passes a hash in.
    pub fn terms_hash(&self, mint: &Pubkey) -> [u8; 32] {
        let (arbiter, days, to) = self.options();
        terms_hash(self.id, &self.buyer, &self.seller, &arbiter, mint, self.amount, days, to)
    }
}

#[program]
pub mod forest_escrow {
    use super::*;

    /// Open an escrow. The buyer or the seller signs as its creator (an escrow the seller opens is
    /// an invoice). The address comes from a hash of every term, so only a party to those terms
    /// can open an escrow there, and either may. Whoever pays the rent signs too, and is recorded
    /// as the payer and the rent recipient: every rent goes back to it.
    ///
    /// The deposit account is the escrow's associated token account for the mint, made by the
    /// associated token program under the mint's own token program, with whatever account
    /// extensions the mint requires. So any wallet that can send this token "to an address" lands
    /// it here: the address to send to is the escrow's own. If that account already exists,
    /// because money arrived before this landed, it is adopted, and what it holds is part of the
    /// deal.
    pub fn create(ctx: Context<Create>, args: CreateArgs) -> Result<()> {
        // Every argument is checked before anything is written.
        let buyer = args.buyer;
        require_keys_neq!(args.seller, buyer, EscrowError::SameParty);
        require_keys_neq!(buyer, Pubkey::default(), EscrowError::EmptyKey);
        require_keys_neq!(args.seller, Pubkey::default(), EscrowError::EmptyKey);
        // Neither party may be the escrow itself or its deposit account. Neither can ever sign, so
        // a party named as either could never give, agree or be paid: the escrow's standard
        // account is the deposit account itself, and the deposit account's is a token account no
        // key can move anything out of. Money paid in would leave only by a way out that pays that
        // party nothing, if the creator set one. Since the address is a hash of both parties, a
        // party equal to it would need a SHA-256 fixed point: this cannot fire, and stays as v1
        // wrote it.
        let escrow_key = ctx.accounts.escrow.key();
        let vault_key = ctx.accounts.vault.key();
        for party in [buyer, args.seller] {
            require!(party != escrow_key && party != vault_key, EscrowError::PartyIsTheEscrow);
        }
        let creator_key = ctx.accounts.creator.key();
        let creator = if creator_key == buyer {
            Side::Buyer
        } else if creator_key == args.seller {
            Side::Seller
        } else {
            return err!(EscrowError::NotAParty);
        };
        if let Some(key) = args.arbiter {
            // The zero key means "none" in the account, so it cannot also be a named arbiter.
            require_keys_neq!(key, Pubkey::default(), EscrowError::EmptyKey);
            // A party as arbiter could decide any split alone, and so take everything. Which key
            // a third arbiter belongs to, the program cannot tell.
            require!(key != buyer && key != args.seller, EscrowError::ArbiterIsAParty);
        }
        require_keys_neq!(ctx.accounts.mint.key(), NATIVE_MINT, EscrowError::NativeMint);
        require_keys_neq!(ctx.accounts.mint.key(), NATIVE_MINT_2022, EscrowError::NativeMint);
        refuse_extensions(&ctx.accounts.mint)?;
        require!(args.amount > 0, EscrowError::AmountZero);
        if let Some(t) = args.timer {
            require!(t.days > 0, EscrowError::TimerZero);
        }
        // Stored exactly as the address was made from them.
        let (arbiter, timer_days, timer_to) = args.options();

        let now = Clock::get()?.unix_timestamp;
        let escrow = &mut ctx.accounts.escrow;
        escrow.version = VERSION;
        escrow.id = args.id;
        escrow.buyer = buyer;
        escrow.seller = args.seller;
        escrow.arbiter = arbiter;
        escrow.mint = ctx.accounts.mint.key();
        escrow.vault = ctx.accounts.vault.key();
        escrow.rent_recipient = ctx.accounts.payer.key();
        escrow.amount = args.amount;
        escrow.creator = creator;
        escrow.timer_days = timer_days;
        escrow.timer_to = timer_to;
        escrow.created_at = now;
        escrow.funded_at = 0;
        escrow.status = Status::Open;
        escrow.bump = ctx.bumps.escrow;
        escrow.ended_at = 0;
        escrow.outcome = Outcome::ReleasedToSeller; // meaningless until the status is Ended
        escrow.to_seller = 0;
        escrow.to_buyer = 0;
        escrow.payer = ctx.accounts.payer.key();
        escrow.objection = Objection::None;
        escrow.objected_at = 0;

        emit!(Created {
            escrow: escrow.key(),
            version: VERSION,
            id: args.id,
            buyer,
            seller: args.seller,
            creator,
            arbiter,
            mint: escrow.mint,
            vault: escrow.vault,
            rent_recipient: escrow.rent_recipient,
            amount: args.amount,
            timer_days,
            timer_to,
            created_at: now,
            payer: escrow.payer,
        });
        Ok(())
    }

    /// Record that the deposit account holds the amount. Anyone may send it, once.
    ///
    /// It records the time and nothing else. The timer counts from it; no way out needs it, since
    /// each one checks the balance itself, and an ending nobody marked records its own time as the
    /// funding time.
    pub fn mark_funded(ctx: Context<MarkFunded>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        require!(escrow.live(), EscrowError::Ended);
        require!(escrow.status == Status::Open, EscrowError::AlreadyFunded);
        let balance = ctx.accounts.vault.amount;
        require!(balance >= escrow.amount, EscrowError::NotFunded);
        let now = Clock::get()?.unix_timestamp;
        escrow.funded_at = now;
        escrow.status = Status::Funded;
        emit!(Funded { escrow: escrow.key(), balance, funded_at: now });
        Ok(())
    }

    /// A party objects. The buyer or the seller signs; once per escrow, by either, at any time
    /// while it is live and before its timer is due. It moves no money. From then on the timer
    /// never runs: the money moves only by a release, a split, or the arbiter if one was named.
    /// `close_unfunded` and `recover_late` are unchanged: neither is the timer.
    ///
    /// "Before the timer is due" is `timer_due`, the same deadline `timer_release` reads: before
    /// it only an objection can land, from it on only the timer, so the two never race. A timer
    /// whose funding nobody marked is never due, and an escrow with no timer can be objected to
    /// at any time before it ends: the objection is then on the receipt and nothing else.
    pub fn object(ctx: Context<Object>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        require!(escrow.live(), EscrowError::Ended);
        let who = ctx.accounts.party.key();
        let by = if who == escrow.buyer {
            Side::Buyer
        } else if who == escrow.seller {
            Side::Seller
        } else {
            return err!(EscrowError::NotAnObjector);
        };
        require!(!escrow.objected(), EscrowError::AlreadyObjected);
        let now = Clock::get()?.unix_timestamp;
        if let Some(due) = escrow.timer_due()? {
            require!(now < due, EscrowError::TimerDue);
        }
        escrow.objection = match by {
            Side::Buyer => Objection::Buyer,
            Side::Seller => Objection::Seller,
        };
        escrow.objected_at = now;
        emit!(Objected { escrow: escrow.key(), by, objected_at: now });
        Ok(())
    }

    /// The buyer gives: everything the deposit account holds, to the seller.
    pub fn release_to_seller<'info>(ctx: Context<'info, ReleaseToSeller<'info>>) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.escrow.live(), EscrowError::Ended);
        require_keys_eq!(a.buyer.key(), a.escrow.buyer, EscrowError::NotTheBuyer);
        let balance = funded_balance(&a.escrow, &a.vault)?;
        let out = Out { escrow: &a.escrow, vault: &a.vault, mint: &a.mint, token_program: &a.token_program, hook_accounts: ctx.remaining_accounts };
        let rent = pay_out(&out, &[(a.seller_tokens.to_account_info(), balance)], &a.rent_recipient)?;
        end(&mut ctx.accounts.escrow, Outcome::ReleasedToSeller, balance, balance, 0, rent)
    }

    /// The seller gives: everything the deposit account holds, back to the buyer.
    pub fn release_to_buyer<'info>(ctx: Context<'info, ReleaseToBuyer<'info>>) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.escrow.live(), EscrowError::Ended);
        require_keys_eq!(a.seller.key(), a.escrow.seller, EscrowError::NotTheSeller);
        let balance = funded_balance(&a.escrow, &a.vault)?;
        let out = Out { escrow: &a.escrow, vault: &a.vault, mint: &a.mint, token_program: &a.token_program, hook_accounts: ctx.remaining_accounts };
        let rent = pay_out(&out, &[(a.buyer_tokens.to_account_info(), balance)], &a.rent_recipient)?;
        end(&mut ctx.accounts.escrow, Outcome::ReleasedToBuyer, balance, 0, balance, rent)
    }

    /// Both sign any split: `seller_bps` of the balance to the seller, rounded down, the rest to
    /// the buyer.
    pub fn split<'info>(ctx: Context<'info, Split<'info>>, seller_bps: u16) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.escrow.live(), EscrowError::Ended);
        require_keys_eq!(a.buyer.key(), a.escrow.buyer, EscrowError::NotTheBuyer);
        require_keys_eq!(a.seller.key(), a.escrow.seller, EscrowError::NotTheSeller);
        require!(seller_bps <= BPS, EscrowError::BadSplit);
        let balance = funded_balance(&a.escrow, &a.vault)?;
        let (to_seller, to_buyer) = divide(balance, seller_bps)?;
        let payouts = [(a.seller_tokens.to_account_info(), to_seller), (a.buyer_tokens.to_account_info(), to_buyer)];
        let out = Out { escrow: &a.escrow, vault: &a.vault, mint: &a.mint, token_program: &a.token_program, hook_accounts: ctx.remaining_accounts };
        let rent = pay_out(&out, &payouts, &a.rent_recipient)?;
        end(&mut ctx.accounts.escrow, Outcome::Split, balance, to_seller, to_buyer, rent)
    }

    /// The arbiter named at creation signs any split, the same way both parties can. Only if one
    /// was named.
    pub fn arbitrate<'info>(ctx: Context<'info, Arbitrate<'info>>, seller_bps: u16) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.escrow.live(), EscrowError::Ended);
        require!(a.escrow.has_arbiter(), EscrowError::NoArbiter);
        require_keys_eq!(a.arbiter.key(), a.escrow.arbiter, EscrowError::NotTheArbiter);
        require!(seller_bps <= BPS, EscrowError::BadSplit);
        let balance = funded_balance(&a.escrow, &a.vault)?;
        let (to_seller, to_buyer) = divide(balance, seller_bps)?;
        let payouts = [(a.seller_tokens.to_account_info(), to_seller), (a.buyer_tokens.to_account_info(), to_buyer)];
        let out = Out { escrow: &a.escrow, vault: &a.vault, mint: &a.mint, token_program: &a.token_program, hook_accounts: ctx.remaining_accounts };
        let rent = pay_out(&out, &payouts, &a.rent_recipient)?;
        end(&mut ctx.accounts.escrow, Outcome::Arbitrated, balance, to_seller, to_buyer, rent)
    }

    /// The timer set at creation is due: anyone may send everything to the side it names. Due
    /// from `timer_days` whole days after the funding was marked, to the second. Only if a timer
    /// was set, nobody objected, and the funding has been marked.
    pub fn timer_release<'info>(ctx: Context<'info, TimerRelease<'info>>) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.escrow.live(), EscrowError::Ended);
        require!(a.escrow.has_timer(), EscrowError::NoTimer);
        require!(!a.escrow.objected(), EscrowError::Objected);
        require!(a.escrow.status == Status::Funded, EscrowError::FundingNotMarked);
        let due = a.escrow.timer_due()?.ok_or_else(|| error!(EscrowError::FundingNotMarked))?;
        let now = Clock::get()?.unix_timestamp;
        require!(now >= due, EscrowError::TimerNotDue);
        let balance = funded_balance(&a.escrow, &a.vault)?;
        // Anyone sends this, so the account it pays is checked against the side the timer names:
        // that side's standard token account for the mint, by address, as on every way out.
        let to = a.to.to_account_info();
        let token_program = a.token_program.key();
        let (to_seller, to_buyer) = match a.escrow.timer_to {
            Side::Buyer => {
                require_keys_eq!(to.key(), a.escrow.refund_address(&token_program), EscrowError::NotTheRefundAddress);
                (0, balance)
            }
            Side::Seller => {
                require_keys_eq!(to.key(), a.escrow.payout_address(&token_program), EscrowError::NotTheSellersAccount);
                (balance, 0)
            }
        };
        let out = Out { escrow: &a.escrow, vault: &a.vault, mint: &a.mint, token_program: &a.token_program, hook_accounts: ctx.remaining_accounts };
        let rent = pay_out(&out, &[(to, balance)], &a.rent_recipient)?;
        end(&mut ctx.accounts.escrow, Outcome::TimerReleased, balance, to_seller, to_buyer, rent)
    }

    /// Close an escrow that never held the amount. Whatever the deposit account holds goes back
    /// to the buyer, both accounts close, and both rents go back to the payer who fronted them:
    /// nothing was dealt, so there is no receipt to keep. The buyer or the seller may do this at
    /// any time; the payer has no say. A funded escrow cannot be closed at all.
    pub fn close_unfunded<'info>(ctx: Context<'info, CloseUnfunded<'info>>) -> Result<()> {
        let a = &ctx.accounts;
        require!(a.escrow.live(), EscrowError::Ended);
        let closer = a.closer.key();
        require!(closer == a.escrow.buyer || closer == a.escrow.seller, EscrowError::NotACloser);
        let balance = a.vault.amount;
        require!(balance < a.escrow.amount, EscrowError::StillFunded);
        let out = Out { escrow: &a.escrow, vault: &a.vault, mint: &a.mint, token_program: &a.token_program, hook_accounts: ctx.remaining_accounts };
        let vault_rent = pay_out(&out, &[(a.buyer_tokens.to_account_info(), balance)], &a.rent_recipient)?;
        // Anchor closes the escrow account to the payer after this returns (`close`).
        let escrow_rent = a.escrow.to_account_info().lamports();
        emit!(Closed {
            escrow: a.escrow.key(),
            closed_by: closer,
            to_buyer: balance,
            rent_recipient: a.escrow.rent_recipient,
            // Two accounts' lamports cannot add up past the total supply of SOL, far below u64::MAX.
            rent_lamports: vault_rent.saturating_add(escrow_rent),
        });
        Ok(())
    }

    /// Money that arrives after the end goes back to the buyer. Anyone may send this, on an escrow
    /// that has ended: whatever sits at its deposit address, which a later payment made again,
    /// goes to the buyer's refund address, the buyer's associated token account for the mint,
    /// which the caller makes first, at the caller's cost, if it does not exist. The deposit
    /// account closes again and its rent goes to the buyer, whose wallet almost always made it:
    /// this rent was not fronted at creation, so it is not the payer's.
    /// The receipt does not change: it says what the deal was, and this was not part of it.
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
            transfer_out(&out, ctx.accounts.refund.to_account_info(), late, signer)?;
        }
        let rent = ctx.accounts.vault.to_account_info().lamports();
        token_interface::close_account(CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            CloseAccount {
                account: ctx.accounts.vault.to_account_info(),
                destination: ctx.accounts.buyer.to_account_info(),
                authority: escrow.to_account_info(),
            },
            signer,
        ))?;
        emit!(RecoveredLate { escrow: escrow.key(), to_buyer: late, rent_lamports: rent });
        Ok(())
    }

    /// Move the lamports the escrow account holds above the current rent-exempt minimum to the
    /// payer recorded at creation: the key that fronted the rent.
    ///
    /// Solana is part way through a cut to the rent rate, and receipts are never closed, so each
    /// one would keep the difference forever: only an instruction in this program can move it.
    /// Anyone may call it, on an escrow in any state: the only possible destination is the
    /// payer, and the account keeps exactly its minimum. SOL sent to the escrow's address leaves
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
        //   payer.lamports += excess                   the recorded payer; never a caller's choice
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
        **ctx.accounts.payer.try_borrow_mut_lamports()? += excess;
        require_eq!(account.lamports(), minimum, EscrowError::NothingToSweep);

        emit!(RentSwept { escrow: account.key(), payer: ctx.accounts.payer.key(), lamports: excess, left: minimum });
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

/// A split of the whole balance: `seller_bps` of it to the seller, rounded down, and the rest to
/// the buyer. The two always add up to the balance.
fn divide(balance: u64, seller_bps: u16) -> Result<(u64, u64)> {
    let to_seller = share(balance, seller_bps);
    let to_buyer = balance.checked_sub(to_seller).ok_or_else(|| error!(EscrowError::BadSplit))?;
    Ok((to_seller, to_buyer))
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
/// deposit account with its rent to the payer. Returns the rent returned.
///
/// The amounts are the whole balance, split by the caller. Nothing here re-checks their sum: the
/// token program refuses a transfer above what the deposit account holds, and refuses to close it
/// while anything is left, so an ending that does not pay out exactly the balance reverts whole.
fn pay_out<'info>(out: &Out<'_, 'info>, payouts: &[(AccountInfo<'info>, u64)], rent_recipient: &UncheckedAccount<'info>) -> Result<u64> {
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
            destination: rent_recipient.to_account_info(),
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
fn end(escrow: &mut Account<Escrow>, outcome: Outcome, balance: u64, to_seller: u64, to_buyer: u64, rent_lamports: u64) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    if escrow.status == Status::Open {
        escrow.funded_at = now;
    }
    escrow.status = Status::Ended;
    escrow.ended_at = now;
    escrow.outcome = outcome;
    escrow.to_seller = to_seller;
    escrow.to_buyer = to_buyer;
    emit!(Ended {
        escrow: escrow.key(),
        outcome,
        amount: escrow.amount,
        balance,
        to_seller,
        to_buyer,
        ended_at: now,
        rent_recipient: escrow.rent_recipient,
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
        payer = payer,
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
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = escrow,
        associated_token::token_program = token_program,
    )]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The buyer, proposing; or the seller, invoicing. Checked in the handler to be one of the two
    /// parties the terms name; recorded as the creator, and nothing more.
    pub creator: Signer<'info>,
    /// Fronts the rent of both accounts: either party, or any key paying for them, such as a fee
    /// payer. Recorded as the payer and the rent recipient: every rent goes back to it.
    #[account(mut)]
    pub payer: Signer<'info>,
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

#[derive(Accounts)]
pub struct MarkFunded<'info> {
    #[account(mut, has_one = vault)]
    pub escrow: Account<'info, Escrow>,
    pub vault: InterfaceAccount<'info, TokenAccount>,
}

/// A party objects: `object`. Names no token account: it moves nothing.
#[derive(Accounts)]
pub struct Object<'info> {
    #[account(mut)]
    pub escrow: Account<'info, Escrow>,
    /// The buyer or the seller; checked in the handler.
    pub party: Signer<'info>,
}

// Every instruction below that pays out names the mint, which `transfer_checked` needs, and the
// token program that owns it; each party's standard account is derived under that program. Any
// accounts after the named ones are forwarded to every transfer, for a transfer hook
// (`transfer_out`).

/// The buyer gives. Names only the seller's account: the buyer is paid nothing.
#[derive(Accounts)]
pub struct ReleaseToSeller<'info> {
    #[account(mut, has_one = vault, has_one = mint, has_one = rent_recipient)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: the seller's standard token account for the mint, by address, and no other account;
    /// the same rule as the buyer's (see `ReleaseToBuyer`).
    #[account(mut, address = escrow.payout_address(&token_program.key()) @ EscrowError::NotTheSellersAccount)]
    pub seller_tokens: UncheckedAccount<'info>,
    /// CHECK: the payer's key, recorded at creation as the rent recipient, checked by `has_one`.
    /// It only receives lamports.
    #[account(mut)]
    pub rent_recipient: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    /// Checked against the escrow's buyer in the handler.
    pub buyer: Signer<'info>,
}

/// The seller gives. Names only the buyer's account: the seller is paid nothing.
#[derive(Accounts)]
pub struct ReleaseToBuyer<'info> {
    #[account(mut, has_one = vault, has_one = mint, has_one = rent_recipient)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: the buyer's standard token account for the mint, by address, and no other account.
    /// Checked by address alone, not by who holds it now, so a buyer who hands it to another key
    /// cannot block an ending. The token program checks the rest when it is paid: an initialized
    /// token account of that program for the same mint, not frozen.
    #[account(mut, address = escrow.refund_address(&token_program.key()) @ EscrowError::NotTheRefundAddress)]
    pub buyer_tokens: UncheckedAccount<'info>,
    /// CHECK: the payer's key, recorded at creation as the rent recipient, checked by `has_one`.
    /// It only receives lamports.
    #[account(mut)]
    pub rent_recipient: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    /// Checked against the escrow's seller in the handler.
    pub seller: Signer<'info>,
}

/// Both parties sign a split.
#[derive(Accounts)]
pub struct Split<'info> {
    #[account(mut, has_one = vault, has_one = mint, has_one = rent_recipient)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: the buyer's standard token account for the mint, by address, and no other account;
    /// see `ReleaseToBuyer`. It needs to exist only if the buyer's share is above zero.
    #[account(mut, address = escrow.refund_address(&token_program.key()) @ EscrowError::NotTheRefundAddress)]
    pub buyer_tokens: UncheckedAccount<'info>,
    /// CHECK: the seller's standard token account for the mint, by address, and no other account;
    /// the same rule as the buyer's (see `ReleaseToBuyer`).
    #[account(mut, address = escrow.payout_address(&token_program.key()) @ EscrowError::NotTheSellersAccount)]
    pub seller_tokens: UncheckedAccount<'info>,
    /// CHECK: the payer's key, recorded at creation as the rent recipient, checked by `has_one`.
    /// It only receives lamports.
    #[account(mut)]
    pub rent_recipient: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    /// Checked against the escrow's buyer in the handler.
    pub buyer: Signer<'info>,
    /// Checked against the escrow's seller in the handler.
    pub seller: Signer<'info>,
}

/// The arbiter named at creation signs a split. The same accounts as `Split`, one signer.
#[derive(Accounts)]
pub struct Arbitrate<'info> {
    #[account(mut, has_one = vault, has_one = mint, has_one = rent_recipient)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: the buyer's standard token account for the mint, by address, and no other account;
    /// see `ReleaseToBuyer`. It needs to exist only if the buyer's share is above zero.
    #[account(mut, address = escrow.refund_address(&token_program.key()) @ EscrowError::NotTheRefundAddress)]
    pub buyer_tokens: UncheckedAccount<'info>,
    /// CHECK: the seller's standard token account for the mint, by address, and no other account;
    /// the same rule as the buyer's (see `ReleaseToBuyer`).
    #[account(mut, address = escrow.payout_address(&token_program.key()) @ EscrowError::NotTheSellersAccount)]
    pub seller_tokens: UncheckedAccount<'info>,
    /// CHECK: the payer's key, recorded at creation as the rent recipient, checked by `has_one`.
    /// It only receives lamports.
    #[account(mut)]
    pub rent_recipient: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    /// Checked against the escrow's arbiter in the handler.
    pub arbiter: Signer<'info>,
}

/// The timer pays one side, so it names one account. No signer: anyone may send it.
#[derive(Accounts)]
pub struct TimerRelease<'info> {
    #[account(mut, has_one = vault, has_one = mint, has_one = rent_recipient)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: checked in the handler, by address, against the side the timer names: that side's
    /// standard token account for the mint. The token program checks the rest when it is paid.
    #[account(mut)]
    pub to: UncheckedAccount<'info>,
    /// CHECK: the payer's key, recorded at creation as the rent recipient, checked by `has_one`.
    /// It only receives lamports.
    #[account(mut)]
    pub rent_recipient: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

/// Closing an escrow that never held the amount. The only instruction that closes an escrow
/// account, and only this kind. It pays the seller nothing and names no seller account.
#[derive(Accounts)]
pub struct CloseUnfunded<'info> {
    #[account(mut, close = rent_recipient, has_one = vault, has_one = mint, has_one = rent_recipient)]
    pub escrow: Account<'info, Escrow>,
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: the buyer's standard token account for the mint, by address, and no other account;
    /// see `ReleaseToBuyer`. It needs to exist only if the deposit account holds anything, so an
    /// escrow nobody paid closes without anyone making the buyer an account.
    #[account(mut, address = escrow.refund_address(&token_program.key()) @ EscrowError::NotTheRefundAddress)]
    pub buyer_tokens: UncheckedAccount<'info>,
    /// CHECK: the payer's key, recorded at creation as the rent recipient, checked by `has_one`.
    /// It only receives lamports.
    #[account(mut)]
    pub rent_recipient: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    /// The buyer or the seller; checked in the handler.
    pub closer: Signer<'info>,
}

/// Late money back to the buyer: `recover_late`. The escrow is read only, because the receipt
/// does not change.
#[derive(Accounts)]
pub struct RecoverLate<'info> {
    #[account(has_one = vault, has_one = buyer, has_one = mint)]
    pub escrow: Account<'info, Escrow>,
    /// The deposit address, made again by a payment that came after the end. If nothing made it
    /// again, there is nothing to recover and this fails to load.
    #[account(mut)]
    pub vault: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: the buyer recorded at creation, checked by `has_one`. It owns the refund account and
    /// receives the deposit account's rent.
    #[account(mut)]
    pub buyer: UncheckedAccount<'info>,
    /// The buyer's refund address: its associated token account for the mint, under the mint's
    /// token program, and no other account. Made here, at the caller's cost, if it does not exist.
    #[account(
        init_if_needed,
        payer = caller,
        associated_token::mint = mint,
        associated_token::authority = buyer,
        associated_token::token_program = token_program,
    )]
    pub refund: InterfaceAccount<'info, TokenAccount>,
    /// The escrow's mint, owned by `token_program`.
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,
    /// Anyone. Pays for the refund account if it has to be made.
    #[account(mut)]
    pub caller: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// Rent above the minimum back to the payer: `sweep_rent`. No signer.
#[derive(Accounts)]
pub struct SweepRent<'info> {
    #[account(mut, has_one = payer)]
    pub escrow: Account<'info, Escrow>,
    /// CHECK: the key that fronted the rent, recorded at creation, checked by `has_one`. It only
    /// receives lamports.
    #[account(mut)]
    pub payer: UncheckedAccount<'info>,
}

// ---------------------------------------------------------------------------------------------
// Events. Every state change, with amounts, so an index can read outcomes from the log alone.
// ---------------------------------------------------------------------------------------------

#[event]
pub struct Created {
    pub escrow: Pubkey,
    pub version: u8,
    pub id: u64,
    pub buyer: Pubkey,
    pub seller: Pubkey,
    /// Who opened it. The seller, for an invoice.
    pub creator: Side,
    /// The zero key when none.
    pub arbiter: Pubkey,
    pub mint: Pubkey,
    pub vault: Pubkey,
    pub rent_recipient: Pubkey,
    pub amount: u64,
    /// 0 when there is no timer.
    pub timer_days: u16,
    /// Meaningless when `timer_days` is 0.
    pub timer_to: Side,
    pub created_at: i64,
    /// The key that fronted the rent; rent above the receipt's minimum goes back to it.
    pub payer: Pubkey,
}

/// `mark_funded` saw the deposit account holding the amount. The timer counts from `funded_at`.
#[event]
pub struct Funded {
    pub escrow: Pubkey,
    pub balance: u64,
    pub funded_at: i64,
}

/// Every ending of an escrow that held the amount. `balance` is what the deposit account held;
/// `to_seller + to_buyer == balance`. The deposit account's rent went back to the payer; the
/// escrow account stays, holding the same numbers, as the receipt. `funded_at` is the mark's time,
/// or `ended_at` when nobody marked it.
#[event]
pub struct Ended {
    pub escrow: Pubkey,
    pub outcome: Outcome,
    pub amount: u64,
    pub balance: u64,
    pub to_seller: u64,
    pub to_buyer: u64,
    pub ended_at: i64,
    pub rent_recipient: Pubkey,
    pub rent_lamports: u64,
    pub funded_at: i64,
}

/// An escrow that never held the amount, closed. Whatever the deposit account held went back to
/// the buyer; both accounts are gone and both rents went back to the payer. Not a receipt of
/// anything: nothing was dealt.
#[event]
pub struct Closed {
    pub escrow: Pubkey,
    pub closed_by: Pubkey,
    pub to_buyer: u64,
    pub rent_recipient: Pubkey,
    pub rent_lamports: u64,
}

/// Money that arrived after the end went back to the buyer's refund address, and the deposit
/// account closed again with its rent to the buyer. The receipt did not change.
#[event]
pub struct RecoveredLate {
    pub escrow: Pubkey,
    pub to_buyer: u64,
    pub rent_lamports: u64,
}

/// Lamports above the escrow account's rent-exempt minimum went to the payer; `left` is the
/// minimum it still holds.
#[event]
pub struct RentSwept {
    pub escrow: Pubkey,
    /// The key that fronted the rent, recorded at creation: where the lamports went.
    pub payer: Pubkey,
    pub lamports: u64,
    pub left: u64,
}

/// A party objected. From here on the timer never runs; the receipt keeps who and when.
#[event]
pub struct Objected {
    pub escrow: Pubkey,
    pub by: Side,
    pub objected_at: i64,
}

/// Compile-time proof that the sealed size is what `state.rs` says it is.
const _: () = {
    assert!(Escrow::LEN == 297);
    assert!(BPS == 10_000);
};
