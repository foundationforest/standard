//! The escrow under Trident.
//!
//! Random flows against the built program (`../target/deploy/forest_escrow.so`), with a model
//! of every escrow kept beside it. The model is the README's state table written out a third
//! time: for every instruction the fuzzer sends, it says whether the program must accept it and,
//! if so, exactly what moves. After every step the invariants below are checked.
//!
//! Trident's runtime does not check signatures: an account marked as a signer is taken as signed.
//! So every key here can "sign", and every authority rule has to hold on key comparisons alone.
//!
//! Invariants, for the escrow `escrow/README.md` describes (money in, and out only when the two
//! sides agree; an arbiter and a timer only if the creator turned them on; either side may object
//! once, which turns the timer off):
//!   I1 every deposit account holds exactly what was sent to it;
//!   I2 every way out pays out the whole balance, no more and no less, and a split gives the
//!      seller exactly its basis points of the balance, rounded down;
//!   I3 rent goes back to the payer who fronted it, to the lamport, and to nobody else: the
//!      deposit account's at every ending, the escrow account's too only when it never held the
//!      amount, and what a sweep takes above the escrow account's minimum; a deposit account made
//!      again after the end goes back to the buyer with the late money;
//!   I4 an ended escrow accepts nothing but `recover_late` and `sweep_rent`, even after a later
//!      payment re-creates its deposit account, and its address never opens again;
//!   I5 money leaves a funded escrow only with an authority named at creation: the buyer's
//!      release to the seller, the seller's release to the buyer, both signing a split, the
//!      arbiter named at creation, or the timer set at creation once due and while nobody has
//!      objected; checked on every
//!      accepted way out by a separate `authorized` test, apart from the model's own verdict;
//!      and it lands only at the receiving party's standard token account for the mint;
//!   I6 no token is created or destroyed: every balance, every standard account and every
//!      deposit account add up to a constant;
//!   I7 the program accepts exactly what the model allows, and refuses everything else;
//!   I8 a receipt, once written, never changes its bytes and never closes, and says when the
//!      money was there: the mark's time, or the ending's if nobody marked it;
//!   I9 late money always reaches the buyer: `recover_late` runs whenever an ended escrow's
//!      deposit account exists, and pays exactly what it held to the buyer's standard account;
//!   I10 a sweep never breaches the minimum: every escrow account always holds at least its
//!      rent-exempt minimum, and a sweep leaves exactly that and pays the rest to the payer;
//!   I11 nothing is stuck: at the end of every run, every live escrow is ended by the parties'
//!      own signatures (a funded one by the buyer's release, a never-funded one by its
//!      creator's close), and every unit comes out;
//!   I12 a timer never pays before it is due: never before `timer_days` whole days after the mark;
//!   I13 an escrow's address is its terms': `create` lands only at `["escrow", SHA-256 of every
//!      term]`, with the buyer or the seller signing, so a payment to an address counts only toward
//!      a deal with exactly its terms;
//!   I14 no arbiter is a party: `create` refuses the buyer or the seller as arbiter;
//!   I15 an objection moves nothing and changes only the escrow's objection and its time; it lands
//!      once per escrow, from the buyer or the seller only, and only before the timer is due; after
//!      it the timer never pays. So at no second can both an objection and the timer land.
//!
//! Run: `cargo run --release --bin fuzz_escrow` from this directory (after `cargo build-sbf --arch
//! v0` in `escrow/program`: Trident's runtime runs no v3 program). The mint is a classic SPL Token
//! mint; Token-2022 is the LiteSVM tests' alone. `FOREST_FUZZ_ITERATIONS` and `FOREST_FUZZ_FLOWS` set the size;
//! `FUZZING_METRICS=1 FUZZING_JSON=metrics.json` writes Trident's per-instruction outcome counts.

use sha2::{Digest, Sha256};
use trident_fuzz::fuzzing::*;

const PROGRAM_ID: Pubkey = pubkey!("FoRE2EscrowV2objectsTimerFundedAtPayer222222");
const TOKEN_PROGRAM: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA_PROGRAM: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const SYSTEM_PROGRAM: Pubkey = pubkey!("11111111111111111111111111111111");
const NATIVE_MINT: Pubkey = pubkey!("So11111111111111111111111111111111111111112");
const BPS: u16 = 10_000;
const DAY: i64 = 86_400;
const T0: i64 = 1_800_000_000;
const START_TOKENS: u64 = 100_000_000_000_000_000;
/// People: two buyers, two sellers, an arbiter, a stranger and a sponsor. Anyone can be anything.
const PEOPLE: usize = 7;
const SPONSOR: usize = 6;
/// Side bytes, as the program stores them.
const BUYER: u8 = 0;
const SELLER: u8 = 1;
/// The receipt's offsets after the eight-byte discriminator.
const AT_RENT_RECIPIENT: usize = 169;
const AT_CREATOR: usize = 209;
const AT_FUNDED_AT: usize = 221;
const AT_STATUS: usize = 229;
const AT_OUTCOME: usize = 239;
const AT_TO_SELLER: usize = 240;
const AT_TO_BUYER: usize = 248;
const AT_PAYER: usize = 256;
const AT_OBJECTION: usize = 288;
const AT_OBJECTED_AT: usize = 289;
const ENDED: u8 = 2;
/// Objection bytes, as the program stores them.
const NOBODY: u8 = 0;

fn disc(namespace: &str, name: &str) -> [u8; 8] {
    Sha256::digest(format!("{namespace}:{name}").as_bytes())[..8].try_into().unwrap()
}

fn share(amount: u64, bps: u16) -> u64 {
    ((u128::from(amount) * u128::from(bps)) / u128::from(BPS)) as u64
}

/// The escrow's address: `["escrow", SHA-256 of every term]`, each term at a fixed length in the
/// receipt's order (`state::terms_hash`), written here a fourth time.
fn escrow_address(id: u64, buyer: &Pubkey, seller: &Pubkey, arbiter: Option<Pubkey>, mint: &Pubkey, amount: u64, timer: Option<(u16, u8)>) -> Pubkey {
    let (days, side) = timer.unwrap_or((0, BUYER));
    let mut h = Sha256::new();
    h.update(id.to_le_bytes());
    h.update(buyer.as_ref());
    h.update(seller.as_ref());
    h.update(arbiter.unwrap_or_default().as_ref());
    h.update(mint.as_ref());
    h.update(amount.to_le_bytes());
    h.update(days.to_le_bytes());
    h.update([side]);
    let hash: [u8; 32] = h.finalize().into();
    Pubkey::find_program_address(&[b"escrow", &hash], &PROGRAM_ID).0
}

fn ata(owner: &Pubkey, mint: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[owner.as_ref(), TOKEN_PROGRAM.as_ref(), mint.as_ref()], &ATA_PROGRAM).0
}

fn token_account(mint: &Pubkey, owner: &Pubkey, amount: u64) -> AccountSharedData {
    let mut d = vec![0u8; 165];
    d[..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d[64..72].copy_from_slice(&amount.to_le_bytes());
    d[108] = 1;
    let mut a = AccountSharedData::new(2_039_280, 165, &TOKEN_PROGRAM);
    a.set_data_from_slice(&d);
    a
}

fn mint_account(decimals: u8) -> AccountSharedData {
    let mut d = vec![0u8; 82];
    d[44] = decimals;
    d[45] = 1;
    let mut a = AccountSharedData::new(1_461_600, 82, &TOKEN_PROGRAM);
    a.set_data_from_slice(&d);
    a
}

#[derive(Clone, Debug)]
struct Deal {
    escrow: Pubkey,
    vault: Pubkey,
    buyer: Pubkey,
    seller: Pubkey,
    creator: u8,
    arbiter: Option<Pubkey>,
    /// (days, side)
    timer: Option<(u16, u8)>,
    /// Where every rent goes back: the payer's key.
    rent_recipient: Pubkey,
    /// Who fronted the rent at creation: the payer recorded, which gets every rent back.
    payer: Pubkey,
    amount: u64,
    /// When `mark_funded` ran, or 0. An ending nobody marked writes its own time into the receipt;
    /// the model keeps 0 here and checks the receipt for it.
    funded_at: i64,
    /// Which side objected (`NOBODY`, then 1 the buyer, 2 the seller), and when.
    objection: u8,
    objected_at: i64,
    deposited: u64,
    /// Paid out: the escrow account stays as the receipt.
    ended: bool,
    /// Closed without ever holding the amount: both accounts gone, the address free again.
    closed: bool,
    /// The receipt's bytes, as the ending left them. Its lamports may move (a tip in, a sweep out),
    /// never below the minimum.
    receipt: Option<Vec<u8>>,
}

impl Deal {
    fn live(&self) -> bool {
        !self.ended && !self.closed
    }
    fn creator_key(&self) -> Pubkey {
        if self.creator == BUYER { self.buyer } else { self.seller }
    }
    fn marked(&self) -> bool {
        self.funded_at != 0
    }
    /// When the timer is due; `None` with no timer or before the mark. An objection does not move
    /// it: it stops the timer from paying, and stops further objections from that second on.
    fn timer_due(&self) -> Option<i64> {
        match self.timer {
            Some((days, _)) if self.marked() => self.funded_at.checked_add(i64::from(days) * DAY),
            _ => None,
        }
    }
}

#[derive(Default, Clone, Copy)]
struct Counts {
    accepted: u64,
    refused: u64,
}

#[derive(FuzzTestMethods)]
struct FuzzTest {
    trident: Trident,
    people: Vec<Pubkey>,
    /// Each person's everyday token account for the mint: not their standard one.
    tokens: Vec<Pubkey>,
    /// Each person's standard token account for the mint. Most people start with one; the rest
    /// get it from `make_refund`, or from `recover_late` when a buyer is paid there first. Every
    /// payout to either party lands here and nowhere else.
    refunds: Vec<Pubkey>,
    /// An escrow account's rent-exempt minimum: what `create` put in the first one. Trident's rent
    /// rate never changes, and every escrow account has the same size.
    escrow_min: u64,
    mint: Pubkey,
    deals: Vec<Deal>,
    total_tokens: u128,
    counts: std::collections::BTreeMap<&'static str, Counts>,
    /// Trident's per-iteration account storage. Unused: the model above keeps every address.
    fuzz_accounts: FuzzAccounts,
}

#[derive(Default)]
struct FuzzAccounts {}

#[flow_executor]
impl FuzzTest {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            people: vec![],
            tokens: vec![],
            refunds: vec![],
            escrow_min: 0,
            mint: Pubkey::default(),
            deals: vec![],
            total_tokens: 0,
            counts: Default::default(),
            fuzz_accounts: FuzzAccounts::default(),
        }
    }

    #[init]
    fn start(&mut self) {
        self.trident.warp_to_timestamp(T0);
        self.people.clear();
        self.tokens.clear();
        self.refunds.clear();
        self.deals.clear();
        self.mint = self.trident.random_pubkey();
        let mint = self.mint;
        self.trident.set_account_custom(&mint, &mint_account(6));
        self.trident.set_account_custom(&NATIVE_MINT, &mint_account(9));
        for _ in 0..PEOPLE {
            let p = self.trident.random_pubkey();
            self.trident.airdrop(&p, 1_000 * LAMPORTS_PER_SOL);
            let t = self.trident.random_pubkey();
            self.trident.set_account_custom(&t, &token_account(&mint, &p, START_TOKENS));
            self.people.push(p);
            self.tokens.push(t);
            let refund = ata(&p, &mint);
            if self.pick(4) != 0 {
                self.trident.set_account_custom(&refund, &token_account(&mint, &p, 0));
            }
            self.refunds.push(refund);
        }
        self.total_tokens = u128::from(START_TOKENS) * PEOPLE as u128;
    }

    // -- flows --------------------------------------------------------------------------------

    #[flow]
    fn create(&mut self) {
        let buyer_i = self.pick(PEOPLE);
        let buyer = self.people[buyer_i];
        let native = self.pick(40) == 0;
        let mint = if native { NATIVE_MINT } else { self.mint };
        // Mostly well-formed terms, so the ways out get exercised; each malformed choice ~3%.
        let seller = match self.pick(33) {
            0 => Pubkey::default(),
            1 => buyer,
            _ => self.other_than(buyer_i),
        };
        let arbiter = match self.pick(33) {
            0 => Some(Pubkey::default()),
            1..=3 => Some(buyer),
            4..=6 => Some(seller),
            k if k < 20 => None,
            _ => Some(self.person()),
        };
        let timer: Option<(u16, u8)> = match self.pick(33) {
            0 => Some((0, self.side())),
            1 => Some((u16::MAX, self.side())),
            k if k < 16 => None,
            _ => Some((self.trident.random_from_range(1..=3), self.side())),
        };
        let amount = self.amount();
        let id: u64 = self.trident.random_from_range(0..6);
        // Who fronts the rent: the buyer, a sponsor (a fee payer, in production), or anyone.
        let payer_i = match self.pick(3) {
            0 => buyer_i,
            1 => SPONSOR,
            _ => self.pick(PEOPLE),
        };
        let payer = self.people[payer_i];
        // Who opens it: the buyer, proposing; the seller, invoicing; now and then someone else.
        let creator = match self.pick(20) {
            0 => self.person(),
            k if k < 8 => seller,
            _ => buyer,
        };

        // The address is the terms'; now and then the sender aims at the address of other terms,
        // the same but for the id or the buyer (I13).
        let own = escrow_address(id, &buyer, &seller, arbiter, &mint, amount, timer);
        let escrow = match self.pick(40) {
            0 => escrow_address(id ^ 1, &buyer, &seller, arbiter, &mint, amount, timer),
            1 => escrow_address(id, &self.person(), &seller, arbiter, &mint, amount, timer),
            _ => own,
        };
        let vault = ata(&escrow, &mint);
        // An address is taken while a deal there is live, and for good once one has ended.
        let taken = self.deals.iter().any(|d| d.escrow == escrow && !d.closed);
        let valid = escrow == own
            && seller != buyer
            && seller != Pubkey::default()
            && (creator == buyer || creator == seller)
            && arbiter != Some(Pubkey::default())
            && arbiter != Some(buyer)
            && arbiter != Some(seller)
            && !native
            && amount > 0
            && timer.map_or(true, |(days, _)| days > 0)
            && !taken;

        let mut data = disc("global", "create").to_vec();
        data.extend_from_slice(&id.to_le_bytes());
        data.extend_from_slice(buyer.as_ref());
        data.extend_from_slice(seller.as_ref());
        data.extend_from_slice(&amount.to_le_bytes());
        match arbiter {
            Some(k) => {
                data.push(1);
                data.extend_from_slice(k.as_ref());
            }
            None => data.push(0),
        }
        match timer {
            Some((days, side)) => {
                data.push(1);
                data.extend_from_slice(&days.to_le_bytes());
                data.push(side);
            }
            None => data.push(0),
        }
        // What the client sends: the deposit address made first, by the payer, as its own
        // instruction (so a fee payer that checks every destination finds it made), then `create`.
        // Now and then `create` alone, which makes it itself.
        let mut ixs = vec![];
        if !native && self.pick(3) != 0 {
            ixs.push(self.make_ata_ix(payer_i, vault, escrow));
        }
        ixs.push(Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(escrow, false),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(creator, true),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(TOKEN_PROGRAM, false),
                AccountMeta::new_readonly(ATA_PROGRAM, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            data,
        });
        let vault_before = self.trident.get_account(&vault);
        let prefunded = token_amount_of(&vault_before);
        let payer_before = self.lamports(&payer);
        let ok = self.send(&ixs, "create");
        assert_eq!(ok, valid, "I7 create: model says {valid}, program said {ok}");
        if !ok {
            return;
        }
        // Rent: the payer paid for the escrow account, and for the deposit account if create made it.
        let paid = payer_before - self.lamports(&payer);
        let made_vault = if vault_before.lamports() == 0 { self.lamports(&vault) } else { 0 };
        assert_eq!(paid, self.lamports(&escrow) + made_vault, "I3 create: the payer paid both rents and nothing else");
        if self.escrow_min == 0 {
            self.escrow_min = self.lamports(&escrow);
        }
        assert_eq!(self.lamports(&escrow), self.escrow_min, "I10 create: an escrow account starts at its minimum");
        let bytes = self.trident.get_account(&escrow).data().to_vec();
        let creator_byte = if creator == buyer { BUYER } else { SELLER };
        assert_eq!(bytes[8 + AT_CREATOR], creator_byte, "create: the receipt names its creator");
        assert_eq!(&bytes[8 + AT_RENT_RECIPIENT..8 + AT_RENT_RECIPIENT + 32], payer.as_ref(), "I3 create: the rent recipient is the payer");
        assert_eq!(&bytes[8 + AT_PAYER..8 + AT_PAYER + 32], payer.as_ref(), "I3 create: the payer is whoever fronted the rent");
        assert_eq!(bytes[8 + AT_OBJECTION], NOBODY, "I15 create: nobody has objected");
        self.deals.push(Deal {
            escrow,
            vault,
            buyer,
            seller,
            creator: creator_byte,
            arbiter,
            timer,
            rent_recipient: payer,
            payer,
            amount,
            funded_at: 0,
            objection: NOBODY,
            objected_at: 0,
            deposited: prefunded,
            ended: false,
            closed: false,
            receipt: None,
        });
    }

    /// A plain transfer into a deposit account, from anyone. If the deposit account does not exist
    /// (a deal that ended or was closed), a wallet app would create it first: so does this.
    #[flow]
    fn deposit(&mut self) {
        let Some(d) = self.any_deal() else { return };
        let from = self.pick(PEOPLE);
        let have = self.vault_balance(&d);
        let amount = match self.pick(6) {
            0..=2 => d.amount.saturating_sub(have).max(1), // exactly enough
            3 => d.amount.saturating_sub(have).saturating_sub(1).max(1), // one short
            4 => self.trident.random_from_range(1..1_000),
            _ => self.amount(),
        }
        .min(START_TOKENS / 1000);
        if amount == 0 {
            return;
        }
        let mut ixs = vec![];
        if self.trident.get_account(&d.vault).lamports() == 0 {
            ixs.push(self.make_ata_ix(from, d.vault, d.escrow));
        }
        let mut data = vec![3u8];
        data.extend_from_slice(&amount.to_le_bytes());
        ixs.push(Instruction {
            program_id: TOKEN_PROGRAM,
            accounts: vec![
                AccountMeta::new(self.tokens[from], false),
                AccountMeta::new(d.vault, false),
                AccountMeta::new_readonly(self.people[from], true),
            ],
            data,
        });
        let ok = self.send(&ixs, "deposit");
        assert!(ok, "a plain transfer to a deposit address must land");
        // The newest deal at this address owns what arrives, live or not. An ended one's deposit
        // account waits for `recover_late`; a never-funded one that was closed keeps it until the
        // same terms are opened again, which adopts it.
        let latest = self.latest_at(&d.escrow);
        self.deals[latest].deposited += amount;
    }

    /// Anyone makes someone's standard account, the idempotent way: what the sender of a way out
    /// does first when the party paid has none.
    #[flow]
    fn make_refund(&mut self) {
        let owner_i = self.pick(PEOPLE);
        let payer_i = self.pick(PEOPLE);
        let ix = self.make_ata_ix(payer_i, self.refunds[owner_i], self.people[owner_i]);
        let ok = self.send(&[ix], "make_refund");
        assert!(ok, "making a standard token account, or finding it there, must land");
    }

    /// What a buyer's app does: send exactly what is missing and mark it, in one transaction.
    #[flow]
    fn fund_and_mark(&mut self) {
        let Some(i) = self.latest_deal() else { return };
        let d = self.deals[i].clone();
        if !d.live() {
            return;
        }
        let have = self.vault_balance(&d);
        let missing = d.amount.saturating_sub(have);
        let buyer_i = self.index_of(&d.buyer);
        let mut ixs = vec![];
        if missing > 0 {
            let mut data = vec![3u8];
            data.extend_from_slice(&missing.to_le_bytes());
            ixs.push(Instruction {
                program_id: TOKEN_PROGRAM,
                accounts: vec![
                    AccountMeta::new(self.tokens[buyer_i], false),
                    AccountMeta::new(d.vault, false),
                    AccountMeta::new_readonly(d.buyer, true),
                ],
                data,
            });
        }
        let marks = !d.marked();
        if marks {
            ixs.push(self.mark_ix(&d));
        }
        if ixs.is_empty() {
            return;
        }
        let now = self.now();
        let ok = self.send(&ixs, "fund_and_mark");
        assert!(ok, "I7 fund_and_mark: exactly the missing amount, then mark_funded, must land");
        self.deals[i].deposited += missing;
        if marks {
            self.deals[i].funded_at = now;
        }
    }

    #[flow]
    fn mark_funded(&mut self) {
        let Some(i) = self.latest_deal() else { return };
        let d = self.deals[i].clone();
        let balance = self.vault_balance(&d);
        let vault_exists = self.lamports(&d.vault) > 0;
        let valid = d.live() && vault_exists && !d.marked() && balance >= d.amount;
        let ix = self.mark_ix(&d);
        // Trident's runtime moves its clock on by the wall-clock seconds that pass after each
        // transaction, so the time the program saw is the one read before sending, not after.
        let now = self.now();
        let ok = self.send(&[ix], "mark_funded");
        assert_eq!(ok, valid, "I4/I7 mark_funded: model {valid}, program {ok}");
        if ok {
            self.deals[i].funded_at = now;
        }
    }

    /// A party objects: usually the buyer or the seller, now and then anyone. Moves nothing.
    #[flow]
    fn object(&mut self) {
        let Some(i) = self.latest_deal() else { return };
        let d = self.deals[i].clone();
        let actor = match self.pick(10) {
            0..=3 => d.buyer,
            4..=7 => d.seller,
            _ => self.person(),
        };
        let side = if actor == d.buyer {
            1
        } else if actor == d.seller {
            2
        } else {
            NOBODY
        };
        let now = self.now();
        let before_due = d.timer_due().map_or(true, |due| now < due);
        let valid = d.live() && side != NOBODY && d.objection == NOBODY && before_due;
        let bytes = self.trident.get_account(&d.escrow).data().to_vec();
        let lamports = self.lamports(&d.escrow);
        let balance = self.vault_balance(&d);
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![AccountMeta::new(d.escrow, false), AccountMeta::new_readonly(actor, true)],
            data: disc("global", "object").to_vec(),
        };
        let ok = self.send(&[ix], "object");
        assert_eq!(ok, valid, "I7/I15 object: model {valid}, program {ok} (deal {d:?}, now {now})");
        if !ok {
            return;
        }
        let after = self.trident.get_account(&d.escrow);
        let b = after.data();
        assert_eq!(b[8 + AT_OBJECTION], side, "I15 object: the receipt names the side");
        assert_eq!(i64::from_le_bytes(b[8 + AT_OBJECTED_AT..8 + AT_OBJECTED_AT + 8].try_into().unwrap()), now, "I15 object: and the time");
        assert_eq!(&b[..8 + AT_OBJECTION], &bytes[..8 + AT_OBJECTION], "I15 object: nothing else in the account changes");
        assert_eq!(after.lamports(), lamports, "I15 object: no lamports move");
        assert_eq!(self.vault_balance(&d), balance, "I15 object: no token moves");
        self.deals[i].objection = side;
        self.deals[i].objected_at = now;
    }

    #[flow]
    fn release_to_seller(&mut self) {
        self.way_out("release_to_seller");
    }
    #[flow]
    fn release_to_buyer(&mut self) {
        self.way_out("release_to_buyer");
    }
    #[flow]
    fn split(&mut self) {
        self.way_out("split");
    }
    #[flow]
    fn arbitrate(&mut self) {
        self.way_out("arbitrate");
    }
    #[flow]
    fn timer_release(&mut self) {
        self.way_out("timer_release");
    }
    #[flow]
    fn close_unfunded(&mut self) {
        self.way_out("close_unfunded");
    }

    /// SOL sent to an escrow's address, live or ended. It never counts as funding; a sweep takes it
    /// out again, to the payer. Closed addresses are left alone: a tip there would pre-fund an
    /// address a later `create` may use, which is not what this model counts.
    #[flow]
    fn tip(&mut self) {
        let Some(d) = self.any_deal() else { return };
        let d = self.deals[self.latest_at(&d.escrow)].clone();
        if d.closed {
            return;
        }
        let from = self.person();
        let lamports: u64 = self.trident.random_from_range(1..10_000_000);
        let mut data = 2u32.to_le_bytes().to_vec();
        data.extend_from_slice(&lamports.to_le_bytes());
        let ix = Instruction {
            program_id: SYSTEM_PROGRAM,
            accounts: vec![AccountMeta::new(from, true), AccountMeta::new(d.escrow, false)],
            data,
        };
        let ok = self.send(&[ix], "tip");
        assert!(ok, "a plain SOL transfer to an escrow's address lands");
    }

    /// Rent above the minimum back to the payer recorded at creation; anyone sends it, on any
    /// escrow. Now and then it names the creator, or anyone, instead.
    #[flow]
    fn sweep_rent(&mut self) {
        let Some(d) = self.any_deal() else { return };
        let i = self.latest_at(&d.escrow);
        let d = self.deals[i].clone();
        let payer_i = self.index_of(&d.payer);
        let rp_i = match self.pick(10) {
            0 => self.pick(PEOPLE),
            1 => self.index_of(&d.creator_key()),
            _ => payer_i,
        };
        let lamports = self.lamports(&d.escrow);
        let excess = lamports.saturating_sub(self.escrow_min);
        let valid = !d.closed && lamports > 0 && rp_i == payer_i && excess > 0;
        let before: Vec<u64> = (0..PEOPLE).map(|k| self.lamports(&self.people[k].clone())).collect();
        let bytes = self.trident.get_account(&d.escrow).data().to_vec();
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![AccountMeta::new(d.escrow, false), AccountMeta::new(self.people[rp_i], false)],
            data: disc("global", "sweep_rent").to_vec(),
        };
        let ok = self.send(&[ix], "sweep_rent");
        assert_eq!(ok, valid, "I7/I10 sweep_rent: model {valid}, program {ok} (deal {d:?}, lamports {lamports})");
        if !ok {
            return;
        }
        assert_eq!(self.lamports(&d.escrow), self.escrow_min, "I10 sweep_rent: exactly the minimum left");
        for k in 0..PEOPLE {
            let want = if k == payer_i { before[k] + excess } else { before[k] };
            assert_eq!(self.lamports(&self.people[k].clone()), want, "I3/I10 sweep_rent: the excess to the payer and nobody else (person {k})");
        }
        assert_eq!(self.trident.get_account(&d.escrow).data(), &bytes[..], "I8/I10 sweep_rent: the bytes do not change");
    }

    /// Late money back to the buyer. Anyone sends it, usually on an ended escrow, usually naming
    /// the buyer's standard account.
    #[flow]
    fn recover_late(&mut self) {
        let Some(i) = self.ended_deal().or_else(|| self.latest_deal()) else { return };
        let caller_i = self.pick(PEOPLE);
        let wrong_buyer = self.pick(20) == 0;
        let refund_choice = self.pick(20);
        self.send_recover_late(i, caller_i, wrong_buyer, refund_choice);
    }

    /// Time moves: by a random stretch, or to a second either side of a deal's timer.
    #[flow]
    fn time_passes(&mut self) {
        let target = match (self.pick(3), self.latest_deal()) {
            (0, Some(i)) => {
                let Some(due) = self.deals[i].timer_due() else { return };
                due.saturating_add(self.trident.random_from_range(-1..=1))
            }
            _ => self.now().saturating_add(match self.pick(4) {
                0 => self.trident.random_from_range(1..120),
                1 => self.trident.random_from_range(1..DAY),
                _ => self.trident.random_from_range(1..4 * DAY),
            }),
        };
        // The cluster clock never runs backwards.
        if target > self.now() && target < T0 + 100_000 * DAY {
            self.trident.warp_to_timestamp(target);
        }
    }

    #[end]
    fn end(&mut self) {
        self.nothing_is_stuck();
        self.check_everything();
        let mut all = std::collections::BTreeMap::new();
        std::mem::swap(&mut all, &mut self.counts);
        for (k, c) in all {
            self.trident.record_accumulator(&format!("{k} accepted"), c.accepted as f64);
            self.trident.record_accumulator(&format!("{k} refused"), c.refused as f64);
        }
    }

    // -- the ways out ---------------------------------------------------------------------------

    fn way_out(&mut self, name: &'static str) {
        let Some(i) = self.latest_deal() else { return };
        let d = self.deals[i].clone();
        let now = self.now();
        let actor = self.actor_for(&d, name);
        let second = if self.pick(4) == 0 { self.person() } else { d.seller };
        let bps: u16 = match self.pick(5) {
            0 => BPS + self.trident.random_from_range(1..100),
            1 => 0,
            2 => BPS,
            _ => self.trident.random_from_range(0..=BPS),
        };
        let buyer_i = self.index_of(&d.buyer);
        let seller_i = self.index_of(&d.seller);
        let recipient_i = self.index_of(&d.rent_recipient);
        // Each party's slot: its standard account, or now and then another account it holds, or
        // anyone's. Only the standard account is right, by address.
        let buyer_account = self.pick_account(buyer_i);
        let seller_account = self.pick_account(seller_i);
        // The timer's one slot: whichever side it names, or now and then the other.
        let timer_side = d.timer.map(|(_, side)| side).unwrap_or(BUYER);
        let anyone = self.pick(PEOPLE);
        let to_account = match (timer_side, self.pick(8)) {
            (_, 0) => self.pick_account(anyone),
            (BUYER, _) => buyer_account,
            _ => seller_account,
        };
        // The rent slot: the payer, or now and then the creator, or anyone.
        let rp_i = match self.pick(20) {
            0 => self.pick(PEOPLE),
            1 => self.index_of(&d.creator_key()),
            _ => recipient_i,
        };

        let balance = self.vault_balance(&d);
        let vault_exists = self.lamports(&d.vault) > 0;
        let funded = balance >= d.amount;
        let buyer_right = buyer_account == self.refunds[buyer_i];
        let buyer_live = self.lamports(&self.refunds[buyer_i].clone()) > 0;
        let seller_right = seller_account == self.refunds[seller_i];
        let seller_live = self.lamports(&self.refunds[seller_i].clone()) > 0;

        // (valid, to_seller, to_buyer)
        let expect: (bool, u64, u64) = if !d.live() || !vault_exists || rp_i != recipient_i {
            (false, 0, 0)
        } else {
            match name {
                "release_to_seller" => (actor == d.buyer && funded && seller_right && seller_live, balance, 0),
                "release_to_buyer" => (actor == d.seller && funded && buyer_right && buyer_live, 0, balance),
                "split" | "arbitrate" => {
                    let signed = if name == "split" {
                        actor == d.buyer && second == d.seller
                    } else {
                        d.arbiter.is_some() && Some(actor) == d.arbiter
                    };
                    let to_seller = share(balance, bps.min(BPS));
                    let to_buyer = balance - to_seller;
                    let ok = signed
                        && bps <= BPS
                        && funded
                        && buyer_right
                        && seller_right
                        && (to_buyer == 0 || buyer_live)
                        && (to_seller == 0 || seller_live);
                    (ok, to_seller, to_buyer)
                }
                "timer_release" => {
                    let due = d.timer_due().map_or(false, |due| now >= due);
                    let to_right = match timer_side {
                        BUYER => to_account == self.refunds[buyer_i] && buyer_live,
                        _ => to_account == self.refunds[seller_i] && seller_live,
                    };
                    let (s, b) = if timer_side == SELLER { (balance, 0) } else { (0, balance) };
                    (d.timer.is_some() && d.objection == NOBODY && due && funded && to_right, s, b)
                }
                "close_unfunded" => {
                    let closer = actor == d.buyer || actor == d.seller;
                    (closer && !funded && buyer_right && (balance == 0 || buyer_live), 0, balance)
                }
                _ => unreachable!(),
            }
        };

        let mut metas = vec![
            AccountMeta::new(d.escrow, false),
            AccountMeta::new(d.vault, false),
            AccountMeta::new_readonly(self.mint, false),
        ];
        match name {
            "release_to_seller" => metas.push(AccountMeta::new(seller_account, false)),
            "release_to_buyer" | "close_unfunded" => metas.push(AccountMeta::new(buyer_account, false)),
            "timer_release" => metas.push(AccountMeta::new(to_account, false)),
            _ => {
                metas.push(AccountMeta::new(buyer_account, false));
                metas.push(AccountMeta::new(seller_account, false));
            }
        }
        metas.push(AccountMeta::new(self.people[rp_i], false));
        metas.push(AccountMeta::new_readonly(TOKEN_PROGRAM, false));
        let mut data = disc("global", name).to_vec();
        match name {
            "timer_release" => {}
            "split" => {
                metas.push(AccountMeta::new_readonly(actor, true));
                metas.push(AccountMeta::new_readonly(second, true));
                data.extend_from_slice(&bps.to_le_bytes());
            }
            "arbitrate" => {
                metas.push(AccountMeta::new_readonly(actor, true));
                data.extend_from_slice(&bps.to_le_bytes());
            }
            _ => metas.push(AccountMeta::new_readonly(actor, true)),
        }
        let paid_to = |name: &str| match name {
            "release_to_seller" => (seller_account, Pubkey::default()),
            "timer_release" if timer_side == SELLER => (to_account, Pubkey::default()),
            "timer_release" | "release_to_buyer" | "close_unfunded" => (Pubkey::default(), self.refunds[buyer_i]),
            _ => (seller_account, self.refunds[buyer_i]),
        };
        let (seller_paid_at, buyer_paid_at) = paid_to(name);
        let before_s = self.token_balance(&seller_paid_at);
        let before_b = self.token_balance(&buyer_paid_at);
        let escrow_rent = self.lamports(&d.escrow);
        let vault_rent = self.lamports(&d.vault);
        let before_rp: Vec<u64> = (0..PEOPLE).map(|k| self.lamports(&self.people[k].clone())).collect();

        let ok = self.send(&[Instruction { program_id: PROGRAM_ID, accounts: metas, data }], name);
        let (valid, to_seller, to_buyer) = expect;
        assert_eq!(ok, valid, "I4/I7 {name}: model {valid}, program {ok} (deal {d:?}, balance {balance}, now {now})");
        if !ok {
            return;
        }
        assert!(self.authorized(&d, name, actor, second, now), "I5 {name}: money moved without an authority named at creation");
        assert!(seller_paid_at == Pubkey::default() || seller_paid_at == self.refunds[seller_i], "I5 {name}: the seller paid only at its standard account");
        assert!(buyer_paid_at == Pubkey::default() || buyer_paid_at == self.refunds[buyer_i], "I5 {name}: the buyer paid only at its standard account");
        if name == "timer_release" {
            assert!(d.timer_due().is_some_and(|due| now >= due), "I12 timer_release: paid before it was due");
            assert_eq!(d.objection, NOBODY, "I15 timer_release: paid after an objection");
        }
        let got_s = self.token_balance(&seller_paid_at) - before_s;
        let got_b = self.token_balance(&buyer_paid_at) - before_b;
        assert_eq!((got_s, got_b), (to_seller, to_buyer), "I2 {name}: each side's share");
        assert_eq!(got_s + got_b, balance, "I2 {name}: every unit the deposit account held, and no more");
        assert_eq!(balance, d.deposited, "I1 {name}: the deposit account held exactly what was sent");
        // A never-funded escrow gives both rents back and leaves nothing; every other ending gives
        // back the deposit account's and keeps the escrow account as the receipt.
        let returned = if name == "close_unfunded" { escrow_rent + vault_rent } else { vault_rent };
        for k in 0..PEOPLE {
            let want = if k == recipient_i { before_rp[k] + returned } else { before_rp[k] };
            assert_eq!(self.lamports(&self.people[k].clone()), want, "I3 {name}: rent to the payer and to nobody else (person {k})");
        }
        assert_eq!(self.lamports(&d.vault), 0, "{name}: deposit account closed");
        if name == "close_unfunded" {
            assert_eq!(self.lamports(&d.escrow), 0, "{name}: an escrow that never held the amount leaves nothing");
            self.deals[i].closed = true;
        } else {
            let account = self.trident.get_account(&d.escrow);
            assert_eq!(account.lamports(), escrow_rent, "I3/I8 {name}: the receipt keeps its own rent");
            let b = &account.data()[8..];
            let outcome = ["release_to_seller", "release_to_buyer", "split", "arbitrate", "timer_release"]
                .iter()
                .position(|n| *n == name)
                .unwrap() as u8;
            assert_eq!(b[AT_STATUS], ENDED, "I8 {name}: the receipt says Ended");
            assert_eq!(b[AT_OUTCOME], outcome, "I8 {name}: the receipt's outcome");
            assert_eq!(u64::from_le_bytes(b[AT_TO_SELLER..AT_TO_SELLER + 8].try_into().unwrap()), to_seller, "I8 {name}: to the seller");
            assert_eq!(u64::from_le_bytes(b[AT_TO_BUYER..AT_TO_BUYER + 8].try_into().unwrap()), to_buyer, "I8 {name}: to the buyer");
            // The mark's time, or this ending's if nobody marked it: when the money was there.
            let funded_at = if d.marked() { d.funded_at } else { now };
            assert_eq!(i64::from_le_bytes(b[AT_FUNDED_AT..AT_FUNDED_AT + 8].try_into().unwrap()), funded_at, "I8 {name}: when the money was there");
            assert_eq!(b[AT_CREATOR], d.creator, "I8 {name}: who created it");
            assert_eq!(&b[AT_PAYER..AT_PAYER + 32], d.payer.as_ref(), "I8 {name}: who fronted the rent");
            assert_eq!(b[AT_OBJECTION], d.objection, "I8/I15 {name}: the objection stays on the receipt");
            assert_eq!(i64::from_le_bytes(b[AT_OBJECTED_AT..AT_OBJECTED_AT + 8].try_into().unwrap()), d.objected_at, "I8/I15 {name}: and its time");
            self.deals[i].ended = true;
            self.deals[i].receipt = Some(account.data().to_vec());
        }
        self.deals[i].deposited = 0;
    }

    /// I5, apart from the model's verdict: the authority a way out needs, and nothing else.
    fn authorized(&self, d: &Deal, name: &str, actor: Pubkey, second: Pubkey, now: i64) -> bool {
        match name {
            "release_to_seller" => actor == d.buyer,
            "release_to_buyer" => actor == d.seller,
            "split" => actor == d.buyer && second == d.seller,
            "arbitrate" => d.arbiter == Some(actor),
            "timer_release" => d.timer.is_some() && d.objection == NOBODY && d.timer_due().is_some_and(|due| now >= due),
            // Nothing was dealt: whatever is there goes back to the buyer.
            "close_unfunded" => actor == d.buyer || actor == d.seller,
            _ => false,
        }
    }

    /// `recover_late` on deal `i`, naming the right accounts unless told otherwise, checked
    /// against the model and, when it lands, against I1, I3, I8 and I9.
    fn send_recover_late(&mut self, i: usize, caller_i: usize, wrong_buyer: bool, refund_choice: usize) {
        let d = self.deals[i].clone();
        let buyer_i = self.index_of(&d.buyer);
        let buyer_key = if wrong_buyer { self.people[(buyer_i + 1) % PEOPLE] } else { d.buyer };
        let refund = match refund_choice {
            0 => self.tokens[buyer_i], // the buyer's, but not its standard account
            1 => self.refunds[caller_i],
            _ => self.refunds[buyer_i],
        };
        let vault_exists = self.lamports(&d.vault) > 0;
        let valid = d.ended && vault_exists && buyer_key == d.buyer && refund == self.refunds[buyer_i];

        let late = self.vault_balance(&d);
        let vault_lamports = self.lamports(&d.vault);
        let refund_existed = self.lamports(&self.refunds[buyer_i].clone()) > 0;
        let before_ref = self.token_balance(&self.refunds[buyer_i].clone());
        let before: Vec<u64> = (0..PEOPLE).map(|k| self.lamports(&self.people[k].clone())).collect();
        let escrow_before = self.trident.get_account(&d.escrow);
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(d.escrow, false),
                AccountMeta::new(d.vault, false),
                AccountMeta::new(buyer_key, false),
                AccountMeta::new(refund, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new(self.people[caller_i], true),
                AccountMeta::new_readonly(TOKEN_PROGRAM, false),
                AccountMeta::new_readonly(ATA_PROGRAM, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            data: disc("global", "recover_late").to_vec(),
        };
        let ok = self.send(&[ix], "recover_late");
        assert_eq!(ok, valid, "I4/I7/I9 recover_late: model {valid}, program {ok} (deal {d:?})");
        if !ok {
            return;
        }
        assert_eq!(late, d.deposited, "I1 recover_late: the deposit account held exactly what was sent after the end");
        let got = self.token_balance(&self.refunds[buyer_i].clone()) - before_ref;
        assert_eq!(got, late, "I9 recover_late: every late unit to the buyer's standard account");
        assert_eq!(self.lamports(&d.vault), 0, "recover_late: the deposit account closed again");
        let made = if refund_existed { 0 } else { self.lamports(&self.refunds[buyer_i].clone()) };
        for k in 0..PEOPLE {
            let mut want = before[k];
            if k == buyer_i {
                want += vault_lamports;
            }
            if k == caller_i {
                want -= made;
            }
            assert_eq!(
                self.lamports(&self.people[k].clone()),
                want,
                "I3 recover_late: the deposit account's rent to the buyer, the standard account paid for by the caller (person {k})"
            );
        }
        let escrow_after = self.trident.get_account(&d.escrow);
        assert_eq!(escrow_after.data(), escrow_before.data(), "I8 recover_late: the receipt does not change");
        assert_eq!(escrow_after.lamports(), escrow_before.lamports(), "I8 recover_late: nor its lamports");
        self.deals[i].deposited = 0;
    }

    /// I11 and I9 at the end of every run. Every live escrow ends by the parties' own signatures:
    /// a funded one by the buyer's release to the seller (the seller's standard account made
    /// first if it has none), a never-funded one by its creator's close (the buyer's standard
    /// account made first when there is something to return). Then
    /// every late payment at an ended escrow goes back to its buyer. After that, no deposit
    /// account holds anything.
    fn nothing_is_stuck(&mut self) {
        for i in 0..self.deals.len() {
            let d = self.deals[i].clone();
            if !d.live() {
                continue;
            }
            let balance = self.vault_balance(&d);
            let buyer_i = self.index_of(&d.buyer);
            let seller_i = self.index_of(&d.seller);
            let recipient_i = self.index_of(&d.rent_recipient);
            let (name, accounts, signer) = if balance >= d.amount {
                let ix = self.make_ata_ix(SPONSOR, self.refunds[seller_i], d.seller);
                assert!(self.send(&[ix], "make_refund"), "I11: anyone can make the seller's standard account");
                ("release_to_seller", vec![self.refunds[seller_i]], d.buyer)
            } else {
                if balance > 0 {
                    let ix = self.make_ata_ix(SPONSOR, self.refunds[buyer_i], d.buyer);
                    assert!(self.send(&[ix], "make_refund"), "I11: anyone can make the buyer's standard account");
                }
                ("close_unfunded", vec![self.refunds[buyer_i]], d.creator_key())
            };
            let mut metas = vec![
                AccountMeta::new(d.escrow, false),
                AccountMeta::new(d.vault, false),
                AccountMeta::new_readonly(self.mint, false),
            ];
            metas.extend(accounts.iter().map(|a| AccountMeta::new(*a, false)));
            metas.push(AccountMeta::new(self.people[recipient_i], false));
            metas.push(AccountMeta::new_readonly(TOKEN_PROGRAM, false));
            metas.push(AccountMeta::new_readonly(signer, true));
            let ix = Instruction { program_id: PROGRAM_ID, accounts: metas, data: disc("global", name).to_vec() };
            assert!(self.send(&[ix], name), "I11 {name}: a live escrow must always end by its parties ({d:?}, balance {balance})");
            assert_eq!(balance, d.deposited, "I1 {name}");
            if name == "close_unfunded" {
                self.deals[i].closed = true;
            } else {
                self.deals[i].ended = true;
                self.deals[i].receipt = Some(self.trident.get_account(&d.escrow).data().to_vec());
            }
            self.deals[i].deposited = 0;
            self.trident.record_accumulator("I11 live escrows ended at the end of a run", 1.0);
        }
        for i in 0..self.deals.len() {
            let d = self.deals[i].clone();
            if d.ended && self.lamports(&d.vault) > 0 && self.latest_at(&d.escrow) == i {
                self.send_recover_late(i, SPONSOR, false, 2);
                assert_eq!(self.lamports(&d.vault), 0, "I9: late money at an ended escrow always goes back");
            }
        }
        // The newest deal at each address. One that was closed is skipped: money sent to a closed
        // address waits for the same terms to be opened again (adversarial.rs pins that).
        let mut seen = std::collections::HashSet::new();
        for i in (0..self.deals.len()).rev() {
            let d = self.deals[i].clone();
            if !seen.insert(d.escrow) || d.closed {
                continue;
            }
            assert_eq!(self.vault_balance(&d), 0, "I11: nothing left in deposit account {}", d.vault);
        }
    }

    // -- invariants -----------------------------------------------------------------------------

    fn check_everything(&mut self) {
        let mut in_vaults: u128 = 0;
        let mut seen = std::collections::HashSet::new();
        for d in self.deals.clone() {
            if !seen.insert(d.vault) {
                continue; // one deposit account per address; the newest deal holds its count
            }
            let latest = &self.deals[self.latest_at(&d.escrow)];
            let bal = token_amount_of(&self.trident.get_account(&d.vault));
            assert_eq!(bal, latest.deposited, "I1: deposit account {} holds what was sent", d.vault);
            in_vaults += u128::from(bal);
        }
        let held: u128 = (0..PEOPLE)
            .map(|k| u128::from(self.token_balance(&self.tokens[k].clone())) + u128::from(self.token_balance(&self.refunds[k].clone())))
            .sum();
        assert_eq!(held + in_vaults, self.total_tokens, "I6: no token created or destroyed");
        for d in self.deals.clone() {
            if d.closed {
                continue;
            }
            let now = self.trident.get_account(&d.escrow);
            assert!(now.lamports() >= self.escrow_min, "I10: escrow {} holds {} < its minimum {}", d.escrow, now.lamports(), self.escrow_min);
            if let Some(data) = &d.receipt {
                assert_eq!(now.data(), &data[..], "I8: receipt {} keeps its bytes", d.escrow);
            }
        }
        self.trident.record_accumulator("invariant checks", 1.0);
    }

    // -- helpers ----------------------------------------------------------------------------------

    fn send(&mut self, ixs: &[Instruction], name: &'static str) -> bool {
        let r = self.trident.process_transaction(ixs, Some(name));
        let ok = r.is_success();
        let c = self.counts.entry(name).or_default();
        if ok {
            c.accepted += 1;
        } else {
            c.refused += 1;
        }
        ok
    }

    fn mark_ix(&self, d: &Deal) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![AccountMeta::new(d.escrow, false), AccountMeta::new_readonly(d.vault, false)],
            data: disc("global", "mark_funded").to_vec(),
        }
    }

    /// The associated token program's idempotent create: `payer_i` pays for `owner`'s standard
    /// account `account` for the mint.
    fn make_ata_ix(&self, payer_i: usize, account: Pubkey, owner: Pubkey) -> Instruction {
        Instruction {
            program_id: ATA_PROGRAM,
            accounts: vec![
                AccountMeta::new(self.people[payer_i], true),
                AccountMeta::new(account, false),
                AccountMeta::new_readonly(owner, false),
                AccountMeta::new_readonly(self.mint, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
                AccountMeta::new_readonly(TOKEN_PROGRAM, false),
            ],
            data: vec![1],
        }
    }

    /// Someone's token account: usually `k`'s everyday one or standard one, now and then anyone's.
    fn pick_account(&mut self, k: usize) -> Pubkey {
        match self.pick(20) {
            0 => {
                let j = self.pick(PEOPLE);
                if self.coin() { self.refunds[j] } else { self.tokens[j] }
            }
            1..=6 => self.tokens[k],
            _ => self.refunds[k],
        }
    }

    fn index_of(&self, key: &Pubkey) -> usize {
        self.people.iter().position(|p| p == key).unwrap()
    }
    fn person(&mut self) -> Pubkey {
        let k = self.pick(PEOPLE);
        self.people[k]
    }
    fn side(&mut self) -> u8 {
        if self.coin() { SELLER } else { BUYER }
    }
    fn pick(&mut self, n: usize) -> usize {
        self.trident.random_from_range(0..n)
    }
    fn coin(&mut self) -> bool {
        self.trident.random_bool()
    }
    fn now(&self) -> i64 {
        self.trident.get_current_timestamp()
    }
    fn lamports(&mut self, k: &Pubkey) -> u64 {
        self.trident.get_account(k).lamports()
    }
    fn token_balance(&mut self, k: &Pubkey) -> u64 {
        if *k == Pubkey::default() {
            return 0;
        }
        token_amount_of(&self.trident.get_account(k))
    }
    fn vault_balance(&mut self, d: &Deal) -> u64 {
        token_amount_of(&self.trident.get_account(&d.vault))
    }
    fn amount(&mut self) -> u64 {
        match self.pick(18) {
            0 => 0,
            1 => 1,
            2 => self.trident.random_from_range(2..10),
            3 => self.trident.random_from_range(1..1_000_000_000_000),
            4 => START_TOKENS / 1000,
            _ => self.trident.random_from_range(1..10_000_000),
        }
    }
    /// Who sends an instruction: usually the key the rules want, sometimes any party, sometimes anyone.
    fn actor_for(&mut self, d: &Deal, name: &str) -> Pubkey {
        let right = match name {
            "release_to_buyer" => d.seller,
            "arbitrate" => d.arbiter.unwrap_or(d.buyer),
            "close_unfunded" => match self.pick(4) {
                0 => d.payer, // whoever fronted the rent: refused unless a party
                1 => d.seller,
                _ => d.buyer,
            },
            _ => d.buyer,
        };
        match self.pick(10) {
            0 => d.buyer,
            1 => d.seller,
            2 | 3 => self.person(),
            _ => right,
        }
    }
    fn other_than(&mut self, i: usize) -> Pubkey {
        let k = (i + 1 + self.pick(PEOPLE - 1)) % PEOPLE;
        self.people[k]
    }
    fn any_deal(&mut self) -> Option<Deal> {
        if self.deals.is_empty() {
            return None;
        }
        let i = self.pick(self.deals.len());
        Some(self.deals[i].clone())
    }
    /// A deal to act on: usually a live one, sometimes the newest at any address, ended or not.
    fn latest_deal(&mut self) -> Option<usize> {
        if self.deals.is_empty() {
            return None;
        }
        let live: Vec<usize> = (0..self.deals.len()).filter(|&k| self.deals[k].live()).collect();
        if !live.is_empty() && self.pick(5) != 0 {
            let k = self.pick(live.len());
            return Some(live[k]);
        }
        let i = self.pick(self.deals.len());
        Some(self.latest_at(&self.deals[i].escrow.clone()))
    }
    /// An ended deal, three times in four when there is one: the deals `recover_late` is for.
    fn ended_deal(&mut self) -> Option<usize> {
        let ended: Vec<usize> = (0..self.deals.len()).filter(|&k| self.deals[k].ended).collect();
        if ended.is_empty() || self.pick(4) == 0 {
            return None;
        }
        let k = self.pick(ended.len());
        Some(ended[k])
    }
    fn latest_at(&self, escrow: &Pubkey) -> usize {
        self.deals.iter().rposition(|d| d.escrow == *escrow).unwrap()
    }
}

fn token_amount_of(a: &AccountSharedData) -> u64 {
    if a.lamports() == 0 || a.data().len() < 72 {
        return 0;
    }
    u64::from_le_bytes(a.data()[64..72].try_into().unwrap())
}

fn main() {
    let iterations = std::env::var("FOREST_FUZZ_ITERATIONS").ok().and_then(|v| v.parse().ok()).unwrap_or(1_000);
    let flows = std::env::var("FOREST_FUZZ_FLOWS").ok().and_then(|v| v.parse().ok()).unwrap_or(80);
    FuzzTest::fuzz(iterations, flows);
}
