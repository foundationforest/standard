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
//! Invariants, for the escrow `escrows/README.md` describes (money in, then a schedule: generous
//! moves always, selfish moves by the schedule, a stop that freezes the default, a default at the
//! end; an arbiter if the creator named one):
//!   I1 every deposit account holds exactly what was sent to it;
//!   I2 every way out pays out the whole balance, no more and no less, and a split gives the
//!      payer exactly its basis points of the balance, rounded down;
//!   I3 rent goes back to the sponsor who fronted it, to the lamport, and to nobody else: the
//!      deposit account's at every ending, the escrow account's too when it closes without a
//!      receipt, and what a sweep takes above the escrow account's minimum; a deposit account made
//!      again after the end goes back to the payer with the late money;
//!   I4 an ended escrow accepts nothing but `recover_late` and `sweep_rent`, even after a later
//!      payment re-creates its deposit account, and its address never opens again;
//!   I5 money leaves a funded escrow only with an authority named at creation: the payer's pay,
//!      the recipient's refund, the payer's take-back inside a window, both signing a split, the
//!      arbiter named at creation, or the default from the end time; checked on every accepted
//!      way out by a separate `authorized` test, apart from the model's own verdict; and it lands
//!      only at the receiving party's standard token account for the mint;
//!   I6 no token is created or destroyed: every balance, every standard account and every
//!      deposit account add up to a constant;
//!   I7 the program accepts exactly what the model allows, and refuses everything else;
//!   I8 a receipt, once written, never changes its bytes and never closes, and says when the
//!      money was there: the mark's time, or the ending's if nobody marked it;
//!   I9 late money always reaches the payer: `recover_late` runs whenever an ended escrow's
//!      deposit account exists, and pays exactly what it held to the payer's standard account;
//!   I10 a sweep never breaches the minimum: every escrow account always holds at least its
//!      rent-exempt minimum, and a sweep leaves exactly that and pays the rest to the sponsor;
//!   I11 nothing is stuck: at the end of every run, every live escrow is ended by the parties'
//!      own signatures (a funded one by the payer's pay, stopped or not; a never-funded one by its
//!      creator's close), and every unit comes out;
//!   I12 the schedule pays only by its windows: a take-back pays the share of the window in
//!      force at that second, never 0, never from the end time on; the default pays only from the
//!      end time;
//!   I13 an escrow's address is its terms': `create` lands only at `["escrow", SHA-256 of every
//!      term]`, the schedule included, with the payer or the recipient signing, so a payment to an
//!      address counts only toward a deal with exactly its terms;
//!   I14 no arbiter is a party, and no schedule but one to four windows, rising, each share at most
//!      10,000: `create` refuses the rest;
//!   I15 a stop moves nothing and changes only the escrow's stop and its time; it lands once per
//!      escrow, from the payer or the recipient only, and only before the end time;
//!   I16 a stop turns the default off: after it `end` never lands, and giving, agreeing and the
//!      arbiter land as they would without it;
//!   I17 money counts toward the default only if marked before the end time: a mark never lands
//!      from the end time on, the default never pays an escrow nobody marked, and from the end
//!      time on an escrow nobody marked or stopped closes back to the payer.
//!
//! Run: `cargo run --release --bin fuzz_escrow` from this directory (after `cargo build-sbf --arch
//! v0` in `escrows/solana/program`: Trident's runtime runs no v3 program). The mint is a classic SPL
//! Token mint; Token-2022 is the LiteSVM tests' alone. `FOREST_FUZZ_ITERATIONS` and
//! `FOREST_FUZZ_FLOWS` set the size; `FUZZING_METRICS=1 FUZZING_JSON=metrics.json` writes Trident's
//! per-instruction outcome counts.

use sha2::{Digest, Sha256};
use trident_fuzz::fuzzing::*;

const PROGRAM_ID: Pubkey = pubkey!("FoRE3EscrowV3scheduLeWindowsPayRefund3333333");
const TOKEN_PROGRAM: Pubkey = pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA_PROGRAM: Pubkey = pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const SYSTEM_PROGRAM: Pubkey = pubkey!("11111111111111111111111111111111");
const NATIVE_MINT: Pubkey = pubkey!("So11111111111111111111111111111111111111112");
const BPS: u16 = 10_000;
const MAX_WINDOWS: usize = 4;
const DAY: i64 = 86_400;
const T0: i64 = 1_800_000_000;
const START_TOKENS: u64 = 100_000_000_000_000_000;
/// People: two payers, two recipients, an arbiter, a stranger and a sponsor. Anyone can be anything.
const PEOPLE: usize = 7;
const SPONSOR: usize = 6;
/// Side bytes, as the program stores them.
const PAYER: u8 = 0;
const RECIPIENT: u8 = 1;
/// The default's byte: pay 0 (to the recipient), refund 1 (to the payer).
const PAY: u8 = 0;
const REFUND: u8 = 1;
/// The receipt's offsets after the eight-byte discriminator.
const AT_SPONSOR: usize = 169;
const AT_CREATOR: usize = 209;
const AT_FUNDED_AT: usize = 260;
const AT_STATUS: usize = 268;
const AT_OUTCOME: usize = 278;
const AT_TO_PAYER: usize = 279;
const AT_TO_RECIPIENT: usize = 287;
const AT_STOP: usize = 295;
const AT_STOPPED_AT: usize = 296;
const ENDED: u8 = 2;
/// Stop bytes, as the program stores them.
const NOBODY: u8 = 0;
/// The moves that end an escrow with a receipt, in the outcome byte's order.
const OUTCOMES: [&str; 6] = ["pay", "refund", "take_back", "agree", "decide", "end"];

fn disc(namespace: &str, name: &str) -> [u8; 8] {
    Sha256::digest(format!("{namespace}:{name}").as_bytes())[..8].try_into().unwrap()
}

fn share(amount: u64, bps: u16) -> u64 {
    ((u128::from(amount) * u128::from(bps)) / u128::from(BPS)) as u64
}

/// A schedule as `create` takes it: `(until, payer_share)` windows and the default's byte.
type Schedule = (Vec<(i64, u16)>, u8);

/// The escrow's address: `["escrow", SHA-256 of every term]`, each term at a fixed length in the
/// receipt's order (`state::terms_hash`), written here a fourth time. A schedule `create` refuses
/// with more than four windows hashes its count and first four; it never opens.
fn escrow_address(id: u64, payer: &Pubkey, recipient: &Pubkey, arbiter: Option<Pubkey>, mint: &Pubkey, amount: u64, schedule: &Option<Schedule>) -> Pubkey {
    let mut h = Sha256::new();
    h.update(id.to_le_bytes());
    h.update(payer.as_ref());
    h.update(recipient.as_ref());
    h.update(arbiter.unwrap_or_default().as_ref());
    h.update(mint.as_ref());
    h.update(amount.to_le_bytes());
    let (windows, end) = schedule.clone().unwrap_or((vec![], PAY));
    h.update([u8::try_from(windows.len()).unwrap_or(u8::MAX)]);
    for i in 0..MAX_WINDOWS {
        let (until, payer_share) = windows.get(i).copied().unwrap_or((0, 0));
        h.update(until.to_le_bytes());
        h.update(payer_share.to_le_bytes());
    }
    h.update([end]);
    let hash: [u8; 32] = h.finalize().into();
    Pubkey::find_program_address(&[b"escrow", &hash], &PROGRAM_ID).0
}

fn schedule_valid(s: &Schedule) -> bool {
    let w = &s.0;
    !w.is_empty() && w.len() <= MAX_WINDOWS && w.iter().all(|(_, b)| *b <= BPS) && w.windows(2).all(|p| p[0].0 < p[1].0)
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
    payer: Pubkey,
    recipient: Pubkey,
    creator: u8,
    arbiter: Option<Pubkey>,
    /// The windows and the default; `None` with no schedule.
    schedule: Option<Schedule>,
    /// Who fronted the rent at creation: every rent goes back to it.
    sponsor: Pubkey,
    amount: u64,
    /// Whether `mark_funded` ran, and when. An ending nobody marked writes its own time into the
    /// receipt; the model checks the receipt for it.
    marked: bool,
    funded_at: i64,
    /// Which side stopped it (`NOBODY`, then 1 the payer, 2 the recipient), and when.
    stop: u8,
    stopped_at: i64,
    deposited: u64,
    /// Paid out: the escrow account stays as the receipt.
    ended: bool,
    /// Closed without a receipt: both accounts gone, the address free again.
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
        if self.creator == PAYER { self.payer } else { self.recipient }
    }
    fn end_time(&self) -> Option<i64> {
        self.schedule.as_ref().and_then(|(w, _)| w.last().map(|(until, _)| *until))
    }
    /// The window in force at `now`: the first whose `until` is still ahead.
    fn window_at(&self, now: i64) -> Option<(i64, u16)> {
        self.schedule.as_ref().and_then(|(w, _)| w.iter().copied().find(|(until, _)| now < *until))
    }
    fn before_the_end(&self, now: i64) -> bool {
        self.end_time().map_or(true, |end| now < end)
    }
    fn past_the_end(&self, now: i64) -> bool {
        self.end_time().is_some_and(|end| now >= end)
    }
    fn stopped(&self) -> bool {
        self.stop != NOBODY
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
    /// get it from `make_account`, or from `recover_late` when a payer is paid there first. Every
    /// payout to either party lands here and nowhere else.
    standard: Vec<Pubkey>,
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
            standard: vec![],
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
        self.standard.clear();
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
            let standard = ata(&p, &mint);
            if self.pick(4) != 0 {
                self.trident.set_account_custom(&standard, &token_account(&mint, &p, 0));
            }
            self.standard.push(standard);
        }
        self.total_tokens = u128::from(START_TOKENS) * PEOPLE as u128;
    }

    // -- flows --------------------------------------------------------------------------------

    #[flow]
    fn create(&mut self) {
        let payer_i = self.pick(PEOPLE);
        let payer = self.people[payer_i];
        let native = self.pick(40) == 0;
        let mint = if native { NATIVE_MINT } else { self.mint };
        // Mostly well-formed terms, so the moves get exercised; each malformed choice ~3%.
        let recipient = match self.pick(33) {
            0 => Pubkey::default(),
            1 => payer,
            _ => self.other_than(payer_i),
        };
        let arbiter = match self.pick(33) {
            0 => Some(Pubkey::default()),
            1..=3 => Some(payer),
            4..=6 => Some(recipient),
            k if k < 20 => None,
            _ => Some(self.person()),
        };
        let schedule = self.schedule();
        let amount = self.amount();
        let id: u64 = self.trident.random_from_range(0..6);
        // Who fronts the rent: the payer, a sponsor (usually a fee payer), or anyone.
        let sponsor_i = match self.pick(3) {
            0 => payer_i,
            1 => SPONSOR,
            _ => self.pick(PEOPLE),
        };
        let sponsor = self.people[sponsor_i];
        // Who opens it: the payer, proposing; the recipient, invoicing; now and then someone else.
        let creator = match self.pick(20) {
            0 => self.person(),
            k if k < 8 => recipient,
            _ => payer,
        };

        // The address is the terms'; now and then the sender aims at the address of other terms,
        // the same but for the id, the payer or the schedule (I13).
        let own = escrow_address(id, &payer, &recipient, arbiter, &mint, amount, &schedule);
        let escrow = match self.pick(40) {
            0 => escrow_address(id ^ 1, &payer, &recipient, arbiter, &mint, amount, &schedule),
            1 => escrow_address(id, &self.person(), &recipient, arbiter, &mint, amount, &schedule),
            2 => escrow_address(id, &payer, &recipient, arbiter, &mint, amount, &None),
            _ => own,
        };
        let vault = ata(&escrow, &mint);
        // An address is taken while a deal there is live, and for good once one has ended.
        let taken = self.deals.iter().any(|d| d.escrow == escrow && !d.closed);
        let valid = escrow == own
            && recipient != payer
            && recipient != Pubkey::default()
            && (creator == payer || creator == recipient)
            && arbiter != Some(Pubkey::default())
            && arbiter != Some(payer)
            && arbiter != Some(recipient)
            && !native
            && amount > 0
            && schedule.as_ref().map_or(true, schedule_valid)
            && !taken;

        let mut data = disc("global", "create").to_vec();
        data.extend_from_slice(&id.to_le_bytes());
        data.extend_from_slice(payer.as_ref());
        data.extend_from_slice(recipient.as_ref());
        data.extend_from_slice(&amount.to_le_bytes());
        match arbiter {
            Some(k) => {
                data.push(1);
                data.extend_from_slice(k.as_ref());
            }
            None => data.push(0),
        }
        match &schedule {
            Some((windows, end)) => {
                data.push(1);
                data.extend_from_slice(&(windows.len() as u32).to_le_bytes());
                for (until, payer_share) in windows {
                    data.extend_from_slice(&until.to_le_bytes());
                    data.extend_from_slice(&payer_share.to_le_bytes());
                }
                data.push(*end);
            }
            None => data.push(0),
        }
        // What the client sends: the deposit address made first, by the sponsor, as its own
        // instruction (so a fee payer that checks every destination finds it made), then `create`.
        // Now and then `create` alone, which makes it itself.
        let mut ixs = vec![];
        if !native && self.pick(3) != 0 {
            ixs.push(self.make_ata_ix(sponsor_i, vault, escrow));
        }
        ixs.push(Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new(escrow, false),
                AccountMeta::new(vault, false),
                AccountMeta::new_readonly(creator, true),
                AccountMeta::new(sponsor, true),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(TOKEN_PROGRAM, false),
                AccountMeta::new_readonly(ATA_PROGRAM, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
            ],
            data,
        });
        let vault_before = self.trident.get_account(&vault);
        let prefunded = token_amount_of(&vault_before);
        let sponsor_before = self.lamports(&sponsor);
        let ok = self.send(&ixs, "create");
        assert_eq!(ok, valid, "I7/I14 create: model says {valid}, program said {ok} (schedule {schedule:?})");
        if !ok {
            return;
        }
        // Rent: the sponsor paid for the escrow account, and for the deposit account if create made it.
        let paid = sponsor_before - self.lamports(&sponsor);
        let made_vault = if vault_before.lamports() == 0 { self.lamports(&vault) } else { 0 };
        assert_eq!(paid, self.lamports(&escrow) + made_vault, "I3 create: the sponsor paid both rents and nothing else");
        if self.escrow_min == 0 {
            self.escrow_min = self.lamports(&escrow);
        }
        assert_eq!(self.lamports(&escrow), self.escrow_min, "I10 create: an escrow account starts at its minimum");
        let bytes = self.trident.get_account(&escrow).data().to_vec();
        let creator_byte = if creator == payer { PAYER } else { RECIPIENT };
        assert_eq!(bytes[8 + AT_CREATOR], creator_byte, "create: the receipt names its creator");
        assert_eq!(&bytes[8 + AT_SPONSOR..8 + AT_SPONSOR + 32], sponsor.as_ref(), "I3 create: the sponsor is whoever fronted the rent");
        assert_eq!(bytes[8 + AT_STOP], NOBODY, "I15 create: nobody has stopped it");
        self.deals.push(Deal {
            escrow,
            vault,
            payer,
            recipient,
            creator: creator_byte,
            arbiter,
            schedule,
            sponsor,
            amount,
            marked: false,
            funded_at: 0,
            stop: NOBODY,
            stopped_at: 0,
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
        ixs.push(self.transfer_ix(from, d.vault, amount));
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
    fn make_account(&mut self) {
        let owner_i = self.pick(PEOPLE);
        let funder_i = self.pick(PEOPLE);
        let ix = self.make_ata_ix(funder_i, self.standard[owner_i], self.people[owner_i]);
        let ok = self.send(&[ix], "make_account");
        assert!(ok, "making a standard token account, or finding it there, must land");
    }

    /// What a payer's app does: send exactly what is missing and mark it, in one transaction. From
    /// the end time on the mark is refused, so the whole transaction fails and nothing moves (I17).
    #[flow]
    fn fund_and_mark(&mut self) {
        let Some(i) = self.latest_deal() else { return };
        let d = self.deals[i].clone();
        if !d.live() {
            return;
        }
        let have = self.vault_balance(&d);
        let missing = d.amount.saturating_sub(have);
        let payer_i = self.index_of(&d.payer);
        let mut ixs = vec![];
        if missing > 0 {
            ixs.push(self.transfer_ix(payer_i, d.vault, missing));
        }
        let marks = !d.marked;
        if marks {
            ixs.push(self.mark_ix(&d));
        }
        if ixs.is_empty() {
            return;
        }
        let now = self.now();
        let valid = !marks || d.before_the_end(now);
        let balance = self.vault_balance(&d);
        let ok = self.send(&ixs, "fund_and_mark");
        assert_eq!(ok, valid, "I7/I17 fund_and_mark: model {valid}, program {ok} (deal {d:?}, now {now})");
        if !ok {
            assert_eq!(self.vault_balance(&d), balance, "I17 fund_and_mark: a refused mark takes the payment with it");
            return;
        }
        self.deals[i].deposited += missing;
        if marks {
            self.deals[i].marked = true;
            self.deals[i].funded_at = now;
        }
    }

    #[flow]
    fn mark_funded(&mut self) {
        let Some(i) = self.latest_deal() else { return };
        let d = self.deals[i].clone();
        let balance = self.vault_balance(&d);
        let vault_exists = self.lamports(&d.vault) > 0;
        // Trident's runtime moves its clock on by the wall-clock seconds that pass after each
        // transaction, so the time the program saw is the one read before sending, not after.
        let now = self.now();
        let valid = d.live() && vault_exists && !d.marked && d.before_the_end(now) && balance >= d.amount;
        let ix = self.mark_ix(&d);
        let ok = self.send(&[ix], "mark_funded");
        assert_eq!(ok, valid, "I4/I7/I17 mark_funded: model {valid}, program {ok} (deal {d:?}, now {now})");
        if ok {
            assert!(d.before_the_end(now), "I17 mark_funded: marked from the end time on");
            self.deals[i].marked = true;
            self.deals[i].funded_at = now;
        }
    }

    /// A party stops the escrow: usually the payer or the recipient, now and then anyone. Moves nothing.
    #[flow]
    fn stop(&mut self) {
        let Some(i) = self.latest_deal() else { return };
        let d = self.deals[i].clone();
        let actor = match self.pick(10) {
            0..=3 => d.payer,
            4..=7 => d.recipient,
            _ => self.person(),
        };
        let side = if actor == d.payer {
            1
        } else if actor == d.recipient {
            2
        } else {
            NOBODY
        };
        let now = self.now();
        let valid = d.live() && side != NOBODY && !d.stopped() && d.before_the_end(now);
        let bytes = self.trident.get_account(&d.escrow).data().to_vec();
        let lamports = self.lamports(&d.escrow);
        let balance = self.vault_balance(&d);
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![AccountMeta::new(d.escrow, false), AccountMeta::new_readonly(actor, true)],
            data: disc("global", "stop").to_vec(),
        };
        let ok = self.send(&[ix], "stop");
        assert_eq!(ok, valid, "I7/I15 stop: model {valid}, program {ok} (deal {d:?}, now {now})");
        if !ok {
            return;
        }
        let after = self.trident.get_account(&d.escrow);
        let b = after.data();
        assert_eq!(b[8 + AT_STOP], side, "I15 stop: the receipt names the side");
        assert_eq!(i64::from_le_bytes(b[8 + AT_STOPPED_AT..8 + AT_STOPPED_AT + 8].try_into().unwrap()), now, "I15 stop: and the time");
        assert_eq!(&b[..8 + AT_STOP], &bytes[..8 + AT_STOP], "I15 stop: nothing else in the account changes");
        assert_eq!(after.lamports(), lamports, "I15 stop: no lamports move");
        assert_eq!(self.vault_balance(&d), balance, "I15 stop: no token moves");
        self.deals[i].stop = side;
        self.deals[i].stopped_at = now;
    }

    #[flow]
    fn pay(&mut self) {
        self.way_out("pay");
    }
    #[flow]
    fn refund(&mut self) {
        self.way_out("refund");
    }
    #[flow]
    fn take_back(&mut self) {
        self.way_out("take_back");
    }
    #[flow]
    fn agree(&mut self) {
        self.way_out("agree");
    }
    #[flow]
    fn decide(&mut self) {
        self.way_out("decide");
    }
    #[flow]
    fn end(&mut self) {
        self.way_out("end");
    }
    #[flow]
    fn close_unfunded(&mut self) {
        self.way_out("close_unfunded");
    }

    /// SOL sent to an escrow's address, live or ended. It never counts as funding; a sweep takes it
    /// out again, to the sponsor. Closed addresses are left alone: a tip there would pre-fund an
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

    /// Rent above the minimum back to the sponsor recorded at creation; anyone sends it, on any
    /// escrow. Now and then it names the creator, or anyone, instead.
    #[flow]
    fn sweep_rent(&mut self) {
        let Some(d) = self.any_deal() else { return };
        let i = self.latest_at(&d.escrow);
        let d = self.deals[i].clone();
        let sponsor_i = self.index_of(&d.sponsor);
        let to_i = match self.pick(10) {
            0 => self.pick(PEOPLE),
            1 => self.index_of(&d.creator_key()),
            _ => sponsor_i,
        };
        let lamports = self.lamports(&d.escrow);
        let excess = lamports.saturating_sub(self.escrow_min);
        let valid = !d.closed && lamports > 0 && to_i == sponsor_i && excess > 0;
        let before: Vec<u64> = (0..PEOPLE).map(|k| self.lamports(&self.people[k].clone())).collect();
        let bytes = self.trident.get_account(&d.escrow).data().to_vec();
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![AccountMeta::new(d.escrow, false), AccountMeta::new(self.people[to_i], false)],
            data: disc("global", "sweep_rent").to_vec(),
        };
        let ok = self.send(&[ix], "sweep_rent");
        assert_eq!(ok, valid, "I7/I10 sweep_rent: model {valid}, program {ok} (deal {d:?}, lamports {lamports})");
        if !ok {
            return;
        }
        assert_eq!(self.lamports(&d.escrow), self.escrow_min, "I10 sweep_rent: exactly the minimum left");
        for k in 0..PEOPLE {
            let want = if k == sponsor_i { before[k] + excess } else { before[k] };
            assert_eq!(self.lamports(&self.people[k].clone()), want, "I3/I10 sweep_rent: the excess to the sponsor and nobody else (person {k})");
        }
        assert_eq!(self.trident.get_account(&d.escrow).data(), &bytes[..], "I8/I10 sweep_rent: the bytes do not change");
    }

    /// Late money back to the payer. Anyone sends it, usually on an ended escrow, usually naming
    /// the payer's standard account.
    #[flow]
    fn recover_late(&mut self) {
        let Some(i) = self.ended_deal().or_else(|| self.latest_deal()) else { return };
        let caller_i = self.pick(PEOPLE);
        let wrong_payer = self.pick(20) == 0;
        let account_choice = self.pick(20);
        self.send_recover_late(i, caller_i, wrong_payer, account_choice);
    }

    /// Time moves: by a random stretch, or to a second either side of one of a deal's windows.
    #[flow]
    fn time_passes(&mut self) {
        let target = match (self.pick(3), self.latest_deal()) {
            (0, Some(i)) => {
                let Some((windows, _)) = self.deals[i].schedule.clone() else { return };
                let k = self.pick(windows.len());
                windows[k].0.saturating_add(self.trident.random_from_range(-1..=1))
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
    fn end_of_run(&mut self) {
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
        let second = if self.pick(4) == 0 { self.person() } else { d.recipient };
        let bps: u16 = match self.pick(5) {
            0 => BPS + self.trident.random_from_range(1..100),
            1 => 0,
            2 => BPS,
            _ => self.trident.random_from_range(0..=BPS),
        };
        let payer_i = self.index_of(&d.payer);
        let recipient_i = self.index_of(&d.recipient);
        let sponsor_i = self.index_of(&d.sponsor);
        // Each party's slot: its standard account, or now and then another account it holds, or
        // anyone's. Only the standard account is right, by address.
        let payer_account = self.pick_account(payer_i);
        let recipient_account = self.pick_account(recipient_i);
        // The default's one slot: whichever side it names, or now and then the other.
        let end = d.schedule.as_ref().map_or(PAY, |(_, end)| *end);
        let anyone = self.pick(PEOPLE);
        let to_account = match (end, self.pick(8)) {
            (_, 0) => self.pick_account(anyone),
            (REFUND, _) => payer_account,
            _ => recipient_account,
        };
        // The rent slot: the sponsor, or now and then the creator, or anyone.
        let rp_i = match self.pick(20) {
            0 => self.pick(PEOPLE),
            1 => self.index_of(&d.creator_key()),
            _ => sponsor_i,
        };

        let balance = self.vault_balance(&d);
        let vault_exists = self.lamports(&d.vault) > 0;
        let funded = balance >= d.amount;
        let payer_right = payer_account == self.standard[payer_i];
        let payer_live = self.lamports(&self.standard[payer_i].clone()) > 0;
        let recipient_right = recipient_account == self.standard[recipient_i];
        let recipient_live = self.lamports(&self.standard[recipient_i].clone()) > 0;
        let both = |to_payer: u64, to_recipient: u64| payer_right && recipient_right && (to_payer == 0 || payer_live) && (to_recipient == 0 || recipient_live);

        // (valid, to_payer, to_recipient)
        let expect: (bool, u64, u64) = if !d.live() || !vault_exists || rp_i != sponsor_i {
            (false, 0, 0)
        } else {
            match name {
                "pay" => (actor == d.payer && funded && recipient_right && recipient_live, 0, balance),
                "refund" => (actor == d.recipient && funded && payer_right && payer_live, balance, 0),
                "take_back" => {
                    let window = d.window_at(now);
                    let payer_share = window.map_or(0, |(_, s)| s);
                    let to_payer = share(balance, payer_share);
                    let to_recipient = balance - to_payer;
                    let ok = actor == d.payer && payer_share > 0 && funded && both(to_payer, to_recipient);
                    (ok, to_payer, to_recipient)
                }
                "agree" | "decide" => {
                    let signed = if name == "agree" { actor == d.payer && second == d.recipient } else { d.arbiter.is_some() && Some(actor) == d.arbiter };
                    let to_payer = share(balance, bps.min(BPS));
                    let to_recipient = balance - to_payer;
                    (signed && bps <= BPS && funded && both(to_payer, to_recipient), to_payer, to_recipient)
                }
                "end" => {
                    let to_right = match end {
                        REFUND => to_account == self.standard[payer_i] && payer_live,
                        _ => to_account == self.standard[recipient_i] && recipient_live,
                    };
                    let (p, r) = if end == REFUND { (balance, 0) } else { (0, balance) };
                    (d.schedule.is_some() && !d.stopped() && d.marked && d.past_the_end(now) && funded && to_right, p, r)
                }
                "close_unfunded" => {
                    let closer = actor == d.payer || actor == d.recipient;
                    let late = !d.marked && !d.stopped() && d.past_the_end(now);
                    (closer && (!funded || late) && payer_right && (balance == 0 || payer_live), balance, 0)
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
            "pay" => metas.push(AccountMeta::new(recipient_account, false)),
            "refund" | "close_unfunded" => metas.push(AccountMeta::new(payer_account, false)),
            "end" => metas.push(AccountMeta::new(to_account, false)),
            _ => {
                metas.push(AccountMeta::new(payer_account, false));
                metas.push(AccountMeta::new(recipient_account, false));
            }
        }
        metas.push(AccountMeta::new(self.people[rp_i], false));
        metas.push(AccountMeta::new_readonly(TOKEN_PROGRAM, false));
        let mut data = disc("global", name).to_vec();
        match name {
            "end" => {}
            "agree" => {
                metas.push(AccountMeta::new_readonly(actor, true));
                metas.push(AccountMeta::new_readonly(second, true));
                data.extend_from_slice(&bps.to_le_bytes());
            }
            "decide" => {
                metas.push(AccountMeta::new_readonly(actor, true));
                data.extend_from_slice(&bps.to_le_bytes());
            }
            _ => metas.push(AccountMeta::new_readonly(actor, true)),
        }
        // Where each side is paid, if it is: (the payer's slot, the recipient's slot).
        let (payer_paid_at, recipient_paid_at) = match name {
            "pay" => (Pubkey::default(), recipient_account),
            "refund" | "close_unfunded" => (self.standard[payer_i], Pubkey::default()),
            "end" if end == REFUND => (to_account, Pubkey::default()),
            "end" => (Pubkey::default(), to_account),
            _ => (self.standard[payer_i], recipient_account),
        };
        let before_p = self.token_balance(&payer_paid_at);
        let before_r = self.token_balance(&recipient_paid_at);
        let escrow_rent = self.lamports(&d.escrow);
        let vault_rent = self.lamports(&d.vault);
        let before_people: Vec<u64> = (0..PEOPLE).map(|k| self.lamports(&self.people[k].clone())).collect();

        let ok = self.send(&[Instruction { program_id: PROGRAM_ID, accounts: metas, data }], name);
        let (valid, to_payer, to_recipient) = expect;
        assert_eq!(ok, valid, "I4/I7 {name}: model {valid}, program {ok} (deal {d:?}, balance {balance}, now {now})");
        if !ok {
            return;
        }
        assert!(self.authorized(&d, name, actor, second, now, balance), "I5 {name}: money moved without an authority named at creation");
        assert!(payer_paid_at == Pubkey::default() || payer_paid_at == self.standard[payer_i], "I5 {name}: the payer paid only at its standard account");
        assert!(recipient_paid_at == Pubkey::default() || recipient_paid_at == self.standard[recipient_i], "I5 {name}: the recipient paid only at its standard account");
        match name {
            "take_back" => {
                let w = d.window_at(now);
                assert!(w.is_some_and(|(_, s)| s > 0), "I12 take_back: paid outside a window whose share is above 0");
                assert_eq!(to_payer, share(balance, w.unwrap().1), "I12 take_back: the share of the window in force");
            }
            "end" => {
                assert!(d.past_the_end(now), "I12 end: paid before the end time");
                assert!(!d.stopped(), "I16 end: paid after a stop");
                assert!(d.marked && d.before_the_end(d.funded_at), "I17 end: paid an escrow nobody marked before the end time");
            }
            _ => {}
        }
        let got_p = self.token_balance(&payer_paid_at) - before_p;
        let got_r = self.token_balance(&recipient_paid_at) - before_r;
        assert_eq!((got_p, got_r), (to_payer, to_recipient), "I2 {name}: each side's share");
        assert_eq!(got_p + got_r, balance, "I2 {name}: every unit the deposit account held, and no more");
        assert_eq!(balance, d.deposited, "I1 {name}: the deposit account held exactly what was sent");
        // A close gives both rents back and leaves nothing; every other ending gives back the
        // deposit account's and keeps the escrow account as the receipt.
        let returned = if name == "close_unfunded" { escrow_rent + vault_rent } else { vault_rent };
        for k in 0..PEOPLE {
            let want = if k == sponsor_i { before_people[k] + returned } else { before_people[k] };
            assert_eq!(self.lamports(&self.people[k].clone()), want, "I3 {name}: rent to the sponsor and to nobody else (person {k})");
        }
        assert_eq!(self.lamports(&d.vault), 0, "{name}: deposit account closed");
        if name == "close_unfunded" {
            assert_eq!(self.lamports(&d.escrow), 0, "{name}: a closed escrow leaves nothing");
            self.deals[i].closed = true;
        } else {
            let account = self.trident.get_account(&d.escrow);
            assert_eq!(account.lamports(), escrow_rent, "I3/I8 {name}: the receipt keeps its own rent");
            let b = &account.data()[8..];
            let outcome = OUTCOMES.iter().position(|n| *n == name).unwrap() as u8;
            assert_eq!(b[AT_STATUS], ENDED, "I8 {name}: the receipt says Ended");
            assert_eq!(b[AT_OUTCOME], outcome, "I8 {name}: the receipt's outcome");
            assert_eq!(u64::from_le_bytes(b[AT_TO_PAYER..AT_TO_PAYER + 8].try_into().unwrap()), to_payer, "I8 {name}: to the payer");
            assert_eq!(u64::from_le_bytes(b[AT_TO_RECIPIENT..AT_TO_RECIPIENT + 8].try_into().unwrap()), to_recipient, "I8 {name}: to the recipient");
            // The mark's time, or this ending's if nobody marked it: when the money was there.
            let funded_at = if d.marked { d.funded_at } else { now };
            assert_eq!(i64::from_le_bytes(b[AT_FUNDED_AT..AT_FUNDED_AT + 8].try_into().unwrap()), funded_at, "I8 {name}: when the money was there");
            assert_eq!(b[AT_CREATOR], d.creator, "I8 {name}: who created it");
            assert_eq!(&b[AT_SPONSOR..AT_SPONSOR + 32], d.sponsor.as_ref(), "I8 {name}: who fronted the rent");
            assert_eq!(b[AT_STOP], d.stop, "I8/I15 {name}: the stop stays on the receipt");
            assert_eq!(i64::from_le_bytes(b[AT_STOPPED_AT..AT_STOPPED_AT + 8].try_into().unwrap()), d.stopped_at, "I8/I15 {name}: and its time");
            self.deals[i].ended = true;
            self.deals[i].receipt = Some(account.data().to_vec());
        }
        if d.stopped() {
            self.trident.record_accumulator(&format!("I16 {name} after a stop"), 1.0);
        }
        if name == "close_unfunded" && funded {
            self.trident.record_accumulator("I17 close_unfunded of money nobody marked by the end time", 1.0);
        }
        self.deals[i].deposited = 0;
    }

    /// I5, apart from the model's verdict: the authority a way out needs, and nothing else.
    fn authorized(&self, d: &Deal, name: &str, actor: Pubkey, second: Pubkey, now: i64, balance: u64) -> bool {
        match name {
            "pay" => actor == d.payer,
            "refund" => actor == d.recipient,
            "take_back" => actor == d.payer && d.window_at(now).is_some_and(|(_, s)| s > 0),
            "agree" => actor == d.payer && second == d.recipient,
            "decide" => d.arbiter == Some(actor),
            "end" => d.schedule.is_some() && !d.stopped() && d.marked && d.past_the_end(now),
            // Not the deal's to end: everything goes back to the payer.
            "close_unfunded" => (actor == d.payer || actor == d.recipient) && (balance < d.amount || (!d.marked && !d.stopped() && d.past_the_end(now))),
            _ => false,
        }
    }

    /// `recover_late` on deal `i`, naming the right accounts unless told otherwise, checked
    /// against the model and, when it lands, against I1, I3, I8 and I9.
    fn send_recover_late(&mut self, i: usize, caller_i: usize, wrong_payer: bool, account_choice: usize) {
        let d = self.deals[i].clone();
        let payer_i = self.index_of(&d.payer);
        let payer_key = if wrong_payer { self.people[(payer_i + 1) % PEOPLE] } else { d.payer };
        let to = match account_choice {
            0 => self.tokens[payer_i], // the payer's, but not its standard account
            1 => self.standard[caller_i],
            _ => self.standard[payer_i],
        };
        let vault_exists = self.lamports(&d.vault) > 0;
        let valid = d.ended && vault_exists && payer_key == d.payer && to == self.standard[payer_i];

        let late = self.vault_balance(&d);
        let vault_lamports = self.lamports(&d.vault);
        let account_existed = self.lamports(&self.standard[payer_i].clone()) > 0;
        let before_tokens = self.token_balance(&self.standard[payer_i].clone());
        let before: Vec<u64> = (0..PEOPLE).map(|k| self.lamports(&self.people[k].clone())).collect();
        let escrow_before = self.trident.get_account(&d.escrow);
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(d.escrow, false),
                AccountMeta::new(d.vault, false),
                AccountMeta::new(payer_key, false),
                AccountMeta::new(to, false),
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
        let got = self.token_balance(&self.standard[payer_i].clone()) - before_tokens;
        assert_eq!(got, late, "I9 recover_late: every late unit to the payer's standard account");
        assert_eq!(self.lamports(&d.vault), 0, "recover_late: the deposit account closed again");
        let made = if account_existed { 0 } else { self.lamports(&self.standard[payer_i].clone()) };
        for k in 0..PEOPLE {
            let mut want = before[k];
            if k == payer_i {
                want += vault_lamports;
            }
            if k == caller_i {
                want -= made;
            }
            assert_eq!(
                self.lamports(&self.people[k].clone()),
                want,
                "I3 recover_late: the deposit account's rent to the payer, the standard account paid for by the caller (person {k})"
            );
        }
        let escrow_after = self.trident.get_account(&d.escrow);
        assert_eq!(escrow_after.data(), escrow_before.data(), "I8 recover_late: the receipt does not change");
        assert_eq!(escrow_after.lamports(), escrow_before.lamports(), "I8 recover_late: nor its lamports");
        self.deals[i].deposited = 0;
    }

    /// I11 and I9 at the end of every run. Every live escrow ends by the parties' own signatures:
    /// a funded one by the payer's pay, stopped or not (the recipient's standard account made
    /// first if it has none), a never-funded one by its creator's close (the payer's standard
    /// account made first when there is something to return). Then every late payment at an ended
    /// escrow goes back to its payer. After that, no deposit account holds anything.
    fn nothing_is_stuck(&mut self) {
        for i in 0..self.deals.len() {
            let d = self.deals[i].clone();
            if !d.live() {
                continue;
            }
            let balance = self.vault_balance(&d);
            let payer_i = self.index_of(&d.payer);
            let recipient_i = self.index_of(&d.recipient);
            let sponsor_i = self.index_of(&d.sponsor);
            let (name, accounts, signer) = if balance >= d.amount {
                let ix = self.make_ata_ix(SPONSOR, self.standard[recipient_i], d.recipient);
                assert!(self.send(&[ix], "make_account"), "I11: anyone can make the recipient's standard account");
                ("pay", vec![self.standard[recipient_i]], d.payer)
            } else {
                if balance > 0 {
                    let ix = self.make_ata_ix(SPONSOR, self.standard[payer_i], d.payer);
                    assert!(self.send(&[ix], "make_account"), "I11: anyone can make the payer's standard account");
                }
                ("close_unfunded", vec![self.standard[payer_i]], d.creator_key())
            };
            let mut metas = vec![
                AccountMeta::new(d.escrow, false),
                AccountMeta::new(d.vault, false),
                AccountMeta::new_readonly(self.mint, false),
            ];
            metas.extend(accounts.iter().map(|a| AccountMeta::new(*a, false)));
            metas.push(AccountMeta::new(self.people[sponsor_i], false));
            metas.push(AccountMeta::new_readonly(TOKEN_PROGRAM, false));
            metas.push(AccountMeta::new_readonly(signer, true));
            let ix = Instruction { program_id: PROGRAM_ID, accounts: metas, data: disc("global", name).to_vec() };
            assert!(self.send(&[ix], name), "I11/I16 {name}: a live escrow must always end by its parties ({d:?}, balance {balance})");
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
            .map(|k| u128::from(self.token_balance(&self.tokens[k].clone())) + u128::from(self.token_balance(&self.standard[k].clone())))
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

    /// A schedule for `create`: none four times in ten; usually one to four windows from a little
    /// before now to a few days ahead, rising, each share any of 0 to 10,000; now and then one
    /// `create` must refuse (I14).
    fn schedule(&mut self) -> Option<Schedule> {
        if self.pick(10) < 4 {
            return None;
        }
        let end = if self.coin() { PAY } else { REFUND };
        let count = 1 + self.pick(MAX_WINDOWS);
        let mut until = self.now() + self.trident.random_from_range(-DAY..2 * DAY);
        let mut windows = vec![];
        for _ in 0..count {
            let payer_share = match self.pick(5) {
                0 => 0,
                1 => BPS,
                _ => self.trident.random_from_range(0..=BPS),
            };
            windows.push((until, payer_share));
            until += self.trident.random_from_range(1..2 * DAY);
        }
        match self.pick(30) {
            0 => windows.clear(),
            1 => {
                let last = windows.last().unwrap().0;
                while windows.len() <= MAX_WINDOWS {
                    windows.push((last + windows.len() as i64, 0));
                }
            }
            2 => windows[0].1 = BPS + self.trident.random_from_range(1..100),
            3 if windows.len() > 1 => windows[1].0 = windows[0].0,
            4 if windows.len() > 1 => windows.swap(0, 1),
            _ => {}
        }
        Some((windows, end))
    }

    fn mark_ix(&self, d: &Deal) -> Instruction {
        Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![AccountMeta::new(d.escrow, false), AccountMeta::new_readonly(d.vault, false)],
            data: disc("global", "mark_funded").to_vec(),
        }
    }

    /// A plain SPL Token transfer of `amount` from person `from`'s everyday account.
    fn transfer_ix(&self, from: usize, to: Pubkey, amount: u64) -> Instruction {
        let mut data = vec![3u8];
        data.extend_from_slice(&amount.to_le_bytes());
        Instruction {
            program_id: TOKEN_PROGRAM,
            accounts: vec![
                AccountMeta::new(self.tokens[from], false),
                AccountMeta::new(to, false),
                AccountMeta::new_readonly(self.people[from], true),
            ],
            data,
        }
    }

    /// The associated token program's idempotent create: `funder_i` pays for `owner`'s standard
    /// account `account` for the mint.
    fn make_ata_ix(&self, funder_i: usize, account: Pubkey, owner: Pubkey) -> Instruction {
        Instruction {
            program_id: ATA_PROGRAM,
            accounts: vec![
                AccountMeta::new(self.people[funder_i], true),
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
                if self.coin() { self.standard[j] } else { self.tokens[j] }
            }
            1..=6 => self.tokens[k],
            _ => self.standard[k],
        }
    }

    fn index_of(&self, key: &Pubkey) -> usize {
        self.people.iter().position(|p| p == key).unwrap()
    }
    fn person(&mut self) -> Pubkey {
        let k = self.pick(PEOPLE);
        self.people[k]
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
            "refund" => d.recipient,
            "decide" => d.arbiter.unwrap_or(d.payer),
            "close_unfunded" => match self.pick(4) {
                0 => d.sponsor, // whoever fronted the rent: refused unless a party
                1 => d.recipient,
                _ => d.payer,
            },
            _ => d.payer,
        };
        match self.pick(10) {
            0 => d.payer,
            1 => d.recipient,
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
