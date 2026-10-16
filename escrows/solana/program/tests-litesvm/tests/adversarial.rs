//! The escrow, attacked.
//!
//! The attacks on the escrow `README.md` describes: those from the first adversarial review that
//! still apply, and the ones its options and its whole-balance rule open. A test named
//! for what should be refused asserts that it is refused. A test named `finding_…` is something
//! the program accepts by design: it asserts the acceptance, so the suite pins the behaviour the
//! README and the security checklist describe, and a later change shows up here as a failure.
//!
//! Run with `cargo test --test adversarial -- --nocapture` to see what each attack did.

use forest_escrow_tests::*;
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

fn token_account_owned_by(program: Address, mint: &Address, owner: &Address, amount: u64) -> Account {
    let mut a = spl_token_account(mint, owner, amount);
    a.owner = program;
    a
}

/// A wrapped-SOL token account holding nothing: `is_native` is `Some(rent reserve)` at 109..121.
fn wsol_account(owner: &Address) -> Account {
    let mut a = spl_token_account(&NATIVE_MINT, owner, 0);
    a.data[109..113].copy_from_slice(&1u32.to_le_bytes());
    a.data[113..121].copy_from_slice(&2_039_280u64.to_le_bytes());
    a
}

fn sync_native_ix(account: Address) -> Instruction {
    Instruction { program_id: TOKEN_PROGRAM, accounts: vec![AccountMeta::new(account, false)], data: vec![17] }
}

fn spl_close_ix(account: Address, destination: Address, owner: Address) -> Instruction {
    Instruction {
        program_id: TOKEN_PROGRAM,
        accounts: vec![
            AccountMeta::new(account, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(owner, true),
        ],
        data: vec![9],
    }
}

/// SPL Token `SetAuthority`, `AccountOwner`: hand a token account to another key.
fn hand_over_ix(account: Address, owner: Address, new_owner: Address) -> Instruction {
    let mut data = vec![6u8, 2, 1];
    data.extend_from_slice(new_owner.as_ref());
    Instruction {
        program_id: TOKEN_PROGRAM,
        accounts: vec![AccountMeta::new(account, false), AccountMeta::new_readonly(owner, true)],
        data,
    }
}

/// A fresh payer whose tokens sit at its standard account, where every payout to it lands.
fn new_payer(h: &mut Harness, tokens: u64) -> (Keypair, Address) {
    let payer = h.someone();
    let t = ata_address(&payer.pubkey(), &h.mint);
    h.svm.set_account(t, spl_token_account(&h.mint, &payer.pubkey(), tokens)).unwrap();
    (payer, t)
}

// ---------------------------------------------------------------------------------------------
// 1. Account substitution
// ---------------------------------------------------------------------------------------------

#[test]
fn substitution_another_escrows_deposit_account_is_refused() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let a = h.funded(&h.terms(1));
    let b = h.funded(&h.terms(2));
    // Pay out A, but hand it B's deposit account: A's rules paying out B's money.
    let s = Accounts { vault: vault_address(&b, &h.mint), ..h.accounts(&a) };
    let err = h.send(&[pay_ix(&s, payer.pubkey())], &[&payer]).expect_err("must be refused");
    assert!(err.contains("ConstraintHasOne"), "{err}");
    let err = h.send(&[mark_funded_ix(a, s.vault)], &[]).expect_err("A marked by B's money");
    assert!(err.contains("ConstraintHasOne"), "{err}");
    assert_eq!((h.vault_balance(&a), h.vault_balance(&b)), (AMOUNT, AMOUNT));
    println!("rejected as expected: escrow A cannot pay out, or be marked by, escrow B's deposit account");
}

#[test]
fn substitution_a_look_alike_deposit_account_is_refused() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    // A token account for the right mint, held by the escrow's own address, but not the one the
    // escrow recorded: anyone can make one of these.
    let look_alike = Address::new_unique();
    h.svm.set_account(look_alike, spl_token_account(&h.mint, &escrow, 5 * AMOUNT)).unwrap();
    let s = Accounts { vault: look_alike, ..h.accounts(&escrow) };
    let err = h.send(&[pay_ix(&s, payer.pubkey())], &[&payer]).expect_err("must be refused");
    assert!(err.contains("ConstraintHasOne"), "{err}");

    // Nor can one be handed to create in place of the associated token account.
    let escrow2 = h.address(&h.terms(2));
    let look_alike2 = Address::new_unique();
    h.svm.set_account(look_alike2, spl_token_account(&h.mint, &escrow2, 0)).unwrap();
    let mut ix = create_ix(&h.terms(2), &h.create_accounts());
    ix.accounts[1].pubkey = look_alike2;
    let err = h.send(&[ix], &[&payer]).expect_err("must be refused");
    assert!(err.contains("ConstraintAssociated") || err.contains("AccountNotAssociatedTokenAccount") || err.contains("2009") || err.contains("3014"), "{err}");
    assert!(!h.exists(&escrow2));
    println!("rejected as expected: a look-alike deposit account, at a way out and at create");
}

#[test]
fn substitution_payout_accounts_of_the_wrong_mint_owner_or_program_are_refused() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    let base = h.accounts(&escrow);

    // The payer's slot, holding another mint, owned by the payer.
    let other_mint = Address::new_unique();
    h.svm.set_account(other_mint, spl_mint_account(6, TOKEN_PROGRAM)).unwrap();
    let wrong_mint = Address::new_unique();
    h.svm.set_account(wrong_mint, spl_token_account(&other_mint, &payer.pubkey(), 0)).unwrap();
    let err = h.send(&[refund_ix(&Accounts { payer_tokens: wrong_mint, ..base }, recipient.pubkey())], &[&recipient]).expect_err("wrong mint");
    assert!(err.contains("NotThePayersAccount"), "{err}");

    // The recipient puts its own account in the payer's slot, to catch the payer's share.
    let err = h
        .send(&[agree_ix(&Accounts { payer_tokens: h.recipient_tokens, ..base }, payer.pubkey(), recipient.pubkey(), 5_000)], &[&payer, &recipient])
        .expect_err("the recipient's account as the payer's");
    assert!(err.contains("NotThePayersAccount"), "{err}");

    // The recipient's slot: the payer's own account, the recipient's standard one for another mint, a
    // Token-2022 look-alike. Only the recipient's standard account for this mint is paid.
    let err = h.send(&[pay_ix(&Accounts { recipient_tokens: h.payer_account(), ..base }, payer.pubkey())], &[&payer]).expect_err("the payer's as the recipient's");
    assert!(err.contains("NotTheRecipientsAccount"), "{err}");
    let recipients_other_mint = ata_address(&recipient.pubkey(), &other_mint);
    h.svm.set_account(recipients_other_mint, spl_token_account(&other_mint, &recipient.pubkey(), 0)).unwrap();
    let err = h.send(&[pay_ix(&Accounts { recipient_tokens: recipients_other_mint, ..base }, payer.pubkey())], &[&payer]).expect_err("another mint");
    assert!(err.contains("NotTheRecipientsAccount"), "{err}");
    let t22 = Address::new_unique();
    h.svm.set_account(t22, token_account_owned_by(TOKEN_2022_PROGRAM, &h.mint, &recipient.pubkey(), 0)).unwrap();
    let err = h.send(&[pay_ix(&Accounts { recipient_tokens: t22, ..base }, payer.pubkey())], &[&payer]).expect_err("Token-2022 account");
    assert!(err.contains("NotTheRecipientsAccount"), "{err}");

    // Token-2022 passed as the token program for a classic mint, at a way out and at create: the
    // token program must be the one that owns the mint.
    let mut ix = pay_ix(&base, payer.pubkey());
    assert_eq!(ix.accounts[5].pubkey, TOKEN_PROGRAM);
    ix.accounts[5].pubkey = TOKEN_2022_PROGRAM;
    let err = h.send(&[ix], &[&payer]).expect_err("Token-2022 program");
    assert!(err.contains("ConstraintMintTokenProgram"), "{err}");
    let mut ix = create_ix(&h.terms(2), &h.create_accounts());
    ix.accounts[5].pubkey = TOKEN_2022_PROGRAM;
    let err = h.send(&[ix], &[&payer]).expect_err("Token-2022 program at create");
    // The deposit address is derived under the token program named, so the associated token
    // program is asked for an address this transaction does not carry.
    assert!(err.contains("MissingAccount"), "{err}");
    // Named with its address under Token-2022 too, the mint is still the classic program's.
    let mut ix = create_ix(&h.terms(2), &h.create_accounts());
    let escrow2 = h.address(&h.terms(2));
    ix.accounts[1].pubkey = ata_address_under(&escrow2, &h.mint, &TOKEN_2022_PROGRAM);
    ix.accounts[5].pubkey = TOKEN_2022_PROGRAM;
    let err = h.send(&[ix], &[&payer]).expect_err("Token-2022 program and its address at create");
    assert!(err.contains("IncorrectProgramId") || err.contains("ConstraintMintTokenProgram"), "{err}");
    assert!(!h.exists(&escrow2));

    assert_eq!(h.vault_balance(&escrow), AMOUNT, "nothing moved");
    println!("rejected as expected: wrong mint, the other party's account in either slot, a Token-2022 account, Token-2022 as the program");
}

#[test]
fn substitution_an_escrow_shaped_account_owned_by_another_program_is_refused() {
    // Any other program's id: an account laid out exactly like an escrow, with the attacker as
    // recipient, owned by something other than the escrow program.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let stranger = Keypair::new();
    let escrow = h.funded(&h.terms(1));
    let mut data = h.account(&escrow).data;
    data[8 + 41..8 + 73].copy_from_slice(stranger.pubkey().as_ref()); // recipient
    for owner in [Address::new_unique(), SYSTEM_PROGRAM, TOKEN_PROGRAM] {
        let forged = Address::new_unique();
        h.svm
            .set_account(forged, Account { lamports: 10_000_000, data: data.clone(), owner, executable: false, rent_epoch: 0 })
            .unwrap();
        let s = Accounts { escrow: forged, ..h.accounts(&escrow) };
        let err = h.send(&[pay_ix(&s, payer.pubkey())], &[&payer]).expect_err("forged escrow");
        assert!(err.contains("AccountOwnedByWrongProgram"), "{owner}: {err}");
    }
    assert_eq!(h.vault_balance(&escrow), AMOUNT);
    println!("rejected as expected: an escrow's bytes under three other owners");
}

// ---------------------------------------------------------------------------------------------
// 2. Signers and addresses
// ---------------------------------------------------------------------------------------------

#[test]
fn signers_whoever_fronts_the_rent_must_sign_create() {
    // A sponsor named as the sponsor who did not sign: the payer spending someone else's SOL.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let sponsor = h.someone();
    let a = CreateAccounts { payer: payer.pubkey(), sponsor: sponsor.pubkey(), mint: h.mint };
    let mut ix = create_ix(&h.terms(1), &a);
    ix.accounts[3].is_signer = false;
    let err = h.send(&[ix], &[&payer]).expect_err("an unsigned sponsor");
    assert!(err.contains("AccountNotSigner"), "{err}");
    println!("rejected as expected: a sponsor who did not sign");
}

#[test]
fn reinit_create_on_a_live_escrow_is_refused() {
    // Only the same terms reach a live escrow's address, from either party; other terms at the
    // same id land at their own address and leave it as it is.
    let mut h = Harness::new();
    let escrow = h.funded(&h.terms(1));
    let err = h.create(&h.terms(1)).expect_err("the payer again");
    assert!(err.contains("already in use"), "{err}");
    let err = h.invoice(&h.terms(1)).expect_err("the recipient, the same terms");
    assert!(err.contains("already in use"), "{err}");
    let t = Terms { recipient: Keypair::new().pubkey(), amount: 1, schedule: Some(Schedule { windows: vec![window(T0 + DAY, 0)], end: End::Refund }), ..h.terms(1) };
    let (other, _) = h.create(&t).expect("other terms, the same id");
    assert_ne!(other, escrow);
    let e = h.escrow(&escrow);
    assert_eq!((e.recipient, e.amount, e.schedule), (h.recipient.pubkey(), AMOUNT, None), "the terms stand");
    assert_eq!(h.vault_balance(&escrow), AMOUNT, "and so does the money");
    println!("rejected as expected: create over a live escrow");
}

#[test]
fn reinit_an_ended_escrows_address_never_holds_a_second_deal() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    let s = h.accounts(&escrow);
    let t2 = h.terms(1);
    let err = h
        .send(&[pay_ix(&s, payer.pubkey()), create_ix(&t2, &h.create_accounts())], &[&payer])
        .expect_err("end and reopen in one transaction");
    assert!(err.contains("already in use"), "{err}");
    h.pay(&escrow).expect("the ending alone");
    let err = h.create(&t2).expect_err("reopen later");
    assert!(err.contains("already in use"), "{err}");
    assert_eq!(h.escrow(&escrow).recipient, h.recipient.pubkey(), "the receipt still names the first deal's recipient");
    println!("rejected as expected: an ended escrow's address never holds a second deal");
}

#[test]
fn nobody_can_open_the_address_a_payer_is_about_to_use() {
    // An earlier version derived the address from the payer's key and an id, and whoever opened
    // it named the recipient, so anyone who saw a payer's `create` could open that address first as
    // an invoice to itself. Now the address is made from every term: the front-runner's invoice
    // names itself as recipient, so it lands at its own terms' address; the payer's one tap lands at
    // the payer's, untouched.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let squatter = h.someone();
    let meant = h.terms(1);
    let escrow = h.address(&meant);
    let squat = Terms { recipient: squatter.pubkey(), schedule: Some(Schedule { windows: vec![window(T0 + DAY, 0)], end: End::Pay }), ..h.terms(1) };
    let a = CreateAccounts { payer: payer.pubkey(), sponsor: squatter.pubkey(), mint: h.mint };
    h.send(&[invoice_ix(&squat, &a)], &[&squatter]).expect("the squatter's own invoice");
    assert!(h.exists(&escrow_address(&squat, &payer.pubkey(), &h.mint)));
    assert!(!h.exists(&escrow));

    // The payer's one tap, the deposit address made first, lands at the payer's address.
    let s = h.accounts(&escrow);
    h.send(
        &[
            create_ata_idempotent_ix(h.sponsor.pubkey(), escrow, h.mint).0,
            create_ix(&meant, &h.create_accounts()),
            spl_transfer_ix(h.payer_wallet, s.vault, payer.pubkey(), AMOUNT),
            pay_ix(&s, payer.pubkey()),
        ],
        &[&payer],
    )
    .expect("the payer's one tap");
    let e = h.escrow(&escrow);
    assert_eq!((e.recipient, e.creator, e.schedule), (h.recipient.pubkey(), Side::Payer, None), "the payer's own terms");
    assert_eq!(h.balance(&h.recipient_tokens), AMOUNT, "the recipient the payer meant is paid");
    println!("rejected as expected: a front-runner lands at its own address; the payer's one tap is untouched");
}

#[test]
fn pda_another_program_cannot_share_an_address() {
    // Every address a program derives includes its own program id, so the escrow's seeds under any
    // other program land apart; and the escrow refuses accounts another program owns (see the
    // forged-escrow test above).
    let other = Address::new_unique();
    let payer = Keypair::new().pubkey();
    let seeds = [b"escrow".to_vec(), terms_hash(&Terms { id: 7, recipient: payer, amount: 1, arbiter: None, schedule: None }, &payer, &payer).to_vec()];
    let s: Vec<&[u8]> = seeds.iter().map(|v| v.as_slice()).collect();
    assert_ne!(Address::find_program_address(&s, &PROGRAM_ID).0, Address::find_program_address(&s, &other).0);
    // Within the escrow, the seeds are the tag and one 32-byte hash of terms that are each a fixed
    // length, so two different sets of terms meet only if SHA-256 collides.
    println!("rejected as expected: the escrow's seeds land elsewhere under another program");
}

// ---------------------------------------------------------------------------------------------
// 3. Arithmetic
// ---------------------------------------------------------------------------------------------

#[test]
fn arithmetic_splits_at_the_edges_add_up_and_never_overflow() {
    let mut h = Harness::new();
    let recipient = h.recipient.insecure_clone();
    let arbiter = h.arbiter.insecure_clone();

    // One base unit, split every way.
    for (id, bps) in [(1u64, 1u16), (2, 5_000), (3, 9_999), (4, 10_000), (5, 0)] {
        let escrow = h.funded(&Terms { amount: 1, ..h.terms(id) });
        let meta = h.agree(&escrow, bps).expect("agree");
        let (_, balance, to_recipient, to_payer, _) = ended(&events(&meta.logs));
        assert_eq!((balance, to_recipient + to_payer, to_payer), (1, 1, share(1, bps)));
    }

    // The largest balance a u64 holds, in a fresh payer's hands, through every way out that divides
    // or moves it whole.
    let (big, big_tokens) = new_payer(&mut h, u64::MAX);
    for (id, how) in [(10u64, "agree"), (11, "decide"), (12, "take_back"), (13, "pay"), (14, "end")] {
        h.set_time(T0);
        h.svm.set_account(big_tokens, spl_token_account(&h.mint, &big.pubkey(), u64::MAX)).unwrap();
        h.svm.set_account(h.recipient_tokens, spl_token_account(&h.mint, &recipient.pubkey(), 0)).unwrap();
        let t = Terms {
            amount: u64::MAX,
            arbiter: Some(arbiter.pubkey()),
            schedule: Some(Schedule { windows: vec![window(T0 + DAY, 3_333)], end: End::Pay }),
            ..h.terms(id)
        };
        let a = CreateAccounts { payer: big.pubkey(), sponsor: h.sponsor.pubkey(), mint: h.mint };
        let escrow = escrow_address(&t, &big.pubkey(), &h.mint);
        let vault = vault_address(&escrow, &h.mint);
        h.send(&[create_ix(&t, &a), spl_transfer_ix(big_tokens, vault, big.pubkey(), u64::MAX), mark_funded_ix(escrow, vault)], &[&big])
            .expect("create, fund and mark");
        let s = Accounts { escrow, vault, payer_tokens: big_tokens, recipient_tokens: h.recipient_tokens, sponsor: h.sponsor.pubkey(), ..h.accounts(&escrow) };
        let (ix, signers): (Instruction, Vec<&Keypair>) = match how {
            "agree" => (agree_ix(&s, big.pubkey(), recipient.pubkey(), 7_777), vec![&big, &recipient]),
            "decide" => (decide_ix(&s, arbiter.pubkey(), 1), vec![&arbiter]),
            "take_back" => (take_back_ix(&s, big.pubkey()), vec![&big]),
            "pay" => (pay_ix(&s, big.pubkey()), vec![&big]),
            _ => {
                h.advance(DAY);
                (end_ix(escrow, vault, h.mint, h.recipient_tokens, h.sponsor.pubkey()), vec![])
            }
        };
        let meta = h.send(&[ix], &signers).unwrap_or_else(|e| panic!("{how}: {e}"));
        let (_, balance, to_recipient, to_payer, _) = ended(&events(&meta.logs));
        assert_eq!(balance, u64::MAX, "{how}");
        assert_eq!(u128::from(to_recipient) + u128::from(to_payer), u128::from(u64::MAX), "{how}");
        assert_eq!(h.balance(&h.recipient_tokens), to_recipient, "{how}");
        assert_eq!(h.balance(&big_tokens), to_payer, "{how}");
    }
    println!("rejected as expected: no overflow or lost unit at 1 or at u64::MAX, for agree, decide, take_back, pay and the default");
}

// ---------------------------------------------------------------------------------------------
// 4. The schedule
// ---------------------------------------------------------------------------------------------

#[test]
fn schedule_the_mark_needs_the_money_and_lands_only_before_the_end_time() {
    // The default pays only a marked escrow, and the mark is the moment `mark_funded` runs with
    // the amount there, before the end time. Nobody can mark before the money, or after the end
    // time, so money that comes late never counts toward the default.
    let mut h = Harness::new();
    let t = h.scheduled(1, &[window(T0 + 2 * DAY, 0)], End::Pay);
    let (escrow, _) = h.create(&t).expect("create");
    let err = h.mark_funded(&escrow).expect_err("before the money");
    assert!(err.contains("NotFunded"), "{err}");
    h.advance(DAY);
    h.fund(&escrow, AMOUNT);
    h.mark_funded(&escrow).expect("the recipient marks at once");
    assert_eq!(h.escrow(&escrow).funded_at, T0 + DAY, "the mark is now, not the creation");
    h.set_time(T0 + 2 * DAY - 1);
    let err = h.end(&escrow, Side::Recipient).expect_err("a second early");
    assert!(err.contains("ScheduleNotOver"), "{err}");

    let late = h.funded(&h.scheduled(2, &[window(T0 + 2 * DAY, 0)], End::Pay));
    h.set_time(T0 + 2 * DAY);
    let err = h.mark_funded(&late).expect_err("at the end time");
    assert!(err.contains("ScheduleOver"), "{err}");
    println!("rejected as expected: a mark before the money, and one at the end time");
}

#[test]
fn finding_an_invoice_with_a_short_schedule_pays_the_recipient_whatever_the_payer_thinks() {
    // A schedule the creator sets and the other side accepts by paying or working. The recipient
    // invoices with a one-day window and a default to itself; a payer who pays without looking
    // cannot stop it past that day: the payer's only way out alone is to give. The payer's app
    // shows it before paying (the client's `optionsNotAgreed`).
    let mut h = Harness::new();
    let t = h.scheduled(1, &[window(T0 + DAY, 0)], End::Pay);
    let (escrow, _) = h.invoice(&t).expect("invoice");
    h.fund(&escrow, AMOUNT);
    h.mark_funded(&escrow).expect("the recipient marks");
    h.advance(DAY);
    h.end(&escrow, Side::Recipient).expect("accepted");
    assert_eq!(h.balance(&h.recipient_tokens), AMOUNT);
    println!("FINDING (app): a schedule the payer did not set pays the recipient at its end time; the app must show it before paying");
}

#[test]
fn finding_an_invoices_windows_are_dates_so_paying_late_shortens_them() {
    // Every time in a schedule is a date fixed when the escrow opens. The recipient invoices with a
    // week to take everything back; the payer pays on the last day and has the rest of that day,
    // not a week. "Seven days after payment" is exact only when the payer opens and pays in one
    // transaction.
    let mut h = Harness::new();
    let t = h.scheduled(1, &[window(T0 + 7 * DAY, 10_000)], End::Pay);
    let (escrow, _) = h.invoice(&t).expect("invoice");
    h.set_time(T0 + 7 * DAY - 60);
    let vault = h.vault(&escrow);
    let ixs = [h.fund_ix(&escrow, AMOUNT), mark_funded_ix(escrow, vault)];
    let payer = h.payer.insecure_clone();
    h.send(&ixs, &[&payer]).expect("paid and marked a minute before the end time");
    h.advance(60);
    let err = h.take_back(&escrow).expect_err("the window closed a minute after paying");
    assert!(err.contains("ScheduleOver"), "{err}");
    h.end(&escrow, Side::Recipient).expect("the default");
    println!("FINDING (app): an invoice's windows run from its opening; paid late, they are short; the app shows the dates before paying");
}

#[test]
fn finding_a_payers_schedule_can_take_back_money_the_recipient_worked_for() {
    // The mirror: the payer opens an escrow it may take back in full for a month, with the
    // default back to itself, pays, and the recipient works without looking. The payer takes it
    // all back on day 29. The recipient's app shows the schedule before the recipient works.
    let mut h = Harness::new();
    let t = h.scheduled(1, &[window(T0 + 30 * DAY, 10_000)], End::Refund);
    let escrow = h.marked(&t);
    h.advance(29 * DAY);
    h.take_back(&escrow).expect("accepted");
    assert_eq!(h.payer_total(), PAYER_START);
    println!("FINDING (app): a schedule the recipient did not set returns everything to the payer; the app must show it before working");
}

#[test]
fn end_whoever_sends_the_default_can_pay_only_the_recipients_standard_account() {
    // Anyone sends the default. An earlier version paid the recipient at any token account it
    // held, so the sender chose which: one the recipient's wallet app might not show. The recipient,
    // like the payer, is paid only at its standard token account for the mint.
    let mut h = Harness::new();
    let recipient = h.recipient.insecure_clone();
    let t = h.scheduled(1, &[window(T0 + DAY, 0)], End::Pay);
    let escrow = h.marked(&t);
    h.advance(DAY);
    // Anyone can make a token account held by the recipient: here, a stranger does, and aims at it.
    let obscure = Address::new_unique();
    h.svm.set_account(obscure, spl_token_account(&h.mint, &recipient.pubkey(), 0)).unwrap();
    let stranger = h.someone();
    let vault = vault_address(&escrow, &h.mint);
    let send_as_stranger = |h: &mut Harness, to: Address| {
        let ix = end_ix(escrow, vault, h.mint, to, h.sponsor.pubkey());
        h.svm.expire_blockhash();
        let tx = Transaction::new(&[&stranger], Message::new(&[ix], Some(&stranger.pubkey())), h.svm.latest_blockhash());
        h.send_tx(tx)
    };
    let err = send_as_stranger(&mut h, obscure).expect_err("an account the recipient holds, not its standard one");
    assert!(err.contains("NotTheRecipientsAccount"), "{err}");
    assert_eq!(h.balance(&obscure), 0);
    let standard = h.recipient_tokens;
    send_as_stranger(&mut h, standard).expect("the stranger sends it, to the recipient's standard account");
    assert_eq!(h.balance(&h.recipient_tokens), AMOUNT);
    println!("rejected as expected: the default's sender cannot choose which of the recipient's accounts is paid");
}

// ---------------------------------------------------------------------------------------------
// 5. The whole balance
// ---------------------------------------------------------------------------------------------

#[test]
fn finding_an_overpayment_goes_wherever_the_way_out_sends_the_balance() {
    // Carlos's rule: every way out pays out the whole balance, whatever it is. A second payment
    // made before the end, by mistake or by a second tap on a link, is part of the balance, and
    // `pay` sends it to the recipient. The client's pay link asks only for what is
    // missing and refuses once the amount is there.
    let mut h = Harness::new();
    let escrow = h.funded(&h.terms(1));
    h.fund(&escrow, AMOUNT);
    let meta = h.pay(&escrow).expect("accepted");
    let (_, balance, to_recipient, to_payer, _) = ended(&events(&meta.logs));
    assert_eq!((balance, to_recipient, to_payer), (2 * AMOUNT, 2 * AMOUNT, 0));
    println!("FINDING (app): a double payment before the end went to the recipient with the rest; only the recipient can give it back");
}

#[test]
fn finding_a_part_payment_can_be_closed_under_the_payer_by_the_recipient() {
    // `close_unfunded` runs at any time while the balance is below the amount, by either party. A
    // payer paying in two transfers can find the escrow closed between them:
    // the first part comes back, and the second, sent to the closed address, lands only if the
    // wallet app makes the deposit account again. Then there is no receipt to recover it through;
    // the payer opening the same terms again adopts it.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();
    let t = h.terms(1);
    let (escrow, _) = h.create(&t).expect("create");
    h.fund(&escrow, AMOUNT / 2);
    h.close_unfunded(&escrow, &recipient).expect("the recipient closes between the two parts");
    assert_eq!(h.balance(&h.payer_account()), AMOUNT / 2, "the first part back");
    let (make, vault) = create_ata_idempotent_ix(payer.pubkey(), escrow, h.mint);
    h.send(&[make, spl_transfer_ix(h.payer_wallet, vault, payer.pubkey(), AMOUNT / 2)], &[&payer]).expect("the second part");
    let err = h.recover_late(&escrow, &payer).expect_err("no receipt");
    assert!(err.contains("AccountNotInitialized"), "{err}");
    h.create(&t).expect("the payer opens the same terms again");
    h.close_unfunded(&escrow, &payer).expect("and closes it");
    assert_eq!(h.payer_total(), PAYER_START, "every unit back");
    println!("FINDING (app): a part payment can be closed under the payer; pay in one transfer, or open the same terms again to recover");
}

#[test]
fn finding_a_frozen_payer_account_blocks_only_the_ways_out_that_pay_the_payer() {
    // A classic mint's freeze authority can freeze the payer's standard account. Every way out
    // that pays the payer anything then fails until it is thawed; the ones that pay the payer
    // nothing still run, since they do not touch it.
    let mut h = Harness::new();
    let arbiter = h.arbiter.insecure_clone();
    let t = Terms { arbiter: Some(arbiter.pubkey()), ..h.terms(1) };
    let escrow = h.funded(&t);
    let payer_tokens = h.payer_account();
    let mut frozen = h.account(&payer_tokens);
    frozen.data[108] = 2; // AccountState::Frozen
    h.svm.set_account(payer_tokens, frozen).unwrap();
    let err = h.refund(&escrow).expect_err("frozen");
    assert!(err.contains("0x11") || err.contains("frozen") || err.contains("Frozen"), "{err}");
    let err = h.decide(&escrow, 5_000).expect_err("frozen");
    assert!(err.contains("0x11") || err.contains("frozen") || err.contains("Frozen"), "{err}");
    h.decide(&escrow, 0).expect("everything to the recipient does not touch the payer's account");
    assert_eq!(h.balance(&h.recipient_tokens), AMOUNT);
    println!("FINDING (token): a frozen payer account blocks every way out that pays the payer, and nothing else");
}

// ---------------------------------------------------------------------------------------------
// 6. Replays and double spends
// ---------------------------------------------------------------------------------------------

#[test]
fn double_spend_a_signed_way_out_sent_twice_is_refused() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let t = h.terms(1);
    let escrow = h.funded(&t);
    let s = h.accounts(&escrow);
    h.svm.expire_blockhash();
    let msg = Message::new(&[pay_ix(&s, payer.pubkey())], Some(&h.sponsor.pubkey()));
    let tx = Transaction::new(&[&h.sponsor, &payer], msg, h.svm.latest_blockhash());
    h.svm.send_transaction(tx.clone()).expect("first");
    // Someone pays the same address again, so a replay would have money to hit.
    h.svm.set_account(s.vault, spl_token_account(&h.mint, &escrow, AMOUNT)).unwrap();
    let err = h.svm.send_transaction(tx).expect_err("replay");
    assert!(format!("{:?}", err.err).contains("AlreadyProcessed"), "{:?}", err.err);
    // A fresh signature over the same pay: the escrow has ended.
    let err = h.send(&[pay_ix(&s, payer.pubkey())], &[&payer]).expect_err("sign again");
    assert!(err.contains("Ended"), "{err}");
    let err = h.create(&t).expect_err("reopen");
    assert!(err.contains("already in use"), "{err}");
    assert_eq!(h.vault_balance(&escrow), AMOUNT, "the second payment is untouched");
    assert_eq!(h.balance(&h.recipient_tokens), AMOUNT, "the recipient was paid once");
    println!("rejected as expected: the same signed pay replayed, re-signed, and the id reopened");
}

#[test]
fn double_spend_nobody_moves_or_closes_the_deposit_account_directly() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    let vault = vault_address(&escrow, &h.mint);
    let err = h.send(&[spl_transfer_ix(vault, h.payer_wallet, payer.pubkey(), AMOUNT)], &[&payer]).expect_err("transfer out");
    assert!(err.contains("owner does not match") || err.contains("OwnerMismatch") || err.contains("custom program error: 0x4"), "{err}");
    let err = h.send(&[spl_close_ix(vault, payer.pubkey(), payer.pubkey())], &[&payer]).expect_err("close");
    assert!(err.contains("0x4") || err.contains("0xb") || err.contains("owner"), "{err}");
    assert_eq!(h.vault_balance(&escrow), AMOUNT);
    println!("rejected as expected: the payer cannot pull or close the deposit account through the token program");
}

// ---------------------------------------------------------------------------------------------
// 7. Tokens
// ---------------------------------------------------------------------------------------------

#[test]
fn finding_a_self_minted_token_makes_a_receipt_that_looks_like_real_money() {
    // Any classic mint is accepted. A payer who owns a mint can fund a billion "dollars" and
    // produce a Created and Ended pair naming any amount. Only the mint says it is worthless.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let fake = Address::new_unique();
    h.svm.set_account(fake, spl_mint_account(6, TOKEN_PROGRAM)).unwrap();
    let fake_tokens = ata_address(&payer.pubkey(), &fake);
    h.svm.set_account(fake_tokens, spl_token_account(&fake, &payer.pubkey(), 1_000_000_000_000_000)).unwrap();
    let recipient_fake = ata_address(&h.recipient.pubkey(), &fake);
    h.svm.set_account(recipient_fake, spl_token_account(&fake, &h.recipient.pubkey(), 0)).unwrap();
    let t = Terms { amount: 1_000_000_000_000_000, ..h.terms(1) };
    let a = CreateAccounts { payer: payer.pubkey(), sponsor: h.sponsor.pubkey(), mint: fake };
    let escrow = escrow_address(&t, &payer.pubkey(), &fake);
    let vault = vault_address(&escrow, &fake);
    let s = Accounts { escrow, vault, mint: fake, payer_tokens: fake_tokens, recipient_tokens: recipient_fake, sponsor: h.sponsor.pubkey(), token_program: TOKEN_PROGRAM };
    let meta = h
        .send(&[create_ix(&t, &a), spl_transfer_ix(fake_tokens, vault, payer.pubkey(), t.amount), pay_ix(&s, payer.pubkey())], &[&payer])
        .expect("accepted");
    let (outcome, balance, ..) = ended(&events(&meta.logs));
    assert_eq!((outcome, balance), (Outcome::Pay, 1_000_000_000_000_000));
    println!("FINDING (index): a billion-unit receipt in a token the payer minted; only the mint field tells");
}

#[test]
fn tokens_wrapped_sol_is_refused_at_create() {
    // SOL sent to a wrapped-SOL deposit account without a sync would never count and would leave
    // with the rent. The native mint is refused at create, as the payer, as the recipient, with or
    // without money already at the address.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();
    h.svm.set_account(NATIVE_MINT, spl_mint_account(9, TOKEN_PROGRAM)).unwrap();
    let t = Terms { amount: 100_000_000, ..h.terms(1) }; // 0.1 SOL
    let a = CreateAccounts { payer: payer.pubkey(), sponsor: h.sponsor.pubkey(), mint: NATIVE_MINT };
    let err = h.send(&[create_ix(&t, &a)], &[&payer]).expect_err("the payer, with the native mint");
    assert!(err.contains("NativeMint"), "{err}");
    let err = h.send(&[invoice_ix(&t, &a)], &[&recipient]).expect_err("the recipient, with the native mint");
    assert!(err.contains("NativeMint"), "{err}");
    let escrow = escrow_address(&t, &payer.pubkey(), &NATIVE_MINT);
    let vault = vault_address(&escrow, &NATIVE_MINT);
    h.svm.set_account(vault, wsol_account(&escrow)).unwrap();
    h.send(&[sol_transfer_ix(payer.pubkey(), vault, t.amount), sync_native_ix(vault)], &[&payer]).expect("SOL sent first");
    let err = h.send(&[create_ix(&t, &a)], &[&payer]).expect_err("over a funded wrapped-SOL account");
    assert!(err.contains("NativeMint"), "{err}");
    assert!(!h.exists(&escrow), "nothing written");
    println!("rejected as expected: wrapped SOL at create, from either party, even with money already there");
}

// ---------------------------------------------------------------------------------------------
// 8. Rent, late money and the sweep
// ---------------------------------------------------------------------------------------------

#[test]
fn rent_stray_sol_goes_to_the_payer_at_a_close_and_by_a_sweep() {
    // Someone pays the escrow's address in SOL instead of the token. It never counts as funding.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();

    // Never funded: close_unfunded closes the escrow account, and the stray SOL leaves with its
    // rent, to the sponsor.
    let (escrow, _) = h.create(&h.terms(1)).expect("create");
    h.send(&[sol_transfer_ix(recipient.pubkey(), escrow, 30_000_000)], &[&recipient]).expect("SOL to the escrow's address");
    let (payer_sol, sponsor_sol) = (h.lamports(&payer.pubkey()), h.lamports(&h.sponsor.pubkey()));
    let meta = h.close_unfunded(&escrow, &recipient).expect("close");
    let Some(Event::Closed { rent_lamports, sponsor, .. }) = events(&meta.logs).pop() else { panic!("no Closed") };
    assert!(rent_lamports > 30_000_000, "the stray SOL went with the rents: {rent_lamports}");
    assert_eq!(sponsor, h.sponsor.pubkey());
    assert_eq!(h.lamports(&h.sponsor.pubkey()), sponsor_sol - 2 * 5_000 + rent_lamports, "to the sponsor, which paid the fee");
    assert_eq!(h.lamports(&payer.pubkey()), payer_sol, "none to the creator");

    // Ended: the receipt is never closed; `sweep_rent` moves what is above the minimum, the stray
    // SOL included, to the sponsor recorded at creation. The program cannot tell stray SOL from rent.
    let escrow2 = h.funded(&h.terms(2));
    h.pay(&escrow2).expect("pay");
    let before = h.lamports(&escrow2);
    h.send(&[sol_transfer_ix(recipient.pubkey(), escrow2, 30_000_000)], &[&recipient]).expect("SOL to a receipt");
    let (payer_sol, sponsor_sol) = (h.lamports(&payer.pubkey()), h.lamports(&h.sponsor.pubkey()));
    h.sweep(&escrow2).expect("sweep");
    assert_eq!(h.lamports(&escrow2), before, "back to its minimum");
    assert_eq!(h.lamports(&h.sponsor.pubkey()), sponsor_sol + 30_000_000 - 5_000, "the stray SOL went to the sponsor");
    assert_eq!(h.lamports(&payer.pubkey()), payer_sol, "none to the creator");
    println!("accepted, note: stray SOL goes to the sponsor, from a never-funded escrow at close ({rent_lamports} lamports) and from a receipt by sweep_rent");
}

/// Paid out, then paid into again at the old address: the state `recover_late` is for.
fn ended_and_paid_again(h: &mut Harness, id: u64, late: u64) -> Address {
    let payer = h.payer.insecure_clone();
    let escrow = h.funded(&h.terms(id));
    h.pay(&escrow).expect("pay");
    let (make, vault) = create_ata_idempotent_ix(payer.pubkey(), escrow, h.mint);
    h.send(&[make, spl_transfer_ix(h.payer_wallet, vault, payer.pubkey(), late)], &[&payer]).expect("paid again");
    escrow
}

#[test]
fn late_money_goes_only_to_the_payers_standard_account_and_only_after_the_end() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();
    let thief = h.someone();

    // A live escrow's money is not late: it is the deal's.
    let live = h.funded(&h.terms(1));
    let live_vault = vault_address(&live, &h.mint);
    let err = h.send(&[recover_late_ix(live, live_vault, payer.pubkey(), h.mint, thief.pubkey())], &[&thief]).expect_err("live");
    assert!(err.contains("NotEnded"), "{err}");

    let escrow = ended_and_paid_again(&mut h, 2, 300_000);
    let vault = vault_address(&escrow, &h.mint);
    let (thief_ata_ix, thief_ata) = create_ata_idempotent_ix(thief.pubkey(), thief.pubkey(), h.mint);
    h.send(&[thief_ata_ix], &[&thief]).expect("the thief's own token account");
    let (recipient_ata_ix, recipient_ata) = create_ata_idempotent_ix(recipient.pubkey(), recipient.pubkey(), h.mint);
    h.send(&[recipient_ata_ix], &[&recipient]).expect("the recipient's standard token account");
    let cases: Vec<(&str, Instruction, &str)> = vec![
        ("the thief's token account", recover_late_ix_to(escrow, vault, payer.pubkey(), thief_ata, h.mint, thief.pubkey()), "ConstraintTokenOwner"),
        ("the recipient's standard account", recover_late_ix_to(escrow, vault, payer.pubkey(), recipient_ata, h.mint, thief.pubkey()), "ConstraintTokenOwner"),
        (
            "a token account the payer holds, not the standard one",
            recover_late_ix_to(escrow, vault, payer.pubkey(), h.payer_wallet, h.mint, thief.pubkey()),
            "AccountNotAssociatedTokenAccount",
        ),
        ("the thief as the payer", recover_late_ix(escrow, vault, thief.pubkey(), h.mint, thief.pubkey()), "ConstraintHasOne"),
        ("another escrow's deposit account", recover_late_ix(escrow, live_vault, payer.pubkey(), h.mint, thief.pubkey()), "ConstraintHasOne"),
    ];
    for (what, ix, want) in cases {
        let err = h.send(&[ix], &[&thief]).err().unwrap_or_else(|| panic!("{what}: must be refused"));
        assert!(err.contains(want), "{what}: expected {want}, got\n{err}");
    }
    assert_eq!(h.balance(&vault), 300_000, "nothing moved");
    h.send(&[recover_late_ix(escrow, vault, payer.pubkey(), h.mint, thief.pubkey())], &[&thief]).expect("to the payer");
    assert_eq!(h.balance(&h.payer_account()), 300_000);
    assert_eq!(h.balance(&thief_ata), 0);
    println!("rejected as expected: late money goes to the payer's standard account and nowhere else, and only after the end");
}

#[test]
fn finding_a_payer_who_hands_its_standard_account_away_blocks_its_own_late_money() {
    // `recover_late` makes the payer's standard account if it is missing, with Anchor's
    // create-if-missing, which also checks that the payer still holds it. A payer who hands that
    // account to another key blocks its own late money there until it takes the account back.
    // Nothing else: the ways out check the address alone.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let escrow = ended_and_paid_again(&mut h, 1, 1);
    let payer_tokens = h.payer_account();
    h.send(&[hand_over_ix(payer_tokens, payer.pubkey(), Keypair::new().pubkey())], &[&payer]).expect("handed away");
    let err = h.recover_late(&escrow, &payer).expect_err("blocked");
    assert!(err.contains("ConstraintTokenOwner") || err.contains("IllegalOwner") || err.contains("InvalidAccountOwner"), "{err}");
    println!("FINDING (known limit): recover_late checks who holds the payer's standard account; a payer who hands it away blocks its own late money");
}

#[test]
fn a_party_who_hands_its_standard_account_away_blocks_no_way_out() {
    // The ways out check each party's account by address, not by who holds it now: a party who
    // hands its standard account to another key cannot stop the arbiter, a split, or the default. The
    // money goes to the address, as that party arranged.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();
    let t = Terms { arbiter: Some(h.arbiter.pubkey()), ..h.terms(1) };
    let escrow = h.funded(&t);
    let payer_tokens = h.payer_account();
    let elsewhere = Keypair::new().pubkey();
    h.send(&[hand_over_ix(payer_tokens, payer.pubkey(), elsewhere)], &[&payer]).expect("the payer hands its account away");
    h.send(&[hand_over_ix(h.recipient_tokens, recipient.pubkey(), elsewhere)], &[&recipient]).expect("and the recipient its own");
    h.decide(&escrow, 4_000).expect("the arbiter still decides");
    assert_eq!((h.balance(&h.recipient_tokens), h.balance(&payer_tokens)), (600_000, 400_000));
    println!("standard accounts handed to another key block nothing: the arbiter still decides");
}

#[test]
fn a_missing_payer_account_is_made_in_the_same_transaction_by_whoever_sends_the_way_out() {
    // A payer may close its empty standard account. A way out that pays the payer then needs it
    // made first, which anyone can do in the same transaction with the standard idempotent
    // instruction, at its own cost; one that pays the payer nothing does not need it at all.
    let mut h = Harness::new();
    let recipient = h.recipient.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    h.drop_payer_account();
    let err = h.refund(&escrow).expect_err("no payer account");
    // The token program refuses to pay an account that does not exist.
    assert!(err.contains("InvalidAccountData"), "{err}");
    let (make, payer_tokens) = create_ata_idempotent_ix(recipient.pubkey(), h.payer.pubkey(), h.mint);
    assert_eq!(payer_tokens, h.payer_account());
    let s = h.accounts(&escrow);
    h.send(&[make, refund_ix(&s, recipient.pubkey())], &[&recipient]).expect("made, then paid, in one transaction");
    assert_eq!(h.balance(&payer_tokens), AMOUNT);

    // An agreed split that pays the payer nothing runs with no payer account at all.
    let mut h = Harness::new();
    let escrow = h.funded(&h.terms(1));
    h.drop_payer_account();
    h.agree(&escrow, 0).expect("all to the recipient: the payer's account is never touched");
    assert!(!h.exists(&h.payer_account()));
    println!("a missing payer account: made first in the same transaction when the payer is paid, and not needed when it is not");
}

#[test]
fn sweep_pays_only_the_recorded_sponsor_and_only_from_an_escrow() {
    let mut h = Harness::new();
    let thief = Keypair::new();
    let escrow = h.funded(&h.terms(1));
    let s = h.accounts(&escrow);
    h.svm.set_sysvar(&rent_at(RENT_FINAL));
    let before = h.account(&escrow);

    let err = h.send(&[sweep_rent_ix(escrow, thief.pubkey())], &[]).expect_err("to a thief");
    assert!(err.contains("ConstraintHasOne"), "{err}");
    for (who, key) in [("the creator", h.payer.pubkey()), ("the recipient", h.recipient.pubkey())] {
        let err = h.send(&[sweep_rent_ix(escrow, key)], &[]).expect_err(who);
        assert!(err.contains("ConstraintHasOne"), "{who}: {err}");
    }
    // Something that is not an escrow: its deposit account, and an escrow-shaped account another
    // program owns.
    let err = h.send(&[sweep_rent_ix(s.vault, h.sponsor.pubkey())], &[]).expect_err("a token account");
    assert!(err.contains("AccountOwnedByWrongProgram"), "{err}");
    let forged = Address::new_unique();
    let mut fake = before.clone();
    fake.owner = TOKEN_PROGRAM;
    fake.lamports += 50_000_000;
    h.svm.set_account(forged, fake).unwrap();
    let err = h.send(&[sweep_rent_ix(forged, h.sponsor.pubkey())], &[]).expect_err("forged");
    assert!(err.contains("AccountOwnedByWrongProgram"), "{err}");
    assert_eq!(h.account(&escrow).lamports, before.lamports, "nothing moved");
    h.sweep(&escrow).expect("to the sponsor");
    assert_eq!(h.lamports(&escrow), (128 + ESCROW_LEN as u64) * RENT_FINAL);
    println!("rejected as expected: the sweep pays only the recorded sponsor, and only from an escrow");
}

// ---------------------------------------------------------------------------------------------
// 8. The edges (session 16, the attack pass): the deposit address and money meant for other terms,
//    a frozen deposit or recipient account, and a sweep then a close.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_deposit_address_never_adopts_money_meant_for_other_terms() {
    // An earlier version made the address from the creator's key and an id, so money one payer
    // sent there, before an escrow existed or after a close, was adopted by whatever deal next took
    // the id, even one naming another payer, who could then pay it to the recipient. Now the
    // payer is a term: another payer's deal is at another address, and the money waits for an
    // escrow with exactly the terms it was sent to, which its own payer can open, and close.
    let mut h = Harness::new();
    let recipient = h.recipient.insecure_clone();
    let payer_a = h.payer.insecure_clone();
    let meant = h.terms(1);
    let escrow = h.address(&meant);

    // Payer A pays half to its own deal's address before the escrow exists, making the account
    // first as a wallet app would.
    let (make, vault) = create_ata_idempotent_ix(payer_a.pubkey(), escrow, h.mint);
    h.send(&[make, spl_transfer_ix(h.payer_wallet, vault, payer_a.pubkey(), AMOUNT / 2)], &[&payer_a]).expect("payer A pays");

    // The recipient invoices payer B at the same id: another address, holding nothing.
    let payer_b = h.someone();
    let a = CreateAccounts { payer: payer_b.pubkey(), sponsor: h.sponsor.pubkey(), mint: h.mint };
    h.send(&[invoice_ix(&meant, &a)], &[&recipient]).expect("the recipient invoices payer B at the same id");
    let other = escrow_address(&meant, &payer_b.pubkey(), &h.mint);
    assert_ne!(other, escrow);
    assert_eq!(h.vault_balance(&other), 0, "payer B's deal holds none of payer A's money");
    assert_eq!(h.balance(&vault), AMOUNT / 2);

    // Payer A opens the terms it paid, which adopt the part, and closes them: the part comes back.
    h.create(&meant).expect("payer A opens the terms it paid");
    h.close_unfunded(&escrow, &payer_a).expect("and closes them");
    assert_eq!(h.payer_total(), PAYER_START, "payer A has all its money back");
    println!("rejected as expected: money sent to one payer's terms is never adopted by a deal naming another");
}

#[test]
fn a_payment_to_an_address_lands_only_in_a_deal_with_its_terms() {
    // The recipient invoices with one arbiter, closes it unpaid, and reopens the same id with another
    // it picked. The payer read the first deal and pays its address. That money must never count
    // toward the second deal: another arbiter is another address.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();
    let fair = h.arbiter.pubkey();
    let picked = h.someone();
    let first_terms = Terms { arbiter: Some(fair), ..h.terms(1) };
    let (first, _) = h.invoice(&first_terms).expect("the first invoice");
    h.close_unfunded(&first, &recipient).expect("closed unpaid");
    let second_terms = Terms { arbiter: Some(picked.pubkey()), ..h.terms(1) };
    let (second, _) = h.invoice(&second_terms).expect("the same id, another arbiter");

    // The payer pays the address it read, making its deposit account as a wallet app would.
    let (make, first_vault) = create_ata_idempotent_ix(payer.pubkey(), first, h.mint);
    h.send(&[make, spl_transfer_ix(h.payer_wallet, first_vault, payer.pubkey(), AMOUNT)], &[&payer]).expect("the payer pays");

    assert_ne!(second, first, "another arbiter is another address");
    assert_eq!(h.vault_balance(&second), 0, "the second deal holds none of it");
    let s = h.accounts(&second);
    let err = h.send(&[decide_ix(&s, picked.pubkey(), 10_000)], &[&picked]).expect_err("the picked arbiter");
    assert!(err.contains("NotFunded"), "{err}");
    assert_eq!(h.balance(&first_vault), AMOUNT, "the money waits at the address it was sent to");

    // Only the first terms take it: reopened, they hold it, with the arbiter the payer read.
    let (again, _) = h.invoice(&first_terms).expect("the first terms, reopened");
    assert_eq!(again, first);
    assert_eq!((h.escrow(&first).arbiter, h.vault_balance(&first)), (fair, AMOUNT));
    println!("rejected as expected: a payment to one deal's address never counts toward another deal's terms");
}

#[test]
fn finding_a_frozen_deposit_account_blocks_every_way_out() {
    // The checklist reasons that freezing the deposit account stops every way out, since each moves
    // tokens out of it; only the payer's account had been frozen in a test. Here the deposit
    // account itself is frozen: no way out runs until it is thawed. USDC's maker holds this freeze
    // authority.
    let mut h = Harness::new();
    let t = Terms { arbiter: Some(h.arbiter.pubkey()), schedule: Some(Schedule { windows: vec![window(T0 + DAY, 5_000)], end: End::Pay }), ..h.terms(1) };
    let escrow = h.marked(&t);
    let vault = vault_address(&escrow, &h.mint);
    let mut frozen = h.account(&vault);
    frozen.data[108] = 2; // AccountState::Frozen
    h.svm.set_account(vault, frozen).unwrap();

    let froze = |e: String, what: &str| assert!(e.contains("0x11") || e.to_lowercase().contains("frozen"), "{what}: {e}");
    froze(h.pay(&escrow).expect_err("pay"), "pay");
    froze(h.refund(&escrow).expect_err("refund"), "refund");
    froze(h.take_back(&escrow).expect_err("take_back"), "take_back");
    froze(h.agree(&escrow, 5_000).expect_err("agree"), "agree");
    froze(h.decide(&escrow, 5_000).expect_err("decide"), "decide");
    // Even one that pays the whole balance to one side moves it out of the frozen deposit account.
    froze(h.decide(&escrow, 0).expect_err("all to the recipient"), "decide all to the recipient");
    h.advance(DAY + 1);
    froze(h.end(&escrow, Side::Recipient).expect_err("end"), "end");
    assert_eq!(h.vault_balance(&escrow), AMOUNT, "nothing moved");
    println!("FINDING (token): a frozen deposit account blocks every way out until it is thawed");
}

#[test]
fn finding_a_frozen_recipient_account_blocks_only_the_ways_out_that_pay_the_recipient() {
    // The mirror of the payer-freeze finding, for the recipient. Freezing the recipient's standard account
    // stops every way out that pays the recipient anything; the ones that pay the recipient nothing run,
    // since they never touch it.
    let mut h = Harness::new();
    let t = Terms { arbiter: Some(h.arbiter.pubkey()), ..h.terms(1) };
    let escrow = h.funded(&t);
    let mut frozen = h.account(&h.recipient_tokens);
    frozen.data[108] = 2; // AccountState::Frozen
    h.svm.set_account(h.recipient_tokens, frozen).unwrap();

    let e = h.pay(&escrow).expect_err("frozen");
    assert!(e.contains("0x11") || e.to_lowercase().contains("frozen"), "{e}");
    let e = h.decide(&escrow, 5_000).expect_err("frozen");
    assert!(e.contains("0x11") || e.to_lowercase().contains("frozen"), "{e}");
    // Everything to the payer pays the recipient nothing and never touches its frozen account.
    h.decide(&escrow, 10_000).expect("all to the payer runs");
    assert_eq!(h.balance(&h.payer_account()), AMOUNT);
    println!("FINDING (token): a frozen recipient account blocks every way out that pays the recipient, and nothing else");
}

#[test]
fn close_unfunded_after_a_sweep_returns_every_rent_to_the_sponsor() {
    // A never-funded escrow can be swept as its rent minimum falls, and then closed. The two must
    // compose: the sweep sends the excess to the sponsor and leaves the escrow account at exactly the
    // current minimum; the close returns that (and the deposit account's rent) to the sponsor too,
    // with no underflow and nothing stranded.
    let mut h = Harness::new();
    h.svm.set_sysvar(&rent_at(6_960)); // the older, higher rate, so the cut leaves an excess
    let payer = h.payer.insecure_clone();
    let sponsor = h.someone();
    let a = CreateAccounts { sponsor: sponsor.pubkey(), ..h.create_accounts() };
    h.send(&[create_ix(&h.terms(1), &a)], &[&payer, &sponsor]).expect("create at the old rate, the sponsor paying");
    let escrow = h.address(&h.terms(1));
    let vault = vault_address(&escrow, &h.mint);
    h.svm.set_sysvar(&rent_at(RENT_FINAL)); // the cut lands
    let minimum = (128 + ESCROW_LEN as u64) * RENT_FINAL;
    let excess = h.lamports(&escrow) - minimum;
    let (creator_before, sponsor_before) = (h.lamports(&payer.pubkey()), h.lamports(&sponsor.pubkey()));

    h.sweep(&escrow).expect("sweep the escrow's excess to the sponsor");
    assert_eq!(h.lamports(&escrow), minimum, "left at exactly the new minimum");
    assert_eq!(h.lamports(&sponsor.pubkey()), sponsor_before + excess);

    let vault_rent = h.lamports(&vault);
    h.close_unfunded(&escrow, &payer).expect("close after the sweep");
    h.assert_closed(&escrow, "escrow");
    h.assert_closed(&vault, "vault");
    assert_eq!(h.lamports(&sponsor.pubkey()), sponsor_before + excess + minimum + vault_rent, "the sponsor gets the excess, then what is left of both rents");
    assert_eq!(h.lamports(&payer.pubkey()), creator_before, "none to the creator");
    println!("a sweep then a close compose: the sponsor gets the excess and then the remaining rent, nothing stranded");
}
