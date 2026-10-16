//! The one-tap payment: the deposit address made, `create`, a plain transfer into the deposit
//! account and `pay`, in one transaction, as the client builds it (`payInOneTap`).
//!
//! A product may make every payment an escrow paid out in the same second, so every payment
//! leaves a receipt at an address a review can point at. This file sends exactly that, measures
//! it, and checks what it leaves behind: a permanent receipt, which keeps its own rent and records
//! when the money was there though nobody marked it, and the deposit account's rent back, in the
//! same transaction, to the key that fronted both rents (usually a fee payer); a later
//! sweep of what the rent cuts free goes to it too. The rent is measured at today's rate and at
//! the rate the cuts end at.
//!
//! The deposit address is made by the associated token program at the top of the transaction,
//! before `create`, so a fee payer that checks every transfer's destination before signing (Kora)
//! finds it made; `create` adopts it.
//!
//! Run with `cargo test --test one_tap -- --nocapture` for the numbers.

use forest_escrow_tests::*;
use solana_keypair::Keypair;
use solana_signer::Signer;

/// Lamports per byte: what session 3 read from mainnet.
const RENT_TODAY: u64 = 5_080;
/// The dollar price of SOL the READMEs use for every rent figure.
const SOL_USD: f64 = 100.24;

/// The deposit address, made first: the associated token program's idempotent create, the sponsor
/// paying.
fn make_deposit(h: &Harness, escrow: &solana_address::Address) -> solana_instruction::Instruction {
    create_ata_idempotent_ix(h.sponsor.pubkey(), *escrow, h.mint).0
}

#[test]
fn create_fund_and_pay_ride_in_one_transaction() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    println!("\n== one tap: the deposit address, create, a plain transfer in, pay, in one transaction ==");

    // Another key (the transaction's fee payer) fronts the rent; the payer signs create, the
    // transfer and pay. Every option off. The payer's standard account is not named.
    let t = h.terms(1);
    let escrow = h.address(&t);
    let vault = vault_address(&escrow, &h.mint);
    let s = h.accounts(&escrow);
    let (sponsor_before, payer_before) = (h.lamports(&h.sponsor.pubkey()), h.lamports(&payer.pubkey()));
    let ixs = [
        make_deposit(&h, &escrow),
        create_ix(&t, &h.create_accounts()),
        spl_transfer_ix(h.payer_wallet, vault, payer.pubkey(), AMOUNT),
        pay_ix(&s, payer.pubkey()),
    ];
    let (_, _, ev) = h.measure("one tap, the recipient's account already there", &ixs, &[&payer]);
    assert_eq!(names(&ev), ["Created", "Ended"], "the receipt: no Funded, since pay needs no mark");
    let (outcome, balance, to_recipient, to_payer, rent_lamports) = ended(&ev);
    assert_eq!((outcome, balance, to_recipient, to_payer), (Outcome::Pay, AMOUNT, AMOUNT, 0));
    h.assert_closed(&vault, "the deposit account");
    let e = h.escrow(&escrow);
    assert_eq!((e.status, e.outcome, e.to_recipient, e.creator), (Status::Ended, Some(Outcome::Pay), AMOUNT, Side::Payer));
    assert_eq!(e.sponsor, h.sponsor.pubkey());
    // Nobody marked it, and the receipt still says when the money was there: the ending's time,
    // which in one tap is also the creation's.
    assert_eq!((e.created_at, e.funded_at, e.ended_at), (T0, T0, T0));
    let Some(Event::Ended { funded_at, ended_at, .. }) = ev.iter().find(|e| e.name() == "Ended") else { panic!() };
    assert_eq!((*funded_at, *ended_at), (T0, T0), "the Ended event carries the same funding time");
    assert_eq!(h.balance(&h.recipient_tokens), AMOUNT);
    assert_eq!(h.balance(&h.payer_wallet), PAYER_START - AMOUNT);
    let fee = 2 * 5_000; // two signatures; the compute-budget instruction sets a limit, not a price
    let receipt_rent = h.lamports(&escrow);
    assert_eq!(h.lamports(&h.sponsor.pubkey()), sponsor_before - fee - receipt_rent, "the sponsor fronted both rents and gets the deposit account's back");
    assert_eq!(h.lamports(&payer.pubkey()), payer_before, "none to the payer, its creator");
    println!("   the deposit account's {rent_lamports} lamports of rent go back to the sponsor in the same transaction; the receipt keeps {receipt_rent}");

    // The recipient has never held this token: the same transaction makes the recipient's standard
    // account first. That account's rent is not returned; it is the recipient's account from then on.
    let recipient2 = Keypair::new();
    let t2 = Terms { recipient: recipient2.pubkey(), ..h.terms(2) };
    let (make, recipient2_tokens) = create_ata_idempotent_ix(h.sponsor.pubkey(), recipient2.pubkey(), h.mint);
    let escrow2 = h.address(&t2);
    let vault2 = vault_address(&escrow2, &h.mint);
    let s2 = Accounts { recipient_tokens: recipient2_tokens, ..h.accounts(&escrow2) };
    let ixs = [
        make,
        make_deposit(&h, &escrow2),
        create_ix(&t2, &h.create_accounts()),
        spl_transfer_ix(h.payer_wallet, vault2, payer.pubkey(), AMOUNT),
        pay_ix(&s2, payer.pubkey()),
    ];
    h.measure("one tap, the recipient's account made first", &ixs, &[&payer]);
    assert_eq!(h.balance(&recipient2_tokens), AMOUNT);

    // Both options on, to see the ceiling: an arbiter and four windows.
    let four = [window(T0 + DAY, 10_000), window(T0 + 2 * DAY, 5_000), window(T0 + 3 * DAY, 2_500), window(T0 + 4 * DAY, 0)];
    let mut t3 = h.scheduled(3, &four, End::Pay);
    t3.arbiter = Some(h.arbiter.pubkey());
    let escrow3 = h.address(&t3);
    let s3 = h.accounts(&escrow3);
    let ixs = [
        make_deposit(&h, &escrow3),
        create_ix(&t3, &h.create_accounts()),
        spl_transfer_ix(h.payer_wallet, s3.vault, payer.pubkey(), AMOUNT),
        pay_ix(&s3, payer.pubkey()),
    ];
    h.measure("one tap, an arbiter and four windows", &ixs, &[&payer]);

    // Open and fund with the mark, as `createAndFund` sends it, the escrow left live to run its
    // schedule: the ceiling again.
    let mut t5 = h.scheduled(5, &four, End::Pay);
    t5.arbiter = Some(h.arbiter.pubkey());
    let escrow5 = h.address(&t5);
    let vault5 = vault_address(&escrow5, &h.mint);
    let ixs = [
        make_deposit(&h, &escrow5),
        create_ix(&t5, &h.create_accounts()),
        spl_transfer_ix(h.payer_wallet, vault5, payer.pubkey(), AMOUNT),
        mark_funded_ix(escrow5, vault5),
    ];
    let (_, _, ev) = h.measure("create, fund and mark, an arbiter and four windows", &ixs, &[&payer]);
    assert_eq!(names(&ev), ["Created", "Funded"]);
    assert_eq!(h.escrow(&escrow5).status, Status::Funded);

    // An invoice paid in one tap: the recipient opened it earlier (its deposit address exists since);
    // the payer's app reads it, then, two hours later, pays in and gives in one transaction. The
    // receipt says the recipient created it, and the deposit account's rent goes to the sponsor; it
    // says the money was there when the payment landed, not when the invoice was opened.
    let (invoice, _) = h.invoice(&h.terms(4)).expect("invoice");
    let opened = h.now();
    h.advance(2 * 3_600);
    let s4 = h.accounts(&invoice);
    let ixs = [spl_transfer_ix(h.payer_wallet, s4.vault, payer.pubkey(), AMOUNT), pay_ix(&s4, payer.pubkey())];
    let (_, _, ev) = h.measure("an invoice paid in one tap", &ixs, &[&payer]);
    let e = h.escrow(&invoice);
    assert_eq!((e.creator, e.outcome), (Side::Recipient, Some(Outcome::Pay)));
    assert_eq!((e.created_at, e.funded_at, e.ended_at), (opened, opened + 2 * 3_600, opened + 2 * 3_600), "funded when paid, not when opened");
    let Some(Event::Ended { funded_at, .. }) = ev.iter().find(|e| e.name() == "Ended") else { panic!() };
    assert_eq!(*funded_at, opened + 2 * 3_600);

    // The rents, measured: the same one tap with the Rent sysvar at today's rate and at the rate
    // the cuts end at. The sponsor fronts the receipt's rent and the deposit account's, and gets the
    // deposit account's back in the same transaction; the receipt keeps its own.
    for (id, rate) in [(10u64, RENT_TODAY), (11, RENT_FINAL)] {
        h.svm.set_sysvar(&rent_at(rate));
        let t = h.terms(id);
        let escrow = h.address(&t);
        let s = h.accounts(&escrow);
        let (before, payer_before) = (h.lamports(&h.sponsor.pubkey()), h.lamports(&payer.pubkey()));
        h.send(
            &[
                make_deposit(&h, &escrow),
                create_ix(&t, &h.create_accounts()),
                spl_transfer_ix(h.payer_wallet, s.vault, payer.pubkey(), AMOUNT),
                pay_ix(&s, payer.pubkey()),
            ],
            &[&payer],
        )
        .expect("one tap");
        let spent = before - 2 * 5_000 - h.lamports(&h.sponsor.pubkey());
        let deposit = (128 + 165) * rate;
        let kept = h.lamports(&escrow);
        assert_eq!(kept, (128 + ESCROW_LEN as u64) * rate, "{ESCROW_LEN} bytes and the 128-byte overhead, at {rate} a byte");
        assert_eq!(spent, kept, "the sponsor fronted both rents and got the deposit account's back");
        assert_eq!(h.lamports(&payer.pubkey()), payer_before, "none to the payer");
        let usd = kept as f64 / 1e9 * SOL_USD;
        println!("   at {rate:>5} lamports/byte: fronted {:>9}, {deposit:>9} back to the sponsor, the receipt keeps {kept:>9} (${usd:.4} at SOL ${SOL_USD})", kept + deposit);
    }
    print_cu_summary();
}

#[test]
fn a_second_payment_to_a_one_tap_link_goes_back_to_the_payer() {
    // The receipt is permanent, so a second transfer to the same link lands in a deposit account
    // the escrow will never pay out as part of the deal, and the address never reopens.
    // `recover_late` sends it back to the payer's standard account, and anyone may send it.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let t = h.terms(1);
    let escrow = h.address(&t);
    let s = h.accounts(&escrow);
    h.send(
        &[
            make_deposit(&h, &escrow),
            create_ix(&t, &h.create_accounts()),
            spl_transfer_ix(h.payer_wallet, s.vault, payer.pubkey(), AMOUNT),
            pay_ix(&s, payer.pubkey()),
        ],
        &[&payer],
    )
    .expect("one tap");
    let receipt = h.account(&escrow);
    // Someone pays the same link again: a wallet app makes the deposit account again (anyone may)
    // and sends.
    let (make, again) = create_ata_idempotent_ix(payer.pubkey(), escrow, h.mint);
    assert_eq!(again, s.vault);
    h.send(&[make, spl_transfer_ix(h.payer_wallet, s.vault, payer.pubkey(), AMOUNT)], &[&payer]).expect("a second payment");
    assert_eq!(h.balance(&s.vault), AMOUNT, "at a closed-over deposit address");
    let err = h.create(&t).expect_err("the payer cannot reopen the id");
    assert!(err.contains("already in use"), "{err}");
    let err = h.pay(&escrow).expect_err("the escrow has ended");
    assert!(err.contains("Ended"), "{err}");
    // A stranger sends it back. The payer's standard account does not exist yet; the stranger
    // makes it, and pays for it.
    let stranger = h.someone();
    let payer_tokens = h.payer_account();
    h.drop_payer_account();
    let meta = h.recover_late(&escrow, &stranger).expect("recover_late");
    assert_eq!(names(&events(&meta.logs)), ["RecoveredLate"]);
    assert_eq!(h.balance(&payer_tokens), AMOUNT, "the second payment is back with the payer");
    h.assert_closed(&s.vault, "the deposit account, again");
    assert_eq!(h.account(&escrow).data, receipt.data, "the receipt still says one payment");
    println!("a second payment to a one-tap link: sent back to the payer's standard account by a stranger; the receipt unchanged");
}

#[test]
fn a_marked_invoice_keeps_the_marks_time_as_its_funding_time() {
    // The invoice flow the slow way: the payer pays by a plain transfer, someone marks it an hour
    // later, and the payer pays a day after that. The receipt keeps the mark's time; the ending
    // never moves it.
    let mut h = Harness::new();
    let (invoice, _) = h.invoice(&h.terms(1)).expect("invoice");
    h.advance(600);
    h.fund(&invoice, AMOUNT);
    h.advance(3_600);
    h.mark_funded(&invoice).expect("mark");
    let marked = h.now();
    h.advance(DAY);
    let meta = h.pay(&invoice).expect("pay");
    let e = h.escrow(&invoice);
    assert_eq!((e.funded_at, e.ended_at), (marked, marked + DAY));
    let Some(Event::Ended { funded_at, .. }) = events(&meta.logs).into_iter().find(|e| e.name() == "Ended") else { panic!() };
    assert_eq!(funded_at, marked);
    println!("a marked invoice: the receipt keeps the mark's time as the funding time, the ending its own");
}
