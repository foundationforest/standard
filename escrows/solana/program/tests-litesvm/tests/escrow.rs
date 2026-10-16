//! The escrow, run under LiteSVM with the clock moved by hand.
//!
//! Every way out with exact balances, every rejection, and what each one costs. Run with
//! `cargo test -- --nocapture --test-threads=1` to see the numbers, the summary last. The schedule's
//! own rules, move by move and state by state, are in `schedule.rs`.

use forest_escrow_tests::*;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;

fn zero() -> Address {
    Address::default()
}

/// The deposit account closed, the escrow account still there as the receipt, saying how it
/// ended and what each party got.
fn assert_receipt(h: &Harness, escrow: &Address, outcome: Outcome, to_recipient: u64, to_payer: u64) {
    h.assert_closed(&vault_address(escrow, &h.mint), "the deposit account");
    let e = h.escrow(escrow);
    assert_eq!(e.status, Status::Ended, "the escrow account stays, ended");
    assert_eq!(e.outcome, Some(outcome));
    assert_eq!((e.to_recipient, e.to_payer), (to_recipient, to_payer));
    assert_ne!(e.ended_at, 0);
}

// ---------------------------------------------------------------------------------------------
// Creation and funding
// ---------------------------------------------------------------------------------------------

#[test]
fn create_writes_the_terms_and_makes_the_deposit_account() {
    let mut h = Harness::new();

    // Every option off: the default.
    let (plain, meta) = h.create(&h.terms(1)).expect("create");
    let e = h.escrow(&plain);
    assert_eq!((e.arbiter, e.schedule), (zero(), None), "no arbiter and no schedule unless the creator sets one");
    assert_eq!(e.creator, Side::Payer);
    assert_eq!(names(&events(&meta.logs)), ["Created"]);

    // Both options on: an arbiter and a schedule of three windows.
    let windows = [window(T0 + DAY, 10_000), window(T0 + 7 * DAY, 5_000), window(T0 + 14 * DAY, 0)];
    let mut t = h.scheduled(7, &windows, End::Pay);
    t.arbiter = Some(h.arbiter.pubkey());
    let (escrow, meta) = h.create(&t).expect("create");
    let e = h.escrow(&escrow);
    let schedule = Schedule { windows: windows.to_vec(), end: End::Pay };
    assert_eq!(
        e,
        EscrowView {
            version: VERSION,
            id: 7,
            payer: h.payer.pubkey(),
            recipient: h.recipient.pubkey(),
            arbiter: h.arbiter.pubkey(),
            mint: h.mint,
            vault: vault_address(&escrow, &h.mint),
            sponsor: h.sponsor.pubkey(),
            amount: AMOUNT,
            creator: Side::Payer,
            schedule: Some(schedule),
            created_at: T0,
            funded_at: 0,
            status: Status::Open,
            bump: e.bump,
            ended_at: 0,
            outcome: None,
            to_payer: 0,
            to_recipient: 0,
            stop: None,
            stopped_at: 0,
        }
    );
    assert_eq!(escrow, Address::create_program_address(&[b"escrow", &terms_hash(&t, &h.payer.pubkey(), &h.mint), &[e.bump]], &PROGRAM_ID).unwrap());

    // The deposit account: a classic token account for the mint, held by the escrow, empty.
    let vault = h.account(&e.vault);
    assert_eq!(vault.owner, TOKEN_PROGRAM);
    assert_eq!(&vault.data[..32], h.mint.as_ref());
    assert_eq!(&vault.data[32..64], escrow.as_ref());
    assert_eq!(token_amount(&vault.data), 0);

    let (window_count, stored, end) = stored_schedule(&t.schedule);
    assert_eq!(
        events(&meta.logs),
        [Event::Created {
            escrow,
            version: VERSION,
            id: 7,
            payer: h.payer.pubkey(),
            recipient: h.recipient.pubkey(),
            creator: Side::Payer,
            arbiter: h.arbiter.pubkey(),
            mint: h.mint,
            vault: e.vault,
            sponsor: h.sponsor.pubkey(),
            amount: AMOUNT,
            window_count,
            windows: stored,
            end,
            created_at: T0,
        }]
    );
    assert_eq!((window_count, stored[3]), (3, Window::default()), "three windows, then zeros");

    // The recipient opens one naming the payer: an invoice, at its terms' address, the recipient
    // its creator, the sponsor its rent's.
    let (invoice, meta) = h.invoice(&h.terms(8)).expect("invoice");
    assert_eq!(invoice, h.address(&h.terms(8)));
    let e = h.escrow(&invoice);
    assert_eq!((e.creator, e.payer, e.sponsor), (Side::Recipient, h.payer.pubkey(), h.sponsor.pubkey()));
    let Event::Created { creator, sponsor, .. } = &events(&meta.logs)[0] else { panic!() };
    assert_eq!((*creator, *sponsor), (Side::Recipient, h.sponsor.pubkey()));
    println!("created: every option off by default; an arbiter and three windows; an invoice at its terms' address");
}

#[test]
fn the_address_of_fixed_terms_is_the_clients() {
    // One set of fixed terms and the address they make, asserted here and in the client's tests
    // (`escrows/solana/client/test/client.test.ts`), so the two hand-written hashes cannot drift
    // apart. The program agrees with this harness in every test that opens an escrow.
    let key = |b: u8| Address::new_from_array([b; 32]);
    let schedule = Schedule { windows: vec![window(1_800_000_000, 10_000), window(1_800_604_800, 2_500)], end: End::Refund };
    let t = Terms { id: 7, recipient: key(2), amount: 1_000_000, arbiter: Some(key(4)), schedule: Some(schedule) };
    let hash: String = terms_hash(&t, &key(1), &key(3)).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hash, "a760919547aa835383ec68fb8e789c2466386d7fafd9849faaf5fdfa97eeec04");
    assert_eq!(escrow_address(&t, &key(1), &key(3)).to_string(), "BrkprqAdZVPaEd6ygGrGeHtcPbzsyKRz9UhvJtHnPdoV");
}

#[test]
fn money_arrives_by_plain_transfer_and_anyone_marks_it_funded() {
    let mut h = Harness::new();
    let (escrow, _) = h.create(&h.terms(1)).expect("create");
    let err = h.mark_funded(&escrow).expect_err("empty");
    assert!(err.contains("NotFunded"), "{err}");

    // Short by one base unit: not funded.
    h.fund(&escrow, AMOUNT - 1);
    let err = h.mark_funded(&escrow).expect_err("short");
    assert!(err.contains("NotFunded"), "{err}");
    assert_eq!(h.escrow(&escrow).status, Status::Open);

    // One more base unit, a day later. Nobody but the fee payer signs mark_funded.
    h.advance(DAY);
    h.fund(&escrow, 1);
    let meta = h.mark_funded(&escrow).expect("mark_funded");
    let e = h.escrow(&escrow);
    assert_eq!((e.status, e.funded_at), (Status::Funded, T0 + DAY));
    assert_eq!(events(&meta.logs), [Event::Funded { escrow, balance: AMOUNT, funded_at: T0 + DAY }]);

    // Marked once; a later mark cannot move the time.
    h.advance(DAY);
    let err = h.mark_funded(&escrow).expect_err("twice");
    assert!(err.contains("AlreadyFunded"), "{err}");
    assert_eq!(h.escrow(&escrow).funded_at, T0 + DAY);

    // Money that arrived before the escrow did: create adopts the account, and it counts.
    let escrow2 = h.address(&h.terms(2));
    let vault2 = vault_address(&escrow2, &h.mint);
    h.svm.set_account(vault2, spl_token_account(&h.mint, &escrow2, AMOUNT + 5)).unwrap();
    h.create(&h.terms(2)).expect("create over an existing deposit account");
    assert_eq!(h.escrow(&escrow2).status, Status::Open, "create never marks the funding");
    h.pay(&escrow2).expect("the money already there is the deal's");
    assert_eq!(h.balance(&h.recipient_tokens), AMOUNT + 5);
    println!("funded by plain transfers; marked once by anyone; a pre-funded deposit account is adopted and paid out");
}

// ---------------------------------------------------------------------------------------------
// The ways out, with exact balances
// ---------------------------------------------------------------------------------------------

#[test]
fn pay_the_payer_gives_the_whole_balance() {
    let mut h = Harness::new();
    let (escrow, _) = h.create(&h.terms(1)).expect("create");
    let vault = vault_address(&escrow, &h.mint);
    let (vault_rent, escrow_rent) = (h.lamports(&vault), h.lamports(&escrow));
    // Paid a quarter over the amount: every way out pays out the whole balance.
    h.fund(&escrow, AMOUNT + 250_000);
    // The payer is paid nothing, so its standard account is not named and need not exist.
    h.drop_payer_account();
    let sponsor_before = h.lamports(&h.sponsor.pubkey());
    let payer_sol = h.lamports(&h.payer.pubkey());
    let meta = h.pay(&escrow).expect("pay");

    assert_eq!(
        events(&meta.logs),
        [Event::Ended {
            escrow,
            outcome: Outcome::Pay,
            amount: AMOUNT,
            balance: AMOUNT + 250_000,
            to_payer: 0,
            to_recipient: AMOUNT + 250_000,
            ended_at: T0,
            sponsor: h.sponsor.pubkey(),
            rent_lamports: vault_rent,
            funded_at: T0,
        }]
    );
    assert_eq!(h.balance(&h.recipient_tokens), AMOUNT + 250_000);
    assert_eq!(h.balance(&h.payer_wallet), PAYER_START - AMOUNT - 250_000);
    assert!(!h.exists(&h.payer_account()));
    assert_receipt(&h, &escrow, Outcome::Pay, AMOUNT + 250_000, 0);
    assert_eq!(h.escrow(&escrow).funded_at, T0, "nobody marked it: the ending records its own time as the funding time");
    assert_eq!(h.lamports(&escrow), escrow_rent, "the receipt keeps its own rent");
    assert_eq!(h.lamports(&h.sponsor.pubkey()), sponsor_before - 2 * 5_000 + vault_rent, "the key that fronted the rent pays the fee and gets the deposit account's rent back");
    assert_eq!(h.lamports(&h.payer.pubkey()), payer_sol, "none to the creator");
    println!("pay: 1.25 to the recipient (the whole balance), {vault_rent} lamports of rent back to the sponsor");
}

#[test]
fn refund_the_recipient_gives_the_whole_balance_back() {
    let mut h = Harness::new();
    let escrow = h.marked(&h.terms(1));
    h.fund(&escrow, 7); // a little more after the mark: it goes back too
    let meta = h.refund(&escrow).expect("refund");
    let (outcome, balance, to_recipient, to_payer, _) = ended(&events(&meta.logs));
    assert_eq!((outcome, balance, to_recipient, to_payer), (Outcome::Refund, AMOUNT + 7, 0, AMOUNT + 7));
    assert_eq!(h.balance(&h.payer_account()), AMOUNT + 7, "at the payer's standard account");
    assert_eq!(h.payer_total(), PAYER_START, "every unit back");
    assert_eq!(h.balance(&h.recipient_tokens), 0);
    assert_receipt(&h, &escrow, Outcome::Refund, 0, AMOUNT + 7);
    assert_eq!(h.escrow(&escrow).funded_at, T0);
    println!("refund: everything back to the payer's standard account; the recipient names no account");
}

#[test]
fn agree_divides_the_whole_balance_both_signing() {
    let mut h = Harness::new();
    let balance = AMOUNT + 3; // odd, so the rounding shows
    let (mut recipient_total, mut payer_back) = (0u64, 0u64);
    for (id, bps) in [(1u64, 0u16), (2, 1), (3, 5_000), (4, 9_999), (5, 10_000)] {
        let (escrow, _) = h.create(&h.terms(id)).expect("create");
        h.fund(&escrow, balance);
        let meta = h.agree(&escrow, bps).expect("agree");
        let (outcome, got_balance, to_recipient, to_payer, _) = ended(&events(&meta.logs));
        assert_eq!((outcome, got_balance), (Outcome::Agree, balance));
        assert_eq!(to_payer, share(balance, bps), "{bps}: the payer's share rounds down");
        assert_eq!(to_recipient + to_payer, balance, "{bps}: every unit, once");
        recipient_total += to_recipient;
        payer_back += to_payer;
        assert_eq!(h.balance(&h.recipient_tokens), recipient_total, "{bps}");
        assert_eq!(h.balance(&h.payer_account()), payer_back, "{bps}");
        assert_receipt(&h, &escrow, Outcome::Agree, to_recipient, to_payer);
    }
    assert_eq!(share(balance, 5_000), 500_001, "half of 1,000,003 rounds down for the payer");
    assert_eq!(h.payer_total() + h.balance(&h.recipient_tokens), PAYER_START, "no unit created or lost");
    println!("agree at 0, 1, 5,000, 9,999 and 10,000 basis points to the payer of 1,000,003: exact, the payer's share rounded down");
}

#[test]
fn the_arbiter_decides_any_split() {
    let mut h = Harness::new();

    // A third key: the only kind of arbiter (`the_arbiter_cannot_be_the_payer_or_the_recipient`).
    let mut t = h.terms(1);
    t.arbiter = Some(h.arbiter.pubkey());
    let escrow = h.funded(&t);
    let meta = h.decide(&escrow, 2_500).expect("decide");
    let (outcome, _, to_recipient, to_payer, _) = ended(&events(&meta.logs));
    assert_eq!((outcome, to_recipient, to_payer), (Outcome::Decide, 750_000, 250_000));
    assert_receipt(&h, &escrow, Outcome::Decide, 750_000, 250_000);

    // An arbiter adds a way out; it takes none away.
    let mut t = h.terms(4);
    t.arbiter = Some(h.arbiter.pubkey());
    let escrow = h.funded(&t);
    h.pay(&escrow).expect("the payer can still give");
    assert_eq!(h.balance(&h.recipient_tokens), 750_000 + AMOUNT);
    println!("decide: a third key decided a split; the parties' own ways out still work");
}

#[test]
fn take_back_pays_the_payer_its_windows_share_and_the_rest_to_the_recipient() {
    let mut h = Harness::new();
    let windows = [window(T0 + DAY, 10_000), window(T0 + 2 * DAY, 5_000), window(T0 + 3 * DAY, 0)];
    let balance = AMOUNT + 3;
    for (id, at, payer_share) in [(1u64, T0, 10_000u16), (2, T0 + DAY, 5_000), (3, T0 + 2 * DAY - 1, 5_000)] {
        h.set_time(T0);
        let (escrow, _) = h.create(&h.scheduled(id, &windows, End::Pay)).expect("create");
        h.fund(&escrow, balance);
        h.set_time(at);
        let (recipient_before, payer_before) = (h.balance(&h.recipient_tokens), h.balance(&h.payer_account()));
        let meta = h.take_back(&escrow).expect("take_back");
        let (outcome, got, to_recipient, to_payer, _) = ended(&events(&meta.logs));
        assert_eq!((outcome, got), (Outcome::TakeBack, balance));
        assert_eq!(to_payer, share(balance, payer_share), "{payer_share}: the payer's share, rounded down");
        assert_eq!(to_recipient, balance - to_payer, "{payer_share}: the rest to the recipient");
        assert_eq!(h.balance(&h.payer_account()), payer_before + to_payer);
        assert_eq!(h.balance(&h.recipient_tokens), recipient_before + to_recipient);
        assert_receipt(&h, &escrow, Outcome::TakeBack, to_recipient, to_payer);
    }

    // In the last window the share is 0: nothing to take back; giving it all is pay.
    h.set_time(T0);
    let escrow = h.funded(&h.scheduled(4, &windows, End::Pay));
    h.set_time(T0 + 2 * DAY);
    let err = h.take_back(&escrow).expect_err("a share of 0");
    assert!(err.contains("BadShare"), "{err}");
    // From the end time on, no window is in force.
    h.set_time(T0 + 3 * DAY);
    let err = h.take_back(&escrow).expect_err("past the end");
    assert!(err.contains("ScheduleOver"), "{err}");
    // No schedule, no take-back.
    let escrow = h.funded(&h.terms(5));
    let err = h.take_back(&escrow).expect_err("no schedule");
    assert!(err.contains("NoSchedule"), "{err}");
    println!("take_back: all of it in the first window, half in the second to its last second, refused at 0, after the end and with no schedule");
}

#[test]
fn end_pays_the_default_from_the_end_time_and_anyone_sends_it() {
    let mut h = Harness::new();
    for (id, end, to) in [(1u64, End::Pay, Side::Recipient), (2, End::Refund, Side::Payer)] {
        h.set_time(T0);
        let t = h.scheduled(id, &[window(T0 + 3 * DAY, 0)], end);
        let escrow = h.funded(&t);
        // Only a marked escrow: money nobody said was there before the end time never counts.
        h.set_time(T0 + 3 * DAY);
        let err = h.end(&escrow, to).expect_err("not marked");
        assert!(err.contains("FundingNotMarked"), "{err}");
        h.set_time(T0 + 3_600);
        h.mark_funded(&escrow).expect("mark");
        let end_time = T0 + 3 * DAY;
        h.set_time(end_time - 1);
        let err = h.end(&escrow, to).expect_err("a second early");
        assert!(err.contains("ScheduleNotOver"), "{err}");
        h.set_time(end_time);
        let recipient_before = h.balance(&h.recipient_tokens);
        let payer_before = h.balance(&h.payer_account());
        // Nobody signs but the fee payer: anyone may send it.
        let meta = h.end(&escrow, to).expect("from the end time, to the second");
        let (outcome, balance, to_recipient, to_payer, _) = ended(&events(&meta.logs));
        assert_eq!((outcome, balance), (Outcome::End, AMOUNT));
        match to {
            Side::Recipient => {
                assert_eq!((to_recipient, to_payer), (AMOUNT, 0));
                assert_eq!(h.balance(&h.recipient_tokens), recipient_before + AMOUNT);
            }
            Side::Payer => {
                assert_eq!((to_recipient, to_payer), (0, AMOUNT));
                assert_eq!(h.balance(&h.payer_account()), payer_before + AMOUNT);
            }
        }
        assert_receipt(&h, &escrow, Outcome::End, to_recipient, to_payer);
        let e = h.escrow(&escrow);
        assert_eq!((e.ended_at, e.funded_at), (end_time, T0 + 3_600));
    }

    // The parties can end it any time before the end time; the schedule takes no way out away.
    h.set_time(T0);
    let escrow = h.marked(&h.scheduled(3, &[window(T0 + 3 * DAY, 0)], End::Pay));
    h.advance(DAY);
    h.refund(&escrow).expect("the recipient gives back on day one");
    h.advance(3 * DAY);
    let err = h.end(&escrow, Side::Recipient).expect_err("ended");
    assert!(err.contains("AccountNotInitialized") || err.contains("Ended"), "{err}");

    // The latest end time there is: no overflow, and it never comes.
    let escrow = h.marked(&h.scheduled(4, &[window(i64::MAX, 0)], End::Refund));
    h.set_time(i64::MAX - 1);
    let err = h.end(&escrow, Side::Payer).expect_err("a second before the end of time");
    assert!(err.contains("ScheduleNotOver"), "{err}");
    println!("end: refused unmarked and a second early, runs from the end time to the recipient and to the payer; the parties still end it first");
}

#[test]
fn a_never_funded_escrow_is_closed_by_either_party_at_any_time() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();
    let sponsor = h.sponsor.insecure_clone();

    // Nobody paid. The payer, its creator, closes it at once; both rents go to the key that
    // fronted them, not to the payer, and the payer's standard account is not needed: nothing
    // goes to it.
    let (escrow, _) = h.create(&h.terms(1)).expect("create");
    let vault = vault_address(&escrow, &h.mint);
    let (vault_rent, escrow_rent) = (h.lamports(&vault), h.lamports(&escrow));
    h.drop_payer_account();
    let err = h.close_unfunded(&escrow, &sponsor).expect_err("the key that fronted the rent is not a party");
    assert!(err.contains("NotAParty"), "{err}");
    let (sponsor_before, payer_before) = (h.lamports(&sponsor.pubkey()), h.lamports(&payer.pubkey()));
    let meta = h.close_unfunded(&escrow, &payer).expect("the payer closes");
    assert_eq!(
        events(&meta.logs),
        [Event::Closed { escrow, closed_by: payer.pubkey(), to_payer: 0, sponsor: sponsor.pubkey(), rent_lamports: vault_rent + escrow_rent }]
    );
    h.assert_closed(&escrow, "the escrow account");
    h.assert_closed(&vault, "the deposit account");
    assert_eq!(h.lamports(&payer.pubkey()), payer_before, "none to the creator");
    assert_eq!(h.lamports(&sponsor.pubkey()), sponsor_before - 2 * 5_000 + vault_rent + escrow_rent, "both rents to the key that fronted them, which paid the fee");
    assert!(!h.exists(&h.payer_account()), "nobody had to make the payer an account");

    // The address is free again: nothing was dealt there.
    h.create(&h.terms(1)).expect("the same terms, again");

    // Part paid, closed by the recipient: the part goes back to the payer's standard account,
    // which has to exist when it is paid (whoever closes makes it first); the rents to the
    // sponsor.
    let (make, payer_tokens) = create_ata_idempotent_ix(recipient.pubkey(), payer.pubkey(), h.mint);
    h.send(&[make], &[&recipient]).expect("the payer's standard account");
    h.fund(&escrow, 400_000);
    let sponsor_before = h.lamports(&sponsor.pubkey());
    let rents = h.lamports(&escrow) + h.lamports(&vault);
    h.close_unfunded(&escrow, &recipient).expect("the recipient closes");
    assert_eq!(h.balance(&payer_tokens), 400_000);
    assert_eq!(h.lamports(&sponsor.pubkey()), sponsor_before - 2 * 5_000 + rents, "the rents to the sponsor, whoever closes");
    h.assert_closed(&escrow, "the escrow account");

    // An invoice, part paid, closed by the payer: the part to the payer, the rents to the sponsor,
    // none to the recipient who opened it.
    let (invoice, _) = h.invoice(&h.terms(3)).expect("invoice");
    h.fund(&invoice, AMOUNT - 1);
    let (sponsor_before, recipient_before) = (h.lamports(&sponsor.pubkey()), h.lamports(&recipient.pubkey()));
    let rents = h.lamports(&invoice) + h.lamports(&vault_address(&invoice, &h.mint));
    h.close_unfunded(&invoice, &payer).expect("the payer closes");
    assert_eq!(h.balance(&payer_tokens), 400_000 + AMOUNT - 1);
    assert_eq!(h.payer_total(), PAYER_START);
    assert_eq!(h.lamports(&sponsor.pubkey()), sponsor_before - 2 * 5_000 + rents, "the invoice's rents to the sponsor");
    assert_eq!(h.lamports(&recipient.pubkey()), recipient_before, "none to the recipient, its creator");

    // Funded, marked or not, with no schedule: it ends by a way out, not by closing.
    let funded = h.funded(&h.terms(4));
    h.advance(10_000 * DAY);
    let err = h.close_unfunded(&funded, &payer).expect_err("funded");
    assert!(err.contains("StillFunded"), "{err}");
    h.mark_funded(&funded).expect("mark");
    let err = h.close_unfunded(&funded, &recipient).expect_err("marked");
    assert!(err.contains("StillFunded"), "{err}");
    println!("close_unfunded: by the payer with no payer account needed, by the recipient with part paid, an invoice by the payer; both rents to the sponsor every time");
}

#[test]
fn the_escrow_address_is_its_terms_and_only_a_party_opens_it() {
    // The address is ["escrow", SHA-256 of every term]. Who opens it is not a term: the payer and
    // the recipient land at the same address with the same terms, and whoever is second finds it
    // taken. A stranger cannot open it: with the same terms it is not a party, and naming itself
    // a party changes the terms, and so the address.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let stranger = h.someone();
    let t = h.terms(1);
    let target = h.address(&t);
    let a = CreateAccounts { sponsor: stranger.pubkey(), ..h.create_accounts() };

    let err = h.send(&[create_ix_by(&t, &a, stranger.pubkey())], &[&stranger]).expect_err("a stranger, the same terms");
    assert!(err.contains("NotAParty"), "{err}");
    let err = h.send(&[unsigned(create_ix(&t, &a), &payer.pubkey())], &[&stranger]).expect_err("the payer's key, unsigned");
    assert!(err.contains("AccountNotSigner"), "{err}");
    let squat = Terms { recipient: stranger.pubkey(), ..t.clone() };
    h.send(&[create_ix_by(&squat, &a, stranger.pubkey())], &[&stranger]).expect("the stranger's own terms");
    assert_ne!(h.address(&squat), target, "its own terms, its own address");
    let mut ix = create_ix_by(&Terms { recipient: stranger.pubkey(), ..h.terms(2) }, &a, stranger.pubkey());
    ix.accounts[0].pubkey = target;
    ix.accounts[1].pubkey = vault_address(&target, &h.mint);
    let err = h.send(&[ix], &[&stranger]).expect_err("the stranger's terms aimed at the payer's address");
    assert!(err.contains("ConstraintSeeds"), "{err}");
    assert!(!h.exists(&target));

    // Either party opens the same terms at the same address; the second finds it taken.
    let (opened, _) = h.create(&t).expect("the payer opens");
    assert_eq!(opened, target);
    let err = h.invoice(&t).expect_err("the recipient, the same terms");
    assert!(err.contains("already in use"), "{err}");
    let (invoiced, _) = h.invoice(&h.terms(3)).expect("the recipient opens other terms");
    let err = h.create(&h.terms(3)).expect_err("the payer, the invoice's terms");
    assert!(err.contains("already in use"), "{err}");
    assert_eq!((h.escrow(&target).creator, h.escrow(&invoiced).creator), (Side::Payer, Side::Recipient));
    println!("the address is the terms': a stranger cannot open it, and either party lands at the same one");
}

#[test]
fn every_term_is_in_the_address() {
    // Change any one term and the address changes: `create` aimed at the first terms' address
    // with any one of them different is refused by its seeds. So a payment to an address counts
    // only toward a deal with exactly its terms. The creator and the sponsor are not terms.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();
    let other_payer = h.someone();
    let other_mint = Address::new_unique();
    h.svm.set_account(other_mint, spl_mint_account(6, TOKEN_PROGRAM)).unwrap();
    let windows = [window(T0 + DAY, 10_000), window(T0 + 7 * DAY, 0)];
    let t = Terms { arbiter: Some(h.arbiter.pubkey()), ..h.scheduled(1, &windows, End::Pay) };
    let target = h.address(&t);
    let with = |w: &[Window], end| Some(Schedule { windows: w.to_vec(), end });
    let variants: Vec<(&str, Terms, &Keypair, Address)> = vec![
        ("the id", Terms { id: 2, ..t.clone() }, &payer, h.mint),
        ("the payer", t.clone(), &other_payer, h.mint),
        ("the recipient", Terms { recipient: Address::new_unique(), ..t.clone() }, &payer, h.mint),
        ("the amount", Terms { amount: AMOUNT + 1, ..t.clone() }, &payer, h.mint),
        ("the mint", t.clone(), &payer, other_mint),
        ("the arbiter", Terms { arbiter: Some(Address::new_unique()), ..t.clone() }, &payer, h.mint),
        ("no arbiter", Terms { arbiter: None, ..t.clone() }, &payer, h.mint),
        ("a window's until", Terms { schedule: with(&[window(T0 + DAY + 1, 10_000), windows[1]], End::Pay), ..t.clone() }, &payer, h.mint),
        ("a window's share", Terms { schedule: with(&[window(T0 + DAY, 9_999), windows[1]], End::Pay), ..t.clone() }, &payer, h.mint),
        ("one window fewer", Terms { schedule: with(&windows[1..], End::Pay), ..t.clone() }, &payer, h.mint),
        ("one window more", Terms { schedule: with(&[windows[0], windows[1], window(T0 + 8 * DAY, 0)], End::Pay), ..t.clone() }, &payer, h.mint),
        ("the default", Terms { schedule: with(&windows, End::Refund), ..t.clone() }, &payer, h.mint),
        ("no schedule", Terms { schedule: None, ..t.clone() }, &payer, h.mint),
    ];
    let count = variants.len();
    for (what, terms, creator, mint) in variants {
        let a = CreateAccounts { payer: creator.pubkey(), sponsor: h.sponsor.pubkey(), mint };
        assert_ne!(escrow_address(&terms, &a.payer, &mint), target, "{what}");
        let mut ix = create_ix_by(&terms, &a, creator.pubkey());
        ix.accounts[0].pubkey = target;
        ix.accounts[1].pubkey = vault_address(&target, &mint);
        let err = h.send(&[ix], &[creator]).err().unwrap_or_else(|| panic!("{what}: must be refused"));
        assert!(err.contains("ConstraintSeeds"), "{what}: {err}");
    }
    assert!(!h.exists(&target));

    // The recipient as creator, and another sponsor: the same terms, the same address.
    let sponsor = h.someone();
    let a = CreateAccounts { sponsor: sponsor.pubkey(), ..h.create_accounts() };
    h.send(&[create_ix_by(&t, &a, recipient.pubkey())], &[&recipient, &sponsor]).expect("the recipient, another sponsor");
    assert_eq!(h.escrow(&target).arbiter, h.arbiter.pubkey());
    println!("rejected as expected: each of {count} one-term changes lands elsewhere; the creator and the sponsor do not move the address");
}

#[test]
fn every_rent_goes_back_to_the_sponsor() {
    // Whoever fronts the rent gets it back: here a sponsor that is neither party and not the
    // transaction's fee payer, as a fee payer service fronts it. None goes to the creator.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();
    let sponsor = h.someone();
    let a = CreateAccounts { sponsor: sponsor.pubkey(), ..h.create_accounts() };

    // Closed unpaid: both rents to the sponsor, none to the payer who opened it or the recipient
    // who closed it.
    h.send(&[create_ix(&h.terms(1), &a)], &[&payer, &sponsor]).expect("create, the sponsor paying");
    let escrow = h.address(&h.terms(1));
    let rents = h.lamports(&escrow) + h.lamports(&vault_address(&escrow, &h.mint));
    let before = (h.lamports(&sponsor.pubkey()), h.lamports(&payer.pubkey()), h.lamports(&recipient.pubkey()));
    let meta = h.close_unfunded(&escrow, &recipient).expect("closed unpaid");
    let Some(Event::Closed { sponsor: to, .. }) = events(&meta.logs).pop() else { panic!("no Closed") };
    assert_eq!(to, sponsor.pubkey());
    assert_eq!(
        (h.lamports(&sponsor.pubkey()), h.lamports(&payer.pubkey()), h.lamports(&recipient.pubkey())),
        (before.0 + rents, before.1, before.2),
        "both rents to the sponsor, none to the creator or the closer"
    );

    // An invoice, ended: the deposit account's rent to the sponsor, none to the recipient who
    // opened it.
    h.send(&[invoice_ix(&h.terms(2), &a)], &[&recipient, &sponsor]).expect("invoice, the sponsor paying");
    let invoice = h.address(&h.terms(2));
    assert_eq!(h.escrow(&invoice).sponsor, sponsor.pubkey());
    h.fund(&invoice, AMOUNT);
    // The rent goes only to the key recorded: the creator in its place is refused.
    let wrong = Accounts { sponsor: recipient.pubkey(), ..h.accounts(&invoice) };
    let err = h.send(&[pay_ix(&wrong, payer.pubkey())], &[&payer]).expect_err("the creator as the sponsor");
    assert!(err.contains("ConstraintHasOne"), "{err}");
    let vault_rent = h.lamports(&vault_address(&invoice, &h.mint));
    let before = (h.lamports(&sponsor.pubkey()), h.lamports(&recipient.pubkey()));
    h.pay(&invoice).expect("the payer pays");
    assert_eq!(
        (h.lamports(&sponsor.pubkey()), h.lamports(&recipient.pubkey())),
        (before.0 + vault_rent, before.1),
        "the deposit account's rent to the sponsor, none to the creator"
    );

    // A party that fronts its own rent gets it back the same way: the recipient invoices and pays.
    let own = CreateAccounts { sponsor: recipient.pubkey(), ..h.create_accounts() };
    h.send(&[invoice_ix(&h.terms(3), &own)], &[&recipient]).expect("the recipient pays its own invoice's rent");
    assert_eq!(h.escrow(&h.address(&h.terms(3))).sponsor, recipient.pubkey());
    println!("rent: every rent back to whoever fronted it, at a close and at an ending, never to the creator");
}

// ---------------------------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------------------------

/// The same instruction with `who` marked as not signing, the way a stranger would have to send
/// it: Anchor's `Signer` check refuses before the handler runs.
fn unsigned(mut ix: Instruction, who: &Address) -> Instruction {
    for m in ix.accounts.iter_mut() {
        if m.pubkey == *who {
            m.is_signer = false;
        }
    }
    ix
}

#[test]
fn the_wrong_signer_is_refused_for_every_instruction() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();
    let arbiter = h.arbiter.insecure_clone();
    let stranger = h.someone();

    // create: the payer or the recipient must sign. A stranger cannot open an escrow in either's
    // name.
    let t = h.terms(1);
    let a = h.create_accounts();
    let err = h.send(&[unsigned(create_ix(&t, &a), &payer.pubkey())], &[]).expect_err("create unsigned");
    assert!(err.contains("AccountNotSigner"), "{err}");
    for (who, key) in [("a stranger", &stranger), ("the arbiter", &arbiter)] {
        let err = h.send(&[create_ix_by(&t, &a, key.pubkey())], &[key]).expect_err("create");
        assert!(err.contains("NotAParty"), "create by {who}: {err}");
    }

    let mut t = h.scheduled(1, &[window(T0 + DAY, 5_000)], End::Pay);
    t.arbiter = Some(arbiter.pubkey());
    let escrow = h.funded(&t);
    let s = h.accounts(&escrow);
    let p = payer.pubkey();
    let r = recipient.pubkey();
    let cases: Vec<(&str, Instruction, Vec<&Keypair>, &str)> = vec![
        ("pay by the recipient", pay_ix(&s, r), vec![&recipient], "NotThePayer"),
        ("pay by the arbiter", pay_ix(&s, arbiter.pubkey()), vec![&arbiter], "NotThePayer"),
        ("pay by a stranger", pay_ix(&s, stranger.pubkey()), vec![&stranger], "NotThePayer"),
        ("pay, the payer not signing", unsigned(pay_ix(&s, p), &p), vec![], "AccountNotSigner"),
        ("refund by the payer", refund_ix(&s, p), vec![&payer], "NotTheRecipient"),
        ("refund by the arbiter", refund_ix(&s, arbiter.pubkey()), vec![&arbiter], "NotTheRecipient"),
        ("refund by a stranger", refund_ix(&s, stranger.pubkey()), vec![&stranger], "NotTheRecipient"),
        ("refund, the recipient not signing", unsigned(refund_ix(&s, r), &r), vec![], "AccountNotSigner"),
        ("take_back by the recipient", take_back_ix(&s, r), vec![&recipient], "NotThePayer"),
        ("take_back by the arbiter", take_back_ix(&s, arbiter.pubkey()), vec![&arbiter], "NotThePayer"),
        ("take_back by a stranger", take_back_ix(&s, stranger.pubkey()), vec![&stranger], "NotThePayer"),
        ("take_back, the payer not signing", unsigned(take_back_ix(&s, p), &p), vec![], "AccountNotSigner"),
        ("agree with only the payer signing", unsigned(agree_ix(&s, p, r, 5_000), &r), vec![&payer], "AccountNotSigner"),
        ("agree with only the recipient signing", unsigned(agree_ix(&s, p, r, 5_000), &p), vec![&recipient], "AccountNotSigner"),
        ("agree, the parties swapped", agree_ix(&s, r, p, 5_000), vec![&payer, &recipient], "NotThePayer"),
        ("agree, the arbiter as the recipient", agree_ix(&s, p, arbiter.pubkey(), 5_000), vec![&payer, &arbiter], "NotTheRecipient"),
        ("agree, a stranger as the payer", agree_ix(&s, stranger.pubkey(), r, 5_000), vec![&stranger, &recipient], "NotThePayer"),
        ("decide by the payer", decide_ix(&s, p, 10_000), vec![&payer], "NotTheArbiter"),
        ("decide by the recipient", decide_ix(&s, r, 0), vec![&recipient], "NotTheArbiter"),
        ("decide by a stranger", decide_ix(&s, stranger.pubkey(), 5_000), vec![&stranger], "NotTheArbiter"),
        ("decide, the arbiter not signing", unsigned(decide_ix(&s, arbiter.pubkey(), 5_000), &arbiter.pubkey()), vec![], "AccountNotSigner"),
        ("close_unfunded by a stranger", close_unfunded_ix(&s, stranger.pubkey()), vec![&stranger], "NotAParty"),
        ("close_unfunded by the arbiter", close_unfunded_ix(&s, arbiter.pubkey()), vec![&arbiter], "NotAParty"),
        ("recover_late by a stranger, live", recover_late_ix(escrow, s.vault, p, h.mint, stranger.pubkey()), vec![&stranger], "NotEnded"),
        ("sweep_rent to a stranger", sweep_rent_ix(escrow, stranger.pubkey()), vec![], "ConstraintHasOne"),
        ("sweep_rent to the creator", sweep_rent_ix(escrow, p), vec![], "ConstraintHasOne"),
        ("stop by a stranger", stop_ix(escrow, stranger.pubkey()), vec![&stranger], "NotAParty"),
        ("stop by the arbiter", stop_ix(escrow, arbiter.pubkey()), vec![&arbiter], "NotAParty"),
        ("stop by the sponsor", stop_ix(escrow, h.sponsor.pubkey()), vec![], "NotAParty"),
        ("stop, the payer not signing", unsigned(stop_ix(escrow, p), &p), vec![], "AccountNotSigner"),
    ];
    for (what, ix, signers, want) in cases {
        let err = h.send(&[ix], &signers).err().unwrap_or_else(|| panic!("{what}: must be refused"));
        assert!(err.contains(want), "{what}: expected {want}, got\n{err}");
    }

    // Payouts go only to the recorded parties' standard accounts, rent only to the sponsor.
    let strangers_tokens = Address::new_unique();
    h.svm.set_account(strangers_tokens, spl_token_account(&h.mint, &stranger.pubkey(), 0)).unwrap();
    let bad = Accounts { recipient_tokens: strangers_tokens, ..s };
    let err = h.send(&[pay_ix(&bad, p)], &[&payer]).expect_err("a stranger's account as the recipient's");
    assert!(err.contains("NotTheRecipientsAccount"), "{err}");
    let bad = Accounts { sponsor: stranger.pubkey(), ..s };
    let err = h.send(&[pay_ix(&bad, p)], &[&payer]).expect_err("a stranger as the sponsor");
    assert!(err.contains("ConstraintHasOne"), "{err}");

    assert_eq!(h.vault_balance(&escrow), AMOUNT, "nothing above moved anything");
    let e = h.escrow(&escrow);
    assert_eq!((e.status, e.stop), (Status::Open, None));
    println!("every instruction refused its wrong signer; payouts and rent cannot be redirected");
}

#[test]
fn decide_needs_an_arbiter_named_at_creation() {
    let mut h = Harness::new();
    let arbiter = h.arbiter.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    let s = h.accounts(&escrow);
    for (who, key) in [("a would-be arbiter", arbiter.insecure_clone()), ("the payer", h.payer.insecure_clone()), ("the recipient", h.recipient.insecure_clone())] {
        let err = h.send(&[decide_ix(&s, key.pubkey(), 5_000)], &[&key]).expect_err("no arbiter");
        assert!(err.contains("NoArbiter"), "{who}: {err}");
    }
    assert_eq!(h.escrow(&escrow).arbiter, zero());
    println!("no arbiter named: decide refused, whoever signs");
}

#[test]
fn end_needs_a_schedule_a_mark_before_the_end_time_and_the_end_time() {
    let mut h = Harness::new();
    // No schedule, however long after the mark.
    let escrow = h.marked(&h.terms(1));
    h.advance(10_000 * DAY);
    for to in [Side::Recipient, Side::Payer] {
        let err = h.end(&escrow, to).expect_err("no schedule");
        assert!(err.contains("NoSchedule"), "{err}");
    }

    // A schedule, the money there, never marked: it never runs, however long.
    h.set_time(T0);
    let t = h.scheduled(2, &[window(T0 + DAY, 0)], End::Pay);
    let escrow = h.funded(&t);
    h.advance(1_000 * DAY);
    let err = h.end(&escrow, Side::Recipient).expect_err("never marked");
    assert!(err.contains("FundingNotMarked"), "{err}");

    // Marked and ended in one breath never pays: before the end time `end` is early, and from it
    // on the mark is late.
    let vault = vault_address(&escrow, &h.mint);
    let both = [mark_funded_ix(escrow, vault), end_ix(escrow, vault, h.mint, h.recipient_tokens, h.sponsor.pubkey())];
    let err = h.send(&both, &[]).expect_err("mark and end together, after the end time");
    assert!(err.contains("ScheduleOver"), "{err}");
    let escrow = h.funded(&h.scheduled(3, &[window(h.now() + DAY, 0)], End::Pay));
    let vault = vault_address(&escrow, &h.mint);
    let both = [mark_funded_ix(escrow, vault), end_ix(escrow, vault, h.mint, h.recipient_tokens, h.sponsor.pubkey())];
    let err = h.send(&both, &[]).expect_err("mark and end together, before the end time");
    assert!(err.contains("ScheduleNotOver"), "{err}");
    assert_eq!(h.escrow(&escrow).status, Status::Open, "the failed transactions marked nothing");

    // A schedule and no money: nothing to mark, nothing to end.
    let (empty, _) = h.create(&h.scheduled(4, &[window(h.now() + DAY, 0)], End::Refund)).expect("create");
    let err = h.mark_funded(&empty).expect_err("empty");
    assert!(err.contains("NotFunded"), "{err}");
    println!("end: refused with no schedule, with the funding never marked, and marked in the same transaction on either side of the end time");
}

#[test]
fn nothing_moves_before_the_deposit_account_holds_the_amount() {
    let mut h = Harness::new();
    let mut t = h.scheduled(1, &[window(T0 + DAY, 5_000)], End::Pay);
    t.arbiter = Some(h.arbiter.pubkey());
    let (escrow, _) = h.create(&t).expect("create");
    h.fund(&escrow, AMOUNT - 1);
    for (what, result) in [
        ("pay", h.pay(&escrow)),
        ("refund", h.refund(&escrow)),
        ("take_back", h.take_back(&escrow)),
        ("agree", h.agree(&escrow, 5_000)),
        ("decide", h.decide(&escrow, 5_000)),
        ("mark_funded", h.mark_funded(&escrow)),
    ] {
        let err = result.err().unwrap_or_else(|| panic!("{what}: must be refused"));
        assert!(err.contains("NotFunded"), "{what}: {err}");
    }
    assert_eq!(h.vault_balance(&escrow), AMOUNT - 1);
    println!("one unit short: no way out runs and nothing is marked; only close_unfunded runs");
}

#[test]
fn a_payout_lands_only_at_the_receiving_partys_standard_account() {
    // Every payout to the payer lands at the payer's standard token account for the mint, and
    // every payout to the recipient at the recipient's, on every way out, the default included.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();
    let arbiter = h.arbiter.insecure_clone();
    let p = payer.pubkey();
    let r = recipient.pubkey();
    let ar = arbiter.pubkey();

    // (move, the side whose account is swapped, the default)
    let cases = [
        ("refund", Side::Payer, End::Refund),
        ("take_back", Side::Payer, End::Refund),
        ("agree", Side::Payer, End::Refund),
        ("decide", Side::Payer, End::Refund),
        ("end", Side::Payer, End::Refund),
        ("close_unfunded", Side::Payer, End::Refund),
        ("pay", Side::Recipient, End::Pay),
        ("take_back", Side::Recipient, End::Pay),
        ("agree", Side::Recipient, End::Pay),
        ("decide", Side::Recipient, End::Pay),
        ("end", Side::Recipient, End::Pay),
    ];
    let count = cases.len();
    // A dollar for each case and one more: the payer's ten would not go round.
    h.svm.set_account(h.payer_wallet, spl_token_account(&h.mint, &p, (count as u64 + 1) * AMOUNT)).unwrap();
    for (id, (name, side, end)) in cases.into_iter().enumerate() {
        h.set_time(T0);
        let t = Terms { arbiter: Some(ar), ..h.scheduled(id as u64, &[window(T0 + DAY, 5_000)], end) };
        let (escrow, _) = h.create(&t).expect("create");
        h.fund(&escrow, if name == "close_unfunded" { AMOUNT / 2 } else { AMOUNT });
        if name == "end" {
            h.mark_funded(&escrow).expect("mark");
            h.advance(DAY);
        }
        let right = h.accounts(&escrow);
        // The account the party holds but that is not its standard one.
        let (wrong, other, standard, want) = match side {
            Side::Payer => (Accounts { payer_tokens: h.payer_wallet, ..right }, h.payer_wallet, h.payer_account(), "NotThePayersAccount"),
            Side::Recipient => (Accounts { recipient_tokens: h.recipient_other, ..right }, h.recipient_other, h.recipient_tokens, "NotTheRecipientsAccount"),
        };
        let ix = |s: &Accounts| match name {
            "refund" => refund_ix(s, r),
            "pay" => pay_ix(s, p),
            "take_back" => take_back_ix(s, p),
            "agree" => agree_ix(s, p, r, 5_000),
            "decide" => decide_ix(s, ar, 5_000),
            "end" => end_ix(s.escrow, s.vault, s.mint, if end == End::Refund { s.payer_tokens } else { s.recipient_tokens }, s.sponsor),
            _ => close_unfunded_ix(s, r),
        };
        let signers: Vec<&Keypair> = match name {
            "refund" | "close_unfunded" => vec![&recipient],
            "pay" | "take_back" => vec![&payer],
            "agree" => vec![&payer, &recipient],
            "decide" => vec![&arbiter],
            _ => vec![],
        };
        let other_before = h.balance(&other);
        let err = h.send(&[ix(&wrong)], &signers).err().unwrap_or_else(|| panic!("{name}: paid the {side:?} elsewhere"));
        assert!(err.contains(want), "{name}, {side:?}: expected {want}, got\n{err}");
        assert_eq!(h.balance(&other), other_before, "{name}: nothing moved");
        let standard_before = h.balance(&standard);
        h.send(&[ix(&right)], &signers).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(h.balance(&standard) > standard_before, "{name}: paid at the {side:?}'s standard account");
    }

    // A default that pays the recipient refuses every other account: the payer's, a stranger's,
    // the recipient's for another mint, the deposit account itself, the recipient's address.
    h.set_time(T0);
    let escrow = h.marked(&h.scheduled(20, &[window(T0 + DAY, 0)], End::Pay));
    h.advance(DAY);
    let vault = vault_address(&escrow, &h.mint);
    let strangers = Address::new_unique();
    h.svm.set_account(strangers, spl_token_account(&h.mint, &Address::new_unique(), 0)).unwrap();
    let other_mint = Address::new_unique();
    h.svm.set_account(other_mint, spl_mint_account(6, TOKEN_PROGRAM)).unwrap();
    let recipients_other_mint = ata_address(&r, &other_mint);
    h.svm.set_account(recipients_other_mint, spl_token_account(&other_mint, &r, 0)).unwrap();
    for (what, to) in [
        ("the payer's standard account", h.payer_account()),
        ("a stranger's account", strangers),
        ("another account the recipient holds", h.recipient_other),
        ("the recipient's standard account for another mint", recipients_other_mint),
        ("the deposit account itself", vault),
        ("the recipient's address, not a token account", r),
    ] {
        let err = h.send(&[end_ix(escrow, vault, h.mint, to, h.sponsor.pubkey())], &[]).expect_err(what);
        assert!(err.contains("NotTheRecipientsAccount"), "{what}: {err}");
    }
    h.end(&escrow, Side::Recipient).expect("to the recipient's standard account");
    println!("{count} ways of paying a party refused any account but its standard one; the default to the recipient refused six wrong accounts");
}

#[test]
fn wrapped_sol_of_either_token_program_is_refused() {
    // A Token-2022 mint is accepted (`token_2022.rs`); wrapped SOL is not, under either program.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    h.svm.set_account(NATIVE_MINT, spl_mint_account(9, TOKEN_PROGRAM)).unwrap();
    let a = CreateAccounts { payer: payer.pubkey(), sponsor: h.sponsor.pubkey(), mint: NATIVE_MINT };
    let err = h.send(&[create_ix(&h.terms(1), &a)], &[&payer]).expect_err("wrapped SOL");
    assert!(err.contains("NativeMint"), "{err}");
    assert!(!h.exists(&escrow_address(&h.terms(1), &payer.pubkey(), &NATIVE_MINT)));

    h.svm.set_account(NATIVE_MINT_2022, spl_mint_account(9, TOKEN_2022_PROGRAM)).unwrap();
    let a = CreateAccounts { payer: payer.pubkey(), sponsor: h.sponsor.pubkey(), mint: NATIVE_MINT_2022 };
    let err = h.send(&[create_ix_under(&h.terms(1), &a, payer.pubkey(), TOKEN_2022_PROGRAM)], &[&payer]).expect_err("Token-2022's wrapped SOL");
    assert!(err.contains("NativeMint"), "{err}");
    assert!(!h.exists(&escrow_address(&h.terms(1), &payer.pubkey(), &NATIVE_MINT_2022)));
    println!("wrapped SOL, classic and Token-2022: refused at create, nothing written");
}

#[test]
fn bad_terms_are_refused_at_creation() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let payer_key = payer.pubkey();
    let schedule = |windows: Vec<Window>| Some(Schedule { windows, end: End::Pay });
    let cases: Vec<(&str, Box<dyn Fn(&mut Terms)>, &str)> = vec![
        ("payer equals recipient", Box::new(move |t| t.recipient = payer_key), "SameParty"),
        ("the zero key as recipient", Box::new(|t| t.recipient = Address::default()), "EmptyKey"),
        ("the zero key as arbiter", Box::new(|t| t.arbiter = Some(Address::default())), "EmptyKey"),
        ("amount zero", Box::new(|t| t.amount = 0), "AmountZero"),
        ("a schedule with no windows", Box::new(move |t| t.schedule = schedule(vec![])), "ScheduleEmpty"),
        ("five windows", Box::new(move |t| t.schedule = schedule((1..=5).map(|i| window(T0 + i * DAY, 0)).collect())), "TooManyWindows"),
        ("a share of 10,001", Box::new(move |t| t.schedule = schedule(vec![window(T0 + DAY, 10_001)])), "BadShare"),
        ("a share of 65,535 in the last window", Box::new(move |t| t.schedule = schedule(vec![window(T0 + DAY, 0), window(T0 + 2 * DAY, u16::MAX)])), "BadShare"),
        ("two windows ending together", Box::new(move |t| t.schedule = schedule(vec![window(T0 + DAY, 10_000), window(T0 + DAY, 0)])), "WindowsOutOfOrder"),
        ("windows out of order", Box::new(move |t| t.schedule = schedule(vec![window(T0 + 2 * DAY, 10_000), window(T0 + DAY, 0)])), "WindowsOutOfOrder"),
    ];
    let count = cases.len() + 2;
    for (what, change, want) in cases {
        let mut t = h.terms(1);
        change(&mut t);
        let err = h.send(&[create_ix(&t, &h.create_accounts())], &[&payer]).err().unwrap_or_else(|| panic!("{what}: must be refused"));
        assert!(err.contains(want), "{what}: expected {want}, got\n{err}");
        assert!(!h.exists(&escrow_address(&t, &payer_key, &h.mint)), "{what}: nothing written");
    }
    // The zero key as payer: its address is its own, and still refused.
    let zero_payer = CreateAccounts { payer: Address::default(), sponsor: h.sponsor.pubkey(), mint: h.mint };
    let recipient = h.recipient.insecure_clone();
    let err = h.send(&[invoice_ix(&h.terms(1), &zero_payer)], &[&recipient]).expect_err("zero payer");
    assert!(err.contains("EmptyKey"), "{err}");
    // A default that is neither pay nor refund: the bytes do not decode.
    let mut ix = create_ix(&h.scheduled(1, &[window(T0 + DAY, 0)], End::Refund), &h.create_accounts());
    let last = ix.data.len() - 1;
    ix.data[last] = 2;
    let err = h.send(&[ix], &[&payer]).expect_err("end 2");
    assert!(err.contains("InstructionDidNotDeserialize"), "{err}");
    // Four windows, the widest times there are, every share from all to none: fine. So is a
    // schedule already past: nothing compares a window with the clock at create.
    let mut t = h.scheduled(1, &[window(i64::MIN, 10_000), window(-1, 5_000), window(T0 - 1, 1), window(i64::MAX, 0)], End::Refund);
    t.arbiter = Some(h.arbiter.pubkey());
    h.create(&t).expect("four windows, the widest times");
    h.create(&h.scheduled(2, &[window(T0 - DAY, 0)], End::Pay)).expect("a schedule already past");
    println!("{count} bad term sets refused at create; four windows at the widest times accepted, and one already past");
}

#[test]
fn the_arbiter_cannot_be_the_payer_or_the_recipient() {
    // A party as arbiter could decide any split alone, so it could take everything. Refused, from
    // either creator; a third key is still fine.
    let mut h = Harness::new();
    let (payer, recipient, arbiter) = (h.payer.pubkey(), h.recipient.pubkey(), h.arbiter.pubkey());
    for (id, party) in [(1, payer), (2, recipient)] {
        let t = Terms { arbiter: Some(party), ..h.terms(id) };
        let err = h.create(&t).expect_err("opened by the payer");
        assert!(err.contains("ArbiterIsAParty"), "{err}");
        let err = h.invoice(&t).expect_err("opened by the recipient");
        assert!(err.contains("ArbiterIsAParty"), "{err}");
    }
    h.create(&Terms { arbiter: Some(arbiter), ..h.terms(3) }).expect("a third key");
    println!("rejected as expected: the payer or the recipient as arbiter, from either creator");
}

#[test]
fn a_share_over_ten_thousand_basis_points_is_refused() {
    let mut h = Harness::new();
    let mut t = h.terms(1);
    t.arbiter = Some(h.arbiter.pubkey());
    let escrow = h.funded(&t);
    for (what, result) in [("agree", h.agree(&escrow, 10_001)), ("decide", h.decide(&escrow, u16::MAX))] {
        let err = result.err().unwrap_or_else(|| panic!("{what}: must be refused"));
        assert!(err.contains("BadShare"), "{what}: {err}");
    }
    println!("10,001 and 65,535 basis points: agree and decide refused");
}

#[test]
fn an_escrow_ends_once() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();
    let arbiter = h.arbiter.insecure_clone();
    let mut t = h.scheduled(1, &[window(T0 + DAY, 5_000)], End::Pay);
    t.arbiter = Some(arbiter.pubkey());
    let escrow = h.marked(&t);
    let s = h.accounts(&escrow);

    // Two ways out in one transaction: the second fails, so neither lands.
    for (first, second, signers) in [
        (pay_ix(&s, payer.pubkey()), refund_ix(&s, recipient.pubkey()), vec![&payer, &recipient]),
        (refund_ix(&s, recipient.pubkey()), agree_ix(&s, payer.pubkey(), recipient.pubkey(), 5_000), vec![&recipient, &payer]),
        (take_back_ix(&s, payer.pubkey()), take_back_ix(&s, payer.pubkey()), vec![&payer]),
        (decide_ix(&s, arbiter.pubkey(), 0), decide_ix(&s, arbiter.pubkey(), 10_000), vec![&arbiter]),
    ] {
        let err = h.send(&[first, second], &signers).expect_err("the second ending must fail");
        assert!(err.contains("AccountNotInitialized") || err.contains("Ended"), "{err}");
    }
    assert_eq!(h.vault_balance(&escrow), AMOUNT, "the failed transactions moved nothing");

    h.pay(&escrow).expect("the one ending");
    let receipt = h.account(&escrow);

    // Later, with the deposit account gone: nothing loads.
    let err = h.refund(&escrow).expect_err("again");
    assert!(err.contains("AccountNotInitialized"), "{err}");

    // Later still, after a payment made the deposit account again: every instruction but
    // recover_late and sweep_rent is refused as ended, inside the window and after the end time,
    // and the id never reopens.
    let (make, vault) = create_ata_idempotent_ix(payer.pubkey(), escrow, h.mint);
    h.send(&[make, spl_transfer_ix(h.payer_wallet, vault, payer.pubkey(), AMOUNT)], &[&payer]).expect("a second payment");
    let p = payer.pubkey();
    let r = recipient.pubkey();
    for at in [T0, T0 + 2 * DAY] {
        h.set_time(at);
        let cases: Vec<(&str, Instruction, Vec<&Keypair>)> = vec![
            ("mark_funded", mark_funded_ix(escrow, vault), vec![]),
            ("pay", pay_ix(&s, p), vec![&payer]),
            ("refund", refund_ix(&s, r), vec![&recipient]),
            ("take_back", take_back_ix(&s, p), vec![&payer]),
            ("agree", agree_ix(&s, p, r, 5_000), vec![&payer, &recipient]),
            ("decide", decide_ix(&s, arbiter.pubkey(), 5_000), vec![&arbiter]),
            ("end", end_ix(escrow, vault, h.mint, h.recipient_tokens, h.sponsor.pubkey()), vec![]),
            ("close_unfunded", close_unfunded_ix(&s, p), vec![&payer]),
            ("stop", stop_ix(escrow, r), vec![&recipient]),
        ];
        for (what, ix, signers) in cases {
            let err = h.send(&[ix], &signers).err().unwrap_or_else(|| panic!("{what}: an ended escrow must refuse it"));
            assert!(err.contains("Ended"), "{what} at {at}: {err}");
        }
    }
    let err = h.create(&t).expect_err("reopen");
    assert!(err.contains("already in use"), "{err}");
    assert_eq!(h.account(&escrow).data, receipt.data, "the receipt is unchanged");
    assert_eq!(h.balance(&h.recipient_tokens), AMOUNT, "the recipient was paid once");
    println!("one ending: two in a transaction revert together; after it, everything but recover_late and sweep_rent is refused, in a window and after the end time");
}

#[test]
fn money_after_the_end_goes_back_to_the_payer_whoever_sends_it() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    h.pay(&escrow).expect("pay");
    let receipt = h.account(&escrow);
    let stranger = h.someone();

    // Nothing arrived after the end: there is nothing to recover, and no deposit account to load.
    let err = h.recover_late(&escrow, &stranger).expect_err("nothing there");
    assert!(err.contains("AccountNotInitialized"), "{err}");

    // A second tap on the old pay link: the payer's wallet app makes the deposit account again
    // and pays.
    let (make, vault) = create_ata_idempotent_ix(payer.pubkey(), escrow, h.mint);
    h.send(&[make, spl_transfer_ix(h.payer_wallet, vault, payer.pubkey(), 400_000)], &[&payer]).expect("a second payment");
    let vault_rent = h.lamports(&vault);
    let payer_sol = h.lamports(&payer.pubkey());

    // A stranger sends it back. The payer's standard account does not exist yet: the stranger
    // makes it and pays its rent (the harness key pays the fee).
    let payer_tokens = h.payer_account();
    h.drop_payer_account();
    let stranger_sol = h.lamports(&stranger.pubkey());
    let meta = h.recover_late(&escrow, &stranger).expect("recover_late");
    assert_eq!(events(&meta.logs), [Event::RecoveredLate { escrow, to_payer: 400_000, rent_lamports: vault_rent }]);
    assert_eq!(h.balance(&payer_tokens), 400_000, "the late money is the payer's, at its standard account");
    h.assert_closed(&vault, "the deposit account, again");
    assert_eq!(h.lamports(&payer.pubkey()), payer_sol + vault_rent, "its rent to the payer, whose wallet app made it");
    assert_eq!(h.lamports(&stranger.pubkey()), stranger_sol - h.lamports(&payer_tokens), "the stranger paid for the payer's account");
    assert_eq!(h.account(&escrow).data, receipt.data, "the receipt does not change");
    assert_eq!(h.account(&escrow).lamports, receipt.lamports);

    // Again, the payer's account already there, sent by the payer this time.
    let (make, _) = create_ata_idempotent_ix(payer.pubkey(), escrow, h.mint);
    h.send(&[make, spl_transfer_ix(h.payer_wallet, vault, payer.pubkey(), 1)], &[&payer]).expect("a third payment");
    h.recover_late(&escrow, &payer).expect("recover_late by the payer");
    assert_eq!(h.balance(&payer_tokens), 400_001);
    assert_eq!(h.balance(&h.payer_wallet), PAYER_START - AMOUNT - 400_001, "every late unit is at the standard account");
    println!("late money after the end: back at the payer's standard account, sent by a stranger who made it; the receipt unchanged");
}

#[test]
fn a_sweep_returns_rent_above_the_minimum_to_the_sponsor_and_never_goes_below_it() {
    // A sponsor, neither party and not the transaction's fee payer, fronts both rents. The deposit
    // account's rent goes back to it at the ending; what the rent cuts free above the receipt's
    // minimum goes to it too, sent by anyone.
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let sponsor = h.someone();
    let a = CreateAccounts { sponsor: sponsor.pubkey(), ..h.create_accounts() };
    h.send(&[create_ix(&h.terms(1), &a)], &[&payer, &sponsor]).expect("create, the sponsor fronting the rent");
    let escrow = h.address(&h.terms(1));
    assert_eq!(h.escrow(&escrow).sponsor, sponsor.pubkey());
    h.fund(&escrow, AMOUNT);
    h.pay(&escrow).expect("pay");
    let live = h.funded(&h.terms(2));
    let receipt = h.account(&escrow);

    // At the rate it was made at, the receipt holds exactly its minimum.
    let err = h.sweep(&escrow).expect_err("nothing above the minimum");
    assert!(err.contains("NothingToSweep"), "{err}");

    // The cuts land: the same bytes need far less. The excess goes to the sponsor recorded at
    // creation, the account keeps exactly the new minimum, and its bytes do not change.
    h.svm.set_sysvar(&rent_at(RENT_FINAL));
    let minimum = (128 + ESCROW_LEN as u64) * RENT_FINAL;
    let excess = receipt.lamports - minimum;
    let (fee_payer, payer_sol, sponsor_sol) = (h.lamports(&h.sponsor.pubkey()), h.lamports(&payer.pubkey()), h.lamports(&sponsor.pubkey()));
    let err = h.send(&[sweep_rent_ix(escrow, payer.pubkey())], &[]).expect_err("to the creator");
    assert!(err.contains("ConstraintHasOne"), "{err}");
    let meta = h.sweep(&escrow).expect("sweep");
    assert_eq!(events(&meta.logs), [Event::RentSwept { escrow, sponsor: sponsor.pubkey(), lamports: excess, left: minimum }]);
    assert_eq!(h.lamports(&escrow), minimum);
    assert_eq!(h.lamports(&sponsor.pubkey()), sponsor_sol + excess, "the sponsor gets the excess");
    assert_eq!(h.lamports(&payer.pubkey()), payer_sol, "the creator gets none of it");
    assert_eq!(h.lamports(&h.sponsor.pubkey()), fee_payer - 2 * 5_000, "whoever sends it pays only the fee (two sends)");
    assert_eq!(h.account(&escrow).data, receipt.data, "the receipt's bytes do not change");
    let err = h.sweep(&escrow).expect_err("twice");
    assert!(err.contains("NothingToSweep"), "{err}");

    // SOL sent to the escrow's address leaves the same way: to the sponsor.
    h.send(&[sol_transfer_ix(payer.pubkey(), escrow, 1_000_000)], &[&payer]).expect("SOL to a receipt");
    let meta = h.sweep(&escrow).expect("sweep the stray SOL");
    assert_eq!(events(&meta.logs), [Event::RentSwept { escrow, sponsor: sponsor.pubkey(), lamports: 1_000_000, left: minimum }]);

    // A live escrow can be swept too, and still ends as usual, keeping the minimum.
    h.sweep(&live).expect("sweep a live escrow");
    assert_eq!(h.lamports(&live), minimum);
    h.pay(&live).expect("a way out after a sweep");
    assert_eq!((h.escrow(&live).status, h.lamports(&live)), (Status::Ended, minimum));

    // The rate rises again: the account is below the new minimum, and a sweep finds nothing.
    h.svm.set_sysvar(&rent_at(6_960));
    let err = h.sweep(&escrow).expect_err("below the new minimum");
    assert!(err.contains("NothingToSweep"), "{err}");
    assert_eq!(h.lamports(&escrow), minimum);
    println!("rent sweep at {RENT_FINAL} lamports a byte: {excess} lamports back to the sponsor, none to the creator, {minimum} kept, bytes unchanged");
}

// ---------------------------------------------------------------------------------------------
// What it costs
// ---------------------------------------------------------------------------------------------

#[test]
fn what_each_way_out_costs() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();
    let arbiter = h.arbiter.insecure_clone();
    let four = [window(T0 + DAY, 10_000), window(T0 + 2 * DAY, 5_000), window(T0 + 3 * DAY, 2_500), window(T0 + 4 * DAY, 0)];

    // create with every option off, and with an arbiter and four windows.
    let a = h.create_accounts();
    h.measure("create, no options", &[create_ix(&h.terms(1), &a)], &[&payer]);
    let mut full = h.scheduled(2, &four, End::Pay);
    full.arbiter = Some(arbiter.pubkey());
    h.measure("create, an arbiter and four windows", &[create_ix(&full, &a)], &[&payer]);

    let e1 = h.address(&h.terms(1));
    h.fund(&e1, AMOUNT);
    let v1 = vault_address(&e1, &h.mint);
    h.measure("mark_funded", &[mark_funded_ix(e1, v1)], &[]);
    let s = h.accounts(&e1);
    h.measure("pay", &[pay_ix(&s, payer.pubkey())], &[&payer]);

    let e = h.funded(&h.terms(3));
    let s = h.accounts(&e);
    h.measure("refund", &[refund_ix(&s, recipient.pubkey())], &[&recipient]);

    let e = h.funded(&h.terms(4));
    let s = h.accounts(&e);
    h.measure("agree 30/70", &[agree_ix(&s, payer.pubkey(), recipient.pubkey(), 3_000)], &[&payer, &recipient]);

    let e2 = h.address(&full);
    h.fund(&e2, AMOUNT);
    let s = h.accounts(&e2);
    h.measure("decide 30/70", &[decide_ix(&s, arbiter.pubkey(), 3_000)], &[&arbiter]);

    let e = h.funded(&h.scheduled(5, &four, End::Pay));
    let s = h.accounts(&e);
    h.set_time(T0 + 2 * DAY);
    h.measure("take_back, in the third of four windows", &[take_back_ix(&s, payer.pubkey())], &[&payer]);

    h.set_time(T0);
    let to_recipient = h.marked(&h.scheduled(6, &four, End::Pay));
    let to_payer = h.marked(&h.scheduled(7, &four, End::Refund));
    let stopped = h.marked(&h.scheduled(8, &four, End::Pay));
    h.set_time(T0 + 2 * DAY);
    h.measure("stop, in the third of four windows", &[stop_ix(stopped, recipient.pubkey())], &[&recipient]);
    h.set_time(T0 + 4 * DAY);
    let v = vault_address(&to_recipient, &h.mint);
    h.measure("end, four windows, to the recipient", &[end_ix(to_recipient, v, h.mint, h.recipient_tokens, h.sponsor.pubkey())], &[]);
    let v = vault_address(&to_payer, &h.mint);
    h.measure("end, four windows, to the payer", &[end_ix(to_payer, v, h.mint, h.payer_account(), h.sponsor.pubkey())], &[]);

    let (e, _) = h.create(&h.terms(9)).expect("create");
    let s = h.accounts(&e);
    h.measure("close_unfunded, nothing paid", &[close_unfunded_ix(&s, recipient.pubkey())], &[&recipient]);

    // recover_late by a stranger who has to make the payer's standard account, then sweep_rent.
    let stranger = h.someone();
    let (make, v) = create_ata_idempotent_ix(payer.pubkey(), e1, h.mint);
    h.send(&[make, spl_transfer_ix(h.payer_wallet, v, payer.pubkey(), 1)], &[&payer]).expect("late money");
    let payer_tokens = h.payer_account();
    let held = h.balance(&payer_tokens);
    h.send(&[spl_transfer_ix(payer_tokens, h.payer_wallet, payer.pubkey(), held)], &[&payer]).expect("empty it");
    h.drop_payer_account();
    h.measure("recover_late, making the payer's account", &[recover_late_ix(e1, v, payer.pubkey(), h.mint, stranger.pubkey())], &[&stranger]);
    h.svm.set_sysvar(&rent_at(RENT_FINAL));
    let sponsor = h.sponsor.pubkey();
    h.measure("sweep_rent", &[sweep_rent_ix(e1, sponsor)], &[]);
    print_cu_summary();
}
