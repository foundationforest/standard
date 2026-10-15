//! The escrow, run under LiteSVM with the clock moved by hand.
//!
//! Every way out with exact balances, every rejection, and what each one costs. Run with
//! `cargo test -- --nocapture --test-threads=1` to see the numbers, the summary last.

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
fn assert_receipt(h: &Harness, escrow: &Address, outcome: Outcome, to_seller: u64, to_buyer: u64) {
    h.assert_closed(&vault_address(escrow, &h.mint), "the deposit account");
    let e = h.escrow(escrow);
    assert_eq!(e.status, Status::Ended, "the escrow account stays, ended");
    assert_eq!(e.outcome, Some(outcome));
    assert_eq!((e.to_seller, e.to_buyer), (to_seller, to_buyer));
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
    assert_eq!((e.arbiter, e.timer), (zero(), None), "no arbiter and no timer unless the creator turns one on");
    assert_eq!(e.creator, Side::Buyer);
    assert_eq!(names(&events(&meta.logs)), ["Created"]);

    // Both options on.
    let mut t = h.terms(7);
    t.arbiter = Some(h.arbiter.pubkey());
    t.timer = Some(Timer { days: 14, to: Side::Seller });
    let (escrow, meta) = h.create(&t).expect("create");
    let e = h.escrow(&escrow);
    assert_eq!(
        e,
        EscrowView {
            version: VERSION,
            id: 7,
            buyer: h.buyer.pubkey(),
            seller: h.seller.pubkey(),
            arbiter: h.arbiter.pubkey(),
            mint: h.mint,
            vault: vault_address(&escrow, &h.mint),
            rent_recipient: h.payer.pubkey(),
            amount: AMOUNT,
            creator: Side::Buyer,
            timer: Some(Timer { days: 14, to: Side::Seller }),
            created_at: T0,
            funded_at: 0,
            status: Status::Open,
            bump: e.bump,
            ended_at: 0,
            outcome: None,
            to_seller: 0,
            to_buyer: 0,
            payer: h.payer.pubkey(),
            objection: None,
            objected_at: 0,
        }
    );
    assert_eq!(escrow, Address::create_program_address(&[b"escrow", &terms_hash(&t, &h.buyer.pubkey(), &h.mint), &[e.bump]], &PROGRAM_ID).unwrap());

    // The deposit account: a classic token account for the mint, held by the escrow, empty.
    let vault = h.account(&e.vault);
    assert_eq!(vault.owner, TOKEN_PROGRAM);
    assert_eq!(&vault.data[..32], h.mint.as_ref());
    assert_eq!(&vault.data[32..64], escrow.as_ref());
    assert_eq!(token_amount(&vault.data), 0);

    assert_eq!(
        events(&meta.logs),
        [Event::Created {
            escrow,
            version: VERSION,
            id: 7,
            buyer: h.buyer.pubkey(),
            seller: h.seller.pubkey(),
            creator: Side::Buyer,
            arbiter: h.arbiter.pubkey(),
            mint: h.mint,
            vault: e.vault,
            rent_recipient: h.payer.pubkey(),
            amount: AMOUNT,
            timer_days: 14,
            timer_to: Side::Seller,
            created_at: T0,
            payer: h.payer.pubkey(),
        }]
    );

    // The seller opens one naming the buyer: an invoice, at its terms' address, the seller its
    // creator, the payer its rent recipient.
    let (invoice, meta) = h.invoice(&h.terms(8)).expect("invoice");
    assert_eq!(invoice, h.address(&h.terms(8)));
    let e = h.escrow(&invoice);
    assert_eq!((e.creator, e.buyer, e.rent_recipient, e.payer), (Side::Seller, h.buyer.pubkey(), h.payer.pubkey(), h.payer.pubkey()));
    let Event::Created { creator, rent_recipient, payer, .. } = &events(&meta.logs)[0] else { panic!() };
    assert_eq!((*creator, *rent_recipient, *payer), (Side::Seller, h.payer.pubkey(), h.payer.pubkey()));
    println!("created: every option off by default; both on; an invoice at its terms' address, the payer its rent recipient");
}

#[test]
fn the_address_of_fixed_terms_is_the_clients() {
    // One set of fixed terms and the address they make, asserted here and in the client's tests
    // (`escrow/client/test/client.test.ts`), so the two hand-written hashes cannot drift apart.
    // The program agrees with this harness in every test that opens an escrow.
    let key = |b: u8| Address::new_from_array([b; 32]);
    let t = Terms { id: 7, seller: key(2), amount: 1_000_000, arbiter: Some(key(4)), timer: Some(Timer { days: 3, to: Side::Seller }) };
    let hash: String = terms_hash(&t, &key(1), &key(3)).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hash, "8e18bf2edbfebf9ff5fad9a21a034c5c9cfca68e03cd0cb65cd00e09c789821a");
    assert_eq!(escrow_address(&t, &key(1), &key(3)).to_string(), "Cxa9ex9RSxEPHnDbsmGvNbcLQZ2U4XUmSvdwgGegiKS5");
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
    h.release_to_seller(&escrow2).expect("the money already there is the deal's");
    assert_eq!(h.balance(&h.seller_tokens), AMOUNT + 5);
    println!("funded by plain transfers; marked once by anyone; a pre-funded deposit account is adopted and paid out");
}

// ---------------------------------------------------------------------------------------------
// The ways out, with exact balances
// ---------------------------------------------------------------------------------------------

#[test]
fn release_to_seller_the_buyer_gives_the_whole_balance() {
    let mut h = Harness::new();
    let (escrow, _) = h.create(&h.terms(1)).expect("create");
    let vault = vault_address(&escrow, &h.mint);
    let (vault_rent, escrow_rent) = (h.lamports(&vault), h.lamports(&escrow));
    // Paid a quarter over the amount: every way out pays out the whole balance.
    h.fund(&escrow, AMOUNT + 250_000);
    // The buyer is paid nothing, so its standard account is not named and need not exist.
    h.drop_refund();
    let payer_before = h.lamports(&h.payer.pubkey());
    let buyer_sol = h.lamports(&h.buyer.pubkey());
    let meta = h.release_to_seller(&escrow).expect("release_to_seller");

    assert_eq!(
        events(&meta.logs),
        [Event::Ended {
            escrow,
            outcome: Outcome::ReleasedToSeller,
            amount: AMOUNT,
            balance: AMOUNT + 250_000,
            to_seller: AMOUNT + 250_000,
            to_buyer: 0,
            ended_at: T0,
            rent_recipient: h.payer.pubkey(),
            rent_lamports: vault_rent,
            funded_at: T0,
        }]
    );
    assert_eq!(h.balance(&h.seller_tokens), AMOUNT + 250_000);
    assert_eq!(h.balance(&h.buyer_tokens), BUYER_START - AMOUNT - 250_000);
    assert!(!h.exists(&h.refund()));
    assert_receipt(&h, &escrow, Outcome::ReleasedToSeller, AMOUNT + 250_000, 0);
    assert_eq!(h.escrow(&escrow).funded_at, T0, "nobody marked it: the ending records its own time as the funding time");
    assert_eq!(h.lamports(&escrow), escrow_rent, "the receipt keeps its own rent");
    assert_eq!(h.lamports(&h.payer.pubkey()), payer_before - 2 * 5_000 + vault_rent, "the key that fronted the rent pays the fee and gets the deposit account's rent back");
    assert_eq!(h.lamports(&h.buyer.pubkey()), buyer_sol, "none to the creator");
    println!("release_to_seller: 1.25 to the seller (the whole balance), {vault_rent} lamports of rent back to the payer");
}

#[test]
fn release_to_buyer_the_seller_gives_the_whole_balance_back() {
    let mut h = Harness::new();
    let escrow = h.marked(&h.terms(1));
    h.fund(&escrow, 7); // a little more after the mark: it goes back too
    let meta = h.release_to_buyer(&escrow).expect("release_to_buyer");
    let (outcome, balance, to_seller, to_buyer, _) = ended(&events(&meta.logs));
    assert_eq!((outcome, balance, to_seller, to_buyer), (Outcome::ReleasedToBuyer, AMOUNT + 7, 0, AMOUNT + 7));
    assert_eq!(h.balance(&h.refund()), AMOUNT + 7, "at the buyer's standard account");
    assert_eq!(h.buyer_total(), BUYER_START, "every unit back");
    assert_eq!(h.balance(&h.seller_tokens), 0);
    assert_receipt(&h, &escrow, Outcome::ReleasedToBuyer, 0, AMOUNT + 7);
    assert_eq!(h.escrow(&escrow).funded_at, T0);
    println!("release_to_buyer: everything back to the buyer's standard account; the seller names no account");
}

#[test]
fn a_split_divides_the_whole_balance_both_signing() {
    let mut h = Harness::new();
    let balance = AMOUNT + 3; // odd, so the rounding shows
    let (mut seller_total, mut buyer_back) = (0u64, 0u64);
    for (id, bps) in [(1u64, 0u16), (2, 1), (3, 5_000), (4, 9_999), (5, 10_000)] {
        let (escrow, _) = h.create(&h.terms(id)).expect("create");
        h.fund(&escrow, balance);
        let meta = h.split(&escrow, bps).expect("split");
        let (outcome, got_balance, to_seller, to_buyer, _) = ended(&events(&meta.logs));
        assert_eq!((outcome, got_balance), (Outcome::Split, balance));
        assert_eq!(to_seller, share(balance, bps), "{bps}: the seller's share rounds down");
        assert_eq!(to_seller + to_buyer, balance, "{bps}: every unit, once");
        seller_total += to_seller;
        buyer_back += to_buyer;
        assert_eq!(h.balance(&h.seller_tokens), seller_total, "{bps}");
        assert_eq!(h.balance(&h.refund()), buyer_back, "{bps}");
        assert_receipt(&h, &escrow, Outcome::Split, to_seller, to_buyer);
    }
    assert_eq!(share(balance, 5_000), 500_001, "half of 1,000,003 rounds down for the seller");
    assert_eq!(h.buyer_total() + h.balance(&h.seller_tokens), BUYER_START, "no unit created or lost");
    println!("split at 0, 1, 5,000, 9,999 and 10,000 basis points of 1,000,003: exact, the seller's share rounded down");
}

#[test]
fn the_arbiter_signs_any_split() {
    let mut h = Harness::new();

    // A third key: the only kind of arbiter (`the_arbiter_cannot_be_the_buyer_or_the_seller`).
    let mut t = h.terms(1);
    t.arbiter = Some(h.arbiter.pubkey());
    let escrow = h.funded(&t);
    let meta = h.arbitrate(&escrow, 2_500).expect("arbitrate");
    let (outcome, _, to_seller, to_buyer, _) = ended(&events(&meta.logs));
    assert_eq!((outcome, to_seller, to_buyer), (Outcome::Arbitrated, 250_000, 750_000));
    assert_receipt(&h, &escrow, Outcome::Arbitrated, 250_000, 750_000);

    // An arbiter adds a way out; it takes none away.
    let mut t = h.terms(4);
    t.arbiter = Some(h.arbiter.pubkey());
    let escrow = h.funded(&t);
    h.release_to_seller(&escrow).expect("the buyer can still give");
    assert_eq!(h.balance(&h.seller_tokens), 250_000 + AMOUNT);
    println!("arbitrate: a third key decided a split; the parties' own ways out still work");
}

#[test]
fn the_timer_pays_the_side_it_names_once_due_and_anyone_sends_it() {
    let mut h = Harness::new();
    for (id, to) in [(1u64, Side::Seller), (2, Side::Buyer)] {
        h.set_time(T0);
        let mut t = h.terms(id);
        t.timer = Some(Timer { days: 3, to });
        let escrow = h.funded(&t);
        // The timer counts from the mark, and from nothing else.
        let err = h.timer_release(&escrow, to).expect_err("not marked");
        assert!(err.contains("FundingNotMarked"), "{err}");
        h.set_time(T0 + 3_600);
        h.mark_funded(&escrow).expect("mark");
        let due = T0 + 3_600 + 3 * DAY;
        h.set_time(due - 1);
        let err = h.timer_release(&escrow, to).expect_err("a second early");
        assert!(err.contains("TimerNotDue"), "{err}");
        h.set_time(due);
        let seller_before = h.balance(&h.seller_tokens);
        let refund_before = h.balance(&h.refund());
        // Nobody signs but the fee payer: anyone may send it.
        let meta = h.timer_release(&escrow, to).expect("due to the second");
        let (outcome, balance, to_seller, to_buyer, _) = ended(&events(&meta.logs));
        assert_eq!((outcome, balance), (Outcome::TimerReleased, AMOUNT));
        match to {
            Side::Seller => {
                assert_eq!((to_seller, to_buyer), (AMOUNT, 0));
                assert_eq!(h.balance(&h.seller_tokens), seller_before + AMOUNT);
            }
            Side::Buyer => {
                assert_eq!((to_seller, to_buyer), (0, AMOUNT));
                assert_eq!(h.balance(&h.refund()), refund_before + AMOUNT);
            }
        }
        assert_receipt(&h, &escrow, Outcome::TimerReleased, to_seller, to_buyer);
        assert_eq!(h.escrow(&escrow).ended_at, due);
    }

    // The parties can end it any time before the timer is due; the timer takes no way out away.
    h.set_time(T0);
    let mut t = h.terms(3);
    t.timer = Some(Timer { days: 3, to: Side::Seller });
    let escrow = h.marked(&t);
    h.advance(DAY);
    h.release_to_buyer(&escrow).expect("the seller gives back on day one");
    h.advance(3 * DAY);
    let err = h.timer_release(&escrow, Side::Seller).expect_err("ended");
    assert!(err.contains("AccountNotInitialized") || err.contains("Ended"), "{err}");

    // The longest timer there is: 65,535 days, no overflow.
    let mut t = h.terms(4);
    t.timer = Some(Timer { days: u16::MAX, to: Side::Buyer });
    let escrow = h.marked(&t);
    let err = h.timer_release(&escrow, Side::Buyer).expect_err("179 years early");
    assert!(err.contains("TimerNotDue"), "{err}");
    h.set_time(h.escrow(&escrow).funded_at + i64::from(u16::MAX) * DAY);
    h.timer_release(&escrow, Side::Buyer).expect("179 years later");
    println!("timer_release: refused unmarked and a second early, runs at due to the seller and to the buyer; the parties still end it first");
}

#[test]
fn a_never_funded_escrow_is_closed_by_either_party_at_any_time() {
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let payer = h.payer.insecure_clone();

    // Nobody paid. The buyer, its creator, closes it at once; both rents go to the key that
    // fronted them, not to the buyer, and the buyer's standard account is not needed: nothing goes
    // to the buyer's tokens.
    let (escrow, _) = h.create(&h.terms(1)).expect("create");
    let vault = vault_address(&escrow, &h.mint);
    let (vault_rent, escrow_rent) = (h.lamports(&vault), h.lamports(&escrow));
    h.drop_refund();
    let err = h.close_unfunded(&escrow, &payer).expect_err("the key that fronted the rent is not a party");
    assert!(err.contains("NotACloser"), "{err}");
    let (payer_before, buyer_before) = (h.lamports(&payer.pubkey()), h.lamports(&buyer.pubkey()));
    let meta = h.close_unfunded(&escrow, &buyer).expect("the buyer closes");
    assert_eq!(
        events(&meta.logs),
        [Event::Closed { escrow, closed_by: buyer.pubkey(), to_buyer: 0, rent_recipient: payer.pubkey(), rent_lamports: vault_rent + escrow_rent }]
    );
    h.assert_closed(&escrow, "the escrow account");
    h.assert_closed(&vault, "the deposit account");
    assert_eq!(h.lamports(&buyer.pubkey()), buyer_before, "none to the creator");
    assert_eq!(h.lamports(&payer.pubkey()), payer_before - 2 * 5_000 + vault_rent + escrow_rent, "both rents to the key that fronted them, which paid the fee");
    assert!(!h.exists(&h.refund()), "nobody had to make the buyer an account");

    // The address is free again: nothing was dealt there.
    h.create(&h.terms(1)).expect("the same terms, again");

    // Part paid, closed by the seller: the part goes back to the buyer's standard account, which
    // has to exist when it is paid (whoever closes makes it first); the rents to the payer.
    let (make, refund) = create_ata_idempotent_ix(seller.pubkey(), buyer.pubkey(), h.mint);
    h.send(&[make], &[&seller]).expect("the buyer's standard account");
    h.fund(&escrow, 400_000);
    let payer_before = h.lamports(&payer.pubkey());
    let rents = h.lamports(&escrow) + h.lamports(&vault);
    h.close_unfunded(&escrow, &seller).expect("the seller closes");
    assert_eq!(h.balance(&refund), 400_000);
    assert_eq!(h.lamports(&payer.pubkey()), payer_before - 2 * 5_000 + rents, "the rents to the payer, whoever closes");
    h.assert_closed(&escrow, "the escrow account");

    // An invoice, part paid, closed by the buyer: the part to the buyer, the rents to the payer,
    // none to the seller who opened it.
    let (invoice, _) = h.invoice(&h.terms(3)).expect("invoice");
    h.fund(&invoice, AMOUNT - 1);
    let (payer_before, seller_before) = (h.lamports(&payer.pubkey()), h.lamports(&seller.pubkey()));
    let rents = h.lamports(&invoice) + h.lamports(&vault_address(&invoice, &h.mint));
    h.close_unfunded(&invoice, &buyer).expect("the buyer closes");
    assert_eq!(h.balance(&refund), 400_000 + AMOUNT - 1);
    assert_eq!(h.buyer_total(), BUYER_START);
    assert_eq!(h.lamports(&payer.pubkey()), payer_before - 2 * 5_000 + rents, "the invoice's rents to the payer");
    assert_eq!(h.lamports(&seller.pubkey()), seller_before, "none to the seller, its creator");

    // Funded, marked or not: it ends by a way out, not by closing.
    let funded = h.funded(&h.terms(4));
    let err = h.close_unfunded(&funded, &buyer).expect_err("funded");
    assert!(err.contains("StillFunded"), "{err}");
    h.mark_funded(&funded).expect("mark");
    let err = h.close_unfunded(&funded, &seller).expect_err("marked");
    assert!(err.contains("StillFunded"), "{err}");
    println!("close_unfunded: by the buyer with no buyer account needed, by the seller with part paid, an invoice by the buyer; both rents to the payer every time");
}

#[test]
fn the_escrow_address_is_its_terms_and_only_a_party_opens_it() {
    // The address is ["escrow", SHA-256 of every term]. Who opens it is not a term: the buyer and
    // the seller land at the same address with the same terms, and whoever is second finds it
    // taken. A stranger cannot open it: with the same terms it is not a party, and naming itself
    // a party changes the terms, and so the address.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let stranger = h.someone();
    let t = h.terms(1);
    let target = h.address(&t);
    let a = CreateAccounts { payer: stranger.pubkey(), ..h.create_accounts() };

    let err = h.send(&[create_ix_by(&t, &a, stranger.pubkey())], &[&stranger]).expect_err("a stranger, the same terms");
    assert!(err.contains("NotAParty"), "{err}");
    let err = h.send(&[unsigned(create_ix(&t, &a), &buyer.pubkey())], &[&stranger]).expect_err("the buyer's key, unsigned");
    assert!(err.contains("AccountNotSigner"), "{err}");
    let squat = Terms { seller: stranger.pubkey(), ..t.clone() };
    h.send(&[create_ix_by(&squat, &a, stranger.pubkey())], &[&stranger]).expect("the stranger's own terms");
    assert_ne!(h.address(&squat), target, "its own terms, its own address");
    let mut ix = create_ix_by(&Terms { seller: stranger.pubkey(), ..h.terms(2) }, &a, stranger.pubkey());
    ix.accounts[0].pubkey = target;
    ix.accounts[1].pubkey = vault_address(&target, &h.mint);
    let err = h.send(&[ix], &[&stranger]).expect_err("the stranger's terms aimed at the buyer's address");
    assert!(err.contains("ConstraintSeeds"), "{err}");
    assert!(!h.exists(&target));

    // Either party opens the same terms at the same address; the second finds it taken.
    let (opened, _) = h.create(&t).expect("the buyer opens");
    assert_eq!(opened, target);
    let err = h.invoice(&t).expect_err("the seller, the same terms");
    assert!(err.contains("already in use"), "{err}");
    let (invoiced, _) = h.invoice(&h.terms(3)).expect("the seller opens other terms");
    let err = h.create(&h.terms(3)).expect_err("the buyer, the invoice's terms");
    assert!(err.contains("already in use"), "{err}");
    assert_eq!((h.escrow(&target).creator, h.escrow(&invoiced).creator), (Side::Buyer, Side::Seller));
    println!("the address is the terms': a stranger cannot open it, and either party lands at the same one");
}

#[test]
fn every_term_is_in_the_address() {
    // Change any one term and the address changes: `create` aimed at the first terms' address
    // with any one of them different is refused by its seeds. So a payment to an address counts
    // only toward a deal with exactly its terms. The creator and the payer are not terms.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let other_buyer = h.someone();
    let other_mint = Address::new_unique();
    h.svm.set_account(other_mint, spl_mint_account(6, TOKEN_PROGRAM)).unwrap();
    let t = Terms { arbiter: Some(h.arbiter.pubkey()), timer: Some(Timer { days: 7, to: Side::Seller }), ..h.terms(1) };
    let target = h.address(&t);
    let timer = |days, to| Some(Timer { days, to });
    let variants: Vec<(&str, Terms, &Keypair, Address)> = vec![
        ("the id", Terms { id: 2, ..t.clone() }, &buyer, h.mint),
        ("the buyer", t.clone(), &other_buyer, h.mint),
        ("the seller", Terms { seller: Address::new_unique(), ..t.clone() }, &buyer, h.mint),
        ("the amount", Terms { amount: AMOUNT + 1, ..t.clone() }, &buyer, h.mint),
        ("the mint", t.clone(), &buyer, other_mint),
        ("the arbiter", Terms { arbiter: Some(Address::new_unique()), ..t.clone() }, &buyer, h.mint),
        ("no arbiter", Terms { arbiter: None, ..t.clone() }, &buyer, h.mint),
        ("the timer's days", Terms { timer: timer(8, Side::Seller), ..t.clone() }, &buyer, h.mint),
        ("the timer's side", Terms { timer: timer(7, Side::Buyer), ..t.clone() }, &buyer, h.mint),
        ("no timer", Terms { timer: None, ..t.clone() }, &buyer, h.mint),
    ];
    for (what, terms, creator, mint) in variants {
        let a = CreateAccounts { buyer: creator.pubkey(), payer: h.payer.pubkey(), mint };
        assert_ne!(escrow_address(&terms, &a.buyer, &mint), target, "{what}");
        let mut ix = create_ix_by(&terms, &a, creator.pubkey());
        ix.accounts[0].pubkey = target;
        ix.accounts[1].pubkey = vault_address(&target, &mint);
        let err = h.send(&[ix], &[creator]).err().unwrap_or_else(|| panic!("{what}: must be refused"));
        assert!(err.contains("ConstraintSeeds"), "{what}: {err}");
    }
    assert!(!h.exists(&target));

    // The seller as creator, and another payer: the same terms, the same address.
    let sponsor = h.someone();
    let a = CreateAccounts { payer: sponsor.pubkey(), ..h.create_accounts() };
    h.send(&[create_ix_by(&t, &a, seller.pubkey())], &[&seller, &sponsor]).expect("the seller, another payer");
    assert_eq!(h.escrow(&target).arbiter, h.arbiter.pubkey());
    println!("rejected as expected: each of ten one-term changes lands elsewhere; the creator and the payer do not move the address");
}

#[test]
fn every_rent_goes_back_to_the_payer() {
    // Whoever fronts the rent gets it back: here a sponsor that is neither party and not the
    // transaction's fee payer, as a fee payer service fronts it. None goes to the creator.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let sponsor = h.someone();
    let a = CreateAccounts { payer: sponsor.pubkey(), ..h.create_accounts() };

    // Closed unpaid: both rents to the sponsor, none to the buyer who opened it or the seller who
    // closed it.
    h.send(&[create_ix(&h.terms(1), &a)], &[&buyer, &sponsor]).expect("create, the sponsor paying");
    let escrow = h.address(&h.terms(1));
    let rents = h.lamports(&escrow) + h.lamports(&vault_address(&escrow, &h.mint));
    let before = (h.lamports(&sponsor.pubkey()), h.lamports(&buyer.pubkey()), h.lamports(&seller.pubkey()));
    let meta = h.close_unfunded(&escrow, &seller).expect("closed unpaid");
    let Some(Event::Closed { rent_recipient, .. }) = events(&meta.logs).pop() else { panic!("no Closed") };
    assert_eq!(rent_recipient, sponsor.pubkey());
    assert_eq!(
        (h.lamports(&sponsor.pubkey()), h.lamports(&buyer.pubkey()), h.lamports(&seller.pubkey())),
        (before.0 + rents, before.1, before.2),
        "both rents to the sponsor, none to the creator or the closer"
    );

    // An invoice, ended: the deposit account's rent to the sponsor, none to the seller who opened it.
    h.send(&[invoice_ix(&h.terms(2), &a)], &[&seller, &sponsor]).expect("invoice, the sponsor paying");
    let invoice = h.address(&h.terms(2));
    let e = h.escrow(&invoice);
    assert_eq!((e.rent_recipient, e.payer), (sponsor.pubkey(), sponsor.pubkey()));
    h.fund(&invoice, AMOUNT);
    // The rent goes only to the key recorded: the creator in its place is refused.
    let wrong = Accounts { rent_recipient: seller.pubkey(), ..h.accounts(&invoice) };
    let err = h.send(&[release_to_seller_ix(&wrong, buyer.pubkey())], &[&buyer]).expect_err("the creator as rent recipient");
    assert!(err.contains("ConstraintHasOne"), "{err}");
    let vault_rent = h.lamports(&vault_address(&invoice, &h.mint));
    let before = (h.lamports(&sponsor.pubkey()), h.lamports(&seller.pubkey()));
    h.release_to_seller(&invoice).expect("the buyer releases");
    assert_eq!(
        (h.lamports(&sponsor.pubkey()), h.lamports(&seller.pubkey())),
        (before.0 + vault_rent, before.1),
        "the deposit account's rent to the sponsor, none to the creator"
    );

    // A party that fronts its own rent gets it back the same way: the seller invoices and pays.
    let own = CreateAccounts { payer: seller.pubkey(), ..h.create_accounts() };
    h.send(&[invoice_ix(&h.terms(3), &own)], &[&seller]).expect("the seller pays its own invoice's rent");
    let e = h.escrow(&h.address(&h.terms(3)));
    assert_eq!((e.rent_recipient, e.payer), (seller.pubkey(), seller.pubkey()));
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
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let arbiter = h.arbiter.insecure_clone();
    let stranger = h.someone();

    // create: the buyer or the seller must sign. A stranger cannot open an escrow in either's name.
    let t = h.terms(1);
    let a = h.create_accounts();
    let err = h.send(&[unsigned(create_ix(&t, &a), &buyer.pubkey())], &[]).expect_err("create unsigned");
    assert!(err.contains("AccountNotSigner"), "{err}");
    for (who, key) in [("a stranger", &stranger), ("the arbiter", &arbiter)] {
        let err = h.send(&[create_ix_by(&t, &a, key.pubkey())], &[key]).expect_err("create");
        assert!(err.contains("NotAParty"), "create by {who}: {err}");
    }

    let mut t = h.terms(1);
    t.arbiter = Some(arbiter.pubkey());
    let escrow = h.funded(&t);
    let s = h.accounts(&escrow);
    let b = buyer.pubkey();
    let sl = seller.pubkey();
    let cases: Vec<(&str, Instruction, Vec<&Keypair>, &str)> = vec![
        ("release_to_seller by the seller", release_to_seller_ix(&s, sl), vec![&seller], "NotTheBuyer"),
        ("release_to_seller by the arbiter", release_to_seller_ix(&s, arbiter.pubkey()), vec![&arbiter], "NotTheBuyer"),
        ("release_to_seller by a stranger", release_to_seller_ix(&s, stranger.pubkey()), vec![&stranger], "NotTheBuyer"),
        ("release_to_seller, the buyer not signing", unsigned(release_to_seller_ix(&s, b), &b), vec![], "AccountNotSigner"),
        ("release_to_buyer by the buyer", release_to_buyer_ix(&s, b), vec![&buyer], "NotTheSeller"),
        ("release_to_buyer by the arbiter", release_to_buyer_ix(&s, arbiter.pubkey()), vec![&arbiter], "NotTheSeller"),
        ("release_to_buyer by a stranger", release_to_buyer_ix(&s, stranger.pubkey()), vec![&stranger], "NotTheSeller"),
        ("release_to_buyer, the seller not signing", unsigned(release_to_buyer_ix(&s, sl), &sl), vec![], "AccountNotSigner"),
        ("split with only the buyer signing", unsigned(split_ix(&s, b, sl, 5_000), &sl), vec![&buyer], "AccountNotSigner"),
        ("split with only the seller signing", unsigned(split_ix(&s, b, sl, 5_000), &b), vec![&seller], "AccountNotSigner"),
        ("split, the parties swapped", split_ix(&s, sl, b, 5_000), vec![&buyer, &seller], "NotTheBuyer"),
        ("split, the arbiter as the seller", split_ix(&s, b, arbiter.pubkey(), 5_000), vec![&buyer, &arbiter], "NotTheSeller"),
        ("split, a stranger as the buyer", split_ix(&s, stranger.pubkey(), sl, 5_000), vec![&stranger, &seller], "NotTheBuyer"),
        ("arbitrate by the buyer", arbitrate_ix(&s, b, 0), vec![&buyer], "NotTheArbiter"),
        ("arbitrate by the seller", arbitrate_ix(&s, sl, 10_000), vec![&seller], "NotTheArbiter"),
        ("arbitrate by a stranger", arbitrate_ix(&s, stranger.pubkey(), 5_000), vec![&stranger], "NotTheArbiter"),
        ("arbitrate, the arbiter not signing", unsigned(arbitrate_ix(&s, arbiter.pubkey(), 5_000), &arbiter.pubkey()), vec![], "AccountNotSigner"),
        ("close_unfunded by a stranger", close_unfunded_ix(&s, stranger.pubkey()), vec![&stranger], "NotACloser"),
        ("close_unfunded by the arbiter", close_unfunded_ix(&s, arbiter.pubkey()), vec![&arbiter], "NotACloser"),
        ("recover_late by a stranger, live", recover_late_ix(escrow, s.vault, b, h.mint, stranger.pubkey()), vec![&stranger], "NotEnded"),
        ("sweep_rent to a stranger", sweep_rent_ix(escrow, stranger.pubkey()), vec![], "ConstraintHasOne"),
        ("sweep_rent to the creator", sweep_rent_ix(escrow, b), vec![], "ConstraintHasOne"),
        ("object by a stranger", object_ix(escrow, stranger.pubkey()), vec![&stranger], "NotAnObjector"),
        ("object by the arbiter", object_ix(escrow, arbiter.pubkey()), vec![&arbiter], "NotAnObjector"),
        ("object, the buyer not signing", unsigned(object_ix(escrow, b), &b), vec![], "AccountNotSigner"),
    ];
    for (what, ix, signers, want) in cases {
        let err = h.send(&[ix], &signers).err().unwrap_or_else(|| panic!("{what}: must be refused"));
        assert!(err.contains(want), "{what}: expected {want}, got\n{err}");
    }

    // Payouts go only to the recorded parties' standard accounts, rent only to the payer.
    let strangers_tokens = Address::new_unique();
    h.svm.set_account(strangers_tokens, spl_token_account(&h.mint, &stranger.pubkey(), 0)).unwrap();
    let bad = Accounts { seller_tokens: strangers_tokens, ..s };
    let err = h.send(&[release_to_seller_ix(&bad, b)], &[&buyer]).expect_err("a stranger's account as the seller's");
    assert!(err.contains("NotTheSellersAccount"), "{err}");
    let bad = Accounts { rent_recipient: stranger.pubkey(), ..s };
    let err = h.send(&[release_to_seller_ix(&bad, b)], &[&buyer]).expect_err("a stranger as the rent recipient");
    assert!(err.contains("ConstraintHasOne"), "{err}");

    assert_eq!(h.vault_balance(&escrow), AMOUNT, "nothing above moved anything");
    let e = h.escrow(&escrow);
    assert_eq!((e.status, e.objection), (Status::Open, None));
    println!("every instruction refused its wrong signer; payouts and rent cannot be redirected");
}

#[test]
fn arbitrate_needs_an_arbiter_named_at_creation() {
    let mut h = Harness::new();
    let arbiter = h.arbiter.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    let s = h.accounts(&escrow);
    for (who, key) in [("a would-be arbiter", arbiter.insecure_clone()), ("the buyer", h.buyer.insecure_clone()), ("the seller", h.seller.insecure_clone())] {
        let err = h.send(&[arbitrate_ix(&s, key.pubkey(), 5_000)], &[&key]).expect_err("no arbiter");
        assert!(err.contains("NoArbiter"), "{who}: {err}");
    }
    assert_eq!(h.escrow(&escrow).arbiter, zero());
    println!("no arbiter named: arbitrate refused, whoever signs");
}

#[test]
fn timer_release_needs_a_timer_the_funding_marked_and_its_day() {
    let mut h = Harness::new();
    // No timer, however long after the mark.
    let escrow = h.marked(&h.terms(1));
    h.advance(10_000 * DAY);
    for to in [Side::Seller, Side::Buyer] {
        let err = h.timer_release(&escrow, to).expect_err("no timer");
        assert!(err.contains("NoTimer"), "{err}");
    }

    // A timer, the money there, never marked: it never runs, however long.
    let mut t = h.terms(2);
    t.timer = Some(Timer { days: 1, to: Side::Seller });
    let escrow = h.funded(&t);
    h.advance(1_000 * DAY);
    let err = h.timer_release(&escrow, Side::Seller).expect_err("never marked");
    assert!(err.contains("FundingNotMarked"), "{err}");

    // Marked and released in one breath: the mark is now, so the timer is not due.
    let vault = vault_address(&escrow, &h.mint);
    let err = h
        .send(&[mark_funded_ix(escrow, vault), timer_release_ix(escrow, vault, h.mint, h.seller_tokens, h.payer.pubkey())], &[])
        .expect_err("mark and release together");
    assert!(err.contains("TimerNotDue"), "{err}");
    assert_eq!(h.escrow(&escrow).status, Status::Open, "the failed transaction marked nothing");

    // A timer and no money: nothing to mark, nothing to release.
    let mut t = h.terms(3);
    t.timer = Some(Timer { days: 1, to: Side::Buyer });
    let (empty, _) = h.create(&t).expect("create");
    let err = h.mark_funded(&empty).expect_err("empty");
    assert!(err.contains("NotFunded"), "{err}");
    println!("timer_release: refused with no timer, with the funding never marked, and marked in the same transaction");
}

#[test]
fn nothing_moves_before_the_deposit_account_holds_the_amount() {
    let mut h = Harness::new();
    let mut t = h.terms(1);
    t.arbiter = Some(h.arbiter.pubkey());
    let (escrow, _) = h.create(&t).expect("create");
    h.fund(&escrow, AMOUNT - 1);
    for (what, result) in [
        ("release_to_seller", h.release_to_seller(&escrow)),
        ("release_to_buyer", h.release_to_buyer(&escrow)),
        ("split", h.split(&escrow, 5_000)),
        ("arbitrate", h.arbitrate(&escrow, 5_000)),
    ] {
        let err = result.err().unwrap_or_else(|| panic!("{what}: must be refused"));
        assert!(err.contains("NotFunded"), "{what}: {err}");
    }
    assert_eq!(h.vault_balance(&escrow), AMOUNT - 1);
    println!("one unit short: no way out runs; only close_unfunded does");
}

#[test]
fn a_payout_lands_only_at_the_receiving_partys_standard_account() {
    // Every payout to the buyer lands at the buyer's standard token account for the mint, and
    // (Carlos's second change) every payout to the seller at the seller's, on every way out, the
    // timer included.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let arbiter = h.arbiter.insecure_clone();
    let b = buyer.pubkey();
    let sl = seller.pubkey();
    let ar = arbiter.pubkey();

    // (way out, the side whose account is swapped, the timer's side)
    let cases = [
        ("release_to_buyer", Side::Buyer, Side::Buyer),
        ("split", Side::Buyer, Side::Buyer),
        ("arbitrate", Side::Buyer, Side::Buyer),
        ("timer_release", Side::Buyer, Side::Buyer),
        ("close_unfunded", Side::Buyer, Side::Buyer),
        ("release_to_seller", Side::Seller, Side::Seller),
        ("split", Side::Seller, Side::Seller),
        ("arbitrate", Side::Seller, Side::Seller),
        ("timer_release", Side::Seller, Side::Seller),
    ];
    for (id, (name, side, timer_to)) in cases.into_iter().enumerate() {
        h.set_time(T0);
        let t = Terms { arbiter: Some(ar), timer: Some(Timer { days: 1, to: timer_to }), ..h.terms(id as u64) };
        let (escrow, _) = h.create(&t).expect("create");
        h.fund(&escrow, if name == "close_unfunded" { AMOUNT / 2 } else { AMOUNT });
        if name == "timer_release" {
            h.mark_funded(&escrow).expect("mark");
            h.advance(DAY);
        }
        let right = h.accounts(&escrow);
        // The account the party holds but that is not its standard one.
        let (wrong, other, standard, want) = match side {
            Side::Buyer => (Accounts { buyer_tokens: h.buyer_tokens, ..right }, h.buyer_tokens, h.refund(), "NotTheRefundAddress"),
            Side::Seller => (Accounts { seller_tokens: h.seller_other, ..right }, h.seller_other, h.seller_tokens, "NotTheSellersAccount"),
        };
        let ix = |s: &Accounts| match name {
            "release_to_buyer" => release_to_buyer_ix(s, sl),
            "release_to_seller" => release_to_seller_ix(s, b),
            "split" => split_ix(s, b, sl, 5_000),
            "arbitrate" => arbitrate_ix(s, ar, 5_000),
            "timer_release" => timer_release_ix(s.escrow, s.vault, s.mint, if timer_to == Side::Buyer { s.buyer_tokens } else { s.seller_tokens }, s.rent_recipient),
            _ => close_unfunded_ix(s, sl),
        };
        let signers: Vec<&Keypair> = match name {
            "release_to_buyer" | "close_unfunded" => vec![&seller],
            "release_to_seller" => vec![&buyer],
            "split" => vec![&buyer, &seller],
            "arbitrate" => vec![&arbiter],
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

    // A timer that pays the seller refuses every other account: the buyer's, a stranger's, the
    // seller's for another mint, the deposit account itself, the seller's address.
    h.set_time(T0);
    let t = Terms { timer: Some(Timer { days: 1, to: Side::Seller }), ..h.terms(20) };
    let escrow = h.marked(&t);
    h.advance(DAY);
    let vault = vault_address(&escrow, &h.mint);
    let strangers = Address::new_unique();
    h.svm.set_account(strangers, spl_token_account(&h.mint, &Address::new_unique(), 0)).unwrap();
    let other_mint = Address::new_unique();
    h.svm.set_account(other_mint, spl_mint_account(6, TOKEN_PROGRAM)).unwrap();
    let sellers_other_mint = payout_address(&sl, &other_mint);
    h.svm.set_account(sellers_other_mint, spl_token_account(&other_mint, &sl, 0)).unwrap();
    for (what, to) in [
        ("the buyer's standard account", h.refund()),
        ("a stranger's account", strangers),
        ("another account the seller holds", h.seller_other),
        ("the seller's standard account for another mint", sellers_other_mint),
        ("the deposit account itself", vault),
        ("the seller's address, not a token account", sl),
    ] {
        let err = h.send(&[timer_release_ix(escrow, vault, h.mint, to, h.payer.pubkey())], &[]).expect_err(what);
        assert!(err.contains("NotTheSellersAccount"), "{what}: {err}");
    }
    h.timer_release(&escrow, Side::Seller).expect("to the seller's standard account");
    println!("nine ways of paying a party refused any account but its standard one; the seller's timer refused six wrong accounts");
}

#[test]
fn wrapped_sol_of_either_token_program_is_refused() {
    // A Token-2022 mint is accepted (`token_2022.rs`); wrapped SOL is not, under either program.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    h.svm.set_account(NATIVE_MINT, spl_mint_account(9, TOKEN_PROGRAM)).unwrap();
    let a = CreateAccounts { buyer: buyer.pubkey(), payer: h.payer.pubkey(), mint: NATIVE_MINT };
    let err = h.send(&[create_ix(&h.terms(1), &a)], &[&buyer]).expect_err("wrapped SOL");
    assert!(err.contains("NativeMint"), "{err}");
    assert!(!h.exists(&escrow_address(&h.terms(1), &buyer.pubkey(), &NATIVE_MINT)));

    h.svm.set_account(NATIVE_MINT_2022, spl_mint_account(9, TOKEN_2022_PROGRAM)).unwrap();
    let a = CreateAccounts { buyer: buyer.pubkey(), payer: h.payer.pubkey(), mint: NATIVE_MINT_2022 };
    let err = h.send(&[create_ix_under(&h.terms(1), &a, buyer.pubkey(), TOKEN_2022_PROGRAM)], &[&buyer]).expect_err("Token-2022's wrapped SOL");
    assert!(err.contains("NativeMint"), "{err}");
    assert!(!h.exists(&escrow_address(&h.terms(1), &buyer.pubkey(), &NATIVE_MINT_2022)));
    println!("wrapped SOL, classic and Token-2022: refused at create, nothing written");
}

#[test]
fn bad_terms_are_refused_at_creation() {
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let buyer_key = buyer.pubkey();
    let cases: Vec<(&str, Box<dyn Fn(&mut Terms)>, &str)> = vec![
        ("buyer equals seller", Box::new(move |t| t.seller = buyer_key), "SameParty"),
        ("the zero key as seller", Box::new(|t| t.seller = Address::default()), "EmptyKey"),
        ("the zero key as arbiter", Box::new(|t| t.arbiter = Some(Address::default())), "EmptyKey"),
        ("amount zero", Box::new(|t| t.amount = 0), "AmountZero"),
        ("a timer of zero days", Box::new(|t| t.timer = Some(Timer { days: 0, to: Side::Seller })), "TimerZero"),
    ];
    for (what, change, want) in cases {
        let mut t = h.terms(1);
        change(&mut t);
        let err = h.send(&[create_ix(&t, &h.create_accounts())], &[&buyer]).err().unwrap_or_else(|| panic!("{what}: must be refused"));
        assert!(err.contains(want), "{what}: expected {want}, got\n{err}");
        assert!(!h.exists(&escrow_address(&t, &buyer_key, &h.mint)), "{what}: nothing written");
    }
    // The zero key as buyer: its address is its own, and still refused.
    let zero_buyer = CreateAccounts { buyer: Address::default(), payer: h.payer.pubkey(), mint: h.mint };
    let seller = h.seller.insecure_clone();
    let err = h.send(&[invoice_ix(&h.terms(1), &zero_buyer)], &[&seller]).expect_err("zero buyer");
    assert!(err.contains("EmptyKey"), "{err}");
    // A timer side that is neither party: the bytes do not decode.
    let mut ix = create_ix(&Terms { timer: Some(Timer { days: 1, to: Side::Seller }), ..h.terms(1) }, &h.create_accounts());
    let last = ix.data.len() - 1;
    ix.data[last] = 2;
    let err = h.send(&[ix], &[&buyer]).expect_err("side 2");
    assert!(err.contains("InstructionDidNotDeserialize"), "{err}");
    // The longest timer is fine.
    let mut t = h.terms(1);
    t.arbiter = Some(h.arbiter.pubkey());
    t.timer = Some(Timer { days: u16::MAX, to: Side::Buyer });
    h.create(&t).expect("a 65,535-day timer");
    println!("seven bad term sets refused at create; the longest timer accepted");
}

#[test]
fn the_arbiter_cannot_be_the_buyer_or_the_seller() {
    // A party as arbiter could decide any split alone, so it could take everything. Refused, from
    // either creator; a third key is still fine.
    let mut h = Harness::new();
    let (buyer, seller, arbiter) = (h.buyer.pubkey(), h.seller.pubkey(), h.arbiter.pubkey());
    for (id, party) in [(1, buyer), (2, seller)] {
        let t = Terms { arbiter: Some(party), ..h.terms(id) };
        let err = h.create(&t).expect_err("opened by the buyer");
        assert!(err.contains("ArbiterIsAParty"), "{err}");
        let err = h.invoice(&t).expect_err("opened by the seller");
        assert!(err.contains("ArbiterIsAParty"), "{err}");
    }
    h.create(&Terms { arbiter: Some(arbiter), ..h.terms(3) }).expect("a third key");
    println!("rejected as expected: the buyer or the seller as arbiter, from either creator");
}

#[test]
fn a_split_over_ten_thousand_basis_points_is_refused() {
    let mut h = Harness::new();
    let mut t = h.terms(1);
    t.arbiter = Some(h.arbiter.pubkey());
    let escrow = h.funded(&t);
    for (what, result) in [("split", h.split(&escrow, 10_001)), ("arbitrate", h.arbitrate(&escrow, u16::MAX))] {
        let err = result.err().unwrap_or_else(|| panic!("{what}: must be refused"));
        assert!(err.contains("BadSplit"), "{what}: {err}");
    }
    println!("10,001 and 65,535 basis points: split and arbitrate refused");
}

#[test]
fn an_escrow_ends_once() {
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let arbiter = h.arbiter.insecure_clone();
    let mut t = h.terms(1);
    t.arbiter = Some(arbiter.pubkey());
    t.timer = Some(Timer { days: 1, to: Side::Seller });
    let escrow = h.marked(&t);
    let s = h.accounts(&escrow);

    // Two ways out in one transaction: the second fails, so neither lands.
    for (first, second, signers) in [
        (release_to_seller_ix(&s, buyer.pubkey()), release_to_buyer_ix(&s, seller.pubkey()), vec![&buyer, &seller]),
        (release_to_buyer_ix(&s, seller.pubkey()), split_ix(&s, buyer.pubkey(), seller.pubkey(), 5_000), vec![&seller, &buyer]),
        (arbitrate_ix(&s, arbiter.pubkey(), 0), arbitrate_ix(&s, arbiter.pubkey(), 10_000), vec![&arbiter]),
    ] {
        let err = h.send(&[first, second], &signers).expect_err("the second ending must fail");
        assert!(err.contains("AccountNotInitialized") || err.contains("Ended"), "{err}");
    }
    assert_eq!(h.vault_balance(&escrow), AMOUNT, "the failed transactions moved nothing");

    h.release_to_seller(&escrow).expect("the one ending");
    let receipt = h.account(&escrow);

    // Later, with the deposit account gone: nothing loads.
    let err = h.release_to_buyer(&escrow).expect_err("again");
    assert!(err.contains("AccountNotInitialized"), "{err}");

    // Later still, after a payment made the deposit account again: every instruction but
    // recover_late and sweep_rent is refused as ended, and the id never reopens.
    let (make, vault) = create_ata_idempotent_ix(buyer.pubkey(), escrow, h.mint);
    h.send(&[make, spl_transfer_ix(h.buyer_tokens, vault, buyer.pubkey(), AMOUNT)], &[&buyer]).expect("a second payment");
    h.advance(2 * DAY);
    let b = buyer.pubkey();
    let sl = seller.pubkey();
    let cases: Vec<(&str, Instruction, Vec<&Keypair>)> = vec![
        ("mark_funded", mark_funded_ix(escrow, vault), vec![]),
        ("release_to_seller", release_to_seller_ix(&s, b), vec![&buyer]),
        ("release_to_buyer", release_to_buyer_ix(&s, sl), vec![&seller]),
        ("split", split_ix(&s, b, sl, 5_000), vec![&buyer, &seller]),
        ("arbitrate", arbitrate_ix(&s, arbiter.pubkey(), 5_000), vec![&arbiter]),
        ("timer_release", timer_release_ix(escrow, vault, h.mint, h.seller_tokens, h.payer.pubkey()), vec![]),
        ("close_unfunded", close_unfunded_ix(&s, b), vec![&buyer]),
        ("object", object_ix(escrow, sl), vec![&seller]),
    ];
    for (what, ix, signers) in cases {
        let err = h.send(&[ix], &signers).err().unwrap_or_else(|| panic!("{what}: an ended escrow must refuse it"));
        assert!(err.contains("Ended"), "{what}: {err}");
    }
    let err = h.create(&t).expect_err("reopen");
    assert!(err.contains("already in use"), "{err}");
    assert_eq!(h.account(&escrow).data, receipt.data, "the receipt is unchanged");
    assert_eq!(h.balance(&h.seller_tokens), AMOUNT, "the seller was paid once");
    println!("one ending: two in a transaction revert together; after it, everything but recover_late and sweep_rent is refused, object included");
}

#[test]
fn money_after_the_end_goes_back_to_the_buyer_whoever_sends_it() {
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    h.release_to_seller(&escrow).expect("release");
    let receipt = h.account(&escrow);
    let stranger = h.someone();

    // Nothing arrived after the end: there is nothing to recover, and no deposit account to load.
    let err = h.recover_late(&escrow, &stranger).expect_err("nothing there");
    assert!(err.contains("AccountNotInitialized"), "{err}");

    // A second tap on the old pay link: the buyer's wallet app makes the deposit account again and
    // pays.
    let (make, vault) = create_ata_idempotent_ix(buyer.pubkey(), escrow, h.mint);
    h.send(&[make, spl_transfer_ix(h.buyer_tokens, vault, buyer.pubkey(), 400_000)], &[&buyer]).expect("a second payment");
    let vault_rent = h.lamports(&vault);
    let buyer_sol = h.lamports(&buyer.pubkey());

    // A stranger sends it back. The buyer's standard account does not exist yet: the stranger
    // makes it and pays its rent (the harness key pays the fee).
    let refund = h.refund();
    h.drop_refund();
    let stranger_sol = h.lamports(&stranger.pubkey());
    let meta = h.recover_late(&escrow, &stranger).expect("recover_late");
    assert_eq!(events(&meta.logs), [Event::RecoveredLate { escrow, to_buyer: 400_000, rent_lamports: vault_rent }]);
    assert_eq!(h.balance(&refund), 400_000, "the late money is the buyer's, at its standard account");
    h.assert_closed(&vault, "the deposit account, again");
    assert_eq!(h.lamports(&buyer.pubkey()), buyer_sol + vault_rent, "its rent to the buyer, whose wallet app made it");
    assert_eq!(h.lamports(&stranger.pubkey()), stranger_sol - h.lamports(&refund), "the stranger paid for the buyer's account");
    assert_eq!(h.account(&escrow).data, receipt.data, "the receipt does not change");
    assert_eq!(h.account(&escrow).lamports, receipt.lamports);

    // Again, the buyer's account already there, sent by the buyer this time.
    let (make, _) = create_ata_idempotent_ix(buyer.pubkey(), escrow, h.mint);
    h.send(&[make, spl_transfer_ix(h.buyer_tokens, vault, buyer.pubkey(), 1)], &[&buyer]).expect("a third payment");
    h.recover_late(&escrow, &buyer).expect("recover_late by the buyer");
    assert_eq!(h.balance(&refund), 400_001);
    assert_eq!(h.balance(&h.buyer_tokens), BUYER_START - AMOUNT - 400_001, "every late unit is at the standard account");
    println!("late money after the end: back at the buyer's standard account, sent by a stranger who made it; the receipt unchanged");
}

#[test]
fn a_sweep_returns_rent_above_the_minimum_to_the_payer_and_never_goes_below_it() {
    // The refund to the payer: a sponsor, neither party and not the transaction's fee payer,
    // fronts both rents. The deposit account's rent goes back to it at the ending; what the rent
    // cuts free above the receipt's minimum goes to it too, sent by anyone.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let sponsor = h.someone();
    let a = CreateAccounts { payer: sponsor.pubkey(), ..h.create_accounts() };
    h.send(&[create_ix(&h.terms(1), &a)], &[&buyer, &sponsor]).expect("create, the sponsor fronting the rent");
    let escrow = h.address(&h.terms(1));
    assert_eq!(h.escrow(&escrow).payer, sponsor.pubkey());
    h.fund(&escrow, AMOUNT);
    h.release_to_seller(&escrow).expect("release");
    let live = h.funded(&h.terms(2));
    let receipt = h.account(&escrow);

    // At the rate it was made at, the receipt holds exactly its minimum.
    let err = h.sweep(&escrow).expect_err("nothing above the minimum");
    assert!(err.contains("NothingToSweep"), "{err}");

    // The cuts land: the same bytes need far less. The excess goes to the payer recorded at
    // creation, the account keeps exactly the new minimum, and its bytes do not change.
    h.svm.set_sysvar(&rent_at(RENT_FINAL));
    let minimum = (128 + ESCROW_LEN as u64) * RENT_FINAL;
    let excess = receipt.lamports - minimum;
    let (fee_payer, buyer_sol, sponsor_sol) = (h.lamports(&h.payer.pubkey()), h.lamports(&buyer.pubkey()), h.lamports(&sponsor.pubkey()));
    let err = h.send(&[sweep_rent_ix(escrow, buyer.pubkey())], &[]).expect_err("to the creator");
    assert!(err.contains("ConstraintHasOne"), "{err}");
    let meta = h.sweep(&escrow).expect("sweep");
    assert_eq!(events(&meta.logs), [Event::RentSwept { escrow, payer: sponsor.pubkey(), lamports: excess, left: minimum }]);
    assert_eq!(h.lamports(&escrow), minimum);
    assert_eq!(h.lamports(&sponsor.pubkey()), sponsor_sol + excess, "the payer gets the excess");
    assert_eq!(h.lamports(&buyer.pubkey()), buyer_sol, "the creator gets none of it");
    assert_eq!(h.lamports(&h.payer.pubkey()), fee_payer - 2 * 5_000, "whoever sends it pays only the fee (two sends)");
    assert_eq!(h.account(&escrow).data, receipt.data, "the receipt's bytes do not change");
    let err = h.sweep(&escrow).expect_err("twice");
    assert!(err.contains("NothingToSweep"), "{err}");

    // SOL sent to the escrow's address leaves the same way: to the payer.
    h.send(&[sol_transfer_ix(buyer.pubkey(), escrow, 1_000_000)], &[&buyer]).expect("SOL to a receipt");
    let meta = h.sweep(&escrow).expect("sweep the stray SOL");
    assert_eq!(events(&meta.logs), [Event::RentSwept { escrow, payer: sponsor.pubkey(), lamports: 1_000_000, left: minimum }]);

    // A live escrow can be swept too, and still ends as usual, keeping the minimum.
    h.sweep(&live).expect("sweep a live escrow");
    assert_eq!(h.lamports(&live), minimum);
    h.release_to_seller(&live).expect("a way out after a sweep");
    assert_eq!((h.escrow(&live).status, h.lamports(&live)), (Status::Ended, minimum));

    // The rate rises again: the account is below the new minimum, and a sweep finds nothing.
    h.svm.set_sysvar(&rent_at(6_960));
    let err = h.sweep(&escrow).expect_err("below the new minimum");
    assert!(err.contains("NothingToSweep"), "{err}");
    assert_eq!(h.lamports(&escrow), minimum);
    println!("rent sweep at {RENT_FINAL} lamports a byte: {excess} lamports back to the payer, none to the creator, {minimum} kept, bytes unchanged");
}

// ---------------------------------------------------------------------------------------------
// What it costs
// ---------------------------------------------------------------------------------------------

#[test]
fn what_each_way_out_costs() {
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let arbiter = h.arbiter.insecure_clone();

    // create with every option off, and with both on.
    let a = h.create_accounts();
    h.measure("create, no options", &[create_ix(&h.terms(1), &a)], &[&buyer]);
    let mut full = h.terms(2);
    full.arbiter = Some(arbiter.pubkey());
    full.timer = Some(Timer { days: 7, to: Side::Seller });
    h.measure("create, an arbiter and a timer", &[create_ix(&full, &a)], &[&buyer]);

    let e1 = h.address(&h.terms(1));
    h.fund(&e1, AMOUNT);
    let v1 = vault_address(&e1, &h.mint);
    h.measure("mark_funded", &[mark_funded_ix(e1, v1)], &[]);
    let s = h.accounts(&e1);
    h.measure("release_to_seller", &[release_to_seller_ix(&s, buyer.pubkey())], &[&buyer]);

    let e = h.funded(&h.terms(3));
    let s = h.accounts(&e);
    h.measure("release_to_buyer", &[release_to_buyer_ix(&s, seller.pubkey())], &[&seller]);

    let e = h.funded(&h.terms(4));
    let s = h.accounts(&e);
    h.measure("split 70/30", &[split_ix(&s, buyer.pubkey(), seller.pubkey(), 7_000)], &[&buyer, &seller]);

    let e2 = h.address(&full);
    h.fund(&e2, AMOUNT);
    let s = h.accounts(&e2);
    h.measure("arbitrate 70/30", &[arbitrate_ix(&s, arbiter.pubkey(), 7_000)], &[&arbiter]);

    let mut timed = h.terms(5);
    timed.timer = Some(Timer { days: 1, to: Side::Seller });
    let e = h.marked(&timed);
    h.advance(DAY);
    let v = vault_address(&e, &h.mint);
    h.measure("timer_release, to the seller", &[timer_release_ix(e, v, h.mint, h.seller_tokens, h.payer.pubkey())], &[]);
    let mut timed = h.terms(6);
    timed.timer = Some(Timer { days: 1, to: Side::Buyer });
    let e = h.marked(&timed);
    h.advance(DAY);
    let v = vault_address(&e, &h.mint);
    h.measure("timer_release, to the buyer", &[timer_release_ix(e, v, h.mint, h.refund(), h.payer.pubkey())], &[]);

    let (e, _) = h.create(&h.terms(7)).expect("create");
    let s = h.accounts(&e);
    h.measure("close_unfunded, nothing paid", &[close_unfunded_ix(&s, seller.pubkey())], &[&seller]);

    // recover_late by a stranger who has to make the buyer's standard account, then sweep_rent.
    let stranger = h.someone();
    let (make, v) = create_ata_idempotent_ix(buyer.pubkey(), e1, h.mint);
    h.send(&[make, spl_transfer_ix(h.buyer_tokens, v, buyer.pubkey(), 1)], &[&buyer]).expect("late money");
    let refund = h.refund();
    let held = h.balance(&refund);
    h.send(&[spl_transfer_ix(refund, h.buyer_tokens, buyer.pubkey(), held)], &[&buyer]).expect("empty it");
    h.drop_refund();
    h.measure(
        "recover_late, making the buyer's account",
        &[recover_late_ix(e1, v, buyer.pubkey(), h.mint, stranger.pubkey())],
        &[&stranger],
    );
    h.svm.set_sysvar(&rent_at(RENT_FINAL));
    let payer = h.payer.pubkey();
    h.measure("sweep_rent", &[sweep_rent_ix(e1, payer)], &[]);

    // object, by the seller, on a live escrow with a timer.
    let mut objected = h.terms(8);
    objected.timer = Some(Timer { days: 7, to: Side::Buyer });
    let e = h.marked(&objected);
    h.measure("object", &[object_ix(e, seller.pubkey())], &[&seller]);
    print_cu_summary();
}
