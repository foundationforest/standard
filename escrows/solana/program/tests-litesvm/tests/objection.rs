//! The objection, v2's one new instruction.
//!
//! Either party may object once per escrow, at any time before the timer is due. After an
//! objection the timer never runs: the money moves only by the parties agreeing (a release or a
//! split) or by the arbiter, if one was named at creation. The receipt records who objected and
//! when, and `Objected` is emitted.
//!
//! Run with `cargo test --test objection -- --nocapture` to see what each case did.

use forest_escrow_tests::*;
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;

/// A timer of three days to `to`, and the arbiter named: marked at `T0`, so due at `T0 + 3 days`.
fn timed(h: &mut Harness, id: u64, to: Side) -> Address {
    h.set_time(T0);
    let t = Terms { arbiter: Some(h.arbiter.pubkey()), timer: Some(Timer { days: 3, to }), ..h.terms(id) };
    h.marked(&t)
}

const DUE: i64 = T0 + 3 * DAY;

fn party(h: &Harness, side: Side) -> Keypair {
    match side {
        Side::Buyer => h.buyer.insecure_clone(),
        Side::Seller => h.seller.insecure_clone(),
    }
}

#[test]
fn either_side_objects_before_the_timer_is_due_and_then_the_timer_never_runs() {
    // Every pair of (who objects, whom the timer pays): the side the timer favours may object too,
    // and it turns off its own timer.
    let mut h = Harness::new();
    let mut id = 0;
    for objector in [Side::Buyer, Side::Seller] {
        for to in [Side::Buyer, Side::Seller] {
            id += 1;
            let escrow = timed(&mut h, id, to);
            let who = party(&h, objector);
            let (vault_before, seller_before, refund_before) = (h.vault_balance(&escrow), h.balance(&h.seller_tokens), h.balance(&h.refund()));

            // The last second before the timer is due.
            h.set_time(DUE - 1);
            let meta = h.object(&escrow, &who).unwrap_or_else(|e| panic!("{objector:?} objects to a timer to the {to:?}: {e}"));
            assert_eq!(events(&meta.logs), [Event::Objected { escrow, by: objector, objected_at: DUE - 1 }]);
            let e = h.escrow(&escrow);
            assert_eq!((e.objection, e.objected_at, e.status), (Some(objector), DUE - 1, Status::Funded));
            assert_eq!(
                (h.vault_balance(&escrow), h.balance(&h.seller_tokens), h.balance(&h.refund())),
                (vault_before, seller_before, refund_before),
                "an objection moves no money"
            );

            // Due, and long after: the timer is off for good.
            for at in [DUE, DUE + 1_000 * DAY] {
                h.set_time(at);
                let err = h.timer_release(&escrow, to).expect_err("the timer after an objection");
                assert!(err.contains("Objected"), "{objector:?}, timer to the {to:?}, at {at}: {err}");
            }
            assert_eq!(h.vault_balance(&escrow), vault_before);
        }
    }
    println!("objected a second before due, by each side, to a timer to each side: the timer refused at due and a thousand days later; nothing moved");
}

#[test]
fn an_objection_from_the_moment_the_timer_is_due_is_refused() {
    // The one deadline, `timer_due`, splits the two: before it only an objection lands, from it on
    // only the timer. At the due second, and after, an objection is refused, and the timer runs.
    let mut h = Harness::new();
    let mut id = 0;
    for objector in [Side::Buyer, Side::Seller] {
        for to in [Side::Buyer, Side::Seller] {
            id += 1;
            let escrow = timed(&mut h, id, to);
            let who = party(&h, objector);
            for at in [DUE, DUE + 1] {
                h.set_time(at);
                let err = h.object(&escrow, &who).expect_err("an objection once the timer is due");
                assert!(err.contains("TimerDue"), "{objector:?}, timer to the {to:?}, at {at}: {err}");
            }
            // In one transaction with the timer, in either order: the objection fails, so neither lands.
            let vault = vault_address(&escrow, &h.mint);
            let to_account = match to {
                Side::Buyer => h.refund(),
                Side::Seller => h.seller_tokens,
            };
            let release = timer_release_ix(escrow, vault, h.mint, to_account, h.payer.pubkey());
            let err = h.send(&[object_ix(escrow, who.pubkey()), release.clone()], &[&who]).expect_err("object, then the timer");
            assert!(err.contains("TimerDue"), "{err}");
            let err = h.send(&[release, object_ix(escrow, who.pubkey())], &[&who]).expect_err("the timer, then object");
            assert!(err.contains("Ended"), "{err}");
            assert_eq!(h.escrow(&escrow).objection, None);

            // The timer runs; after the end, an objection is refused as ended, and the receipt says
            // nobody objected.
            h.timer_release(&escrow, to).expect("the timer, due and unobjected");
            let err = h.object(&escrow, &who).expect_err("an objection after the end");
            assert!(err.contains("Ended"), "{err}");
            let e = h.escrow(&escrow);
            assert_eq!((e.outcome, e.objection, e.objected_at), (Some(Outcome::TimerReleased), None, 0));
        }
    }
    println!("an objection at due, a second after, beside the timer in one transaction, and after the end: refused; the timer ran");
}

#[test]
fn an_escrow_takes_one_objection() {
    // Twice by the same side, then by the other: refused, and the receipt keeps the first.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let escrow = timed(&mut h, 1, Side::Seller);
    h.set_time(T0 + DAY);
    h.object(&escrow, &buyer).expect("the buyer objects");
    h.advance(60);
    let err = h.object(&escrow, &buyer).expect_err("the buyer again");
    assert!(err.contains("AlreadyObjected"), "{err}");
    let err = h.object(&escrow, &seller).expect_err("the seller after the buyer");
    assert!(err.contains("AlreadyObjected"), "{err}");
    // Two objections in one transaction: the second fails, so neither lands.
    let other = timed(&mut h, 2, Side::Buyer);
    let err = h
        .send(&[object_ix(other, seller.pubkey()), object_ix(other, buyer.pubkey())], &[&seller, &buyer])
        .expect_err("two in one transaction");
    assert!(err.contains("AlreadyObjected"), "{err}");
    assert_eq!(h.escrow(&other).objection, None);
    let e = h.escrow(&escrow);
    assert_eq!((e.objection, e.objected_at), (Some(Side::Buyer), T0 + DAY), "the first objection stands");
    println!("one objection per escrow: the same side twice, the other side after, and two in one transaction refused");
}

#[test]
fn a_stranger_the_arbiter_or_the_payer_cannot_object() {
    let mut h = Harness::new();
    let arbiter = h.arbiter.insecure_clone();
    let stranger = h.someone();
    let escrow = timed(&mut h, 1, Side::Seller);
    h.set_time(T0 + DAY);
    for (who, key) in [("a stranger", &stranger), ("the arbiter", &arbiter)] {
        let err = h.object(&escrow, key).expect_err(who);
        assert!(err.contains("NotAnObjector"), "{who}: {err}");
    }
    // The key that fronted the rent, which also signs every transaction here.
    let payer = h.payer.pubkey();
    let err = h.send(&[object_ix(escrow, payer)], &[]).expect_err("the payer");
    assert!(err.contains("NotAnObjector"), "{err}");
    // The buyer's key without the buyer's signature.
    let mut ix = object_ix(escrow, h.buyer.pubkey());
    ix.accounts[1].is_signer = false;
    let err = h.send(&[ix], &[]).expect_err("unsigned");
    assert!(err.contains("AccountNotSigner"), "{err}");
    assert_eq!(h.escrow(&escrow).objection, None);
    h.set_time(DUE);
    h.timer_release(&escrow, Side::Seller).expect("nobody objected, so the timer runs");
    println!("refused as expected: a stranger, the arbiter and the fee payer cannot object, nor the buyer's key unsigned");
}

#[test]
fn after_an_objection_the_parties_agreeing_or_the_arbiter_end_it() {
    // Each way out but the timer, on an escrow a party objected to. The receipt keeps the
    // objection past the end.
    let mut h = Harness::new();
    let seller = h.seller.insecure_clone();
    let ways: [(&str, Side, Outcome, u64, u64); 5] = [
        ("release_to_seller", Side::Seller, Outcome::ReleasedToSeller, AMOUNT, 0),
        ("release_to_buyer", Side::Buyer, Outcome::ReleasedToBuyer, 0, AMOUNT),
        ("split", Side::Buyer, Outcome::Split, 600_000, 400_000),
        ("arbitrate", Side::Seller, Outcome::Arbitrated, 250_000, 750_000),
        ("arbitrate to one side", Side::Buyer, Outcome::Arbitrated, AMOUNT, 0),
    ];
    for (id, (how, objector, outcome, to_seller, to_buyer)) in ways.into_iter().enumerate() {
        let escrow = timed(&mut h, id as u64, Side::Seller);
        h.set_time(T0 + DAY);
        h.object(&escrow, &party(&h, objector)).expect("object");
        h.set_time(DUE + DAY);
        let (seller_before, refund_before) = (h.balance(&h.seller_tokens), h.balance(&h.refund()));
        let result = match how {
            "release_to_seller" => h.release_to_seller(&escrow),
            "release_to_buyer" => h.release_to_buyer(&escrow),
            "split" => h.split(&escrow, 6_000),
            "arbitrate" => h.arbitrate(&escrow, 2_500),
            _ => h.arbitrate(&escrow, 10_000),
        };
        let meta = result.unwrap_or_else(|e| panic!("{how} after the {objector:?} objected: {e}"));
        assert_eq!(ended(&events(&meta.logs)).0, outcome, "{how}");
        assert_eq!((h.balance(&h.seller_tokens) - seller_before, h.balance(&h.refund()) - refund_before), (to_seller, to_buyer), "{how}");
        let e = h.escrow(&escrow);
        assert_eq!((e.status, e.outcome, e.objection, e.objected_at), (Status::Ended, Some(outcome), Some(objector), T0 + DAY), "{how}: the receipt keeps the objection");
        assert_eq!((e.funded_at, e.ended_at), (T0, DUE + DAY), "{how}: the mark's time and the ending's");
    }

    // With no arbiter named, only the parties can end an objected escrow.
    h.set_time(T0);
    let t = Terms { timer: Some(Timer { days: 1, to: Side::Buyer }), ..h.terms(20) };
    let escrow = h.marked(&t);
    h.object(&escrow, &seller).expect("the seller objects to a refund timer");
    h.advance(10 * DAY);
    let err = h.timer_release(&escrow, Side::Buyer).expect_err("the buyer's timer");
    assert!(err.contains("Objected"), "{err}");
    let arbiter = h.arbiter.insecure_clone();
    let s = h.accounts(&escrow);
    let err = h.send(&[arbitrate_ix(&s, arbiter.pubkey(), 0)], &[&arbiter]).expect_err("no arbiter");
    assert!(err.contains("NoArbiter"), "{err}");
    h.split(&escrow, 5_000).expect("both agree on half each");
    println!("after an objection: both releases, a split, the arbiter's splits; the timer and a would-be arbiter refused; the receipt keeps the objection");
}

#[test]
fn an_objection_before_the_money_or_the_mark_turns_the_timer_off_all_the_same() {
    // A buyer who reads an invoice with a one-day timer to the seller can object before paying.
    // The escrow is still funded, marked and ended as usual; only the timer is gone.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let t = Terms { timer: Some(Timer { days: 1, to: Side::Seller }), ..h.terms(1) };
    let (invoice, _) = h.invoice(&t).expect("invoice");
    h.object(&invoice, &buyer).expect("the buyer objects before paying");
    h.advance(60);
    h.fund(&invoice, AMOUNT);
    let meta = h.mark_funded(&invoice).expect("marking still records the time");
    assert_eq!(names(&events(&meta.logs)), ["Funded"]);
    h.advance(2 * DAY);
    let err = h.timer_release(&invoice, Side::Seller).expect_err("the seller's timer");
    assert!(err.contains("Objected"), "{err}");
    h.release_to_seller(&invoice).expect("the buyer releases when the work is done");
    let e = h.escrow(&invoice);
    assert_eq!((e.objection, e.objected_at, e.funded_at), (Some(Side::Buyer), T0, T0 + 60));

    // Objected and never funded: close_unfunded is not the timer, and still runs, by either party.
    let t = Terms { timer: Some(Timer { days: 1, to: Side::Buyer }), ..h.terms(2) };
    let (escrow, _) = h.create(&t).expect("create");
    h.object(&escrow, &seller).expect("the seller objects before any money");
    h.fund(&escrow, AMOUNT / 2);
    let meta = h.close_unfunded(&escrow, &seller).expect("close, part paid");
    assert_eq!(names(&events(&meta.logs)), ["Closed"]);
    assert_eq!(h.balance(&h.refund()), AMOUNT / 2, "the part back to the buyer");
    h.assert_closed(&escrow, "the escrow account");
    println!("an objection before any money: the timer is off, the mark and the ways out are not; an objected, part-paid escrow still closes");
}

#[test]
fn an_objection_with_no_timer_is_on_the_receipt_and_nothing_else() {
    // No timer to turn off: the objection is recorded, and every way out is as before.
    let mut h = Harness::new();
    let seller = h.seller.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    h.advance(DAY);
    h.object(&escrow, &seller).expect("the seller objects to an escrow with no timer");
    let err = h.timer_release(&escrow, Side::Seller).expect_err("still no timer");
    assert!(err.contains("NoTimer"), "{err}");
    h.advance(DAY);
    h.release_to_buyer(&escrow).expect("the seller gives it back");
    let e = h.escrow(&escrow);
    assert_eq!((e.outcome, e.objection, e.objected_at), (Some(Outcome::ReleasedToBuyer), Some(Side::Seller), T0 + DAY));
    assert_eq!((e.funded_at, e.ended_at), (T0 + 2 * DAY, T0 + 2 * DAY), "nobody marked it: funded when it ended");

    // A timer whose funding nobody marked is never due, so an objection is never too late.
    let t = Terms { timer: Some(Timer { days: 1, to: Side::Seller }), ..h.terms(2) };
    let escrow = h.funded(&t);
    h.advance(1_000 * DAY);
    let buyer = h.buyer.insecure_clone();
    h.object(&escrow, &buyer).expect("unmarked: a thousand days on");
    println!("no timer: the objection is recorded and changes no way out; an unmarked timer is never too late to object to");
}
