//! The schedule: every move in every state, the window boundaries to the second, the stop, the
//! default, and the one-window schedule that does what v2's timer did.
//!
//! The schedule used throughout: two windows, the payer may take back everything until a day in
//! and half until two days in, then the default pays the recipient. An arbiter is named, so every
//! move has someone to send it.

use forest_escrow_tests::*;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_signer::Signer;

fn two_windows() -> [Window; 2] {
    [window(T0 + DAY, 10_000), window(T0 + 2 * DAY, 5_000)]
}

fn terms(h: &Harness, id: u64) -> Terms {
    Terms { arbiter: Some(h.arbiter.pubkey()), ..h.scheduled(id, &two_windows(), End::Pay) }
}

/// Every state an escrow can be in, by how it got there and what the clock says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Created at the opening, nothing paid in.
    Unfunded,
    /// The amount paid in by a plain transfer, nobody marked it; the first window.
    FundedUnmarked,
    /// Paid in and marked; the first window.
    MarkedWindow1,
    /// Paid in and marked; the second window.
    MarkedWindow2,
    /// Paid in and marked; from the end time on.
    MarkedAfterTheEnd,
    /// Paid in, never marked; from the end time on.
    UnmarkedAfterTheEnd,
    /// Paid in, marked, and stopped by the recipient; the first window.
    StoppedWindow1,
    /// Paid in, marked, stopped in the first window; from the end time on.
    StoppedAfterTheEnd,
    /// Paid in, never marked, stopped in the first window; from the end time on.
    StoppedUnmarkedAfterTheEnd,
    /// Ended by `pay`, and paid into again, so its deposit account is there.
    Ended,
    /// Closed by `close_unfunded`: nothing left at the address.
    Closed,
}

const STATES: [State; 11] = [
    State::Unfunded,
    State::FundedUnmarked,
    State::MarkedWindow1,
    State::MarkedWindow2,
    State::MarkedAfterTheEnd,
    State::UnmarkedAfterTheEnd,
    State::StoppedWindow1,
    State::StoppedAfterTheEnd,
    State::StoppedUnmarkedAfterTheEnd,
    State::Ended,
    State::Closed,
];

/// A fresh harness holding one escrow in `state`.
fn in_state(state: State) -> (Harness, Address) {
    let mut h = Harness::new();
    let recipient = h.recipient.insecure_clone();
    let payer = h.payer.insecure_clone();
    let t = terms(&h, 1);
    let (escrow, _) = h.create(&t).expect("create");
    if state != State::Unfunded && state != State::Closed {
        h.fund(&escrow, AMOUNT);
    }
    if matches!(state, State::MarkedWindow1 | State::MarkedWindow2 | State::MarkedAfterTheEnd | State::StoppedWindow1 | State::StoppedAfterTheEnd | State::Ended) {
        h.mark_funded(&escrow).expect("mark");
    }
    if matches!(state, State::StoppedWindow1 | State::StoppedAfterTheEnd | State::StoppedUnmarkedAfterTheEnd) {
        h.stop(&escrow, &recipient).expect("stop");
    }
    match state {
        State::MarkedWindow2 => h.set_time(T0 + DAY),
        State::MarkedAfterTheEnd | State::UnmarkedAfterTheEnd | State::StoppedAfterTheEnd | State::StoppedUnmarkedAfterTheEnd => h.set_time(T0 + 2 * DAY),
        State::Ended => {
            h.pay(&escrow).expect("pay");
            let (make, vault) = create_ata_idempotent_ix(payer.pubkey(), escrow, h.mint);
            h.send(&[make, spl_transfer_ix(h.payer_wallet, vault, payer.pubkey(), 1)], &[&payer]).expect("a payment after the end");
        }
        State::Closed => {
            h.close_unfunded(&escrow, &payer).expect("close");
        }
        _ => {}
    }
    (h, escrow)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Move {
    MarkFunded,
    Pay,
    Refund,
    TakeBack,
    Stop,
    Agree,
    Decide,
    End,
    CloseUnfunded,
}

const MOVES: [Move; 9] = [Move::MarkFunded, Move::Pay, Move::Refund, Move::TakeBack, Move::Stop, Move::Agree, Move::Decide, Move::End, Move::CloseUnfunded];

/// The move, sent by the key it needs: the payer for take-back, stop and close.
fn send(h: &mut Harness, escrow: &Address, m: Move) -> Result<litesvm::types::TransactionMetadata, String> {
    let payer = h.payer.insecure_clone();
    match m {
        Move::MarkFunded => h.mark_funded(escrow),
        Move::Pay => h.pay(escrow),
        Move::Refund => h.refund(escrow),
        Move::TakeBack => h.take_back(escrow),
        Move::Stop => h.stop(escrow, &payer),
        Move::Agree => h.agree(escrow, 4_000),
        Move::Decide => h.decide(escrow, 4_000),
        Move::End => h.end(escrow, Side::Recipient),
        Move::CloseUnfunded => h.close_unfunded(escrow, &payer),
    }
}

/// What the program must answer: `None` for accepted, or the error it refuses with. The state
/// table in `escrows/solana/README.md`, written out for these states.
fn expected(state: State, m: Move) -> Option<&'static str> {
    use Move::*;
    use State::*;
    match (state, m) {
        (Ended, _) => Some("Ended"),
        (Closed, _) => Some("AccountNotInitialized"),

        (Unfunded, Stop | CloseUnfunded) => None,
        (Unfunded, End) => Some("FundingNotMarked"),
        (Unfunded, _) => Some("NotFunded"),

        // Giving, agreeing and deciding: in every live state with the amount there.
        (_, Pay | Refund | Agree | Decide) => None,

        (FundedUnmarked, MarkFunded | TakeBack | Stop) => None,
        (FundedUnmarked, End) => Some("FundingNotMarked"),
        (FundedUnmarked, CloseUnfunded) => Some("StillFunded"),

        (MarkedWindow1 | MarkedWindow2, MarkFunded) => Some("AlreadyFunded"),
        (MarkedWindow1 | MarkedWindow2, TakeBack | Stop) => None,
        (MarkedWindow1 | MarkedWindow2, End) => Some("ScheduleNotOver"),
        (MarkedWindow1 | MarkedWindow2, CloseUnfunded) => Some("StillFunded"),

        (MarkedAfterTheEnd, MarkFunded) => Some("AlreadyFunded"),
        (MarkedAfterTheEnd, TakeBack | Stop) => Some("ScheduleOver"),
        (MarkedAfterTheEnd, End) => None,
        (MarkedAfterTheEnd, CloseUnfunded) => Some("StillFunded"),

        (UnmarkedAfterTheEnd, MarkFunded | TakeBack | Stop) => Some("ScheduleOver"),
        (UnmarkedAfterTheEnd, End) => Some("FundingNotMarked"),
        (UnmarkedAfterTheEnd, CloseUnfunded) => None,

        (StoppedWindow1 | StoppedAfterTheEnd, MarkFunded) => Some("AlreadyFunded"),
        (StoppedUnmarkedAfterTheEnd, MarkFunded) => Some("ScheduleOver"),
        (StoppedWindow1 | StoppedAfterTheEnd | StoppedUnmarkedAfterTheEnd, TakeBack | End) => Some("Stopped"),
        (StoppedWindow1 | StoppedAfterTheEnd | StoppedUnmarkedAfterTheEnd, Stop) => Some("AlreadyStopped"),
        (StoppedWindow1 | StoppedAfterTheEnd | StoppedUnmarkedAfterTheEnd, CloseUnfunded) => Some("StillFunded"),
    }
}

#[test]
fn every_move_in_every_state() {
    let mut accepted = 0;
    for state in STATES {
        for m in MOVES {
            let (mut h, escrow) = in_state(state);
            let before = h.svm.get_account(&escrow);
            let (recipient_before, payer_before) = (h.balance(&h.recipient_tokens), h.balance(&h.payer_account()));
            let result = send(&mut h, &escrow, m);
            match (expected(state, m), result) {
                (Some(want), Err(err)) => {
                    assert!(err.contains(want), "{state:?}, {m:?}: expected {want}, got\n{err}");
                    assert_eq!(h.svm.get_account(&escrow), before, "{state:?}, {m:?}: a refusal changes nothing");
                }
                (Some(want), Ok(_)) => panic!("{state:?}, {m:?}: accepted, but must be refused with {want}"),
                (None, Err(err)) => panic!("{state:?}, {m:?}: refused, but must be accepted:\n{err}"),
                (None, Ok(meta)) => {
                    accepted += 1;
                    let got = events(&meta.logs);
                    let (recipient_now, payer_now) = (h.balance(&h.recipient_tokens), h.balance(&h.payer_account()));
                    let (to_recipient, to_payer) = (recipient_now - recipient_before, payer_now - payer_before);
                    match m {
                        Move::MarkFunded => assert_eq!(names(&got), ["Funded"], "{state:?}"),
                        Move::Stop => {
                            assert_eq!(names(&got), ["Stopped"], "{state:?}");
                            assert_eq!(h.escrow(&escrow).stop, Some(Side::Payer), "{state:?}");
                            assert_eq!((to_recipient, to_payer), (0, 0), "{state:?}: a stop moves nothing");
                        }
                        Move::CloseUnfunded => {
                            assert_eq!(names(&got), ["Closed"], "{state:?}");
                            h.assert_closed(&escrow, "no receipt");
                            assert_eq!(to_payer, h.balance(&h.payer_account()) - payer_before, "{state:?}");
                        }
                        _ => {
                            let (outcome, balance, r, p, _) = ended(&got);
                            assert_eq!((r, p), (to_recipient, to_payer), "{state:?}, {m:?}: the event says what moved");
                            assert_eq!(balance, AMOUNT, "{state:?}, {m:?}");
                            let want = match m {
                                Move::Pay => (Outcome::Pay, AMOUNT, 0),
                                Move::Refund => (Outcome::Refund, 0, AMOUNT),
                                Move::Agree => (Outcome::Agree, 600_000, 400_000),
                                Move::Decide => (Outcome::Decide, 600_000, 400_000),
                                Move::End => (Outcome::End, AMOUNT, 0),
                                Move::TakeBack if state == State::MarkedWindow2 => (Outcome::TakeBack, 500_000, 500_000),
                                Move::TakeBack => (Outcome::TakeBack, 0, AMOUNT),
                                _ => unreachable!(),
                            };
                            assert_eq!((outcome, to_recipient, to_payer), want, "{state:?}, {m:?}");
                        }
                    }
                }
            }
        }
    }
    println!("{} states x {} moves: {accepted} accepted, the rest refused with their own error", STATES.len(), MOVES.len());
}

#[test]
fn take_back_follows_the_window_in_force_to_the_second() {
    let windows = [window(T0 + DAY, 10_000), window(T0 + 2 * DAY, 5_000), window(T0 + 3 * DAY, 0)];
    // (when, what the payer gets back, or the error)
    let cases: [(i64, Result<u64, &str>); 7] = [
        (T0, Ok(AMOUNT)),
        (T0 + DAY - 1, Ok(AMOUNT)),
        (T0 + DAY, Ok(AMOUNT / 2)),
        (T0 + 2 * DAY - 1, Ok(AMOUNT / 2)),
        (T0 + 2 * DAY, Err("BadShare")),
        (T0 + 3 * DAY - 1, Err("BadShare")),
        (T0 + 3 * DAY, Err("ScheduleOver")),
    ];
    for (at, want) in cases {
        let mut h = Harness::new();
        let escrow = h.marked(&h.scheduled(1, &windows, End::Pay));
        h.set_time(at);
        let before = h.balance(&h.payer_account());
        match (h.take_back(&escrow), want) {
            (Ok(_), Ok(back)) => assert_eq!(h.balance(&h.payer_account()) - before, back, "at {at}"),
            (Err(err), Err(e)) => assert!(err.contains(e), "at {at}: expected {e}, got {err}"),
            (got, want) => panic!("at {at}: got {got:?}, expected {want:?}"),
        }
    }
    println!("take_back to the second: all until a day in, half until two, nothing in the last window, refused from the end time");
}

#[test]
fn stop_and_mark_land_only_before_the_end_time_and_end_only_from_it() {
    // One deadline, read by all three: at no second can a stop and the default both land.
    for (at, before_the_end) in [(T0 + 2 * DAY - 1, true), (T0 + 2 * DAY, false)] {
        let mut h = Harness::new();
        let recipient = h.recipient.insecure_clone();
        let stopped = h.marked(&terms(&h, 1));
        let unmarked = h.funded(&terms(&h, 2));
        let ended = h.marked(&terms(&h, 3));
        h.set_time(at);
        let stop = h.stop(&stopped, &recipient);
        let mark = h.mark_funded(&unmarked);
        let end = h.end(&ended, Side::Recipient);
        if before_the_end {
            stop.expect("a stop a second before the end time");
            mark.expect("a mark a second before the end time");
            assert!(end.expect_err("end a second early").contains("ScheduleNotOver"));
        } else {
            assert!(stop.expect_err("a stop at the end time").contains("ScheduleOver"));
            assert!(mark.expect_err("a mark at the end time").contains("ScheduleOver"));
            end.expect("the default at the end time");
        }
    }

    // A stop and the default in one transaction, in either order, at either second: never both.
    for at in [T0 + 2 * DAY - 1, T0 + 2 * DAY] {
        for stop_first in [true, false] {
            let mut h = Harness::new();
            let recipient = h.recipient.insecure_clone();
            let escrow = h.marked(&terms(&h, 1));
            h.set_time(at);
            let s = h.accounts(&escrow);
            let stop = stop_ix(escrow, recipient.pubkey());
            let end = end_ix(escrow, s.vault, s.mint, s.recipient_tokens, s.sponsor);
            let ixs = if stop_first { [stop, end] } else { [end, stop] };
            let err = h.send(&ixs, &[&recipient]).expect_err("a stop and the default together");
            assert!(err.contains("ScheduleNotOver") || err.contains("ScheduleOver") || err.contains("Stopped") || err.contains("Ended"), "{err}");
            assert_eq!(h.vault_balance(&escrow), AMOUNT, "nothing moved");
            assert_eq!(h.escrow(&escrow).stop, None, "nothing was stopped");
        }
    }
    println!("stop and mark a second before the end time, the default from it; together, never");
}

#[test]
fn a_stop_freezes_the_schedule_and_the_money_leaves_by_giving_agreeing_or_the_arbiter() {
    // Either side stops, once. After it neither take_back nor the default ever runs; each of the
    // four other ways out still ends the escrow, and the receipt keeps who stopped it and when.
    let ways: [(&str, Box<dyn Fn(&mut Harness, &Address) -> Result<litesvm::types::TransactionMetadata, String>>, Outcome); 4] = [
        ("pay", Box::new(|h, e| h.pay(e)), Outcome::Pay),
        ("refund", Box::new(|h, e| h.refund(e)), Outcome::Refund),
        ("agree", Box::new(|h, e| h.agree(e, 2_500)), Outcome::Agree),
        ("decide", Box::new(|h, e| h.decide(e, 7_500)), Outcome::Decide),
    ];
    for (side, (what, way, outcome)) in [Side::Payer, Side::Recipient].into_iter().flat_map(|s| ways.iter().map(move |w| (s, w))) {
        let mut h = Harness::new();
        let stopper = match side {
            Side::Payer => h.payer.insecure_clone(),
            Side::Recipient => h.recipient.insecure_clone(),
        };
        let other = match side {
            Side::Payer => h.recipient.insecure_clone(),
            Side::Recipient => h.payer.insecure_clone(),
        };
        let escrow = h.marked(&terms(&h, 1));
        h.set_time(T0 + 3_600);
        let meta = h.stop(&escrow, &stopper).expect("stop");
        assert_eq!(events(&meta.logs), [Event::Stopped { escrow, by: side, stopped_at: T0 + 3_600 }]);
        let err = h.stop(&escrow, &other).expect_err("the other side, a second stop");
        assert!(err.contains("AlreadyStopped"), "{err}");
        let err = h.take_back(&escrow).expect_err("take_back after a stop");
        assert!(err.contains("Stopped"), "{err}");
        h.set_time(T0 + 1_000 * DAY);
        let err = h.end(&escrow, Side::Recipient).expect_err("the default after a stop, however long");
        assert!(err.contains("Stopped"), "{err}");
        way(&mut h, &escrow).unwrap_or_else(|e| panic!("{what} after a stop by the {side:?}: {e}"));
        let e = h.escrow(&escrow);
        assert_eq!((e.outcome, e.stop, e.stopped_at), (Some(*outcome), Some(side), T0 + 3_600), "{what}: the stop stays on the receipt");
    }
    println!("a stop by either side, once: no take_back and no default, ever; pay, refund, agree and decide each still end it");
}

#[test]
fn a_stop_with_no_schedule_is_on_the_receipt_and_nothing_else() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let escrow = h.marked(&h.terms(1));
    h.advance(10_000 * DAY);
    h.stop(&escrow, &payer).expect("no end time: a stop lands at any time");
    let err = h.take_back(&escrow).expect_err("no schedule");
    assert!(err.contains("NoSchedule"), "{err}");
    h.pay(&escrow).expect("giving still works");
    assert_eq!(h.escrow(&escrow).stop, Some(Side::Payer));

    // A stop before any money comes in turns the schedule off all the same.
    let recipient = h.recipient.insecure_clone();
    h.set_time(T0);
    let escrow = h.address(&terms(&h, 2));
    h.create(&terms(&h, 2)).expect("create");
    h.stop(&escrow, &recipient).expect("a stop before the money");
    h.fund(&escrow, AMOUNT);
    h.mark_funded(&escrow).expect("marked after the stop");
    h.set_time(T0 + 2 * DAY);
    let err = h.end(&escrow, Side::Recipient).expect_err("stopped before the money");
    assert!(err.contains("Stopped"), "{err}");
    println!("a stop with no schedule lands any time and changes only the receipt; one before the money freezes the schedule all the same");
}

#[test]
fn money_that_arrives_after_the_end_time_never_counts_toward_the_default() {
    let mut h = Harness::new();
    let payer = h.payer.insecure_clone();
    let recipient = h.recipient.insecure_clone();

    // An app pays and marks in one transaction: after the end time the mark is refused, so the
    // whole transaction fails and no money moves. Here the payer opens a schedule already past
    // and pays in with the mark, the way `createAndFund` does.
    h.set_time(T0 + 2 * DAY);
    let t = terms(&h, 1);
    let escrow = h.address(&t);
    let vault = h.vault(&escrow);
    let (make, _) = create_ata_idempotent_ix(h.sponsor.pubkey(), escrow, h.mint);
    let ixs = [make, h.create_ix(&t, payer.pubkey()), h.fund_ix(&escrow, AMOUNT), mark_funded_ix(escrow, vault)];
    let wallet = h.balance(&h.payer_wallet);
    let err = h.send(&ixs, &[&payer]).expect_err("opened, paid and marked after the end time");
    assert!(err.contains("ScheduleOver"), "{err}");
    assert_eq!(h.balance(&h.payer_wallet), wallet, "no money moved");
    assert!(!h.exists(&escrow), "nothing was opened");

    // An invoice the recipient opened in time, paid with the mark after its end time: the same.
    h.set_time(T0);
    let (invoice, _) = h.invoice(&terms(&h, 2)).expect("invoice");
    h.set_time(T0 + 2 * DAY);
    let ixs = [h.fund_ix(&invoice, AMOUNT), mark_funded_ix(invoice, h.vault(&invoice))];
    let err = h.send(&ixs, &[&payer]).expect_err("paid and marked after the end time");
    assert!(err.contains("ScheduleOver"), "{err}");
    assert_eq!((h.balance(&h.payer_wallet), h.vault_balance(&invoice)), (wallet, 0), "no money moved");

    // A wallet's plain transfer cannot be refused, and lands. It never counts: nobody can mark it,
    // the default refuses it, and either side closes it, everything back to the payer and no
    // receipt.
    h.fund(&invoice, AMOUNT);
    let err = h.mark_funded(&invoice).expect_err("too late to mark");
    assert!(err.contains("ScheduleOver"), "{err}");
    let err = h.end(&invoice, Side::Recipient).expect_err("never marked");
    assert!(err.contains("FundingNotMarked"), "{err}");
    let rents = h.lamports(&invoice) + h.lamports(&h.vault(&invoice));
    let sponsor = h.lamports(&h.sponsor.pubkey());
    let meta = h.close_unfunded(&invoice, &recipient).expect("closed back to the payer");
    assert_eq!(
        events(&meta.logs),
        [Event::Closed { escrow: invoice, closed_by: recipient.pubkey(), to_payer: AMOUNT, sponsor: h.sponsor.pubkey(), rent_lamports: rents }]
    );
    assert_eq!(h.payer_total(), PAYER_START, "every unit back to the payer");
    assert_eq!(h.lamports(&h.sponsor.pubkey()), sponsor - 2 * 5_000 + rents, "both rents to the sponsor, who paid the fee for two signatures");
    h.assert_closed(&invoice, "no receipt");

    // The same raw payment, made before the end time and marked by the recipient, whose default
    // it is: the default pays it.
    h.set_time(T0);
    let (invoice, _) = h.invoice(&terms(&h, 3)).expect("invoice");
    h.fund(&invoice, AMOUNT);
    h.set_time(T0 + 2 * DAY - 1);
    let vault = h.vault(&invoice);
    h.send(&[mark_funded_ix(invoice, vault)], &[]).expect("the recipient's app marks it, a second before the end time; it needs no signature");
    h.set_time(T0 + 2 * DAY);
    h.end(&invoice, Side::Recipient).expect("the default");
    assert_eq!(h.balance(&h.recipient_tokens), AMOUNT);
    println!("after the end time: pay-and-mark fails whole, a raw payment never counts and closes back to the payer; marked in time, the default pays it");
}

#[test]
fn one_window_does_what_the_v2_timer_did() {
    // v2's timer, "N days, then everything to one side unless a side objects first", is one
    // window whose share is 0 and whose default names that side, counted from the opening.
    for (end, to) in [(End::Pay, Side::Recipient), (End::Refund, Side::Payer)] {
        // Nobody objects: the default pays at the end time, and anyone sends it.
        let mut h = Harness::new();
        let t = h.scheduled(1, &[window(T0 + 7 * DAY, 0)], end);
        let escrow = h.marked(&t);
        let err = h.take_back(&escrow).expect_err("nothing to take back");
        assert!(err.contains("BadShare"), "{err}");
        h.set_time(T0 + 7 * DAY - 1);
        assert!(h.end(&escrow, to).expect_err("a second early").contains("ScheduleNotOver"));
        h.set_time(T0 + 7 * DAY);
        let meta = h.end(&escrow, to).expect("at the end time");
        let (outcome, _, to_recipient, to_payer, _) = ended(&events(&meta.logs));
        assert_eq!(outcome, Outcome::End);
        assert_eq!((to_recipient, to_payer), if to == Side::Recipient { (AMOUNT, 0) } else { (0, AMOUNT) });

        // The other side stops it the day before: the default is off for good, and the two split.
        let mut h = Harness::new();
        let objector = if to == Side::Recipient { h.payer.insecure_clone() } else { h.recipient.insecure_clone() };
        let escrow = h.marked(&h.scheduled(2, &[window(T0 + 7 * DAY, 0)], end));
        h.set_time(T0 + 6 * DAY);
        h.stop(&escrow, &objector).expect("stopped the day before");
        h.set_time(T0 + 1_000 * DAY);
        assert!(h.end(&escrow, to).expect_err("off for good").contains("Stopped"));
        h.agree(&escrow, 4_000).expect("they agree");
        assert_eq!(h.escrow(&escrow).outcome, Some(Outcome::Agree));

        // A stop at the end time is too late, as v2's objection was.
        let mut h = Harness::new();
        let objector = if to == Side::Recipient { h.payer.insecure_clone() } else { h.recipient.insecure_clone() };
        let escrow = h.marked(&h.scheduled(3, &[window(T0 + 7 * DAY, 0)], end));
        h.set_time(T0 + 7 * DAY);
        assert!(h.stop(&escrow, &objector).expect_err("at the end time").contains("ScheduleOver"));
        h.end(&escrow, to).expect("the default");
    }
    println!("one window of share 0: the default at the end time to either side, off for good after a stop, a stop at the end time too late");
}

#[test]
fn the_receipt_and_the_events_carry_the_whole_schedule() {
    let mut h = Harness::new();
    let recipient = h.recipient.insecure_clone();
    let windows = [window(T0 + DAY, 10_000), window(T0 + 2 * DAY, 7_500), window(T0 + 3 * DAY, 2_500), window(T0 + 4 * DAY, 0)];
    let t = h.scheduled(1, &windows, End::Refund);
    let (escrow, meta) = h.create(&t).expect("four windows");
    let Event::Created { window_count, windows: got, end, .. } = events(&meta.logs).remove(0) else { panic!("no Created") };
    assert_eq!((window_count, got, end), (4, windows, End::Refund));
    h.fund(&escrow, AMOUNT);
    h.mark_funded(&escrow).expect("mark");
    h.set_time(T0 + 2 * DAY + 5);
    h.stop(&escrow, &recipient).expect("stop in the third window");
    h.agree(&escrow, 2_500).expect("agree on the third window's share");
    let e = h.escrow(&escrow);
    assert_eq!(e.schedule, Some(Schedule { windows: windows.to_vec(), end: End::Refund }), "the receipt keeps the schedule");
    assert_eq!((e.stop, e.stopped_at, e.funded_at, e.outcome, e.to_payer, e.to_recipient), (Some(Side::Recipient), T0 + 2 * DAY + 5, T0, Some(Outcome::Agree), 250_000, 750_000));
    println!("four windows on the receipt and in Created; the stop and the agreed split beside them");
}

/// Every instruction but `create` names the escrow account first; the error a refused one returns
/// is the program's, so the matrix above reads each by name. This checks the matrix covers every
/// instruction a live escrow takes but `recover_late` and `sweep_rent`, whose own tests are in
/// `escrow.rs`.
#[test]
fn the_matrix_names_every_move() {
    let names: Vec<&str> = MOVES
        .iter()
        .map(|m| match m {
            Move::MarkFunded => "mark_funded",
            Move::Pay => "pay",
            Move::Refund => "refund",
            Move::TakeBack => "take_back",
            Move::Stop => "stop",
            Move::Agree => "agree",
            Move::Decide => "decide",
            Move::End => "end",
            Move::CloseUnfunded => "close_unfunded",
        })
        .collect();
    let h = Harness::new();
    let s = h.accounts(&Address::new_unique());
    let k = Keypair::new().pubkey();
    let built: [Instruction; 9] = [
        mark_funded_ix(s.escrow, s.vault),
        pay_ix(&s, k),
        refund_ix(&s, k),
        take_back_ix(&s, k),
        stop_ix(s.escrow, k),
        agree_ix(&s, k, k, 0),
        decide_ix(&s, k, 0),
        end_ix(s.escrow, s.vault, s.mint, s.recipient_tokens, s.sponsor),
        close_unfunded_ix(&s, k),
    ];
    for (name, ix) in names.iter().zip(built.iter()) {
        assert_eq!(ix.data[..8], discriminator("global", name), "{name}");
        assert_eq!(ix.accounts[0].pubkey, s.escrow, "{name}");
    }
}
