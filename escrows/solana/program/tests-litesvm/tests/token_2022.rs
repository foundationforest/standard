//! Token-2022: a mint made with every extension Open USD has on mainnet (`src/token_2022.rs`),
//! through every way into and out of an escrow, with its transfer hook naming no program (as Open
//! USD has it) and naming one; the powers of the dollar's maker, used as a maker would; and the
//! refusals: a mint with a transfer fee, and a token program or an account that is not the mint's.

use forest_escrow_tests::*;
use solana_address::Address;
use solana_instruction::AccountMeta;
use solana_keypair::Keypair;
use solana_signer::Signer;
use spl_tlv_account_resolution::account::ExtraAccountMeta;
use spl_token_2022_interface::extension::{BaseStateWithExtensions, ExtensionType, StateWithExtensions};
use spl_token_2022_interface::state::Account as TokenAccount22;

const HOOKS: [HookProgram; 2] = [HookProgram::None, HookProgram::Test];

/// The test hook's calls since `before`, or zero when the mint names no hook program.
fn calls_since(h: &Harness, before: u64) -> u64 {
    hook_calls(h) - before
}

/// How many transfers a hook named at creation sees for `transfers` transfers.
fn expected(hook: HookProgram, transfers: u64) -> u64 {
    if hook == HookProgram::Test { transfers } else { 0 }
}

fn account_extensions(h: &Harness, account: &Address) -> Vec<ExtensionType> {
    StateWithExtensions::<TokenAccount22>::unpack(&h.account(account).data).unwrap().get_extension_types().unwrap()
}

#[test]
fn the_test_mint_has_open_usds_extensions_in_open_usds_order() {
    let h = Harness::open_usd(HookProgram::None);
    let ours = h.account(&h.mint);
    let mainnet = open_usd_mainnet();
    assert_eq!(ours.owner, TOKEN_2022_PROGRAM);
    assert_eq!(mint_extensions(&ours.data), mint_extensions(&mainnet), "the same extensions, in the same order");
    assert_eq!(ours.data.len(), mainnet.len(), "the same size, with the same name, symbol and address");
    assert_eq!(mainnet.len(), 630);
    // decimals, and a freeze authority set, as on mainnet.
    assert_eq!(ours.data[44], mainnet[44]);
    assert_eq!(&ours.data[46..50], &mainnet[46..50]);
    assert_eq!(&mainnet[46..50], &[1, 0, 0, 0]);
    println!("the test mint: {:?}", mint_extensions(&ours.data));
}

#[test]
fn a_deposit_account_is_made_under_token_2022_with_the_extensions_the_mint_requires() {
    for hook in HOOKS {
        let mut h = Harness::open_usd(hook);
        let (escrow, _) = h.create(&h.terms(1)).expect("create");
        let vault = h.vault(&escrow);
        let account = h.account(&vault);
        assert_eq!(account.owner, TOKEN_2022_PROGRAM);
        assert_eq!(h.escrow(&escrow).vault, vault);
        let mut got = account_extensions(&h, &vault);
        got.sort_by_key(|t| *t as u16);
        let mut want = vec![ExtensionType::ImmutableOwner, ExtensionType::TransferHookAccount, ExtensionType::PausableAccount];
        want.sort_by_key(|t| *t as u16);
        assert_eq!(got, want, "{hook:?}");
        assert!(account.data.len() > 165);
        // A wallet app's plain `Transfer` does not reach it: an account with a hook extension takes
        // only `transfer_checked`, which names the mint.
        let plain = solana_instruction::Instruction { program_id: TOKEN_2022_PROGRAM, ..spl_transfer_ix(h.buyer_tokens, vault, h.buyer.pubkey(), AMOUNT) };
        let buyer = h.buyer.insecure_clone();
        let err = h.send(&[plain], &[&buyer]).expect_err("plain transfer");
        assert!(err.contains("0x1f") || err.contains("Custom(31)"), "MintRequiredForTransfer: {err}");
        h.fund(&escrow, AMOUNT);
        assert_eq!(h.vault_balance(&escrow), AMOUNT);
    }
    println!("the deposit account: Token-2022's, immutable owner, hook and pause account extensions");
}

#[test]
fn release_to_the_seller() {
    for hook in HOOKS {
        let mut h = Harness::open_usd(hook);
        let before = hook_calls(&h);
        let escrow = h.funded(&h.terms(1));
        let rent = h.lamports(&h.vault(&escrow));
        let payer_before = h.lamports(&h.payer.pubkey());
        let meta = h.release_to_seller(&escrow).expect("release");
        assert_eq!(h.balance(&h.seller_tokens), AMOUNT);
        assert_eq!(h.buyer_total(), BUYER_START - AMOUNT);
        h.assert_closed(&h.vault(&escrow), "deposit account");
        assert_eq!(h.lamports(&h.payer.pubkey()), payer_before + rent - 2 * 5_000, "its rent to the payer, which paid the fee");
        let e = h.escrow(&escrow);
        assert_eq!((e.status, e.outcome, e.to_seller, e.to_buyer), (Status::Ended, Some(Outcome::ReleasedToSeller), AMOUNT, 0));
        assert_eq!(ended(&events(&meta.logs)).0, Outcome::ReleasedToSeller);
        assert_eq!(calls_since(&h, before), expected(hook, 2), "{hook:?}: the payment in and the payment out");
    }
}

#[test]
fn release_to_the_buyer_the_refund() {
    for hook in HOOKS {
        let mut h = Harness::open_usd(hook);
        let before = hook_calls(&h);
        let escrow = h.funded(&h.terms(1));
        h.release_to_buyer(&escrow).expect("refund");
        assert_eq!(h.buyer_total(), BUYER_START);
        assert_eq!(h.balance(&h.refund()), AMOUNT, "at the buyer's standard account");
        assert_eq!(h.balance(&h.seller_tokens), 0);
        assert_eq!(h.escrow(&escrow).outcome, Some(Outcome::ReleasedToBuyer));
        assert_eq!(calls_since(&h, before), expected(hook, 2), "{hook:?}");
    }
}

#[test]
fn split_and_arbitrate() {
    for hook in HOOKS {
        let mut h = Harness::open_usd(hook);
        let before = hook_calls(&h);
        let escrow = h.funded(&h.terms(1));
        h.split(&escrow, 6_000).expect("split");
        assert_eq!(h.balance(&h.seller_tokens), 600_000);
        assert_eq!(h.balance(&h.refund()), 400_000);
        assert_eq!(h.escrow(&escrow).outcome, Some(Outcome::Split));
        // Two payouts, each to a different owner, so the hook's accounts differ between them and
        // both sets are forwarded.
        assert_eq!(calls_since(&h, before), expected(hook, 3), "{hook:?}: in, and out to each side");

        let before = hook_calls(&h);
        let t = Terms { arbiter: Some(h.arbiter.pubkey()), ..h.terms(2) };
        let escrow = h.funded(&t);
        h.arbitrate(&escrow, 2_500).expect("arbitrate");
        assert_eq!(h.balance(&h.seller_tokens), 600_000 + 250_000);
        assert_eq!(h.balance(&h.refund()), 400_000 + 750_000);
        assert_eq!(h.escrow(&escrow).outcome, Some(Outcome::Arbitrated));
        assert_eq!(calls_since(&h, before), expected(hook, 3), "{hook:?}");
    }
}

#[test]
fn the_timer_to_either_side() {
    for hook in HOOKS {
        let mut h = Harness::open_usd(hook);
        let before = hook_calls(&h);
        let t = Terms { timer: Some(Timer { days: 1, to: Side::Seller }), ..h.terms(1) };
        let escrow = h.marked(&t);
        h.advance(DAY - 1);
        let err = h.timer_release(&escrow, Side::Seller).expect_err("a second early");
        assert!(err.contains("TimerNotDue"), "{err}");
        h.advance(1);
        h.timer_release(&escrow, Side::Seller).expect("due");
        assert_eq!(h.balance(&h.seller_tokens), AMOUNT);
        assert_eq!(h.escrow(&escrow).outcome, Some(Outcome::TimerReleased));

        let t = Terms { timer: Some(Timer { days: 2, to: Side::Buyer }), ..h.terms(2) };
        let escrow = h.marked(&t);
        h.advance(2 * DAY);
        h.timer_release(&escrow, Side::Buyer).expect("due, to the buyer");
        assert_eq!(h.balance(&h.refund()), AMOUNT);
        assert_eq!(calls_since(&h, before), expected(hook, 4), "{hook:?}");
    }
}

#[test]
fn an_objection_turns_the_timer_off_and_the_parties_split() {
    for hook in HOOKS {
        let mut h = Harness::open_usd(hook);
        let t = Terms { timer: Some(Timer { days: 1, to: Side::Seller }), ..h.terms(1) };
        let escrow = h.marked(&t);
        let buyer = h.buyer.insecure_clone();
        h.object(&escrow, &buyer).expect("the buyer objects");
        h.advance(DAY);
        let err = h.timer_release(&escrow, Side::Seller).expect_err("the timer is off");
        assert!(err.contains("Objected"), "{err}");
        h.split(&escrow, 5_000).expect("both agree");
        let e = h.escrow(&escrow);
        assert_eq!((e.objection, e.outcome, e.to_seller, e.to_buyer), (Some(Side::Buyer), Some(Outcome::Split), 500_000, 500_000));
    }
}

#[test]
fn a_part_payment_goes_back_by_close_unfunded_and_late_money_by_recover_late() {
    for hook in HOOKS {
        let mut h = Harness::open_usd(hook);
        let before = hook_calls(&h);
        let (escrow, _) = h.create(&h.terms(1)).expect("create");
        h.fund(&escrow, AMOUNT / 4);
        let seller = h.seller.insecure_clone();
        h.close_unfunded(&escrow, &seller).expect("close");
        assert_eq!(h.buyer_total(), BUYER_START, "the part payment back");
        h.assert_closed(&escrow, "escrow");
        h.assert_closed(&h.vault(&escrow), "deposit account");
        assert_eq!(calls_since(&h, before), expected(hook, 2), "{hook:?}");

        // An ended escrow paid again: the deposit address is made again under Token-2022, and
        // anyone sends the money back to the buyer.
        let escrow = h.funded(&h.terms(2));
        h.release_to_seller(&escrow).expect("release");
        let buyer = h.buyer.insecure_clone();
        let (make, _) = create_ata_idempotent_ix_under(buyer.pubkey(), escrow, h.mint, h.token_program);
        h.send(&[make], &[&buyer]).expect("the deposit address made again");
        h.fund(&escrow, 300_000);
        let before = hook_calls(&h);
        let refund_before = h.balance(&h.refund());
        let stranger = h.someone();
        let meta = h.recover_late(&escrow, &stranger).expect("recover");
        assert!(names(&events(&meta.logs)).contains(&"RecoveredLate"));
        assert_eq!(h.balance(&h.refund()), refund_before + 300_000);
        h.assert_closed(&h.vault(&escrow), "deposit account again");
        assert_eq!(calls_since(&h, before), expected(hook, 1), "{hook:?}");
    }
}

#[test]
fn one_tap_and_an_invoice_paid_in_one_tap() {
    for hook in HOOKS {
        let mut h = Harness::open_usd(hook);
        let buyer = h.buyer.insecure_clone();
        let t = h.terms(1);
        let escrow = h.address(&t);
        let (make, _) = create_ata_idempotent_ix_under(h.payer.pubkey(), escrow, h.mint, h.token_program);
        let create = h.create_ix(&t, buyer.pubkey());
        // The client resolves the hook's accounts against the chain as it stands; in a one-tap the
        // deposit account does not exist yet, so the hook entry for its owner is resolved from the
        // escrow's key, the same bytes a wallet app reads once it exists.
        let (fund, release) = one_tap_transfers(&mut h, &escrow, &[make.clone(), create.clone()], &buyer);
        let label = format!("one tap, Open USD, hook {hook:?}");
        let (_, bytes, events) = h.measure(&label, &[make, create, fund, release], &[&buyer]);
        assert_eq!(names(&events), vec!["Created", "Ended"]);
        assert_eq!(h.balance(&h.seller_tokens), AMOUNT);
        assert!(bytes <= 1232);

        let seller = h.seller.insecure_clone();
        let (invoice, _) = h.invoice(&h.terms(2)).expect("invoice");
        let (make, _) = create_ata_idempotent_ix_under(h.payer.pubkey(), invoice, h.mint, h.token_program);
        let pay = h.fund_ix(&invoice, AMOUNT);
        let release = h.release_to_seller_ix(&invoice);
        let label = format!("an invoice paid in one tap, Open USD, hook {hook:?}");
        h.measure(&label, &[make, pay, release], &[&buyer]);
        assert_eq!(h.balance(&h.seller_tokens), 2 * AMOUNT);
        let _ = seller;
    }
}

/// The transfer into a deposit account that `before` makes, and the release after it, each with
/// the hook's accounts: resolved in a scratch copy of the ledger where `before` has run, as a
/// client simulating the transaction would.
fn one_tap_transfers(h: &mut Harness, escrow: &Address, before: &[solana_instruction::Instruction], buyer: &Keypair) -> (solana_instruction::Instruction, solana_instruction::Instruction) {
    let snapshot = h.svm.clone();
    h.send(before, &[buyer]).expect("the deposit address and the escrow, in a scratch run");
    let fund = h.fund_ix(escrow, AMOUNT);
    let release = h.release_to_seller_ix(escrow);
    h.svm = snapshot;
    (fund, release)
}

#[test]
fn a_hook_switched_on_after_funding_is_honoured_by_forwarding_its_accounts() {
    let mut h = Harness::open_usd(HookProgram::None);
    let escrow = h.funded(&h.terms(1));
    let without = h.release_to_seller_ix(&escrow);
    assert_eq!(without.accounts.len(), 7, "no hook, nothing forwarded");
    set_hook_program(&mut h, Some(TEST_HOOK_PROGRAM));

    // The same instruction as before the switch: Token-2022 now needs the hook's accounts.
    let buyer = h.buyer.insecure_clone();
    let err = h.send(&[without], &[&buyer]).expect_err("without the hook's accounts");
    assert!(err.contains("IncorrectAccount") || err.contains("MissingAccount") || err.contains("NotEnoughAccountKeys"), "{err}");
    assert_eq!(h.vault_balance(&escrow), AMOUNT, "nothing moved");

    let before = hook_calls(&h);
    let with = h.release_to_seller_ix(&escrow);
    assert!(with.accounts.len() > 7);
    h.send(&[with], &[&buyer]).expect("with them, resolved by the client");
    assert_eq!(h.balance(&h.seller_tokens), AMOUNT);
    assert_eq!(calls_since(&h, before), 1);

    // And switched off again: the forwarded accounts are ignored.
    let escrow = h.funded(&h.terms(2));
    let with = h.release_to_seller_ix(&escrow);
    set_hook_program(&mut h, None);
    h.send(&[with], &[&buyer]).expect("extra accounts, no hook");
    assert_eq!(h.balance(&h.seller_tokens), 2 * AMOUNT);
}

#[test]
fn every_hook_account_is_needed_and_each_keeps_its_writability() {
    let mut h = Harness::open_usd(HookProgram::Test);
    let buyer = h.buyer.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    let full = h.release_to_seller_ix(&escrow);
    let named = 7;
    let extras = hook_metas_of(&full, named);
    // counter (writable), holder entry, hook program, validation account.
    assert_eq!(extras.len(), 4, "{extras:?}");
    assert!(extras.iter().any(|m| m.pubkey == hook_counter() && m.is_writable));
    assert!(extras.iter().any(|m| m.pubkey == hook_holder_entry(&h.seller.pubkey())));
    assert!(extras.iter().any(|m| m.pubkey == TEST_HOOK_PROGRAM));
    assert!(extras.iter().any(|m| m.pubkey == hook_validation(&h.mint)));
    assert!(extras.iter().all(|m| !m.is_signer));

    for dropped in 0..extras.len() {
        let mut ix = full.clone();
        ix.accounts.remove(named + dropped);
        let err = h.send(&[ix], &[&buyer]).expect_err("an account missing");
        assert!(!err.is_empty(), "{:?}", extras[dropped]);
        assert_eq!(h.vault_balance(&escrow), AMOUNT, "nothing moved without {:?}", extras[dropped].pubkey);
    }
    // The counter passed read-only: the escrow forwards it as it came, so the hook cannot write.
    let mut ix = full.clone();
    for m in ix.accounts[named..].iter_mut().filter(|m| m.pubkey == hook_counter()) {
        m.is_writable = false;
    }
    let err = h.send(&[ix], &[&buyer]).expect_err("the counter read-only");
    assert!(!err.is_empty());
    assert_eq!(h.vault_balance(&escrow), AMOUNT);
    // Accounts nobody asked for are passed along and ignored.
    let mut ix = full.clone();
    ix.accounts.push(AccountMeta::new_readonly(Address::new_unique(), false));
    ix.accounts.push(AccountMeta::new(h.seller_other, false));
    h.send(&[ix], &[&buyer]).expect("with extra accounts");
    assert_eq!(h.balance(&h.seller_tokens), AMOUNT);
}

#[test]
fn the_escrow_hands_the_token_program_no_signature_but_its_own() {
    // Whatever the transaction marks as signing among the forwarded accounts (here the seller,
    // who signs the split, and the fee payer), the escrow's `transfer_checked` carries them
    // without it: a spy standing in for Token-2022 refuses any forwarded signer, and the split
    // goes through it. The escrow's own signature, as authority, is the only one.
    let mut h = Harness::open_usd(HookProgram::Test);
    let seller = h.seller.insecure_clone();
    let buyer = h.buyer.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    let s = h.accounts(&escrow);
    let mut ix = h.with_hook(split_ix(&s, buyer.pubkey(), seller.pubkey(), 5_000), s.vault, &[s.seller_tokens, s.buyer_tokens], escrow);
    assert!(ix.accounts[9..].iter().all(|m| !m.is_signer), "SPL's resolver asks for no signer");
    ix.accounts.push(AccountMeta::new_readonly(seller.pubkey(), true));
    ix.accounts.push(AccountMeta::new(h.payer.pubkey(), true));

    // The spy sees what a direct call would hand it: the same signers, refused.
    spy_on_token_2022(&mut h);
    let direct = solana_instruction::Instruction {
        program_id: TOKEN_2022_PROGRAM,
        accounts: vec![
            AccountMeta::new(s.vault, false),
            AccountMeta::new_readonly(h.mint, false),
            AccountMeta::new(s.seller_tokens, false),
            AccountMeta::new_readonly(buyer.pubkey(), true),
            AccountMeta::new_readonly(seller.pubkey(), true),
        ],
        data: vec![12, 0, 0, 0, 0, 0, 0, 0, 0, 6],
    };
    let err = h.send(&[direct], &[&buyer, &seller]).expect_err("the spy sees a signer when one is handed to it");
    assert!(err.contains(&format!("Custom({SPY_SAW_A_FORWARDED_SIGNER})")), "{err}");
    h.send(&[ix], &[&buyer, &seller]).expect("through the escrow, no forwarded account signs");
    println!("the escrow's transfer_checked: its own signature as authority, none forwarded");
}

#[test]
fn a_hook_that_asks_for_a_signature_gets_none() {
    // The list the dollar's maker set names the seller as a signer. SPL's resolver drops the flag,
    // so a client following it passes the seller as a plain account; a client that marks it signing
    // anyway, with the seller signing the split, still hands the hook nothing: the escrow forwards
    // it without the signature, and the hook, which refuses any signer, lets the split through.
    let mut h = Harness::open_usd(HookProgram::Test);
    let seller = h.seller.insecure_clone();
    let buyer = h.buyer.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    let mut asks = test_hook_accounts();
    asks.push(ExtraAccountMeta::new_with_pubkey(&seller.pubkey(), true, false).unwrap());
    set_hook_list(&mut h, &asks);
    let s = h.accounts(&escrow);
    let mut ix = h.with_hook(split_ix(&s, buyer.pubkey(), seller.pubkey(), 5_000), s.vault, &[s.seller_tokens, s.buyer_tokens], escrow);
    for m in ix.accounts[9..].iter_mut().filter(|m| m.pubkey == seller.pubkey()) {
        m.is_signer = true;
    }
    let before = hook_calls(&h);
    h.send(&[ix], &[&buyer, &seller]).expect("the hook saw no signer");
    assert_eq!(calls_since(&h, before), 2);
    assert_eq!(h.balance(&h.seller_tokens), 500_000);
}

#[test]
fn the_issuer_can_pause_every_transfer() {
    let mut h = Harness::open_usd(HookProgram::None);
    let escrow = h.funded(&h.terms(1));
    let t = Terms { timer: Some(Timer { days: 1, to: Side::Seller }), ..h.terms(2) };
    let timed = h.marked(&t);
    set_paused(&mut h, true);
    for (what, result) in [
        ("release to the seller", h.release_to_seller(&escrow)),
        ("release to the buyer", h.release_to_buyer(&escrow)),
        ("split", h.split(&escrow, 5_000)),
    ] {
        let err = result.expect_err(what);
        assert!(err.contains("0x43") || err.contains("Custom(67)") || err.to_lowercase().contains("paused"), "{what}: {err}");
    }
    h.advance(DAY);
    assert!(h.timer_release(&timed, Side::Seller).is_err(), "the timer too");
    let (fresh, _) = h.create(&h.terms(3)).expect("an escrow can still be opened");
    let buyer = h.buyer.insecure_clone();
    let pay = h.fund_ix(&fresh, AMOUNT);
    assert!(h.send(&[pay], &[&buyer]).is_err(), "and nobody can pay into it");
    // Objecting moves nothing, so it still lands.
    let t = Terms { timer: Some(Timer { days: 5, to: Side::Seller }), ..h.terms(4) };
    set_paused(&mut h, false);
    let objectable = h.marked(&t);
    set_paused(&mut h, true);
    h.object(&objectable, &buyer).expect("an objection needs no transfer");
    assert_eq!(h.vault_balance(&escrow), AMOUNT);

    set_paused(&mut h, false);
    h.release_to_seller(&escrow).expect("resumed");
    h.timer_release(&timed, Side::Seller).expect("resumed");
    assert_eq!(h.balance(&h.seller_tokens), 2 * AMOUNT);
}

#[test]
fn the_issuer_can_freeze_a_deposit_account_or_a_partys_account() {
    let mut h = Harness::open_usd(HookProgram::None);
    let escrow = h.funded(&h.terms(1));
    let vault = h.vault(&escrow);
    set_frozen(&mut h, &vault, true);
    assert!(h.release_to_seller(&escrow).is_err(), "the deposit account frozen");
    assert!(h.release_to_buyer(&escrow).is_err());
    set_frozen(&mut h, &vault, false);

    // The seller's standard account frozen: the seller cannot be paid, but can still give back.
    let seller_tokens = h.seller_tokens;
    set_frozen(&mut h, &seller_tokens, true);
    let err = h.release_to_seller(&escrow).expect_err("the seller's account frozen");
    assert!(err.contains("0x11") || err.contains("Custom(17)"), "AccountFrozen: {err}");
    h.release_to_buyer(&escrow).expect("the seller gives back");
    assert_eq!(h.buyer_total(), BUYER_START);
}

#[test]
fn the_issuer_can_make_new_accounts_start_frozen() {
    // Open USD's default account state is "initialized"; its freeze authority can change it. A
    // deposit account made after that starts frozen, and nothing can be paid into it until thawed.
    let mut h = Harness::open_usd(HookProgram::None);
    let freezer = h.issuer.as_ref().unwrap().freezer.insecure_clone();
    let ix = spl_token_2022_interface::extension::default_account_state::instruction::update_default_account_state(
        &TOKEN_2022_PROGRAM,
        &h.mint,
        &freezer.pubkey(),
        &[],
        &spl_token_2022_interface::state::AccountState::Frozen,
    )
    .unwrap();
    h.send(&[ix], &[&freezer]).expect("frozen by default");
    let (escrow, _) = h.create(&h.terms(1)).expect("create still works");
    let buyer = h.buyer.insecure_clone();
    let pay = h.fund_ix(&escrow, AMOUNT);
    assert!(h.send(&[pay], &[&buyer]).is_err(), "a frozen deposit account takes nothing");
    let vault = h.vault(&escrow);
    set_frozen(&mut h, &vault, false);
    h.fund(&escrow, AMOUNT);
    h.release_to_seller(&escrow).expect("thawed");
}

#[test]
fn the_permanent_delegate_can_take_the_money_and_the_escrow_then_ends_only_by_close() {
    let mut h = Harness::open_usd(HookProgram::None);
    let t = Terms { timer: Some(Timer { days: 1, to: Side::Seller }), ..h.terms(1) };
    let escrow = h.marked(&t);
    let vault = h.vault(&escrow);
    let elsewhere = make_other_account(&mut h, &Address::new_unique());
    // No party signs: the delegate alone moves money out of the deposit account.
    delegate_takes(&mut h, &vault, &elsewhere, 1).expect("the delegate takes a unit");
    assert_eq!(h.vault_balance(&escrow), AMOUNT - 1);
    let err = h.release_to_seller(&escrow).expect_err("no longer holds the amount");
    assert!(err.contains("NotFunded"), "{err}");
    h.advance(DAY);
    let err = h.timer_release(&escrow, Side::Seller).expect_err("the timer too");
    assert!(err.contains("NotFunded"), "{err}");
    // Put back, the escrow is funded again; taken, it closes like one that never held the amount,
    // what is left to the buyer, though its funding was marked.
    delegate_takes(&mut h, &elsewhere, &vault, 1).expect("back");
    let s = h.accounts(&escrow);
    let release = h.with_hook(release_to_seller_ix(&s, h.buyer.pubkey()), s.vault, &[s.seller_tokens], escrow);
    let buyer = h.buyer.insecure_clone();
    h.send(&[release.clone()], &[&buyer]).expect("funded again");
    assert_eq!(h.balance(&h.seller_tokens), AMOUNT);

    let escrow = h.marked(&h.terms(2));
    let vault = h.vault(&escrow);
    delegate_takes(&mut h, &vault, &elsewhere, AMOUNT / 2).expect("half");
    let seller = h.seller.insecure_clone();
    h.close_unfunded(&escrow, &seller).expect("closed");
    assert_eq!(h.buyer_total(), BUYER_START - AMOUNT - AMOUNT / 2, "half back to the buyer; the delegate kept the rest");
    h.assert_closed(&escrow, "escrow");
}

#[test]
fn a_transfer_fee_mint_is_refused_at_create() {
    let mut h = Harness::open_usd(HookProgram::None);
    let buyer = h.buyer.insecure_clone();
    for bps in [0u16, 50] {
        let fee_mint = transfer_fee_mint(&mut h, bps);
        let a = CreateAccounts { mint: fee_mint, ..h.create_accounts() };
        let id = 10 + u64::from(bps);
        let err = h.send(&[create_ix_under(&h.terms(id), &a, buyer.pubkey(), TOKEN_2022_PROGRAM)], &[&buyer]).expect_err("a transfer fee");
        assert!(err.contains("TransferFee"), "{bps} bps: {err}");
        let escrow = escrow_address(&h.terms(id), &buyer.pubkey(), &fee_mint);
        assert!(!h.exists(&escrow), "nothing written");
        assert!(!h.exists(&ata_address_under(&escrow, &fee_mint, &TOKEN_2022_PROGRAM)), "not even the deposit account");
    }
    println!("a Token-2022 mint with a transfer fee, even at zero: refused at create, nothing written");
}

#[test]
fn a_non_transferable_mint_is_refused_at_create() {
    // Nothing could be paid into its deposit account, and what the token's maker minted there could
    // never leave: the escrow and both rents would be stuck.
    let mut h = Harness::open_usd(HookProgram::None);
    let buyer = h.buyer.insecure_clone();
    let (mint, _) = one_extension_mint(&mut h, OneExtension::NonTransferable);
    let a = CreateAccounts { mint, ..h.create_accounts() };
    let err = h.send(&[create_ix_under(&h.terms(1), &a, buyer.pubkey(), TOKEN_2022_PROGRAM)], &[&buyer]).expect_err("non-transferable");
    assert!(err.contains("NonTransferable"), "{err}");
    let escrow = escrow_address(&h.terms(1), &buyer.pubkey(), &mint);
    assert!(!h.exists(&escrow), "nothing written");
    assert!(!h.exists(&ata_address_under(&escrow, &mint, &TOKEN_2022_PROGRAM)), "not even the deposit account");
}

#[test]
fn interest_bearing_and_scaled_mints_deal_in_raw_amounts_and_only_their_display_drifts() {
    for extension in [OneExtension::InterestBearing(500), OneExtension::ScaledUiAmount(2.0)] {
        let mut h = Harness::open_usd(HookProgram::None);
        let (mint, authority) = one_extension_mint(&mut h, extension);
        use_mint(&mut h, mint, &authority);
        let t = Terms { timer: Some(Timer { days: 30, to: Side::Seller }), ..h.terms(1) };
        let escrow = h.marked(&t);
        let before = shown(&mut h, AMOUNT);
        // A year passes, or the token's maker changes the scale: what the amount shows moves.
        h.advance(365 * DAY);
        if let OneExtension::ScaledUiAmount(_) = extension {
            let ix = spl_token_2022_interface::extension::scaled_ui_amount::instruction::update_multiplier(
                &TOKEN_2022_PROGRAM,
                &mint,
                &authority.pubkey(),
                &[],
                3.0,
                0,
            )
            .unwrap();
            h.send(&[ix], &[&authority]).expect("the token's maker rescales");
        }
        let after = shown(&mut h, AMOUNT);
        assert_ne!(before, after, "{extension:?}: the display drifted ({before} to {after})");
        // The escrow holds and pays raw amounts: exactly the amount, whatever it shows.
        assert_eq!(h.vault_balance(&escrow), AMOUNT);
        h.timer_release(&escrow, Side::Seller).expect("the timer");
        assert_eq!(h.balance(&h.seller_tokens), AMOUNT, "{extension:?}");
        let e = h.escrow(&escrow);
        assert_eq!((e.amount, e.to_seller), (AMOUNT, AMOUNT));
        println!("{extension:?}: {AMOUNT} raw shown as {before}, then {after}; paid {AMOUNT} raw");
    }
}

#[test]
fn a_plain_token_2022_mint_works_too() {
    let mut h = Harness::open_usd(HookProgram::None);
    let plain = plain_2022_mint(&mut h);
    let buyer = h.buyer.insecure_clone();
    let a = CreateAccounts { mint: plain, ..h.create_accounts() };
    h.send(&[create_ix_under(&h.terms(1), &a, buyer.pubkey(), TOKEN_2022_PROGRAM)], &[&buyer]).expect("create");
    let escrow = escrow_address(&h.terms(1), &buyer.pubkey(), &plain);
    assert_eq!(h.account(&ata_address_under(&escrow, &plain, &TOKEN_2022_PROGRAM)).owner, TOKEN_2022_PROGRAM);
    let seller = h.seller.insecure_clone();
    let s = Accounts {
        vault: ata_address_under(&escrow, &plain, &TOKEN_2022_PROGRAM),
        mint: plain,
        buyer_tokens: standard_2022(&buyer.pubkey(), &plain),
        seller_tokens: standard_2022(&seller.pubkey(), &plain),
        ..h.accounts(&escrow)
    };
    h.send(&[close_unfunded_ix(&s, seller.pubkey())], &[&seller]).expect("closed, nothing paid");
    h.assert_closed(&escrow, "escrow");
}

#[test]
fn only_the_mints_token_program_and_the_standard_accounts_under_it() {
    let mut h = Harness::open_usd(HookProgram::None);
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    let base = h.accounts(&escrow);

    // The classic token program named for a Token-2022 mint.
    let mut ix = release_to_seller_ix(&base, buyer.pubkey());
    ix.accounts[5].pubkey = TOKEN_PROGRAM;
    let err = h.send(&[ix], &[&buyer]).expect_err("the classic program");
    assert!(err.contains("ConstraintMintTokenProgram"), "{err}");

    // The seller's address under the classic program, or another account of the seller's.
    for (what, other) in [("the classic-program address", ata_address(&seller.pubkey(), &h.mint)), ("another account", h.seller_other)] {
        let s = Accounts { seller_tokens: other, ..base };
        let err = h.send(&[release_to_seller_ix(&s, buyer.pubkey())], &[&buyer]).expect_err(what);
        assert!(err.contains("NotTheSellersAccount"), "{what}: {err}");
    }
    // The buyer's likewise.
    let s = Accounts { buyer_tokens: ata_address(&buyer.pubkey(), &h.mint), ..base };
    let err = h.send(&[release_to_buyer_ix(&s, seller.pubkey())], &[&seller]).expect_err("the classic-program refund address");
    assert!(err.contains("NotTheRefundAddress"), "{err}");
    // Another mint named beside this escrow's.
    let other = plain_2022_mint(&mut h);
    let s = Accounts { mint: other, ..base };
    let err = h.send(&[release_to_seller_ix(&s, buyer.pubkey())], &[&buyer]).expect_err("another mint");
    assert!(err.contains("ConstraintHasOne"), "{err}");

    assert_eq!(h.vault_balance(&escrow), AMOUNT, "nothing moved");
    h.release_to_seller(&escrow).expect("the right accounts");
}

#[test]
fn what_each_way_out_costs_under_token_2022() {
    for hook in HOOKS {
        let mut h = Harness::open_usd(hook);
        let buyer = h.buyer.insecure_clone();
        let seller = h.seller.insecure_clone();
        let tag = if hook == HookProgram::Test { "with a hook" } else { "no hook program" };

        let create = h.create_ix(&h.terms(1), buyer.pubkey());
        h.measure(&format!("create, Open USD, {tag}"), &[create], &[&buyer]);
        let e1 = h.address(&h.terms(1));
        h.fund(&e1, AMOUNT);
        let ix = h.release_to_seller_ix(&e1);
        h.measure(&format!("release_to_seller, Open USD, {tag}"), &[ix], &[&buyer]);

        let e2 = h.funded(&h.terms(2));
        let s = h.accounts(&e2);
        let ix = h.with_hook(split_ix(&s, buyer.pubkey(), seller.pubkey(), 5_000), s.vault, &[s.seller_tokens, s.buyer_tokens], e2);
        h.measure(&format!("split, Open USD, {tag}"), &[ix], &[&buyer, &seller]);
    }
}

#[test]
fn zz_cu_summary() {
    print_cu_summary();
}
