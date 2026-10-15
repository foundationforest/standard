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

/// A fresh buyer whose tokens sit at its standard account, which is also its refund address.
fn new_buyer(h: &mut Harness, tokens: u64) -> (Keypair, Address) {
    let buyer = h.someone();
    let t = refund_address(&buyer.pubkey(), &h.mint);
    h.svm.set_account(t, spl_token_account(&h.mint, &buyer.pubkey(), tokens)).unwrap();
    (buyer, t)
}

// ---------------------------------------------------------------------------------------------
// 1. Account substitution
// ---------------------------------------------------------------------------------------------

#[test]
fn substitution_another_escrows_deposit_account_is_refused() {
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let a = h.funded(&h.terms(1));
    let b = h.funded(&h.terms(2));
    // Release A, but hand it B's deposit account: A's rules paying out B's money.
    let s = Accounts { vault: vault_address(&b, &h.mint), ..h.accounts(&a) };
    let err = h.send(&[release_to_seller_ix(&s, buyer.pubkey())], &[&buyer]).expect_err("must be refused");
    assert!(err.contains("ConstraintHasOne"), "{err}");
    let err = h.send(&[mark_funded_ix(a, s.vault)], &[]).expect_err("A marked by B's money");
    assert!(err.contains("ConstraintHasOne"), "{err}");
    assert_eq!((h.vault_balance(&a), h.vault_balance(&b)), (AMOUNT, AMOUNT));
    println!("rejected as expected: escrow A cannot pay out, or be marked by, escrow B's deposit account");
}

#[test]
fn substitution_a_look_alike_deposit_account_is_refused() {
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    // A token account for the right mint, held by the escrow's own address, but not the one the
    // escrow recorded: anyone can make one of these.
    let look_alike = Address::new_unique();
    h.svm.set_account(look_alike, spl_token_account(&h.mint, &escrow, 5 * AMOUNT)).unwrap();
    let s = Accounts { vault: look_alike, ..h.accounts(&escrow) };
    let err = h.send(&[release_to_seller_ix(&s, buyer.pubkey())], &[&buyer]).expect_err("must be refused");
    assert!(err.contains("ConstraintHasOne"), "{err}");

    // Nor can one be handed to create in place of the associated token account.
    let escrow2 = h.address(&h.terms(2));
    let look_alike2 = Address::new_unique();
    h.svm.set_account(look_alike2, spl_token_account(&h.mint, &escrow2, 0)).unwrap();
    let mut ix = create_ix(&h.terms(2), &h.create_accounts());
    ix.accounts[1].pubkey = look_alike2;
    let err = h.send(&[ix], &[&buyer]).expect_err("must be refused");
    assert!(err.contains("ConstraintAssociated") || err.contains("AccountNotAssociatedTokenAccount") || err.contains("2009") || err.contains("3014"), "{err}");
    assert!(!h.exists(&escrow2));
    println!("rejected as expected: a look-alike deposit account, at a way out and at create");
}

#[test]
fn substitution_payout_accounts_of_the_wrong_mint_owner_or_program_are_refused() {
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    let base = h.accounts(&escrow);

    // The buyer's slot, holding another mint, owned by the buyer.
    let other_mint = Address::new_unique();
    h.svm.set_account(other_mint, spl_mint_account(6, TOKEN_PROGRAM)).unwrap();
    let wrong_mint = Address::new_unique();
    h.svm.set_account(wrong_mint, spl_token_account(&other_mint, &buyer.pubkey(), 0)).unwrap();
    let err = h.send(&[release_to_buyer_ix(&Accounts { buyer_tokens: wrong_mint, ..base }, seller.pubkey())], &[&seller]).expect_err("wrong mint");
    assert!(err.contains("NotTheRefundAddress"), "{err}");

    // The seller puts its own account in the buyer's slot, to catch the buyer's share.
    let err = h
        .send(&[split_ix(&Accounts { buyer_tokens: h.seller_tokens, ..base }, buyer.pubkey(), seller.pubkey(), 5_000)], &[&buyer, &seller])
        .expect_err("the seller's account as the buyer's");
    assert!(err.contains("NotTheRefundAddress"), "{err}");

    // The seller's slot: the buyer's own account, the seller's standard one for another mint, a
    // Token-2022 look-alike. Only the seller's standard account for this mint is paid.
    let err = h.send(&[release_to_seller_ix(&Accounts { seller_tokens: h.refund(), ..base }, buyer.pubkey())], &[&buyer]).expect_err("the buyer's as the seller's");
    assert!(err.contains("NotTheSellersAccount"), "{err}");
    let sellers_other_mint = payout_address(&seller.pubkey(), &other_mint);
    h.svm.set_account(sellers_other_mint, spl_token_account(&other_mint, &seller.pubkey(), 0)).unwrap();
    let err = h.send(&[release_to_seller_ix(&Accounts { seller_tokens: sellers_other_mint, ..base }, buyer.pubkey())], &[&buyer]).expect_err("another mint");
    assert!(err.contains("NotTheSellersAccount"), "{err}");
    let t22 = Address::new_unique();
    h.svm.set_account(t22, token_account_owned_by(TOKEN_2022_PROGRAM, &h.mint, &seller.pubkey(), 0)).unwrap();
    let err = h.send(&[release_to_seller_ix(&Accounts { seller_tokens: t22, ..base }, buyer.pubkey())], &[&buyer]).expect_err("Token-2022 account");
    assert!(err.contains("NotTheSellersAccount"), "{err}");

    // Token-2022 passed as the token program for a classic mint, at a way out and at create: the
    // token program must be the one that owns the mint.
    let mut ix = release_to_seller_ix(&base, buyer.pubkey());
    assert_eq!(ix.accounts[5].pubkey, TOKEN_PROGRAM);
    ix.accounts[5].pubkey = TOKEN_2022_PROGRAM;
    let err = h.send(&[ix], &[&buyer]).expect_err("Token-2022 program");
    assert!(err.contains("ConstraintMintTokenProgram"), "{err}");
    let mut ix = create_ix(&h.terms(2), &h.create_accounts());
    ix.accounts[5].pubkey = TOKEN_2022_PROGRAM;
    let err = h.send(&[ix], &[&buyer]).expect_err("Token-2022 program at create");
    // The deposit address is derived under the token program named, so the associated token
    // program is asked for an address this transaction does not carry.
    assert!(err.contains("MissingAccount"), "{err}");
    // Named with its address under Token-2022 too, the mint is still the classic program's.
    let mut ix = create_ix(&h.terms(2), &h.create_accounts());
    let escrow2 = h.address(&h.terms(2));
    ix.accounts[1].pubkey = ata_address_under(&escrow2, &h.mint, &TOKEN_2022_PROGRAM);
    ix.accounts[5].pubkey = TOKEN_2022_PROGRAM;
    let err = h.send(&[ix], &[&buyer]).expect_err("Token-2022 program and its address at create");
    assert!(err.contains("IncorrectProgramId") || err.contains("ConstraintMintTokenProgram"), "{err}");
    assert!(!h.exists(&escrow2));

    assert_eq!(h.vault_balance(&escrow), AMOUNT, "nothing moved");
    println!("rejected as expected: wrong mint, the other party's account in either slot, a Token-2022 account, Token-2022 as the program");
}

#[test]
fn substitution_an_escrow_shaped_account_owned_by_another_program_is_refused() {
    // The registry's program id, or any program's: an account laid out exactly like an escrow,
    // with the attacker as seller, owned by something other than the escrow program.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let stranger = Keypair::new();
    let escrow = h.funded(&h.terms(1));
    let mut data = h.account(&escrow).data;
    data[8 + 41..8 + 73].copy_from_slice(stranger.pubkey().as_ref()); // seller
    let registry = solana_address::address!("FoRPzGfMyWjK8uLjMoZfae2yevnviyCsGsHM7AwBwK8B");
    for owner in [registry, SYSTEM_PROGRAM, TOKEN_PROGRAM] {
        let forged = Address::new_unique();
        h.svm
            .set_account(forged, Account { lamports: 10_000_000, data: data.clone(), owner, executable: false, rent_epoch: 0 })
            .unwrap();
        let s = Accounts { escrow: forged, ..h.accounts(&escrow) };
        let err = h.send(&[release_to_seller_ix(&s, buyer.pubkey())], &[&buyer]).expect_err("forged escrow");
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
    // A sponsor named as the payer who did not sign: the buyer spending someone else's SOL.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let sponsor = h.someone();
    let a = CreateAccounts { buyer: buyer.pubkey(), payer: sponsor.pubkey(), mint: h.mint };
    let mut ix = create_ix(&h.terms(1), &a);
    ix.accounts[3].is_signer = false;
    let err = h.send(&[ix], &[&buyer]).expect_err("an unsigned payer");
    assert!(err.contains("AccountNotSigner"), "{err}");
    println!("rejected as expected: a payer who did not sign");
}

#[test]
fn reinit_create_on_a_live_escrow_is_refused() {
    // Only the same terms reach a live escrow's address, from either party; other terms at the
    // same id land at their own address and leave it as it is.
    let mut h = Harness::new();
    let escrow = h.funded(&h.terms(1));
    let err = h.create(&h.terms(1)).expect_err("the buyer again");
    assert!(err.contains("already in use"), "{err}");
    let err = h.invoice(&h.terms(1)).expect_err("the seller, the same terms");
    assert!(err.contains("already in use"), "{err}");
    let t = Terms { seller: Keypair::new().pubkey(), amount: 1, timer: Some(Timer { days: 1, to: Side::Buyer }), ..h.terms(1) };
    let (other, _) = h.create(&t).expect("other terms, the same id");
    assert_ne!(other, escrow);
    let e = h.escrow(&escrow);
    assert_eq!((e.seller, e.amount, e.timer), (h.seller.pubkey(), AMOUNT, None), "the terms stand");
    assert_eq!(h.vault_balance(&escrow), AMOUNT, "and so does the money");
    println!("rejected as expected: create over a live escrow");
}

#[test]
fn reinit_an_ended_escrows_address_never_holds_a_second_deal() {
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    let s = h.accounts(&escrow);
    let t2 = h.terms(1);
    let err = h
        .send(&[release_to_seller_ix(&s, buyer.pubkey()), create_ix(&t2, &h.create_accounts())], &[&buyer])
        .expect_err("end and reopen in one transaction");
    assert!(err.contains("already in use"), "{err}");
    h.release_to_seller(&escrow).expect("the ending alone");
    let err = h.create(&t2).expect_err("reopen later");
    assert!(err.contains("already in use"), "{err}");
    assert_eq!(h.escrow(&escrow).seller, h.seller.pubkey(), "the receipt still names the first deal's seller");
    println!("rejected as expected: an ended escrow's address never holds a second deal");
}

#[test]
fn nobody_can_open_the_address_a_buyer_is_about_to_use() {
    // An earlier version derived the address from the buyer's key and an id, and whoever opened
    // it named the seller, so anyone who saw a buyer's `create` could open that address first as
    // an invoice to itself. Now the address is made from every term: the front-runner's invoice
    // names itself as seller, so it lands at its own terms' address; the buyer's one tap lands at
    // the buyer's, untouched.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let squatter = h.someone();
    let meant = h.terms(1);
    let escrow = h.address(&meant);
    let squat = Terms { seller: squatter.pubkey(), timer: Some(Timer { days: 1, to: Side::Seller }), ..h.terms(1) };
    let a = CreateAccounts { buyer: buyer.pubkey(), payer: squatter.pubkey(), mint: h.mint };
    h.send(&[invoice_ix(&squat, &a)], &[&squatter]).expect("the squatter's own invoice");
    assert!(h.exists(&escrow_address(&squat, &buyer.pubkey(), &h.mint)));
    assert!(!h.exists(&escrow));

    // The buyer's one tap, the deposit address made first, lands at the buyer's address.
    let s = h.accounts(&escrow);
    h.send(
        &[
            create_ata_idempotent_ix(h.payer.pubkey(), escrow, h.mint).0,
            create_ix(&meant, &h.create_accounts()),
            spl_transfer_ix(h.buyer_tokens, s.vault, buyer.pubkey(), AMOUNT),
            release_to_seller_ix(&s, buyer.pubkey()),
        ],
        &[&buyer],
    )
    .expect("the buyer's one tap");
    let e = h.escrow(&escrow);
    assert_eq!((e.seller, e.creator, e.timer), (h.seller.pubkey(), Side::Buyer, None), "the buyer's own terms");
    assert_eq!(h.balance(&h.seller_tokens), AMOUNT, "the seller the buyer meant is paid");
    println!("rejected as expected: a front-runner lands at its own address; the buyer's one tap is untouched");
}

#[test]
fn pda_the_two_programs_cannot_share_an_address() {
    // Every address either program derives includes its own program id, so the same seeds under
    // the two programs land apart; and each program refuses accounts the other owns (see the
    // forged-escrow test above). Checked here for the seed strings both programs use.
    let registry = solana_address::address!("FoRPzGfMyWjK8uLjMoZfae2yevnviyCsGsHM7AwBwK8B");
    let buyer = Keypair::new().pubkey();
    for seeds in [
        vec![b"escrow".to_vec(), terms_hash(&Terms { id: 7, seller: buyer, amount: 1, arbiter: None, timer: None }, &buyer, &buyer).to_vec()],
        vec![b"config".to_vec()],
        vec![b"list".to_vec(), 0u32.to_le_bytes().to_vec()],
        vec![b"code-tree".to_vec()],
        vec![b"code".to_vec(), [7u8; 32].to_vec()],
    ] {
        let s: Vec<&[u8]> = seeds.iter().map(|v| v.as_slice()).collect();
        assert_ne!(Address::find_program_address(&s, &PROGRAM_ID).0, Address::find_program_address(&s, &registry).0);
    }
    // Within the escrow, the seeds are the tag and one 32-byte hash of terms that are each a fixed
    // length, so two different sets of terms meet only if SHA-256 collides.
    println!("rejected as expected: no seed collides across the two programs");
}

// ---------------------------------------------------------------------------------------------
// 3. Arithmetic
// ---------------------------------------------------------------------------------------------

#[test]
fn arithmetic_splits_at_the_edges_add_up_and_never_overflow() {
    let mut h = Harness::new();
    let seller = h.seller.insecure_clone();
    let arbiter = h.arbiter.insecure_clone();

    // One base unit, split every way.
    for (id, bps) in [(1u64, 1u16), (2, 5_000), (3, 9_999), (4, 10_000), (5, 0)] {
        let escrow = h.funded(&Terms { amount: 1, ..h.terms(id) });
        let meta = h.split(&escrow, bps).expect("split");
        let (_, balance, to_seller, to_buyer, _) = ended(&events(&meta.logs));
        assert_eq!((balance, to_seller + to_buyer, to_seller), (1, 1, share(1, bps)));
    }

    // The largest balance a u64 holds, in a fresh buyer's hands, through every way out that divides
    // or moves it whole.
    let (big, big_tokens) = new_buyer(&mut h, u64::MAX);
    for (id, how) in [(10u64, "split"), (11, "arbitrate"), (12, "release_to_seller"), (13, "timer_release")] {
        h.svm.set_account(big_tokens, spl_token_account(&h.mint, &big.pubkey(), u64::MAX)).unwrap();
        h.svm.set_account(h.seller_tokens, spl_token_account(&h.mint, &seller.pubkey(), 0)).unwrap();
        let t = Terms {
            amount: u64::MAX,
            arbiter: Some(arbiter.pubkey()),
            timer: Some(Timer { days: 1, to: Side::Seller }),
            ..h.terms(id)
        };
        let a = CreateAccounts { buyer: big.pubkey(), payer: h.payer.pubkey(), mint: h.mint };
        let escrow = escrow_address(&t, &big.pubkey(), &h.mint);
        let vault = vault_address(&escrow, &h.mint);
        h.send(&[create_ix(&t, &a), spl_transfer_ix(big_tokens, vault, big.pubkey(), u64::MAX), mark_funded_ix(escrow, vault)], &[&big])
            .expect("create, fund and mark");
        let s = Accounts { escrow, vault, buyer_tokens: big_tokens, seller_tokens: h.seller_tokens, rent_recipient: h.payer.pubkey(), ..h.accounts(&escrow) };
        let (ix, signers): (Instruction, Vec<&Keypair>) = match how {
            "split" => (split_ix(&s, big.pubkey(), seller.pubkey(), 7_777), vec![&big, &seller]),
            "arbitrate" => (arbitrate_ix(&s, arbiter.pubkey(), 1), vec![&arbiter]),
            "release_to_seller" => (release_to_seller_ix(&s, big.pubkey()), vec![&big]),
            _ => {
                h.advance(DAY);
                (timer_release_ix(escrow, vault, h.mint, h.seller_tokens, h.payer.pubkey()), vec![])
            }
        };
        let meta = h.send(&[ix], &signers).unwrap_or_else(|e| panic!("{how}: {e}"));
        let (_, balance, to_seller, to_buyer, _) = ended(&events(&meta.logs));
        assert_eq!(balance, u64::MAX, "{how}");
        assert_eq!(u128::from(to_seller) + u128::from(to_buyer), u128::from(u64::MAX), "{how}");
        assert_eq!(h.balance(&h.seller_tokens), to_seller, "{how}");
        assert_eq!(h.balance(&big_tokens), to_buyer, "{how}");
    }
    println!("rejected as expected: no overflow or lost unit at 1 or at u64::MAX, for split, arbitrate, release and the timer");
}

// ---------------------------------------------------------------------------------------------
// 4. The timer
// ---------------------------------------------------------------------------------------------

#[test]
fn timer_the_mark_cannot_be_back_dated_or_made_before_the_money() {
    // The timer counts from the mark, and the mark is the moment `mark_funded` runs, with the
    // amount there. The side the timer favours marks as soon as the money lands; the other side
    // cannot delay it past that, and nobody can make it earlier.
    let mut h = Harness::new();
    let t = Terms { timer: Some(Timer { days: 2, to: Side::Seller }), ..h.terms(1) };
    let (escrow, _) = h.create(&t).expect("create");
    let err = h.mark_funded(&escrow).expect_err("before the money");
    assert!(err.contains("NotFunded"), "{err}");
    h.advance(5 * DAY);
    h.fund(&escrow, AMOUNT);
    h.mark_funded(&escrow).expect("the seller marks at once");
    assert_eq!(h.escrow(&escrow).funded_at, T0 + 5 * DAY, "the mark is now, not the creation");
    h.advance(2 * DAY - 1);
    let err = h.timer_release(&escrow, Side::Seller).expect_err("a second early");
    assert!(err.contains("TimerNotDue"), "{err}");
    println!("rejected as expected: the timer counts from a mark made with the money there, no earlier");
}

#[test]
fn finding_an_invoice_with_a_short_timer_to_the_seller_pays_the_seller_whatever_the_buyer_thinks() {
    // An option the creator sets and the other side accepts by paying or working. The seller
    // invoices with a one-day timer to itself; a buyer who pays without looking cannot stop it:
    // the buyer's only way out alone is to give. The buyer's app shows it before paying (the
    // client's `optionsNotAgreed`).
    let mut h = Harness::new();
    let t = Terms { timer: Some(Timer { days: 1, to: Side::Seller }), ..h.terms(1) };
    let (escrow, _) = h.invoice(&t).expect("invoice");
    h.fund(&escrow, AMOUNT);
    h.mark_funded(&escrow).expect("the seller marks");
    h.advance(DAY);
    h.timer_release(&escrow, Side::Seller).expect("accepted");
    assert_eq!(h.balance(&h.seller_tokens), AMOUNT);
    println!("FINDING (app): a timer the buyer did not set pays the seller a day after funding; the app must show it before paying");
}

#[test]
fn finding_a_buyers_short_timer_to_itself_takes_back_money_the_seller_worked_for() {
    // The mirror: the buyer opens an escrow with a one-day timer to itself, pays, and the seller
    // works without looking. A day later anyone sends everything back. The seller's app shows the
    // timer before the seller works.
    let mut h = Harness::new();
    let t = Terms { timer: Some(Timer { days: 1, to: Side::Buyer }), ..h.terms(1) };
    let escrow = h.marked(&t);
    h.advance(DAY);
    h.timer_release(&escrow, Side::Buyer).expect("accepted");
    assert_eq!(h.buyer_total(), BUYER_START);
    println!("FINDING (app): a timer the seller did not set returns everything to the buyer; the app must show it before working");
}

#[test]
fn timer_whoever_sends_the_sellers_timer_can_pay_only_its_standard_account() {
    // Anyone sends a due timer. The last version paid the seller at any token account it held, so
    // the sender chose which: one the seller's wallet app might not show. Carlos's second change:
    // the seller, like the buyer, is paid only at its standard token account for the mint.
    let mut h = Harness::new();
    let seller = h.seller.insecure_clone();
    let t = Terms { timer: Some(Timer { days: 1, to: Side::Seller }), ..h.terms(1) };
    let escrow = h.marked(&t);
    h.advance(DAY);
    // Anyone can make a token account held by the seller: here, a stranger does, and aims at it.
    let obscure = Address::new_unique();
    h.svm.set_account(obscure, spl_token_account(&h.mint, &seller.pubkey(), 0)).unwrap();
    let stranger = h.someone();
    let vault = vault_address(&escrow, &h.mint);
    let send_as_stranger = |h: &mut Harness, to: Address| {
        let ix = timer_release_ix(escrow, vault, h.mint, to, h.payer.pubkey());
        h.svm.expire_blockhash();
        let tx = Transaction::new(&[&stranger], Message::new(&[ix], Some(&stranger.pubkey())), h.svm.latest_blockhash());
        h.send_tx(tx)
    };
    let err = send_as_stranger(&mut h, obscure).expect_err("an account the seller holds, not its standard one");
    assert!(err.contains("NotTheSellersAccount"), "{err}");
    assert_eq!(h.balance(&obscure), 0);
    let standard = h.seller_tokens;
    send_as_stranger(&mut h, standard).expect("the stranger sends it, to the seller's standard account");
    assert_eq!(h.balance(&h.seller_tokens), AMOUNT);
    println!("rejected as expected: the timer's sender cannot choose which of the seller's accounts is paid");
}

// ---------------------------------------------------------------------------------------------
// 5. The whole balance
// ---------------------------------------------------------------------------------------------

#[test]
fn finding_an_overpayment_goes_wherever_the_way_out_sends_the_balance() {
    // Carlos's rule: every way out pays out the whole balance, whatever it is. A second payment
    // made before the end, by mistake or by a second tap on a link, is part of the balance, and
    // `release_to_seller` sends it to the seller. The client's pay link asks only for what is
    // missing and refuses once the amount is there.
    let mut h = Harness::new();
    let escrow = h.funded(&h.terms(1));
    h.fund(&escrow, AMOUNT);
    let meta = h.release_to_seller(&escrow).expect("accepted");
    let (_, balance, to_seller, to_buyer, _) = ended(&events(&meta.logs));
    assert_eq!((balance, to_seller, to_buyer), (2 * AMOUNT, 2 * AMOUNT, 0));
    println!("FINDING (app): a double payment before the end went to the seller with the rest; only the seller can give it back");
}

#[test]
fn finding_a_part_payment_can_be_closed_under_the_buyer_by_the_seller() {
    // `close_unfunded` runs at any time while the balance is below the amount, by either party. A
    // buyer paying in two transfers can find the escrow closed between them:
    // the first part comes back, and the second, sent to the closed address, lands only if the
    // wallet app makes the deposit account again. Then there is no receipt to recover it through;
    // the buyer opening the same terms again adopts it.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let t = h.terms(1);
    let (escrow, _) = h.create(&t).expect("create");
    h.fund(&escrow, AMOUNT / 2);
    h.close_unfunded(&escrow, &seller).expect("the seller closes between the two parts");
    assert_eq!(h.balance(&h.refund()), AMOUNT / 2, "the first part back");
    let (make, vault) = create_ata_idempotent_ix(buyer.pubkey(), escrow, h.mint);
    h.send(&[make, spl_transfer_ix(h.buyer_tokens, vault, buyer.pubkey(), AMOUNT / 2)], &[&buyer]).expect("the second part");
    let err = h.recover_late(&escrow, &buyer).expect_err("no receipt");
    assert!(err.contains("AccountNotInitialized"), "{err}");
    h.create(&t).expect("the buyer opens the same terms again");
    h.close_unfunded(&escrow, &buyer).expect("and closes it");
    assert_eq!(h.buyer_total(), BUYER_START, "every unit back");
    println!("FINDING (app): a part payment can be closed under the buyer; pay in one transfer, or open the same terms again to recover");
}

#[test]
fn finding_a_frozen_buyer_account_blocks_only_the_ways_out_that_pay_the_buyer() {
    // A classic mint's freeze authority can freeze the buyer's standard account. Every way out
    // that pays the buyer anything then fails until it is thawed; the ones that pay the buyer
    // nothing still run, since they do not touch it.
    let mut h = Harness::new();
    let arbiter = h.arbiter.insecure_clone();
    let t = Terms { arbiter: Some(arbiter.pubkey()), ..h.terms(1) };
    let escrow = h.funded(&t);
    let refund = h.refund();
    let mut frozen = h.account(&refund);
    frozen.data[108] = 2; // AccountState::Frozen
    h.svm.set_account(refund, frozen).unwrap();
    let err = h.release_to_buyer(&escrow).expect_err("frozen");
    assert!(err.contains("0x11") || err.contains("frozen") || err.contains("Frozen"), "{err}");
    let err = h.arbitrate(&escrow, 5_000).expect_err("frozen");
    assert!(err.contains("0x11") || err.contains("frozen") || err.contains("Frozen"), "{err}");
    h.arbitrate(&escrow, 10_000).expect("everything to the seller does not touch the buyer's account");
    assert_eq!(h.balance(&h.seller_tokens), AMOUNT);
    println!("FINDING (token): a frozen buyer account blocks every way out that pays the buyer, and nothing else");
}

// ---------------------------------------------------------------------------------------------
// 6. Replays and double spends
// ---------------------------------------------------------------------------------------------

#[test]
fn double_spend_a_signed_way_out_sent_twice_is_refused() {
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let t = h.terms(1);
    let escrow = h.funded(&t);
    let s = h.accounts(&escrow);
    h.svm.expire_blockhash();
    let msg = Message::new(&[release_to_seller_ix(&s, buyer.pubkey())], Some(&h.payer.pubkey()));
    let tx = Transaction::new(&[&h.payer, &buyer], msg, h.svm.latest_blockhash());
    h.svm.send_transaction(tx.clone()).expect("first");
    // Someone pays the same address again, so a replay would have money to hit.
    h.svm.set_account(s.vault, spl_token_account(&h.mint, &escrow, AMOUNT)).unwrap();
    let err = h.svm.send_transaction(tx).expect_err("replay");
    assert!(format!("{:?}", err.err).contains("AlreadyProcessed"), "{:?}", err.err);
    // A fresh signature over the same release: the escrow has ended.
    let err = h.send(&[release_to_seller_ix(&s, buyer.pubkey())], &[&buyer]).expect_err("sign again");
    assert!(err.contains("Ended"), "{err}");
    let err = h.create(&t).expect_err("reopen");
    assert!(err.contains("already in use"), "{err}");
    assert_eq!(h.vault_balance(&escrow), AMOUNT, "the second payment is untouched");
    assert_eq!(h.balance(&h.seller_tokens), AMOUNT, "the seller was paid once");
    println!("rejected as expected: the same signed release replayed, re-signed, and the id reopened");
}

#[test]
fn double_spend_nobody_moves_or_closes_the_deposit_account_directly() {
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    let vault = vault_address(&escrow, &h.mint);
    let err = h.send(&[spl_transfer_ix(vault, h.buyer_tokens, buyer.pubkey(), AMOUNT)], &[&buyer]).expect_err("transfer out");
    assert!(err.contains("owner does not match") || err.contains("OwnerMismatch") || err.contains("custom program error: 0x4"), "{err}");
    let err = h.send(&[spl_close_ix(vault, buyer.pubkey(), buyer.pubkey())], &[&buyer]).expect_err("close");
    assert!(err.contains("0x4") || err.contains("0xb") || err.contains("owner"), "{err}");
    assert_eq!(h.vault_balance(&escrow), AMOUNT);
    println!("rejected as expected: the buyer cannot pull or close the deposit account through the token program");
}

// ---------------------------------------------------------------------------------------------
// 7. Tokens
// ---------------------------------------------------------------------------------------------

#[test]
fn finding_a_self_minted_token_makes_a_receipt_that_looks_like_real_money() {
    // Any classic mint is accepted. A buyer who owns a mint can fund a billion "dollars" and
    // produce a Created and Ended pair naming any amount. Only the mint says it is worthless.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let fake = Address::new_unique();
    h.svm.set_account(fake, spl_mint_account(6, TOKEN_PROGRAM)).unwrap();
    let fake_tokens = refund_address(&buyer.pubkey(), &fake);
    h.svm.set_account(fake_tokens, spl_token_account(&fake, &buyer.pubkey(), 1_000_000_000_000_000)).unwrap();
    let seller_fake = payout_address(&h.seller.pubkey(), &fake);
    h.svm.set_account(seller_fake, spl_token_account(&fake, &h.seller.pubkey(), 0)).unwrap();
    let t = Terms { amount: 1_000_000_000_000_000, ..h.terms(1) };
    let a = CreateAccounts { buyer: buyer.pubkey(), payer: h.payer.pubkey(), mint: fake };
    let escrow = escrow_address(&t, &buyer.pubkey(), &fake);
    let vault = vault_address(&escrow, &fake);
    let s = Accounts { escrow, vault, mint: fake, buyer_tokens: fake_tokens, seller_tokens: seller_fake, rent_recipient: h.payer.pubkey(), token_program: TOKEN_PROGRAM };
    let meta = h
        .send(&[create_ix(&t, &a), spl_transfer_ix(fake_tokens, vault, buyer.pubkey(), t.amount), release_to_seller_ix(&s, buyer.pubkey())], &[&buyer])
        .expect("accepted");
    let (outcome, balance, ..) = ended(&events(&meta.logs));
    assert_eq!((outcome, balance), (Outcome::ReleasedToSeller, 1_000_000_000_000_000));
    println!("FINDING (index): a billion-unit receipt in a token the buyer minted; only the mint field tells");
}

#[test]
fn tokens_wrapped_sol_is_refused_at_create() {
    // SOL sent to a wrapped-SOL deposit account without a sync would never count and would leave
    // with the rent. The native mint is refused at create, as the buyer, as the seller, with or
    // without money already at the address.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    h.svm.set_account(NATIVE_MINT, spl_mint_account(9, TOKEN_PROGRAM)).unwrap();
    let t = Terms { amount: 100_000_000, ..h.terms(1) }; // 0.1 SOL
    let a = CreateAccounts { buyer: buyer.pubkey(), payer: h.payer.pubkey(), mint: NATIVE_MINT };
    let err = h.send(&[create_ix(&t, &a)], &[&buyer]).expect_err("the buyer, with the native mint");
    assert!(err.contains("NativeMint"), "{err}");
    let err = h.send(&[invoice_ix(&t, &a)], &[&seller]).expect_err("the seller, with the native mint");
    assert!(err.contains("NativeMint"), "{err}");
    let escrow = escrow_address(&t, &buyer.pubkey(), &NATIVE_MINT);
    let vault = vault_address(&escrow, &NATIVE_MINT);
    h.svm.set_account(vault, wsol_account(&escrow)).unwrap();
    h.send(&[sol_transfer_ix(buyer.pubkey(), vault, t.amount), sync_native_ix(vault)], &[&buyer]).expect("SOL sent first");
    let err = h.send(&[create_ix(&t, &a)], &[&buyer]).expect_err("over a funded wrapped-SOL account");
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
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();

    // Never funded: close_unfunded closes the escrow account, and the stray SOL leaves with its
    // rent, to the rent recipient: the payer.
    let (escrow, _) = h.create(&h.terms(1)).expect("create");
    h.send(&[sol_transfer_ix(seller.pubkey(), escrow, 30_000_000)], &[&seller]).expect("SOL to the escrow's address");
    let (buyer_sol, payer_sol) = (h.lamports(&buyer.pubkey()), h.lamports(&h.payer.pubkey()));
    let meta = h.close_unfunded(&escrow, &seller).expect("close");
    let Some(Event::Closed { rent_lamports, rent_recipient, .. }) = events(&meta.logs).pop() else { panic!("no Closed") };
    assert!(rent_lamports > 30_000_000, "the stray SOL went with the rents: {rent_lamports}");
    assert_eq!(rent_recipient, h.payer.pubkey());
    assert_eq!(h.lamports(&h.payer.pubkey()), payer_sol - 2 * 5_000 + rent_lamports, "to the payer, which paid the fee");
    assert_eq!(h.lamports(&buyer.pubkey()), buyer_sol, "none to the creator");

    // Ended: the receipt is never closed; `sweep_rent` moves what is above the minimum, the stray
    // SOL included, to the payer recorded at creation. The program cannot tell stray SOL from rent.
    let escrow2 = h.funded(&h.terms(2));
    h.release_to_seller(&escrow2).expect("release");
    let before = h.lamports(&escrow2);
    h.send(&[sol_transfer_ix(seller.pubkey(), escrow2, 30_000_000)], &[&seller]).expect("SOL to a receipt");
    let (buyer_sol, payer_sol) = (h.lamports(&buyer.pubkey()), h.lamports(&h.payer.pubkey()));
    h.sweep(&escrow2).expect("sweep");
    assert_eq!(h.lamports(&escrow2), before, "back to its minimum");
    assert_eq!(h.lamports(&h.payer.pubkey()), payer_sol + 30_000_000 - 5_000, "the stray SOL went to the payer");
    assert_eq!(h.lamports(&buyer.pubkey()), buyer_sol, "none to the creator");
    println!("accepted, note: stray SOL goes to the payer, from a never-funded escrow at close ({rent_lamports} lamports) and from a receipt by sweep_rent");
}

/// Released, then paid again at the old address: the state `recover_late` is for.
fn ended_and_paid_again(h: &mut Harness, id: u64, late: u64) -> Address {
    let buyer = h.buyer.insecure_clone();
    let escrow = h.funded(&h.terms(id));
    h.release_to_seller(&escrow).expect("release");
    let (make, vault) = create_ata_idempotent_ix(buyer.pubkey(), escrow, h.mint);
    h.send(&[make, spl_transfer_ix(h.buyer_tokens, vault, buyer.pubkey(), late)], &[&buyer]).expect("paid again");
    escrow
}

#[test]
fn late_money_goes_only_to_the_buyers_standard_account_and_only_after_the_end() {
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let thief = h.someone();

    // A live escrow's money is not late: it is the deal's.
    let live = h.funded(&h.terms(1));
    let live_vault = vault_address(&live, &h.mint);
    let err = h.send(&[recover_late_ix(live, live_vault, buyer.pubkey(), h.mint, thief.pubkey())], &[&thief]).expect_err("live");
    assert!(err.contains("NotEnded"), "{err}");

    let escrow = ended_and_paid_again(&mut h, 2, 300_000);
    let vault = vault_address(&escrow, &h.mint);
    let (thief_ata_ix, thief_ata) = create_ata_idempotent_ix(thief.pubkey(), thief.pubkey(), h.mint);
    h.send(&[thief_ata_ix], &[&thief]).expect("the thief's own token account");
    let (seller_ata_ix, seller_ata) = create_ata_idempotent_ix(seller.pubkey(), seller.pubkey(), h.mint);
    h.send(&[seller_ata_ix], &[&seller]).expect("the seller's standard token account");
    let cases: Vec<(&str, Instruction, &str)> = vec![
        ("the thief's token account", recover_late_ix_to(escrow, vault, buyer.pubkey(), thief_ata, h.mint, thief.pubkey()), "ConstraintTokenOwner"),
        ("the seller's standard account", recover_late_ix_to(escrow, vault, buyer.pubkey(), seller_ata, h.mint, thief.pubkey()), "ConstraintTokenOwner"),
        (
            "a token account the buyer holds, not the standard one",
            recover_late_ix_to(escrow, vault, buyer.pubkey(), h.buyer_tokens, h.mint, thief.pubkey()),
            "AccountNotAssociatedTokenAccount",
        ),
        ("the thief as the buyer", recover_late_ix(escrow, vault, thief.pubkey(), h.mint, thief.pubkey()), "ConstraintHasOne"),
        ("another escrow's deposit account", recover_late_ix(escrow, live_vault, buyer.pubkey(), h.mint, thief.pubkey()), "ConstraintHasOne"),
    ];
    for (what, ix, want) in cases {
        let err = h.send(&[ix], &[&thief]).err().unwrap_or_else(|| panic!("{what}: must be refused"));
        assert!(err.contains(want), "{what}: expected {want}, got\n{err}");
    }
    assert_eq!(h.balance(&vault), 300_000, "nothing moved");
    h.send(&[recover_late_ix(escrow, vault, buyer.pubkey(), h.mint, thief.pubkey())], &[&thief]).expect("to the buyer");
    assert_eq!(h.balance(&h.refund()), 300_000);
    assert_eq!(h.balance(&thief_ata), 0);
    println!("rejected as expected: late money goes to the buyer's standard account and nowhere else, and only after the end");
}

#[test]
fn finding_a_buyer_who_hands_its_standard_account_away_blocks_its_own_late_money() {
    // `recover_late` makes the buyer's standard account if it is missing, with Anchor's
    // create-if-missing, which also checks that the buyer still holds it. A buyer who hands that
    // account to another key blocks its own late money there until it takes the account back.
    // Nothing else: the ways out check the address alone.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let escrow = ended_and_paid_again(&mut h, 1, 1);
    let refund = h.refund();
    h.send(&[hand_over_ix(refund, buyer.pubkey(), Keypair::new().pubkey())], &[&buyer]).expect("handed away");
    let err = h.recover_late(&escrow, &buyer).expect_err("blocked");
    assert!(err.contains("ConstraintTokenOwner") || err.contains("IllegalOwner") || err.contains("InvalidAccountOwner"), "{err}");
    println!("FINDING (known limit): recover_late checks who holds the buyer's standard account; a buyer who hands it away blocks its own late money");
}

#[test]
fn a_party_who_hands_its_standard_account_away_blocks_no_way_out() {
    // The ways out check each party's account by address, not by who holds it now: a party who
    // hands its standard account to another key cannot stop the arbiter, a split, or a timer. The
    // money goes to the address, as that party arranged.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let t = Terms { arbiter: Some(h.arbiter.pubkey()), ..h.terms(1) };
    let escrow = h.funded(&t);
    let refund = h.refund();
    let elsewhere = Keypair::new().pubkey();
    h.send(&[hand_over_ix(refund, buyer.pubkey(), elsewhere)], &[&buyer]).expect("the buyer hands its account away");
    h.send(&[hand_over_ix(h.seller_tokens, seller.pubkey(), elsewhere)], &[&seller]).expect("and the seller its own");
    h.arbitrate(&escrow, 6_000).expect("the arbiter still decides");
    assert_eq!((h.balance(&h.seller_tokens), h.balance(&refund)), (600_000, 400_000));
    println!("standard accounts handed to another key block nothing: the arbiter still decides");
}

#[test]
fn a_missing_buyer_account_is_made_in_the_same_transaction_by_whoever_sends_the_way_out() {
    // A buyer may close its empty standard account. A way out that pays the buyer then needs it
    // made first, which anyone can do in the same transaction with the standard idempotent
    // instruction, at its own cost; one that pays the buyer nothing does not need it at all.
    let mut h = Harness::new();
    let seller = h.seller.insecure_clone();
    let escrow = h.funded(&h.terms(1));
    h.drop_refund();
    let err = h.release_to_buyer(&escrow).expect_err("no buyer account");
    // The token program refuses to pay an account that does not exist.
    assert!(err.contains("InvalidAccountData"), "{err}");
    let (make, refund) = create_ata_idempotent_ix(seller.pubkey(), h.buyer.pubkey(), h.mint);
    assert_eq!(refund, h.refund());
    let s = h.accounts(&escrow);
    h.send(&[make, release_to_buyer_ix(&s, seller.pubkey())], &[&seller]).expect("made, then paid, in one transaction");
    assert_eq!(h.balance(&refund), AMOUNT);

    // A split that pays the buyer nothing runs with no buyer account at all.
    let mut h = Harness::new();
    let escrow = h.funded(&h.terms(1));
    h.drop_refund();
    h.split(&escrow, 10_000).expect("all to the seller: the buyer's account is never touched");
    assert!(!h.exists(&h.refund()));
    println!("a missing buyer account: made first in the same transaction when the buyer is paid, and not needed when it is not");
}

#[test]
fn sweep_pays_only_the_recorded_payer_and_only_from_an_escrow() {
    let mut h = Harness::new();
    let thief = Keypair::new();
    let escrow = h.funded(&h.terms(1));
    let s = h.accounts(&escrow);
    h.svm.set_sysvar(&rent_at(RENT_FINAL));
    let before = h.account(&escrow);

    let err = h.send(&[sweep_rent_ix(escrow, thief.pubkey())], &[]).expect_err("to a thief");
    assert!(err.contains("ConstraintHasOne"), "{err}");
    for (who, key) in [("the creator", h.buyer.pubkey()), ("the seller", h.seller.pubkey())] {
        let err = h.send(&[sweep_rent_ix(escrow, key)], &[]).expect_err(who);
        assert!(err.contains("ConstraintHasOne"), "{who}: {err}");
    }
    // Something that is not an escrow: its deposit account, and an escrow-shaped account another
    // program owns.
    let err = h.send(&[sweep_rent_ix(s.vault, h.payer.pubkey())], &[]).expect_err("a token account");
    assert!(err.contains("AccountOwnedByWrongProgram"), "{err}");
    let forged = Address::new_unique();
    let mut fake = before.clone();
    fake.owner = TOKEN_PROGRAM;
    fake.lamports += 50_000_000;
    h.svm.set_account(forged, fake).unwrap();
    let err = h.send(&[sweep_rent_ix(forged, h.payer.pubkey())], &[]).expect_err("forged");
    assert!(err.contains("AccountOwnedByWrongProgram"), "{err}");
    assert_eq!(h.account(&escrow).lamports, before.lamports, "nothing moved");
    h.sweep(&escrow).expect("to the payer");
    assert_eq!(h.lamports(&escrow), (128 + ESCROW_LEN as u64) * RENT_FINAL);
    println!("rejected as expected: the sweep pays only the recorded payer, and only from an escrow");
}

// ---------------------------------------------------------------------------------------------
// 8. The edges (session 16, the attack pass): the deposit address and money meant for other terms,
//    a frozen deposit or seller account, and a sweep then a close.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_deposit_address_never_adopts_money_meant_for_other_terms() {
    // An earlier version made the address from the creator's key and an id, so money one buyer
    // sent there, before an escrow existed or after a close, was adopted by whatever deal next took
    // the id, even one naming another buyer, who could then release it to the seller. Now the
    // buyer is a term: another buyer's deal is at another address, and the money waits for an
    // escrow with exactly the terms it was sent to, which its own buyer can open, and close.
    let mut h = Harness::new();
    let seller = h.seller.insecure_clone();
    let buyer_a = h.buyer.insecure_clone();
    let meant = h.terms(1);
    let escrow = h.address(&meant);

    // Buyer A pays half to its own deal's address before the escrow exists, making the account
    // first as a wallet app would.
    let (make, vault) = create_ata_idempotent_ix(buyer_a.pubkey(), escrow, h.mint);
    h.send(&[make, spl_transfer_ix(h.buyer_tokens, vault, buyer_a.pubkey(), AMOUNT / 2)], &[&buyer_a]).expect("buyer A pays");

    // The seller invoices buyer B at the same id: another address, holding nothing.
    let buyer_b = h.someone();
    let a = CreateAccounts { buyer: buyer_b.pubkey(), payer: h.payer.pubkey(), mint: h.mint };
    h.send(&[invoice_ix(&meant, &a)], &[&seller]).expect("the seller invoices buyer B at the same id");
    let other = escrow_address(&meant, &buyer_b.pubkey(), &h.mint);
    assert_ne!(other, escrow);
    assert_eq!(h.vault_balance(&other), 0, "buyer B's deal holds none of buyer A's money");
    assert_eq!(h.balance(&vault), AMOUNT / 2);

    // Buyer A opens the terms it paid, which adopt the part, and closes them: the part comes back.
    h.create(&meant).expect("buyer A opens the terms it paid");
    h.close_unfunded(&escrow, &buyer_a).expect("and closes them");
    assert_eq!(h.buyer_total(), BUYER_START, "buyer A has all its money back");
    println!("rejected as expected: money sent to one buyer's terms is never adopted by a deal naming another");
}

#[test]
fn a_payment_to_an_address_lands_only_in_a_deal_with_its_terms() {
    // The seller invoices with one arbiter, closes it unpaid, and reopens the same id with another
    // it picked. The buyer read the first deal and pays its address. That money must never count
    // toward the second deal: another arbiter is another address.
    let mut h = Harness::new();
    let buyer = h.buyer.insecure_clone();
    let seller = h.seller.insecure_clone();
    let fair = h.arbiter.pubkey();
    let picked = h.someone();
    let first_terms = Terms { arbiter: Some(fair), ..h.terms(1) };
    let (first, _) = h.invoice(&first_terms).expect("the first invoice");
    h.close_unfunded(&first, &seller).expect("closed unpaid");
    let second_terms = Terms { arbiter: Some(picked.pubkey()), ..h.terms(1) };
    let (second, _) = h.invoice(&second_terms).expect("the same id, another arbiter");

    // The buyer pays the address it read, making its deposit account as a wallet app would.
    let (make, first_vault) = create_ata_idempotent_ix(buyer.pubkey(), first, h.mint);
    h.send(&[make, spl_transfer_ix(h.buyer_tokens, first_vault, buyer.pubkey(), AMOUNT)], &[&buyer]).expect("the buyer pays");

    assert_ne!(second, first, "another arbiter is another address");
    assert_eq!(h.vault_balance(&second), 0, "the second deal holds none of it");
    let s = h.accounts(&second);
    let err = h.send(&[arbitrate_ix(&s, picked.pubkey(), 10_000)], &[&picked]).expect_err("the picked arbiter");
    assert!(err.contains("NotFunded"), "{err}");
    assert_eq!(h.balance(&first_vault), AMOUNT, "the money waits at the address it was sent to");

    // Only the first terms take it: reopened, they hold it, with the arbiter the buyer read.
    let (again, _) = h.invoice(&first_terms).expect("the first terms, reopened");
    assert_eq!(again, first);
    assert_eq!((h.escrow(&first).arbiter, h.vault_balance(&first)), (fair, AMOUNT));
    println!("rejected as expected: a payment to one deal's address never counts toward another deal's terms");
}

#[test]
fn finding_a_frozen_deposit_account_blocks_every_way_out() {
    // The checklist reasons that freezing the deposit account stops every way out, since each moves
    // tokens out of it; only the buyer's account had been frozen in a test. Here the deposit
    // account itself is frozen: no way out runs until it is thawed. USDC's maker holds this freeze
    // authority.
    let mut h = Harness::new();
    let t = Terms { arbiter: Some(h.arbiter.pubkey()), timer: Some(Timer { days: 1, to: Side::Seller }), ..h.terms(1) };
    let escrow = h.marked(&t);
    let vault = vault_address(&escrow, &h.mint);
    let mut frozen = h.account(&vault);
    frozen.data[108] = 2; // AccountState::Frozen
    h.svm.set_account(vault, frozen).unwrap();

    let froze = |e: String, what: &str| assert!(e.contains("0x11") || e.to_lowercase().contains("frozen"), "{what}: {e}");
    froze(h.release_to_seller(&escrow).expect_err("release_to_seller"), "release_to_seller");
    froze(h.release_to_buyer(&escrow).expect_err("release_to_buyer"), "release_to_buyer");
    froze(h.split(&escrow, 5_000).expect_err("split"), "split");
    froze(h.arbitrate(&escrow, 5_000).expect_err("arbitrate"), "arbitrate");
    // Even one that pays the whole balance to one side moves it out of the frozen deposit account.
    froze(h.arbitrate(&escrow, 10_000).expect_err("all to the seller"), "arbitrate all to seller");
    h.advance(DAY + 1);
    froze(h.timer_release(&escrow, Side::Seller).expect_err("timer_release"), "timer_release");
    assert_eq!(h.vault_balance(&escrow), AMOUNT, "nothing moved");
    println!("FINDING (token): a frozen deposit account blocks every way out until it is thawed");
}

#[test]
fn finding_a_frozen_seller_account_blocks_only_the_ways_out_that_pay_the_seller() {
    // The mirror of the buyer-freeze finding, for the seller. Freezing the seller's standard account
    // stops every way out that pays the seller anything; the ones that pay the seller nothing run,
    // since they never touch it.
    let mut h = Harness::new();
    let t = Terms { arbiter: Some(h.arbiter.pubkey()), ..h.terms(1) };
    let escrow = h.funded(&t);
    let mut frozen = h.account(&h.seller_tokens);
    frozen.data[108] = 2; // AccountState::Frozen
    h.svm.set_account(h.seller_tokens, frozen).unwrap();

    let e = h.release_to_seller(&escrow).expect_err("frozen");
    assert!(e.contains("0x11") || e.to_lowercase().contains("frozen"), "{e}");
    let e = h.arbitrate(&escrow, 5_000).expect_err("frozen");
    assert!(e.contains("0x11") || e.to_lowercase().contains("frozen"), "{e}");
    // Everything to the buyer pays the seller nothing and never touches its frozen account.
    h.arbitrate(&escrow, 0).expect("all to the buyer runs");
    assert_eq!(h.balance(&h.refund()), AMOUNT);
    println!("FINDING (token): a frozen seller account blocks every way out that pays the seller, and nothing else");
}

#[test]
fn close_unfunded_after_a_sweep_returns_every_rent_to_the_payer() {
    // A never-funded escrow can be swept as its rent minimum falls, and then closed. The two must
    // compose: the sweep sends the excess to the payer and leaves the escrow account at exactly the
    // current minimum; the close returns that (and the deposit account's rent) to the payer too,
    // with no underflow and nothing stranded.
    let mut h = Harness::new();
    h.svm.set_sysvar(&rent_at(6_960)); // the older, higher rate, so the cut leaves an excess
    let buyer = h.buyer.insecure_clone();
    let sponsor = h.someone();
    let a = CreateAccounts { payer: sponsor.pubkey(), ..h.create_accounts() };
    h.send(&[create_ix(&h.terms(1), &a)], &[&buyer, &sponsor]).expect("create at the old rate, the sponsor paying");
    let escrow = h.address(&h.terms(1));
    let vault = vault_address(&escrow, &h.mint);
    h.svm.set_sysvar(&rent_at(RENT_FINAL)); // the cut lands
    let minimum = (128 + ESCROW_LEN as u64) * RENT_FINAL;
    let excess = h.lamports(&escrow) - minimum;
    let (creator_before, sponsor_before) = (h.lamports(&buyer.pubkey()), h.lamports(&sponsor.pubkey()));

    h.sweep(&escrow).expect("sweep the escrow's excess to the payer");
    assert_eq!(h.lamports(&escrow), minimum, "left at exactly the new minimum");
    assert_eq!(h.lamports(&sponsor.pubkey()), sponsor_before + excess);

    let vault_rent = h.lamports(&vault);
    h.close_unfunded(&escrow, &buyer).expect("close after the sweep");
    h.assert_closed(&escrow, "escrow");
    h.assert_closed(&vault, "vault");
    assert_eq!(h.lamports(&sponsor.pubkey()), sponsor_before + excess + minimum + vault_rent, "the payer gets the excess, then what is left of both rents");
    assert_eq!(h.lamports(&buyer.pubkey()), creator_before, "none to the creator");
    println!("a sweep then a close compose: the payer gets the excess and then the remaining rent, nothing stranded");
}
