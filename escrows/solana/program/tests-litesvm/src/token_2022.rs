//! Token-2022 for the tests: a mint with every extension Open USD has on mainnet, made by
//! Token-2022's own instructions; a transfer hook program the tests can switch on; and the powers
//! of the dollar's maker (pause, freeze, the permanent delegate), used the way a maker would.
//!
//! The hook is a builtin written here, not an SBF program: LiteSVM runs it where Token-2022 calls a
//! hook, so nothing extra is built or checked in. Token-2022 finds the accounts it needs among the
//! ones the escrow forwards, and calls it with them, exactly as it would call any hook; the hook
//! then checks what the hook of a dollar's maker sees (called mid-transfer, no signer, its accounts
//! present) and counts its calls in an account it owns, which it can write only because that
//! account reached it writable.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use litesvm::LiteSVM;
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_runtime::__private::InstructionError;
use solana_keypair::Keypair;
use solana_program_runtime::solana_sbpf::program::BuiltinFunctionDefinition;
use solana_signer::Signer;
use spl_discriminator::SplDiscriminate;
use spl_tlv_account_resolution::{account::ExtraAccountMeta, seeds::Seed, state::ExtraAccountMetaList};
use spl_token_2022_interface::extension::transfer_hook::{TransferHook, TransferHookAccount};
use spl_token_2022_interface::extension::{
    confidential_transfer, default_account_state, interest_bearing_mint, metadata_pointer, pausable, scaled_ui_amount, transfer_fee,
    transfer_hook, BaseStateWithExtensions, ExtensionType, StateWithExtensions,
};
use spl_token_2022_interface::instruction as t22;
use spl_token_2022_interface::state::{Account as TokenAccount22, AccountState, Mint as Mint22};
use spl_transfer_hook_interface::instruction::ExecuteInstruction;

use crate::{ata_address_under, create_ata_idempotent_ix_under, Harness, BUYER_START, SYSTEM_PROGRAM, TOKEN_2022_PROGRAM};

/// Open USD, on mainnet.
pub const OPEN_USD: Address = solana_address::address!("ousd2mJsPEckLHcSCDxyKD7NDGARZcfLbDZkKiatYHB");

/// Open USD's mint account as mainnet held it at slot 452,061,257 (2026-09-30), from
/// `getAccountInfo`, base64: 630 bytes owned by Token-2022. Its extensions, in order: mint close
/// authority, permanent delegate, default account state (initialized), confidential transfer mint
/// (no auto-approve, no auditor), transfer hook (no program), metadata pointer (to itself),
/// pausable (not paused), token metadata ("OpenUSD", "OUSD"); and a freeze authority. The tests
/// compare the mint they make with it, extension by extension.
pub const OPEN_USD_MAINNET: &str = "AQAAAMPC4g04FP5Ks0+9gus5/MiD1+5YE2RYCtNeUaW3v7VJQEOZgGEQAAAGAQEAAADuG8gelqQtHOqICEOW7L2pIUflH7h3sZEBvdoX0weB/QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQMAIADCxVfvfgyL6/ghXl884xFBxmaSZMR5xLlk5z75keVAjgwAIACQfXxiVUupkl9L/xRFKXoCl5MW9UszzJz5UOz3j0WiDQYAAQABBABBAMLFV+9+DIvr+CFeXzzjEUHGZpJkxHnEuWTnPvmR5UCOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADgBAAMLFV+9+DIvr+CFeXzzjEUHGZpJkxHnEuWTnPvmR5UCOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAEAAwsVX734Mi+v4IV5fPOMRQcZmkmTEecS5ZOc++ZHlQI4MBIArPwQK7SQvb7xz4ZK/HOj7Jvo/oHS2m715iEyCrhoAIQDCxVfvfgyL6/ghXl884xFBxmaSZMR5xLlk5z75keVAjgATAI0AwsVX734Mi+v4IV5fPOMRQcZmkmTEecS5ZOc++ZHlQI4MBIArPwQK7SQvb7xz4ZK/HOj7Jvo/oHS2m715iEyCrgcAAABPcGVuVVNEBAAAAE9VU0QyAAAAaHR0cHM6Ly90b2tlbi1tZXRhZGF0YS5icmlkZ2UueHl6L3NvbGFuYS9vdXNkLmpzb24AAAAA";

pub const OPEN_USD_NAME: &str = "OpenUSD";
pub const OPEN_USD_SYMBOL: &str = "OUSD";
pub const OPEN_USD_URI: &str = "https://token-metadata.bridge.xyz/solana/ousd.json";

/// The test hook's program id.
pub const TEST_HOOK_PROGRAM: Address = Address::new_from_array(*b"forest-escrow-v2-transfer-hook!!");
/// The hook's error when it is called with a signer among its accounts.
pub const HOOK_SAW_A_SIGNER: u32 = 0x5157;
/// The hook's error when the source or destination is not mid-transfer.
pub const HOOK_NOT_TRANSFERRING: u32 = 0x7e57;

/// The hook's call counter: the first account its list names, written on every call.
pub fn hook_counter() -> Address {
    Address::find_program_address(&[b"counter"], &TEST_HOOK_PROGRAM).0
}

/// The second: one read-only account per destination owner, as a hook keeping a list of allowed
/// holders would have. It need not exist; it only has to be passed.
pub fn hook_holder_entry(owner: &Address) -> Address {
    Address::find_program_address(&[b"holder", owner.as_ref()], &TEST_HOOK_PROGRAM).0
}

/// The hook's validation account for a mint: where Token-2022 and every client read which
/// accounts it needs.
pub fn hook_validation(mint: &Address) -> Address {
    spl_transfer_hook_interface::get_extra_account_metas_address(mint, &TEST_HOOK_PROGRAM)
}

/// The accounts the test hook lists: its counter, writable, and the entry for the destination
/// token account's owner (bytes 32..64 of the destination), read-only.
pub fn test_hook_accounts() -> Vec<ExtraAccountMeta> {
    vec![
        ExtraAccountMeta::new_with_seeds(&[Seed::Literal { bytes: b"counter".to_vec() }], false, true).unwrap(),
        ExtraAccountMeta::new_with_seeds(
            &[Seed::Literal { bytes: b"holder".to_vec() }, Seed::AccountData { account_index: 2, data_index: 32, length: 32 }],
            false,
            false,
        )
        .unwrap(),
    ]
}

solana_program_runtime::declare_process_instruction!(TestHook, 500, |invoke_context| {
    let transaction_context = &invoke_context.transaction_context;
    let ic = transaction_context.get_current_instruction_context()?;
    let data = ic.get_instruction_data();
    if data.len() != 16 || data[..8] != *ExecuteInstruction::SPL_DISCRIMINATOR_SLICE {
        return Err(InstructionError::InvalidInstructionData);
    }
    // source, mint, destination, authority, validation, counter, holder entry.
    let n = ic.get_number_of_instruction_accounts();
    if n < 7 {
        return Err(InstructionError::MissingAccount);
    }
    for i in 0..n {
        if ic.is_instruction_account_signer(i)? {
            return Err(InstructionError::Custom(HOOK_SAW_A_SIGNER));
        }
    }
    for i in [0, 2] {
        let account = ic.try_borrow_instruction_account(i)?;
        let state = StateWithExtensions::<TokenAccount22>::unpack(account.get_data()).map_err(|_| InstructionError::InvalidAccountData)?;
        let flag = state.get_extension::<TransferHookAccount>().map_err(|_| InstructionError::InvalidAccountData)?;
        if !bool::from(flag.transferring) {
            return Err(InstructionError::Custom(HOOK_NOT_TRANSFERRING));
        }
    }
    let mut counter = ic.try_borrow_instruction_account(5)?;
    let bytes: [u8; 8] = counter.get_data().get(..8).and_then(|b| b.try_into().ok()).ok_or(InstructionError::InvalidAccountData)?;
    counter.set_data_from_slice(&(u64::from_le_bytes(bytes) + 1).to_le_bytes())?;
    Ok(())
});

/// The spy's error when an account after the four `transfer_checked` names arrives as a signer.
pub const SPY_SAW_A_FORWARDED_SIGNER: u32 = 0x5b1;

solana_program_runtime::declare_process_instruction!(TokenSpy, 100, |invoke_context| {
    // Stands in for the token program: accepts everything and moves nothing, but refuses a
    // `transfer_checked` (12) that carries a signature on any account after its authority.
    let transaction_context = &invoke_context.transaction_context;
    let ic = transaction_context.get_current_instruction_context()?;
    if ic.get_instruction_data().first() == Some(&12) {
        for i in 4..ic.get_number_of_instruction_accounts() {
            if ic.is_instruction_account_signer(i)? {
                return Err(InstructionError::Custom(SPY_SAW_A_FORWARDED_SIGNER));
            }
        }
    }
    Ok(())
});

/// Replace Token-2022 with the spy, for a test of what the escrow itself hands the token program.
pub fn spy_on_token_2022(h: &mut Harness) {
    h.svm.add_builtin(TOKEN_2022_PROGRAM, TokenSpy::register);
}

/// Which program the mint's transfer hook names at first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookProgram {
    /// None, as Open USD has it today: the extension is there, the dollar's maker can name one
    /// later.
    None,
    /// The test hook.
    Test,
}

/// The keys behind the mint's authorities, in Open USD's roles.
pub struct Issuer {
    /// Open USD's `E7Jd…`: the mint's close authority, and the confidential transfer, transfer
    /// hook, metadata pointer, pause and metadata authority.
    pub admin: Keypair,
    pub minter: Keypair,
    pub freezer: Keypair,
    pub delegate: Keypair,
}

/// Runs a future that never waits: the hook resolver's reads here return at once.
fn block_on<F: Future>(f: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut f = pin!(f);
    loop {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

/// The program the mint's transfer hook names now, if any.
pub fn hook_program_of(svm: &LiteSVM, mint: &Address) -> Option<Address> {
    let account = svm.get_account(mint)?;
    if account.owner != TOKEN_2022_PROGRAM {
        return None;
    }
    let state = StateWithExtensions::<Mint22>::unpack(&account.data).ok()?;
    let hook = state.get_extension::<TransferHook>().ok()?;
    Option::<Address>::from(hook.program_id)
}

/// Appends to `ix` what a transfer from `source` to `destination` by `authority` needs for the
/// mint's hook, by `spl-transfer-hook-interface`'s own resolver reading the ledger.
pub fn resolve_hook_accounts(svm: &LiteSVM, ix: &mut Instruction, hook: &Address, source: &Address, mint: &Address, destination: &Address, authority: &Address) {
    let fetch = |key: Address| {
        let data = svm.get_account(&key).map(|a| a.data);
        async move { Ok(data) }
    };
    block_on(spl_transfer_hook_interface::offchain::add_extra_account_metas_for_execute(
        ix, hook, source, mint, destination, authority, 0, fetch,
    ))
    .unwrap_or_else(|e| panic!("resolving the hook's accounts: {e:?}"));
}

/// The mint's extension types, in the order its data holds them.
pub fn mint_extensions(data: &[u8]) -> Vec<ExtensionType> {
    StateWithExtensions::<Mint22>::unpack(data).unwrap().get_extension_types().unwrap()
}

/// Open USD's mint as mainnet holds it (`OPEN_USD_MAINNET`).
pub fn open_usd_mainnet() -> Vec<u8> {
    base64_decode(OPEN_USD_MAINNET)
}

fn base64_decode(s: &str) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for ch in s.bytes().take_while(|c| *c != b'=') {
        acc = (acc << 6) | TABLE.iter().position(|c| *c == ch).expect("base64") as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn system_create(payer: &Address, account: &Address, lamports: u64, space: usize, owner: &Address) -> Instruction {
    let mut data = 0u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&(space as u64).to_le_bytes());
    data.extend_from_slice(owner.as_ref());
    Instruction {
        program_id: SYSTEM_PROGRAM,
        accounts: vec![AccountMeta::new(*payer, true), AccountMeta::new(*account, true)],
        data,
    }
}

/// A token account at a fresh keypair's address, not a standard one, made the way a wallet app
/// makes one: the size Token-2022 asks for the mint's extensions, then `InitializeAccount3`.
pub fn make_other_account(h: &mut Harness, owner: &Address) -> Address {
    let account = Keypair::new();
    let mint_types = mint_extensions(&h.account(&h.mint).data);
    let needed = ExtensionType::get_required_init_account_extensions(&mint_types);
    let space = ExtensionType::try_calculate_account_len::<TokenAccount22>(&needed).unwrap();
    let lamports = h.svm.minimum_balance_for_rent_exemption(space);
    let ixs = [
        system_create(&h.payer.pubkey(), &account.pubkey(), lamports, space, &TOKEN_2022_PROGRAM),
        t22::initialize_account3(&TOKEN_2022_PROGRAM, &account.pubkey(), &h.mint, owner).unwrap(),
    ];
    h.send(&ixs, &[&account]).expect("a token account");
    account.pubkey()
}

/// `owner`'s standard account for the harness's mint, made by the associated token program.
pub fn make_standard_account(h: &mut Harness, owner: &Address) -> Address {
    let (ix, ata) = create_ata_idempotent_ix_under(h.payer.pubkey(), *owner, h.mint, h.token_program);
    h.send(&[ix], &[]).expect("a standard account");
    ata
}

/// Makes the harness's mint: Open USD's eight extensions in Open USD's order, each by its own
/// Token-2022 instruction, then the mint, then its metadata; the test hook's validation and
/// counter accounts if `hook` names it; then the parties' accounts and the buyer's ten dollars.
pub(crate) fn make_open_usd(h: &mut Harness, hook: HookProgram) {
    h.svm.add_builtin(TEST_HOOK_PROGRAM, TestHook::register);
    let issuer = Issuer { admin: Keypair::new(), minter: Keypair::new(), freezer: Keypair::new(), delegate: Keypair::new() };
    for k in [&issuer.admin, &issuer.minter, &issuer.freezer, &issuer.delegate] {
        h.svm.airdrop(&k.pubkey(), 1_000_000_000).unwrap();
    }
    let mint = Keypair::new();
    let m = mint.pubkey();
    let admin = issuer.admin.pubkey();
    let fixed = [
        ExtensionType::MintCloseAuthority,
        ExtensionType::PermanentDelegate,
        ExtensionType::DefaultAccountState,
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::TransferHook,
        ExtensionType::MetadataPointer,
        ExtensionType::Pausable,
    ];
    let space = ExtensionType::try_calculate_account_len::<Mint22>(&fixed).unwrap();
    // The metadata is appended by its own instruction, which grows the account: fund the final size.
    let metadata_len = 4 + 32 + 32 + (4 + OPEN_USD_NAME.len()) + (4 + OPEN_USD_SYMBOL.len()) + (4 + OPEN_USD_URI.len()) + 4;
    let lamports = h.svm.minimum_balance_for_rent_exemption(space + metadata_len);
    let hook_program = match hook {
        HookProgram::None => None,
        HookProgram::Test => Some(TEST_HOOK_PROGRAM),
    };
    let ixs = [
        system_create(&h.payer.pubkey(), &m, lamports, space, &TOKEN_2022_PROGRAM),
        t22::initialize_mint_close_authority(&TOKEN_2022_PROGRAM, &m, Some(&admin)).unwrap(),
        t22::initialize_permanent_delegate(&TOKEN_2022_PROGRAM, &m, &issuer.delegate.pubkey()).unwrap(),
        default_account_state::instruction::initialize_default_account_state(&TOKEN_2022_PROGRAM, &m, &AccountState::Initialized).unwrap(),
        confidential_transfer::instruction::initialize_mint(&TOKEN_2022_PROGRAM, &m, Some(admin), false, None).unwrap(),
        transfer_hook::instruction::initialize(&TOKEN_2022_PROGRAM, &m, Some(admin), hook_program).unwrap(),
        metadata_pointer::instruction::initialize(&TOKEN_2022_PROGRAM, &m, Some(admin), Some(m)).unwrap(),
        pausable::instruction::initialize(&TOKEN_2022_PROGRAM, &m, &admin).unwrap(),
        t22::initialize_mint2(&TOKEN_2022_PROGRAM, &m, &issuer.minter.pubkey(), Some(&issuer.freezer.pubkey()), 6).unwrap(),
    ];
    h.send(&ixs, &[&mint]).expect("the mint");
    let minter = issuer.minter.insecure_clone();
    let metadata = spl_token_metadata_interface::instruction::initialize(
        &TOKEN_2022_PROGRAM,
        &m,
        &admin,
        &m,
        &minter.pubkey(),
        OPEN_USD_NAME.to_string(),
        OPEN_USD_SYMBOL.to_string(),
        OPEN_USD_URI.to_string(),
    );
    h.send(&[metadata], &[&minter]).expect("the metadata");
    h.mint = m;
    h.decimals = 6;
    h.token_program = TOKEN_2022_PROGRAM;

    // The hook's accounts exist whether or not the mint names it yet, so the dollar's maker can
    // switch it on later (`set_hook_program`).
    set_hook_list(h, &test_hook_accounts());
    let rent = h.svm.minimum_balance_for_rent_exemption(8);
    h.svm.set_account(hook_counter(), Account { lamports: rent, data: vec![0; 8], owner: TEST_HOOK_PROGRAM, executable: false, rent_epoch: 0 }).unwrap();

    let buyer = h.buyer.pubkey();
    let seller = h.seller.pubkey();
    h.buyer_tokens = make_other_account(h, &buyer);
    let buyer_tokens = h.buyer_tokens;
    h.send(
        &[t22::mint_to_checked(&TOKEN_2022_PROGRAM, &m, &buyer_tokens, &minter.pubkey(), &[], BUYER_START, 6).unwrap()],
        &[&minter],
    )
    .expect("the buyer's ten dollars");
    make_standard_account(h, &buyer);
    h.seller_tokens = make_standard_account(h, &seller);
    h.seller_other = make_other_account(h, &seller);
    h.issuer = Some(issuer);
    assert_eq!(h.refund(), ata_address_under(&buyer, &m, &TOKEN_2022_PROGRAM));
}

/// Writes the test hook's validation account for the harness's mint, listing `accounts`.
pub fn set_hook_list(h: &mut Harness, accounts: &[ExtraAccountMeta]) {
    let size = ExtraAccountMetaList::size_of(accounts.len()).unwrap();
    let mut data = vec![0u8; size];
    ExtraAccountMetaList::init::<ExecuteInstruction>(&mut data, accounts).unwrap();
    let lamports = h.svm.minimum_balance_for_rent_exemption(size);
    h.svm.set_account(hook_validation(&h.mint), Account { lamports, data, owner: TEST_HOOK_PROGRAM, executable: false, rent_epoch: 0 }).unwrap();
}

/// How many transfers the test hook has seen.
pub fn hook_calls(h: &Harness) -> u64 {
    u64::from_le_bytes(h.account(&hook_counter()).data[..8].try_into().unwrap())
}

fn issuer(h: &Harness) -> &Issuer {
    h.issuer.as_ref().expect("a Token-2022 harness")
}

/// The dollar's maker names a hook program, or none: `TransferHook`'s update, signed by its
/// authority.
pub fn set_hook_program(h: &mut Harness, program: Option<Address>) {
    let admin = issuer(h).admin.insecure_clone();
    let ix = transfer_hook::instruction::update(&TOKEN_2022_PROGRAM, &h.mint, &admin.pubkey(), &[], program).unwrap();
    h.send(&[ix], &[&admin]).expect("the hook updated");
}

/// The dollar's maker pauses every transfer of the mint, or resumes them.
pub fn set_paused(h: &mut Harness, paused: bool) {
    let admin = issuer(h).admin.insecure_clone();
    let ix = if paused {
        pausable::instruction::pause(&TOKEN_2022_PROGRAM, &h.mint, &admin.pubkey(), &[]).unwrap()
    } else {
        pausable::instruction::resume(&TOKEN_2022_PROGRAM, &h.mint, &admin.pubkey(), &[]).unwrap()
    };
    h.send(&[ix], &[&admin]).expect("paused or resumed");
}

/// The dollar's maker freezes a token account, or thaws it.
pub fn set_frozen(h: &mut Harness, account: &Address, frozen: bool) {
    let freezer = issuer(h).freezer.insecure_clone();
    let ix = if frozen {
        t22::freeze_account(&TOKEN_2022_PROGRAM, account, &h.mint, &freezer.pubkey(), &[]).unwrap()
    } else {
        t22::thaw_account(&TOKEN_2022_PROGRAM, account, &h.mint, &freezer.pubkey(), &[]).unwrap()
    };
    h.send(&[ix], &[&freezer]).expect("frozen or thawed");
}

/// The permanent delegate moves `amount` out of any account of the mint, a deposit account
/// included, to `to`: no one else signs.
pub fn delegate_takes(h: &mut Harness, from: &Address, to: &Address, amount: u64) -> Result<(), String> {
    let delegate = issuer(h).delegate.insecure_clone();
    let ix = t22::transfer_checked(&TOKEN_2022_PROGRAM, from, &h.mint, to, &delegate.pubkey(), &[], amount, h.decimals).unwrap();
    let ix = h.with_hook(ix, *from, &[*to], delegate.pubkey());
    h.send(&[ix], &[&delegate]).map(|_| ())
}

/// A Token-2022 mint with a transfer fee (`bps`, any maximum) and nothing else, its fee
/// authority a throwaway key. Returns its address.
pub fn transfer_fee_mint(h: &mut Harness, bps: u16) -> Address {
    let mint = Keypair::new();
    let m = mint.pubkey();
    let space = ExtensionType::try_calculate_account_len::<Mint22>(&[ExtensionType::TransferFeeConfig]).unwrap();
    let lamports = h.svm.minimum_balance_for_rent_exemption(space);
    let authority = Address::new_unique();
    let ixs = [
        system_create(&h.payer.pubkey(), &m, lamports, space, &TOKEN_2022_PROGRAM),
        transfer_fee::instruction::initialize_transfer_fee_config(&TOKEN_2022_PROGRAM, &m, Some(&authority), Some(&authority), bps, u64::MAX).unwrap(),
        t22::initialize_mint2(&TOKEN_2022_PROGRAM, &m, &authority, None, 6).unwrap(),
    ];
    h.send(&ixs, &[&mint]).expect("a transfer-fee mint");
    m
}

/// One extension Open USD does not have, for a mint of its own.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OneExtension {
    NonTransferable,
    /// Interest at this many basis points a year, shown in the displayed amount only.
    InterestBearing(i16),
    /// The displayed amount is the raw one times this, which the token's maker can change.
    ScaledUiAmount(f64),
}

/// A six-decimal Token-2022 mint with `extension` and nothing else. Returns its address and the
/// key that is its mint authority and the extension's authority.
pub fn one_extension_mint(h: &mut Harness, extension: OneExtension) -> (Address, Keypair) {
    let mint = Keypair::new();
    let m = mint.pubkey();
    let authority = Keypair::new();
    h.svm.airdrop(&authority.pubkey(), 1_000_000_000).unwrap();
    let (kind, init) = match extension {
        OneExtension::NonTransferable => (ExtensionType::NonTransferable, t22::initialize_non_transferable_mint(&TOKEN_2022_PROGRAM, &m).unwrap()),
        OneExtension::InterestBearing(rate) => (
            ExtensionType::InterestBearingConfig,
            interest_bearing_mint::instruction::initialize(&TOKEN_2022_PROGRAM, &m, Some(authority.pubkey()), rate).unwrap(),
        ),
        OneExtension::ScaledUiAmount(multiplier) => (
            ExtensionType::ScaledUiAmount,
            scaled_ui_amount::instruction::initialize(&TOKEN_2022_PROGRAM, &m, Some(authority.pubkey()), multiplier).unwrap(),
        ),
    };
    let space = ExtensionType::try_calculate_account_len::<Mint22>(&[kind]).unwrap();
    let lamports = h.svm.minimum_balance_for_rent_exemption(space);
    let ixs = [
        system_create(&h.payer.pubkey(), &m, lamports, space, &TOKEN_2022_PROGRAM),
        init,
        t22::initialize_mint2(&TOKEN_2022_PROGRAM, &m, &authority.pubkey(), None, 6).unwrap(),
    ];
    h.send(&ixs, &[&mint]).expect("a one-extension mint");
    (m, authority)
}

/// Makes `mint` the harness's: the buyer's non-standard account holding ten of it, both parties'
/// standard accounts, a second seller account. `authority` mints.
pub fn use_mint(h: &mut Harness, mint: Address, authority: &Keypair) {
    h.mint = mint;
    h.token_program = TOKEN_2022_PROGRAM;
    h.decimals = 6;
    let buyer = h.buyer.pubkey();
    let seller = h.seller.pubkey();
    h.buyer_tokens = make_other_account(h, &buyer);
    let buyer_tokens = h.buyer_tokens;
    h.send(&[t22::mint_to_checked(&TOKEN_2022_PROGRAM, &mint, &buyer_tokens, &authority.pubkey(), &[], BUYER_START, 6).unwrap()], &[authority])
        .expect("ten to the buyer");
    make_standard_account(h, &buyer);
    h.seller_tokens = make_standard_account(h, &seller);
    h.seller_other = make_other_account(h, &seller);
}

/// What Token-2022 shows for `amount` of the harness's mint now: its `AmountToUiAmount`.
pub fn shown(h: &mut Harness, amount: u64) -> String {
    let ix = t22::amount_to_ui_amount(&TOKEN_2022_PROGRAM, &h.mint, amount).unwrap();
    let meta = h.send(&[ix], &[]).expect("amount to ui amount");
    String::from_utf8(meta.return_data.data).unwrap()
}

/// A Token-2022 mint with no extension at all.
pub fn plain_2022_mint(h: &mut Harness) -> Address {
    let mint = Keypair::new();
    let m = mint.pubkey();
    let space = ExtensionType::try_calculate_account_len::<Mint22>(&[]).unwrap();
    let lamports = h.svm.minimum_balance_for_rent_exemption(space);
    let ixs = [
        system_create(&h.payer.pubkey(), &m, lamports, space, &TOKEN_2022_PROGRAM),
        t22::initialize_mint2(&TOKEN_2022_PROGRAM, &m, &Address::new_unique(), None, 6).unwrap(),
    ];
    h.send(&ixs, &[&mint]).expect("a plain Token-2022 mint");
    m
}

/// The escrow's standard-account rule under Token-2022: the account a payout must land in.
pub fn standard_2022(owner: &Address, mint: &Address) -> Address {
    ata_address_under(owner, mint, &TOKEN_2022_PROGRAM)
}

/// Every remaining account the escrow receives for a hook, as an `AccountMeta` list: for tests
/// that take them away or add to them.
pub fn hook_metas_of(ix: &Instruction, named: usize) -> Vec<AccountMeta> {
    ix.accounts[named..].to_vec()
}
