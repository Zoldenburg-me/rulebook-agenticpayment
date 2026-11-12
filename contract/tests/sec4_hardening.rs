//! SEC-4 unit tests (security audit run-1 hardening notes): mandate
//! bounds, init pins, the MPC signature check, key reuse after a failed DeleteKey and
//! `list_requests` paging. The owner-nonce step is in c2_owner.rs (it needs a passkey owner);
//! `new` being `#[private]` is in the T1 integration crate (it needs the wasm entry point).

mod mock_mpc;

use std::panic::{catch_unwind, AssertUnwindSafe};

use mandate::types::*;
use mandate::Contract;
use near_sdk::json_types::U128;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{testing_env, AccountId, NearToken, PromiseResult, PublicKey};

const CONTRACT: &str = "mandate-demo.testnet";
const MPC: &str = "v1.signer-prod.testnet";
const WALLET: &str = "sme-owner.testnet";
const USDC: &str = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const EURE: &str = "0x29f37f6adca168b79b8d9567eab9be3fbf21db85";
const PAY_TO: &str = "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f";
const AGENT: &str = "agent-a";
/// Block time of the tests (unix s).
const NOW: u64 = 1_793_599_700;
const WEEK: u64 = 604_800;

// ---------- environment ----------

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn key(n: u8) -> PublicKey {
    format!("ed25519:{}", near_sdk::bs58::encode([n; 32]).into_string())
        .parse()
        .unwrap()
}

/// The wallet owner attaches 1 yoctoNEAR (its full-access key); every other caller attaches
/// nothing (function-call keys cannot).
fn call_at(predecessor: &str, signer_pk: PublicKey, now: u64, results: Vec<PromiseResult>) {
    let deposit = if predecessor == WALLET { 1 } else { 0 };
    call_with(predecessor, signer_pk, now, deposit, results)
}

fn call_with(
    predecessor: &str,
    signer_pk: PublicKey,
    now: u64,
    deposit_yocto: u128,
    results: Vec<PromiseResult>,
) {
    let ctx = VMContextBuilder::new()
        .current_account_id(acc(CONTRACT))
        .predecessor_account_id(acc(predecessor))
        .signer_account_id(acc(predecessor))
        .signer_account_pk(signer_pk)
        .attached_deposit(NearToken::from_yoctonear(deposit_yocto))
        .block_timestamp(now * 1_000_000_000)
        .build();
    testing_env!(
        ctx,
        near_sdk::test_vm_config(),
        near_sdk::RuntimeFeesConfig::test(),
        Default::default(),
        results
    );
}

fn owner_at(now: u64) {
    call_at(WALLET, key(200), now, vec![])
}

/// A call signed with agent A's key (agent keys live on the contract's own account).
fn agent_at(now: u64) {
    call_at(CONTRACT, key(1), now, vec![])
}

/// The MPC callback receipt at `now`, with the `sign` result.
fn mpc_callback_at(now: u64, result: PromiseResult) {
    call_at(CONTRACT, key(201), now, vec![result]);
}

/// The MPC's answer to agent A's request `id`: a signature by the agent's key over its digest.
fn mpc_ok(c: &Contract, id: &str) -> PromiseResult {
    let digest = c.get_request(rkey(AGENT, id)).unwrap().digest;
    PromiseResult::Successful(mock_mpc::sign_response(&digest))
}

fn expect_err<R>(code: &str, f: impl FnOnce() -> R) -> String {
    let err = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => panic!("expected {code}, but the call succeeded"),
        Err(e) => e,
    };
    let msg = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default();
    let msg = match msg.split_once("panic_msg: \"") {
        Some((_, rest)) => rest.trim_end_matches("\" })").to_string(),
        None => msg,
    };
    assert!(
        msg.starts_with(&format!("{code}: ")),
        "expected {code}, got {msg:?}"
    );
    msg
}

// ---------- fixtures ----------

fn sweep_config() -> SweepConfig {
    SweepConfig {
        safe_address: "0x5afe000000000000000000000000000000000001".into(),
        usdc_address: USDC.into(),
        eure_address: EURE.into(),
        chain_id: 84532,
        usdc_eip712_name: "USDC".into(),
        usdc_eip712_version: "2".into(),
    }
}

/// x402: 1..=10_000 per payment and 25_000 per week; SEPA: the demo numbers.
fn mandate() -> Mandate {
    let rail = |max: u128, budget: u128| RailMandate {
        amount_range: AmountRange {
            min: U128(1),
            max: U128(max),
        },
        budget: U128(budget),
        period_secs: WEEK,
    };
    Mandate {
        x402: rail(10_000, 25_000),
        sepa: rail(50 * 10u128.pow(18), 200 * 10u128.pow(18)),
        usdc_address: USDC.into(),
        eure_address: EURE.into(),
        chain_id: 84532,
        float_cap: FloatCap {
            usdc: U128(25_000_000),
            eure: U128(250 * 10u128.pow(18)),
        },
        max_validity_secs: 300,
        paypal: None,
        paypal_refund: None,
        usdc_eip712_name: "USDC".into(),
        usdc_eip712_version: "2".into(),
    }
}

fn add_agent(c: &mut Contract, agent: &str, pk: PublicKey) {
    owner_at(NOW);
    let _ = c.add_agent(
        agent.into(),
        pk.clone(),
        sweep_config(),
        mock_mpc::agent_evm(),
        None,
    );
    call_at(
        CONTRACT,
        key(201),
        NOW,
        vec![PromiseResult::Successful(vec![])],
    );
    assert!(c.on_agent_key_added(agent.into(), pk));
}

/// Wallet-owned contract with agent A (key 1), its mandate, and `PAY_TO` allowlisted.
fn setup() -> Contract {
    owner_at(NOW);
    let mut c = Contract::new(
        OwnerMode::Wallet {
            account: acc(WALLET),
        },
        "testnet".into(),
        acc(MPC),
    );
    add_agent(&mut c, AGENT, key(1));
    owner_at(NOW);
    c.set_mandate(AGENT.into(), mandate(), None);
    c.add_payee(
        AGENT.into(),
        Payee::X402 {
            pay_to: PAY_TO.into(),
        },
        None,
    );
    c
}

fn x402(amount: u128) -> Shape {
    Shape::X402(X402PaymentRequirements {
        resource_url: "http://localhost:4021/weather".into(),
        scheme: "exact".into(),
        network: "eip155:84532".into(),
        asset: USDC.into(),
        pay_to: PAY_TO.into(),
        amount: U128(amount),
        max_timeout_seconds: 240,
    })
}

fn rkey(agent: &str, request_id: &str) -> RequestKey {
    RequestKey {
        agent: agent.into(),
        caller: Caller::Agent,
        request_id: request_id.into(),
    }
}

/// Agent A requests an x402 payment at `now`.
fn request_at(c: &mut Contract, now: u64, id: &str, amount: u128) {
    agent_at(now);
    let _ = c.request_signature(id.into(), x402(amount));
}

fn set_mandate(c: &mut Contract, m: Mandate) {
    owner_at(NOW);
    c.set_mandate(AGENT.into(), m, None);
}

// ---------- period_secs is capped, budget_window cannot overflow ----------

#[test]
fn period_secs_above_366_days_is_rejected() {
    let mut c = setup();
    for period in [MAX_PERIOD_SECS + 1, u64::MAX] {
        let mut m = mandate();
        m.x402.period_secs = period;
        owner_at(NOW);
        expect_err("ERR_INVALID_MANDATE", || {
            c.set_mandate(AGENT.into(), m, None)
        });
        let mut m = mandate();
        m.sepa.period_secs = period;
        owner_at(NOW);
        expect_err("ERR_INVALID_MANDATE", || {
            c.set_mandate(AGENT.into(), m, None)
        });
    }
    let mut m = mandate();
    m.x402.period_secs = MAX_PERIOD_SECS;
    m.sepa.period_secs = MAX_PERIOD_SECS;
    set_mandate(&mut c, m);
    assert_eq!(MAX_PERIOD_SECS, 366 * 24 * 3600);
}

#[test]
fn budget_window_does_not_overflow_on_a_huge_period() {
    let c = setup();
    let far = u64::MAX - 1;
    // Past the stored window, with a period whose length in ms does not fit in u64.
    let (start, secs) = c
        .budget_window(&AGENT.to_string(), Rail::X402, u64::MAX, far)
        .unwrap();
    assert!(start <= far);
    assert_eq!(secs, u64::MAX);
}

// ---------- amount_range.min >= 1 ----------

#[test]
fn zero_amount_range_min_is_rejected() {
    let mut c = setup();
    let mut m = mandate();
    m.x402.amount_range.min = U128(0);
    owner_at(NOW);
    expect_err("ERR_INVALID_MANDATE", || {
        c.set_mandate(AGENT.into(), m, None)
    });
    let mut m = mandate();
    m.sepa.amount_range.min = U128(0);
    owner_at(NOW);
    expect_err("ERR_INVALID_MANDATE", || {
        c.set_mandate(AGENT.into(), m, None)
    });
}

// ---------- init pins the network and the MPC contract ----------

fn wallet_owner() -> OwnerMode {
    OwnerMode::Wallet {
        account: acc(WALLET),
    }
}

#[test]
fn new_rejects_a_network_other_than_testnet() {
    for network in ["", "mainnet", "Testnet"] {
        owner_at(NOW);
        expect_err("ERR_WRONG_NETWORK", || {
            Contract::new(wallet_owner(), network.into(), acc(MPC))
        });
    }
}

#[test]
fn new_rejects_an_mpc_contract_other_than_v1_signer_prod_testnet() {
    for mpc in ["v1.signer", "signer-prod.testnet", "evil.testnet"] {
        owner_at(NOW);
        expect_err("ERR_WRONG_NETWORK", || {
            Contract::new(wallet_owner(), "testnet".into(), acc(mpc))
        });
    }
    owner_at(NOW);
    let c = Contract::new(wallet_owner(), "testnet".into(), acc(MPC));
    assert_eq!(c.get_config().mpc_contract, acc(MPC));
}

// ---------- the MPC signature must recover to the agent's evm_address ----------

#[test]
fn signature_from_another_key_marks_the_request_unknown() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    let digest = c.get_request(rkey(AGENT, "p1")).unwrap().digest;
    // A misconfigured mpc_contract: a valid signature, but not by the agent's derived key.
    let wrong = mock_mpc::sign_response_with(0x07, &digest);
    mpc_callback_at(NOW + 12, PromiseResult::Successful(wrong));
    let res = c.on_signature(rkey(AGENT, "p1"));
    assert_eq!(res.status, RequestStatus::Unknown);
    assert!(res.signature.is_none());
    assert!(res.counts_against_budget);
    assert_eq!(c.get_request(rkey(AGENT, "p1")), Some(res));
    let logs = near_sdk::test_utils::get_logs();
    assert!(
        logs.iter()
            .any(|l| l.contains("request_unknown") && l.contains("signature_mismatch")),
        "{logs:?}"
    );
}

#[test]
fn signature_over_another_digest_marks_the_request_unknown() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    let other = format!("0x{}", "ab".repeat(32));
    mpc_callback_at(
        NOW + 12,
        PromiseResult::Successful(mock_mpc::sign_response(&other)),
    );
    assert_eq!(
        c.on_signature(rkey(AGENT, "p1")).status,
        RequestStatus::Unknown
    );
}

#[test]
fn signature_by_the_agent_key_is_recorded() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    mpc_callback_at(NOW + 12, mpc_ok(&c, "p1"));
    let res = c.on_signature(rkey(AGENT, "p1"));
    assert_eq!(res.status, RequestStatus::Signed);
    assert!(res.signature.is_some());
}

#[test]
fn mismatched_late_callback_after_expiry_is_a_no_op() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    call_at("anyone.testnet", key(202), NOW + 300, vec![]);
    c.expire_pending(rkey(AGENT, "p1"));
    let digest = c.get_request(rkey(AGENT, "p1")).unwrap().digest;
    mpc_callback_at(
        NOW + 310,
        PromiseResult::Successful(mock_mpc::sign_response_with(0x07, &digest)),
    );
    let res = c.on_signature(rkey(AGENT, "p1"));
    assert_eq!(res.status, RequestStatus::Unknown);
    assert!(res.signature.is_none());
    assert!(near_sdk::test_utils::get_logs().is_empty());
}

// ---------- a key whose DeleteKey failed cannot be given to a new agent ----------

fn revoke_with_failed_delete_key(c: &mut Contract) {
    owner_at(NOW);
    let _ = c.revoke(AGENT.into(), None);
    mpc_callback_at(NOW, PromiseResult::Failed);
    assert!(!c.on_agent_key_deleted(AGENT.into()).key_deleted);
}

#[test]
fn add_agent_rejects_a_key_still_waiting_for_delete_key() {
    let mut c = setup();
    revoke_with_failed_delete_key(&mut c);
    owner_at(NOW);
    expect_err("ERR_KEY_EXISTS", || {
        c.add_agent(
            "agent-c".into(),
            key(1),
            sweep_config(),
            mock_mpc::agent_evm(),
            None,
        )
    });
    // Once a retried revoke deletes the key, it may be reused.
    owner_at(NOW);
    let _ = c.revoke(AGENT.into(), None);
    mpc_callback_at(NOW, PromiseResult::Successful(vec![]));
    assert!(c.on_agent_key_deleted(AGENT.into()).key_deleted);
    add_agent(&mut c, "agent-c", key(1));
    assert_eq!(c.agent_of_key(key(1)), Some("agent-c".to_string()));
}

// ---------- list_requests pages one agent's requests without a full scan ----------

/// Agent B (key 2) with the fixture mandate and payee.
fn add_agent_b(c: &mut Contract) {
    add_agent(c, "agent-b", key(2));
    owner_at(NOW);
    c.set_mandate("agent-b".into(), mandate(), None);
    c.add_payee(
        "agent-b".into(),
        Payee::X402 {
            pay_to: PAY_TO.into(),
        },
        None,
    );
}

fn request_b(c: &mut Contract, id: &str) {
    call_at(CONTRACT, key(2), NOW, vec![]);
    let _ = c.request_signature(id.into(), x402(1));
}

fn ids(list: Vec<Reservation>) -> Vec<String> {
    list.into_iter().map(|r| r.key.request_id).collect()
}

#[test]
fn list_requests_pages_one_agents_requests_oldest_first() {
    let mut c = setup();
    add_agent_b(&mut c);
    for i in 0..5 {
        request_at(&mut c, NOW, &format!("a{i}"), 1);
        request_b(&mut c, &format!("b{i}"));
    }
    owner_at(NOW);
    assert_eq!(
        ids(c.list_requests(AGENT.into(), 0, 100)),
        ["a0", "a1", "a2", "a3", "a4"]
    );
    assert_eq!(ids(c.list_requests(AGENT.into(), 1, 2)), ["a1", "a2"]);
    assert_eq!(ids(c.list_requests("agent-b".into(), 3, 100)), ["b3", "b4"]);
    assert!(c.list_requests(AGENT.into(), 5, 10).is_empty());
    assert!(c.list_requests(AGENT.into(), u32::MAX, u32::MAX).is_empty());
    assert!(c.list_requests("nobody".into(), 0, 10).is_empty());
}

/// Gas `list_requests(agent-a, 1, 1)` burns on a contract loaded from storage, as a view
/// call would (the collections' in-memory cache would hide a scan).
fn list_gas(c: Contract) -> u64 {
    near_sdk::env::state_write(&c);
    drop(c); // flushes the collections
    owner_at(NOW);
    let c: Contract = near_sdk::env::state_read().unwrap();
    let before = near_sdk::env::used_gas().as_gas();
    assert_eq!(ids(c.list_requests(AGENT.into(), 1, 1)), ["a1"]);
    near_sdk::env::used_gas().as_gas() - before
}

/// Agent A's requests a0 and a1, with `others` requests of agent B in between.
fn with_others(others: usize) -> Contract {
    near_sdk::mock::with_mocked_blockchain(|b| drop(b.take_storage())); // a fresh account
    let mut c = setup();
    add_agent_b(&mut c);
    request_at(&mut c, NOW, "a0", 1);
    for i in 0..others {
        request_b(&mut c, &format!("b{i}"));
    }
    request_at(&mut c, NOW, "a1", 1);
    c
}

#[test]
fn list_requests_cost_does_not_grow_with_other_agents_requests() {
    let alone = list_gas(with_others(0));
    let crowded = list_gas(with_others(40));
    assert!(
        crowded < alone * 3 / 2,
        "list_requests scans other agents' requests: {alone} gas alone, {crowded} with 40 more"
    );
}
