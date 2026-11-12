//! SEC-1 unit tests (security audit run-1, NEEDS-VALIDATION #1 and #2): wallet-mode owner
//! calls need exactly 1 yoctoNEAR attached, and the agent's stored requests are capped.

mod mock_mpc;

use std::panic::{catch_unwind, AssertUnwindSafe};

use mandate::request::MAX_AGENT_REQUESTS;
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

// ---------- #1: wallet-mode owner calls need exactly 1 yoctoNEAR ----------

/// A wallet-owner call carrying `yocto` (0 is what a function-call key on the owner account
/// can send).
fn owner_with(yocto: u128) {
    call_with(WALLET, key(200), NOW, yocto, vec![])
}

fn payee(n: u8) -> Payee {
    Payee::X402 {
        pay_to: format!("0x{}", hex_byte(n).repeat(20)),
    }
}

fn hex_byte(n: u8) -> String {
    format!("{n:02x}")
}

#[test]
fn wallet_owner_call_without_a_deposit_is_rejected() {
    let mut c = setup();
    let others = c.get_payees(AGENT.into());
    owner_with(0);
    expect_err("ERR_NOT_OWNER", || {
        c.add_payee(AGENT.into(), payee(0xaa), None)
    });
    owner_with(0);
    expect_err("ERR_NOT_OWNER", || {
        c.set_mandate(AGENT.into(), mandate(), None)
    });
    owner_with(0);
    expect_err("ERR_NOT_OWNER", || {
        c.set_relayer(Some(acc("attacker.testnet")), None)
    });
    owner_with(0);
    expect_err("ERR_NOT_OWNER", || {
        c.remove_payee(AGENT.into(), payee(0xaa), None)
    });
    owner_with(0);
    expect_err("ERR_NOT_OWNER", || {
        c.add_agent(
            "agent-x".into(),
            key(9),
            sweep_config(),
            "0xbbc0320e02d371a71f18a40b7b15404df218d880".into(),
            None,
        )
    });
    owner_with(0);
    expect_err("ERR_NOT_OWNER", || c.revoke(AGENT.into(), None));
    owner_with(0);
    expect_err("ERR_NOT_OWNER", || {
        c.resolve_reservation(rkey(AGENT, "r1"), ResolveOutcome::Spent, None)
    });
    assert_eq!(c.get_payees(AGENT.into()), others);
    assert_eq!(c.get_config().relayer, None);
    assert!(c.get_agent("agent-x".into()).is_none());
    assert!(!c.get_agent(AGENT.into()).unwrap().revoked);
}

#[test]
fn wallet_owner_call_with_more_than_one_yocto_is_rejected() {
    let mut c = setup();
    owner_with(2);
    expect_err("ERR_NOT_OWNER", || {
        c.add_payee(AGENT.into(), payee(0xaa), None)
    });
}

#[test]
fn wallet_owner_call_with_one_yocto_succeeds() {
    let mut c = setup();
    owner_with(1);
    c.add_payee(AGENT.into(), payee(0xaa), None);
    assert!(c.get_payees(AGENT.into()).contains(&payee(0xaa)));
}

#[test]
fn deposit_does_not_help_another_account() {
    let mut c = setup();
    call_with("attacker.testnet", key(203), NOW, 1, vec![]);
    expect_err("ERR_NOT_OWNER", || {
        c.add_payee(AGENT.into(), payee(0xaa), None)
    });
}

// ---------- #2: the agent's stored requests are capped ----------

/// Agent A with a mandate whose budget never binds, so only the request cap can stop it.
fn setup_unbounded_budget() -> Contract {
    let mut c = setup();
    let mut m = mandate();
    m.x402.budget = U128(u128::MAX);
    owner_at(NOW);
    c.set_mandate(AGENT.into(), m, None);
    c
}

#[test]
fn agent_requests_past_the_cap_are_rejected() {
    let mut c = setup_unbounded_budget();
    for i in 0..MAX_AGENT_REQUESTS {
        request_at(&mut c, NOW, &format!("r{i}"), 1);
    }
    agent_at(NOW);
    let msg = expect_err("ERR_OVER_BUDGET", || {
        c.request_signature("one-more".into(), x402(1))
    });
    assert!(msg.contains("requests"), "{msg}");
    assert!(c.get_request(rkey(AGENT, "one-more")).is_none());
    assert_eq!(
        c.list_requests(AGENT.into(), 0, 1000).len(),
        MAX_AGENT_REQUESTS as usize
    );
}

#[test]
fn final_requests_still_count_against_the_cap() {
    // Signed is final and stays stored, so a cap on open requests alone would not bound
    // storage: the cap counts every request the agent has made.
    let mut c = setup_unbounded_budget();
    for i in 0..MAX_AGENT_REQUESTS {
        let id = format!("r{i}");
        request_at(&mut c, NOW, &id, 1);
        mpc_callback_at(NOW + 1, mpc_ok(&c, &id));
        c.on_signature(rkey(AGENT, &id));
    }
    agent_at(NOW + 2);
    expect_err("ERR_OVER_BUDGET", || {
        c.request_signature("one-more".into(), x402(1))
    });
}

#[test]
fn the_cap_is_per_agent() {
    let mut c = setup_unbounded_budget();
    for i in 0..MAX_AGENT_REQUESTS {
        request_at(&mut c, NOW, &format!("r{i}"), 1);
    }
    add_agent(&mut c, "agent-b", key(2));
    let mut m = mandate();
    m.x402.budget = U128(u128::MAX);
    owner_at(NOW);
    c.set_mandate("agent-b".into(), m, None);
    c.add_payee(
        "agent-b".into(),
        Payee::X402 {
            pay_to: PAY_TO.into(),
        },
        None,
    );
    call_at(CONTRACT, key(2), NOW, vec![]);
    let _ = c.request_signature("r0".into(), x402(1));
    assert!(c.get_request(rkey("agent-b", "r0")).is_some());
}
