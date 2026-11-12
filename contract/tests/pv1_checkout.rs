//! PP-V1 pipeline tests for shape 5 (charge on the owner's vaulted PayPal wallet):
//! `request_signature` with a `paypal_checkout` shape. Accept within the mandate; refuse
//! over cap, wrong payee, expired, after revoke; share the PayPal budget with shape 4;
//! dedupe like shape 4. Builder unit tests are in `src/shapes/paypal_checkout.rs`.

mod mock_mpc;

use std::panic::{catch_unwind, AssertUnwindSafe};

use mandate::types::*;
use mandate::Contract;
use near_sdk::json_types::U128;
use near_sdk::serde_json;
use near_sdk::test_utils::VMContextBuilder;
use near_sdk::{testing_env, AccountId, NearToken, PromiseResult, PublicKey};

const CONTRACT: &str = "mandate-demo.testnet";
const MPC: &str = "v1.signer-prod.testnet";
const WALLET: &str = "sme-owner.testnet";
const USDC: &str = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const EURE: &str = "0x29f37f6adca168b79b8d9567eab9be3fbf21db85";
const AGENT: &str = "agent-a";
const EMAIL: &str = "supplier@example.com";
const NOW: u64 = 1_793_599_700;
const WEEK: u64 = 604_800;

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn key(n: u8) -> PublicKey {
    format!("ed25519:{}", near_sdk::bs58::encode([n; 32]).into_string())
        .parse()
        .unwrap()
}

fn call_at(predecessor: &str, signer_pk: PublicKey, now: u64, results: Vec<PromiseResult>) {
    let ctx = VMContextBuilder::new()
        .current_account_id(acc(CONTRACT))
        .predecessor_account_id(acc(predecessor))
        .signer_account_id(acc(predecessor))
        .signer_account_pk(signer_pk)
        .attached_deposit(NearToken::from_yoctonear(u128::from(predecessor == WALLET)))
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

fn agent_at(now: u64) {
    call_at(CONTRACT, key(1), now, vec![])
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

fn rail(max: u128, budget: u128) -> RailMandate {
    RailMandate {
        amount_range: AmountRange {
            min: U128(1),
            max: U128(max),
        },
        budget: U128(budget),
        period_secs: WEEK,
    }
}

/// PayPal: 0.01..=50.00 USD per payout, 100.00 USD per week.
fn mandate() -> Mandate {
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
        paypal: Some(rail(5_000, 10_000)),
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
        SweepConfig {
            safe_address: "0x5afe000000000000000000000000000000000001".into(),
            usdc_address: USDC.into(),
            eure_address: EURE.into(),
            chain_id: 84532,
            usdc_eip712_name: "USDC".into(),
            usdc_eip712_version: "2".into(),
        },
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

/// Agent A (key 1) with the mandate above and `EMAIL` allowlisted (added in mixed case).
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
        Payee::Paypal {
            receiver: " Supplier@Example.com".into(),
        },
        None,
    );
    c
}

const ORDER: &str = "ORD-42";

fn checkout(amount: &str, timestamp: u64) -> Shape {
    Shape::PaypalCheckout(PaypalCheckoutRequest {
        payee: EMAIL.into(),
        amount: amount.into(),
        order_ref: ORDER.into(),
        timestamp,
    })
}

fn paypal(amount: &str, timestamp: u64) -> Shape {
    Shape::Paypal(PaypalRequest {
        payee: EMAIL.into(),
        amount: amount.into(),
        timestamp,
    })
}

fn rkey(agent: &str, request_id: &str) -> RequestKey {
    RequestKey {
        agent: agent.into(),
        caller: Caller::Agent,
        request_id: request_id.into(),
    }
}

fn reserved(c: &Contract) -> u128 {
    c.get_budget(AGENT.into(), Rail::Paypal).unwrap().reserved.0
}

#[test]
fn checkout_within_mandate_is_signed_on_the_paypal_rail() {
    let mut c = setup();
    agent_at(NOW);
    let _ = c.request_signature("chk-1".into(), checkout("25.00", NOW));
    let res = c.get_request(rkey(AGENT, "chk-1")).unwrap();
    assert_eq!(res.shape, ShapeKind::PaypalCheckout);
    assert_eq!(res.rail, Some(Rail::Paypal));
    assert_eq!(res.amount, U128(2_500));
    assert_eq!(
        res.payload,
        SignedPayload::Message {
            text: "Charge USD 25.00 to merchant supplier@example.com for order ORD-42 at \
                   2026-11-02T06:08:20Z ref chk-1"
                .into()
        }
    );
    assert_eq!(reserved(&c), 2_500);
}

#[test]
fn over_cap_wrong_payee_and_expired_are_refused() {
    let mut c = setup();
    agent_at(NOW);
    expect_err("ERR_OVER_PER_PAYMENT_CAP", || {
        c.request_signature("chk-1".into(), checkout("50.01", NOW))
    });
    let msg = expect_err("ERR_PAYPAL_PAYEE_NOT_ALLOWED", || {
        c.request_signature(
            "chk-2".into(),
            Shape::PaypalCheckout(PaypalCheckoutRequest {
                payee: "attacker@example.com".into(),
                amount: "25.00".into(),
                order_ref: ORDER.into(),
                timestamp: NOW,
            }),
        )
    });
    assert_eq!(msg, "ERR_PAYPAL_PAYEE_NOT_ALLOWED: payee");
    expect_err("ERR_TIMESTAMP_STALE", || {
        c.request_signature("chk-3".into(), checkout("1.00", NOW - 241))
    });
    expect_err("ERR_TIMESTAMP_FUTURE", || {
        c.request_signature("chk-4".into(), checkout("1.00", NOW + 61))
    });
    let msg = expect_err("ERR_INVALID_ORDER_REF", || {
        c.request_signature(
            "chk-5".into(),
            Shape::PaypalCheckout(PaypalCheckoutRequest {
                payee: EMAIL.into(),
                amount: "1.00".into(),
                order_ref: "x at 2026".into(),
                timestamp: NOW,
            }),
        )
    });
    assert_eq!(msg, "ERR_INVALID_ORDER_REF: order_ref");
    assert_eq!(reserved(&c), 0);
}

#[test]
fn checkout_after_revoke_is_refused() {
    let mut c = setup();
    agent_at(NOW);
    let _ = c.request_signature("chk-1".into(), checkout("1.00", NOW));
    owner_at(NOW + 1);
    let _ = c.revoke(AGENT.into(), None);
    // Revoke drops the agent key, so the request fails before any shape check.
    agent_at(NOW + 2);
    expect_err("ERR_UNKNOWN_AGENT_KEY", || {
        c.request_signature("chk-2".into(), checkout("1.00", NOW + 2))
    });
    assert!(c.get_request(rkey(AGENT, "chk-2")).is_none());
}

#[test]
fn checkout_and_payout_share_the_paypal_budget() {
    let mut c = setup();
    agent_at(NOW);
    let _ = c.request_signature("inv-1".into(), paypal("50.00", NOW));
    let _ = c.request_signature("chk-1".into(), checkout("50.00", NOW + 1));
    assert_eq!(reserved(&c), 10_000);
    expect_err("ERR_OVER_BUDGET", || {
        c.request_signature("chk-2".into(), checkout("0.01", NOW + 2))
    });
}

#[test]
fn same_charge_under_a_new_request_id_or_order_ref_is_refused() {
    let mut c = setup();
    agent_at(NOW);
    let _ = c.request_signature("chk-1".into(), checkout("10.00", NOW));
    expect_err("ERR_DUPLICATE_PAYOUT", || {
        c.request_signature(
            "chk-2".into(),
            Shape::PaypalCheckout(PaypalCheckoutRequest {
                payee: "SUPPLIER@example.com".into(),
                amount: "10.00".into(),
                order_ref: "ORD-43".into(),
                timestamp: NOW,
            }),
        )
    });
    // A shape 4 payout with the same fields is a different dedupe set.
    let _ = c.request_signature("inv-1".into(), paypal("10.00", NOW));
    assert!(c.get_request(rkey(AGENT, "inv-1")).is_some());
}

#[test]
fn mandate_without_a_paypal_rail_refuses_shape_5() {
    let mut c = setup();
    owner_at(NOW);
    let mut m = mandate();
    m.paypal = None;
    c.set_mandate(AGENT.into(), m, None);
    agent_at(NOW);
    expect_err("ERR_SHAPE_NOT_ALLOWED", || {
        c.request_signature("chk-1".into(), checkout("1.00", NOW))
    });
}

#[test]
fn shape_json_is_paypal_checkout() {
    let json = serde_json::to_value(checkout("1.00", NOW)).unwrap();
    assert_eq!(json["type"], "paypal_checkout");
    assert_eq!(json["order_ref"], ORDER);
    assert_eq!(ShapeKind::PaypalCheckout.tag(), 6);
}
