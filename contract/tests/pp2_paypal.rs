//! PP2 pipeline tests for shape 4 (PayPal payout): `request_signature` with a `paypal`
//! shape, its `paypal` budget, and the two dedupes (`request_id` per caller and agent, and
//! `(payee, amount, timestamp)` per agent, D3). The builder's own checks are unit tests in
//! `src/shapes/paypal.rs`. The owner is a NEAR wallet here.

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
fn paypal_payout_is_signed_and_reserved_on_the_paypal_rail() {
    let mut c = setup();
    assert_eq!(
        c.get_payees(AGENT.into()),
        vec![Payee::Paypal {
            receiver: EMAIL.into()
        }]
    );
    agent_at(NOW);
    let _ = c.request_signature("inv-1".into(), paypal("42.50", NOW));
    let res = c.get_request(rkey(AGENT, "inv-1")).unwrap();
    assert_eq!(res.shape, ShapeKind::Paypal);
    assert_eq!(res.rail, Some(Rail::Paypal));
    assert_eq!(res.amount, U128(4_250));
    assert_eq!(
        res.payload,
        SignedPayload::Message {
            text: "Send USD 42.50 to supplier@example.com at 2026-11-02T06:08:20Z ref inv-1".into()
        }
    );
    assert_eq!(reserved(&c), 4_250);
    // Rails keep separate budgets.
    assert_eq!(
        c.get_budget(AGENT.into(), Rail::Sepa).unwrap().reserved.0,
        0
    );
}

#[test]
fn over_budget_is_refused() {
    let mut c = setup();
    agent_at(NOW);
    let _ = c.request_signature("inv-1".into(), paypal("50.00", NOW));
    let _ = c.request_signature("inv-2".into(), paypal("50.00", NOW + 1));
    assert_eq!(reserved(&c), 10_000);
    expect_err("ERR_OVER_BUDGET", || {
        c.request_signature("inv-3".into(), paypal("0.01", NOW + 2))
    });
    assert!(c.get_request(rkey(AGENT, "inv-3")).is_none());
}

#[test]
fn duplicate_request_id_is_refused() {
    let mut c = setup();
    agent_at(NOW);
    let _ = c.request_signature("inv-1".into(), paypal("1.00", NOW));
    // Same id, different order: refused before any shape check.
    expect_err("ERR_DUPLICATE_REQUEST_ID", || {
        c.request_signature("inv-1".into(), paypal("2.00", NOW + 1))
    });
    assert_eq!(reserved(&c), 100);
}

#[test]
fn same_order_under_a_new_request_id_is_refused() {
    let mut c = setup();
    add_agent(&mut c, "agent-b", key(2));
    owner_at(NOW);
    c.set_mandate("agent-b".into(), mandate(), None);
    c.add_payee(
        "agent-b".into(),
        Payee::Paypal {
            receiver: EMAIL.into(),
        },
        None,
    );
    agent_at(NOW);
    let _ = c.request_signature("inv-a".into(), paypal("10.00", NOW));
    // Another agent may sign the same payee, amount and second.
    call_at(CONTRACT, key(2), NOW, vec![]);
    let _ = c.request_signature("inv-b".into(), paypal("10.00", NOW));
    assert!(c.get_request(rkey("agent-b", "inv-b")).is_some());
    // The same agent, a new request_id (PayPal would pay a new sender_batch_id again), and
    // the payee spelt differently: refused.
    agent_at(NOW);
    expect_err("ERR_DUPLICATE_PAYOUT", || {
        c.request_signature(
            "inv-a2".into(),
            Shape::Paypal(PaypalRequest {
                payee: "SUPPLIER@example.com ".into(),
                amount: "10.00".into(),
                timestamp: NOW,
            }),
        )
    });
    assert!(c.get_request(rkey(AGENT, "inv-a2")).is_none());
    // A new timestamp is a new order.
    let _ = c.request_signature("inv-a3".into(), paypal("10.00", NOW + 1));
    assert!(c.get_request(rkey(AGENT, "inv-a3")).is_some());
}

#[test]
fn shape_check_failures_name_the_field() {
    let mut c = setup();
    agent_at(NOW);
    let msg = expect_err("ERR_PAYPAL_PAYEE_NOT_ALLOWED", || {
        c.request_signature(
            "inv-1".into(),
            Shape::Paypal(PaypalRequest {
                payee: "attacker@example.com".into(),
                amount: "1.00".into(),
                timestamp: NOW,
            }),
        )
    });
    assert_eq!(msg, "ERR_PAYPAL_PAYEE_NOT_ALLOWED: payee");
    let msg = expect_err("ERR_INVALID_AMOUNT", || {
        c.request_signature("inv-2".into(), paypal("1.5", NOW))
    });
    assert_eq!(msg, "ERR_INVALID_AMOUNT: amount");
    expect_err("ERR_OVER_PER_PAYMENT_CAP", || {
        c.request_signature("inv-3".into(), paypal("50.01", NOW))
    });
    expect_err("ERR_TIMESTAMP_STALE", || {
        c.request_signature("inv-4".into(), paypal("1.00", NOW - 241))
    });
    expect_err("ERR_TIMESTAMP_FUTURE", || {
        c.request_signature("inv-5".into(), paypal("1.00", NOW + 61))
    });
    assert_eq!(reserved(&c), 0);
}

#[test]
fn mandate_without_a_paypal_rail_refuses_shape_4() {
    let mut c = setup();
    owner_at(NOW);
    let mut m = mandate();
    m.paypal = None;
    c.set_mandate(AGENT.into(), m, None);
    assert!(c.get_budget(AGENT.into(), Rail::Paypal).is_none());
    agent_at(NOW);
    let msg = expect_err("ERR_SHAPE_NOT_ALLOWED", || {
        c.request_signature("inv-1".into(), paypal("1.00", NOW))
    });
    assert_eq!(msg, "ERR_SHAPE_NOT_ALLOWED: mandate.paypal");
}

#[test]
fn paypal_rail_limits_are_validated() {
    let mut c = setup();
    for (bad, detail) in [
        (
            rail(2_000_001, 10_000_000),
            "paypal.amount_range max > 20000.00 USD",
        ),
        (
            RailMandate {
                amount_range: AmountRange {
                    min: U128(0),
                    max: U128(100),
                },
                ..rail(100, 100)
            },
            "paypal.amount_range min is 0",
        ),
        (
            RailMandate {
                period_secs: 0,
                ..rail(100, 100)
            },
            "paypal.period_secs",
        ),
    ] {
        let mut m = mandate();
        m.paypal = Some(bad);
        owner_at(NOW);
        let msg = expect_err("ERR_INVALID_MANDATE", || {
            c.set_mandate(AGENT.into(), m, None)
        });
        assert_eq!(msg, format!("ERR_INVALID_MANDATE: {detail}"));
    }
}

#[test]
fn invalid_paypal_payee_is_refused_by_add_payee() {
    let mut c = setup();
    owner_at(NOW);
    expect_err("ERR_INVALID_PAYPAL_PAYEE", || {
        c.add_payee(
            AGENT.into(),
            Payee::Paypal {
                receiver: "not an email".into(),
            },
            None,
        )
    });
    // remove_payee matches the normalised form; an unlisted one names the rail's error.
    expect_err("ERR_PAYPAL_PAYEE_NOT_ALLOWED", || {
        c.remove_payee(
            AGENT.into(),
            Payee::Paypal {
                receiver: "@other-handle".into(),
            },
            None,
        )
    });
    c.remove_payee(
        AGENT.into(),
        Payee::Paypal {
            receiver: "SUPPLIER@EXAMPLE.COM".into(),
        },
        None,
    );
    assert!(c.get_payees(AGENT.into()).is_empty());
}

#[test]
fn mandate_json_omits_an_absent_paypal_rail() {
    let mut m = mandate();
    m.paypal = None;
    let v = serde_json::to_value(&m).unwrap();
    assert!(v.get("paypal").is_none());
    let back: Mandate = serde_json::from_value(v).unwrap();
    assert_eq!(back, m);
    let shape: Shape = serde_json::from_str(
        r#"{"type":"paypal","payee":"supplier@example.com","amount":"1.00","timestamp":1}"#,
    )
    .unwrap();
    assert_eq!(shape.kind(), ShapeKind::Paypal);
}
