//! PP-T1 pipeline tests for shape 6 (PayPal refund): `request_signature` with a `refund`
//! shape, its own `paypal_refund` rail (per-refund cap and daily budget, apart from the
//! PayPal payout budget), and the refusal of a "refund all orders" burst once the cap or the
//! budget is reached. The builder's own checks are unit tests in `src/shapes/refund.rs`; the
//! captured-minus-refunded bound is the rail's (rails/paypal). The owner is a NEAR wallet here.

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
const CAPTURE: &str = "4E871663M29867546";
const NOW: u64 = 1_793_599_700;
const WEEK: u64 = 604_800;
const DAY: u64 = 86_400;

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

fn rail(max: u128, budget: u128, period_secs: u64) -> RailMandate {
    RailMandate {
        amount_range: AmountRange {
            min: U128(1),
            max: U128(max),
        },
        budget: U128(budget),
        period_secs,
    }
}

/// PayPal payouts: 50.00 USD cap, 100.00 per week. Refunds: 10.00 USD cap, 15.00 per day.
fn mandate() -> Mandate {
    Mandate {
        x402: rail(10_000, 25_000, WEEK),
        sepa: rail(50 * 10u128.pow(18), 200 * 10u128.pow(18), WEEK),
        usdc_address: USDC.into(),
        eure_address: EURE.into(),
        chain_id: 84532,
        float_cap: FloatCap {
            usdc: U128(25_000_000),
            eure: U128(250 * 10u128.pow(18)),
        },
        max_validity_secs: 300,
        paypal: Some(rail(5_000, 10_000, WEEK)),
        paypal_refund: Some(rail(1_000, 1_500, DAY)),
        usdc_eip712_name: "USDC".into(),
        usdc_eip712_version: "2".into(),
    }
}

fn setup() -> Contract {
    owner_at(NOW);
    let mut c = Contract::new(
        OwnerMode::Wallet {
            account: acc(WALLET),
        },
        "testnet".into(),
        acc(MPC),
    );
    owner_at(NOW);
    let pk = key(1);
    let _ = c.add_agent(
        AGENT.into(),
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
    assert!(c.on_agent_key_added(AGENT.into(), pk));
    owner_at(NOW);
    c.set_mandate(AGENT.into(), mandate(), None);
    c
}

fn refund(capture_id: &str, amount: &str) -> Shape {
    Shape::Refund(RefundRequest {
        capture_id: capture_id.into(),
        amount: amount.into(),
    })
}

fn rkey(request_id: &str) -> RequestKey {
    RequestKey {
        agent: AGENT.into(),
        caller: Caller::Agent,
        request_id: request_id.into(),
    }
}

fn reserved(c: &Contract, rail: Rail) -> u128 {
    c.get_budget(AGENT.into(), rail).unwrap().reserved.0
}

#[test]
fn refund_is_signed_and_reserved_on_the_refund_rail() {
    let mut c = setup();
    agent_at(NOW);
    let _ = c.request_signature("refund-1".into(), refund(CAPTURE, "4.00"));
    let res = c.get_request(rkey("refund-1")).unwrap();
    assert_eq!(res.shape, ShapeKind::Refund);
    assert_eq!(res.rail, Some(Rail::PaypalRefund));
    assert_eq!(res.amount, U128(400));
    assert_eq!(res.status, RequestStatus::Pending);
    assert_eq!(
        res.payload,
        SignedPayload::Message {
            text: "Refund USD 4.00 of capture 4E871663M29867546 ref refund-1".into()
        }
    );
    assert_eq!(res.valid_before, NOW + 240);
    assert_eq!(reserved(&c, Rail::PaypalRefund), 400);
    // Refunds never use the payout budget, and the other way round.
    assert_eq!(reserved(&c, Rail::Paypal), 0);
    let view = c.get_budget(AGENT.into(), Rail::PaypalRefund).unwrap();
    assert_eq!((view.budget, view.period_secs), (U128(1_500), DAY));
}

#[test]
fn over_the_per_refund_cap_is_refused() {
    let mut c = setup();
    agent_at(NOW);
    let msg = expect_err("ERR_OVER_PER_PAYMENT_CAP", || {
        c.request_signature("refund-1".into(), refund(CAPTURE, "10.01"))
    });
    assert_eq!(msg, "ERR_OVER_PER_PAYMENT_CAP: amount");
    assert!(c.get_request(rkey("refund-1")).is_none());
    assert_eq!(reserved(&c, Rail::PaypalRefund), 0);
    // The payout cap (50.00) does not apply to refunds.
    let _ = c.request_signature("refund-2".into(), refund(CAPTURE, "10.00"));
    assert_eq!(reserved(&c, Rail::PaypalRefund), 1_000);
}

#[test]
fn refund_all_orders_burst_is_refused_after_the_daily_budget() {
    let mut c = setup();
    agent_at(NOW);
    // Two genuine refunds: 4.00 + 6.00 of the 15.00 daily budget.
    let _ = c.request_signature("refund-1".into(), refund(CAPTURE, "4.00"));
    let _ = c.request_signature("refund-2".into(), refund("5RT48122BA4404726", "6.00"));
    // "Refund all orders": each capture in full, one after another.
    let _ = c.request_signature("refund-3".into(), refund("8MC585209K746392H", "5.00"));
    assert_eq!(reserved(&c, Rail::PaypalRefund), 1_500);
    for (i, capture) in ["2GG279541U471931P", "0VF52814937998046"]
        .iter()
        .enumerate()
    {
        let id = format!("refund-{}", 4 + i);
        let msg = expect_err("ERR_OVER_BUDGET", || {
            c.request_signature(id.clone(), refund(capture, "0.01"))
        });
        assert!(msg.contains("budget 1500"), "{msg}");
        assert!(c.get_request(rkey(&id)).is_none());
    }
    assert_eq!(reserved(&c, Rail::PaypalRefund), 1_500);
    // The budget is daily: the next window takes refunds again.
    agent_at(NOW + DAY);
    let _ = c.request_signature("refund-6".into(), refund(CAPTURE, "1.00"));
    assert_eq!(reserved(&c, Rail::PaypalRefund), 100);
}

#[test]
fn duplicate_request_id_is_refused() {
    let mut c = setup();
    agent_at(NOW);
    let _ = c.request_signature("refund-1".into(), refund(CAPTURE, "1.00"));
    expect_err("ERR_DUPLICATE_REQUEST_ID", || {
        c.request_signature("refund-1".into(), refund(CAPTURE, "2.00"))
    });
    assert_eq!(reserved(&c, Rail::PaypalRefund), 100);
}

#[test]
fn shape_check_failures_name_the_field() {
    let mut c = setup();
    agent_at(NOW);
    let msg = expect_err("ERR_INVALID_CAPTURE_ID", || {
        c.request_signature(
            "refund-1".into(),
            refund("4E871663M29867546/refund", "1.00"),
        )
    });
    assert_eq!(msg, "ERR_INVALID_CAPTURE_ID: capture_id");
    let msg = expect_err("ERR_INVALID_AMOUNT", || {
        c.request_signature("refund-2".into(), refund(CAPTURE, "1.5"))
    });
    assert_eq!(msg, "ERR_INVALID_AMOUNT: amount");
    assert_eq!(reserved(&c, Rail::PaypalRefund), 0);
}

#[test]
fn mandate_without_a_refund_rail_refuses_shape_6() {
    let mut c = setup();
    owner_at(NOW);
    let mut m = mandate();
    m.paypal_refund = None;
    c.set_mandate(AGENT.into(), m, None);
    assert!(c.get_budget(AGENT.into(), Rail::PaypalRefund).is_none());
    agent_at(NOW);
    let msg = expect_err("ERR_SHAPE_NOT_ALLOWED", || {
        c.request_signature("refund-1".into(), refund(CAPTURE, "1.00"))
    });
    assert_eq!(msg, "ERR_SHAPE_NOT_ALLOWED: mandate.paypal_refund");
}

#[test]
fn revoked_agent_cannot_request_a_refund() {
    let mut c = setup();
    owner_at(NOW);
    let _ = c.revoke(AGENT.into(), None);
    agent_at(NOW);
    expect_err("ERR_UNKNOWN_AGENT_KEY", || {
        c.request_signature("refund-1".into(), refund(CAPTURE, "1.00"))
    });
}

#[test]
fn refund_rail_limits_are_validated() {
    let mut c = setup();
    for (bad, detail) in [
        (
            rail(2_000_001, 10_000_000, DAY),
            "paypal_refund.amount_range max > 20000.00 USD",
        ),
        (
            RailMandate {
                amount_range: AmountRange {
                    min: U128(0),
                    max: U128(100),
                },
                ..rail(100, 100, DAY)
            },
            "paypal_refund.amount_range min is 0",
        ),
        (
            RailMandate {
                amount_range: AmountRange {
                    min: U128(200),
                    max: U128(100),
                },
                ..rail(100, 100, DAY)
            },
            "paypal_refund.amount_range min > max",
        ),
        (rail(100, 100, 0), "paypal_refund.period_secs"),
    ] {
        let mut m = mandate();
        m.paypal_refund = Some(bad);
        owner_at(NOW);
        let msg = expect_err("ERR_INVALID_MANDATE", || {
            c.set_mandate(AGENT.into(), m, None)
        });
        assert_eq!(msg, format!("ERR_INVALID_MANDATE: {detail}"));
    }
}

#[test]
fn refund_json_shapes() {
    let mut m = mandate();
    m.paypal_refund = None;
    let v = serde_json::to_value(&m).unwrap();
    assert!(v.get("paypal_refund").is_none());
    let back: Mandate = serde_json::from_value(v).unwrap();
    assert_eq!(back, m);
    let v = serde_json::to_value(mandate()).unwrap();
    assert_eq!(v["paypal_refund"]["period_secs"], 86_400);
    let shape: Shape = serde_json::from_str(
        r#"{"type":"refund","capture_id":"4E871663M29867546","amount":"1.00"}"#,
    )
    .unwrap();
    assert_eq!(shape.kind(), ShapeKind::Refund);
    assert_eq!(ShapeKind::Refund.tag(), 7);
    assert_eq!(
        serde_json::to_value(Rail::PaypalRefund).unwrap(),
        "paypal_refund"
    );
}
