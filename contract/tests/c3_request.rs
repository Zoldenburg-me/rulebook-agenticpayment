//! C3 unit tests: the request pipeline. `request_signature` (dedupe, shape filter, budget
//! per rail, the MPC call), the `on_signature` callback, `expire_pending` and
//! `resolve_reservation`. The owner is a NEAR wallet here; passkey owner calls are C2's tests.

mod mock_mpc;

use std::panic::{catch_unwind, AssertUnwindSafe};

use mandate::events::MandateEvent;
use mandate::types::*;
use mandate::Contract;
use near_sdk::json_types::U128;
use near_sdk::mock::MockAction;
use near_sdk::serde_json::{self, json, Value};
use near_sdk::test_utils::{get_created_receipts, get_logs, VMContextBuilder};
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
/// The MPC response recorded in spikes/chainsig (`recovery_id` 1, `big_r` prefix 02).
const MPC_RESPONSE: &str = r#"{"scheme":"Secp256k1","big_r":{"affine_point":"025650b556dbf54a03596dd195c0d850ccb07ba2c0c5af0233477d9c2f6d67639c"},"s":{"scalar":"2c67c30ea3bf01f0e8a66e4b4c337d87d477d7a7f8b8c89d70a9a1b3ee3b2424"},"recovery_id":1}"#;

// ---------- environment ----------

fn acc(s: &str) -> AccountId {
    s.parse().unwrap()
}

fn key(n: u8) -> PublicKey {
    format!("ed25519:{}", near_sdk::bs58::encode([n; 32]).into_string())
        .parse()
        .unwrap()
}

/// The wallet owner attaches 1 yoctoNEAR, as its full-access key must; other callers attach
/// nothing (function-call keys cannot).
fn owner_deposit(predecessor: &str) -> NearToken {
    NearToken::from_yoctonear(if predecessor == WALLET { 1 } else { 0 })
}

fn call_at(predecessor: &str, signer_pk: PublicKey, now: u64, results: Vec<PromiseResult>) {
    let ctx = VMContextBuilder::new()
        .current_account_id(acc(CONTRACT))
        .predecessor_account_id(acc(predecessor))
        .signer_account_id(acc(predecessor))
        .signer_account_pk(signer_pk)
        .attached_deposit(owner_deposit(predecessor))
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

fn anyone_at(now: u64) {
    call_at("anyone.testnet", key(202), now, vec![])
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

fn events() -> Vec<MandateEvent> {
    get_logs()
        .iter()
        .filter_map(|l| l.strip_prefix("EVENT_JSON:"))
        .map(|j| serde_json::from_str::<EventLog>(j).unwrap().event)
        .collect()
}

#[derive(near_sdk::serde::Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct EventLog {
    #[serde(flatten)]
    event: MandateEvent,
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

fn reserved(c: &Contract) -> u128 {
    c.get_budget(AGENT.into(), Rail::X402).unwrap().reserved.0
}

fn status(c: &Contract, id: &str) -> RequestStatus {
    c.get_request(rkey(AGENT, id)).unwrap().status
}

/// A pending request that the MPC callback then fails: status `unknown`.
fn unknown_request(c: &mut Contract, id: &str, amount: u128) {
    request_at(c, NOW, id, amount);
    mpc_callback_at(NOW + 10, PromiseResult::Failed);
    c.on_signature(rkey(AGENT, id));
    assert_eq!(status(c, id), RequestStatus::Unknown);
}

// ---------- request_signature ----------

#[test]
fn request_within_limits_is_reserved_and_sent_to_the_mpc() {
    let mut c = setup();
    agent_at(NOW);
    let _ = c.request_signature("pay-0001".into(), x402(10_000));

    let res = c.get_request(rkey(AGENT, "pay-0001")).unwrap();
    assert_eq!(res.status, RequestStatus::Pending);
    assert_eq!(res.shape, ShapeKind::X402);
    assert_eq!(res.rail, Some(Rail::X402));
    assert_eq!(res.amount, U128(10_000));
    assert_eq!(res.created_at_ms, NOW * 1000);
    assert_eq!(
        res.period_start_ms,
        NOW * 1000,
        "window starts at set_mandate"
    );
    assert!(res.counts_against_budget);
    assert!(res.signature.is_none());
    assert!(matches!(
        &res.payload,
        SignedPayload::Eip3009 { to, value, .. } if to == PAY_TO && *value == U128(10_000)
    ));
    assert_eq!(reserved(&c), 10_000);

    // One MPC `sign` call with the contract-built digest on path = agent id, then the callback.
    let receipts = get_created_receipts();
    let sign = receipts
        .iter()
        .find(|r| r.receiver_id == acc(MPC))
        .expect("sign receipt");
    let (method, args, deposit) = match &sign.actions[..] {
        [MockAction::FunctionCallWeight {
            method_name,
            args,
            attached_deposit,
            ..
        }] => (method_name.clone(), args.clone(), *attached_deposit),
        other => panic!("unexpected actions {other:?}"),
    };
    assert_eq!(method, b"sign");
    assert_eq!(deposit, NearToken::from_yoctonear(1));
    let args: Value = serde_json::from_slice(&args).unwrap();
    assert_eq!(
        args,
        json!({"request": {
            "payload_v2": {"Ecdsa": res.digest.trim_start_matches("0x")},
            "path": AGENT,
            "domain_id": 0
        }})
    );
    let callback = receipts
        .iter()
        .find(|r| r.receiver_id == acc(CONTRACT))
        .expect("callback receipt");
    assert!(matches!(
        &callback.actions[..],
        [MockAction::FunctionCallWeight { method_name, .. }] if method_name == b"on_signature"
    ));

    assert!(matches!(
        &events()[..],
        [MandateEvent::SignatureRequested { key, amount, .. }]
            if *key == rkey(AGENT, "pay-0001") && *amount == U128(10_000)
    ));
}

#[test]
fn request_over_the_rail_budget_is_rejected() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    request_at(&mut c, NOW, "p2", 10_000);
    // 20_000 reserved of 25_000: 5_001 does not fit, 5_000 fits exactly.
    agent_at(NOW);
    let msg = expect_err("ERR_OVER_BUDGET", || {
        c.request_signature("p3".into(), x402(5_001))
    });
    assert!(msg.contains("budget 25000"), "{msg}");
    assert!(
        c.get_request(rkey(AGENT, "p3")).is_none(),
        "nothing reserved"
    );
    request_at(&mut c, NOW, "p4", 5_000);
    assert_eq!(reserved(&c), 25_000);
    agent_at(NOW);
    expect_err("ERR_OVER_BUDGET", || {
        c.request_signature("p5".into(), x402(1))
    });
}

#[test]
fn pending_and_unknown_reservations_keep_counting() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000); // stays pending
    unknown_request(&mut c, "p2", 10_000);
    assert_eq!(reserved(&c), 20_000);
    agent_at(NOW + 20);
    expect_err("ERR_OVER_BUDGET", || {
        c.request_signature("p3".into(), x402(10_000))
    });
}

#[test]
fn budget_window_rolls_forward_and_a_reservation_counts_in_its_own_window() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    request_at(&mut c, NOW, "p2", 10_000);
    request_at(&mut c, NOW, "p3", 5_000);
    // Last second of the first window: still full.
    agent_at(NOW + WEEK - 1);
    expect_err("ERR_OVER_BUDGET", || {
        c.request_signature("p4".into(), x402(1))
    });
    // The next window (D7) starts empty, back to back with the first.
    request_at(&mut c, NOW + WEEK + 5, "p5", 10_000);
    let res = c.get_request(rkey(AGENT, "p5")).unwrap();
    assert_eq!(res.period_start_ms, (NOW + WEEK) * 1000);
    assert_eq!(reserved(&c), 10_000);
}

#[test]
fn rails_have_separate_budgets() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    request_at(&mut c, NOW, "p2", 10_000);
    request_at(&mut c, NOW, "p3", 5_000);
    assert_eq!(reserved(&c), 25_000);
    assert_eq!(
        c.get_budget(AGENT.into(), Rail::Sepa).unwrap().reserved,
        U128(0)
    );
}

#[test]
fn reused_request_id_is_rejected() {
    let mut c = setup();
    request_at(&mut c, NOW, "pay-0001", 1_000);
    agent_at(NOW);
    expect_err("ERR_DUPLICATE_REQUEST_ID", || {
        c.request_signature("pay-0001".into(), x402(2_000))
    });
    // Still rejected once the first one has failed and is `unknown`.
    mpc_callback_at(NOW, PromiseResult::Failed);
    c.on_signature(rkey(AGENT, "pay-0001"));
    agent_at(NOW + 1);
    expect_err("ERR_DUPLICATE_REQUEST_ID", || {
        c.request_signature("pay-0001".into(), x402(1_000))
    });
    assert_eq!(reserved(&c), 1_000);
}

#[test]
fn request_id_is_deduped_per_agent() {
    let mut c = setup();
    add_agent(&mut c, "agent-b", key(2));
    owner_at(NOW);
    c.set_mandate("agent-b".into(), mandate(), None);
    c.add_payee(
        "agent-b".into(),
        Payee::X402 {
            pay_to: PAY_TO.into(),
        },
        None,
    );
    request_at(&mut c, NOW, "pay-0001", 1_000);
    call_at(CONTRACT, key(2), NOW, vec![]);
    let _ = c.request_signature("pay-0001".into(), x402(1_000));
    let a = c.get_request(rkey(AGENT, "pay-0001")).unwrap();
    let b = c.get_request(rkey("agent-b", "pay-0001")).unwrap();
    assert_ne!(a.payload, b.payload, "different EIP-3009 nonces");
}

#[test]
fn invalid_request_id_is_rejected() {
    let mut c = setup();
    for id in ["", "has space", "slash/no", &"x".repeat(65)] {
        agent_at(NOW);
        expect_err("ERR_INVALID_REQUEST_ID", || {
            c.request_signature(id.into(), x402(1))
        });
    }
}

#[test]
fn sweep_and_link_shapes_are_not_allowed() {
    let mut c = setup();
    agent_at(NOW);
    expect_err("ERR_SHAPE_NOT_ALLOWED", || {
        c.request_signature(
            "s1".into(),
            Shape::Sweep {
                token: Token::Usdc,
                amount: U128(1),
            },
        )
    });
    agent_at(NOW);
    expect_err("ERR_SHAPE_NOT_ALLOWED", || {
        c.request_signature("l1".into(), Shape::Link)
    });
}

#[test]
fn unknown_shape_type_fails_argument_parsing() {
    for bad in [
        r#"{"type":"permit","amount":"1"}"#,
        r#"{"type":"raw","digest":"0x00"}"#,
        r#"{"amount":"1"}"#,
    ] {
        assert!(serde_json::from_str::<Shape>(bad).is_err(), "{bad}");
    }
}

#[test]
fn payout_is_checked_by_shape_3_and_reserved_on_sepa() {
    let mut c = setup();
    let payout = || {
        Shape::Payout(PayoutRequest {
            iban: "DE89370400440532013000".into(),
            amount: "42.50".into(),
            timestamp: NOW,
        })
    };
    agent_at(NOW);
    let msg = expect_err("ERR_IBAN_NOT_ALLOWED", || {
        c.request_signature("inv-1".into(), payout())
    });
    assert_eq!(msg, "ERR_IBAN_NOT_ALLOWED: iban");

    owner_at(NOW);
    c.add_payee(
        AGENT.into(),
        Payee::Sepa {
            iban: "DE89370400440532013000".into(),
        },
        None,
    );
    agent_at(NOW);
    let _ = c.request_signature("inv-2".into(), payout());
    let res = c.get_request(rkey(AGENT, "inv-2")).unwrap();
    assert_eq!(res.shape, ShapeKind::Payout);
    assert_eq!(res.rail, Some(Rail::Sepa));
    assert_eq!(res.amount, U128(42_500_000_000_000_000_000));
    assert!(matches!(
        &res.payload,
        SignedPayload::Message { text } if text.starts_with("Send EUR 42.5 to DE89370400440532013000 at ")
    ));
    assert_eq!(
        c.get_budget(AGENT.into(), Rail::Sepa).unwrap().reserved,
        res.amount
    );
}

#[test]
fn payout_is_deduped_per_agent() {
    const IBAN: &str = "DE89370400440532013000";
    let mut c = setup();
    add_agent(&mut c, "agent-b", key(2));
    owner_at(NOW);
    c.set_mandate("agent-b".into(), mandate(), None);
    for agent in [AGENT, "agent-b"] {
        c.add_payee(agent.into(), Payee::Sepa { iban: IBAN.into() }, None);
    }
    let payout = || {
        Shape::Payout(PayoutRequest {
            iban: IBAN.into(),
            amount: "10".into(),
            timestamp: NOW,
        })
    };
    // Two agents, same IBAN, amount and second: both signed.
    agent_at(NOW);
    let _ = c.request_signature("inv-a".into(), payout());
    call_at(CONTRACT, key(2), NOW, vec![]);
    let _ = c.request_signature("inv-b".into(), payout());
    assert!(c.get_request(rkey(AGENT, "inv-a")).is_some());
    assert!(c.get_request(rkey("agent-b", "inv-b")).is_some());
    // The same agent re-submitting the same order, even as `10.00` under a new id: refused.
    agent_at(NOW);
    expect_err("ERR_DUPLICATE_PAYOUT", || {
        c.request_signature(
            "inv-a2".into(),
            Shape::Payout(PayoutRequest {
                iban: IBAN.into(),
                amount: "10.00".into(),
                timestamp: NOW,
            }),
        )
    });
    assert!(c.get_request(rkey(AGENT, "inv-a2")).is_none());
}

#[test]
fn shape_check_failure_names_the_field_and_reserves_nothing() {
    let mut c = setup();
    let Shape::X402(mut req) = x402(1_000) else {
        unreachable!()
    };
    req.pay_to = "0x000000000000000000000000000000000000dead".into();
    agent_at(NOW);
    let msg = expect_err("ERR_PAYEE_NOT_ALLOWED", || {
        c.request_signature("p1".into(), Shape::X402(req))
    });
    assert_eq!(msg, "ERR_PAYEE_NOT_ALLOWED: payTo");
    agent_at(NOW);
    expect_err("ERR_OVER_PER_PAYMENT_CAP", || {
        c.request_signature("p2".into(), x402(10_001))
    });
    assert_eq!(reserved(&c), 0);
}

#[test]
fn request_without_a_mandate_is_rejected() {
    let mut c = setup();
    add_agent(&mut c, "agent-b", key(2));
    call_at(CONTRACT, key(2), NOW, vec![]);
    expect_err("ERR_NO_MANDATE", || {
        c.request_signature("p1".into(), x402(1))
    });
}

#[test]
fn request_after_revoke_fails() {
    let mut c = setup();
    owner_at(NOW);
    let _ = c.revoke(AGENT.into(), None);
    agent_at(NOW);
    expect_err("ERR_UNKNOWN_AGENT_KEY", || {
        c.request_signature("p1".into(), x402(1))
    });
}

#[test]
fn request_after_revoke_self_fails() {
    let mut c = setup();
    agent_at(NOW);
    let _ = c.revoke_self();
    agent_at(NOW);
    expect_err("ERR_UNKNOWN_AGENT_KEY", || {
        c.request_signature("p1".into(), x402(1))
    });
}

#[test]
fn request_not_signed_with_an_agent_key_is_rejected() {
    let mut c = setup();
    call_at("anyone.testnet", key(1), NOW, vec![]);
    expect_err("ERR_NOT_AGENT_KEY", || {
        c.request_signature("p1".into(), x402(1))
    });
    call_at(CONTRACT, key(9), NOW, vec![]);
    expect_err("ERR_UNKNOWN_AGENT_KEY", || {
        c.request_signature("p1".into(), x402(1))
    });
}

// ---------- on_signature ----------

#[test]
fn mpc_response_takes_v_from_recovery_id() {
    let sig = mandate::request::parse_mpc_response(MPC_RESPONSE.as_bytes()).unwrap();
    let expected = EvmSignature {
        r: "0x5650b556dbf54a03596dd195c0d850ccb07ba2c0c5af0233477d9c2f6d67639c".into(),
        s: "0x2c67c30ea3bf01f0e8a66e4b4c337d87d477d7a7f8b8c89d70a9a1b3ee3b2424".into(),
        v: 28, // recovery_id 1, although the big_r prefix is 02
    };
    assert_eq!(sig, expected);
}

#[test]
fn callback_success_records_signed() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    let response = mpc_ok(&c, "p1");
    let PromiseResult::Successful(body) = &response else {
        unreachable!()
    };
    let sig = mandate::request::parse_mpc_response(body).unwrap();
    mpc_callback_at(NOW + 12, response);
    let res = c.on_signature(rkey(AGENT, "p1"));
    assert_eq!(res.status, RequestStatus::Signed);
    assert_eq!(res.signature.as_ref(), Some(&sig));
    assert_eq!(c.get_request(rkey(AGENT, "p1")), Some(res));
    assert_eq!(reserved(&c), 10_000, "signed keeps counting");
    assert_eq!(
        events(),
        vec![MandateEvent::SignatureRecorded {
            key: rkey(AGENT, "p1"),
            status: RequestStatus::Signed,
            signature: sig,
        }]
    );
}

#[test]
fn callback_failure_marks_unknown_and_keeps_counting() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    mpc_callback_at(NOW + 12, PromiseResult::Failed);
    let res = c.on_signature(rkey(AGENT, "p1"));
    assert_eq!(res.status, RequestStatus::Unknown);
    assert!(res.signature.is_none());
    assert!(res.counts_against_budget);
    assert_eq!(reserved(&c), 10_000);
    assert_eq!(
        events(),
        vec![MandateEvent::RequestUnknown {
            key: rkey(AGENT, "p1"),
            reason: UnknownReason::CallbackFailed,
        }]
    );
}

#[test]
fn malformed_mpc_response_marks_unknown_without_panicking() {
    let bad: [&[u8]; 5] = [
        b"not json",
        br#"{"big_r":{"affine_point":"04aa"},"s":{"scalar":"01"},"recovery_id":0}"#,
        br#"{"big_r":{"affine_point":"025650b556dbf54a03596dd195c0d850ccb07ba2c0c5af0233477d9c2f6d67639c"},"s":{"scalar":"zz"},"recovery_id":0}"#,
        br#"{"big_r":{"affine_point":"025650b556dbf54a03596dd195c0d850ccb07ba2c0c5af0233477d9c2f6d67639c"},"s":{"scalar":"01"},"recovery_id":2}"#,
        &[b'x'; 2000],
    ];
    let mut c = setup();
    for (i, body) in bad.into_iter().enumerate() {
        let id = format!("p{i}");
        request_at(&mut c, NOW, &id, 1);
        mpc_callback_at(NOW + 1, PromiseResult::Successful(body.to_vec()));
        assert_eq!(
            c.on_signature(rkey(AGENT, &id)).status,
            RequestStatus::Unknown
        );
    }
}

#[test]
fn short_scalar_is_left_padded() {
    let sig = mandate::request::parse_mpc_response(
        br#"{"big_r":{"affine_point":"035650b556dbf54a03596dd195c0d850ccb07ba2c0c5af0233477d9c2f6d67639c"},"s":{"scalar":"ABC"},"recovery_id":0}"#,
    )
    .unwrap();
    assert_eq!(sig.s, format!("0x{}abc", "0".repeat(61)));
    assert_eq!(sig.v, 27);
}

#[test]
fn callback_after_revoke_records_revoked_with_the_signature() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    owner_at(NOW + 1);
    let _ = c.revoke(AGENT.into(), None);
    mpc_callback_at(NOW + 12, mpc_ok(&c, "p1"));
    let res = c.on_signature(rkey(AGENT, "p1"));
    assert_eq!(res.status, RequestStatus::Revoked);
    assert!(
        res.signature.is_some(),
        "D10: the signature is still returned"
    );
}

// ---------- expire_pending ----------

#[test]
fn expire_pending_before_the_mpc_timeout_is_rejected() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    anyone_at(NOW + MPC_TIMEOUT_MS / 1000 - 1);
    expect_err("ERR_MPC_TIMEOUT_NOT_REACHED", || {
        c.expire_pending(rkey(AGENT, "p1"))
    });
    assert_eq!(status(&c, "p1"), RequestStatus::Pending);
}

#[test]
fn expire_pending_after_the_timeout_marks_unknown() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    anyone_at(NOW + MPC_TIMEOUT_MS / 1000);
    c.expire_pending(rkey(AGENT, "p1"));
    assert_eq!(status(&c, "p1"), RequestStatus::Unknown);
    assert_eq!(reserved(&c), 10_000);
    assert_eq!(
        events(),
        vec![MandateEvent::RequestUnknown {
            key: rkey(AGENT, "p1"),
            reason: UnknownReason::MpcTimeout,
        }]
    );
    // Only a pending request expires.
    anyone_at(NOW + 400);
    expect_err("ERR_BAD_TRANSITION", || c.expire_pending(rkey(AGENT, "p1")));
    expect_err("ERR_REQUEST_NOT_FOUND", || {
        c.expire_pending(rkey(AGENT, "nope"))
    });
}

#[test]
fn late_callback_after_expiry_still_records_signed() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    anyone_at(NOW + 300);
    c.expire_pending(rkey(AGENT, "p1"));
    mpc_callback_at(NOW + 310, mpc_ok(&c, "p1"));
    let res = c.on_signature(rkey(AGENT, "p1"));
    assert_eq!(res.status, RequestStatus::Signed);
    assert!(res.signature.is_some());
}

#[test]
fn failed_callback_after_expiry_is_a_no_op() {
    let mut c = setup();
    request_at(&mut c, NOW, "p1", 10_000);
    anyone_at(NOW + 300);
    c.expire_pending(rkey(AGENT, "p1"));
    mpc_callback_at(NOW + 310, PromiseResult::Failed);
    assert_eq!(
        c.on_signature(rkey(AGENT, "p1")).status,
        RequestStatus::Unknown
    );
    assert!(events().is_empty(), "no second request_unknown");
}

// ---------- resolve_reservation ----------

#[test]
fn released_is_refused_before_release_after() {
    let mut c = setup();
    unknown_request(&mut c, "p1", 10_000);
    let release_after = c.get_request(rkey(AGENT, "p1")).unwrap().release_after;
    assert!(release_after > NOW);
    owner_at(release_after - 1);
    expect_err("ERR_VALIDITY_NOT_ENDED", || {
        c.resolve_reservation(rkey(AGENT, "p1"), ResolveOutcome::Released, None)
    });
    assert_eq!(status(&c, "p1"), RequestStatus::Unknown);
    assert_eq!(reserved(&c), 10_000);
}

#[test]
fn released_after_release_after_frees_the_budget() {
    let mut c = setup();
    request_at(&mut c, NOW, "p0", 10_000);
    unknown_request(&mut c, "p1", 10_000);
    let release_after = c.get_request(rkey(AGENT, "p1")).unwrap().release_after;
    owner_at(release_after);
    c.resolve_reservation(rkey(AGENT, "p1"), ResolveOutcome::Released, None);
    let res = c.get_request(rkey(AGENT, "p1")).unwrap();
    assert_eq!(res.status, RequestStatus::Released);
    assert!(!res.counts_against_budget);
    assert_eq!(reserved(&c), 10_000);
    assert_eq!(
        events(),
        vec![MandateEvent::ReservationResolved {
            key: rkey(AGENT, "p1"),
            outcome: ResolveOutcome::Released,
        }]
    );
    // A late callback still records `signed`, and the release stays uncounted.
    mpc_callback_at(release_after + 1, mpc_ok(&c, "p1"));
    let res = c.on_signature(rkey(AGENT, "p1"));
    assert_eq!(res.status, RequestStatus::Signed);
    assert!(!res.counts_against_budget);
    assert_eq!(reserved(&c), 10_000);
}

#[test]
fn spent_is_allowed_at_once_and_keeps_counting() {
    let mut c = setup();
    unknown_request(&mut c, "p1", 10_000);
    owner_at(NOW + 11);
    c.resolve_reservation(rkey(AGENT, "p1"), ResolveOutcome::Spent, None);
    assert_eq!(status(&c, "p1"), RequestStatus::Spent);
    assert_eq!(reserved(&c), 10_000);
    // spent is not unknown any more: no second resolution.
    owner_at(NOW + 1_000);
    expect_err("ERR_BAD_TRANSITION", || {
        c.resolve_reservation(rkey(AGENT, "p1"), ResolveOutcome::Released, None)
    });
}

#[test]
fn only_unknown_reservations_are_resolved() {
    let mut c = setup();
    request_at(&mut c, NOW, "pending", 1_000);
    request_at(&mut c, NOW, "signed", 1_000);
    mpc_callback_at(NOW + 1, mpc_ok(&c, "signed"));
    c.on_signature(rkey(AGENT, "signed"));
    for id in ["pending", "signed"] {
        owner_at(NOW + 1_000);
        expect_err("ERR_BAD_TRANSITION", || {
            c.resolve_reservation(rkey(AGENT, id), ResolveOutcome::Spent, None)
        });
    }
    owner_at(NOW + 1_000);
    expect_err("ERR_REQUEST_NOT_FOUND", || {
        c.resolve_reservation(rkey(AGENT, "nope"), ResolveOutcome::Spent, None)
    });
}

#[test]
fn resolve_reservation_is_owner_only() {
    let mut c = setup();
    unknown_request(&mut c, "p1", 1_000);
    anyone_at(NOW + 1_000);
    expect_err("ERR_NOT_OWNER", || {
        c.resolve_reservation(rkey(AGENT, "p1"), ResolveOutcome::Released, None)
    });
    agent_at(NOW + 1_000);
    expect_err("ERR_NOT_OWNER", || {
        c.resolve_reservation(rkey(AGENT, "p1"), ResolveOutcome::Released, None)
    });
}

#[test]
fn release_of_an_old_window_does_not_touch_the_current_one() {
    let mut c = setup();
    unknown_request(&mut c, "p1", 10_000);
    request_at(&mut c, NOW + WEEK, "p2", 10_000);
    owner_at(NOW + WEEK + 1);
    c.resolve_reservation(rkey(AGENT, "p1"), ResolveOutcome::Released, None);
    assert_eq!(reserved(&c), 10_000);
}
