//! PP-W1: settlement feedback. `report_settlement` is callable only by the
//! `settlement_reporter`, and only tightens: it marks a PayPal receipt confirmed or suspends
//! the payee; caps, budgets and reservations never move. The owner re-enables a payee with
//! `reinstate_payee`. The owner is a NEAR wallet here.

mod mock_mpc;

use std::panic::{catch_unwind, AssertUnwindSafe};

use mandate::settlement::SettlementStatus;
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

const REPORTER: &str = "pp-webhooks.testnet";
const STRANGER: &str = "stranger.testnet";

fn as_reporter() {
    call_at(REPORTER, key(210), NOW, vec![])
}

/// `setup()` with the reporter set and one signed payout `inv-1` (42.50 USD to `EMAIL`).
fn signed() -> Contract {
    let mut c = setup();
    owner_at(NOW);
    c.set_settlement_reporter(Some(acc(REPORTER)), None);
    agent_at(NOW);
    let _ = c.request_signature("inv-1".into(), paypal("42.50", NOW));
    let res = c.get_request(rkey(AGENT, "inv-1")).unwrap();
    call_at(
        CONTRACT,
        key(201),
        NOW,
        vec![PromiseResult::Successful(mock_mpc::sign_response(
            &res.digest,
        ))],
    );
    let res = c.on_signature(rkey(AGENT, "inv-1"));
    assert_eq!(res.status, RequestStatus::Signed);
    c
}

fn email() -> Payee {
    Payee::Paypal {
        receiver: EMAIL.into(),
    }
}

/// Everything the reporter must never move.
fn snapshot(c: &Contract) -> String {
    serde_json::to_string(&(
        c.get_mandate(AGENT.into()),
        c.get_payees(AGENT.into()),
        c.get_budget(AGENT.into(), Rail::Paypal),
        c.get_request(rkey(AGENT, "inv-1")),
        c.get_agent(AGENT.into()),
    ))
    .unwrap()
}

#[test]
fn completed_marks_the_receipt_confirmed_and_changes_nothing_else() {
    let mut c = signed();
    let before = snapshot(&c);
    as_reporter();
    assert!(c.report_settlement(
        AGENT.into(),
        "inv-1".into(),
        SettlementStatus::Completed,
        "S5WD75AYHNGH4".into()
    ));
    let s = c.get_settlement(rkey(AGENT, "inv-1")).unwrap();
    assert_eq!(s.status, SettlementStatus::Completed);
    assert_eq!(s.paypal_id, "S5WD75AYHNGH4");
    assert!(c.get_suspended_payees(AGENT.into()).is_empty());
    assert_eq!(snapshot(&c), before);
}

/// One contract per test: the mocked blockchain keeps its storage for the whole test.
fn adverse_report_suspends_the_payee_and_blocks_the_next_payout(status: SettlementStatus) {
    let mut c = signed();
    let before = snapshot(&c);
    as_reporter();
    assert!(c.report_settlement(AGENT.into(), "inv-1".into(), status, "ITEM1".into()));
    assert_eq!(c.get_suspended_payees(AGENT.into()), vec![email()]);
    // No cap, budget, payee list or reservation moved: in particular no budget released.
    assert_eq!(snapshot(&c), before);
    let reserved = c.get_budget(AGENT.into(), Rail::Paypal).unwrap().reserved.0;
    assert_eq!(reserved, 4_250);
    // The agent's next payout to that payee is refused, in any spelling.
    agent_at(NOW + 1);
    let msg = expect_err("ERR_PAYEE_SUSPENDED", || {
        c.request_signature(
            "inv-2".into(),
            Shape::Paypal(PaypalRequest {
                payee: " SUPPLIER@example.com".into(),
                amount: "1.00".into(),
                timestamp: NOW + 1,
            }),
        )
    });
    assert_eq!(msg, "ERR_PAYEE_SUSPENDED: payee");
    assert!(c.get_request(rkey(AGENT, "inv-2")).is_none());
}

#[test]
fn failed_suspends() {
    adverse_report_suspends_the_payee_and_blocks_the_next_payout(SettlementStatus::Failed)
}
#[test]
fn returned_suspends() {
    adverse_report_suspends_the_payee_and_blocks_the_next_payout(SettlementStatus::Returned)
}
#[test]
fn blocked_suspends() {
    adverse_report_suspends_the_payee_and_blocks_the_next_payout(SettlementStatus::Blocked)
}
#[test]
fn refunded_suspends() {
    adverse_report_suspends_the_payee_and_blocks_the_next_payout(SettlementStatus::Refunded)
}
#[test]
fn reversed_suspends() {
    adverse_report_suspends_the_payee_and_blocks_the_next_payout(SettlementStatus::Reversed)
}
#[test]
fn disputed_suspends() {
    adverse_report_suspends_the_payee_and_blocks_the_next_payout(SettlementStatus::Disputed)
}

#[test]
fn suspension_is_per_agent_and_per_payee() {
    let mut c = signed();
    owner_at(NOW);
    c.add_payee(
        AGENT.into(),
        Payee::Paypal {
            receiver: "other@example.com".into(),
        },
        None,
    );
    as_reporter();
    c.report_settlement(
        AGENT.into(),
        "inv-1".into(),
        SettlementStatus::Failed,
        "I".into(),
    );
    agent_at(NOW + 1);
    let _ = c.request_signature(
        "inv-2".into(),
        Shape::Paypal(PaypalRequest {
            payee: "other@example.com".into(),
            amount: "1.00".into(),
            timestamp: NOW + 1,
        }),
    );
    assert!(c.get_request(rkey(AGENT, "inv-2")).is_some());
    assert!(c.get_suspended_payees("agent-b".into()).is_empty());
}

#[test]
fn non_reporter_is_refused() {
    let mut c = signed();
    let before = snapshot(&c);
    // A stranger, the owner, the relayer, and the agent key (predecessor = this contract).
    owner_at(NOW);
    c.set_relayer(Some(acc("relayer.testnet")), None);
    for (who, pk) in [
        (STRANGER, key(220)),
        (WALLET, key(200)),
        ("relayer.testnet", key(221)),
        (CONTRACT, key(1)),
    ] {
        call_at(who, pk, NOW, vec![]);
        expect_err("ERR_NOT_SETTLEMENT_REPORTER", || {
            c.report_settlement(
                AGENT.into(),
                "inv-1".into(),
                SettlementStatus::Completed,
                "I".into(),
            )
        });
    }
    assert!(c.get_settlement(rkey(AGENT, "inv-1")).is_none());
    assert_eq!(snapshot(&c), before);
}

#[test]
fn without_a_reporter_nobody_can_report() {
    let mut c = signed();
    owner_at(NOW);
    c.set_settlement_reporter(None, None);
    assert_eq!(c.get_config().settlement_reporter, None);
    as_reporter();
    expect_err("ERR_NOT_SETTLEMENT_REPORTER", || {
        c.report_settlement(
            AGENT.into(),
            "inv-1".into(),
            SettlementStatus::Failed,
            "I".into(),
        )
    });
}

#[test]
fn only_the_owner_sets_the_reporter_and_never_to_this_contract() {
    let mut c = setup();
    call_at(STRANGER, key(220), NOW, vec![]);
    expect_err("ERR_NOT_OWNER", || {
        c.set_settlement_reporter(Some(acc(STRANGER)), None)
    });
    owner_at(NOW);
    expect_err("ERR_NOT_SETTLEMENT_REPORTER", || {
        c.set_settlement_reporter(Some(acc(CONTRACT)), None)
    });
    c.set_settlement_reporter(Some(acc(REPORTER)), None);
    assert_eq!(c.get_config().settlement_reporter, Some(acc(REPORTER)));
}

#[test]
fn a_later_success_never_lifts_a_suspension() {
    let mut c = signed();
    as_reporter();
    c.report_settlement(
        AGENT.into(),
        "inv-1".into(),
        SettlementStatus::Returned,
        "I".into(),
    );
    for status in [SettlementStatus::Completed, SettlementStatus::Unclaimed] {
        assert!(!c.report_settlement(AGENT.into(), "inv-1".into(), status, "I".into()));
    }
    assert_eq!(
        c.get_settlement(rkey(AGENT, "inv-1")).unwrap().status,
        SettlementStatus::Returned
    );
    assert_eq!(c.get_suspended_payees(AGENT.into()), vec![email()]);
}

#[test]
fn an_adverse_report_after_a_completed_one_still_tightens() {
    // A reversal or dispute after the money arrived.
    let mut c = signed();
    as_reporter();
    c.report_settlement(
        AGENT.into(),
        "inv-1".into(),
        SettlementStatus::Completed,
        "I".into(),
    );
    c.report_settlement(
        AGENT.into(),
        "inv-1".into(),
        SettlementStatus::Disputed,
        "PP-D-1".into(),
    );
    assert_eq!(c.get_suspended_payees(AGENT.into()), vec![email()]);
}

#[test]
fn reporter_can_only_name_a_signed_paypal_request() {
    let mut c = signed();
    as_reporter();
    expect_err("ERR_REQUEST_NOT_FOUND", || {
        c.report_settlement(
            AGENT.into(),
            "nope".into(),
            SettlementStatus::Failed,
            "I".into(),
        )
    });
    expect_err("ERR_REQUEST_NOT_FOUND", || {
        c.report_settlement(
            "agent-x".into(),
            "inv-1".into(),
            SettlementStatus::Failed,
            "I".into(),
        )
    });
    // A pending (unsigned) order was never submitted.
    agent_at(NOW + 1);
    let _ = c.request_signature("inv-2".into(), paypal("1.00", NOW + 1));
    as_reporter();
    expect_err("ERR_BAD_TRANSITION", || {
        c.report_settlement(
            AGENT.into(),
            "inv-2".into(),
            SettlementStatus::Failed,
            "I".into(),
        )
    });
    for bad in ["", "has space", &"x".repeat(65), "a/b"] {
        expect_err("ERR_INVALID_SETTLEMENT", || {
            c.report_settlement(
                AGENT.into(),
                "inv-1".into(),
                SettlementStatus::Failed,
                bad.into(),
            )
        });
    }
    assert!(c.get_suspended_payees(AGENT.into()).is_empty());
}

#[test]
fn only_the_owner_reinstates_a_payee() {
    let mut c = signed();
    as_reporter();
    c.report_settlement(
        AGENT.into(),
        "inv-1".into(),
        SettlementStatus::Failed,
        "I".into(),
    );
    for (who, pk) in [
        (REPORTER, key(210)),
        (CONTRACT, key(1)),
        (STRANGER, key(220)),
    ] {
        call_at(who, pk, NOW, vec![]);
        expect_err("ERR_NOT_OWNER", || {
            c.reinstate_payee(AGENT.into(), email(), None)
        });
    }
    owner_at(NOW);
    expect_err("ERR_PAYEE_NOT_SUSPENDED", || {
        c.reinstate_payee(
            AGENT.into(),
            Payee::Paypal {
                receiver: "other@example.com".into(),
            },
            None,
        )
    });
    // Matched in stored form.
    c.reinstate_payee(
        AGENT.into(),
        Payee::Paypal {
            receiver: "Supplier@Example.com ".into(),
        },
        None,
    );
    assert!(c.get_suspended_payees(AGENT.into()).is_empty());
    agent_at(NOW + 1);
    let _ = c.request_signature("inv-2".into(), paypal("1.00", NOW + 1));
    assert!(c.get_request(rkey(AGENT, "inv-2")).is_some());
}
