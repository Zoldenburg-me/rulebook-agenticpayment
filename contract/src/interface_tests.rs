//! Serde round trips of every example in docs/interfaces.md: each ```` ```json example=<name> ````
//! block must parse into its type and serialize back to the same JSON.

use near_sdk::serde::de::DeserializeOwned;
use near_sdk::serde::Serialize;
use near_sdk::serde_json::{self, Value};

use crate::events::{EventLog, EVENT_STANDARD, EVENT_VERSION};
use crate::types::*;

const INTERFACES_MD: &str = include_str!("../../docs/interfaces.md");

const SHAPES: [&str; 4] = ["sweep", "x402", "payout", "link"];
const EVENTS: [&str; 12] = [
    "agent_added",
    "agent_add_failed",
    "relayer_set",
    "mandate_set",
    "payee_added",
    "payee_removed",
    "signature_requested",
    "signature_recorded",
    "request_unknown",
    "reservation_resolved",
    "agent_unlinked",
    "agent_revoked",
];
const MCP_TOOLS: [&str; 4] = ["pay_x402", "pay_sepa", "revoke", "get_receipt"];

/// (name, json) for every tagged block, in document order.
fn examples() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in INTERFACES_MD.lines() {
        match current.as_mut() {
            None => {
                if let Some(name) = line.trim().strip_prefix("```json example=") {
                    current = Some((name.trim().to_string(), String::new()));
                }
            }
            Some((_, body)) => {
                if line.trim() == "```" {
                    out.push(current.take().unwrap());
                } else {
                    body.push_str(line);
                    body.push('\n');
                }
            }
        }
    }
    assert!(current.is_none(), "unterminated example block");
    out
}

fn example(name: &str) -> String {
    examples()
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("docs/interfaces.md has no example={name}"))
        .1
}

/// Parses `json` as `T`, serializes it back, and requires the same JSON value.
fn round_trip<T: Serialize + DeserializeOwned>(name: &str, json: &str) -> T {
    let original: Value =
        serde_json::from_str(json).unwrap_or_else(|e| panic!("{name}: not JSON: {e}"));
    let parsed: T =
        serde_json::from_value(original.clone()).unwrap_or_else(|e| panic!("{name}: {e}"));
    let again = serde_json::to_value(&parsed).unwrap();
    assert_eq!(again, original, "{name}: round trip changed the JSON");
    parsed
}

#[test]
fn every_example_round_trips() {
    let all = examples();
    assert!(!all.is_empty());
    for (name, json) in &all {
        let (kind, _) = name.split_once(':').unwrap_or((name.as_str(), ""));
        match kind {
            "shape" => drop(round_trip::<Shape>(name, json)),
            "event" => drop(round_trip::<EventLog>(name, json)),
            "owner_mode" => drop(round_trip::<OwnerMode>(name, json)),
            "payee" => drop(round_trip::<Payee>(name, json)),
            "mandate" => drop(round_trip::<Mandate>(name, json)),
            "sweep_config" => drop(round_trip::<SweepConfig>(name, json)),
            "assertion" => drop(round_trip::<OwnerAssertion>(name, json)),
            "x402_requirements" => drop(round_trip::<X402PaymentRequirements>(name, json)),
            "request_key" => drop(round_trip::<RequestKey>(name, json)),
            "reservation" => drop(round_trip::<Reservation>(name, json)),
            "evm_tx" => drop(round_trip::<EvmTxParams>(name, json)),
            "revoke_result" => drop(round_trip::<RevokeResult>(name, json)),
            // Off-chain shapes: owned by SC1/DB1 and A2; here they only have to be JSON.
            "held_item" | "mcp" => drop(round_trip::<Value>(name, json)),
            other => panic!("{name}: no type registered for example kind {other}"),
        }
    }
}

#[test]
fn each_shape_round_trips_with_its_variant() {
    for name in SHAPES {
        let shape: Shape = round_trip(name, &example(&format!("shape:{name}")));
        let kind = serde_json::to_value(shape.kind()).unwrap();
        assert_eq!(kind, Value::String(name.to_string()));
    }
}

#[test]
fn each_event_round_trips_with_its_name() {
    for name in EVENTS {
        let log: EventLog = round_trip(name, &example(&format!("event:{name}")));
        assert_eq!(log.standard, EVENT_STANDARD);
        assert_eq!(log.version, EVENT_VERSION);
        // `to_log` rebuilds the same envelope from the event alone.
        assert_eq!(log.event.to_log(), log);
        let json = serde_json::to_value(&log).unwrap();
        assert_eq!(json["event"], Value::String(name.to_string()));
    }
    let documented = examples()
        .into_iter()
        .filter(|(n, _)| n.starts_with("event:"))
        .count();
    assert_eq!(
        documented,
        EVENTS.len(),
        "an event example has no entry in EVENTS"
    );
}

#[test]
fn mcp_exposes_exactly_four_tools() {
    let tools: Vec<String> = examples()
        .into_iter()
        .filter_map(|(n, json)| {
            n.strip_prefix("mcp:").map(|tool| {
                let v: Value = serde_json::from_str(&json).unwrap();
                assert_eq!(
                    v["name"],
                    Value::String(tool.to_string()),
                    "{n}: name field"
                );
                tool.to_string()
            })
        })
        .collect();
    assert_eq!(tools, MCP_TOOLS);
}

#[test]
fn unknown_shape_is_rejected_by_parsing() {
    let err = serde_json::from_str::<Shape>(r#"{"type":"permit","amount":"1"}"#);
    assert!(err.is_err());
}

#[test]
fn agent_key_methods() {
    assert_eq!(
        AGENT_METHOD_NAMES,
        ["request_signature", "sweep", "revoke_self"]
    );
}

#[test]
fn shape_tags_are_the_nonce_bytes() {
    let tags: Vec<u8> = [
        ShapeKind::Sweep,
        ShapeKind::X402,
        ShapeKind::Payout,
        ShapeKind::Link,
        ShapeKind::Paypal,
        ShapeKind::PaypalCheckout,
    ]
    .iter()
    .map(|k| k.tag())
    .collect();
    assert_eq!(tags, [1, 2, 3, 4, 5, 6]);
}

#[test]
fn status_transitions() {
    use RequestStatus::*;
    let all = [Pending, Signed, Unknown, Spent, Released, Revoked];
    let allowed = [
        (Pending, Signed),
        (Pending, Revoked),
        (Pending, Unknown),
        (Unknown, Signed),
        (Unknown, Revoked),
        (Unknown, Spent),
        (Unknown, Released),
        (Spent, Signed),
        (Spent, Revoked),
        (Released, Signed),
        (Released, Revoked),
    ];
    for from in all {
        for to in all {
            assert_eq!(
                from.can_become(to),
                allowed.contains(&(from, to)),
                "{from:?} -> {to:?}"
            );
        }
    }
}

#[test]
fn reservation_examples_cover_every_payload_kind() {
    let kinds: Vec<String> = examples()
        .into_iter()
        .filter(|(n, _)| n == "reservation" || n.starts_with("reservation:"))
        .map(|(n, json)| {
            let r: Reservation = round_trip(&n, &json);
            serde_json::to_value(&r.payload).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(kinds, ["eip3009", "message", "eip1559_tx"]);
}

// Every validity window keeps room after the clock skew is subtracted, and none exceeds
// the cap. Checked at compile time.
const _: () = {
    assert!(MIN_VALIDITY_SECS as u64 == 2 * CLOCK_SKEW_SECS);
    assert!(MIN_VALIDITY_SECS <= MAX_VALIDITY_CAP_SECS);
    assert!(PAYOUT_RELEASE_DELAY_SECS >= MAX_VALIDITY_CAP_SECS as u64);
    assert!(SWEEP_VALIDITY_SECS <= MAX_VALIDITY_CAP_SECS as u64);
};
