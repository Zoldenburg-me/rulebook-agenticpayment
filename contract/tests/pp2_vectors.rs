//! Shared shape 4 vectors (`tests/vectors/paypal.json`): the contract's `normalize_receiver`
//! and `amount_to_cents` define them; scamcheck's `normPaypal`/`PAYPAL_AMOUNT` and the PayPal
//! rail's amount check are tested against the same file, so all sides keep one grammar.

use mandate::errors::ContractError;
use mandate::shapes::paypal::{amount_to_cents, normalize_receiver};
use near_sdk::serde_json::{self, Value};

fn vectors() -> Value {
    serde_json::from_str(include_str!("vectors/paypal.json")).unwrap()
}

#[test]
fn receivers_match_the_shared_vectors() {
    let v = vectors();
    let cases = v["receivers"].as_array().unwrap();
    assert!(cases.len() > 10);
    for c in cases {
        let input = c["input"].as_str().unwrap();
        let want = match &c["output"] {
            Value::Null => Err(ContractError::InvalidPaypalPayee),
            o => Ok(o.as_str().unwrap().to_string()),
        };
        assert_eq!(normalize_receiver(input), want, "{input:?}");
    }
}

#[test]
fn amounts_match_the_shared_vectors() {
    let v = vectors();
    let cases = v["amounts"].as_array().unwrap();
    assert!(cases.len() > 10);
    for c in cases {
        let amount = c["amount"].as_str().unwrap();
        let want = match &c["cents"] {
            Value::Null => Err(ContractError::InvalidAmount),
            n => Ok(u128::from(n.as_u64().unwrap())),
        };
        assert_eq!(amount_to_cents(amount), want, "{amount:?}");
    }
}
