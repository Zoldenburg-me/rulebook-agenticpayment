//! Shape 5: a charge on the owner's vaulted PayPal wallet (PP-V1). The contract renders
//! `Charge USD {amount} to merchant {payee} for order {order_ref} at {RFC3339} ref {request_id}`
//! from decoded fields and signs it with EIP-191. The PayPal rail charges the vault into its
//! own merchant account (Orders v2, `PayPal-Request-Id = request_id`) and then pays the
//! merchant through Payouts (`sender_batch_id = request_id`), the PP-V0 fallback.
//!
//! The checks are shape 4's: the mandate's PayPal rail (caps and budget), the `Payee::Paypal`
//! allowlist, canonical USD amounts and the same validity window. Dedupe is shape 4's
//! content dedupe under its own domain tag ([`checkout_dedupe_key`]).

use near_sdk::{borsh, env};

use super::payout::rfc3339_utc;
use super::paypal::{amount_to_cents, normalize_receiver};
use super::{eip191_digest, BuiltRequest};
use crate::errors::ContractError;
use crate::request::MAX_REQUEST_ID_LEN;
use crate::types::{
    AgentId, Mandate, Payee, PaypalCheckoutRequest, Rail, SignedPayload, CLOCK_SKEW_SECS,
    PAYOUT_RELEASE_DELAY_SECS,
};

/// `order_ref` is 1–64 of `[A-Za-z0-9._:-]` (the `request_id` alphabet), so it cannot carry
/// ` at ` or ` ref ` into the message; `ERR_INVALID_ORDER_REF` otherwise.
pub fn validate_order_ref(order_ref: &str) -> Result<(), ContractError> {
    let ok = !order_ref.is_empty()
        && order_ref.len() <= MAX_REQUEST_ID_LEN
        && order_ref
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(ContractError::InvalidOrderRef)
    }
}

/// `Charge USD {amount} to merchant {payee} for order {order_ref} at {YYYY-MM-DDTHH:MM:SSZ}
/// ref {request_id}`.
pub fn checkout_message(
    amount: &str,
    payee: &str,
    order_ref: &str,
    timestamp_secs: u64,
    request_id: &str,
) -> String {
    format!(
        "Charge USD {amount} to merchant {payee} for order {order_ref} at {} ref {request_id}",
        rfc3339_utc(timestamp_secs)
    )
}

/// Domain tag of [`checkout_dedupe_key`]; differs from the shape 3 and 4 tags.
const CHECKOUT_DEDUPE_DOMAIN: &str = "nearh:paypal-checkout-dedupe:v1";

/// `keccak256(borsh((CHECKOUT_DEDUPE_DOMAIN, agent, payee, amount, timestamp: u64)))`.
/// Neither `request_id` nor `order_ref` is in the key: a new one of either would be a second
/// charge for the same (payee, amount, timestamp), which this refuses.
pub fn checkout_dedupe_key(
    agent: &AgentId,
    payee: &str,
    amount: &str,
    timestamp_secs: u64,
) -> [u8; 32] {
    let preimage = borsh::to_vec(&(
        CHECKOUT_DEDUPE_DOMAIN,
        agent.as_str(),
        payee,
        amount,
        timestamp_secs,
    ))
    .unwrap_or_else(|_| env::panic_str("borsh checkout dedupe preimage"));
    env::keccak256_array(&preimage)
}

/// Shape 4's checks (see `paypal::build_paypal`) plus `order_ref`, then the shape 5 message.
/// Reserves on `Rail::Paypal`, so shapes 4 and 5 share one per-rail budget.
pub fn build_paypal_checkout(
    req: &PaypalCheckoutRequest,
    request_id: &str,
    mandate: &Mandate,
    allowed_payees: &[Payee],
    now_secs: u64,
) -> Result<BuiltRequest, ContractError> {
    let rail = mandate
        .paypal
        .as_ref()
        .ok_or(ContractError::ShapeNotAllowed)?;
    let payee = normalize_receiver(&req.payee)?;
    let allowed = allowed_payees
        .iter()
        .any(|p| matches!(p, Payee::Paypal { receiver } if *receiver == payee));
    if !allowed {
        return Err(ContractError::PaypalPayeeNotAllowed);
    }
    validate_order_ref(&req.order_ref)?;
    let amount = amount_to_cents(&req.amount)?;
    if amount < rail.amount_range.min.0 {
        return Err(ContractError::BelowMinimum);
    }
    if amount > rail.amount_range.max.0 {
        return Err(ContractError::OverPerPaymentCap);
    }
    let lifetime = u64::from(mandate.max_validity_secs).saturating_sub(CLOCK_SKEW_SECS);
    if lifetime == 0 {
        return Err(ContractError::InvalidMandate);
    }
    if req.timestamp < now_secs.saturating_sub(lifetime) {
        return Err(ContractError::TimestampStale);
    }
    if req.timestamp > now_secs + CLOCK_SKEW_SECS {
        return Err(ContractError::TimestampFuture);
    }

    let text = checkout_message(
        &req.amount,
        &payee,
        &req.order_ref,
        req.timestamp,
        request_id,
    );
    let valid_before = req.timestamp + lifetime;
    Ok(BuiltRequest {
        digest: eip191_digest(&text),
        payload: SignedPayload::Message { text },
        rail: Some(Rail::Paypal),
        amount,
        valid_before,
        release_after: valid_before.max(req.timestamp + PAYOUT_RELEASE_DELAY_SECS),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AmountRange, FloatCap, RailMandate};
    use near_sdk::json_types::U128;

    const MERCHANT: &str = "merchant@example.com";
    const OTHER: &str = "attacker@example.com";
    /// 2026-11-04T22:27:06Z.
    const TS: u64 = 1_793_831_226;
    const ID: &str = "chk-0001";
    const ORDER: &str = "ORD-2026-0042";

    fn mandate() -> Mandate {
        let rail = |min: u128, max: u128, budget: u128| RailMandate {
            amount_range: AmountRange {
                min: U128(min),
                max: U128(max),
            },
            budget: U128(budget),
            period_secs: 604_800,
        };
        Mandate {
            x402: rail(1, 1_000_000, 20_000_000),
            sepa: rail(1, 50, 200),
            usdc_address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e".to_string(),
            eure_address: "0x29f37f6adca168b79b8d9567eab9be3fbf21db85".to_string(),
            chain_id: 84532,
            float_cap: FloatCap {
                usdc: U128(25_000_000),
                eure: U128(250),
            },
            max_validity_secs: 300,
            // 0.01..=50.00 USD per charge, 200.00 USD per week.
            paypal: Some(rail(1, 5_000, 20_000)),
            paypal_refund: None,
            usdc_eip712_name: "USDC".into(),
            usdc_eip712_version: "2".into(),
        }
    }

    fn payees() -> Vec<Payee> {
        vec![Payee::Paypal {
            receiver: MERCHANT.to_string(),
        }]
    }

    fn req(payee: &str, amount: &str, order_ref: &str, timestamp: u64) -> PaypalCheckoutRequest {
        PaypalCheckoutRequest {
            payee: payee.to_string(),
            amount: amount.to_string(),
            order_ref: order_ref.to_string(),
            timestamp,
        }
    }

    fn build(r: &PaypalCheckoutRequest, now: u64) -> Result<BuiltRequest, ContractError> {
        build_paypal_checkout(r, ID, &mandate(), &payees(), now)
    }

    #[test]
    fn within_mandate_builds_the_message() {
        let built = build(&req(" Merchant@Example.com ", "25.00", ORDER, TS), TS + 5).unwrap();
        let expected = "Charge USD 25.00 to merchant merchant@example.com for order \
                        ORD-2026-0042 at 2026-11-04T22:27:06Z ref chk-0001";
        assert_eq!(
            built.payload,
            SignedPayload::Message {
                text: expected.to_string()
            }
        );
        assert_eq!(built.digest, eip191_digest(expected));
        assert_eq!(built.rail, Some(Rail::Paypal));
        assert_eq!(built.amount, 2_500);
        assert_eq!(built.valid_before, TS + 240);
        assert_eq!(built.release_after, TS + PAYOUT_RELEASE_DELAY_SECS);
    }

    #[test]
    fn over_cap_is_refused() {
        assert!(build(&req(MERCHANT, "50.00", ORDER, TS), TS).is_ok());
        assert_eq!(
            build(&req(MERCHANT, "50.01", ORDER, TS), TS),
            Err(ContractError::OverPerPaymentCap)
        );
    }

    #[test]
    fn wrong_payee_is_refused() {
        assert_eq!(
            build(&req(OTHER, "1.00", ORDER, TS), TS),
            Err(ContractError::PaypalPayeeNotAllowed)
        );
        assert_eq!(
            build(&req("not an email", "1.00", ORDER, TS), TS),
            Err(ContractError::InvalidPaypalPayee)
        );
    }

    #[test]
    fn expired_and_future_timestamps_are_refused() {
        assert!(build(&req(MERCHANT, "1.00", ORDER, TS), TS + 240).is_ok());
        assert_eq!(
            build(&req(MERCHANT, "1.00", ORDER, TS), TS + 241),
            Err(ContractError::TimestampStale)
        );
        assert_eq!(
            build(&req(MERCHANT, "1.00", ORDER, TS + 61), TS),
            Err(ContractError::TimestampFuture)
        );
    }

    #[test]
    fn bad_order_ref_and_amount_are_refused() {
        for bad in ["", "a b", "x at 2026", "ref\n1", "é", &"a".repeat(65)] {
            assert_eq!(
                build(&req(MERCHANT, "1.00", bad, TS), TS),
                Err(ContractError::InvalidOrderRef),
                "{bad:?}"
            );
        }
        assert!(validate_order_ref(&"a".repeat(64)).is_ok());
        for bad in ["1", "1.5", "01.00", "0.00", "-1.00"] {
            assert_eq!(
                build(&req(MERCHANT, bad, ORDER, TS), TS),
                Err(ContractError::InvalidAmount),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn mandate_without_paypal_rail_refuses_shape_5() {
        let mut m = mandate();
        m.paypal = None;
        assert_eq!(
            build_paypal_checkout(&req(MERCHANT, "1.00", ORDER, TS), ID, &m, &payees(), TS),
            Err(ContractError::ShapeNotAllowed)
        );
    }

    #[test]
    fn dedupe_key_differs_from_shape_4() {
        let a: AgentId = "agent-a".into();
        assert_eq!(
            checkout_dedupe_key(&a, MERCHANT, "1.00", TS),
            checkout_dedupe_key(&a, MERCHANT, "1.00", TS)
        );
        assert_ne!(
            checkout_dedupe_key(&a, MERCHANT, "1.00", TS),
            super::super::paypal::paypal_dedupe_key(&a, MERCHANT, "1.00", TS)
        );
    }
}
