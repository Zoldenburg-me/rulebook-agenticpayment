//! Shape 6: a PayPal refund order (PP-T1). The contract renders
//! `Refund USD {amount} of capture {capture_id} ref {request_id}` from decoded fields and
//! signs it with EIP-191. The PayPal rail submits it once, as
//! `POST /v2/payments/captures/{capture_id}/refund`, after checking that the amount is at
//! most what the capture has left (captured minus already refunded). The contract checks the
//! per-refund cap and reserves the amount on the `paypal_refund` budget; it cannot see the
//! capture, so that bound is the rail's.

use super::paypal::amount_to_cents;
use super::{eip191_digest, BuiltRequest};
use crate::errors::ContractError;
use crate::types::{
    Mandate, Rail, RefundRequest, SignedPayload, CLOCK_SKEW_SECS, PAYOUT_RELEASE_DELAY_SECS,
};

/// PayPal capture ids are 17 characters today; this leaves room either side.
const CAPTURE_ID_LEN: std::ops::RangeInclusive<usize> = 10..=32;

/// `ERR_INVALID_CAPTURE_ID` unless `id` is 10-32 of `[A-Z0-9]`. Not rewritten (no trimming,
/// no case folding), so the id in the message is the one the rail sends, and it cannot carry
/// ` ref ` or a path segment.
pub fn validate_capture_id(id: &str) -> Result<(), ContractError> {
    let ok = CAPTURE_ID_LEN.contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit());
    if ok {
        Ok(())
    } else {
        Err(ContractError::InvalidCaptureId)
    }
}

/// `Refund USD {amount} of capture {capture_id} ref {request_id}`.
pub fn refund_message(amount: &str, capture_id: &str, request_id: &str) -> String {
    format!("Refund USD {amount} of capture {capture_id} ref {request_id}")
}

/// Checks that the mandate has a PayPal refund rail (`ERR_SHAPE_NOT_ALLOWED`), the capture
/// id is well formed, and the amount is canonical USD within
/// `mandate.paypal_refund.amount_range` (the per-refund cap); then builds the message.
/// `request_id` must already have passed `validate_request_id`. The message has no
/// timestamp, so the window starts at block time: `valid_before = now + max_validity_secs -
/// CLOCK_SKEW_SECS`, and the rail must not submit after it.
/// `release_after = max(valid_before, now + PAYOUT_RELEASE_DELAY_SECS)`.
pub fn build_refund(
    req: &RefundRequest,
    request_id: &str,
    mandate: &Mandate,
    now_secs: u64,
) -> Result<BuiltRequest, ContractError> {
    let rail = mandate
        .paypal_refund
        .as_ref()
        .ok_or(ContractError::ShapeNotAllowed)?;
    validate_capture_id(&req.capture_id)?;
    let amount = amount_to_cents(&req.amount)?;
    if amount < rail.amount_range.min.0 {
        return Err(ContractError::BelowMinimum);
    }
    if amount > rail.amount_range.max.0 {
        return Err(ContractError::OverPerPaymentCap);
    }
    let lifetime = u64::from(mandate.max_validity_secs).saturating_sub(CLOCK_SKEW_SECS);
    // set_mandate keeps max_validity_secs >= MIN_VALIDITY_SECS; never sign if that breaks.
    if lifetime == 0 {
        return Err(ContractError::InvalidMandate);
    }
    let text = refund_message(&req.amount, &req.capture_id, request_id);
    let valid_before = now_secs + lifetime;
    Ok(BuiltRequest {
        digest: eip191_digest(&text),
        payload: SignedPayload::Message { text },
        rail: Some(Rail::PaypalRefund),
        amount,
        valid_before,
        release_after: valid_before.max(now_secs + PAYOUT_RELEASE_DELAY_SECS),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AmountRange, FloatCap, RailMandate};
    use near_sdk::json_types::U128;

    /// A sandbox capture id from the PP-T1 probe, not a live one.
    const CAPTURE: &str = "4E871663M29867546";
    const ID: &str = "refund-0001";
    const NOW: u64 = 1_793_831_226;

    fn mandate() -> Mandate {
        let rail = |min: u128, max: u128, budget: u128, period_secs: u64| RailMandate {
            amount_range: AmountRange {
                min: U128(min),
                max: U128(max),
            },
            budget: U128(budget),
            period_secs,
        };
        Mandate {
            x402: rail(1, 1_000_000, 20_000_000, 604_800),
            sepa: rail(1, 50, 200, 604_800),
            usdc_address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e".to_string(),
            eure_address: "0x29f37f6adca168b79b8d9567eab9be3fbf21db85".to_string(),
            chain_id: 84532,
            float_cap: FloatCap {
                usdc: U128(25_000_000),
                eure: U128(250),
            },
            max_validity_secs: 300,
            paypal: None,
            // 0.01..=10.00 USD per refund, 15.00 USD per day.
            paypal_refund: Some(rail(1, 1_000, 1_500, 86_400)),
            usdc_eip712_name: "USDC".into(),
            usdc_eip712_version: "2".into(),
        }
    }

    fn req(capture_id: &str, amount: &str) -> RefundRequest {
        RefundRequest {
            capture_id: capture_id.to_string(),
            amount: amount.to_string(),
        }
    }

    fn build(r: &RefundRequest) -> Result<BuiltRequest, ContractError> {
        build_refund(r, ID, &mandate(), NOW)
    }

    fn text(b: &BuiltRequest) -> String {
        match &b.payload {
            SignedPayload::Message { text } => text.clone(),
            other => panic!("not a message: {other:?}"),
        }
    }

    #[test]
    fn happy_path_message_bytes() {
        let built = build(&req(CAPTURE, "4.00")).unwrap();
        let expected = "Refund USD 4.00 of capture 4E871663M29867546 ref refund-0001";
        assert_eq!(text(&built).as_bytes(), expected.as_bytes());
        assert_eq!(built.digest, eip191_digest(expected));
        // keccak256("\x19Ethereum Signed Message:\n60" || expected), computed with @noble/hashes
        // (rails/paypal/test/refund.test.ts checks the same vector).
        assert_eq!(
            hex::encode(built.digest),
            "2e3ba4ba32bf1c828ac702efb64d757e9aad22437c76ec48639752bb4d6f94ed"
        );
        assert_eq!(built.rail, Some(Rail::PaypalRefund));
        assert_eq!(built.amount, 400);
        assert_eq!(built.valid_before, NOW + 240);
        assert_eq!(built.release_after, NOW + PAYOUT_RELEASE_DELAY_SECS);
    }

    #[test]
    fn over_cap_is_refused() {
        assert_eq!(build(&req(CAPTURE, "10.00")).unwrap().amount, 1_000);
        assert_eq!(
            build(&req(CAPTURE, "10.01")),
            Err(ContractError::OverPerPaymentCap)
        );
        assert_eq!(
            build(&req(CAPTURE, "999999999999.99")),
            Err(ContractError::OverPerPaymentCap)
        );
    }

    #[test]
    fn below_minimum_is_refused() {
        let mut m = mandate();
        m.paypal_refund.as_mut().unwrap().amount_range.min = U128(100);
        assert_eq!(
            build_refund(&req(CAPTURE, "0.99"), ID, &m, NOW),
            Err(ContractError::BelowMinimum)
        );
    }

    #[test]
    fn mandate_without_refund_rail_refuses_shape_6() {
        let mut m = mandate();
        m.paypal_refund = None;
        // A PayPal payout rail does not allow refunds.
        m.paypal = mandate().paypal_refund;
        assert_eq!(
            build_refund(&req(CAPTURE, "1.00"), ID, &m, NOW),
            Err(ContractError::ShapeNotAllowed)
        );
    }

    #[test]
    fn non_canonical_amount_is_refused() {
        for bad in [
            "", "1", "1.5", "01.00", "0.00", "-1.00", " 1.00", "1,00", "1e2",
        ] {
            assert_eq!(
                build(&req(CAPTURE, bad)),
                Err(ContractError::InvalidAmount),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn malformed_capture_id_is_refused() {
        for bad in [
            "",
            "4E871663M",
            &"A".repeat(33),
            "4e871663m29867546",
            " 4E871663M29867546",
            "4E871663M29867546 ",
            "4E871663M2986754_",
            "4E871663M-29867546",
            "4E871663M29867546 ref x",
            "../../orders/3M977226H0197750E",
            "4E871663M29867546/refund",
            "4E871663M2986754Ä",
        ] {
            assert_eq!(
                build(&req(bad, "1.00")),
                Err(ContractError::InvalidCaptureId),
                "{bad:?}"
            );
        }
        assert!(validate_capture_id(&"A".repeat(10)).is_ok());
        assert!(validate_capture_id(&"9".repeat(32)).is_ok());
    }

    #[test]
    fn request_id_and_capture_are_in_the_message() {
        let a = build_refund(&req(CAPTURE, "1.00"), "r-1", &mandate(), NOW).unwrap();
        let b = build_refund(&req(CAPTURE, "1.00"), "r-2", &mandate(), NOW).unwrap();
        let c = build_refund(&req("4E871663M29867547", "1.00"), "r-1", &mandate(), NOW).unwrap();
        assert!(text(&a).ends_with(" ref r-1"));
        assert_ne!(a.digest, b.digest);
        assert_ne!(a.digest, c.digest);
        // Not a shape 4 payout text: a refund message can never pass as a payout order.
        assert!(!text(&a).starts_with("Send "));
    }
}
