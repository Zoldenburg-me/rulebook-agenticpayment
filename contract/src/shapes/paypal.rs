//! Shape 4: a PayPal payout order (PP2). The contract renders
//! `Send USD {amount} to {payee} at {RFC3339} ref {request_id}` from decoded fields and
//! signs it with EIP-191. The PayPal rail (PP3) submits it with
//! `sender_batch_id = request_id`; PayPal refuses a reused `sender_batch_id` but pays the
//! same item again under a new one (spikes/paypal/RESULT.md), so the contract dedupes both
//! the `request_id` (C3) and the order content ([`paypal_dedupe_key`], D3).

use near_sdk::{borsh, env};

use super::payout::rfc3339_utc;
use super::{eip191_digest, BuiltRequest};
use crate::errors::ContractError;
use crate::types::{
    AgentId, Mandate, Payee, PaypalRequest, Rail, SignedPayload, CLOCK_SKEW_SECS,
    PAYOUT_RELEASE_DELAY_SECS,
};

/// Longest email address (RFC 5321 path limit).
pub const MAX_EMAIL_LEN: usize = 254;
/// Longest local part of an email address (RFC 5321).
const MAX_EMAIL_LOCAL_LEN: usize = 64;
/// Venmo usernames are 5–30 characters.
const VENMO_HANDLE_LEN: std::ops::RangeInclusive<usize> = 5..=30;
/// At most 12 integer digits (under 10^12 USD), far above PayPal's per-item limit, so cents
/// never overflow and the cap check decides.
const MAX_AMOUNT_INT_DIGITS: usize = 12;

/// The stored and signed form of a PayPal receiver, or `ERR_INVALID_PAYPAL_PAYEE`.
/// Surrounding ASCII whitespace is trimmed and ASCII letters are lowercased. Then it must be
/// either
/// - a Venmo handle: `@` and 5–30 of `[a-z0-9_-]` (the rail sends `VENMO_HANDLE`), or
/// - an email: at most 254 bytes, one `@`, a local part of 1–64 of `[a-z0-9._%+-]` with no
///   leading, trailing or double dot, and a domain of at least two dot-separated labels of
///   `[a-z0-9-]` that do not start or end with `-` (the rail sends `EMAIL`).
///
/// Anything else (non-ASCII, inner spaces, quoted local parts, IP-literal domains) is refused,
/// so the payee in the message has one spelling and cannot carry ` at ` or ` ref `.
pub fn normalize_receiver(receiver: &str) -> Result<String, ContractError> {
    let r = receiver
        .trim_matches(|c: char| c.is_ascii_whitespace())
        .to_ascii_lowercase();
    let ok = match r.strip_prefix('@') {
        Some(handle) => {
            VENMO_HANDLE_LEN.contains(&handle.len())
                && handle
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        }
        None => valid_email(&r),
    };
    if ok {
        Ok(r)
    } else {
        Err(ContractError::InvalidPaypalPayee)
    }
}

/// Lowercase email check for [`normalize_receiver`].
fn valid_email(email: &str) -> bool {
    if email.len() > MAX_EMAIL_LEN {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    let local_ok = (1..=MAX_EMAIL_LOCAL_LEN).contains(&local.len())
        && local.bytes().all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
        })
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..");
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    local_ok && domain_ok
}

/// USD cents of an amount in canonical form, or `ERR_INVALID_AMOUNT`. Canonical is what the
/// Payouts API takes as `amount.value`: `^(0|[1-9][0-9]*)\.[0-9]{2}$`, not zero. The input is
/// not rewritten: `1.5`, `01.50`, `1`, `1.500`, `.50`, signs, spaces and commas are refused,
/// so the signed message always holds the exact string the rail sends to PayPal.
pub fn amount_to_cents(amount: &str) -> Result<u128, ContractError> {
    let (int, frac) = amount.split_once('.').ok_or(ContractError::InvalidAmount)?;
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    let canonical = digits(int)
        && digits(frac)
        && frac.len() == 2
        && int.len() <= MAX_AMOUNT_INT_DIGITS
        && (int == "0" || !int.starts_with('0'));
    if !canonical {
        return Err(ContractError::InvalidAmount);
    }
    let parse = |s: &str| s.parse::<u128>().map_err(|_| ContractError::InvalidAmount);
    let cents = parse(int)? * 100 + parse(frac)?;
    if cents == 0 {
        return Err(ContractError::InvalidAmount);
    }
    Ok(cents)
}

/// `Send USD {amount} to {payee} at {YYYY-MM-DDTHH:MM:SSZ} ref {request_id}`.
pub fn paypal_message(amount: &str, payee: &str, timestamp_secs: u64, request_id: &str) -> String {
    format!(
        "Send USD {amount} to {payee} at {} ref {request_id}",
        rfc3339_utc(timestamp_secs)
    )
}

/// Domain tag of [`paypal_dedupe_key`]; differs from the shape 3 tag, so both live in the
/// same set without colliding.
const PAYPAL_DEDUPE_DOMAIN: &str = "nearh:paypal-dedupe:v1";

/// Key of the per-agent `(agent, payee, amount, ts)` re-signing dedupe (D3, as shape 3):
/// `keccak256(borsh((PAYPAL_DEDUPE_DOMAIN, agent, payee, amount, timestamp: u64)))`, with
/// the normalised payee and the canonical amount. The `request_id` is left out on purpose:
/// the same order under a new `request_id` would get a new `sender_batch_id`, which PayPal
/// pays again.
pub fn paypal_dedupe_key(
    agent: &AgentId,
    payee: &str,
    amount: &str,
    timestamp_secs: u64,
) -> [u8; 32] {
    let preimage = borsh::to_vec(&(
        PAYPAL_DEDUPE_DOMAIN,
        agent.as_str(),
        payee,
        amount,
        timestamp_secs,
    ))
    .unwrap_or_else(|_| env::panic_str("borsh paypal dedupe preimage"));
    env::keccak256_array(&preimage)
}

/// Checks that the mandate has a PayPal rail (`ERR_SHAPE_NOT_ALLOWED`), the payee is
/// valid and on `allowed_payees` after normalisation, the amount is canonical and within
/// `mandate.paypal.amount_range`, and the timestamp is in the shape 3 window
/// (`now - (max_validity_secs - CLOCK_SKEW_SECS) <= timestamp <= now + CLOCK_SKEW_SECS`);
/// then builds the message. `request_id` must already have passed `validate_request_id`.
/// `valid_before = timestamp + max_validity_secs - CLOCK_SKEW_SECS`; the rail must not
/// submit after it. `release_after = max(valid_before, timestamp + PAYOUT_RELEASE_DELAY_SECS)`.
pub fn build_paypal(
    req: &PaypalRequest,
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
    if req.timestamp < now_secs.saturating_sub(lifetime) {
        return Err(ContractError::TimestampStale);
    }
    if req.timestamp > now_secs + CLOCK_SKEW_SECS {
        return Err(ContractError::TimestampFuture);
    }

    let text = paypal_message(&req.amount, &payee, req.timestamp, request_id);
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

    /// Documentation-style receivers, not accounts of ours.
    const EMAIL: &str = "supplier@example.com";
    const VENMO: &str = "@demo-supplier";
    const OTHER_EMAIL: &str = "attacker@example.com";
    /// 2026-11-04T22:27:06Z, the PP-S1 sandbox run.
    const TS: u64 = 1_793_831_226;
    const ID: &str = "inv-2026-0042";

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
            // 0.01..=50.00 USD per payout, 200.00 USD per week.
            paypal: Some(rail(1, 5_000, 20_000)),
            paypal_refund: None,
            usdc_eip712_name: "USDC".into(),
            usdc_eip712_version: "2".into(),
        }
    }

    fn payees() -> Vec<Payee> {
        vec![
            Payee::Sepa {
                iban: "DE89370400440532013000".to_string(),
            },
            Payee::Paypal {
                receiver: EMAIL.to_string(),
            },
            Payee::Paypal {
                receiver: VENMO.to_string(),
            },
        ]
    }

    fn req(payee: &str, amount: &str, timestamp: u64) -> PaypalRequest {
        PaypalRequest {
            payee: payee.to_string(),
            amount: amount.to_string(),
            timestamp,
        }
    }

    fn build(r: &PaypalRequest, now: u64) -> Result<BuiltRequest, ContractError> {
        build_paypal(r, ID, &mandate(), &payees(), now)
    }

    fn text(b: &BuiltRequest) -> String {
        match &b.payload {
            SignedPayload::Message { text } => text.clone(),
            other => panic!("not a message: {other:?}"),
        }
    }

    #[test]
    fn happy_path_message_bytes() {
        let built = build(&req(EMAIL, "1.00", TS), TS + 12).unwrap();
        let expected =
            "Send USD 1.00 to supplier@example.com at 2026-11-04T22:27:06Z ref inv-2026-0042";
        assert_eq!(text(&built).as_bytes(), expected.as_bytes());
        assert_eq!(built.digest, eip191_digest(expected));
        // keccak256("\x19Ethereum Signed Message:\n79" || expected), computed independently.
        assert_eq!(
            hex::encode(built.digest),
            "93a3d0f96e79b1166369480f28cc76d1e61202632b09d66839b21cd231d0a7c1"
        );
        assert_eq!(built.rail, Some(Rail::Paypal));
        assert_eq!(built.amount, 100);
        assert_eq!(built.valid_before, TS + 240);
        assert_eq!(built.release_after, TS + PAYOUT_RELEASE_DELAY_SECS);
    }

    #[test]
    fn venmo_handle_and_payee_normalisation() {
        let built = build(&req("  @Demo-Supplier\t", "42.50", TS), TS).unwrap();
        assert_eq!(
            text(&built),
            "Send USD 42.50 to @demo-supplier at 2026-11-04T22:27:06Z ref inv-2026-0042"
        );
        assert_eq!(built.amount, 4_250);
        // An email in mixed case with whitespace signs the stored lowercase form.
        let a = build(&req(" Supplier@Example.COM ", "1.00", TS), TS).unwrap();
        assert_eq!(a, build(&req(EMAIL, "1.00", TS), TS).unwrap());
    }

    #[test]
    fn payee_not_allowlisted_is_refused() {
        assert_eq!(
            build(&req(OTHER_EMAIL, "1.00", TS), TS),
            Err(ContractError::PaypalPayeeNotAllowed)
        );
        assert_eq!(
            build(&req("@other-handle", "1.00", TS), TS),
            Err(ContractError::PaypalPayeeNotAllowed)
        );
        // An email allowlisted as a Venmo handle (or the reverse) is a different payee.
        assert_eq!(
            build(&req("@supplier", "1.00", TS), TS),
            Err(ContractError::PaypalPayeeNotAllowed)
        );
        assert_eq!(
            build(&req("demo-supplier@example.com", "1.00", TS), TS),
            Err(ContractError::PaypalPayeeNotAllowed)
        );
        // A listed IBAN is not a PayPal payee.
        assert_eq!(
            build(&req("DE89370400440532013000", "1.00", TS), TS),
            Err(ContractError::InvalidPaypalPayee)
        );
    }

    #[test]
    fn malformed_payee_is_refused() {
        let long_local = format!("{}@example.com", "a".repeat(65));
        let long_email = format!("a@{}.com", "b.".repeat(126));
        for bad in [
            "",
            " ",
            "@",
            "@abcd",
            &format!("@{}", "a".repeat(31)),
            "@demo.supplier",
            "@demo supplier",
            "supplier",
            "supplier@",
            "@example.com",
            "supplier@example",
            "supplier@@example.com",
            "a@b@example.com",
            "sup plier@example.com",
            "supplier@exa mple.com",
            ".supplier@example.com",
            "supplier.@example.com",
            "sup..plier@example.com",
            "supplier@example..com",
            "supplier@-example.com",
            "supplier@example-.com",
            "supplier@.example.com",
            "\"s\"@example.com",
            "supplier@[127.0.0.1]",
            "suppliér@example.com",
            "supplier@example.com at 2026",
            "supplier@example.com\nref x",
            &long_local,
            &long_email,
        ] {
            assert_eq!(
                build(&req(bad, "1.00", TS), TS),
                Err(ContractError::InvalidPaypalPayee),
                "{bad:?}"
            );
        }
        assert!(normalize_receiver(&format!("{}@example.com", "a".repeat(64))).is_ok());
        assert!(normalize_receiver(&format!("@{}", "a".repeat(30))).is_ok());
        assert!(normalize_receiver("sb-abc123@personal.example.com").is_ok());
        assert!(normalize_receiver("first.last+tag@sub.example.co.uk").is_ok());
    }

    #[test]
    fn stale_timestamp_is_refused() {
        // max_validity_secs 300, skew 60: the oldest accepted timestamp is now - 240.
        let now = TS + 240;
        assert!(build(&req(EMAIL, "1.00", TS), now).is_ok());
        assert_eq!(
            build(&req(EMAIL, "1.00", TS), now + 1),
            Err(ContractError::TimestampStale)
        );
        assert_eq!(
            build(&req(EMAIL, "1.00", 0), now),
            Err(ContractError::TimestampStale)
        );
    }

    #[test]
    fn future_timestamp_is_refused() {
        assert!(build(&req(EMAIL, "1.00", TS + 60), TS).is_ok());
        assert_eq!(
            build(&req(EMAIL, "1.00", TS + 61), TS),
            Err(ContractError::TimestampFuture)
        );
        assert_eq!(
            build(&req(EMAIL, "1.00", u64::MAX), TS),
            Err(ContractError::TimestampFuture)
        );
    }

    #[test]
    fn non_canonical_amount_is_refused() {
        for (good, cents) in [
            ("0.01", 1),
            ("1.00", 100),
            ("10.50", 1_050),
            ("50.00", 5_000),
        ] {
            assert_eq!(amount_to_cents(good), Ok(cents), "{good}");
        }
        for bad in [
            "",
            "1",
            "1.5",
            "1.500",
            "01.50",
            "00.50",
            "001.00",
            ".50",
            "1.",
            "0.00",
            "0",
            "-1.00",
            "+1.00",
            "1e2",
            " 1.00",
            "1.00 ",
            "1,00",
            "1..00",
            "1.0.0",
            "0x10",
            "١.00",
            "1000000000000.00",
        ] {
            assert_eq!(
                build(&req(EMAIL, bad, TS), TS),
                Err(ContractError::InvalidAmount),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn over_cap_is_refused() {
        assert_eq!(build(&req(EMAIL, "50.00", TS), TS).unwrap().amount, 5_000);
        assert_eq!(
            build(&req(EMAIL, "50.01", TS), TS),
            Err(ContractError::OverPerPaymentCap)
        );
        assert_eq!(
            build(&req(EMAIL, "999999999999.99", TS), TS),
            Err(ContractError::OverPerPaymentCap)
        );
    }

    #[test]
    fn below_minimum_is_refused() {
        let mut m = mandate();
        m.paypal.as_mut().unwrap().amount_range.min = U128(100);
        assert_eq!(
            build_paypal(&req(EMAIL, "0.99", TS), ID, &m, &payees(), TS),
            Err(ContractError::BelowMinimum)
        );
    }

    #[test]
    fn mandate_without_paypal_rail_refuses_shape_4() {
        let mut m = mandate();
        m.paypal = None;
        assert_eq!(
            build_paypal(&req(EMAIL, "1.00", TS), ID, &m, &payees(), TS),
            Err(ContractError::ShapeNotAllowed)
        );
    }

    #[test]
    fn request_id_is_in_the_message() {
        let a = build_paypal(&req(EMAIL, "1.00", TS), "a-1", &mandate(), &payees(), TS).unwrap();
        let b = build_paypal(&req(EMAIL, "1.00", TS), "a-2", &mandate(), &payees(), TS).unwrap();
        assert!(text(&a).ends_with(" ref a-1"));
        assert_ne!(a.digest, b.digest);
    }

    #[test]
    fn dedupe_key_is_per_agent_and_fields_cannot_shift() {
        let (a, b): (AgentId, AgentId) = ("agent-a".into(), "agent-b".into());
        let key = paypal_dedupe_key;
        assert_eq!(key(&a, EMAIL, "1.00", TS), key(&a, EMAIL, "1.00", TS));
        assert_ne!(key(&a, EMAIL, "1.00", TS), key(&b, EMAIL, "1.00", TS));
        assert_ne!(key(&a, EMAIL, "1.00", TS), key(&a, EMAIL, "1.00", TS + 1));
        assert_ne!(key(&a, EMAIL, "1.00", TS), key(&a, VENMO, "1.00", TS));
        assert_ne!(
            key(&a, "x@y.io", "11.00", TS),
            key(&a, "x@y.io1", "1.00", TS)
        );
        // Not the shape 3 key for the same fields, and not the untagged tuple.
        assert_ne!(
            key(&a, EMAIL, "1.00", TS),
            super::super::payout::payout_dedupe_key(&a, EMAIL, "1.00", TS)
        );
        let untagged = borsh::to_vec(&("agent-a", EMAIL, "1.00", TS)).unwrap();
        assert_ne!(key(&a, EMAIL, "1.00", TS), env::keccak256_array(&untagged));
    }
}
