//! Shape 3: a Monerium payout order (C6). The contract renders
//! `Send EUR {amount} to {iban} at {RFC3339}` from decoded fields and signs it with EIP-191.

use near_sdk::{borsh, env};

use super::{eip191_digest, BuiltRequest};
use crate::errors::ContractError;
use crate::types::{
    AgentId, Mandate, Payee, PayoutRequest, Rail, SignedPayload, CLOCK_SKEW_SECS,
    PAYOUT_RELEASE_DELAY_SECS,
};

/// EURe decimals.
const EURE_DECIMALS: u32 = 18;

/// Canonical amount (D9): no leading zeros in the integer part, no trailing zeros and no
/// trailing dot (`007.50` → `7.5`, `1.50` → `1.5`, `2.00` → `2`, `0.50` → `0.5`), matching
/// Zold-app's `moneriumAmountString`. Input must match `^[0-9]+(\.[0-9]{1,2})?$`, so `.5`,
/// `5.`, signs, exponents, spaces, commas and 3+ decimals are `ERR_INVALID_AMOUNT`; so is a
/// value of zero (`0`, `0.00`).
pub fn canonical_amount(amount: &str) -> Result<String, ContractError> {
    let (int, frac) = match amount.split_once('.') {
        Some((i, f)) => (i, f),
        None => (amount, ""),
    };
    let digits = |s: &str| s.bytes().all(|c| c.is_ascii_digit());
    let well_formed = !int.is_empty()
        && digits(int)
        && digits(frac)
        && (!amount.contains('.') || (1..=2).contains(&frac.len()));
    if !well_formed {
        return Err(ContractError::InvalidAmount);
    }
    let int = int.trim_start_matches('0');
    let frac = frac.trim_end_matches('0');
    if int.is_empty() && frac.is_empty() {
        return Err(ContractError::InvalidAmount);
    }
    let int = if int.is_empty() { "0" } else { int };
    Ok(if frac.is_empty() {
        int.to_string()
    } else {
        format!("{int}.{frac}")
    })
}

/// EURe base units (18 decimals) of a canonical amount, for cap and budget checks.
pub fn amount_to_base_units(canonical: &str) -> Result<u128, ContractError> {
    let (int, frac) = canonical.split_once('.').unwrap_or((canonical, ""));
    let parse = |s: &str| -> Result<u128, ContractError> {
        if s.is_empty() {
            return Ok(0);
        }
        s.parse::<u128>().map_err(|_| ContractError::InvalidAmount)
    };
    if frac.len() > 2 {
        return Err(ContractError::InvalidAmount);
    }
    let frac_units = parse(frac)? * 10u128.pow(EURE_DECIMALS - frac.len() as u32);
    parse(int)?
        .checked_mul(10u128.pow(EURE_DECIMALS))
        .and_then(|i| i.checked_add(frac_units))
        .ok_or(ContractError::InvalidAmount)
}

/// `Send EUR {canonical_amount} to {iban} at {YYYY-MM-DDTHH:MM:SSZ}`.
pub fn payout_message(canonical_amount: &str, iban: &str, timestamp_secs: u64) -> String {
    format!(
        "Send EUR {canonical_amount} to {iban} at {}",
        rfc3339_utc(timestamp_secs)
    )
}

/// Domain tag of [`payout_dedupe_key`], so its preimage never equals another hash's.
const PAYOUT_DEDUPE_DOMAIN: &str = "nearh:payout-dedupe:v1";

/// Key of the per-agent `(agent, iban, amount, ts)` re-signing dedupe (D3):
/// `keccak256(borsh((PAYOUT_DEDUPE_DOMAIN, agent, iban, canonical_amount, timestamp: u64)))`.
/// Borsh length-prefixes every string (u32 LE), so no field can run into the next. Two agents
/// paying the same IBAN and amount in the same second get different keys.
pub fn payout_dedupe_key(
    agent: &AgentId,
    iban: &str,
    canonical_amount: &str,
    timestamp_secs: u64,
) -> [u8; 32] {
    let preimage = borsh::to_vec(&(
        PAYOUT_DEDUPE_DOMAIN,
        agent.as_str(),
        iban,
        canonical_amount,
        timestamp_secs,
    ))
    .unwrap_or_else(|_| env::panic_str("borsh payout dedupe preimage"));
    env::keccak256_array(&preimage)
}

/// Checks the IBAN against `allowed_payees`, the amount against `mandate.sepa.amount_range`,
/// and `now - (max_validity_secs - CLOCK_SKEW_SECS) <= timestamp <= now + CLOCK_SKEW_SECS`
/// (`ERR_TIMESTAMP_STALE`, `ERR_TIMESTAMP_FUTURE`); then builds the message.
/// `valid_before = timestamp + max_validity_secs - CLOCK_SKEW_SECS`, so the window in which
/// the contract would sign a given timestamp is at most `max_validity_secs` long.
/// `release_after = max(valid_before, timestamp + PAYOUT_RELEASE_DELAY_SECS)`.
pub fn build_payout(
    req: &PayoutRequest,
    mandate: &Mandate,
    allowed_payees: &[Payee],
    now_secs: u64,
) -> Result<BuiltRequest, ContractError> {
    let allowed = allowed_payees
        .iter()
        .any(|p| matches!(p, Payee::Sepa { iban } if *iban == req.iban));
    if !allowed {
        return Err(ContractError::IbanNotAllowed);
    }
    let canonical = canonical_amount(&req.amount)?;
    let amount = amount_to_base_units(&canonical)?;
    if amount < mandate.sepa.amount_range.min.0 {
        return Err(ContractError::BelowMinimum);
    }
    if amount > mandate.sepa.amount_range.max.0 {
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

    let text = payout_message(&canonical, &req.iban, req.timestamp);
    let valid_before = req.timestamp + lifetime;
    Ok(BuiltRequest {
        digest: eip191_digest(&text),
        payload: SignedPayload::Message { text },
        rail: Some(Rail::Sepa),
        amount,
        valid_before,
        release_after: valid_before.max(req.timestamp + PAYOUT_RELEASE_DELAY_SECS),
    })
}

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (proleptic Gregorian, UTC).
pub(crate) fn rfc3339_utc(secs: u64) -> String {
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Howard Hinnant's civil_from_days, for days since 1970-01-01 (non-negative here).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AmountRange, FloatCap, RailMandate};
    use near_sdk::json_types::U128;

    /// The standard documentation IBAN (docs/interfaces.md), not an account of ours.
    const IBAN: &str = "DE89370400440532013000";
    /// Another documentation IBAN, never on the allowlist here.
    const OTHER_IBAN: &str = "GB33BUKB20201555555555";
    /// S-b's accepted order was signed at 2026-11-03T07:25:38Z (spikes/monerium/RESULT.md).
    const SB_TS: u64 = 1_793_690_738;
    const EURE_UNIT: u128 = 1_000_000_000_000_000_000;

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
            sepa: rail(1, 50 * EURE_UNIT, 200 * EURE_UNIT),
            usdc_address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e".to_string(),
            eure_address: "0x29f37f6adca168b79b8d9567eab9be3fbf21db85".to_string(),
            chain_id: 84532,
            float_cap: FloatCap {
                usdc: U128(25_000_000),
                eure: U128(250 * EURE_UNIT),
            },
            max_validity_secs: 300,
            paypal: None,
            paypal_refund: None,
            usdc_eip712_name: "USDC".into(),
            usdc_eip712_version: "2".into(),
        }
    }

    fn payees() -> Vec<Payee> {
        vec![
            Payee::X402 {
                pay_to: "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f".to_string(),
            },
            Payee::Sepa {
                iban: IBAN.to_string(),
            },
        ]
    }

    fn req(amount: &str, timestamp: u64) -> PayoutRequest {
        PayoutRequest {
            iban: IBAN.to_string(),
            amount: amount.to_string(),
            timestamp,
        }
    }

    fn build(r: &PayoutRequest, now: u64) -> Result<BuiltRequest, ContractError> {
        build_payout(r, &mandate(), &payees(), now)
    }

    fn text(b: &BuiltRequest) -> &str {
        match &b.payload {
            SignedPayload::Message { text } => text,
            other => panic!("not a message: {other:?}"),
        }
    }

    #[test]
    fn message_is_byte_equal_to_the_sb_accepted_order() {
        // RESULT.md redacts the sandbox IBAN; the rest of the order is compared byte for byte.
        let built = build(&req("0.01", SB_TS), SB_TS + 12).unwrap();
        let expected = format!("Send EUR 0.01 to {IBAN} at 2026-11-03T07:25:38Z");
        assert_eq!(text(&built).as_bytes(), expected.as_bytes());
        assert_eq!(built.digest, eip191_digest(&expected));
        assert_eq!(built.rail, Some(Rail::Sepa));
        assert_eq!(built.amount, EURE_UNIT / 100);
    }

    #[test]
    fn matches_the_interfaces_reservation_example() {
        let built = build(&req("42.50", 1_793_700_000), 1_793_700_010).unwrap();
        assert_eq!(
            text(&built),
            "Send EUR 42.5 to DE89370400440532013000 at 2026-11-03T10:00:00Z"
        );
        assert_eq!(
            hex::encode(built.digest),
            "7292cb34abf39914f4e4b4ad39d14974b6311ebc7cebce59c89d35d8f2834659"
        );
        assert_eq!(built.amount, 42_500_000_000_000_000_000);
        assert_eq!(built.valid_before, 1_793_700_240);
        assert_eq!(built.release_after, 1_793_700_300);
    }

    #[test]
    fn iban_not_allowlisted_is_refused() {
        let mut r = req("1", SB_TS);
        r.iban = OTHER_IBAN.to_string();
        assert_eq!(build(&r, SB_TS), Err(ContractError::IbanNotAllowed));
        // An x402 payee never matches, nor does a differently formatted listed IBAN.
        r.iban = "de89370400440532013000".to_string();
        assert_eq!(build(&r, SB_TS), Err(ContractError::IbanNotAllowed));
        r.iban = "DE89 3704 0044 0532 0130 00".to_string();
        assert_eq!(build(&r, SB_TS), Err(ContractError::IbanNotAllowed));
    }

    #[test]
    fn stale_timestamp_is_refused() {
        // max_validity_secs 300, skew 60: the oldest accepted timestamp is now - 240.
        let now = SB_TS + 240;
        assert!(build(&req("1", SB_TS), now).is_ok());
        assert_eq!(
            build(&req("1", SB_TS), now + 1),
            Err(ContractError::TimestampStale)
        );
        assert_eq!(build(&req("1", 0), now), Err(ContractError::TimestampStale));
    }

    #[test]
    fn future_timestamp_is_refused() {
        assert!(build(&req("1", SB_TS + 60), SB_TS).is_ok());
        assert_eq!(
            build(&req("1", SB_TS + 61), SB_TS),
            Err(ContractError::TimestampFuture)
        );
        assert_eq!(
            build(&req("1", u64::MAX), SB_TS),
            Err(ContractError::TimestampFuture)
        );
    }

    #[test]
    fn signing_window_never_exceeds_max_validity() {
        // A timestamp is signable from ts - 60 to ts + 240: 300 s, and valid_before is its end.
        let built = build(&req("1", SB_TS), SB_TS).unwrap();
        assert_eq!(built.valid_before, SB_TS + 240);
        assert_eq!(built.release_after, SB_TS + PAYOUT_RELEASE_DELAY_SECS);
    }

    #[test]
    fn equal_amounts_give_the_same_message() {
        let a = build(&req("1.5", SB_TS), SB_TS).unwrap();
        for same in ["1.50", "01.5", "001.50"] {
            assert_eq!(build(&req(same, SB_TS), SB_TS).unwrap(), a, "{same}");
        }
        assert_eq!(
            text(&a),
            format!("Send EUR 1.5 to {IBAN} at 2026-11-03T07:25:38Z")
        );
        let agent: AgentId = "agent-a".into();
        assert_eq!(
            payout_dedupe_key(&agent, IBAN, &canonical_amount("1.50").unwrap(), SB_TS),
            payout_dedupe_key(&agent, IBAN, &canonical_amount("1.5").unwrap(), SB_TS)
        );
    }

    #[test]
    fn dedupe_key_is_per_agent_and_fields_cannot_shift() {
        let (a, b): (AgentId, AgentId) = ("agent-a".into(), "agent-b".into());
        let key = |agent: &AgentId, iban: &str, amount: &str, ts: u64| {
            payout_dedupe_key(agent, iban, amount, ts)
        };
        assert_eq!(key(&a, IBAN, "1.5", SB_TS), key(&a, IBAN, "1.5", SB_TS));
        assert_ne!(key(&a, IBAN, "1.5", SB_TS), key(&b, IBAN, "1.5", SB_TS));
        // Moving bytes between adjacent fields changes the key (length prefixes).
        assert_ne!(key(&a, "DE89", "1.5", SB_TS), key(&a, "DE8", "91.5", SB_TS));
        assert_ne!(
            key(&"ab".into(), "c", "1", SB_TS),
            key(&"a".into(), "bc", "1", SB_TS)
        );
        // The domain tag: the key is not the hash of the untagged tuple.
        let untagged = borsh::to_vec(&("agent-a", IBAN, "1.5", SB_TS)).unwrap();
        assert_ne!(key(&a, IBAN, "1.5", SB_TS), env::keccak256_array(&untagged));
    }

    #[test]
    fn over_cap_is_refused() {
        assert_eq!(
            build(&req("50", SB_TS), SB_TS).unwrap().amount,
            50 * EURE_UNIT
        );
        assert_eq!(
            build(&req("50.01", SB_TS), SB_TS),
            Err(ContractError::OverPerPaymentCap)
        );
        // Too large for u128 base units: invalid, never wrapped under the cap.
        let huge = "9".repeat(40);
        assert_eq!(
            build(&req(&huge, SB_TS), SB_TS),
            Err(ContractError::InvalidAmount)
        );
    }

    #[test]
    fn below_minimum_is_refused() {
        let mut m = mandate();
        m.sepa.amount_range.min = U128(EURE_UNIT);
        assert_eq!(
            build_payout(&req("0.99", SB_TS), &m, &payees(), SB_TS),
            Err(ContractError::BelowMinimum)
        );
    }

    #[test]
    fn canonical_amount_follows_d9() {
        for (input, want) in [
            ("007.50", "7.5"),
            ("1.50", "1.5"),
            ("2.00", "2"),
            ("2", "2"),
            ("0.50", "0.5"),
            ("0.01", "0.01"),
            ("42.5", "42.5"),
            ("10", "10"),
            ("100.10", "100.1"),
        ] {
            assert_eq!(canonical_amount(input).as_deref(), Ok(want), "{input}");
        }
        for bad in [
            "", ".5", "5.", "0", "0.00", "00", "-1", "+1", "1e2", " 1", "1 ", "1,50", "1.505",
            "1..5", "1.5.0", "0x10", "١",
        ] {
            assert_eq!(
                canonical_amount(bad),
                Err(ContractError::InvalidAmount),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn base_units_scale_by_18_decimals() {
        assert_eq!(amount_to_base_units("2"), Ok(2 * EURE_UNIT));
        assert_eq!(amount_to_base_units("0.5"), Ok(EURE_UNIT / 2));
        assert_eq!(
            amount_to_base_units("7.05"),
            Ok(7 * EURE_UNIT + EURE_UNIT / 20)
        );
    }

    #[test]
    fn rfc3339_renders_utc_seconds() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_709_251_199), "2024-02-29T23:59:59Z");
        assert_eq!(rfc3339_utc(SB_TS), "2026-11-03T07:25:38Z");
    }
}
