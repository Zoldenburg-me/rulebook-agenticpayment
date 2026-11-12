//! Shape 2: an x402 payment (C5). EIP-3009 `transferWithAuthorization` of USDC with
//! `to = payTo` and `value = amount`, after the checks below.

use near_sdk::json_types::U128;

use super::{eip3009_digest, BuiltRequest, Eip3009Authorization, Eip712Domain};
use crate::errors::ContractError;
use crate::types::{
    EvmAddress, Mandate, Payee, Rail, SignedPayload, X402PaymentRequirements, CLOCK_SKEW_SECS,
};

/// The EIP-712 domain is `{mandate.usdc_eip712_name, mandate.usdc_eip712_version, chain_id,
/// usdc_address}` (USDC / `2` by default, PYUSD is `PayPal USD` / `1`, spikes/pyusd-x402).
///
/// Checks `scheme == "exact"`, `payTo` in `allowed_payees`, `asset == usdc_address`,
/// `network == "eip155:{chain_id}"`, the amount within `mandate.x402.amount_range` and
/// `max_timeout_seconds >= 1` (`ERR_INVALID_TIMEOUT`); then builds the authorization from
/// `from` (the agent EOA) with `validAfter = now - CLOCK_SKEW_SECS` and `validBefore = now +
/// min(max_timeout_seconds, max_validity_secs - CLOCK_SKEW_SECS)`. A long seller timeout is
/// clamped, not rejected, so `validBefore - validAfter <= max_validity_secs`. The budget is
/// checked by the request pipeline with the returned amount.
///
/// `release_after = valid_before + CLOCK_SKEW_SECS`: USDC checks `validBefore` against Base
/// block time, which may lag NEAR block time, so the budget is never released while the
/// authorization could still settle.
///
/// Addresses are compared case-insensitively (`payTo` against the allowlist, `asset` against
/// `usdc_address`), and the payload carries them lowercased.
/// `nonce` is `eip3009_nonce(key, ShapeKind::X402)`.
pub fn build_x402(
    req: &X402PaymentRequirements,
    mandate: &Mandate,
    allowed_payees: &[Payee],
    from: &EvmAddress,
    nonce: [u8; 32],
    now_secs: u64,
) -> Result<BuiltRequest, ContractError> {
    if req.scheme != "exact" {
        return Err(ContractError::WrongScheme);
    }
    let pay_to = req.pay_to.to_ascii_lowercase();
    let allowed = allowed_payees
        .iter()
        .any(|p| matches!(p, Payee::X402 { pay_to: a } if a.eq_ignore_ascii_case(&pay_to)));
    if !allowed {
        return Err(ContractError::PayeeNotAllowed);
    }
    if !req.asset.eq_ignore_ascii_case(&mandate.usdc_address) {
        return Err(ContractError::WrongAsset);
    }
    if req.network != format!("eip155:{}", mandate.chain_id) {
        return Err(ContractError::WrongNetwork);
    }
    let amount = req.amount.0;
    if amount < mandate.x402.amount_range.min.0 {
        return Err(ContractError::BelowMinimum);
    }
    if amount > mandate.x402.amount_range.max.0 {
        return Err(ContractError::OverPerPaymentCap);
    }
    if req.max_timeout_seconds == 0 {
        return Err(ContractError::InvalidTimeout);
    }

    let max_validity = u64::from(mandate.max_validity_secs);
    let lifetime =
        u64::from(req.max_timeout_seconds).min(max_validity.saturating_sub(CLOCK_SKEW_SECS));
    let valid_after = now_secs.saturating_sub(CLOCK_SKEW_SECS);
    let valid_before = now_secs + lifetime;
    // set_mandate keeps max_validity_secs >= MIN_VALIDITY_SECS, so this holds; never sign
    // a longer window if that invariant is ever broken.
    if lifetime == 0 || valid_before - valid_after > max_validity {
        return Err(ContractError::InvalidMandate);
    }

    let domain = Eip712Domain {
        name: mandate.usdc_eip712_name.clone(),
        version: mandate.usdc_eip712_version.clone(),
        chain_id: mandate.chain_id,
        verifying_contract: mandate.usdc_address.to_ascii_lowercase(),
    };
    let auth = Eip3009Authorization {
        from: from.clone(),
        to: pay_to,
        value: amount,
        valid_after,
        valid_before,
        nonce,
    };
    let digest = eip3009_digest(&domain, &auth);
    Ok(BuiltRequest {
        digest,
        payload: SignedPayload::Eip3009 {
            asset: domain.verifying_contract,
            chain_id: domain.chain_id,
            from: auth.from,
            to: auth.to,
            value: U128(amount),
            valid_after,
            valid_before,
            nonce: format!("0x{}", hex::encode(nonce)),
        },
        rail: Some(Rail::X402),
        amount,
        valid_before,
        release_after: valid_before + CLOCK_SKEW_SECS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shapes::eip3009_nonce;
    use crate::types::{AmountRange, Caller, FloatCap, RailMandate, RequestKey, ShapeKind};

    const USDC: &str = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
    const EURE: &str = "0x29f37f6adca168b79b8d9567eab9be3fbf21db85";
    // From spikes/x402/RESULT.md (recorded settled run).
    const SC_FROM: &str = "0xbbc0320e02d371a71f18a40b7b15404df218d880";
    const SC_PAY_TO: &str = "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f";
    const SC_NONCE: &str = "1fc1b8c54141f9488ae59cb01f3500d4b02062c27a2fc5839004370c81a716c7";
    const SC_DIGEST: &str = "720dffe2a39e40e2513eaf70b1d55c4b0b4667c34d2812e2113bebc6834cb5ed";
    const NOW: u64 = 1_793_555_581;

    fn mandate() -> Mandate {
        let rail = |max: u128, budget: u128| RailMandate {
            amount_range: AmountRange {
                min: U128(1),
                max: U128(max),
            },
            budget: U128(budget),
            period_secs: 604_800,
        };
        Mandate {
            x402: rail(1_000_000, 20_000_000),
            sepa: rail(50_000_000_000_000_000_000, 200_000_000_000_000_000_000),
            usdc_address: USDC.to_string(),
            eure_address: EURE.to_string(),
            chain_id: 84532,
            float_cap: FloatCap {
                usdc: U128(25_000_000),
                eure: U128(250_000_000_000_000_000_000),
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
            Payee::Sepa {
                iban: "DE89370400440532013000".to_string(),
            },
            Payee::X402 {
                pay_to: SC_PAY_TO.to_string(),
            },
        ]
    }

    fn req() -> X402PaymentRequirements {
        X402PaymentRequirements {
            resource_url: "http://localhost:4021/weather".to_string(),
            scheme: "exact".to_string(),
            network: "eip155:84532".to_string(),
            asset: USDC.to_string(),
            pay_to: SC_PAY_TO.to_string(),
            amount: U128(10_000),
            max_timeout_seconds: 240,
        }
    }

    fn nonce() -> [u8; 32] {
        let mut n = [0u8; 32];
        hex::decode_to_slice(SC_NONCE, &mut n).unwrap();
        n
    }

    fn build(r: &X402PaymentRequirements) -> Result<BuiltRequest, ContractError> {
        build_x402(r, &mandate(), &payees(), &SC_FROM.to_string(), nonce(), NOW)
    }

    #[test]
    fn digest_matches_sc_tx() {
        // The recorded run used a 360 s window, so call the digest builder directly.
        let domain = Eip712Domain {
            name: "USDC".to_string(),
            version: "2".to_string(),
            chain_id: 84532,
            verifying_contract: USDC.to_string(),
        };
        let auth = Eip3009Authorization {
            from: SC_FROM.to_string(),
            to: SC_PAY_TO.to_string(),
            value: 10_000,
            valid_after: 1_793_555_521,
            valid_before: 1_793_555_881,
            nonce: nonce(),
        };
        assert_eq!(hex::encode(eip3009_digest(&domain, &auth)), SC_DIGEST);
    }

    // From spikes/pyusd-x402/RESULT.md, run 2 `[own]`: PYUSD on Ethereum Sepolia, settled in
    // 0x07a0bc1842fd91473862c5c21cf86db765e4d07416089442275a18be5fecb344.
    const PYUSD: &str = "0xcac524bca292aaade2df8a05cc58f0a65b1b3bb9";
    const PYUSD_CHAIN_ID: u64 = 11_155_111;
    const PYUSD_NONCE: &str = "cca2cda195b032738e79e9df1381c1bf11a789b84c08dcd2d8aa1d360ed410a6";
    const PYUSD_DIGEST: &str = "4587c66d146de4b7fafd2a09a33a44d00b7121995e84a5459f55e7643d44d607";
    const PYUSD_VALID_AFTER: u64 = 1_793_832_722;
    const PYUSD_VALID_BEFORE: u64 = 1_793_832_992;

    fn pyusd_mandate() -> Mandate {
        let mut m = mandate();
        m.usdc_address = PYUSD.to_string();
        m.chain_id = PYUSD_CHAIN_ID;
        m.usdc_eip712_name = "PayPal USD".to_string();
        m.usdc_eip712_version = "1".to_string();
        m
    }

    fn pyusd_req(max_timeout_seconds: u32) -> X402PaymentRequirements {
        let mut r = req();
        r.network = format!("eip155:{PYUSD_CHAIN_ID}");
        r.asset = "0xCaC524BcA292aaade2DF8A05cC58F0a65B1B3bB9".to_string();
        r.max_timeout_seconds = max_timeout_seconds;
        r
    }

    fn pyusd_nonce() -> [u8; 32] {
        let mut n = [0u8; 32];
        hex::decode_to_slice(PYUSD_NONCE, &mut n).unwrap();
        n
    }

    #[test]
    fn pyusd_digest_matches_pp_s2_tx() {
        // Build through build_x402: validAfter = now - 60 and the 210 s seller timeout give
        // the recorded 270 s window.
        let now = PYUSD_VALID_AFTER + CLOCK_SKEW_SECS;
        let built = build_x402(
            &pyusd_req(210),
            &pyusd_mandate(),
            &payees(),
            &SC_FROM.to_string(),
            pyusd_nonce(),
            now,
        )
        .unwrap();
        assert_eq!(hex::encode(built.digest), PYUSD_DIGEST);
        let SignedPayload::Eip3009 {
            asset,
            chain_id,
            valid_after,
            valid_before,
            ..
        } = built.payload
        else {
            panic!("expected Eip3009 payload");
        };
        assert_eq!((asset.as_str(), chain_id), (PYUSD, PYUSD_CHAIN_ID));
        assert_eq!(
            (valid_after, valid_before),
            (PYUSD_VALID_AFTER, PYUSD_VALID_BEFORE)
        );
    }

    #[test]
    fn domain_name_and_version_change_digest() {
        // The same PYUSD authorization under the USDC default domain is a different digest,
        // so a mandate with the wrong name/version yields a signature the token rejects.
        let now = PYUSD_VALID_AFTER + CLOCK_SKEW_SECS;
        let from = SC_FROM.to_string();
        let digest = |m: &Mandate| {
            build_x402(&pyusd_req(210), m, &payees(), &from, pyusd_nonce(), now)
                .unwrap()
                .digest
        };
        let pyusd = digest(&pyusd_mandate());
        let mut m = pyusd_mandate();
        m.usdc_eip712_name = "USDC".to_string();
        assert_ne!(digest(&m), pyusd);
        let mut m = pyusd_mandate();
        m.usdc_eip712_version = "2".to_string();
        assert_ne!(digest(&m), pyusd);
    }

    #[test]
    fn pyusd_mandate_rejects_usdc_asset() {
        // A PYUSD mandate still rejects any other asset, USDC included.
        let mut r = pyusd_req(210);
        r.asset = USDC.to_string();
        let from = SC_FROM.to_string();
        let build = |r: &X402PaymentRequirements| {
            build_x402(r, &pyusd_mandate(), &payees(), &from, pyusd_nonce(), NOW)
        };
        assert_eq!(build(&r), Err(ContractError::WrongAsset));
        r.asset = EURE.to_string();
        assert_eq!(build(&r), Err(ContractError::WrongAsset));
        // And the USDC request against it: wrong asset before network.
        assert_eq!(build(&req()), Err(ContractError::WrongAsset));
    }

    #[test]
    fn builds_authorization_to_pay_to() {
        let built = build(&req()).unwrap();
        assert_eq!(built.rail, Some(Rail::X402));
        assert_eq!(built.amount, 10_000);
        assert_eq!(built.valid_before, NOW + 240);
        assert_eq!(built.release_after, NOW + 240 + CLOCK_SKEW_SECS);
        let SignedPayload::Eip3009 {
            asset,
            chain_id,
            from,
            to,
            value,
            valid_after,
            valid_before,
            nonce: n,
        } = built.payload.clone()
        else {
            panic!("expected Eip3009 payload");
        };
        assert_eq!(
            (asset.as_str(), chain_id, from.as_str(), to.as_str()),
            (USDC, 84532, SC_FROM, SC_PAY_TO)
        );
        assert_eq!(value, U128(10_000));
        assert_eq!((valid_after, valid_before), (NOW - 60, NOW + 240));
        assert_eq!(n, format!("0x{SC_NONCE}"));
        // The digest is the EIP-712 hash of exactly these fields.
        let domain = Eip712Domain {
            name: "USDC".into(),
            version: "2".into(),
            chain_id,
            verifying_contract: asset,
        };
        let auth = Eip3009Authorization {
            from,
            to,
            value: value.0,
            valid_after,
            valid_before,
            nonce: nonce(),
        };
        assert_eq!(built.digest, eip3009_digest(&domain, &auth));
    }

    #[test]
    fn checksummed_addresses_match_lowercase() {
        let mut r = req();
        r.pay_to = "0xEea5E3Bcc1E058aef9586a1c5C4cADc9CFDbC74F".to_string();
        r.asset = "0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_string();
        assert_eq!(build(&r).unwrap(), build(&req()).unwrap());
    }

    #[test]
    fn release_after_covers_base_clock_skew() {
        // Base block time may lag NEAR by up to CLOCK_SKEW_SECS, so the reservation must
        // outlive validBefore by that much, for every timeout and mandate in range.
        let mut r = req();
        for max_validity in [120u32, 300] {
            let mut m = mandate();
            m.max_validity_secs = max_validity;
            for t in [1u32, 60, 240, u32::MAX] {
                r.max_timeout_seconds = t;
                let b = build_x402(&r, &m, &payees(), &SC_FROM.to_string(), nonce(), NOW).unwrap();
                assert_eq!(
                    b.release_after,
                    b.valid_before + CLOCK_SKEW_SECS,
                    "{max_validity} {t}"
                );
                assert!(b.release_after > b.valid_before);
            }
        }
    }

    #[test]
    fn checksummed_mandate_and_allowlist_match() {
        // C2 may store checksummed addresses; the payload stays lowercase either way.
        let mut m = mandate();
        m.usdc_address = "0x036CbD53842c5426634e7929541eC2318f3dCF7e".to_string();
        let allow = vec![Payee::X402 {
            pay_to: "0xEea5E3Bcc1E058aef9586a1c5C4cADc9CFDbC74F".to_string(),
        }];
        let from = SC_FROM.to_string();
        let built = build_x402(&req(), &m, &allow, &from, nonce(), NOW).unwrap();
        assert_eq!(built, build(&req()).unwrap());
        let mut r = req();
        r.pay_to = "0xEEA5E3BCC1E058AEF9586A1C5C4CADC9CFDBC74F".to_string();
        r.asset = USDC.to_uppercase().replacen("0X", "0x", 1);
        assert_eq!(
            build_x402(&r, &m, &allow, &from, nonce(), NOW).unwrap(),
            built
        );
    }

    #[test]
    fn pay_to_not_allowlisted_rejected() {
        let mut r = req();
        r.pay_to = "0x000000000000000000000000000000000000dead".to_string();
        assert_eq!(build(&r), Err(ContractError::PayeeNotAllowed));
        // An empty allowlist rejects too.
        assert_eq!(
            build_x402(&req(), &mandate(), &[], &SC_FROM.to_string(), nonce(), NOW),
            Err(ContractError::PayeeNotAllowed)
        );
    }

    #[test]
    fn wrong_asset_rejected() {
        let mut r = req();
        r.asset = EURE.to_string();
        assert_eq!(build(&r), Err(ContractError::WrongAsset));
    }

    #[test]
    fn wrong_network_rejected() {
        for network in ["eip155:8453", "eip155:84532 ", "base-sepolia", "84532"] {
            let mut r = req();
            r.network = network.to_string();
            assert_eq!(build(&r), Err(ContractError::WrongNetwork), "{network}");
        }
    }

    #[test]
    fn wrong_scheme_rejected() {
        let mut r = req();
        r.scheme = "upto".to_string();
        assert_eq!(build(&r), Err(ContractError::WrongScheme));
    }

    #[test]
    fn over_per_payment_cap_rejected() {
        let mut r = req();
        r.amount = U128(1_000_000);
        assert!(build(&r).is_ok());
        r.amount = U128(1_000_001);
        assert_eq!(build(&r), Err(ContractError::OverPerPaymentCap));
        r.amount = U128(0);
        assert_eq!(build(&r), Err(ContractError::BelowMinimum));
    }

    #[test]
    fn long_timeout_clamped_to_max_validity() {
        let mut r = req();
        r.max_timeout_seconds = 3600;
        let built = build(&r).unwrap();
        // validBefore = now + (300 - 60); window = validBefore - validAfter = 300.
        assert_eq!(built.valid_before, NOW + 240);
        let SignedPayload::Eip3009 {
            valid_after,
            valid_before,
            ..
        } = built.payload
        else {
            panic!("expected Eip3009 payload");
        };
        assert_eq!(valid_before - valid_after, 300);

        // A shorter seller timeout is kept as is.
        r.max_timeout_seconds = 60;
        assert_eq!(build(&r).unwrap().valid_before, NOW + 60);

        // Window never exceeds max_validity_secs for any timeout or mandate in range.
        for max_validity in [120u32, 200, 300] {
            let mut m = mandate();
            m.max_validity_secs = max_validity;
            for t in [1u32, 59, 60, 61, 239, 240, 241, 300, u32::MAX] {
                r.max_timeout_seconds = t;
                let b = build_x402(&r, &m, &payees(), &SC_FROM.to_string(), nonce(), NOW).unwrap();
                let SignedPayload::Eip3009 {
                    valid_after,
                    valid_before,
                    ..
                } = b.payload
                else {
                    panic!();
                };
                assert!(
                    valid_before - valid_after <= u64::from(max_validity),
                    "{max_validity} {t}"
                );
                assert!(valid_before > NOW);
            }
        }
    }

    #[test]
    fn zero_timeout_rejected() {
        let mut r = req();
        r.max_timeout_seconds = 0;
        assert_eq!(build(&r), Err(ContractError::InvalidTimeout));
    }

    #[test]
    fn mandate_below_skew_never_signs_long_window() {
        let mut m = mandate();
        m.max_validity_secs = 60;
        assert_eq!(
            build_x402(&req(), &m, &payees(), &SC_FROM.to_string(), nonce(), NOW),
            Err(ContractError::InvalidMandate)
        );
    }

    #[test]
    fn nonce_differs_by_caller_and_changes_digest() {
        let key = |caller| RequestKey {
            agent: "agent-1".into(),
            caller,
            request_id: "pay-0001".into(),
        };
        let agent = eip3009_nonce(&key(Caller::Agent), ShapeKind::X402);
        let owner = eip3009_nonce(&key(Caller::Owner), ShapeKind::X402);
        let relayer = eip3009_nonce(
            &key(Caller::Relayer {
                account: "relayer.testnet".parse().unwrap(),
            }),
            ShapeKind::X402,
        );
        assert_ne!(agent, owner);
        assert_ne!(agent, relayer);
        assert_ne!(owner, relayer);
        // Same key, other shape or other agent: different nonce. Same inputs: same nonce.
        assert_ne!(agent, eip3009_nonce(&key(Caller::Agent), ShapeKind::Sweep));
        let mut other_agent = key(Caller::Agent);
        other_agent.agent = "agent-2".into();
        assert_ne!(agent, eip3009_nonce(&other_agent, ShapeKind::X402));
        assert_eq!(agent, eip3009_nonce(&key(Caller::Agent), ShapeKind::X402));

        let from = SC_FROM.to_string();
        let a = build_x402(&req(), &mandate(), &payees(), &from, agent, NOW).unwrap();
        let o = build_x402(&req(), &mandate(), &payees(), &from, owner, NOW).unwrap();
        assert_ne!(a.digest, o.digest);
    }

    #[test]
    fn nonce_is_keccak_of_borsh_tuple() {
        let key = RequestKey {
            agent: "agent-1".into(),
            caller: Caller::Agent,
            request_id: "pay-0001".into(),
        };
        // borsh((String, Caller, u8, String)): u32-LE length-prefixed strings, enum index byte.
        let mut pre = Vec::new();
        pre.extend_from_slice(&7u32.to_le_bytes());
        pre.extend_from_slice(b"agent-1");
        pre.push(0); // Caller::Agent
        pre.push(2); // ShapeKind::X402.tag()
        pre.extend_from_slice(&8u32.to_le_bytes());
        pre.extend_from_slice(b"pay-0001");
        assert_eq!(
            eip3009_nonce(&key, ShapeKind::X402),
            near_sdk::env::keccak256_array(&pre)
        );
    }
}
