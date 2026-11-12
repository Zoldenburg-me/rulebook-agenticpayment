use super::{
    address_bytes, address_word, eip3009_digest, word, BuiltRequest, Eip3009Authorization,
    Eip712Domain,
};
use crate::errors::ContractError;
use crate::types::{
    AgentRecord, EvmAddress, EvmTxParams, SignedPayload, SweepConfig, Token, BASE_SEPOLIA_CHAIN_ID,
    CLOCK_SKEW_SECS, MAX_SWEEP_GAS_LIMIT, SWEEP_VALIDITY_SECS,
};
use near_sdk::env;
use near_sdk::json_types::U128;

/// Upper bound for `EvmTxParams::max_fee_per_gas` (EURe raw-transfer sweep): 100 gwei, 50
/// times the interfaces.md example. With `MAX_SWEEP_GAS_LIMIT` this caps the fee the tx can
/// ever authorize at 0.015 ETH.
pub const MAX_SWEEP_FEE_PER_GAS: u128 = 100_000_000_000;

/// Shape 1. `from` and `sweep_config` come from the stored agent record, never from the
/// caller, so the authorization or tx always moves the agent's own EOA balance to its Safe.
/// Returns an error, never panics, on malformed stored addresses.
pub fn build_sweep(
    record: &AgentRecord,
    token: Token,
    amount: u128,
    evm_tx: Option<&EvmTxParams>,
    nonce: [u8; 32],
    now_secs: u64,
) -> Result<BuiltRequest, ContractError> {
    let sweep_config = &record.sweep_config;
    if sweep_config.chain_id != BASE_SEPOLIA_CHAIN_ID {
        return Err(ContractError::WrongNetwork);
    }
    let from = record
        .evm_address
        .as_ref()
        .ok_or(ContractError::InvalidAddress)?;
    address_bytes(from)?;
    address_bytes(&sweep_config.safe_address)?;
    match token {
        Token::Usdc => {
            address_bytes(&sweep_config.usdc_address)?;
            build_usdc_sweep(sweep_config, from, amount, nonce, now_secs, evm_tx)
        }
        Token::Eure => build_eure_sweep(sweep_config, amount, evm_tx),
    }
}

fn build_usdc_sweep(
    sweep_config: &SweepConfig,
    from: &EvmAddress,
    amount: u128,
    nonce: [u8; 32],
    now_secs: u64,
    evm_tx: Option<&EvmTxParams>,
) -> Result<BuiltRequest, ContractError> {
    if evm_tx.is_some() {
        return Err(ContractError::EvmTxForbidden);
    }

    let valid_after = now_secs.saturating_sub(CLOCK_SKEW_SECS);
    let valid_before = valid_after + SWEEP_VALIDITY_SECS;

    let auth = Eip3009Authorization {
        from: from.clone(),
        to: sweep_config.safe_address.clone(),
        value: amount,
        valid_after,
        valid_before,
        nonce,
    };

    let domain = Eip712Domain {
        name: sweep_config.usdc_eip712_name.clone(),
        version: sweep_config.usdc_eip712_version.clone(),
        chain_id: sweep_config.chain_id,
        verifying_contract: sweep_config.usdc_address.clone(),
    };

    let digest = eip3009_digest(&domain, &auth);

    let payload = SignedPayload::Eip3009 {
        asset: sweep_config.usdc_address.clone(),
        chain_id: sweep_config.chain_id,
        from: from.clone(),
        to: sweep_config.safe_address.clone(),
        value: U128(amount),
        valid_after,
        valid_before,
        nonce: format!("0x{}", hex::encode(nonce)),
    };

    Ok(BuiltRequest {
        digest,
        payload,
        rail: None,
        amount: 0,
        valid_before,
        release_after: valid_before,
    })
}

fn build_eure_sweep(
    sweep_config: &SweepConfig,
    amount: u128,
    evm_tx: Option<&EvmTxParams>,
) -> Result<BuiltRequest, ContractError> {
    let tx = evm_tx.ok_or(ContractError::EvmTxRequired)?;

    if tx.gas_limit > MAX_SWEEP_GAS_LIMIT {
        return Err(ContractError::InvalidEvmTx);
    }
    if tx.max_fee_per_gas.0 > MAX_SWEEP_FEE_PER_GAS {
        return Err(ContractError::InvalidEvmTx);
    }
    if tx.max_priority_fee_per_gas.0 > tx.max_fee_per_gas.0 {
        return Err(ContractError::InvalidEvmTx);
    }

    let token_bytes = address_bytes(&sweep_config.eure_address)?;
    let safe_padded = address_word(&sweep_config.safe_address);
    let amount_padded = word(amount);

    let mut data = Vec::with_capacity(4 + 32 + 32);
    data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    data.extend_from_slice(&safe_padded);
    data.extend_from_slice(&amount_padded);

    let items: [Vec<u8>; 9] = [
        rlp_encode_u64(sweep_config.chain_id),
        rlp_encode_u64(tx.nonce),
        rlp_encode_u128(tx.max_priority_fee_per_gas.0),
        rlp_encode_u128(tx.max_fee_per_gas.0),
        rlp_encode_u64(tx.gas_limit),
        rlp_encode_bytes(&token_bytes),
        rlp_encode_u128(0),
        rlp_encode_bytes(&data),
        vec![0xc0],
    ];

    let rlp_tx = rlp_encode_list(&items);

    let mut preimage = Vec::with_capacity(1 + rlp_tx.len());
    preimage.push(0x02);
    preimage.extend_from_slice(&rlp_tx);
    let digest = env::keccak256_array(&preimage);

    let payload = SignedPayload::Eip1559Tx {
        chain_id: sweep_config.chain_id,
        nonce: tx.nonce,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
        max_fee_per_gas: tx.max_fee_per_gas,
        gas_limit: tx.gas_limit,
        to: sweep_config.eure_address.clone(),
        value: U128(0),
        data: format!("0x{}", hex::encode(&data)),
    };

    Ok(BuiltRequest {
        digest,
        payload,
        rail: None,
        amount: 0,
        valid_before: 0,
        release_after: 0,
    })
}

fn rlp_encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let be = value.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let data = &be[start..];
    if data.len() == 1 && data[0] < 0x80 {
        vec![data[0]]
    } else {
        let mut out = vec![0x80 + data.len() as u8];
        out.extend_from_slice(data);
        out
    }
}

fn rlp_encode_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let be = value.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
    let data = &be[start..];
    if data.len() == 1 && data[0] < 0x80 {
        vec![data[0]]
    } else {
        let mut out = vec![0x80 + data.len() as u8];
        out.extend_from_slice(data);
        out
    }
}

fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return vec![data[0]];
    }
    if data.len() <= 55 {
        let mut out = vec![0x80 + data.len() as u8];
        out.extend_from_slice(data);
        out
    } else {
        let len_be = data.len().to_be_bytes();
        let start = len_be
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(len_be.len() - 1);
        let len_bytes = &len_be[start..];
        let mut out = vec![0xb7 + len_bytes.len() as u8];
        out.extend_from_slice(len_bytes);
        out.extend_from_slice(data);
        out
    }
}

fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let mut concat = Vec::new();
    for item in items {
        concat.extend_from_slice(item);
    }
    if concat.len() <= 55 {
        let mut out = vec![0xc0 + concat.len() as u8];
        out.extend_from_slice(&concat);
        out
    } else {
        let len_be = concat.len().to_be_bytes();
        let start = len_be
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(len_be.len() - 1);
        let len_bytes = &len_be[start..];
        let mut out = vec![0xf7 + len_bytes.len() as u8];
        out.extend_from_slice(len_bytes);
        out.extend_from_slice(&concat);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FROM: &str = "0xbbc0320e02d371a71f18a40b7b15404df218d880";

    fn record(cfg: &SweepConfig) -> AgentRecord {
        AgentRecord {
            agent: "a1".to_string(),
            public_key: None,
            sweep_config: cfg.clone(),
            evm_address: Some(FROM.to_string()),
            linked: false,
            revoked: false,
        }
    }

    fn test_sweep_config() -> SweepConfig {
        SweepConfig {
            safe_address: "0x5afe000000000000000000000000000000000001".into(),
            usdc_address: "0x036cbd53842c5426634e7929541ec2318f3dcf7e".into(),
            eure_address: "0x29f37f6adca168b79b8d9567eab9be3fbf21db85".into(),
            chain_id: 84532,
            usdc_eip712_name: "USDC".into(),
            usdc_eip712_version: "2".into(),
        }
    }

    #[test]
    fn usdc_sweep_ok() {
        let cfg = test_sweep_config();
        let nonce = [0xab; 32];
        let r = build_sweep(
            &record(&cfg),
            Token::Usdc,
            19990000,
            None,
            nonce,
            1793555521,
        );
        assert!(r.is_ok());
    }

    #[test]
    fn usdc_sweep_rejects_evm_tx() {
        let cfg = test_sweep_config();
        let tx = EvmTxParams {
            nonce: 0,
            gas_limit: 80000,
            max_fee_per_gas: U128(2_000_000_000),
            max_priority_fee_per_gas: U128(1_000_000),
        };
        let r = build_sweep(
            &record(&cfg),
            Token::Usdc,
            19990000,
            Some(&tx),
            [0xab; 32],
            1793555521,
        );
        assert_eq!(r, Err(ContractError::EvmTxForbidden));
    }

    #[test]
    fn eure_sweep_requires_evm_tx() {
        let cfg = test_sweep_config();
        let r = build_sweep(
            &record(&cfg),
            Token::Eure,
            10_000_000_000_000_000_000u128,
            None,
            [0; 32],
            0,
        );
        assert_eq!(r, Err(ContractError::EvmTxRequired));
    }

    #[test]
    fn eure_sweep_rejects_high_gas_limit() {
        let cfg = test_sweep_config();
        let tx = EvmTxParams {
            nonce: 0,
            gas_limit: MAX_SWEEP_GAS_LIMIT + 1,
            max_fee_per_gas: U128(2_000_000_000),
            max_priority_fee_per_gas: U128(1_000_000),
        };
        let r = build_sweep(
            &record(&cfg),
            Token::Eure,
            10_000_000_000_000_000_000u128,
            Some(&tx),
            [0; 32],
            0,
        );
        assert_eq!(r, Err(ContractError::InvalidEvmTx));
    }

    #[test]
    fn eure_sweep_rejects_priority_fee_over_max() {
        let cfg = test_sweep_config();
        let tx = EvmTxParams {
            nonce: 0,
            gas_limit: 80000,
            max_fee_per_gas: U128(1_000_000_000),
            max_priority_fee_per_gas: U128(2_000_000_000),
        };
        let r = build_sweep(
            &record(&cfg),
            Token::Eure,
            10_000_000_000_000_000_000u128,
            Some(&tx),
            [0; 32],
            0,
        );
        assert_eq!(r, Err(ContractError::InvalidEvmTx));
    }

    #[test]
    fn eure_sweep_digest_matches_reservation_example() {
        let cfg = SweepConfig {
            safe_address: "0x5afe000000000000000000000000000000000001".into(),
            usdc_address: "0x0000000000000000000000000000000000000000".into(),
            eure_address: "0x29f37f6adca168b79b8d9567eab9be3fbf21db85".into(),
            chain_id: 84532,
            usdc_eip712_name: "USDC".into(),
            usdc_eip712_version: "2".into(),
        };
        let tx = EvmTxParams {
            nonce: 0,
            gas_limit: 80000,
            max_fee_per_gas: U128(2_000_000_000),
            max_priority_fee_per_gas: U128(1_000_000),
        };
        let r = build_sweep(
            &record(&cfg),
            Token::Eure,
            10_000_000_000_000_000_000u128,
            Some(&tx),
            [0; 32],
            0,
        )
        .unwrap();
        // Expected digest from interfaces.md reservation:sweep_eure example
        assert_eq!(
            hex::encode(r.digest),
            "2d7d3f98d690daa7f5305927d06b2a2b577de2dc0f911e74722703abe95ff378"
        );
    }

    #[test]
    fn usdc_sweep_validity_uses_fixed_window() {
        let cfg = test_sweep_config();
        let r = build_sweep(
            &record(&cfg),
            Token::Usdc,
            19990000,
            None,
            [0; 32],
            1_000_000,
        )
        .unwrap();
        let valid_after = match &r.payload {
            SignedPayload::Eip3009 { valid_after, .. } => *valid_after,
            _ => panic!("not eip3009"),
        };
        assert_eq!(r.valid_before - valid_after, SWEEP_VALIDITY_SECS);
    }

    #[test]
    fn usdc_sweep_to_is_safe_address() {
        let cfg = test_sweep_config();
        let r = build_sweep(
            &record(&cfg),
            Token::Usdc,
            19990000,
            None,
            [0; 32],
            1_000_000,
        )
        .unwrap();
        match &r.payload {
            SignedPayload::Eip3009 { to, .. } => assert_eq!(to, &cfg.safe_address),
            _ => panic!("expected Eip3009 payload"),
        }
    }

    #[test]
    fn eure_sweep_payload_is_eip1559_tx() {
        let cfg = test_sweep_config();
        let tx = EvmTxParams {
            nonce: 7,
            gas_limit: 80000,
            max_fee_per_gas: U128(2_000_000_000),
            max_priority_fee_per_gas: U128(1_000_000),
        };
        let r = build_sweep(
            &record(&cfg),
            Token::Eure,
            10_000_000_000_000_000_000u128,
            Some(&tx),
            [0; 32],
            0,
        )
        .unwrap();
        match &r.payload {
            SignedPayload::Eip1559Tx {
                chain_id,
                nonce,
                to,
                value,
                ..
            } => {
                assert_eq!(*chain_id, cfg.chain_id);
                assert_eq!(*nonce, 7);
                assert_eq!(to, &cfg.eure_address);
                assert_eq!(*value, U128(0));
            }
            _ => panic!("expected Eip1559Tx payload"),
        }
    }

    #[test]
    fn rejects_wrong_chain_id() {
        let mut cfg = test_sweep_config();
        cfg.chain_id = 1;
        let r = build_sweep(&record(&cfg), Token::Usdc, 100, None, [0; 32], 0);
        assert_eq!(r, Err(ContractError::WrongNetwork));
    }

    #[test]
    fn eure_sweep_calldata_to_is_safe_address() {
        let cfg = test_sweep_config();
        let tx = EvmTxParams {
            nonce: 0,
            gas_limit: 80000,
            max_fee_per_gas: U128(2_000_000_000),
            max_priority_fee_per_gas: U128(1_000_000),
        };
        let r = build_sweep(
            &record(&cfg),
            Token::Eure,
            10_000_000_000_000_000_000u128,
            Some(&tx),
            [0; 32],
            0,
        )
        .unwrap();
        match &r.payload {
            SignedPayload::Eip1559Tx { data, .. } => {
                let raw = hex::decode(data.strip_prefix("0x").unwrap_or(data)).expect("hex data");
                assert!(raw.len() >= 4, "data too short");
                assert_eq!(
                    &raw[0..4],
                    &[0xa9, 0x05, 0x9c, 0xbb],
                    "expected transfer selector"
                );
                let recipient = &raw[16..36];
                let expected =
                    hex::decode(cfg.safe_address.strip_prefix("0x").unwrap()).expect("safe hex");
                assert_eq!(recipient, expected, "recipient does not match safe_address");
                let amount_bytes: [u8; 32] = raw[36..68].try_into().unwrap();
                assert_eq!(
                    u128::from_be_bytes(amount_bytes[16..32].try_into().unwrap()),
                    10_000_000_000_000_000_000u128
                );
            }
            _ => panic!("expected Eip1559Tx payload"),
        }
    }

    fn eure_tx(max_fee_per_gas: u128) -> EvmTxParams {
        EvmTxParams {
            nonce: 0,
            gas_limit: 80000,
            max_fee_per_gas: U128(max_fee_per_gas),
            max_priority_fee_per_gas: U128(1_000_000),
        }
    }

    #[test]
    fn eure_sweep_rejects_max_fee_over_cap() {
        let cfg = test_sweep_config();
        let tx = eure_tx(MAX_SWEEP_FEE_PER_GAS + 1);
        let r = build_sweep(&record(&cfg), Token::Eure, 1, Some(&tx), [0; 32], 0);
        assert_eq!(r, Err(ContractError::InvalidEvmTx));
    }

    #[test]
    fn eure_sweep_bad_eure_address_is_error_not_panic() {
        let mut cfg = test_sweep_config();
        cfg.eure_address = "0xzz000000000000000000000000000000000000zz".into();
        let tx = eure_tx(2_000_000_000);
        let r = std::panic::catch_unwind(|| {
            build_sweep(&record(&cfg), Token::Eure, 1, Some(&tx), [0; 32], 0)
        });
        assert_eq!(r.ok(), Some(Err(ContractError::InvalidAddress)));
    }

    #[test]
    fn usdc_sweep_bad_safe_address_is_error_not_panic() {
        let mut cfg = test_sweep_config();
        cfg.safe_address = "0x5afe".into();
        let r = std::panic::catch_unwind(|| {
            build_sweep(&record(&cfg), Token::Usdc, 1, None, [0; 32], 0)
        });
        assert_eq!(r.ok(), Some(Err(ContractError::InvalidAddress)));
    }

    #[test]
    fn usdc_sweep_digest_matches_independent_vector() {
        // viem 2 `hashTypedData` of TransferWithAuthorization with domain
        // {name: "USDC", version: "2", chainId: 84532, verifyingContract: usdc_address},
        // from/to/value as below, validAfter = now - 60, validBefore = validAfter + 300,
        // nonce = 0xab * 32.
        let cfg = test_sweep_config();
        let r = build_sweep(
            &record(&cfg),
            Token::Usdc,
            19990000,
            None,
            [0xab; 32],
            1793555521,
        )
        .unwrap();
        assert_eq!(
            hex::encode(r.digest),
            "2a42c2c61d2b556363c8bd47c92ba561383320b333036b198c6d85c4a79e8266"
        );
    }

    #[test]
    fn usdc_sweep_uses_sweep_config_domain() {
        // PP1: the digest follows the sweep config's EIP-712 name/version; USDC / 2 keeps
        // the vector above.
        let cfg = test_sweep_config();
        let digest = |cfg: &SweepConfig| {
            build_sweep(
                &record(cfg),
                Token::Usdc,
                19990000,
                None,
                [0xab; 32],
                1793555521,
            )
            .unwrap()
            .digest
        };
        let usdc = digest(&cfg);
        let mut pyusd = cfg.clone();
        pyusd.usdc_eip712_name = "PayPal USD".into();
        pyusd.usdc_eip712_version = "1".into();
        let r = build_sweep(
            &record(&pyusd),
            Token::Usdc,
            19990000,
            None,
            [0xab; 32],
            1793555521,
        )
        .unwrap();
        assert_ne!(r.digest, usdc);
        let domain = Eip712Domain {
            name: "PayPal USD".into(),
            version: "1".into(),
            chain_id: pyusd.chain_id,
            verifying_contract: pyusd.usdc_address.clone(),
        };
        let SignedPayload::Eip3009 {
            from,
            to,
            value,
            valid_after,
            valid_before,
            ..
        } = r.payload
        else {
            panic!("expected Eip3009 payload");
        };
        let auth = Eip3009Authorization {
            from,
            to,
            value: value.0,
            valid_after,
            valid_before,
            nonce: [0xab; 32],
        };
        assert_eq!(r.digest, eip3009_digest(&domain, &auth));
    }

    #[test]
    fn sweep_from_is_stored_evm_address() {
        let cfg = test_sweep_config();
        let r = build_sweep(&record(&cfg), Token::Usdc, 1, None, [0; 32], 0).unwrap();
        match &r.payload {
            SignedPayload::Eip3009 { from, .. } => assert_eq!(from, FROM),
            _ => panic!("expected Eip3009 payload"),
        }
    }

    #[test]
    fn sweep_without_stored_evm_address_is_error() {
        let mut rec = record(&test_sweep_config());
        rec.evm_address = None;
        let r = build_sweep(&rec, Token::Usdc, 1, None, [0; 32], 0);
        assert_eq!(r, Err(ContractError::InvalidAddress));
    }

    #[test]
    fn sweep_bad_stored_evm_address_is_error_not_panic() {
        let mut rec = record(&test_sweep_config());
        rec.evm_address = Some("0xbbc0".to_string());
        let r = std::panic::catch_unwind(|| build_sweep(&rec, Token::Usdc, 1, None, [0; 32], 0));
        assert_eq!(r.ok(), Some(Err(ContractError::InvalidAddress)));
    }

    #[test]
    fn eure_sweep_accepts_max_fee_at_cap() {
        let cfg = test_sweep_config();
        let r = build_sweep(
            &record(&cfg),
            Token::Eure,
            1,
            Some(&eure_tx(MAX_SWEEP_FEE_PER_GAS)),
            [0; 32],
            0,
        );
        assert!(r.is_ok());
    }

    #[test]
    fn rlp_encode_u64_edge_cases() {
        assert_eq!(rlp_encode_u64(0), vec![0x80]);
        assert_eq!(rlp_encode_u64(1), vec![0x01]);
        assert_eq!(rlp_encode_u64(127), vec![0x7f]);
        assert_eq!(rlp_encode_u64(128), vec![0x81, 0x80]);
        assert_eq!(rlp_encode_u64(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(
            rlp_encode_u64(0xffff_ffff_ffff_ffff),
            vec![0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn rlp_encode_u128_edge_cases() {
        assert_eq!(rlp_encode_u128(0), vec![0x80]);
        assert_eq!(rlp_encode_u128(1), vec![0x01]);
        assert_eq!(rlp_encode_u128(128), vec![0x81, 0x80]);
        let max_enc = rlp_encode_u128(u128::MAX);
        assert_eq!(max_enc.len(), 17);
        assert_eq!(max_enc[0], 0x90);
        assert_eq!(&max_enc[1..], &[0xff; 16]);
    }
}
