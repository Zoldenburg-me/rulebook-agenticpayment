//! A fixed secp256k1 key standing in for the MPC's derived agent key in unit tests: the
//! fixtures register its EVM address as the agent's `evm_address`, and it signs digests into
//! the real `sign` response, so `on_signature`'s ecrecover check passes (SEC-4).

#![allow(dead_code)]

use near_sdk::env;
use secp256k1::{Message, Secp256k1, SecretKey};

fn secret(seed: u8) -> SecretKey {
    SecretKey::from_slice(&[seed; 32]).unwrap()
}

/// `0x` + the last 20 bytes of `keccak256(x || y)` of the key from `seed`, lowercase.
pub fn evm_address_of(seed: u8) -> String {
    let pk = secret(seed)
        .public_key(&Secp256k1::new())
        .serialize_uncompressed();
    format!("0x{}", hex::encode(&env::keccak256_array(&pk[1..])[12..]))
}

/// The agent EOA in the fixtures.
pub fn agent_evm() -> String {
    evm_address_of(0x42)
}

/// The `sign` response for `digest` (`0x` hex) from the key of `seed`, in the real format.
/// The `big_r` prefix is always `02`: the contract ignores it and takes `v` from
/// `recovery_id` (spikes/chainsig).
pub fn sign_response_with(seed: u8, digest: &str) -> Vec<u8> {
    let digest = hex::decode(digest.trim_start_matches("0x")).unwrap();
    let sig = Secp256k1::new()
        .sign_ecdsa_recoverable(&Message::from_slice(&digest).unwrap(), &secret(seed));
    let (recid, rs) = sig.serialize_compact();
    format!(
        r#"{{"scheme":"Secp256k1","big_r":{{"affine_point":"02{}"}},"s":{{"scalar":"{}"}},"recovery_id":{}}}"#,
        hex::encode(&rs[..32]),
        hex::encode(&rs[32..]),
        recid.to_i32()
    )
    .into_bytes()
}

/// The agent key's `sign` response for `digest`.
pub fn sign_response(digest: &str) -> Vec<u8> {
    sign_response_with(0x42, digest)
}
