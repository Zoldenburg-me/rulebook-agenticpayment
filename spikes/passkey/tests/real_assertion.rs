//! A REAL passkey assertion (captured by page/ into fixtures/assertion.json) verified
//! on-chain with `env::p256_verify` in the near-workspaces sandbox.
//!
//! Run: `cargo test --test real_assertion` (or set PASSKEY_FIXTURE to another file).

mod common;

use common::*;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn field<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str().unwrap_or_else(|| panic!("fixture field `{k}` missing"))
}

struct Fixture {
    rp_id: String,
    origin: String,
    public_key: [u8; 33],
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: [u8; 64],
}

/// Loads the browser's blob and converts it to the contract's encoding
/// (SPKI -> compressed key, DER -> raw r||s). `None` if the fixture file is absent:
/// the real assertion is kept local (untracked), so CI and fresh clones skip.
fn load() -> Option<Fixture> {
    let path = std::env::var("PASSKEY_FIXTURE")
        .unwrap_or_else(|_| "fixtures/assertion.json".to_string());
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("{path}: {e}"),
    };
    let fx: Value = serde_json::from_str(&raw).expect("fixture JSON");
    Some(Fixture {
        rp_id: field(&fx, "rpId").to_string(),
        origin: field(&fx, "origin").to_string(),
        public_key: spki_to_compressed(&from_b64url(field(&fx, "publicKeySpki"))),
        authenticator_data: from_b64url(field(&fx, "authenticatorData")),
        client_data_json: from_b64url(field(&fx, "clientDataJSON")),
        signature: der_to_raw(&from_b64url(field(&fx, "signature"))),
    })
}

const SKIPPED: &str = "skipped: no real assertion fixture; see RESULT.md";

/// Writes the contract-call args for testnet.sh.
/// Run: `cargo test --test real_assertion -- --ignored write_contract_args`
#[test]
#[ignore]
fn write_contract_args() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let Some(f) = load() else {
        println!("{SKIPPED}");
        return;
    };
    let v = serde_json::json!({
        "public_key": STANDARD.encode(f.public_key),
        "authenticator_data": STANDARD.encode(&f.authenticator_data),
        "client_data_json": STANDARD.encode(&f.client_data_json),
        "signature": STANDARD.encode(f.signature),
    });
    std::fs::write("fixtures/assertion-contract-args.json", format!("{v:#}\n")).unwrap();
}

#[tokio::test]
async fn real_passkey_assertion_verifies_on_chain() -> anyhow::Result<()> {
    let Some(Fixture { rp_id, origin, public_key, authenticator_data, client_data_json, signature }) =
        load()
    else {
        println!("{SKIPPED}");
        return Ok(());
    };
    let (rp_id, origin) = (rp_id.as_str(), origin.as_str());

    // What C2's assert_owner will check off the signature, checked here off-chain.
    let cd: Value = serde_json::from_slice(&client_data_json)?;
    assert_eq!(cd["type"], "webauthn.get");
    assert_eq!(cd["challenge"], b64url(&Sha256::digest(CHALLENGE_TAG)));
    assert_eq!(cd["origin"], origin);
    assert_eq!(authenticator_data[..32], Sha256::digest(rp_id.as_bytes())[..], "rpIdHash");
    assert_eq!(authenticator_data[32] & 0x01, 0x01, "user-present flag");

    let (_worker, contract) = deploy().await?;
    assert!(
        verify(&contract, &public_key, &authenticator_data, &client_data_json, &signature).await?,
        "real assertion must verify on-chain"
    );

    let mut tampered = client_data_json.clone();
    *tampered.last_mut().unwrap() ^= 0x01;
    assert!(
        !verify(&contract, &public_key, &authenticator_data, &tampered, &signature).await?,
        "tampered clientDataJSON must not verify"
    );

    println!(
        "real assertion OK: rpId={rp_id} origin={origin} flags=0x{:02x} low_s={}",
        authenticator_data[32],
        signature[32..] <= flip_s(&signature)[32..]
    );
    Ok(())
}
