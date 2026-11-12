//! A software P-256 key signs exactly what a WebAuthn authenticator signs; the
//! contract verifies it with `env::p256_verify` in the near-workspaces sandbox.

mod common;

use common::*;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;
use sha2::{Digest, Sha256};

const RP_ID: &str = "localhost";
const ORIGIN: &str = "https://localhost:8443";

struct Assertion {
    public_key: [u8; 33],
    authenticator_data: Vec<u8>,
    client_data_json: Vec<u8>,
    signature: [u8; 64],
}

fn software_assertion() -> Assertion {
    let key = SigningKey::random(&mut OsRng);
    let public_key: [u8; 33] = key
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();

    // authenticatorData = rpIdHash (32) || flags (UP|UV) || signCount (4, big-endian)
    let mut authenticator_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
    authenticator_data.push(0x05);
    authenticator_data.extend_from_slice(&0u32.to_be_bytes());

    let challenge = Sha256::digest(CHALLENGE_TAG);
    let client_data_json = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
        b64url(&challenge)
    )
    .into_bytes();

    // The authenticator signs authData || sha256(clientDataJSON) with ES256 (SHA-256 inside).
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data_json));
    let sig: Signature = key.sign(&signed);

    // Go through DER the way a browser hands it over.
    let signature = der_to_raw(sig.to_der().as_bytes());

    Assertion { public_key, authenticator_data, client_data_json, signature }
}

/// Writes one software-key vector (public key and signature only) for testnet.sh.
/// Run: `cargo test --test software_key -- --ignored write_software_vector`
#[test]
#[ignore]
fn write_software_vector() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let a = software_assertion();
    let v = serde_json::json!({
        "public_key": STANDARD.encode(a.public_key),
        "authenticator_data": STANDARD.encode(&a.authenticator_data),
        "client_data_json": STANDARD.encode(&a.client_data_json),
        "signature": STANDARD.encode(a.signature),
    });
    std::fs::write("fixtures/software-vector.json", format!("{v:#}\n")).unwrap();
}

#[tokio::test]
async fn software_key_assertion_verifies_on_chain() -> anyhow::Result<()> {
    let (_worker, contract) = deploy().await?;
    let a = software_assertion();

    assert!(
        verify(&contract, &a.public_key, &a.authenticator_data, &a.client_data_json, &a.signature)
            .await?,
        "valid assertion must verify"
    );

    // p256_verify accepts high-S as well; authenticators do not normalise S, so the
    // contract must not demand low-S (replay protection is the owner nonce, not the sig).
    let flipped = flip_s(&a.signature);
    assert!(
        verify(&contract, &a.public_key, &a.authenticator_data, &a.client_data_json, &flipped)
            .await?,
        "the (r, n - s) twin must verify too"
    );

    // Tampered authenticatorData (e.g. UP flag cleared).
    let mut ad = a.authenticator_data.clone();
    ad[32] ^= 0x01;
    assert!(!verify(&contract, &a.public_key, &ad, &a.client_data_json, &a.signature).await?);

    // Tampered clientDataJSON (different challenge).
    let mut cdj = a.client_data_json.clone();
    let i = cdj.iter().position(|&b| b == b'"').unwrap() + 30;
    cdj[i] ^= 0x01;
    assert!(!verify(&contract, &a.public_key, &a.authenticator_data, &cdj, &a.signature).await?);

    // A different key.
    let other = software_assertion();
    assert!(
        !verify(&contract, &other.public_key, &a.authenticator_data, &a.client_data_json, &a.signature)
            .await?
    );

    // Encodings the contract does not take: DER signature, uncompressed key.
    let der = Signature::from_slice(&a.signature).unwrap().to_der();
    assert!(
        !verify(&contract, &a.public_key, &a.authenticator_data, &a.client_data_json, der.as_bytes())
            .await?
    );
    let uncompressed = p256::PublicKey::from_sec1_bytes(&a.public_key)
        .unwrap()
        .to_encoded_point(false);
    assert!(
        !verify(&contract, uncompressed.as_bytes(), &a.authenticator_data, &a.client_data_json, &a.signature)
            .await?
    );
    Ok(())
}
