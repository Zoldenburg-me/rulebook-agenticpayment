#![allow(dead_code)]

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use near_workspaces::{network::Sandbox, Contract, Worker};
use p256::ecdsa::Signature;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use serde_json::json;

/// The fixed test challenge the page asks the passkey to sign: sha256 of this tag.
pub const CHALLENGE_TAG: &[u8] = b"zold-mandate-v1 S-h spike test challenge";

/// DER `SubjectPublicKeyInfo` prefix for an uncompressed P-256 key (id-ecPublicKey, prime256v1).
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

pub async fn deploy() -> anyhow::Result<(Worker<Sandbox>, Contract)> {
    let wasm = near_workspaces::compile_project("./").await?;
    let worker = near_workspaces::sandbox().await?;
    let contract = worker.dev_deploy(&wasm).await?;
    Ok((worker, contract))
}

/// Calls the view; returns what the contract said.
pub async fn verify(
    contract: &Contract,
    public_key: &[u8],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    signature: &[u8],
) -> anyhow::Result<bool> {
    Ok(contract
        .view("verify_webauthn")
        .args_json(json!({
            "public_key": STANDARD.encode(public_key),
            "authenticator_data": STANDARD.encode(authenticator_data),
            "client_data_json": STANDARD.encode(client_data_json),
            "signature": STANDARD.encode(signature),
        }))
        .await?
        .json()?)
}

/// Browser signatures are ASN.1 DER; the contract wants raw `r || s`.
pub fn der_to_raw(der: &[u8]) -> [u8; 64] {
    Signature::from_der(der).expect("DER ECDSA signature").to_bytes().into()
}

/// 65-byte uncompressed (or 33-byte compressed) SEC1 point -> 33-byte compressed.
pub fn compress(sec1: &[u8]) -> [u8; 33] {
    let pk = PublicKey::from_sec1_bytes(sec1).expect("valid P-256 point");
    pk.to_encoded_point(true).as_bytes().try_into().unwrap()
}

/// `PublicKeyCredential.response.getPublicKey()` returns SPKI DER; take the point out.
pub fn spki_to_compressed(spki: &[u8]) -> [u8; 33] {
    assert_eq!(spki.len(), 91, "expected a P-256 SPKI (91 bytes)");
    assert_eq!(spki[..26], P256_SPKI_PREFIX, "not a P-256 SPKI");
    compress(&spki[26..])
}

/// `s -> n - s`: the other, equally valid ECDSA signature for the same message.
pub fn flip_s(raw: &[u8; 64]) -> [u8; 64] {
    let sig = Signature::from_slice(raw).unwrap();
    let flipped = Signature::from_scalars(sig.r(), -*sig.s()).unwrap();
    flipped.to_bytes().into()
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn from_b64url(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .expect("base64url")
}
