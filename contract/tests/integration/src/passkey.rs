//! Software P-256 owner key: signs exactly what a WebAuthn authenticator signs for an owner
//! call (docs/interfaces.md §2, spikes/passkey). The challenge is rebuilt here from the
//! spec, not taken from the contract crate, so the harness checks the contract against it.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use mandate::types::{OwnerAssertion, OwnerMode, OWNER_CHALLENGE_DOMAIN};
use near_sdk::json_types::Base64VecU8;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256};

pub const RP_ID: &str = "localhost";
pub const ORIGIN: &str = "https://localhost:8443";
/// authenticatorData flags: user present | user verified.
pub const FLAGS_UP_UV: u8 = 0x05;

/// `sha256("zold-mandate-v1" || contract_id || network || method || borsh(args) ||
/// owner_nonce u64 LE || expires_at u64 LE)`.
pub fn owner_challenge(
    contract_id: &str,
    network: &str,
    method: &str,
    args: &[u8],
    owner_nonce: u64,
    expires_at: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(OWNER_CHALLENGE_DOMAIN);
    h.update(contract_id.as_bytes());
    h.update(network.as_bytes());
    h.update(method.as_bytes());
    h.update(args);
    h.update(owner_nonce.to_le_bytes());
    h.update(expires_at.to_le_bytes());
    h.finalize().into()
}

/// A passkey held in software. Test-only key material, never used outside the sandbox.
pub struct Passkey {
    key: SigningKey,
}

impl Default for Passkey {
    fn default() -> Self {
        Self::from_seed([0x11; 32])
    }
}

impl Passkey {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_slice(&seed).expect("valid P-256 scalar"),
        }
    }

    /// 33-byte compressed SEC1 public key.
    pub fn public_key(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// `OwnerMode::Passkey` for `new`.
    pub fn owner_mode(&self) -> OwnerMode {
        OwnerMode::Passkey {
            public_key: Base64VecU8(self.public_key()),
            rp_id: RP_ID.into(),
            origin: ORIGIN.into(),
        }
    }

    /// An assertion for `method(args)` on `contract_id`. `args` is the borsh-encoded argument
    /// tuple without `assertion`, in parameter order.
    pub fn assert(
        &self,
        contract_id: &str,
        network: &str,
        method: &str,
        args: &[u8],
        owner_nonce: u64,
        expires_at: u64,
    ) -> OwnerAssertion {
        let challenge =
            owner_challenge(contract_id, network, method, args, owner_nonce, expires_at);
        let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        auth_data.push(FLAGS_UP_UV);
        auth_data.extend_from_slice(&0u32.to_be_bytes()); // signCount 0, as synced passkeys
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}","crossOrigin":false}}"#,
            URL_SAFE_NO_PAD.encode(challenge)
        );
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(client_data_json.as_bytes()));
        let sig: Signature = self.key.sign(&signed); // ES256: SHA-256 inside
        OwnerAssertion {
            authenticator_data: Base64VecU8(auth_data),
            client_data_json,
            signature: Base64VecU8(sig.to_bytes().to_vec()),
            owner_nonce,
            expires_at,
        }
    }
}
