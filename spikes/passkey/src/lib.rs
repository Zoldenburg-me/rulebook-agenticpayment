//! S-h spike: verify a WebAuthn (passkey) assertion on-chain with `env::p256_verify`.
//!
//! Only the signature check lives here. Parsing `clientDataJSON` (type, challenge,
//! origin), the rpIdHash and flags checks, and the owner nonce are C2's `assert_owner`.

use near_sdk::json_types::Base64VecU8;
use near_sdk::{env, near};

#[near(contract_state)]
#[derive(Default)]
pub struct Contract {}

#[near]
impl Contract {
    /// True if `signature` (raw `r || s`, 64 bytes) is a valid P-256 signature by
    /// `public_key` (33-byte compressed SEC1) over
    /// `sha256(authenticator_data || sha256(client_data_json))`, as WebAuthn signs it.
    /// Wrong lengths return false instead of panicking.
    pub fn verify_webauthn(
        &self,
        public_key: Base64VecU8,
        authenticator_data: Base64VecU8,
        client_data_json: Base64VecU8,
        signature: Base64VecU8,
    ) -> bool {
        let Ok(public_key) = <[u8; 33]>::try_from(public_key.0.as_slice()) else {
            return false;
        };
        let Ok(signature) = <[u8; 64]>::try_from(signature.0.as_slice()) else {
            return false;
        };
        let mut signed = authenticator_data.0;
        signed.extend_from_slice(&env::sha256_array(&client_data_json.0));
        env::p256_verify(&signature, &env::sha256_array(&signed), &public_key)
    }
}
