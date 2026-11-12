//! Owner authorization (docs/interfaces.md §2). In passkey mode every owner method carries a
//! WebAuthn assertion over a challenge that binds the contract, network, method, arguments,
//! `owner_nonce` and `expires_at`; in wallet mode the predecessor must be the owner account
//! and attach exactly 1 yoctoNEAR (proof of a full-access key), and no assertion may be sent.

use near_sdk::base64::engine::general_purpose::URL_SAFE_NO_PAD;
use near_sdk::base64::Engine;
use near_sdk::borsh::{self, BorshSerialize};
use near_sdk::serde::Deserialize;
use near_sdk::{env, serde_json, NearToken};

use crate::errors::ContractError;
use crate::types::{
    OwnerAssertion, OwnerMode, MAX_ASSERTION_TTL_SECS, MAX_OWNER_NONCE_STEP, OWNER_CHALLENGE_DOMAIN,
};
use crate::Contract;

/// Bit 0 of the authenticator-data flags byte: user present.
const FLAG_USER_PRESENT: u8 = 0x01;
/// rpIdHash (32) + flags (1) + signCount (4).
const MIN_AUTH_DATA_LEN: usize = 37;

/// `sha256("zold-mandate-v1" || contract_id || network || method || args || owner_nonce ||
/// expires_at)`, with `args` already borsh-encoded and both numbers as u64 LE.
pub fn owner_challenge(
    contract_id: &str,
    network: &str,
    method: &str,
    args: &[u8],
    owner_nonce: u64,
    expires_at: u64,
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(
        OWNER_CHALLENGE_DOMAIN.len()
            + contract_id.len()
            + network.len()
            + method.len()
            + args.len()
            + 16,
    );
    preimage.extend_from_slice(OWNER_CHALLENGE_DOMAIN);
    preimage.extend_from_slice(contract_id.as_bytes());
    preimage.extend_from_slice(network.as_bytes());
    preimage.extend_from_slice(method.as_bytes());
    preimage.extend_from_slice(args);
    preimage.extend_from_slice(&owner_nonce.to_le_bytes());
    preimage.extend_from_slice(&expires_at.to_le_bytes());
    env::sha256_array(&preimage)
}

/// The fields of `clientDataJSON` the contract checks; others (`crossOrigin`, ...) are ignored.
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
}

impl Contract {
    /// Authorizes an owner call or panics. `args` is the method's argument tuple without
    /// `assertion`, in parameter order. In passkey mode a passing assertion consumes its
    /// `owner_nonce`; if the call panics later, the whole call reverts and so does the nonce.
    pub(crate) fn assert_owner<A: BorshSerialize>(
        &mut self,
        method: &str,
        args: &A,
        assertion: Option<OwnerAssertion>,
    ) {
        match (&self.owner, assertion) {
            (OwnerMode::Wallet { .. }, Some(_)) => {
                ContractError::AssertionForbidden.panic("wallet mode takes no assertion")
            }
            (OwnerMode::Wallet { account }, None) => {
                if env::predecessor_account_id() != *account {
                    ContractError::NotOwner.panic("predecessor is not the owner account");
                }
                // A function-call key cannot attach a deposit, so 1 yoctoNEAR proves the
                // owner's full-access key signed (a dashboard sign-in key cannot act as owner).
                if env::attached_deposit() != NearToken::from_yoctonear(1) {
                    ContractError::NotOwner.panic("wallet owner must attach exactly 1 yoctoNEAR");
                }
            }
            (OwnerMode::Passkey { .. }, None) => {
                ContractError::AssertionRequired.panic("passkey mode needs an assertion")
            }
            (
                OwnerMode::Passkey {
                    public_key,
                    rp_id,
                    origin,
                },
                Some(a),
            ) => {
                let args = borsh::to_vec(args)
                    .unwrap_or_else(|_| ContractError::AssertionMalformed.panic("args"));
                verify_assertion(
                    &a,
                    &public_key.0,
                    rp_id,
                    origin,
                    &self.network,
                    method,
                    &args,
                    self.owner_nonce,
                );
                self.owner_nonce = a.owner_nonce;
            }
        }
    }
}

/// The checks of docs/interfaces.md §2, in that order.
#[allow(clippy::too_many_arguments)]
fn verify_assertion(
    a: &OwnerAssertion,
    public_key: &[u8],
    rp_id: &str,
    origin: &str,
    network: &str,
    method: &str,
    args: &[u8],
    last_nonce: u64,
) {
    // 1. type
    let client_data: ClientData = serde_json::from_str(&a.client_data_json)
        .unwrap_or_else(|_| ContractError::AssertionMalformed.panic("client_data_json"));
    if client_data.kind != "webauthn.get" {
        ContractError::AssertionBadType.panic("client_data_json.type");
    }

    // 2. challenge. Comparing against the canonical unpadded base64url encoding is strict:
    // padding, standard-alphabet characters and non-zero trailing bits all fail.
    let expected = owner_challenge(
        env::current_account_id().as_str(),
        network,
        method,
        args,
        a.owner_nonce,
        a.expires_at,
    );
    if client_data.challenge != URL_SAFE_NO_PAD.encode(expected) {
        ContractError::AssertionBadChallenge.panic("client_data_json.challenge");
    }

    // 3. origin, byte for byte (scheme and port included).
    if client_data.origin != origin {
        ContractError::AssertionBadOrigin.panic("client_data_json.origin");
    }

    // 4. rpIdHash
    let auth_data = &a.authenticator_data.0;
    if auth_data.len() < MIN_AUTH_DATA_LEN {
        ContractError::AssertionMalformed.panic("authenticator_data length");
    }
    if auth_data[..32] != env::sha256_array(rp_id.as_bytes()) {
        ContractError::AssertionBadRpIdHash.panic("authenticator_data.rp_id_hash");
    }

    // 5. user presence. signCount is never read (synced passkeys report 0).
    if auth_data[32] & FLAG_USER_PRESENT == 0 {
        ContractError::AssertionNoUserPresence.panic("authenticator_data.flags.up");
    }

    // 6. nonce: greater than the stored one, by at most MAX_OWNER_NONCE_STEP (so the owner
    // cannot lock themselves out by jumping to u64::MAX).
    if a.owner_nonce <= last_nonce {
        ContractError::AssertionStaleNonce.panic(&format!(
            "owner_nonce {} must be greater than {}",
            a.owner_nonce, last_nonce
        ));
    }
    if a.owner_nonce - last_nonce > MAX_OWNER_NONCE_STEP {
        ContractError::AssertionStaleNonce.panic(&format!(
            "owner_nonce {} is more than {MAX_OWNER_NONCE_STEP} past {}",
            a.owner_nonce, last_nonce
        ));
    }

    // 7. expiry
    let now = env::block_timestamp() / 1_000_000_000;
    if a.expires_at <= now {
        ContractError::AssertionExpired.panic("expires_at");
    }
    if a.expires_at > now + MAX_ASSERTION_TTL_SECS {
        ContractError::AssertionTtlTooLong.panic("expires_at");
    }

    // 8. signature over sha256(authData || sha256(clientDataJSON)). Either S form passes.
    let signature: &[u8; 64] = a.signature.0.as_slice().try_into().unwrap_or_else(|_| {
        ContractError::AssertionMalformed.panic("signature must be 64 bytes r||s")
    });
    let public_key: &[u8; 33] = public_key
        .try_into()
        .unwrap_or_else(|_| ContractError::AssertionMalformed.panic("owner public_key"));
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&env::sha256_array(a.client_data_json.as_bytes()));
    if !env::p256_verify(signature, &env::sha256_array(&signed), public_key) {
        ContractError::AssertionBadSignature.panic("signature");
    }
}
