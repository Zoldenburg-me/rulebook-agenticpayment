//! One builder per shape. Each takes decoded fields, runs that shape's checks and returns
//! the digest the contract sends to the MPC; nothing is signed blind. Budget reservation
//! and request dedupe are not here; they live in the request pipeline (C3).
//!
//! The shared helpers below are stubs; whichever shape task needs one first implements
//! it here (C4 or C5 for EIP-3009, C6 or C7 for EIP-191).

use near_sdk::{borsh, env};

use crate::errors::ContractError;
use crate::types::{EvmAddress, Rail, RequestKey, ShapeKind, SignedPayload};

pub mod link;
pub mod payout;
pub mod paypal;
pub mod paypal_checkout;
pub mod refund;
pub mod sweep;
pub mod x402;

/// A shape's output: what to sign and what to reserve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltRequest {
    /// The 32 bytes sent to the MPC `sign` call as `payload_v2.Ecdsa`.
    pub digest: [u8; 32],
    pub payload: SignedPayload,
    /// `None` for sweeps and the link (they count against no budget, D8).
    pub rail: Option<Rail>,
    /// Base units to reserve on `rail`.
    pub amount: u128,
    /// Unix seconds; 0 when nothing on chain expires it (link, EURe raw tx).
    pub valid_before: u64,
    /// Unix seconds; `Reservation::release_after`.
    pub release_after: u64,
}

/// EIP-712 domain of an EIP-3009 token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eip712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: EvmAddress,
}

/// Fields of `TransferWithAuthorization(address from,address to,uint256 value,uint256
/// validAfter,uint256 validBefore,bytes32 nonce)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Eip3009Authorization {
    pub from: EvmAddress,
    pub to: EvmAddress,
    pub value: u128,
    pub valid_after: u64,
    pub valid_before: u64,
    pub nonce: [u8; 32],
}

/// EIP-3009 nonce for shapes 1 and 2 (D3):
/// `keccak256(borsh((agent: String, caller: Caller, shape.tag(): u8, request_id: String)))`.
pub fn eip3009_nonce(key: &RequestKey, shape: ShapeKind) -> [u8; 32] {
    let preimage = borsh::to_vec(&(&key.agent, &key.caller, shape.tag(), &key.request_id))
        .unwrap_or_else(|_| env::panic_str("borsh nonce preimage"));
    env::keccak256_array(&preimage)
}

const EIP712_DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
const TRANSFER_WITH_AUTHORIZATION_TYPE: &[u8] = b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

/// `keccak256(0x1901 || domainSeparator || structHash)`. Must reproduce the S-c digest.
/// Addresses must be `0x` plus 40 hex digits (`ERR_INVALID_ADDRESS` otherwise); callers
/// pass only addresses the contract has already validated.
pub fn eip3009_digest(domain: &Eip712Domain, auth: &Eip3009Authorization) -> [u8; 32] {
    let mut buf = Vec::with_capacity(7 * 32);
    buf.extend_from_slice(&env::keccak256_array(EIP712_DOMAIN_TYPE));
    buf.extend_from_slice(&env::keccak256_array(domain.name.as_bytes()));
    buf.extend_from_slice(&env::keccak256_array(domain.version.as_bytes()));
    buf.extend_from_slice(&word(domain.chain_id.into()));
    buf.extend_from_slice(&address_word(&domain.verifying_contract));
    let domain_separator = env::keccak256_array(&buf);

    buf.clear();
    buf.extend_from_slice(&env::keccak256_array(TRANSFER_WITH_AUTHORIZATION_TYPE));
    buf.extend_from_slice(&address_word(&auth.from));
    buf.extend_from_slice(&address_word(&auth.to));
    buf.extend_from_slice(&word(auth.value));
    buf.extend_from_slice(&word(auth.valid_after.into()));
    buf.extend_from_slice(&word(auth.valid_before.into()));
    buf.extend_from_slice(&auth.nonce);
    let struct_hash = env::keccak256_array(&buf);

    let mut msg = [0u8; 66];
    msg[..2].copy_from_slice(&[0x19, 0x01]);
    msg[2..34].copy_from_slice(&domain_separator);
    msg[34..].copy_from_slice(&struct_hash);
    env::keccak256_array(msg)
}

/// ABI `uint256` word, big-endian.
pub(crate) fn word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// The 20 bytes of `0x` plus 40 hex digits; `ERR_INVALID_ADDRESS` otherwise.
pub(crate) fn address_bytes(addr: &EvmAddress) -> Result<[u8; 20], ContractError> {
    let mut b = [0u8; 20];
    let hex_part = addr
        .strip_prefix("0x")
        .filter(|h| h.len() == 40)
        .ok_or(ContractError::InvalidAddress)?;
    hex::decode_to_slice(hex_part, &mut b).map_err(|_| ContractError::InvalidAddress)?;
    Ok(b)
}

/// ABI `address` word: 12 zero bytes, then the 20 address bytes. Panics
/// `ERR_INVALID_ADDRESS` on a malformed address; check with `address_bytes` first where a
/// builder must return an error instead.
pub(crate) fn address_word(addr: &EvmAddress) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&address_bytes(addr).unwrap_or_else(|e| e.panic(addr)));
    w
}

/// EIP-191 `personal_sign` hash: `keccak256("\x19Ethereum Signed Message:\n" || len || text)`.
pub fn eip191_digest(text: &str) -> [u8; 32] {
    let len_str = text.len().to_string();
    let mut preimage = Vec::with_capacity(2 + len_str.len() + text.len());
    preimage.extend_from_slice(b"\x19Ethereum Signed Message:\n");
    preimage.extend_from_slice(len_str.as_bytes());
    preimage.extend_from_slice(text.as_bytes());
    env::keccak256_array(&preimage)
}
