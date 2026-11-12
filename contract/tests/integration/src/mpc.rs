//! The mock MPC's key, held off chain: derives the per-(predecessor, path) key the way
//! v1.signer does (spikes/chainsig), signs a payload into the real response JSON, and
//! recovers EVM addresses from stored signatures.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::ops::Reduce;
use k256::{NonZeroScalar, Scalar, U256};
use mandate::types::EvmSignature;
use sha3::{Digest, Keccak256, Sha3_256};

/// Root secret of the mock MPC. Test-only, sandbox only.
pub const MOCK_ROOT_SECRET: [u8; 32] = [0x42; 32];
const EPSILON_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";

/// `epsilon = sha3_256(prefix || predecessor || "," || path)` as a big-endian scalar.
fn epsilon(predecessor: &str, path: &str) -> Scalar {
    let hash = Sha3_256::digest(format!("{EPSILON_PREFIX}{predecessor},{path}"));
    <Scalar as Reduce<U256>>::reduce_bytes(&hash)
}

/// The derived signing key `root + epsilon`.
pub fn derived_key(predecessor: &str, path: &str) -> SigningKey {
    let root = NonZeroScalar::try_from(&MOCK_ROOT_SECRET[..]).expect("valid root scalar");
    let sk = NonZeroScalar::new(*root + epsilon(predecessor, path)).expect("non-zero key");
    SigningKey::from(sk)
}

/// `0x` + the last 20 bytes of `keccak256(x || y)`, lowercase.
pub fn address_of(key: &VerifyingKey) -> String {
    let point = key.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

/// The EVM address the mock MPC signs for on (predecessor, path).
pub fn derived_address(predecessor: &str, path: &str) -> String {
    address_of(derived_key(predecessor, path).verifying_key())
}

/// The response `sign` returns, in the real format:
/// `{"scheme":"Secp256k1","big_r":{"affine_point":"02|03"+x},"s":{"scalar":hex},"recovery_id":0|1}`.
pub fn sign_response(predecessor: &str, path: &str, payload: &[u8; 32]) -> String {
    let key = derived_key(predecessor, path);
    let (sig, recid) = key
        .sign_prehash_recoverable(payload)
        .expect("prehash signing");
    let (r, s) = sig.split_bytes();
    // The R that pairs with the (low-s) signature. The contract ignores the prefix and takes
    // v from recovery_id, as with the real MPC.
    let prefix = if recid.is_y_odd() { "03" } else { "02" };
    format!(
        r#"{{"scheme":"Secp256k1","big_r":{{"affine_point":"{prefix}{}"}},"s":{{"scalar":"{}"}},"recovery_id":{}}}"#,
        hex::encode(r),
        hex::encode(s),
        recid.to_byte()
    )
}

/// The address that signed `digest` (32 bytes, `0x` hex) with the stored signature.
pub fn recover_address(digest: &str, sig: &EvmSignature) -> anyhow::Result<String> {
    let digest = hex::decode(digest.trim_start_matches("0x"))?;
    let r = hex::decode(sig.r.trim_start_matches("0x"))?;
    let s = hex::decode(sig.s.trim_start_matches("0x"))?;
    let signature = Signature::from_scalars(
        <[u8; 32]>::try_from(r.as_slice())?,
        <[u8; 32]>::try_from(s.as_slice())?,
    )?;
    let recid = RecoveryId::from_byte(sig.v.wrapping_sub(27))
        .ok_or_else(|| anyhow::anyhow!("v must be 27 or 28, got {}", sig.v))?;
    let key = VerifyingKey::recover_from_prehash(&digest, &signature, recid)?;
    Ok(address_of(&key))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mock's response parses with the contract's own parser and recovers to the
    /// derived address of its (predecessor, path), and only that one.
    #[test]
    fn response_recovers_to_the_derived_address() {
        let payload = [7u8; 32];
        let response = sign_response("mandate.test.near", "agent-a", &payload);
        let sig = mandate::request::parse_mpc_response(response.as_bytes()).expect("parses");
        let digest = format!("0x{}", hex::encode(payload));
        let recovered = recover_address(&digest, &sig).unwrap();
        assert_eq!(recovered, derived_address("mandate.test.near", "agent-a"));
        assert_ne!(recovered, derived_address("mandate.test.near", "agent-b"));
        assert_ne!(recovered, derived_address("other.test.near", "agent-a"));
    }
}
