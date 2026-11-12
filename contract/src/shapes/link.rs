//! Owner-only: the Monerium link message for the agent EOA (C7). Only `link_agent` builds
//! it; `request_signature` refuses the `link` shape.

use super::{eip191_digest, BuiltRequest};
use crate::errors::ContractError;
use crate::types::SignedPayload;

pub const LINK_MESSAGE: &str = "I hereby declare that I am the address owner.";

/// Builds the EIP-191 digest of `LINK_MESSAGE`; refuses if the agent is already linked.
pub fn build_link(already_linked: bool) -> Result<BuiltRequest, ContractError> {
    if already_linked {
        return Err(ContractError::AlreadyLinked);
    }

    let digest = eip191_digest(LINK_MESSAGE);

    Ok(BuiltRequest {
        digest,
        payload: SignedPayload::Message {
            text: LINK_MESSAGE.to_string(),
        },
        rail: None,
        amount: 0,
        valid_before: 0,
        release_after: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_ok_when_not_already_linked() {
        let r = build_link(false).unwrap();
        assert_eq!(
            r.payload,
            SignedPayload::Message {
                text: LINK_MESSAGE.to_string()
            }
        );
        assert_eq!(r.rail, None);
        assert_eq!(r.amount, 0);
        assert_eq!(r.valid_before, 0);
        assert_eq!(r.release_after, 0);
    }

    #[test]
    fn link_rejects_already_linked() {
        let r = build_link(true);
        assert_eq!(r, Err(ContractError::AlreadyLinked));
    }

    #[test]
    fn link_digest_known_answer() {
        let r = build_link(false).unwrap();
        assert_eq!(
            r.digest,
            [
                0xb7, 0x7c, 0x35, 0xc8, 0x92, 0xa1, 0xb2, 0x4b, 0x10, 0xa2, 0xce, 0x49, 0xb4, 0x24,
                0xe5, 0x78, 0x47, 0x23, 0x33, 0xee, 0x8d, 0x24, 0x56, 0x23, 0x4f, 0xff, 0x90, 0x62,
                0x63, 0x32, 0xc5, 0x0f,
            ]
        );
    }

    #[test]
    fn link_digest_len_is_32_bytes() {
        let r = build_link(false).unwrap();
        assert_eq!(r.digest.len(), 32);
    }
}
