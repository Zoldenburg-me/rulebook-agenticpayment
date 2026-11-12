//! State helpers shared by the owner methods (C2) and the request pipeline (C3): agent lookup,
//! input validation, revoke bookkeeping and the budget window.

use near_sdk::{env, Gas, NearToken, PublicKey};

use crate::errors::ContractError;
use crate::types::{
    AgentId, AgentRecord, EvmAddress, Mandate, Payee, Rail, SweepConfig, BASE_SEPOLIA_CHAIN_ID,
    MAX_EIP712_NAME_LEN, MAX_EIP712_VERSION_LEN, MAX_PERIOD_SECS, MAX_VALIDITY_CAP_SECS,
    MIN_VALIDITY_SECS,
};
use crate::Contract;

/// Gas cap of each agent key, paid from this contract's balance. At 300 Tgas a call reserves
/// about 0.03 NEAR of allowance, so 1 NEAR is about 33 agent calls: enough for the demo, and
/// it bounds what a stolen agent key can burn. O1 tops it up by removing and re-adding the
/// agent, or a later task adds a method for it.
pub const AGENT_KEY_ALLOWANCE: NearToken = NearToken::from_near(1);
/// Gas for `on_agent_key_added` and `on_agent_key_deleted`.
pub const KEY_CALLBACK_GAS: Gas = Gas::from_tgas(10);
/// PayPal Payouts per-item limit (20,000.00 USD), in cents.
pub const PAYPAL_MAX_ITEM_CENTS: u128 = 2_000_000;
/// Longest agent id; the id is the Chain Signatures derivation path.
pub const MAX_AGENT_ID_LEN: usize = 64;

/// 1–64 characters from `[A-Za-z0-9._:-]`, the same charset as `request_id`.
pub fn validate_agent_id(agent: &str) {
    let ok = !agent.is_empty()
        && agent.len() <= MAX_AGENT_ID_LEN
        && agent
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    if !ok {
        ContractError::InvalidAgentId.panic("agent must be 1-64 chars of [A-Za-z0-9._:-]");
    }
}

/// `0x` plus 40 hex digits, returned in lowercase (the form the contract stores and compares).
pub fn normalize_address(field: &str, address: &str) -> EvmAddress {
    let ok = address.len() == 42
        && address.starts_with("0x")
        && address[2..].bytes().all(|b| b.is_ascii_hexdigit());
    if !ok {
        ContractError::InvalidAddress.panic(field);
    }
    address.to_ascii_lowercase()
}

/// Uppercase, no spaces: two letters, two digits, then 11–30 letters or digits.
pub fn validate_iban(iban: &str) {
    let b = iban.as_bytes();
    let ok = (15..=34).contains(&b.len())
        && b[..2].iter().all(u8::is_ascii_uppercase)
        && b[2..4].iter().all(u8::is_ascii_digit)
        && b[4..]
            .iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit());
    if !ok {
        ContractError::InvalidIban.panic("iban must be uppercase with no spaces");
    }
}

/// Validates a payee and returns it in stored form (x402 addresses in lowercase).
pub fn normalize_payee(payee: Payee) -> Payee {
    match payee {
        Payee::X402 { pay_to } => Payee::X402 {
            pay_to: normalize_address("payee.pay_to", &pay_to),
        },
        Payee::Sepa { iban } => {
            validate_iban(&iban);
            Payee::Sepa { iban }
        }
        Payee::Paypal { receiver } => Payee::Paypal {
            receiver: crate::shapes::paypal::normalize_receiver(&receiver)
                .unwrap_or_else(|e| e.panic("payee.receiver")),
        },
    }
}

/// Testnet only: any chain id other than `BASE_SEPOLIA_CHAIN_ID` fails (`ERR_WRONG_NETWORK`).
pub fn validate_chain_id(field: &str, chain_id: u64) {
    if chain_id != BASE_SEPOLIA_CHAIN_ID {
        ContractError::WrongNetwork.panic(&format!(
            "{field} must be {BASE_SEPOLIA_CHAIN_ID} (Base Sepolia)"
        ));
    }
}

/// An EIP-712 domain `name` or `version`: 1 to `max_len` bytes of printable ASCII
/// (`0x20..=0x7e`), so it hashes the same in the contract, viem and the token
/// (`ERR_WRONG_ASSET` otherwise).
pub fn validate_eip712_field(field: &str, value: &str, max_len: usize) {
    let ok = !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|b| (0x20..=0x7e).contains(&b));
    if !ok {
        ContractError::WrongAsset.panic(&format!(
            "{field} must be 1-{max_len} chars of printable ASCII"
        ));
    }
}

/// Validates the EIP-712 domain `name` and `version` of a `usdc_address` token.
fn validate_eip712_domain(prefix: &str, name: &str, version: &str) {
    validate_eip712_field(
        &format!("{prefix}.usdc_eip712_name"),
        name,
        MAX_EIP712_NAME_LEN,
    );
    validate_eip712_field(
        &format!("{prefix}.usdc_eip712_version"),
        version,
        MAX_EIP712_VERSION_LEN,
    );
}

/// Validates a sweep config and returns it with lowercase addresses.
pub fn normalize_sweep_config(sc: SweepConfig) -> SweepConfig {
    validate_chain_id("sweep_config.chain_id", sc.chain_id);
    validate_eip712_domain(
        "sweep_config",
        &sc.usdc_eip712_name,
        &sc.usdc_eip712_version,
    );
    SweepConfig {
        safe_address: normalize_address("sweep_config.safe_address", &sc.safe_address),
        usdc_address: normalize_address("sweep_config.usdc_address", &sc.usdc_address),
        eure_address: normalize_address("sweep_config.eure_address", &sc.eure_address),
        chain_id: sc.chain_id,
        usdc_eip712_name: sc.usdc_eip712_name,
        usdc_eip712_version: sc.usdc_eip712_version,
    }
}

/// Unix milliseconds of the current block.
pub fn now_ms() -> u64 {
    env::block_timestamp_ms()
}

impl Contract {
    /// The agent's record, or `ERR_UNKNOWN_AGENT`.
    pub fn agent_record(&self, agent: &AgentId) -> AgentRecord {
        self.agents
            .get(agent)
            .cloned()
            .unwrap_or_else(|| ContractError::UnknownAgent.panic(agent))
    }

    /// The agent's record if it is not revoked (`ERR_UNKNOWN_AGENT`, `ERR_AGENT_REVOKED`).
    pub fn live_agent_record(&self, agent: &AgentId) -> AgentRecord {
        let record = self.agent_record(agent);
        if record.revoked {
            ContractError::AgentRevoked.panic(agent);
        }
        record
    }

    /// The agent behind an agent-key call: the predecessor must be this contract (agent keys
    /// live on its account) and `env::signer_account_pk()` must be in the key-to-agent map.
    /// The derivation path for MPC requests is this id, never a call argument.
    pub fn calling_agent(&self) -> AgentId {
        if env::predecessor_account_id() != env::current_account_id() {
            ContractError::NotAgentKey.panic("call must be signed with an agent key");
        }
        self.agent_keys
            .get(&env::signer_account_pk())
            .cloned()
            .unwrap_or_else(|| ContractError::UnknownAgentKey.panic("signer key"))
    }

    /// Revoke bookkeeping: clears the mandate, payees and key-to-agent entry and marks the
    /// record revoked. The record and its sweep config stay, so the id is never reused.
    /// Returns the key the caller must delete, if the agent had one.
    pub(crate) fn clear_agent(&mut self, agent: &AgentId) -> Option<PublicKey> {
        let mut record = self.agent_record(agent);
        let key = record.public_key.take();
        if let Some(key) = &key {
            self.agent_keys.remove(key);
        }
        record.revoked = true;
        self.agents.insert(agent.clone(), record);
        self.mandates.remove(agent);
        self.payees.remove(agent);
        key
    }

    /// Validates a mandate against the agent's sweep config and returns it in stored form.
    pub(crate) fn normalize_mandate(&self, record: &AgentRecord, mut mandate: Mandate) -> Mandate {
        validate_chain_id("mandate.chain_id", mandate.chain_id);
        mandate.usdc_address = normalize_address("mandate.usdc_address", &mandate.usdc_address);
        mandate.eure_address = normalize_address("mandate.eure_address", &mandate.eure_address);
        validate_eip712_domain(
            "mandate",
            &mandate.usdc_eip712_name,
            &mandate.usdc_eip712_version,
        );
        let sc = &record.sweep_config;
        if mandate.usdc_address != sc.usdc_address {
            ContractError::InvalidMandate.panic("usdc_address differs from sweep_config");
        }
        if mandate.eure_address != sc.eure_address {
            ContractError::InvalidMandate.panic("eure_address differs from sweep_config");
        }
        if mandate.usdc_eip712_name != sc.usdc_eip712_name
            || mandate.usdc_eip712_version != sc.usdc_eip712_version
        {
            ContractError::InvalidMandate
                .panic("usdc_eip712 name/version differ from sweep_config");
        }
        if mandate.chain_id != sc.chain_id {
            ContractError::InvalidMandate.panic("chain_id differs from sweep_config");
        }
        if !(MIN_VALIDITY_SECS..=MAX_VALIDITY_CAP_SECS).contains(&mandate.max_validity_secs) {
            ContractError::InvalidMandate.panic("max_validity_secs");
        }
        for (name, rail) in [("x402", &mandate.x402), ("sepa", &mandate.sepa)] {
            // min >= 1: the contract never signs a zero-value authorization.
            if rail.amount_range.min.0 == 0 {
                ContractError::InvalidMandate.panic(&format!("{name}.amount_range min is 0"));
            }
            if rail.amount_range.min.0 > rail.amount_range.max.0 {
                ContractError::InvalidMandate.panic(&format!("{name}.amount_range min > max"));
            }
            if !(1..=MAX_PERIOD_SECS).contains(&rail.period_secs) {
                ContractError::InvalidMandate.panic(&format!("{name}.period_secs"));
            }
        }
        let usd_rails = [
            ("paypal", mandate.paypal.as_ref()),
            ("paypal_refund", mandate.paypal_refund.as_ref()),
        ];
        for (name, rail) in usd_rails {
            let Some(rail) = rail else { continue };
            // Same rules as the other rails; PayPal's per-item limit is 20,000.00 USD.
            if rail.amount_range.min.0 == 0 {
                ContractError::InvalidMandate.panic(&format!("{name}.amount_range min is 0"));
            }
            if rail.amount_range.min.0 > rail.amount_range.max.0 {
                ContractError::InvalidMandate.panic(&format!("{name}.amount_range min > max"));
            }
            if rail.amount_range.max.0 > PAYPAL_MAX_ITEM_CENTS {
                ContractError::InvalidMandate
                    .panic(&format!("{name}.amount_range max > 20000.00 USD"));
            }
            if !(1..=MAX_PERIOD_SECS).contains(&rail.period_secs) {
                ContractError::InvalidMandate.panic(&format!("{name}.period_secs"));
            }
        }
        mandate
    }

    /// The current budget window `(start_ms, secs)` of (agent, rail) at `now_ms`, rolled
    /// forward from the stored one (D7): windows run back to back, and once the stored window
    /// has ended, later windows take `period_secs` (the mandate's current value). Read-only;
    /// C3 stores the result when it reserves. `None` before the first `set_mandate`. Never
    /// overflows: `normalize_mandate` caps `period_secs`, and the arithmetic saturates.
    pub fn budget_window(
        &self,
        agent: &AgentId,
        rail: Rail,
        period_secs: u64,
        now_ms: u64,
    ) -> Option<(u64, u64)> {
        let &(start, secs) = self.period_starts.get(&(agent.clone(), rail))?;
        let end = start.saturating_add(secs.saturating_mul(1000));
        if now_ms < end {
            return Some((start, secs));
        }
        let step = period_secs.saturating_mul(1000).max(1);
        Some((end + (now_ms - end) / step * step, period_secs))
    }
}
