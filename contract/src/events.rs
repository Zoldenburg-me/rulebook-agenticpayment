//! NEP-297 events, logged as `EVENT_JSON:{"standard":"zold-mandate","version":"1.0.0",
//! "event":"<name>","data":{...}}`. A rejected call panics, so it emits nothing.

use near_sdk::json_types::U128;
use near_sdk::{env, near, AccountId, PublicKey};

use crate::settlement::{Settlement, SettlementStatus};
use crate::types::{
    AgentId, EvmSignature, Mandate, Payee, Rail, RequestKey, RequestStatus, ResolveOutcome,
    RevokedBy, ShapeKind, SweepConfig, UnknownReason,
};

pub const EVENT_STANDARD: &str = "zold-mandate";
pub const EVENT_VERSION: &str = "1.0.0";

#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum MandateEvent {
    /// The key-to-agent entry is written and `AddKey` was sent.
    AgentAdded {
        agent: AgentId,
        public_key: PublicKey,
        sweep_config: SweepConfig,
    },
    /// `AddKey` failed; the key-to-agent entry was removed again (spikes/deletekey).
    AgentAddFailed {
        agent: AgentId,
        public_key: PublicKey,
    },
    RelayerSet {
        account: Option<AccountId>,
    },
    MandateSet {
        agent: AgentId,
        mandate: Mandate,
    },
    PayeeAdded {
        agent: AgentId,
        payee: Payee,
    },
    PayeeRemoved {
        agent: AgentId,
        payee: Payee,
    },
    /// A reservation was made and the digest sent to the MPC (all shapes, including link).
    SignatureRequested {
        key: RequestKey,
        shape: ShapeKind,
        rail: Option<Rail>,
        amount: U128,
        digest: String,
        valid_before: u64,
    },
    /// The MPC callback delivered a signature; `status` is `signed` or `revoked`.
    SignatureRecorded {
        key: RequestKey,
        status: RequestStatus,
        signature: EvmSignature,
    },
    RequestUnknown {
        key: RequestKey,
        reason: UnknownReason,
    },
    ReservationResolved {
        key: RequestKey,
        outcome: ResolveOutcome,
    },
    /// A failed or wrong-key link callback reset `linked`; the owner may call `link_agent` again.
    AgentUnlinked {
        agent: AgentId,
        key: RequestKey,
    },
    AgentRevoked {
        agent: AgentId,
        by: RevokedBy,
    },
    SettlementReporterSet {
        account: Option<AccountId>,
    },
    /// The settlement reporter relayed a verified PayPal webhook for a signed PayPal payout.
    SettlementReported {
        key: RequestKey,
        settlement: Settlement,
    },
    /// An adverse settlement suspended the payee; shape 4 to it is refused until
    /// `reinstate_payee`.
    PayeeSuspended {
        agent: AgentId,
        payee: Payee,
        status: SettlementStatus,
    },
    PayeeReinstated {
        agent: AgentId,
        payee: Payee,
    },
}

/// The full NEP-297 log object.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq)]
pub struct EventLog {
    pub standard: String,
    pub version: String,
    #[serde(flatten)]
    pub event: MandateEvent,
}

impl MandateEvent {
    pub fn to_log(&self) -> EventLog {
        EventLog {
            standard: EVENT_STANDARD.to_string(),
            version: EVENT_VERSION.to_string(),
            event: self.clone(),
        }
    }

    pub fn emit(&self) {
        let json = near_sdk::serde_json::to_string(&self.to_log())
            .unwrap_or_else(|_| env::panic_str("event serialization failed"));
        env::log_str(&format!("EVENT_JSON:{json}"));
    }
}
