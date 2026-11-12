//! PP-W1: PayPal settlement feedback. A verified PayPal webhook tells the contract, through
//! the one `settlement_reporter` account, what happened to a signed PayPal payout. The
//! reporter can only tighten: it marks a receipt PayPal-confirmed, or suspends the payee
//! after a failed, returned, blocked, refunded or reversed payout or a dispute. It never
//! touches a mandate, a cap, a budget or a reservation's status; only the owner re-enables a
//! suspended payee (`reinstate_payee`) or releases budget (`resolve_reservation`).

use near_sdk::{env, near, AccountId};

use crate::errors::ContractError;
use crate::events::MandateEvent;
use crate::types::{AgentId, Payee, RequestKey, RequestStatus, ShapeKind, SignedPayload};
use crate::Contract;

/// Longest `paypal_id` (PayPal item, transaction, capture and dispute ids are 13–20 chars).
pub const MAX_PAYPAL_ID_LEN: usize = 64;

/// What PayPal reported for a payout, from the webhook event type.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementStatus {
    /// `PAYMENT.PAYOUTS-ITEM.SUCCEEDED` or `PAYMENT.CAPTURE.COMPLETED`: the money arrived.
    Completed,
    /// `PAYMENT.PAYOUTS-ITEM.UNCLAIMED`: the receiver has no account yet; PayPal returns the
    /// money after 30 days (then `returned`). Recorded, nothing suspended.
    Unclaimed,
    /// `PAYMENT.PAYOUTS-ITEM.FAILED` or `.DENIED`.
    Failed,
    /// `PAYMENT.PAYOUTS-ITEM.RETURNED`.
    Returned,
    /// `PAYMENT.PAYOUTS-ITEM.BLOCKED`.
    Blocked,
    /// `PAYMENT.PAYOUTS-ITEM.REFUNDED` or `PAYMENT.CAPTURE.REFUNDED`.
    Refunded,
    /// `PAYMENT.CAPTURE.REVERSED`.
    Reversed,
    /// `CUSTOMER.DISPUTE.CREATED`.
    Disputed,
}

impl SettlementStatus {
    /// A status that suspends the payee.
    pub fn is_adverse(self) -> bool {
        !matches!(
            self,
            SettlementStatus::Completed | SettlementStatus::Unclaimed
        )
    }
}

/// The latest settlement report of a request (`get_settlement`).
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settlement {
    pub status: SettlementStatus,
    /// PayPal's id for the event's resource (payout item, capture or dispute).
    pub paypal_id: String,
    pub reported_at_ms: u64,
}

/// 1–64 of `[A-Za-z0-9_-]` (`ERR_INVALID_SETTLEMENT`).
fn validate_paypal_id(id: &str) {
    let ok = !id.is_empty()
        && id.len() <= MAX_PAYPAL_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
    if !ok {
        ContractError::InvalidSettlement.panic("paypal_id must be 1-64 chars of [A-Za-z0-9_-]");
    }
}

/// The payee of a signed shape 4 text, `Send USD {amount} to {payee} at {RFC3339} ref {id}`.
/// The stored payee never contains a space (`normalize_receiver`), so the first ` at ` after
/// ` to ` ends it.
fn paypal_payee(payload: &SignedPayload) -> Option<String> {
    let SignedPayload::Message { text } = payload else {
        return None;
    };
    let rest = text.strip_prefix("Send USD ")?;
    let (_, rest) = rest.split_once(" to ")?;
    let (payee, _) = rest.split_once(" at ")?;
    Some(payee.to_string())
}

impl Contract {
    pub(crate) fn assert_settlement_reporter(&self) {
        if self.settlement_reporter.as_ref() != Some(&env::predecessor_account_id()) {
            ContractError::NotSettlementReporter
                .panic("predecessor is not the settlement reporter");
        }
    }

    pub(crate) fn is_suspended(&self, agent: &AgentId, payee: &Payee) -> bool {
        self.suspended_payees
            .get(agent)
            .is_some_and(|list| list.contains(payee))
    }

    /// Records a report on an agent's signed PayPal payout. Tighten-only: an adverse report
    /// suspends the payee; a `completed` or `unclaimed` report never replaces an adverse one
    /// (it is ignored and returns false). Returns true if the report was stored.
    pub(crate) fn record_settlement(
        &mut self,
        agent: AgentId,
        request_id: String,
        status: SettlementStatus,
        paypal_id: String,
    ) -> bool {
        self.assert_settlement_reporter();
        validate_paypal_id(&paypal_id);
        let key = RequestKey {
            agent: agent.clone(),
            caller: crate::types::Caller::Agent,
            request_id,
        };
        let res = self
            .requests
            .get(&key)
            .cloned()
            .unwrap_or_else(|| ContractError::RequestNotFound.panic("request"));
        if res.shape != ShapeKind::Paypal {
            ContractError::ShapeNotAllowed.panic("report_settlement takes paypal requests only");
        }
        // Only a `signed` order is ever submitted (PP3 checks the same).
        if res.status != RequestStatus::Signed {
            ContractError::BadTransition.panic("request is not signed");
        }
        let prior = self.settlements.get(&key).cloned();
        if !status.is_adverse() && prior.as_ref().is_some_and(|s| s.status.is_adverse()) {
            return false;
        }
        let settlement = Settlement {
            status,
            paypal_id,
            reported_at_ms: env::block_timestamp_ms(),
        };
        self.settlements.insert(key.clone(), settlement.clone());
        MandateEvent::SettlementReported {
            key,
            settlement: settlement.clone(),
        }
        .emit();
        if status.is_adverse() {
            let receiver = paypal_payee(&res.payload)
                .unwrap_or_else(|| env::panic_str("paypal reservation without a payee"));
            let payee = Payee::Paypal { receiver };
            let mut list = self
                .suspended_payees
                .get(&agent)
                .cloned()
                .unwrap_or_default();
            if !list.contains(&payee) {
                list.push(payee.clone());
                self.suspended_payees.insert(agent.clone(), list);
                MandateEvent::PayeeSuspended {
                    agent,
                    payee,
                    status,
                }
                .emit();
            }
        }
        true
    }

    /// Owner: lifts a suspension. One that is not suspended fails (`ERR_PAYEE_NOT_SUSPENDED`).
    pub(crate) fn lift_suspension(&mut self, agent: AgentId, payee: Payee) {
        let mut list = self
            .suspended_payees
            .get(&agent)
            .cloned()
            .unwrap_or_default();
        let Some(i) = list.iter().position(|p| *p == payee) else {
            ContractError::PayeeNotSuspended.panic("payee");
        };
        list.remove(i);
        if list.is_empty() {
            self.suspended_payees.remove(&agent);
        } else {
            self.suspended_payees.insert(agent.clone(), list);
        }
        MandateEvent::PayeeReinstated { agent, payee }.emit();
    }

    pub(crate) fn set_reporter(&mut self, account: Option<AccountId>) {
        // Agent calls have this contract as predecessor; it can never be the reporter.
        if account.as_ref() == Some(&env::current_account_id()) {
            ContractError::NotSettlementReporter.panic("reporter cannot be this contract");
        }
        self.settlement_reporter = account.clone();
        MandateEvent::SettlementReporterSet { account }.emit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payee_is_read_from_the_signed_text() {
        let p = SignedPayload::Message {
            text: "Send USD 42.50 to supplier@example.com at 2026-11-02T06:08:20Z ref inv-1".into(),
        };
        assert_eq!(paypal_payee(&p).as_deref(), Some("supplier@example.com"));
        let p = SignedPayload::Message {
            text: "Send USD 1.00 to @venmo-handle at 2026-11-02T06:08:20Z ref r".into(),
        };
        assert_eq!(paypal_payee(&p).as_deref(), Some("@venmo-handle"));
        let p = SignedPayload::Message {
            text: "Link".into(),
        };
        assert_eq!(paypal_payee(&p), None);
    }

    #[test]
    fn only_completed_and_unclaimed_are_not_adverse() {
        use SettlementStatus::*;
        for s in [Failed, Returned, Blocked, Refunded, Reversed, Disputed] {
            assert!(s.is_adverse(), "{s:?}");
        }
        assert!(!Completed.is_adverse());
        assert!(!Unclaimed.is_adverse());
    }
}
