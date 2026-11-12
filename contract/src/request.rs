//! The request pipeline (C3): request ids, budget reservation per rail (D7, D8), the MPC
//! `sign` call and its callback, and the reservation state transitions (D4, D10).
//!
//! `reserve_and_sign` is the shared path to the MPC. `request_signature` and `sweep` (C4)
//! call it after their own shape checks; `link_agent` (C7) builds and signs its own
//! reservation directly. Sweep and link skip the budget (D8).

use near_sdk::serde::Deserialize;
use near_sdk::serde_json::{self, json};
use near_sdk::{env, Gas, NearToken, Promise};

use crate::errors::ContractError;
use crate::events::MandateEvent;
use crate::shapes::BuiltRequest;
use crate::state::now_ms;
use crate::types::{
    AgentId, Caller, EvmAddress, EvmSignature, Mandate, Rail, RequestKey, RequestStatus,
    Reservation, ResolveOutcome, ShapeKind, UnknownReason, MPC_TIMEOUT_MS,
};
use crate::Contract;

/// Gas forwarded to the MPC `sign` call. spikes/chainsig burnt about 8.5 Tgas for the whole
/// tx; the rest is refunded.
pub const MPC_SIGN_GAS: Gas = Gas::from_tgas(50);
/// Gas for `on_signature`.
pub const SIGNATURE_CALLBACK_GAS: Gas = Gas::from_tgas(20);
/// Deposit the MPC `sign` call takes (spikes/chainsig), paid from this contract's balance.
pub const MPC_SIGN_DEPOSIT: NearToken = NearToken::from_yoctonear(1);
/// Longest MPC response the callback reads; the real one is about 250 bytes.
const MAX_MPC_RESPONSE_LEN: usize = 1024;
/// Longest `request_id`.
pub const MAX_REQUEST_ID_LEN: usize = 64;
/// Most requests an agent's own key may store over the agent's lifetime, final ones included
/// (`ERR_OVER_BUDGET`). Reservations are never removed and the contract pays their storage
/// (about 850 bytes, 0.0085 NEAR each at the largest ids, plus about 250 bytes in the
/// per-agent index), so this bounds what one agent key can lock at about 0.7 NEAR. Like
/// `AGENT_KEY_ALLOWANCE`, the owner tops it up by adding a new agent.
pub const MAX_AGENT_REQUESTS: u32 = 64;

/// 1–64 characters from `[A-Za-z0-9._:-]` (`ERR_INVALID_REQUEST_ID`).
pub fn validate_request_id(request_id: &str) {
    let ok = !request_id.is_empty()
        && request_id.len() <= MAX_REQUEST_ID_LEN
        && request_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    if !ok {
        ContractError::InvalidRequestId.panic("request_id must be 1-64 chars of [A-Za-z0-9._:-]");
    }
}

/// Unix seconds of the current block.
pub fn now_secs() -> u64 {
    now_ms() / 1000
}

/// The MPC `sign` response (spikes/chainsig):
/// `{"scheme":"Secp256k1","big_r":{"affine_point":"02|03"+x},"s":{"scalar":hex},"recovery_id":0|1}`.
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct MpcResponse {
    big_r: AffinePoint,
    s: Scalar,
    recovery_id: u8,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct AffinePoint {
    affine_point: String,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Scalar {
    scalar: String,
}

/// `0x` plus 64 lowercase hex digits, or `None` if `hex` is not 1–64 hex digits.
fn word_hex(hex: &str) -> Option<String> {
    let ok = !hex.is_empty() && hex.len() <= 64 && hex.bytes().all(|b| b.is_ascii_hexdigit());
    ok.then(|| format!("0x{:0>64}", hex.to_ascii_lowercase()))
}

/// The EVM signature from an MPC response, or `None` if it is malformed: `r` is the x
/// coordinate of `big_r` (its `02`/`03` prefix dropped), `s` the scalar, and
/// `v = 27 + recovery_id`, never derived from the prefix (spikes/chainsig).
pub fn parse_mpc_response(bytes: &[u8]) -> Option<EvmSignature> {
    let resp: MpcResponse = serde_json::from_slice(bytes).ok()?;
    let point = resp.big_r.affine_point;
    let x = match point.get(..2) {
        Some("02" | "03") if point.len() == 66 => &point[2..],
        _ => return None,
    };
    if resp.recovery_id > 1 {
        return None;
    }
    Some(EvmSignature {
        r: word_hex(x)?,
        s: word_hex(&resp.s.scalar)?,
        v: 27 + resp.recovery_id,
    })
}

/// The EVM address that signed `digest` (`0x` hex) with `sig`, or `None` if nothing
/// recovers. Either S form passes (malleability is the EVM side's concern).
pub fn signer_address(digest: &str, sig: &EvmSignature) -> Option<EvmAddress> {
    let hash = hex::decode(digest.strip_prefix("0x")?).ok()?;
    let mut rs = hex::decode(sig.r.strip_prefix("0x")?).ok()?;
    rs.extend(hex::decode(sig.s.strip_prefix("0x")?).ok()?);
    let key = env::ecrecover(&hash, &rs, sig.v.checked_sub(27)?, false)?;
    Some(format!(
        "0x{}",
        hex::encode(&env::keccak256_array(key)[12..])
    ))
}

/// The signature delivered to this callback, or `None` if the MPC call failed or answered
/// something unreadable. Never panics.
pub(crate) fn callback_signature() -> Option<EvmSignature> {
    if env::promise_results_count() != 1 {
        return None;
    }
    let bytes = env::promise_result_checked(0, MAX_MPC_RESPONSE_LEN).ok()?;
    parse_mpc_response(&bytes)
}

impl Contract {
    /// Checks `amount` against the rail's budget in the current window (D7) and books it.
    /// Rolls the stored window forward to now and returns its start, the reservation's
    /// `period_start_ms`. `ERR_OVER_BUDGET` if the window's counting reservations plus
    /// `amount` exceed the mandate's budget.
    pub(crate) fn reserve_budget(
        &mut self,
        agent: &AgentId,
        mandate: &Mandate,
        rail: Rail,
        amount: u128,
    ) -> u64 {
        let rail_mandate = match rail {
            Rail::X402 => &mandate.x402,
            Rail::Sepa => &mandate.sepa,
            Rail::Paypal => mandate
                .paypal
                .as_ref()
                .unwrap_or_else(|| ContractError::ShapeNotAllowed.panic("mandate.paypal")),
            Rail::PaypalRefund => mandate
                .paypal_refund
                .as_ref()
                .unwrap_or_else(|| ContractError::ShapeNotAllowed.panic("mandate.paypal_refund")),
        };
        let now = now_ms();
        let (start, secs) = self
            .budget_window(agent, rail, rail_mandate.period_secs, now)
            .unwrap_or_else(|| ContractError::NoMandate.panic(agent));
        let slot = (agent.clone(), rail);
        let used = self.budget_used_in(agent, rail, start);
        let total = used
            .checked_add(amount)
            .filter(|t| *t <= rail_mandate.budget.0)
            .unwrap_or_else(|| {
                ContractError::OverBudget.panic(&format!(
                    "amount {amount} + reserved {used} > budget {}",
                    rail_mandate.budget.0
                ))
            });
        self.period_starts.insert(slot.clone(), (start, secs));
        self.budget_used.insert(slot, (start, total));
        start
    }

    /// What counts against (agent, rail) in the window starting at `window_start_ms`.
    pub(crate) fn budget_used_in(&self, agent: &AgentId, rail: Rail, window_start_ms: u64) -> u128 {
        match self.budget_used.get(&(agent.clone(), rail)) {
            Some(&(start, used)) if start == window_start_ms => used,
            _ => 0,
        }
    }

    /// `ERR_DUPLICATE_REQUEST_ID` if `key` was used before: `request_id` is deduped per
    /// (caller, agent). Entry points call it before any state change; `reserve_and_sign`
    /// checks again.
    pub(crate) fn assert_new_request(&self, key: &RequestKey) {
        if self.requests.contains_key(key) {
            ContractError::DuplicateRequestId.panic(&key.request_id);
        }
    }

    /// Shared path to the MPC, called by `request_signature` and `sweep` after the caller has
    /// already run the shape checks, reserved the budget and called `assert_new_request`.
    /// For `Caller::Agent`, counts the request against `MAX_AGENT_REQUESTS`
    /// (`ERR_OVER_BUDGET`). Stores the reservation as `pending`, logs
    /// `signature_requested`, and asks the MPC to sign the contract-built digest on path =
    /// `key.agent`, with `on_signature` as the callback.
    pub(crate) fn reserve_and_sign(
        &mut self,
        key: RequestKey,
        shape: ShapeKind,
        built: BuiltRequest,
        period_start_ms: u64,
    ) -> Promise {
        if key.caller == Caller::Agent {
            self.count_agent_request(&key.agent);
        }
        let digest = format!("0x{}", hex::encode(built.digest));
        let reservation = Reservation {
            key: key.clone(),
            shape,
            rail: built.rail,
            amount: built.amount.into(),
            period_start_ms,
            created_at_ms: now_ms(),
            valid_before: built.valid_before,
            release_after: built.release_after,
            digest: digest.clone(),
            payload: built.payload,
            status: RequestStatus::Pending,
            counts_against_budget: built.rail.is_some(),
            signature: None,
        };
        self.requests.insert(key.clone(), reservation);
        self.index_request(&key);
        MandateEvent::SignatureRequested {
            key: key.clone(),
            shape,
            rail: built.rail,
            amount: built.amount.into(),
            digest,
            valid_before: built.valid_before,
        }
        .emit();
        self.mpc_sign(key, built.digest)
    }

    /// Books one more request against the agent's `MAX_AGENT_REQUESTS`, or `ERR_OVER_BUDGET`.
    fn count_agent_request(&mut self, agent: &AgentId) {
        let count = self.agent_request_counts.get(agent).copied().unwrap_or(0);
        if count >= MAX_AGENT_REQUESTS {
            ContractError::OverBudget.panic(&format!(
                "agent has stored {count} requests, the most an agent key may (MAX_AGENT_REQUESTS)"
            ));
        }
        self.agent_request_counts.insert(agent.clone(), count + 1);
    }

    /// Appends `key` to its agent's request index (`list_requests` pages it).
    pub(crate) fn index_request(&mut self, key: &RequestKey) {
        let n = self
            .agent_request_totals
            .get(&key.agent)
            .copied()
            .unwrap_or(0);
        self.request_index
            .insert((key.agent.clone(), n), key.clone());
        self.agent_request_totals.insert(key.agent.clone(), n + 1);
    }

    /// Body of `list_requests`: the agent's requests `from_index..from_index + limit`, oldest
    /// first, read through the index (never a scan of other agents' requests).
    pub(crate) fn requests_of(
        &self,
        agent: &AgentId,
        from_index: u32,
        limit: u32,
    ) -> Vec<Reservation> {
        let total = self.agent_request_totals.get(agent).copied().unwrap_or(0);
        (from_index..total.min(from_index.saturating_add(limit)))
            .filter_map(|i| self.request_index.get(&(agent.clone(), i)))
            .filter_map(|key| self.requests.get(key).cloned())
            .collect()
    }

    /// `sign` on the MPC contract with `domain_id: 0` and path = the agent id, then
    /// `on_signature(key)`. The digest is always one the contract built.
    pub(crate) fn mpc_sign(&self, key: RequestKey, digest: [u8; 32]) -> Promise {
        let args = json!({
            "request": {
                "payload_v2": { "Ecdsa": hex::encode(digest) },
                "path": key.agent,
                "domain_id": 0,
            }
        });
        let args = serde_json::to_vec(&args).unwrap_or_else(|_| env::panic_str("sign args"));
        Promise::new(self.mpc_contract.clone())
            .function_call("sign".to_string(), args, MPC_SIGN_DEPOSIT, MPC_SIGN_GAS)
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SIGNATURE_CALLBACK_GAS)
                    .on_signature(key),
            )
    }

    /// The reservation for `key`, or `ERR_REQUEST_NOT_FOUND`.
    pub(crate) fn reservation(&self, key: &RequestKey) -> Reservation {
        self.requests
            .get(key)
            .cloned()
            .unwrap_or_else(|| ContractError::RequestNotFound.panic(&key.request_id))
    }

    /// Body of `on_signature`. Never panics once the reservation is found (it always is: the
    /// callback is only scheduled by `reserve_and_sign`, after the insert). A signature is
    /// recorded only if it recovers to the agent's `evm_address`.
    pub(crate) fn record_signature(&mut self, key: RequestKey) -> Reservation {
        let mut res = self.reservation(&key);
        let signature = callback_signature();
        let by_agent = signature.as_ref().is_some_and(|sig| {
            let expected = self
                .agents
                .get(&key.agent)
                .and_then(|r| r.evm_address.clone());
            expected.is_some() && signer_address(&res.digest, sig) == expected
        });
        let was_pending = res.status == RequestStatus::Pending;
        match signature {
            Some(signature) if by_agent => {
                // Payments (rail shapes) cannot be requested once revoked, so a revoked agent
                // here was revoked while the request was pending (D10). A sweep after revoke
                // is simply `signed`.
                let revoked =
                    res.rail.is_some() && self.agents.get(&key.agent).is_some_and(|r| r.revoked);
                let next = if revoked {
                    RequestStatus::Revoked
                } else {
                    RequestStatus::Signed
                };
                // `signed` and `revoked` are final; there is one callback per request.
                if res.status.can_become(next) {
                    res.status = next;
                    res.signature = Some(signature.clone());
                    self.requests.insert(key.clone(), res.clone());
                    MandateEvent::SignatureRecorded {
                        key,
                        status: next,
                        signature,
                    }
                    .emit();
                }
            }
            Some(_) if res.status == RequestStatus::Pending => {
                self.mark_unknown(&mut res, UnknownReason::SignatureMismatch);
            }
            None if res.status == RequestStatus::Pending => {
                self.mark_unknown(&mut res, UnknownReason::CallbackFailed);
            }
            // Already unknown (after expire_pending), spent or released: a no-op (§4).
            _ => {}
        }
        if res.shape == ShapeKind::Sweep && res.status != RequestStatus::Pending && was_pending {
            let tok = res.sweep_token();
            self.pending_sweeps.remove(&(res.key.agent.clone(), tok));
        }
        res
    }

    /// `pending` → `unknown`; it keeps counting against the budget until resolved.
    pub(crate) fn mark_unknown(&mut self, res: &mut Reservation, reason: UnknownReason) {
        res.status = RequestStatus::Unknown;
        self.requests.insert(res.key.clone(), res.clone());
        MandateEvent::RequestUnknown {
            key: res.key.clone(),
            reason,
        }
        .emit();
    }

    /// Body of `expire_pending` (D4).
    pub(crate) fn expire(&mut self, key: RequestKey) {
        let mut res = self.reservation(&key);
        if res.status != RequestStatus::Pending {
            ContractError::BadTransition.panic("only a pending request expires");
        }
        if now_ms() < res.created_at_ms.saturating_add(MPC_TIMEOUT_MS) {
            ContractError::MpcTimeoutNotReached.panic(&key.request_id);
        }
        if res.shape == ShapeKind::Sweep {
            let tok = res.sweep_token();
            self.pending_sweeps.remove(&(key.agent.clone(), tok));
        }
        self.mark_unknown(&mut res, UnknownReason::MpcTimeout);
    }

    /// Body of `resolve_reservation` after `assert_owner` (D4): `unknown` → `spent` or
    /// `released`. `released` waits for `release_after` and frees the budget.
    pub(crate) fn resolve(&mut self, key: RequestKey, outcome: ResolveOutcome) {
        let mut res = self.reservation(&key);
        let next = match outcome {
            ResolveOutcome::Spent => RequestStatus::Spent,
            ResolveOutcome::Released => RequestStatus::Released,
        };
        if !res.status.can_become(next) {
            ContractError::BadTransition.panic("only an unknown reservation is resolved");
        }
        if outcome == ResolveOutcome::Released {
            if now_secs() < res.release_after {
                ContractError::ValidityNotEnded
                    .panic(&format!("released only from {}", res.release_after));
            }
            if let Some(rail) = res.rail {
                let slot = (key.agent.clone(), rail);
                if let Some(&(start, used)) = self.budget_used.get(&slot) {
                    if start == res.period_start_ms {
                        self.budget_used
                            .insert(slot, (start, used.saturating_sub(res.amount.0)));
                    }
                }
            }
            res.counts_against_budget = false;
        }
        res.status = next;
        if res.shape == ShapeKind::Sweep {
            let tok = res.sweep_token();
            self.pending_sweeps.remove(&(key.agent.clone(), tok));
        }
        self.requests.insert(key.clone(), res);
        MandateEvent::ReservationResolved { key, outcome }.emit();
    }
}
