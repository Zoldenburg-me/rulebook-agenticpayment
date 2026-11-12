//! The mandate contract: holds each agent's signing power through Chain Signatures and signs
//! only what fits the owner's mandate. C2 implements the owner methods, state and views; C3
//! the request pipeline (`request.rs`); the remaining stubs are C4, C6 and C7 (shapes).
//!
//! Callers:
//! - **Owner methods** take `assertion: Option<OwnerAssertion>` as their last argument:
//!   `Some` in passkey mode (any account may submit), `None` in wallet mode (the predecessor
//!   must be the owner account and attach exactly 1 yoctoNEAR, so they are `#[payable]`).
//! - **Agent methods** (`request_signature`, `sweep`, `revoke_self`) are called with the
//!   agent's function-call key, which lives on this contract's own account. The predecessor
//!   is therefore this contract, and the agent is found by `env::signer_account_pk()` in the
//!   key-to-agent map. Agent methods take no `agent` argument (`sweep` takes one, and an
//!   optional owner assertion, because the owner and the relayer call it too).
//! - `#[private]` alone does not keep agents out of callbacks, because agent calls also have
//!   this contract as predecessor; the agent key's `method_names` do.

use near_sdk::json_types::U128;
use near_sdk::store::{IterableMap, LookupMap, LookupSet};
use near_sdk::{
    env, near, AccountId, Allowance, BorshStorageKey, PanicOnDefault, Promise, PromiseOrValue,
    PublicKey,
};

pub mod errors;
pub mod events;
pub mod owner;
pub mod request;
pub mod settlement;
pub mod shapes;
pub mod state;
pub mod types;

#[cfg(test)]
mod interface_tests;

use errors::ContractError;
use events::MandateEvent;
use request::{now_secs, validate_request_id};
use settlement::{Settlement, SettlementStatus};
use shapes::{eip3009_nonce, payout, paypal, paypal_checkout, refund, x402};
use state::{
    normalize_address, normalize_payee, normalize_sweep_config, now_ms, validate_agent_id,
    AGENT_KEY_ALLOWANCE, KEY_CALLBACK_GAS,
};
use types::{
    AgentId, AgentRecord, BudgetView, Caller, ConfigView, EvmAddress, EvmTxParams, Mandate,
    OwnerAssertion, OwnerMode, Payee, Rail, RequestKey, RequestStatus, Reservation, ResolveOutcome,
    RevokeResult, RevokedBy, Shape, ShapeKind, SweepConfig, Token, UnknownReason,
    AGENT_METHOD_NAMES, MPC_CONTRACT, NETWORK,
};

#[near]
#[derive(BorshStorageKey)]
enum StorageKey {
    Agents,
    AgentKeys,
    Mandates,
    Payees,
    PeriodStarts,
    Requests,
    SignedPayouts,
    PendingSweeps,
    UndeletedKeys,
    BudgetUsed,
    AgentRequestCounts,
    UndeletedKeySet,
    RequestIndex,
    AgentRequestTotals,
    Settlements,
    SuspendedPayees,
}

/// Contract state. The layout is internal (C2 and C3 may reshape it); the interface is
/// the methods and the types in `types`.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner: OwnerMode,
    /// The last owner nonce used; 0 before the first owner call.
    owner_nonce: u64,
    network: String,
    mpc_contract: AccountId,
    relayer: Option<AccountId>,
    /// Every agent ever added, revoked ones included (ids are never reused).
    agents: IterableMap<AgentId, AgentRecord>,
    /// Live agent keys only: written by `add_agent`, removed by revoke or a failed `AddKey`.
    agent_keys: LookupMap<PublicKey, AgentId>,
    mandates: LookupMap<AgentId, Mandate>,
    payees: LookupMap<AgentId, Vec<Payee>>,
    /// Per (agent, rail): start (unix ms) and length (s) of the current budget window. Set at
    /// the agent's first `set_mandate`, rolled forward back to back at request time (D7).
    period_starts: LookupMap<(AgentId, Rail), (u64, u64)>,
    requests: IterableMap<RequestKey, Reservation>,
    /// `payout_dedupe_key` of every payout signed, per agent (D3).
    signed_payouts: LookupSet<[u8; 32]>,
    /// At most one pending sweep per (agent, token).
    pending_sweeps: LookupSet<(AgentId, Token)>,
    /// Keys of revoked agents whose `DeleteKey` has not succeeded yet; a later revoke of
    /// the same agent retries it.
    undeleted_keys: LookupMap<AgentId, PublicKey>,
    /// Per (agent, rail): the window start (unix ms) and the sum of the counting reservations
    /// made in that window. Booked at request time, reduced when one is released (D7, D8).
    budget_used: LookupMap<(AgentId, Rail), (u64, u128)>,
    /// Requests each agent's key has stored, final ones included (`MAX_AGENT_REQUESTS`).
    agent_request_counts: LookupMap<AgentId, u32>,
    /// The keys in `undeleted_keys`, so `add_agent` can refuse one that is still on the account.
    undeleted_key_set: LookupSet<PublicKey>,
    /// Per agent, its requests by any caller in order: (agent, n) → the n-th key.
    request_index: LookupMap<(AgentId, u32), RequestKey>,
    /// Requests per agent by any caller: the length of its `request_index`.
    agent_request_totals: LookupMap<AgentId, u32>,
    /// The one account allowed to call `report_settlement` (PP-W1); `None` until the owner sets it.
    settlement_reporter: Option<AccountId>,
    /// The latest settlement report per PayPal request (PP-W1).
    settlements: LookupMap<RequestKey, Settlement>,
    /// Per agent, the PayPal payees an adverse settlement suspended (PP-W1).
    suspended_payees: LookupMap<AgentId, Vec<Payee>>,
}

/// True if the single key action this callback follows succeeded. Never panics.
fn key_action_succeeded() -> bool {
    env::promise_results_count() == 1 && env::promise_result_checked(0, 64).is_ok()
}

/// `validate_request_id`, plus the `link-` prefix is reserved for `link_agent`'s own ids
/// (`ERR_INVALID_REQUEST_ID`), so a caller-chosen id never takes a link key's slot.
fn validate_caller_request_id(request_id: &str) {
    validate_request_id(request_id);
    if request_id.starts_with("link-") {
        ContractError::InvalidRequestId.panic("request_id prefix link- is reserved");
    }
}

#[near]
impl Contract {
    /// Deploy-time init, callable only by this account (in the deploy tx). `owner` picks
    /// passkey or wallet mode once; `network` must be `testnet` (the string in owner
    /// challenges) and `mpc_contract` `v1.signer-prod.testnet` (`ERR_WRONG_NETWORK`). Rejects
    /// `OwnerMode::Wallet` naming this contract's own account, and a passkey that is not a
    /// 33-byte compressed key or has an empty `rp_id` or `origin` (`ERR_NOT_OWNER`).
    #[init]
    #[private]
    pub fn new(owner: OwnerMode, network: String, mpc_contract: AccountId) -> Self {
        match &owner {
            OwnerMode::Wallet { account } => {
                if *account == env::current_account_id() {
                    ContractError::NotOwner.panic("owner account cannot be this contract");
                }
            }
            OwnerMode::Passkey {
                public_key,
                rp_id,
                origin,
            } => {
                let key = &public_key.0;
                if key.len() != 33 || !matches!(key[0], 2 | 3) {
                    ContractError::NotOwner.panic("public_key must be 33-byte compressed SEC1");
                }
                if rp_id.is_empty() || origin.is_empty() {
                    ContractError::NotOwner.panic("rp_id and origin must be set");
                }
            }
        }
        if network != NETWORK {
            ContractError::WrongNetwork.panic(&format!("network must be {NETWORK}"));
        }
        if mpc_contract.as_str() != MPC_CONTRACT {
            ContractError::WrongNetwork.panic(&format!("mpc_contract must be {MPC_CONTRACT}"));
        }
        Self {
            owner,
            owner_nonce: 0,
            network,
            mpc_contract,
            relayer: None,
            agents: IterableMap::new(StorageKey::Agents),
            agent_keys: LookupMap::new(StorageKey::AgentKeys),
            mandates: LookupMap::new(StorageKey::Mandates),
            payees: LookupMap::new(StorageKey::Payees),
            period_starts: LookupMap::new(StorageKey::PeriodStarts),
            requests: IterableMap::new(StorageKey::Requests),
            signed_payouts: LookupSet::new(StorageKey::SignedPayouts),
            pending_sweeps: LookupSet::new(StorageKey::PendingSweeps),
            undeleted_keys: LookupMap::new(StorageKey::UndeletedKeys),
            budget_used: LookupMap::new(StorageKey::BudgetUsed),
            agent_request_counts: LookupMap::new(StorageKey::AgentRequestCounts),
            undeleted_key_set: LookupSet::new(StorageKey::UndeletedKeySet),
            request_index: LookupMap::new(StorageKey::RequestIndex),
            agent_request_totals: LookupMap::new(StorageKey::AgentRequestTotals),
            settlement_reporter: None,
            settlements: LookupMap::new(StorageKey::Settlements),
            suspended_payees: LookupMap::new(StorageKey::SuspendedPayees),
        }
    }

    // ---- Owner methods ----

    /// Registers `agent`, adds `public_key` as a function-call key on this account with
    /// `AGENT_METHOD_NAMES` and `AGENT_KEY_ALLOWANCE`, and stores `sweep_config`. Rejects an
    /// existing agent id (including revoked ones) or key, live or still waiting for its
    /// `DeleteKey`. `evm_address` is the agent EOA the owner derived off chain from (this
    /// contract, `agent`) as the MPC does; it is checked for format only and stored
    /// lowercase. A wrong one cannot redirect funds: `on_signature` records only signatures
    /// that recover to it, so every request then ends `unknown`. The key-to-agent entry is
    /// written before `AddKey`, so a second `add_agent` with the same key fails at once; if
    /// `AddKey` fails, `on_agent_key_added` clears it again and returns false
    /// (spikes/deletekey).
    #[payable]
    pub fn add_agent(
        &mut self,
        agent: AgentId,
        public_key: PublicKey,
        sweep_config: SweepConfig,
        evm_address: EvmAddress,
        assertion: Option<OwnerAssertion>,
    ) -> Promise {
        self.assert_owner(
            "add_agent",
            &(&agent, &public_key, &sweep_config, &evm_address),
            assertion,
        );
        validate_agent_id(&agent);
        if self.agents.contains_key(&agent) {
            ContractError::AgentExists.panic(&agent);
        }
        if self.agent_keys.contains_key(&public_key) || self.undeleted_key_set.contains(&public_key)
        {
            ContractError::KeyExists.panic("public_key");
        }
        let sweep_config = normalize_sweep_config(sweep_config);
        let evm_address = normalize_address("evm_address", &evm_address);
        self.agent_keys.insert(public_key.clone(), agent.clone());
        self.agents.insert(
            agent.clone(),
            AgentRecord {
                agent: agent.clone(),
                public_key: Some(public_key.clone()),
                sweep_config: sweep_config.clone(),
                evm_address: Some(evm_address),
                linked: false,
                revoked: false,
            },
        );
        MandateEvent::AgentAdded {
            agent: agent.clone(),
            public_key: public_key.clone(),
            sweep_config,
        }
        .emit();

        let me = env::current_account_id();
        let allowance = Allowance::limited(AGENT_KEY_ALLOWANCE)
            .unwrap_or_else(|| env::panic_str("AGENT_KEY_ALLOWANCE is zero"));
        Promise::new(me.clone())
            .add_access_key_allowance(
                public_key.clone(),
                allowance,
                me.clone(),
                AGENT_METHOD_NAMES.join(","),
            )
            .then(
                Self::ext(me)
                    .with_static_gas(KEY_CALLBACK_GAS)
                    .on_agent_key_added(agent, public_key),
            )
    }

    /// Names the one relayer account allowed to request sweeps; `None` removes it. Rejects
    /// this contract's own account, which agent calls have as predecessor
    /// (`ERR_SWEEP_CALLER_NOT_ALLOWED`).
    #[payable]
    pub fn set_relayer(&mut self, account: Option<AccountId>, assertion: Option<OwnerAssertion>) {
        self.assert_owner("set_relayer", &(&account,), assertion);
        if account.as_ref() == Some(&env::current_account_id()) {
            ContractError::SweepCallerNotAllowed.panic("relayer cannot be this contract");
        }
        self.relayer = account.clone();
        MandateEvent::RelayerSet { account }.emit();
    }

    /// Names the one account allowed to call `report_settlement` (PP-W1); `None` removes it.
    /// Rejects this contract's own account, which agent calls have as predecessor
    /// (`ERR_NOT_SETTLEMENT_REPORTER`).
    #[payable]
    pub fn set_settlement_reporter(
        &mut self,
        account: Option<AccountId>,
        assertion: Option<OwnerAssertion>,
    ) {
        self.assert_owner("set_settlement_reporter", &(&account,), assertion);
        self.set_reporter(account);
    }

    /// Re-enables a PayPal payee that an adverse settlement suspended (PP-W1). The payee is
    /// matched in its stored form; one that is not suspended fails (`ERR_PAYEE_NOT_SUSPENDED`).
    #[payable]
    pub fn reinstate_payee(
        &mut self,
        agent: AgentId,
        payee: Payee,
        assertion: Option<OwnerAssertion>,
    ) {
        self.assert_owner("reinstate_payee", &(&agent, &payee), assertion);
        self.agent_record(&agent);
        let payee = normalize_payee(payee);
        self.lift_suspension(agent, payee);
    }

    /// Sets or replaces the agent's mandate. Pending reservations are untouched and the
    /// budget window does not restart; a changed `period_secs` applies from the next window
    /// boundary (D7, D10). The mandate's addresses and chain id must match the sweep config.
    #[payable]
    pub fn set_mandate(
        &mut self,
        agent: AgentId,
        mandate: Mandate,
        assertion: Option<OwnerAssertion>,
    ) {
        self.assert_owner("set_mandate", &(&agent, &mandate), assertion);
        let record = self.live_agent_record(&agent);
        let mandate = self.normalize_mandate(&record, mandate);
        let now = now_ms();
        let old = self.mandates.get(&agent).cloned();
        for (rail, period) in [
            (Rail::X402, mandate.x402.period_secs),
            (Rail::Sepa, mandate.sepa.period_secs),
        ]
        .into_iter()
        .chain(
            mandate
                .paypal
                .as_ref()
                .map(|p| (Rail::Paypal, p.period_secs)),
        )
        .chain(
            mandate
                .paypal_refund
                .as_ref()
                .map(|p| (Rail::PaypalRefund, p.period_secs)),
        ) {
            // Roll the stored window to now under the old period first, so the new period
            // applies only from the next boundary and never rewrites elapsed windows. A
            // window that starts exactly now already takes the new period.
            let window = match (&old, self.period_starts.get(&(agent.clone(), rail))) {
                (Some(old), Some(&(_, secs))) => {
                    let old_period = match rail {
                        Rail::X402 => old.x402.period_secs,
                        Rail::Sepa => old.sepa.period_secs,
                        // A mandate that had no PayPal rail kept no window running.
                        Rail::Paypal => old.paypal.as_ref().map_or(secs, |p| p.period_secs),
                        Rail::PaypalRefund => {
                            old.paypal_refund.as_ref().map_or(secs, |p| p.period_secs)
                        }
                    };
                    self.budget_window(&agent, rail, old_period, now)
                        .unwrap_or((now, secs))
                }
                (_, Some(&w)) => w,
                (_, None) => (now, period),
            };
            let window = if window.0 == now {
                (now, period)
            } else {
                window
            };
            self.period_starts.insert((agent.clone(), rail), window);
        }
        self.mandates.insert(agent.clone(), mandate.clone());
        MandateEvent::MandateSet { agent, mandate }.emit();
    }

    /// Adds an x402 `payTo` or an IBAN to the agent's allowlist (D5). Adding a payee that is
    /// already listed changes nothing.
    #[payable]
    pub fn add_payee(&mut self, agent: AgentId, payee: Payee, assertion: Option<OwnerAssertion>) {
        self.assert_owner("add_payee", &(&agent, &payee), assertion);
        self.live_agent_record(&agent);
        let payee = normalize_payee(payee);
        let mut list = self.payees.get(&agent).cloned().unwrap_or_default();
        if list.contains(&payee) {
            return;
        }
        list.push(payee.clone());
        self.payees.insert(agent.clone(), list);
        MandateEvent::PayeeAdded { agent, payee }.emit();
    }

    /// Removes a payee; one that is not listed fails (`ERR_PAYEE_NOT_ALLOWED` or
    /// `ERR_IBAN_NOT_ALLOWED`) so the owner sees a typo.
    #[payable]
    pub fn remove_payee(
        &mut self,
        agent: AgentId,
        payee: Payee,
        assertion: Option<OwnerAssertion>,
    ) {
        self.assert_owner("remove_payee", &(&agent, &payee), assertion);
        self.live_agent_record(&agent);
        let payee = normalize_payee(payee);
        let mut list = self.payees.get(&agent).cloned().unwrap_or_default();
        let Some(i) = list.iter().position(|p| *p == payee) else {
            match payee {
                Payee::X402 { .. } => ContractError::PayeeNotAllowed.panic("payee not listed"),
                Payee::Sepa { .. } => ContractError::IbanNotAllowed.panic("payee not listed"),
                Payee::Paypal { .. } => {
                    ContractError::PaypalPayeeNotAllowed.panic("payee not listed")
                }
            }
        };
        list.remove(i);
        self.payees.insert(agent.clone(), list);
        MandateEvent::PayeeRemoved { agent, payee }.emit();
    }

    /// Signs the Monerium link message for the agent EOA, once. Returns the MPC promise;
    /// the callback returns the `Reservation` with the signature.
    #[payable]
    pub fn link_agent(&mut self, agent: AgentId, assertion: Option<OwnerAssertion>) -> Promise {
        self.assert_owner("link_agent", &(&agent,), assertion);
        let mut record = self.live_agent_record(&agent);
        let built = shapes::link::build_link(record.linked).unwrap_or_else(|e| e.panic(&agent));
        record.linked = true;
        self.agents.insert(agent.clone(), record);
        let created_at_ms = now_ms();
        let mut suffix = created_at_ms;
        let key = loop {
            let k = RequestKey {
                agent: agent.clone(),
                caller: Caller::Owner,
                request_id: format!("link-{suffix}"),
            };
            if !self.requests.contains_key(&k) {
                break k;
            }
            suffix += 1;
        };
        let digest = format!("0x{}", hex::encode(built.digest));
        let reservation = Reservation {
            key: key.clone(),
            shape: ShapeKind::Link,
            rail: None,
            amount: 0.into(),
            period_start_ms: 0,
            created_at_ms,
            valid_before: 0,
            release_after: 0,
            digest: digest.clone(),
            payload: built.payload,
            status: RequestStatus::Pending,
            counts_against_budget: false,
            signature: None,
        };
        self.requests.insert(key.clone(), reservation);
        self.index_request(&key);
        MandateEvent::SignatureRequested {
            key: key.clone(),
            shape: ShapeKind::Link,
            rail: None,
            amount: 0.into(),
            digest,
            valid_before: 0,
        }
        .emit();
        let args = near_sdk::serde_json::json!({
            "request": {
                "payload_v2": { "Ecdsa": hex::encode(built.digest) },
                "path": agent,
                "domain_id": 0,
            }
        });
        let args = near_sdk::serde_json::to_vec(&args)
            .unwrap_or_else(|_| ContractError::NotImplemented.panic("json args for MPC sign"));
        Promise::new(self.mpc_contract.clone())
            .function_call(
                "sign".to_string(),
                args,
                request::MPC_SIGN_DEPOSIT,
                request::MPC_SIGN_GAS,
            )
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(request::SIGNATURE_CALLBACK_GAS)
                    .on_link_signature(key.clone()),
            )
    }

    /// Clears the agent's mandate, payees and key-to-agent entry, then deletes its
    /// function-call key (D1). The sweep config stays. A failed `DeleteKey` is not an error:
    /// the result comes from `on_agent_key_deleted`, which never fails. An agent that is
    /// already revoked returns `{revoked: true, key_deleted: false}` with no key action,
    /// unless an earlier `DeleteKey` of its key failed: then it retries that `DeleteKey`.
    #[payable]
    pub fn revoke(
        &mut self,
        agent: AgentId,
        assertion: Option<OwnerAssertion>,
    ) -> PromiseOrValue<RevokeResult> {
        self.assert_owner("revoke", &(&agent,), assertion);
        self.revoke_agent(agent, RevokedBy::Owner)
    }

    /// Resolves an `unknown` reservation (D4). `Released` is refused until
    /// `Reservation::release_after` (`ERR_VALIDITY_NOT_ENDED`).
    #[payable]
    pub fn resolve_reservation(
        &mut self,
        key: RequestKey,
        outcome: ResolveOutcome,
        assertion: Option<OwnerAssertion>,
    ) {
        self.assert_owner("resolve_reservation", &(&key, &outcome), assertion);
        self.resolve(key, outcome);
    }

    // ---- Agent methods (the agent key's method_names) ----

    /// Shapes 2 to 6 only (`x402`, `payout`, `paypal`, `paypal_checkout`, `refund`;
    /// `ERR_SHAPE_NOT_ALLOWED` otherwise). The agent is the one behind the signer key, never an argument. Dedupes
    /// `request_id` per (agent caller, agent), checks the shape against the agent's mandate
    /// as it stands now, reserves the amount on the shape's rail (D7, D8) and calls the MPC.
    /// The promise resolves to the `Reservation` returned by `on_signature`.
    pub fn request_signature(&mut self, request_id: String, shape: Shape) -> Promise {
        let agent = self.calling_agent();
        let record = self.live_agent_record(&agent);
        validate_caller_request_id(&request_id);
        let key = RequestKey {
            agent: agent.clone(),
            caller: Caller::Agent,
            request_id,
        };
        self.assert_new_request(&key);
        let mandate = self
            .mandates
            .get(&agent)
            .cloned()
            .unwrap_or_else(|| ContractError::NoMandate.panic(&agent));
        let payees = self.get_payees(agent.clone());
        let now = now_secs();
        let kind = shape.kind();
        let built = match &shape {
            Shape::X402(req) => {
                let from = record
                    .evm_address
                    .as_ref()
                    .unwrap_or_else(|| ContractError::InvalidAddress.panic("agent evm_address"));
                let nonce = eip3009_nonce(&key, ShapeKind::X402);
                x402::build_x402(req, &mandate, &payees, from, nonce, now)
            }
            Shape::Payout(req) => payout::build_payout(req, &mandate, &payees, now),
            Shape::Paypal(req) => {
                paypal::build_paypal(req, &key.request_id, &mandate, &payees, now)
            }
            Shape::PaypalCheckout(req) => {
                paypal_checkout::build_paypal_checkout(req, &key.request_id, &mandate, &payees, now)
            }
            Shape::Refund(req) => refund::build_refund(req, &key.request_id, &mandate, now),
            Shape::Sweep { .. } | Shape::Link => ContractError::ShapeNotAllowed
                .panic("request_signature takes x402, payout, paypal, paypal_checkout or refund"),
        }
        .unwrap_or_else(|e| match (&shape, e) {
            (Shape::Refund(_), ContractError::ShapeNotAllowed) => e.panic("mandate.paypal_refund"),
            _ => e.panic(error_field(e)),
        });
        if let Shape::Payout(req) = &shape {
            // D3: never sign the same (iban, amount, timestamp) twice for one agent.
            let canonical =
                payout::canonical_amount(&req.amount).unwrap_or_else(|e| e.panic("amount"));
            let dedupe = payout::payout_dedupe_key(&agent, &req.iban, &canonical, req.timestamp);
            if !self.signed_payouts.insert(dedupe) {
                ContractError::DuplicatePayout
                    .panic("agent, iban, amount and timestamp already signed");
            }
        }
        if let Shape::Paypal(req) = &shape {
            // D3 as shape 3: never sign the same (payee, amount, timestamp) twice for one
            // agent, whatever the request_id (PayPal pays a new sender_batch_id again).
            // build_paypal has already normalised and checked both.
            let payee = paypal::normalize_receiver(&req.payee).unwrap_or_else(|e| e.panic("payee"));
            // PP-W1: a failed, returned or reversed payout or a dispute suspended this payee.
            if self.is_suspended(
                &agent,
                &Payee::Paypal {
                    receiver: payee.clone(),
                },
            ) {
                ContractError::PayeeSuspended.panic("payee");
            }
            let dedupe = paypal::paypal_dedupe_key(&agent, &payee, &req.amount, req.timestamp);
            if !self.signed_payouts.insert(dedupe) {
                ContractError::DuplicatePayout
                    .panic("agent, payee, amount and timestamp already signed");
            }
        }
        if let Shape::PaypalCheckout(req) = &shape {
            // As shape 4: a suspended merchant is refused, and one (payee, amount, timestamp)
            // is charged at most once per agent, whatever the request_id or order_ref.
            let payee = paypal::normalize_receiver(&req.payee).unwrap_or_else(|e| e.panic("payee"));
            if self.is_suspended(
                &agent,
                &Payee::Paypal {
                    receiver: payee.clone(),
                },
            ) {
                ContractError::PayeeSuspended.panic("payee");
            }
            let dedupe =
                paypal_checkout::checkout_dedupe_key(&agent, &payee, &req.amount, req.timestamp);
            if !self.signed_payouts.insert(dedupe) {
                ContractError::DuplicatePayout
                    .panic("agent, payee, amount and timestamp already signed");
            }
        }
        let rail = built
            .rail
            .unwrap_or_else(|| env::panic_str("payment shape without a rail"));
        let period_start_ms = self.reserve_budget(&agent, &mandate, rail, built.amount);
        self.reserve_and_sign(key, kind, built, period_start_ms)
    }

    /// Shape 1. Callable by the agent itself (agent key), the relayer, or the owner: with
    /// `assertion: Some` in passkey mode (any account may submit it), or from the owner
    /// account with `None` in wallet mode. Agents and the relayer pass `None`. Works after
    /// revoke; at most one pending sweep per (agent, token). `evm_tx` is required for EURe
    /// (raw-transfer sweep) and must be `None` for USDC (EIP-3009).
    #[payable]
    pub fn sweep(
        &mut self,
        agent: AgentId,
        token: Token,
        amount: U128,
        request_id: String,
        evm_tx: Option<EvmTxParams>,
        assertion: Option<OwnerAssertion>,
    ) -> Promise {
        let (record, caller) = match assertion {
            Some(a) => {
                self.assert_owner(
                    "sweep",
                    &(&agent, &token, &amount, &request_id, &evm_tx),
                    Some(a),
                );
                (self.agent_record(&agent), Caller::Owner)
            }
            None if matches!(&self.owner, OwnerMode::Wallet { account } if *account == env::predecessor_account_id()) =>
            {
                self.assert_owner(
                    "sweep",
                    &(&agent, &token, &amount, &request_id, &evm_tx),
                    None,
                );
                (self.agent_record(&agent), Caller::Owner)
            }
            None if Some(env::predecessor_account_id()) == self.relayer => (
                self.agent_record(&agent),
                Caller::Relayer {
                    account: env::predecessor_account_id(),
                },
            ),
            None => {
                // `calling_agent` repeats this check, but would answer ERR_NOT_AGENT_KEY;
                // sweep must refuse a third account with its own code (interfaces.md §1).
                if env::predecessor_account_id() != env::current_account_id() {
                    ContractError::SweepCallerNotAllowed.panic("sweep caller");
                }
                let signer = self.calling_agent();
                if signer != agent {
                    ContractError::SweepCallerNotAllowed.panic("sweep caller");
                }
                (self.live_agent_record(&agent), Caller::Agent)
            }
        };
        validate_caller_request_id(&request_id);
        let key = RequestKey {
            agent: agent.clone(),
            caller: caller.clone(),
            request_id,
        };
        self.assert_new_request(&key);
        if !self.pending_sweeps.insert((agent.clone(), token)) {
            ContractError::SweepPending
                .panic("pending sweep already exists for this agent and token");
        }
        let amount = amount.0;
        let nonce = eip3009_nonce(&key, ShapeKind::Sweep);
        let now = now_secs();
        let built = shapes::sweep::build_sweep(&record, token, amount, evm_tx.as_ref(), nonce, now)
            .unwrap_or_else(|e| e.panic("sweep"));
        self.reserve_and_sign(key, ShapeKind::Sweep, built, 0)
    }

    /// Revokes the calling agent only: clears its mandate and map entry, deletes its key.
    /// Returns like `revoke`.
    pub fn revoke_self(&mut self) -> PromiseOrValue<RevokeResult> {
        let agent = self.calling_agent();
        self.revoke_agent(agent, RevokedBy::Agent)
    }

    // ---- Settlement reporter (PP-W1) ----

    /// Called only by `settlement_reporter` (`ERR_NOT_SETTLEMENT_REPORTER`), after it has
    /// verified a PayPal webhook with PayPal. `request_id` is an agent's `paypal` request,
    /// which must be `signed` (`ERR_REQUEST_NOT_FOUND`, `ERR_SHAPE_NOT_ALLOWED`,
    /// `ERR_BAD_TRANSITION`). Tighten-only: `completed` marks the receipt PayPal-confirmed; an
    /// adverse status (`failed`, `returned`, `blocked`, `refunded`, `reversed`, `disputed`)
    /// also suspends the payee for this agent's shape 4 until the owner calls
    /// `reinstate_payee`. It never changes a mandate, a cap, a budget or the reservation, and
    /// a `completed`/`unclaimed` report after an adverse one is ignored (returns false).
    pub fn report_settlement(
        &mut self,
        agent: AgentId,
        request_id: String,
        status: SettlementStatus,
        paypal_id: String,
    ) -> bool {
        self.record_settlement(agent, request_id, status, paypal_id)
    }

    // ---- Anyone ----

    /// Marks a `pending` reservation `unknown` once `MPC_TIMEOUT_MS` has passed (D4).
    pub fn expire_pending(&mut self, key: RequestKey) {
        self.expire(key);
    }

    // ---- Callbacks ----

    /// After `AddKey`: keeps the key-to-agent entry on success. On failure it removes the
    /// entry and retires the agent id like a revoke (the id may already have been used as a
    /// derivation path), logs `agent_add_failed` and returns false. Never panics, so the tx
    /// status shows success either way; clients read the return value or `get_agent`.
    #[private]
    pub fn on_agent_key_added(&mut self, agent: AgentId, public_key: PublicKey) -> bool {
        if key_action_succeeded() {
            return true;
        }
        if self.agents.get(&agent).and_then(|r| r.public_key.as_ref()) == Some(&public_key) {
            self.clear_agent(&agent);
        }
        MandateEvent::AgentAddFailed { agent, public_key }.emit();
        false
    }

    /// After `DeleteKey` (`revoke`, `revoke_self`). Never panics; reports whether the key
    /// receipt succeeded. The state was already cleared before the key action.
    #[private]
    pub fn on_agent_key_deleted(&mut self, agent: AgentId) -> RevokeResult {
        let key_deleted = key_action_succeeded();
        if key_deleted {
            if let Some(key) = self.undeleted_keys.remove(&agent) {
                self.undeleted_key_set.remove(&key);
            }
        }
        RevokeResult {
            agent,
            revoked: true,
            key_deleted,
        }
    }

    /// MPC callback for `link_agent`: on success, ecrecover-check the signer against the
    /// agent's `evm_address`, return the `Reservation` with the parsed signature. On
    /// failure or mismatch it marks the reservation `Unknown` from `Pending` only, resets
    /// `linked` if the reservation is `Pending`, `Unknown` or `Released` so the owner can
    /// retry (logging `agent_unlinked`), and leaves `Signed`, `Spent`, `Revoked` and their
    /// `linked` alone. Returns the reservation without a signature.
    /// `resolve_reservation(.., Released)` itself keeps `linked`: this callback may still
    /// bring a valid signature, and resetting earlier would allow a second link signature.
    /// Only a callback without one frees the agent.
    #[private]
    pub fn on_link_signature(&mut self, key: RequestKey) -> Reservation {
        let mut res = self.reservation(&key);
        let signature = request::callback_signature();
        let by_agent = signature.as_ref().is_some_and(|sig| {
            let expected = self
                .agents
                .get(&key.agent)
                .and_then(|r| r.evm_address.clone());
            expected.is_some() && request::signer_address(&res.digest, sig) == expected
        });
        match signature {
            Some(sig) if by_agent && res.status.can_become(RequestStatus::Signed) => {
                res.status = RequestStatus::Signed;
                res.signature = Some(sig.clone());
                self.requests.insert(key.clone(), res.clone());
                MandateEvent::SignatureRecorded {
                    key,
                    status: RequestStatus::Signed,
                    signature: sig,
                }
                .emit();
            }
            _ if matches!(
                res.status,
                RequestStatus::Pending | RequestStatus::Unknown | RequestStatus::Released
            ) =>
            {
                if res.status == RequestStatus::Pending {
                    let reason = if signature.is_some() {
                        UnknownReason::SignatureMismatch
                    } else {
                        UnknownReason::CallbackFailed
                    };
                    self.mark_unknown(&mut res, reason);
                }
                if let Some(mut record) = self.agents.get(&key.agent).cloned() {
                    if record.linked {
                        record.linked = false;
                        self.agents.insert(key.agent.clone(), record);
                        MandateEvent::AgentUnlinked {
                            agent: key.agent.clone(),
                            key: key.clone(),
                        }
                        .emit();
                    }
                }
            }
            _ => {}
        }
        res
    }

    /// MPC callback. Never panics: it reads the promise result itself, records `signed`
    /// (or `revoked`), or marks the reservation `unknown`.
    #[private]
    pub fn on_signature(&mut self, key: RequestKey) -> Reservation {
        self.record_signature(key)
    }

    // ---- Views ----

    pub fn get_config(&self) -> ConfigView {
        ConfigView {
            owner: self.owner.clone(),
            owner_nonce: self.owner_nonce,
            network: self.network.clone(),
            mpc_contract: self.mpc_contract.clone(),
            relayer: self.relayer.clone(),
            settlement_reporter: self.settlement_reporter.clone(),
        }
    }

    /// The latest settlement report of a request (PP-W1); `None` before one.
    pub fn get_settlement(&self, key: RequestKey) -> Option<Settlement> {
        self.settlements.get(&key).cloned()
    }

    /// The agent's suspended PayPal payees (PP-W1), in stored form.
    pub fn get_suspended_payees(&self, agent: AgentId) -> Vec<Payee> {
        self.suspended_payees
            .get(&agent)
            .cloned()
            .unwrap_or_default()
    }

    pub fn get_agent(&self, agent: AgentId) -> Option<AgentRecord> {
        self.agents.get(&agent).cloned()
    }

    /// The live agent a key belongs to; `None` once the agent is revoked.
    pub fn agent_of_key(&self, public_key: PublicKey) -> Option<AgentId> {
        self.agent_keys.get(&public_key).cloned()
    }

    /// Agents in the order they were added, revoked ones included.
    pub fn list_agents(&self, from_index: u32, limit: u32) -> Vec<AgentRecord> {
        self.agents
            .values()
            .skip(from_index as usize)
            .take(limit as usize)
            .cloned()
            .collect()
    }

    pub fn get_mandate(&self, agent: AgentId) -> Option<Mandate> {
        self.mandates.get(&agent).cloned()
    }

    pub fn get_payees(&self, agent: AgentId) -> Vec<Payee> {
        self.payees.get(&agent).cloned().unwrap_or_default()
    }

    /// The rail's current window (rolled forward to now, D7) and what counts against it.
    /// `None` without a mandate.
    pub fn get_budget(&self, agent: AgentId, rail: Rail) -> Option<BudgetView> {
        let mandate = self.mandates.get(&agent)?;
        let rail_mandate = match rail {
            Rail::X402 => &mandate.x402,
            Rail::Sepa => &mandate.sepa,
            Rail::Paypal => mandate.paypal.as_ref()?,
            Rail::PaypalRefund => mandate.paypal_refund.as_ref()?,
        };
        let (start, secs) = self.budget_window(&agent, rail, rail_mandate.period_secs, now_ms())?;
        let reserved = self.budget_used_in(&agent, rail, start);
        Some(BudgetView {
            rail,
            period_start_ms: start,
            period_secs: secs,
            budget: rail_mandate.budget,
            reserved: U128(reserved),
        })
    }

    pub fn get_request(&self, key: RequestKey) -> Option<Reservation> {
        self.requests.get(&key).cloned()
    }

    /// Requests of one agent, oldest first.
    pub fn list_requests(&self, agent: AgentId, from_index: u32, limit: u32) -> Vec<Reservation> {
        self.requests_of(&agent, from_index, limit)
    }
}

impl Contract {
    /// Shared by `revoke` and `revoke_self`: clear the state first, then delete the key in a
    /// second receipt whose outcome `on_agent_key_deleted` reports (spikes/deletekey).
    fn revoke_agent(&mut self, agent: AgentId, by: RevokedBy) -> PromiseOrValue<RevokeResult> {
        let key = if self.agent_record(&agent).revoked {
            // Retry a failed DeleteKey, unless the key now belongs to a live agent.
            self.undeleted_keys
                .get(&agent)
                .cloned()
                .filter(|k| !self.agent_keys.contains_key(k))
        } else {
            let key = self.clear_agent(&agent);
            MandateEvent::AgentRevoked {
                agent: agent.clone(),
                by,
            }
            .emit();
            key
        };
        match key {
            Some(key) => {
                self.undeleted_keys.insert(agent.clone(), key.clone());
                self.undeleted_key_set.insert(key.clone());
                let me = env::current_account_id();
                PromiseOrValue::Promise(
                    Promise::new(me.clone()).delete_key(key).then(
                        Self::ext(me)
                            .with_static_gas(KEY_CALLBACK_GAS)
                            .on_agent_key_deleted(agent),
                    ),
                )
            }
            None => PromiseOrValue::Value(RevokeResult {
                agent,
                revoked: true,
                key_deleted: false,
            }),
        }
    }
}

/// The decoded field a shape builder's error is about, for the panic detail (§7).
fn error_field(err: ContractError) -> &'static str {
    use ContractError::*;
    match err {
        WrongScheme => "scheme",
        PayeeNotAllowed => "payTo",
        WrongAsset => "asset",
        WrongNetwork => "network",
        InvalidTimeout => "maxTimeoutSeconds",
        BelowMinimum | OverPerPaymentCap | InvalidAmount => "amount",
        IbanNotAllowed | InvalidIban => "iban",
        PaypalPayeeNotAllowed | InvalidPaypalPayee => "payee",
        InvalidOrderRef => "order_ref",
        InvalidCaptureId => "capture_id",
        ShapeNotAllowed => "mandate.paypal",
        TimestampStale | TimestampFuture => "timestamp",
        DuplicatePayout => "iban, amount and timestamp",
        _ => "mandate",
    }
}
