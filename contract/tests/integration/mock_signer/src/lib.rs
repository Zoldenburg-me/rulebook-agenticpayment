//! Mock `v1.signer` for the sandbox. `sign` takes the real request shape
//! (`{"request":{"payload_v2":{"Ecdsa":hex},"path":..,"domain_id":0}}`, 1 yoctoNEAR) and, like
//! the real MPC, parks it with yield/resume: the caller's callback runs only when the test
//! calls `respond` with the response bytes (the harness signs off chain with a key derived
//! the MPC way), or with a failure when the yield times out (about 200 blocks).
//!
//! Modes: `respond` (park and wait for `respond`), `hold` (like `respond`, but a yield that
//! times out is parked again, so a request stays pending past the contract's
//! `MPC_TIMEOUT_MS`) or `fail` (`sign` panics, so the caller's callback sees a failed promise
//! at once). The mode is read when `sign` runs and when a yield times out.
//! Every method is open to anyone: this contract only exists in the sandbox.

use near_sdk::store::IterableMap;
use near_sdk::{env, near, AccountId, Gas, GasWeight, NearToken, PanicOnDefault, PromiseIndex};

/// Gas for `on_response`, the yield callback.
const RESPONSE_GAS: Gas = Gas::from_tgas(10);
/// Gas `on_response` keeps for itself when `hold` parks a timed-out request again; the rest
/// goes to the next `on_response`.
const REPARK_RESERVE: Gas = Gas::from_tgas(6);
/// Register `promise_yield_create` writes the data id into.
const DATA_ID_REGISTER: u64 = 0;
/// Longest response `on_response` passes on.
const MAX_RESPONSE_LEN: usize = 4096;

#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Park the request until `respond` (or the yield timeout).
    Respond,
    /// Park the request until `respond`, parking it again each time the yield times out.
    Hold,
    /// `sign` panics.
    Fail,
}

/// One parked `sign` call.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug)]
pub struct PendingSign {
    pub id: u64,
    /// The account that called `sign`; the MPC derives the key from (predecessor, path).
    pub predecessor: AccountId,
    pub path: String,
    /// The 32-byte payload, lowercase hex without `0x`, exactly as received.
    pub payload: String,
    pub domain_id: u32,
    /// Yield data id, hex.
    pub data_id: String,
}

#[near(serializers = [json])]
pub struct SignRequest {
    pub payload_v2: PayloadV2,
    pub path: String,
    pub domain_id: u32,
}

#[near(serializers = [json])]
pub struct PayloadV2 {
    #[serde(rename = "Ecdsa")]
    pub ecdsa: String,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct MockSigner {
    mode: Mode,
    next_id: u64,
    pending: IterableMap<u64, PendingSign>,
}

#[near]
impl MockSigner {
    #[init]
    pub fn new() -> Self {
        Self {
            mode: Mode::Respond,
            next_id: 0,
            pending: IterableMap::new(b"p"),
        }
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The real MPC's entry point. Returns, through the yield, whatever `respond` passes in.
    #[payable]
    pub fn sign(&mut self, request: SignRequest) {
        if env::attached_deposit() < NearToken::from_yoctonear(1) {
            env::panic_str("mock signer: attach 1 yoctoNEAR");
        }
        if self.mode == Mode::Fail {
            env::panic_str("mock signer: fail mode");
        }
        let payload = request.payload_v2.ecdsa;
        if payload.len() != 64 || !payload.bytes().all(|b| b.is_ascii_hexdigit()) {
            env::panic_str("mock signer: payload must be 32 bytes hex");
        }
        if request.domain_id != 0 {
            env::panic_str("mock signer: domain_id must be 0");
        }
        let id = self.next_id;
        self.next_id += 1;
        let args = near_sdk::serde_json::to_vec(&near_sdk::serde_json::json!({ "id": id }))
            .unwrap_or_else(|_| env::panic_str("args"));
        // `hold` passes on all the gas it can spare, for the re-parks.
        let gas = match self.mode {
            Mode::Hold => remaining_gas(),
            _ => RESPONSE_GAS,
        };
        let (index, data_id) = park(args, gas);
        self.pending.insert(
            id,
            PendingSign {
                id,
                predecessor: env::predecessor_account_id(),
                path: request.path,
                payload: payload.to_ascii_lowercase(),
                domain_id: request.domain_id,
                data_id,
            },
        );
        env::promise_return(index);
    }

    /// Resumes parked request `id` with `response` as the raw bytes `sign` returns. Returns
    /// false if the yield is gone (already resumed or timed out).
    pub fn respond(&mut self, id: u64, response: String) -> bool {
        let pending = self
            .pending
            .get(&id)
            .unwrap_or_else(|| env::panic_str("mock signer: no such request"));
        let data_id: [u8; 32] = hex::decode(&pending.data_id)
            .ok()
            .and_then(|d| d.try_into().ok())
            .unwrap_or_else(|| env::panic_str("mock signer: bad data id"));
        env::promise_yield_resume(&data_id, response.as_bytes())
    }

    /// Yield callback: hands the response on as `sign`'s return value, or fails on timeout.
    #[private]
    pub fn on_response(&mut self, id: u64) {
        match env::promise_result_checked(0, MAX_RESPONSE_LEN) {
            Ok(bytes) => {
                self.pending.remove(&id);
                env::value_return(&bytes);
            }
            Err(_) if self.mode == Mode::Hold => {
                // Timed out: park it again with this call's remaining gas.
                let args = near_sdk::serde_json::to_vec(&near_sdk::serde_json::json!({ "id": id }))
                    .unwrap_or_else(|_| env::panic_str("args"));
                let (index, data_id) = park(args, remaining_gas());
                let mut pending = self
                    .pending
                    .get(&id)
                    .cloned()
                    .unwrap_or_else(|| env::panic_str("mock signer: no such request"));
                pending.data_id = data_id;
                self.pending.insert(id, pending);
                env::promise_return(index);
            }
            Err(_) => env::panic_str("mock signer: request timed out"),
        }
    }

    /// Parked requests, oldest first.
    pub fn pending_requests(&self) -> Vec<PendingSign> {
        self.pending.values().cloned().collect()
    }
}

/// This call's unused gas minus `REPARK_RESERVE`.
fn remaining_gas() -> Gas {
    env::prepaid_gas()
        .saturating_sub(env::used_gas())
        .saturating_sub(REPARK_RESERVE)
}

/// A yield whose callback is `on_response(args)` with `gas`; returns its index and data id (hex).
fn park(args: Vec<u8>, gas: Gas) -> (PromiseIndex, String) {
    let index = env::promise_yield_create("on_response", args, gas, GasWeight(0), DATA_ID_REGISTER);
    let data_id = env::read_register(DATA_ID_REGISTER)
        .unwrap_or_else(|| env::panic_str("mock signer: no data id"));
    (index, hex::encode(data_id))
}
