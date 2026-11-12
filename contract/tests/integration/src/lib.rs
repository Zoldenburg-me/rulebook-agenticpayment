//! T1 integration harness: the mandate contract in a near-workspaces sandbox with a passkey
//! owner (software P-256 key) and a mock `v1.signer` (`mock_signer/`) that answers, fails or
//! leaves a request pending. T2's adversarial suite reuses these helpers.
//!
//! Run: `cargo test --manifest-path contract/tests/integration/Cargo.toml`. Needs the
//! near-sandbox binary: near-workspaces downloads it at build time on linux-x86_64,
//! linux-aarch64 and darwin-arm64; elsewhere set `NEAR_SANDBOX_BIN_PATH` to a local build
//! for both build and run (spikes/passkey/RESULT.md, "Intel Mac").

pub mod fixtures;
pub mod mpc;
pub mod passkey;

use std::time::Duration;

use anyhow::{bail, Context};
use mandate::types::{
    BudgetView, EvmTxParams, Mandate, OwnerAssertion, Payee, Rail, RequestKey, RequestStatus,
    Reservation, ResolveOutcome, RevokeResult, Shape, SweepConfig, Token, MPC_CONTRACT,
};
use near_sdk::serde::Deserialize;
use near_sdk::serde_json::{json, Value};
use near_workspaces::network::Sandbox;
use near_workspaces::operations::CallTransaction;
use near_workspaces::result::{ExecutionFinalResult, ExecutionSuccess};
use near_workspaces::types::{
    AccessKey, AccessKeyInfo, AccountDetailsPatch, Gas, KeyType, NearToken, PublicKey, SecretKey,
};
use near_workspaces::{Account, Contract, Worker};
use tokio::sync::OnceCell;

pub use passkey::Passkey;

/// The `network` string owner challenges bind.
pub const NETWORK: &str = "testnet";
/// Owner assertions expire this long after the current block (the contract allows 600 s).
pub const ASSERTION_TTL_SECS: u64 = 300;
/// Gas for every call the harness sends, except agent-key calls.
pub const CALL_GAS: Gas = Gas::from_tgas(300);
/// Gas for agent-key calls: enough for the 50 Tgas MPC call and the 20 Tgas callback. A
/// pending request holds its prepaid gas against the key's 1 NEAR allowance until it
/// completes, and sandbox gas costs 10x testnet's, so 300 Tgas would allow only three.
pub const AGENT_GAS: Gas = Gas::from_tgas(120);

/// A `sign` call parked in the mock signer (`mock_signer::PendingSign`).
#[derive(Clone, Debug, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct PendingSign {
    pub id: u64,
    pub predecessor: String,
    pub path: String,
    /// 32 bytes, lowercase hex without `0x`.
    pub payload: String,
    pub domain_id: u32,
}

/// What the mock signer does with the next `sign` call.
#[derive(Clone, Copy, Debug)]
pub enum SignerMode {
    /// Park it until `respond_*` (or the yield timeout, about 200 blocks).
    Respond,
    /// Park it until `respond_*`, parking it again whenever the yield times out, so it stays
    /// pending past `MPC_TIMEOUT_MS` (sandbox fast-forward runs at about 0.3 s per block).
    /// Gas-bounded: each re-park runs on what is left of the `sign` call's prepaid gas, so
    /// a held request survives only a few yield timeouts. Once the gas is spent the yield
    /// times out for good and the contract's callback sees a failure, as in `Respond`.
    Hold,
    /// Panic in `sign`: the contract's callback sees a failed promise.
    Fail,
}

/// Both wasm builds, once per test binary.
async fn wasms() -> anyhow::Result<&'static (Vec<u8>, Vec<u8>)> {
    static WASMS: OnceCell<(Vec<u8>, Vec<u8>)> = OnceCell::const_new();
    WASMS
        .get_or_try_init(|| async {
            let root = env!("CARGO_MANIFEST_DIR");
            let mandate = near_workspaces::compile_project(&format!("{root}/../.."))
                .await
                .context("build the mandate contract")?;
            let signer = near_workspaces::compile_project(&format!("{root}/mock_signer"))
                .await
                .context("build the mock signer")?;
            Ok((mandate, signer))
        })
        .await
}

/// The call's success, or an error carrying its failure.
pub fn expect_ok(result: ExecutionFinalResult) -> anyhow::Result<ExecutionSuccess> {
    Ok(result.into_result()?)
}

/// The failure text of a call that must fail, whether the contract panicked or the
/// transaction itself was refused (a function-call key calling a method it may not, for
/// instance). Errors if the call succeeded.
pub fn rejection<E: std::fmt::Debug>(
    result: Result<ExecutionFinalResult, E>,
) -> anyhow::Result<String> {
    match result {
        Err(e) => Ok(format!("{e:?}")),
        Ok(outcome) => match outcome.into_result() {
            Err(e) => Ok(format!("{e:?}")),
            Ok(ok) => bail!("call succeeded but must fail: {:?}", ok.raw_bytes()),
        },
    }
}

/// The sandbox, the deployed contracts and the owner.
pub struct Harness {
    pub worker: Worker<Sandbox>,
    /// The mandate contract; agent keys are added to this account.
    pub mandate: Contract,
    /// The mock MPC at `v1.signer-prod.testnet`, the only `mpc_contract` `new` accepts.
    pub signer: Contract,
    /// Submits passkey owner calls (any account may, the assertion is what counts).
    pub submitter: Account,
    pub owner: Passkey,
}

impl Harness {
    /// Starts a sandbox, deploys the mock signer and the mandate contract and calls
    /// `new(passkey owner, "testnet", "v1.signer-prod.testnet")` from the contract account.
    pub async fn new() -> anyhow::Result<Self> {
        let h = Self::deployed().await?;
        expect_ok(h.init_from(h.mandate.as_account()).await?)?;
        Ok(h)
    }

    /// Like `new`, but the mandate contract is not initialized yet.
    pub async fn deployed() -> anyhow::Result<Self> {
        let (mandate_wasm, signer_wasm) = wasms().await?;
        let worker = near_workspaces::sandbox().await?;
        let root = worker.root_account()?;
        let sub = |name: &'static str| {
            root.create_subaccount(name)
                .initial_balance(NearToken::from_near(50))
                .transact()
        };
        // `v1.signer-prod.testnet` is not a sub-account of the sandbox root, so the mock is
        // patched into state under that id.
        let signer_id: near_workspaces::AccountId = MPC_CONTRACT.parse()?;
        let signer_key = SecretKey::from_random(KeyType::ED25519);
        worker
            .patch(&signer_id)
            .account(
                AccountDetailsPatch::default()
                    .balance(NearToken::from_near(50))
                    .locked(NearToken::from_near(0))
                    .storage_usage(0),
            )
            .access_key(signer_key.public_key(), AccessKey::full_access())
            .code(signer_wasm)
            .transact()
            .await?;
        let signer = Contract::from_secret_key(signer_id, signer_key, &worker);
        expect_ok(signer.call("new").transact().await?)?;

        let mandate = sub("mandate").await?.into_result()?;
        let mandate = mandate.deploy(mandate_wasm).await?.into_result()?;
        let owner = Passkey::default();
        let submitter = sub("submitter").await?.into_result()?;
        Ok(Self {
            worker,
            mandate,
            signer,
            submitter,
            owner,
        })
    }

    /// Calls `new(passkey owner, "testnet", "v1.signer-prod.testnet")` from `caller`; `new`
    /// is `#[private]`, so only the contract account itself succeeds.
    pub async fn init_from(&self, caller: &Account) -> anyhow::Result<ExecutionFinalResult> {
        Ok(caller
            .call(self.mandate.id(), "new")
            .args_json(json!({
                "owner": self.owner.owner_mode(),
                "network": NETWORK,
                "mpc_contract": MPC_CONTRACT,
            }))
            .transact()
            .await?)
    }

    // ---- time ----

    /// Unix seconds of the latest block.
    pub async fn now_secs(&self) -> anyhow::Result<u64> {
        Ok(self.worker.view_block().await?.timestamp() / 1_000_000_000)
    }

    /// Produces `blocks` blocks at once.
    pub async fn advance_blocks(&self, blocks: u64) -> anyhow::Result<()> {
        Ok(self.worker.fast_forward(blocks).await?)
    }

    /// Fast-forwards until block time has moved at least `secs` seconds.
    pub async fn advance_secs(&self, secs: u64) -> anyhow::Result<()> {
        let target = self.now_secs().await? + secs;
        loop {
            let now = self.now_secs().await?;
            if now >= target {
                return Ok(());
            }
            self.advance_blocks((target - now).max(1)).await?;
        }
    }

    // ---- owner (passkey) ----

    /// The contract's last used owner nonce.
    pub async fn owner_nonce(&self) -> anyhow::Result<u64> {
        let config: Value = self.mandate.view("get_config").await?.json()?;
        config["owner_nonce"]
            .as_u64()
            .context("get_config.owner_nonce")
    }

    /// A fresh assertion for `method` with the next nonce, valid `ASSERTION_TTL_SECS`.
    pub async fn assertion(
        &self,
        method: &str,
        borsh_args: &[u8],
    ) -> anyhow::Result<OwnerAssertion> {
        let nonce = self.owner_nonce().await? + 1;
        let expires_at = self.now_secs().await? + ASSERTION_TTL_SECS;
        Ok(self.owner.assert(
            self.mandate.id().as_str(),
            NETWORK,
            method,
            borsh_args,
            nonce,
            expires_at,
        ))
    }

    /// Sends `method(json_args + assertion)` from the submitter. `borsh_args` is the
    /// borsh-encoded argument tuple without `assertion`, in parameter order (what the
    /// challenge binds). The result is returned as is; wrap it in `expect_ok` to require
    /// success.
    pub async fn owner_call(
        &self,
        method: &str,
        borsh_args: Vec<u8>,
        json_args: Value,
    ) -> anyhow::Result<ExecutionFinalResult> {
        let assertion = self.assertion(method, &borsh_args).await?;
        self.owner_call_with(method, json_args, assertion).await
    }

    /// Sends `method(json_args + assertion)` with a given (possibly bad) assertion.
    pub async fn owner_call_with(
        &self,
        method: &str,
        mut json_args: Value,
        assertion: OwnerAssertion,
    ) -> anyhow::Result<ExecutionFinalResult> {
        json_args["assertion"] = near_sdk::serde_json::to_value(assertion)?;
        Ok(self
            .submitter
            .call(self.mandate.id(), method)
            .args_json(json_args)
            .gas(CALL_GAS)
            .transact()
            .await?)
    }

    /// `add_agent`; returns `on_agent_key_added`'s result (false if `AddKey` failed).
    pub async fn add_agent(
        &self,
        agent: &str,
        public_key: &PublicKey,
        sweep_config: &SweepConfig,
        evm_address: &str,
    ) -> anyhow::Result<bool> {
        let pk: near_sdk::PublicKey = public_key.to_string().parse()?;
        let agent = agent.to_string();
        let evm = evm_address.to_string();
        let borsh = near_sdk::borsh::to_vec(&(&agent, &pk, sweep_config, &evm))?;
        let args = json!({
            "agent": agent,
            "public_key": pk,
            "sweep_config": sweep_config,
            "evm_address": evm,
        });
        Ok(expect_ok(self.owner_call("add_agent", borsh, args).await?)?.json()?)
    }

    pub async fn set_mandate(&self, agent: &str, mandate: &Mandate) -> anyhow::Result<()> {
        let agent = agent.to_string();
        let borsh = near_sdk::borsh::to_vec(&(&agent, mandate))?;
        let args = json!({ "agent": agent, "mandate": mandate });
        expect_ok(self.owner_call("set_mandate", borsh, args).await?)?;
        Ok(())
    }

    pub async fn add_payee(&self, agent: &str, payee: &Payee) -> anyhow::Result<()> {
        let agent = agent.to_string();
        let borsh = near_sdk::borsh::to_vec(&(&agent, payee))?;
        let args = json!({ "agent": agent, "payee": payee });
        expect_ok(self.owner_call("add_payee", borsh, args).await?)?;
        Ok(())
    }

    /// Adds `agent` with a new key and its derived EVM address, sets the fixture mandate and
    /// allowlists `fixtures::PAY_TO`. Returns the agent's account (its key on the contract).
    pub async fn setup_agent(&self, agent: &str) -> anyhow::Result<Account> {
        let key = Self::agent_key();
        let evm = self.agent_evm_address(agent);
        if !self
            .add_agent(agent, &key.public_key(), &fixtures::sweep_config(), &evm)
            .await?
        {
            bail!("AddKey failed for {agent}");
        }
        self.set_mandate(agent, &fixtures::mandate()).await?;
        self.add_payee(agent, &fixtures::pay_to()).await?;
        Ok(self.agent_account(&key))
    }

    pub async fn remove_payee(&self, agent: &str, payee: &Payee) -> anyhow::Result<()> {
        let agent = agent.to_string();
        let borsh = near_sdk::borsh::to_vec(&(&agent, payee))?;
        let args = json!({ "agent": agent, "payee": payee });
        expect_ok(self.owner_call("remove_payee", borsh, args).await?)?;
        Ok(())
    }

    /// `set_relayer(account)`.
    pub async fn set_relayer(&self, account: Option<&Account>) -> anyhow::Result<()> {
        let account: Option<near_sdk::AccountId> =
            account.map(|a| a.id().as_str().parse()).transpose()?;
        let borsh = near_sdk::borsh::to_vec(&(&account,))?;
        let args = json!({ "account": account });
        expect_ok(self.owner_call("set_relayer", borsh, args).await?)?;
        Ok(())
    }

    /// Owner `revoke(agent)`; the tx runs the `DeleteKey` and `on_agent_key_deleted` too.
    pub async fn revoke(&self, agent: &str) -> anyhow::Result<RevokeResult> {
        let agent = agent.to_string();
        let borsh = near_sdk::borsh::to_vec(&(&agent,))?;
        let args = json!({ "agent": agent });
        Ok(expect_ok(self.owner_call("revoke", borsh, args).await?)?.json()?)
    }

    /// Owner `resolve_reservation(key, outcome)`; the result as is.
    pub async fn resolve(
        &self,
        key: &RequestKey,
        outcome: ResolveOutcome,
    ) -> anyhow::Result<ExecutionFinalResult> {
        let borsh = near_sdk::borsh::to_vec(&(key, &outcome))?;
        let args = json!({ "key": key, "outcome": outcome });
        self.owner_call("resolve_reservation", borsh, args).await
    }

    /// Owner `sweep` with a passkey assertion from the submitter, ready to send: with
    /// `transact_async` (the tx completes only after the MPC answers) or, for a call that
    /// must fail, `transact`.
    pub async fn owner_sweep(
        &self,
        agent: &str,
        token: Token,
        amount: u128,
        request_id: &str,
        evm_tx: Option<EvmTxParams>,
    ) -> anyhow::Result<CallTransaction> {
        let agent = agent.to_string();
        let request_id = request_id.to_string();
        let amount = near_sdk::json_types::U128(amount);
        let borsh = near_sdk::borsh::to_vec(&(&agent, &token, &amount, &request_id, &evm_tx))?;
        let assertion = self.assertion("sweep", &borsh).await?;
        Ok(self
            .submitter
            .call(self.mandate.id(), "sweep")
            .args_json(json!({
                "agent": agent,
                "token": token,
                "amount": amount,
                "request_id": request_id,
                "evm_tx": evm_tx,
                "assertion": assertion,
            }))
            .gas(CALL_GAS))
    }

    // ---- other accounts ----

    /// A new sandbox account `name.<root>` with 50 NEAR.
    pub async fn account(&self, name: &str) -> anyhow::Result<Account> {
        Ok(self
            .worker
            .root_account()?
            .create_subaccount(name)
            .initial_balance(NearToken::from_near(50))
            .transact()
            .await?
            .into_result()?)
    }

    /// `sweep` with `assertion: None` from `caller` (an agent key, the relayer or anyone),
    /// ready to send like `owner_sweep`.
    pub fn sweep_from(
        &self,
        caller: &Account,
        agent: &str,
        token: Token,
        amount: u128,
        request_id: &str,
        evm_tx: Option<EvmTxParams>,
    ) -> CallTransaction {
        caller
            .call(self.mandate.id(), "sweep")
            .args_json(json!({
                "agent": agent,
                "token": token,
                "amount": near_sdk::json_types::U128(amount),
                "request_id": request_id,
                "evm_tx": evm_tx,
            }))
            .gas(AGENT_GAS)
    }

    /// `expire_pending(key)` from `caller`; the result as is.
    pub async fn expire_pending(
        &self,
        caller: &Account,
        key: &RequestKey,
    ) -> anyhow::Result<ExecutionFinalResult> {
        Ok(caller
            .call(self.mandate.id(), "expire_pending")
            .args_json(json!({ "key": key }))
            .gas(CALL_GAS)
            .transact()
            .await?)
    }

    /// The access keys on the mandate contract's account.
    pub async fn contract_keys(&self) -> anyhow::Result<Vec<AccessKeyInfo>> {
        Ok(self.worker.view_access_keys(self.mandate.id()).await?)
    }

    // ---- agent ----

    /// A new random agent key (ed25519).
    pub fn agent_key() -> SecretKey {
        SecretKey::from_random(near_workspaces::types::KeyType::ED25519)
    }

    /// Signs as the contract account with the agent's function-call key, as agents do.
    pub fn agent_account(&self, key: &SecretKey) -> Account {
        Account::from_secret_key(self.mandate.id().clone(), key.clone(), &self.worker)
    }

    /// `request_signature` with the agent key, ready to send. For a request that must fail,
    /// send it with `transact`: an async send of a refused tx only times out.
    pub fn request_tx(&self, agent: &Account, request_id: &str, shape: &Shape) -> CallTransaction {
        agent
            .call(self.mandate.id(), "request_signature")
            .args_json(json!({ "request_id": request_id, "shape": shape }))
            .gas(AGENT_GAS)
    }

    /// Sends `request_signature` with the agent key and returns without waiting: with the
    /// mock in `Respond` mode the tx completes only after `respond_*`. Await the returned
    /// status for `on_signature`'s `Reservation`.
    pub async fn request_signature(
        &self,
        agent: &Account,
        request_id: &str,
        shape: &Shape,
    ) -> anyhow::Result<near_workspaces::operations::TransactionStatus> {
        Ok(agent
            .call(self.mandate.id(), "request_signature")
            .args_json(json!({ "request_id": request_id, "shape": shape }))
            .gas(AGENT_GAS)
            .transact_async()
            .await?)
    }

    // ---- mock signer ----

    pub async fn set_signer_mode(&self, mode: SignerMode) -> anyhow::Result<()> {
        let mode = match mode {
            SignerMode::Respond => "respond",
            SignerMode::Hold => "hold",
            SignerMode::Fail => "fail",
        };
        expect_ok(
            self.signer
                .call("set_mode")
                .args_json(json!({ "mode": mode }))
                .transact()
                .await?,
        )?;
        Ok(())
    }

    /// `sign` calls the mock holds, oldest first.
    pub async fn pending_signs(&self) -> anyhow::Result<Vec<PendingSign>> {
        Ok(self.signer.view("pending_requests").await?.json()?)
    }

    /// Waits (up to about 30 s) until the mock holds `n` parked `sign` calls; returns them.
    pub async fn wait_for_signs(&self, n: usize) -> anyhow::Result<Vec<PendingSign>> {
        for _ in 0..60 {
            let pending = self.pending_signs().await?;
            if pending.len() >= n {
                return Ok(pending);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        bail!("mock signer never received {n} sign call(s)")
    }

    /// Answers a parked call with a valid signature from the key derived for its
    /// (predecessor, path).
    pub async fn respond_signed(&self, pending: &PendingSign) -> anyhow::Result<()> {
        let payload: [u8; 32] = hex::decode(&pending.payload)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("payload is not 32 bytes"))?;
        let response = mpc::sign_response(&pending.predecessor, &pending.path, &payload);
        self.respond_raw(pending.id, &response).await
    }

    /// Answers a parked call with arbitrary bytes (a malformed response, for instance).
    pub async fn respond_raw(&self, id: u64, response: &str) -> anyhow::Result<()> {
        let resumed: bool = expect_ok(
            self.signer
                .call("respond")
                .args_json(json!({ "id": id, "response": response }))
                .transact()
                .await?,
        )?
        .json()?;
        if !resumed {
            bail!("sign call {id} could not be resumed (already answered or timed out)");
        }
        Ok(())
    }

    /// Answers the parked `sign` call for `key`'s digest with a valid signature and waits
    /// until the callback has moved the reservation out of `pending`; returns it.
    pub async fn respond_for(&self, key: &RequestKey) -> anyhow::Result<Reservation> {
        let digest = self
            .get_request(key)
            .await?
            .context("no reservation to respond for")?
            .digest;
        let mut sign = None;
        for _ in 0..60 {
            sign = self
                .pending_signs()
                .await?
                .into_iter()
                .find(|p| format!("0x{}", p.payload) == digest);
            if sign.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        let sign =
            sign.with_context(|| format!("the mock never received {key:?} (digest {digest})"))?;
        let before = self.get_request(key).await?.context("reservation")?.status;
        self.respond_signed(&sign).await?;
        self.wait_for_change(key, before).await
    }

    /// Polls (up to about 30 s) until `key`'s status is no longer `from`; returns it.
    pub async fn wait_for_change(
        &self,
        key: &RequestKey,
        from: RequestStatus,
    ) -> anyhow::Result<Reservation> {
        for _ in 0..60 {
            let res = self.get_request(key).await?.context("reservation")?;
            if res.status != from {
                return Ok(res);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        bail!("{key:?} stayed {from:?}")
    }

    // ---- views ----

    pub async fn get_request(&self, key: &RequestKey) -> anyhow::Result<Option<Reservation>> {
        Ok(self
            .mandate
            .view("get_request")
            .args_json(json!({ "key": key }))
            .await?
            .json()?)
    }

    pub async fn get_budget(&self, agent: &str, rail: Rail) -> anyhow::Result<Option<BudgetView>> {
        Ok(self
            .mandate
            .view("get_budget")
            .args_json(json!({ "agent": agent, "rail": rail }))
            .await?
            .json()?)
    }

    pub async fn get_agent(
        &self,
        agent: &str,
    ) -> anyhow::Result<Option<mandate::types::AgentRecord>> {
        Ok(self
            .mandate
            .view("get_agent")
            .args_json(json!({ "agent": agent }))
            .await?
            .json()?)
    }

    pub async fn get_mandate(&self, agent: &str) -> anyhow::Result<Option<Mandate>> {
        Ok(self
            .mandate
            .view("get_mandate")
            .args_json(json!({ "agent": agent }))
            .await?
            .json()?)
    }

    /// The EVM address the mock MPC signs for on behalf of `agent` (path = agent id).
    pub fn agent_evm_address(&self, agent: &str) -> String {
        mpc::derived_address(self.mandate.id().as_str(), agent)
    }
}
