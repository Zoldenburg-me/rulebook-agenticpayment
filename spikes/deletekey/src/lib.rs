//! S-i spike: the contract adds and deletes function-call keys on its own
//! account from inside its own methods, alongside ordinary state changes.
use near_sdk::store::LookupMap;
use near_sdk::{env, near, require, AccountId, Allowance, NearToken, PanicOnDefault, Promise, PublicKey};

const AGENT_METHODS: &str = "request_signature,sweep,revoke_self";
const KEY_ALLOWANCE: NearToken = NearToken::from_millinear(250);

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    owner: AccountId,
    /// agent key -> agent name; stands in for the real mandate state.
    agents: LookupMap<PublicKey, String>,
}

#[near]
impl Contract {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self { owner, agents: LookupMap::new(b"a") }
    }

    /// Owner call: record the agent and add its function-call key on this account, one tx.
    pub fn add_agent(&mut self, agent: String, public_key: PublicKey) -> Promise {
        self.assert_owner();
        require!(!self.agents.contains_key(&public_key), "key already registered");
        self.agents.insert(public_key.clone(), agent.clone());
        env::log_str(&format!("add_agent {agent}"));
        Promise::new(env::current_account_id()).add_access_key_allowance(
            public_key,
            Allowance::limited(KEY_ALLOWANCE).unwrap(),
            env::current_account_id(),
            AGENT_METHODS,
        )
    }

    /// Owner call: clear the agent's state and delete its key, one tx.
    pub fn revoke(&mut self, public_key: PublicKey) -> Promise {
        self.assert_owner();
        let agent = self.agents.remove(&public_key).unwrap_or_else(|| env::panic_str("unknown key"));
        env::log_str(&format!("revoke {agent}"));
        Promise::new(env::current_account_id()).delete_key(public_key)
    }

    /// Agent call, signed with the agent's own function-call key: clear and delete only that key.
    pub fn revoke_self(&mut self) -> Promise {
        require!(env::predecessor_account_id() == env::current_account_id(), "agent key only");
        let pk = env::signer_account_pk();
        let agent = self.agents.remove(&pk).unwrap_or_else(|| env::panic_str("unknown key"));
        env::log_str(&format!("revoke_self {agent}"));
        Promise::new(env::current_account_id()).delete_key(pk)
    }

    /// Stand-in for the real method, so the agent key has something to call.
    pub fn request_signature(&self) -> String {
        let pk = env::signer_account_pk();
        self.agents.get(&pk).cloned().unwrap_or_else(|| env::panic_str("unknown key"))
    }

    pub fn sweep(&self) {}

    pub fn agent_of(&self, public_key: PublicKey) -> Option<String> {
        self.agents.get(&public_key).cloned()
    }

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
    }
}
