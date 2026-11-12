//! Types that cross the contract boundary: method arguments, return values, views and
//! event payloads. `docs/interfaces.md` documents each one with example JSON; the tests in
//! `interface_tests.rs` parse those examples, so the two cannot drift.

use near_sdk::json_types::{Base64VecU8, U128};
use near_sdk::{near, AccountId, PublicKey};

/// An agent's id, chosen by the owner in `add_agent`. It is also the agent's Chain
/// Signatures derivation path, so it is never reused, even after revoke.
pub type AgentId = String;

/// `0x` plus 40 hex digits. The contract stores and compares addresses in lowercase.
pub type EvmAddress = String;

/// The only EVM chain the contract accepts (Base Sepolia): the repo allows testnets only,
/// and the agent EOA is the same address on every EVM chain, so a mainnet `chain_id` would
/// let the MPC sign real-money transfers. `sweep_config` and `mandate` must use it
/// (`ERR_WRONG_NETWORK`).
pub const BASE_SEPOLIA_CHAIN_ID: u64 = 84532;

/// Default EIP-712 domain `name` and `version` of the `usdc_address` token: USDC on Base
/// Sepolia (spikes/x402). A mandate or sweep config without them (older JSON) gets these.
pub const DEFAULT_EIP712_NAME: &str = "USDC";
pub const DEFAULT_EIP712_VERSION: &str = "2";
/// Longest EIP-712 domain `name` and `version` the contract accepts (printable ASCII).
pub const MAX_EIP712_NAME_LEN: usize = 32;
pub const MAX_EIP712_VERSION_LEN: usize = 8;

fn default_eip712_name() -> String {
    DEFAULT_EIP712_NAME.to_string()
}

fn default_eip712_version() -> String {
    DEFAULT_EIP712_VERSION.to_string()
}

/// Methods the agent's function-call key may call; `add_agent` adds the key with these.
pub const AGENT_METHOD_NAMES: [&str; 3] = ["request_signature", "sweep", "revoke_self"];
/// Fixed validity of a sweep authorization (shape 1), with or without a mandate:
/// `validBefore - validAfter` of the EIP-3009 sweep.
pub const SWEEP_VALIDITY_SECS: u64 = 300;
/// Upper bound for `Mandate::max_validity_secs` (shapes 2 and 3).
pub const MAX_VALIDITY_CAP_SECS: u32 = 300;
/// Lower bound for `Mandate::max_validity_secs`: twice the clock skew, so a payout
/// timestamp window and an x402 authorization are never empty.
pub const MIN_VALIDITY_SECS: u32 = 120;
/// Allowed clock difference between NEAR block time and the client, the facilitator or
/// Monerium. EIP-3009 authorizations start `CLOCK_SKEW_SECS` before block time; a payout
/// timestamp may be up to `CLOCK_SKEW_SECS` ahead of block time.
pub const CLOCK_SKEW_SECS: u64 = 60;
/// A released payout's signed order has no on-chain expiry; Monerium's own timestamp
/// tolerance decides. Until S-b measures it, `release_after` for a payout is at least
/// `timestamp + PAYOUT_RELEASE_DELAY_SECS`.
pub const PAYOUT_RELEASE_DELAY_SECS: u64 = MAX_VALIDITY_CAP_SECS as u64;
/// An owner assertion may expire at most this far after block time. A failed owner call is
/// public on chain and replayable until `expires_at`, so the window stays short.
pub const MAX_ASSERTION_TTL_SECS: u64 = 600;
/// Upper bound for `EvmTxParams::gas_limit` (EURe raw-transfer sweep).
pub const MAX_SWEEP_GAS_LIMIT: u64 = 150_000;
/// After this long without a callback, anyone may call `expire_pending` (D4).
pub const MPC_TIMEOUT_MS: u64 = 300_000;
/// Domain tag at the start of every owner-call challenge.
pub const OWNER_CHALLENGE_DOMAIN: &[u8] = b"zold-mandate-v1";
/// Longest `RailMandate::period_secs` (366 days). Longer windows add nothing, and above
/// about 1.8e16 s the window end in ms no longer fits in a u64.
pub const MAX_PERIOD_SECS: u64 = 366 * 24 * 3600;
/// Most an owner assertion's `owner_nonce` may move past the stored one, so a slip (or a
/// nonce of u64::MAX) cannot lock the owner out (`ERR_ASSERTION_STALE_NONCE`).
pub const MAX_OWNER_NONCE_STEP: u64 = 1000;
/// The only `network` `new` accepts, and the string owner challenges bind (testnet only).
pub const NETWORK: &str = "testnet";
/// The only `mpc_contract` `new` accepts: the testnet Chain Signatures signer.
pub const MPC_CONTRACT: &str = "v1.signer-prod.testnet";

/// The payment rails. Each has its own cap and budget (D8).
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Rail {
    X402,
    Sepa,
    /// Shape 4, PayPal payouts in USD (base units: cents).
    Paypal,
    /// Shape 6, refunds of PayPal captures in USD (base units: cents).
    PaypalRefund,
}

/// Tokens the agent EOA holds as float. x402 settles in USDC; Monerium burns EURe.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Token {
    Usdc,
    Eure,
}

/// Inclusive per-payment bounds, in token base units.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AmountRange {
    pub min: U128,
    pub max: U128,
}

/// One rail's limits. Base units: USDC (6 decimals) for `x402`, EURe (18) for `sepa`.
/// Budget windows are back to back from the agent's first `set_mandate`; a changed
/// `period_secs` applies from the next window boundary (D7, docs/interfaces.md §1).
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RailMandate {
    pub amount_range: AmountRange,
    pub budget: U128,
    pub period_secs: u64,
}

/// Owner-side float limits per token, in base units. The contract stores them for the
/// owner scripts (O3); it cannot see Base balances and does not enforce them.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FloatCap {
    pub usdc: U128,
    pub eure: U128,
}

/// The spending mandate, field names after AP2's Open Payment Mandate. The payee
/// allowlist (`allowed_payees`) is kept apart and changed with `add_payee` /
/// `remove_payee` (D5); `get_payees` returns it.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mandate {
    pub x402: RailMandate,
    pub sepa: RailMandate,
    /// `usdc_address`, `eure_address` and `chain_id` must equal the agent's `SweepConfig`
    /// (`ERR_INVALID_MANDATE`); shapes 2 and 3 read them from here.
    pub usdc_address: EvmAddress,
    pub eure_address: EvmAddress,
    pub chain_id: u64,
    pub float_cap: FloatCap,
    /// Validity window for shapes 2, 3 and 4, `MIN_VALIDITY_SECS..=MAX_VALIDITY_CAP_SECS`.
    pub max_validity_secs: u32,
    /// Shape 4 (PayPal payout) limits in USD cents; `None` refuses shape 4
    /// (`ERR_SHAPE_NOT_ALLOWED`). Omitted from JSON when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paypal: Option<RailMandate>,
    /// Shape 6 (PayPal refund) limits in USD cents: `amount_range.max` is the per-refund cap,
    /// `budget` per `period_secs` the refund budget (86400 for a daily one). `None` refuses
    /// shape 6 (`ERR_SHAPE_NOT_ALLOWED`). Omitted from JSON when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paypal_refund: Option<RailMandate>,
    /// EIP-712 domain `name` and `version` of `usdc_address` (the x402 asset), e.g. `USDC`
    /// / `2`, or `PayPal USD` / `1` for PYUSD. Must equal the sweep config's
    /// (`ERR_INVALID_MANDATE`). Default `USDC` / `2` when absent from the JSON.
    #[serde(default = "default_eip712_name")]
    pub usdc_eip712_name: String,
    #[serde(default = "default_eip712_version")]
    pub usdc_eip712_version: String,
}

/// Where a sweep sends the float. Set by `add_agent`; survives revoke.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepConfig {
    pub safe_address: EvmAddress,
    pub usdc_address: EvmAddress,
    pub eure_address: EvmAddress,
    pub chain_id: u64,
    /// EIP-712 domain `name` and `version` of `usdc_address`, as in `Mandate`. Default
    /// `USDC` / `2` when absent from the JSON.
    #[serde(default = "default_eip712_name")]
    pub usdc_eip712_name: String,
    #[serde(default = "default_eip712_version")]
    pub usdc_eip712_version: String,
}

/// One allowlist entry: an x402 `payTo` address or a SEPA IBAN (uppercase, no spaces).
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(tag = "rail", rename_all = "snake_case")]
pub enum Payee {
    X402 {
        pay_to: EvmAddress,
    },
    Sepa {
        iban: String,
    },
    /// A PayPal email (lowercase) or a Venmo handle (`@` plus lowercase handle), stored in
    /// the form `shapes::paypal::normalize_receiver` returns.
    Paypal {
        receiver: String,
    },
}

/// The seller's x402 payment requirements as the agent decoded them (x402 v2 field names).
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct X402PaymentRequirements {
    pub resource_url: String,
    /// Must be `exact`.
    pub scheme: String,
    /// CAIP-2, e.g. `eip155:84532`; must match `Mandate::chain_id`.
    pub network: String,
    /// Must equal `Mandate::usdc_address`.
    pub asset: EvmAddress,
    pub pay_to: EvmAddress,
    /// USDC base units.
    pub amount: U128,
    /// The seller's timeout, at least 1. Clamped, never rejected for being long: the
    /// authorization lives `min(max_timeout_seconds, max_validity_secs - CLOCK_SKEW_SECS)`
    /// past block time.
    pub max_timeout_seconds: u32,
}

/// A Monerium payout as decoded fields. The contract canonicalises the amount (D9) and
/// renders the message `Send EUR {amount} to {iban} at {RFC3339}` itself.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayoutRequest {
    /// Uppercase, no spaces.
    pub iban: String,
    /// Decimal euros, e.g. `42.50`; at most 2 fractional digits, canonicalised (D9).
    pub amount: String,
    /// Unix seconds; rendered as `YYYY-MM-DDTHH:MM:SSZ`. Accepted when
    /// `now - (max_validity_secs - CLOCK_SKEW_SECS) <= timestamp <= now + CLOCK_SKEW_SECS`.
    pub timestamp: u64,
}

/// A PayPal payout as decoded fields (shape 4). The contract renders
/// `Send USD {amount} to {payee} at {RFC3339} ref {request_id}` itself.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaypalRequest {
    /// PayPal email or `@` Venmo handle; normalised as in `Payee::Paypal`.
    pub payee: String,
    /// Decimal USD in canonical form: no leading zeros, exactly 2 decimals (`42.50`, `0.01`).
    pub amount: String,
    /// Unix seconds; same window as `PayoutRequest::timestamp`.
    pub timestamp: u64,
}

/// A charge on the owner's vaulted PayPal wallet as decoded fields (shape 5). The contract
/// renders `Charge USD {amount} to merchant {payee} for order {order_ref} at {RFC3339} ref
/// {request_id}` itself.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaypalCheckoutRequest {
    /// The merchant's PayPal email or `@` Venmo handle; normalised as in `Payee::Paypal`.
    pub payee: String,
    /// Decimal USD in canonical form, as `PaypalRequest::amount`.
    pub amount: String,
    /// The merchant's order reference: 1-64 of `[A-Za-z0-9._:-]`.
    pub order_ref: String,
    /// Unix seconds; same window as `PayoutRequest::timestamp`.
    pub timestamp: u64,
}

/// A refund of a PayPal capture as decoded fields (shape 6). The contract renders
/// `Refund USD {amount} of capture {capture_id} ref {request_id}` itself. The money goes back
/// to the capture's payer, so there is no payee; the PayPal rail checks the capture.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefundRequest {
    /// PayPal capture id: 10-32 of `[A-Z0-9]`.
    pub capture_id: String,
    /// Decimal USD in canonical form, as `PaypalRequest::amount`.
    pub amount: String,
}

/// What can be signed. `request_signature` accepts only `x402` and `payout`; `sweep`
/// builds a `Sweep` and `link_agent` a `Link`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Shape {
    /// Shape 1: the float back to `SweepConfig::safe_address`. USDC: EIP-3009; EURe: a
    /// contract-built raw ERC-20 `transfer` (the `evm_tx` argument of `sweep`).
    Sweep { token: Token, amount: U128 },
    /// Shape 2: EIP-3009 `transferWithAuthorization` to `payTo`.
    X402(X402PaymentRequirements),
    /// Shape 3: the Monerium payout order message (EIP-191).
    Payout(PayoutRequest),
    /// Shape 4: the PayPal payout order message (EIP-191).
    Paypal(PaypalRequest),
    /// Shape 5: the vaulted PayPal checkout charge message (EIP-191).
    PaypalCheckout(PaypalCheckoutRequest),
    /// Shape 6: the PayPal refund order message (EIP-191).
    Refund(RefundRequest),
    /// Owner-only: the Monerium link message (EIP-191).
    Link,
}

/// Which shape a request is; `tag()` is the `shape` byte in the EIP-3009 nonce (D3).
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ShapeKind {
    Sweep,
    X402,
    Payout,
    Link,
    Paypal,
    PaypalCheckout,
    Refund,
}

impl ShapeKind {
    /// The `shape` byte in the EIP-3009 nonce: 1 sweep, 2 x402, 3 payout, 4 link, 5 paypal,
    /// 6 paypal_checkout, 7 refund.
    pub const fn tag(self) -> u8 {
        match self {
            ShapeKind::Sweep => 1,
            ShapeKind::X402 => 2,
            ShapeKind::Payout => 3,
            ShapeKind::Link => 4,
            ShapeKind::Paypal => 5,
            ShapeKind::PaypalCheckout => 6,
            ShapeKind::Refund => 7,
        }
    }
}

impl Shape {
    pub fn kind(&self) -> ShapeKind {
        match self {
            Shape::Sweep { .. } => ShapeKind::Sweep,
            Shape::X402(_) => ShapeKind::X402,
            Shape::Payout(_) => ShapeKind::Payout,
            Shape::Paypal(_) => ShapeKind::Paypal,
            Shape::PaypalCheckout(_) => ShapeKind::PaypalCheckout,
            Shape::Refund(_) => ShapeKind::Refund,
            Shape::Link => ShapeKind::Link,
        }
    }
}

/// Who asked for a signature. Requests are deduped per (caller, agent, request_id), and the
/// caller goes into the EIP-3009 nonce, so callers can never use up each other's ids.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Caller {
    /// The agent's own function-call key (identified by `env::signer_account_pk()`).
    Agent,
    /// An owner call (passkey assertion, or the owner wallet).
    Owner,
    /// The account named by `set_relayer`.
    Relayer { account: AccountId },
}

/// Identifies one request and its reservation.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestKey {
    pub agent: AgentId,
    pub caller: Caller,
    pub request_id: String,
}

/// Reservation state. Transitions are listed in `RequestStatus::can_become`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    /// Reserved; waiting for the MPC callback.
    Pending,
    /// The callback delivered a signature.
    Signed,
    /// The callback failed or `expire_pending` ran; counts as spent until resolved.
    Unknown,
    /// Owner resolved an `unknown` reservation as spent.
    Spent,
    /// Owner released an `unknown` reservation once `Reservation::release_after` passed.
    Released,
    /// The callback arrived after the agent was revoked; the signature is still returned (D10).
    Revoked,
}

impl Reservation {
    /// For sweep reservations: the token determined from the payload variant.
    pub fn sweep_token(&self) -> Token {
        match &self.payload {
            SignedPayload::Eip3009 { .. } => Token::Usdc,
            SignedPayload::Eip1559Tx { .. } => Token::Eure,
            _ => panic!("not a sweep reservation"),
        }
    }
}

impl RequestStatus {
    /// The allowed transitions:
    /// - MPC callback with a signature: `pending | unknown | spent | released` → `signed`, or
    ///   → `revoked` if the agent was revoked meanwhile (a late callback still records it);
    /// - MPC callback that failed, or `expire_pending`: `pending` → `unknown`;
    /// - owner `resolve_reservation`: `unknown` → `spent | released`.
    ///
    /// `signed` and `revoked` are final. A failed callback on a reservation that is already
    /// `unknown` (after `expire_pending`) is a no-op, not a transition and not an error.
    pub fn can_become(self, next: RequestStatus) -> bool {
        use RequestStatus::*;
        matches!(
            (self, next),
            (Pending | Unknown | Spent | Released, Signed | Revoked)
                | (Pending, Unknown)
                | (Unknown, Spent | Released)
        )
    }
}

/// Owner's answer to an `unknown` reservation (D4).
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResolveOutcome {
    Spent,
    Released,
}

/// Why a reservation became `unknown`.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    CallbackFailed,
    MpcTimeout,
    /// The MPC answered with a signature that does not recover to the agent's `evm_address`
    /// (a misconfigured `mpc_contract`, for instance). The signature is not stored.
    SignatureMismatch,
}

/// Who revoked an agent.
#[near(serializers = [borsh, json])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RevokedBy {
    Owner,
    Agent,
}

/// EVM transaction fields for the EURe raw-transfer sweep, supplied by the caller (usually
/// the relayer, which first sends the agent EOA just enough ETH for this one tx). The
/// contract adds `chain_id`, `to`, `value` and `data` itself.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmTxParams {
    /// The agent EOA's next account nonce on Base.
    pub nonce: u64,
    /// At most `MAX_SWEEP_GAS_LIMIT`.
    pub gas_limit: u64,
    /// Wei.
    pub max_fee_per_gas: U128,
    /// Wei; at most `max_fee_per_gas`.
    pub max_priority_fee_per_gas: U128,
}

/// What the contract asked the MPC to sign, in the form a client needs to use the signature.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignedPayload {
    /// EIP-3009 `transferWithAuthorization` (shapes 1 and 2). Numbers are decimal strings or
    /// integers as in x402; `nonce` is `0x` plus 64 hex digits.
    Eip3009 {
        /// The token contract (EIP-712 `verifyingContract`).
        asset: EvmAddress,
        chain_id: u64,
        from: EvmAddress,
        to: EvmAddress,
        value: U128,
        valid_after: u64,
        valid_before: u64,
        nonce: String,
    },
    /// An EIP-191 `personal_sign` text (payout and link).
    Message { text: String },
    /// EIP-1559 (type 2) transaction, the EURe sweep: `to = eure_address`, `value = 0`,
    /// `data = transfer(safe_address, amount)`, empty access list. The digest is
    /// `keccak256(0x02 || rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
    /// gas_limit, to, value, data, []]))`; the client appends `y_parity = v - 27`, `r`, `s`
    /// and broadcasts it.
    Eip1559Tx {
        chain_id: u64,
        nonce: u64,
        max_priority_fee_per_gas: U128,
        max_fee_per_gas: U128,
        gas_limit: u64,
        to: EvmAddress,
        value: U128,
        /// `0x` plus hex calldata: `0xa9059cbb`, then the address and amount as 32-byte words.
        data: String,
    },
}

/// secp256k1 signature from the MPC, EVM form: `v = 27 + recovery_id` (never from the
/// `big_r` prefix, see spikes/chainsig). `r` and `s` are `0x` plus 64 hex digits.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvmSignature {
    pub r: String,
    pub s: String,
    pub v: u8,
}

/// One request and its reservation; returned by the MPC callback and by views.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub key: RequestKey,
    pub shape: ShapeKind,
    /// `None` for sweeps and the link, which count against no budget (D8).
    pub rail: Option<Rail>,
    /// Base units reserved on `rail`; 0 when `rail` is `None`.
    pub amount: U128,
    /// Start (unix ms) of the budget period this reservation counts in (D7).
    pub period_start_ms: u64,
    pub created_at_ms: u64,
    /// End of the signed authorization's validity (unix seconds); `0` when nothing on chain
    /// expires it (the link message, and the EURe raw tx, which is dead once the EOA nonce
    /// passes it).
    pub valid_before: u64,
    /// `resolve_reservation(.., released)` is refused before this (unix seconds):
    /// `valid_before` for EIP-3009 shapes, `max(valid_before, timestamp +
    /// PAYOUT_RELEASE_DELAY_SECS)` for payouts, `0` for the link and the EURe sweep (they
    /// count against no budget; a late EURe sweep tx still goes only to the Safe).
    pub release_after: u64,
    /// The 32-byte digest sent to the MPC, `0x` plus 64 hex digits.
    pub digest: String,
    pub payload: SignedPayload,
    pub status: RequestStatus,
    /// False once released; a late `signed` after a release stays uncounted.
    pub counts_against_budget: bool,
    pub signature: Option<EvmSignature>,
}

/// Owner authorization on every owner method, `Some` in passkey mode and `None` in wallet
/// mode. The challenge is defined in docs/interfaces.md ("Owner calls").
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerAssertion {
    pub authenticator_data: Base64VecU8,
    pub client_data_json: String,
    /// Raw 64-byte `r || s` (the client converts the browser's DER form). Either S form is
    /// accepted (real passkeys produce high-S, spikes/passkey); replay protection is
    /// `owner_nonce`, never the signature bytes.
    pub signature: Base64VecU8,
    /// Must be greater than the last nonce used; consumed only when the call succeeds.
    pub owner_nonce: u64,
    /// Unix seconds; not passed, and at most `MAX_ASSERTION_TTL_SECS` after block time.
    pub expires_at: u64,
}

/// The owner, chosen once at `new` and never changed.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum OwnerMode {
    /// WebAuthn passkey. `public_key` is the 33-byte compressed SEC1 P-256 key;
    /// `rp_id` and `origin` are matched against each assertion.
    Passkey {
        public_key: Base64VecU8,
        rp_id: String,
        origin: String,
    },
    /// Fallback: a NEAR wallet; owner calls must come from this account. `new` rejects this
    /// contract's own account (agent calls have it as predecessor).
    Wallet { account: AccountId },
}

/// Everything the contract knows about one agent. Kept after revoke (with
/// `public_key: None`) so the id, and with it the derivation path, is never reused.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRecord {
    pub agent: AgentId,
    pub public_key: Option<PublicKey>,
    pub sweep_config: SweepConfig,
    /// The agent EOA, `derive(contract_id, agent)` on the MPC. The owner supplies it in
    /// `add_agent` (lowercase once stored), so it is `Some` for every record `add_agent`
    /// writes. A wrong value only makes the agent's signed authorizations fail on chain.
    pub evm_address: Option<EvmAddress>,
    pub linked: bool,
    pub revoked: bool,
}

/// What `revoke` and `revoke_self` return. It reports the state change, which committed
/// before the key action ran; clients check this (or `get_agent`), not the tx status.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokeResult {
    pub agent: AgentId,
    /// Always true: the mandate and key-to-agent entry are cleared.
    pub revoked: bool,
    /// Whether the `DeleteKey` receipt succeeded. False if the key was already gone.
    pub key_deleted: bool,
}

/// Budget use of one rail in the current window.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetView {
    pub rail: Rail,
    /// Start of the current window (unix ms).
    pub period_start_ms: u64,
    /// Length of the current window; a changed `period_secs` shows from the next window.
    pub period_secs: u64,
    pub budget: U128,
    /// Sum of reservations that count against the budget in this period.
    pub reserved: U128,
}

/// Contract-wide settings.
#[near(serializers = [json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigView {
    pub owner: OwnerMode,
    /// The last owner nonce used; the next owner call must use a greater one.
    pub owner_nonce: u64,
    /// The `network` string in owner challenges, e.g. `testnet`.
    pub network: String,
    pub mpc_contract: AccountId,
    pub relayer: Option<AccountId>,
    /// The one account allowed to call `report_settlement` (PP-W1).
    pub settlement_reporter: Option<AccountId>,
}
