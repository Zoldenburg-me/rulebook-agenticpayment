//! Error codes. A failing call panics with `"{CODE}: {detail}"`, where `CODE` is
//! `ContractError::code()` and `detail` names the decoded field that failed, so clients can
//! match the code and the dashboard can show the field.

use near_sdk::env;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractError {
    NotImplemented,
    // Owner calls
    AssertionRequired,
    AssertionForbidden,
    NotOwner,
    AssertionMalformed,
    AssertionBadType,
    AssertionBadChallenge,
    AssertionBadOrigin,
    AssertionBadRpIdHash,
    AssertionNoUserPresence,
    AssertionStaleNonce,
    AssertionExpired,
    AssertionTtlTooLong,
    AssertionBadSignature,
    // Agents and keys
    NotAgentKey,
    UnknownAgentKey,
    UnknownAgent,
    AgentExists,
    KeyExists,
    InvalidAgentId,
    AgentRevoked,
    NoMandate,
    InvalidMandate,
    InvalidAddress,
    // Requests and reservations
    InvalidRequestId,
    DuplicateRequestId,
    ShapeNotAllowed,
    RequestNotFound,
    BadTransition,
    MpcTimeoutNotReached,
    ValidityNotEnded,
    BelowMinimum,
    OverPerPaymentCap,
    OverBudget,
    // Shape 1: sweep
    SweepCallerNotAllowed,
    SweepPending,
    EvmTxRequired,
    EvmTxForbidden,
    InvalidEvmTx,
    // Shape 2: x402
    PayeeNotAllowed,
    WrongScheme,
    WrongAsset,
    WrongNetwork,
    InvalidTimeout,
    // Shape 3: payout
    IbanNotAllowed,
    InvalidIban,
    InvalidAmount,
    TimestampStale,
    TimestampFuture,
    DuplicatePayout,
    // Shape 4: PayPal payout
    PaypalPayeeNotAllowed,
    InvalidPaypalPayee,
    // Shape 5: PayPal checkout
    InvalidOrderRef,
    // Shape 6: PayPal refund
    InvalidCaptureId,
    // Link
    AlreadyLinked,
    // PP-W1: settlement feedback
    NotSettlementReporter,
    InvalidSettlement,
    PayeeSuspended,
    PayeeNotSuspended,
}

impl ContractError {
    pub const fn code(self) -> &'static str {
        use ContractError::*;
        match self {
            NotImplemented => "ERR_NOT_IMPLEMENTED",
            AssertionRequired => "ERR_ASSERTION_REQUIRED",
            AssertionForbidden => "ERR_ASSERTION_FORBIDDEN",
            NotOwner => "ERR_NOT_OWNER",
            AssertionMalformed => "ERR_ASSERTION_MALFORMED",
            AssertionBadType => "ERR_ASSERTION_BAD_TYPE",
            AssertionBadChallenge => "ERR_ASSERTION_BAD_CHALLENGE",
            AssertionBadOrigin => "ERR_ASSERTION_BAD_ORIGIN",
            AssertionBadRpIdHash => "ERR_ASSERTION_BAD_RP_ID_HASH",
            AssertionNoUserPresence => "ERR_ASSERTION_NO_USER_PRESENCE",
            AssertionStaleNonce => "ERR_ASSERTION_STALE_NONCE",
            AssertionExpired => "ERR_ASSERTION_EXPIRED",
            AssertionTtlTooLong => "ERR_ASSERTION_TTL_TOO_LONG",
            AssertionBadSignature => "ERR_ASSERTION_BAD_SIGNATURE",
            NotAgentKey => "ERR_NOT_AGENT_KEY",
            UnknownAgentKey => "ERR_UNKNOWN_AGENT_KEY",
            UnknownAgent => "ERR_UNKNOWN_AGENT",
            AgentExists => "ERR_AGENT_EXISTS",
            KeyExists => "ERR_KEY_EXISTS",
            InvalidAgentId => "ERR_INVALID_AGENT_ID",
            AgentRevoked => "ERR_AGENT_REVOKED",
            NoMandate => "ERR_NO_MANDATE",
            InvalidMandate => "ERR_INVALID_MANDATE",
            InvalidAddress => "ERR_INVALID_ADDRESS",
            InvalidRequestId => "ERR_INVALID_REQUEST_ID",
            DuplicateRequestId => "ERR_DUPLICATE_REQUEST_ID",
            ShapeNotAllowed => "ERR_SHAPE_NOT_ALLOWED",
            RequestNotFound => "ERR_REQUEST_NOT_FOUND",
            BadTransition => "ERR_BAD_TRANSITION",
            MpcTimeoutNotReached => "ERR_MPC_TIMEOUT_NOT_REACHED",
            ValidityNotEnded => "ERR_VALIDITY_NOT_ENDED",
            BelowMinimum => "ERR_BELOW_MINIMUM",
            OverPerPaymentCap => "ERR_OVER_PER_PAYMENT_CAP",
            OverBudget => "ERR_OVER_BUDGET",
            SweepCallerNotAllowed => "ERR_SWEEP_CALLER_NOT_ALLOWED",
            SweepPending => "ERR_SWEEP_PENDING",
            EvmTxRequired => "ERR_EVM_TX_REQUIRED",
            EvmTxForbidden => "ERR_EVM_TX_FORBIDDEN",
            InvalidEvmTx => "ERR_INVALID_EVM_TX",
            PayeeNotAllowed => "ERR_PAYEE_NOT_ALLOWED",
            WrongScheme => "ERR_WRONG_SCHEME",
            WrongAsset => "ERR_WRONG_ASSET",
            WrongNetwork => "ERR_WRONG_NETWORK",
            InvalidTimeout => "ERR_INVALID_TIMEOUT",
            IbanNotAllowed => "ERR_IBAN_NOT_ALLOWED",
            InvalidIban => "ERR_INVALID_IBAN",
            InvalidAmount => "ERR_INVALID_AMOUNT",
            TimestampStale => "ERR_TIMESTAMP_STALE",
            TimestampFuture => "ERR_TIMESTAMP_FUTURE",
            DuplicatePayout => "ERR_DUPLICATE_PAYOUT",
            PaypalPayeeNotAllowed => "ERR_PAYPAL_PAYEE_NOT_ALLOWED",
            InvalidPaypalPayee => "ERR_INVALID_PAYPAL_PAYEE",
            InvalidOrderRef => "ERR_INVALID_ORDER_REF",
            InvalidCaptureId => "ERR_INVALID_CAPTURE_ID",
            AlreadyLinked => "ERR_ALREADY_LINKED",
            NotSettlementReporter => "ERR_NOT_SETTLEMENT_REPORTER",
            InvalidSettlement => "ERR_INVALID_SETTLEMENT",
            PayeeSuspended => "ERR_PAYEE_SUSPENDED",
            PayeeNotSuspended => "ERR_PAYEE_NOT_SUSPENDED",
        }
    }

    /// Aborts the call with `"{CODE}: {detail}"`.
    pub fn panic(self, detail: &str) -> ! {
        env::panic_str(&format!("{}: {}", self.code(), detail))
    }
}

/// What every C1 stub does until its task implements it.
pub fn not_implemented(what: &str) -> ! {
    ContractError::NotImplemented.panic(what)
}
