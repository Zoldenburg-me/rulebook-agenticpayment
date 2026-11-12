//! Demo-shaped values on Base Sepolia (the same numbers as the C3 unit tests).

use mandate::types::{
    AmountRange, Caller, FloatCap, Mandate, Payee, RailMandate, RequestKey, Shape, SweepConfig,
    X402PaymentRequirements,
};
use near_sdk::json_types::U128;

pub const USDC: &str = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
pub const EURE: &str = "0x29f37f6adca168b79b8d9567eab9be3fbf21db85";
pub const SAFE: &str = "0x5afe000000000000000000000000000000000001";
pub const PAY_TO: &str = "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f";
pub const CHAIN_ID: u64 = 84532;
pub const WEEK: u64 = 604_800;

pub fn sweep_config() -> SweepConfig {
    SweepConfig {
        safe_address: SAFE.into(),
        usdc_address: USDC.into(),
        eure_address: EURE.into(),
        chain_id: CHAIN_ID,
        usdc_eip712_name: "USDC".into(),
        usdc_eip712_version: "2".into(),
    }
}

/// x402: 1..=10_000 per payment and 25_000 per week; SEPA: 50 EURe per payout, 200 a week.
pub fn mandate() -> Mandate {
    let rail = |max: u128, budget: u128| RailMandate {
        amount_range: AmountRange {
            min: U128(1),
            max: U128(max),
        },
        budget: U128(budget),
        period_secs: WEEK,
    };
    Mandate {
        x402: rail(10_000, 25_000),
        sepa: rail(50 * 10u128.pow(18), 200 * 10u128.pow(18)),
        usdc_address: USDC.into(),
        eure_address: EURE.into(),
        chain_id: CHAIN_ID,
        float_cap: FloatCap {
            usdc: U128(25_000_000),
            eure: U128(250 * 10u128.pow(18)),
        },
        max_validity_secs: 300,
        paypal: None,
        paypal_refund: None,
        usdc_eip712_name: "USDC".into(),
        usdc_eip712_version: "2".into(),
    }
}

pub fn pay_to() -> Payee {
    Payee::X402 {
        pay_to: PAY_TO.into(),
    }
}

/// An x402 payment of `amount` USDC base units to `PAY_TO`.
pub fn x402(amount: u128) -> Shape {
    Shape::X402(X402PaymentRequirements {
        resource_url: "http://localhost:4021/weather".into(),
        scheme: "exact".into(),
        network: format!("eip155:{CHAIN_ID}"),
        asset: USDC.into(),
        pay_to: PAY_TO.into(),
        amount: U128(amount),
        max_timeout_seconds: 240,
    })
}

/// The key of a request the agent itself made.
pub fn agent_request(agent: &str, request_id: &str) -> RequestKey {
    RequestKey {
        agent: agent.into(),
        caller: Caller::Agent,
        request_id: request_id.into(),
    }
}
