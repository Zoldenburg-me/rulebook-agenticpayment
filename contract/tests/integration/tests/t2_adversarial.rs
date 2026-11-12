//! T2 adversarial suite in the sandbox: reservations, revoke, sweep, the agent key's method
//! restrictions, cross-mandate requests, the link message through `request_signature`, and
//! Monerium payouts (the per-agent duplicate check of D3, IBAN, cap, budget and timestamp).

use mandate::types::{
    Caller, EvmTxParams, Payee, PayoutRequest, Rail, RequestKey, RequestStatus, Reservation,
    ResolveOutcome, RevokeResult, Shape, SignedPayload, Token, AGENT_METHOD_NAMES,
};
use mandate_integration::fixtures::{self, agent_request, x402, PAY_TO, SAFE, WEEK};
use mandate_integration::{expect_ok, mpc, rejection, Harness, SignerMode};
use near_sdk::json_types::U128;
use near_sdk::serde_json::json;
use near_workspaces::types::AccessKeyPermission;
use near_workspaces::Account;

const A: &str = "agent-a";
const B: &str = "agent-b";
/// A second x402 payee, allowlisted for agent B only.
const PAY_TO_B: &str = "0xb0b0000000000000000000000000000000000002";
const SWEEP_AMOUNT: u128 = 1_000_000;

// ---------- helpers ----------

/// `request_signature` that must fail; returns the failure text.
async fn request_rejected(
    h: &Harness,
    agent: &Account,
    request_id: &str,
    shape: &Shape,
) -> anyhow::Result<String> {
    rejection(h.request_tx(agent, request_id, shape).transact().await)
}

/// Sends a request and waits until the mock holds its `sign` call (it stays `pending`).
async fn request_pending(
    h: &Harness,
    agent: &Account,
    agent_id: &str,
    request_id: &str,
    amount: u128,
) -> anyhow::Result<RequestKey> {
    let _tx = h
        .request_signature(agent, request_id, &x402(amount))
        .await?;
    let key = agent_request(agent_id, request_id);
    for _ in 0..60 {
        if h.get_request(&key).await?.is_some() {
            return Ok(key);
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    anyhow::bail!("{request_id} was never reserved")
}

async fn reserved(h: &Harness, agent: &str) -> anyhow::Result<u128> {
    Ok(h.get_budget(agent, Rail::X402)
        .await?
        .map_or(0, |b| b.reserved.0))
}

/// Exact code match: the contract panics with `"{CODE}: {detail}"`, so matching `"{code}:"`
/// keeps `ERR_UNKNOWN_AGENT` from also matching `ERR_UNKNOWN_AGENT_KEY`.
fn assert_code(err: &str, code: &str) {
    assert!(
        err.contains(&format!("{code}:")),
        "expected {code}, got: {err}"
    );
}

/// A tx signed with a deleted key: refused by the chain (or by the nonce lookup before it),
/// not by the contract.
fn assert_key_gone(err: &str) {
    let missing_key = err.contains("AccessKeyNotFound")
        || err.contains("UnknownAccessKey")
        || (err.contains("access key") && err.contains("does not exist"));
    assert!(
        missing_key && !err.contains("ERR_"),
        "expected a missing access key, got: {err}"
    );
}

fn x402_to(pay_to: &str, amount: u128) -> Shape {
    let Shape::X402(mut req) = x402(amount) else {
        unreachable!()
    };
    req.pay_to = pay_to.into();
    Shape::X402(req)
}

fn eure_tx() -> EvmTxParams {
    EvmTxParams {
        nonce: 0,
        gas_limit: 100_000,
        max_fee_per_gas: U128(2_000_000_000),
        max_priority_fee_per_gas: U128(1_000_000_000),
    }
}

fn sweep_key(agent: &str, caller: Caller, request_id: &str) -> RequestKey {
    RequestKey {
        agent: agent.into(),
        caller,
        request_id: request_id.into(),
    }
}

/// The EIP-3009 payload's `(to, valid_before, nonce)`.
fn eip3009(res: &Reservation) -> (String, u64, String) {
    match &res.payload {
        SignedPayload::Eip3009 {
            to,
            valid_before,
            nonce,
            ..
        } => (to.clone(), *valid_before, nonce.clone()),
        other => panic!("not an EIP-3009 payload: {other:?}"),
    }
}

/// Waits for `key`'s reservation to appear (a sweep sent without waiting), answers its
/// `sign` call and returns the settled reservation.
async fn sign_now(h: &Harness, key: &RequestKey) -> anyhow::Result<Reservation> {
    for _ in 0..60 {
        if h.get_request(key).await?.is_some() {
            return h.respond_for(key).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    anyhow::bail!("{key:?} was never reserved")
}

/// True if `key` is still one of the contract account's access keys.
async fn key_on_contract(h: &Harness, agent: &Account) -> anyhow::Result<bool> {
    let pk = agent.secret_key().public_key();
    Ok(h.contract_keys().await?.iter().any(|k| k.public_key == pk))
}

// ---------- reservations ----------

/// A pending request keeps its reservation: a second one is checked against what is left.
#[tokio::test]
async fn pending_request_keeps_its_budget_for_the_next_one() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;

    let first = request_pending(&h, &agent, A, "res-1", 10_000).await?;
    let second = request_pending(&h, &agent, A, "res-2", 10_000).await?;
    assert_eq!(reserved(&h, A).await?, 20_000);

    // 25_000 budget: 20_000 is pending, so 10_000 more is over and 5_000 fits exactly.
    let err = request_rejected(&h, &agent, "res-3", &x402(10_000)).await?;
    assert_code(&err, "ERR_OVER_BUDGET");
    assert!(h.get_request(&agent_request(A, "res-3")).await?.is_none());
    request_pending(&h, &agent, A, "res-4", 5_000).await?;
    assert_eq!(reserved(&h, A).await?, 25_000);
    assert_code(
        &request_rejected(&h, &agent, "res-5", &x402(1)).await?,
        "ERR_OVER_BUDGET",
    );

    // Signing does not change what counts.
    assert_eq!(h.respond_for(&first).await?.status, RequestStatus::Signed);
    assert_eq!(h.respond_for(&second).await?.status, RequestStatus::Signed);
    assert_eq!(reserved(&h, A).await?, 25_000);
    Ok(())
}

/// A failed MPC callback leaves the reservation `unknown`, and it counts as spent: the next
/// request sees the budget without it, also after the owner resolves it `spent`.
#[tokio::test]
async fn failed_callback_is_unknown_and_counts_as_spent() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;
    h.set_signer_mode(SignerMode::Fail).await?;

    let mut unknown = Vec::new();
    for id in ["fail-1", "fail-0"] {
        let tx = h.request_signature(&agent, id, &x402(10_000)).await?;
        let res: Reservation = tx.await?.into_result()?.json()?;
        assert_eq!(res.status, RequestStatus::Unknown);
        assert!(res.counts_against_budget);
        unknown.push(res);
    }
    let res = unknown.remove(0);
    assert_eq!(reserved(&h, A).await?, 20_000);

    h.set_signer_mode(SignerMode::Respond).await?;
    assert_code(
        &request_rejected(&h, &agent, "fail-2", &x402(10_000)).await?,
        "ERR_OVER_BUDGET",
    );

    expect_ok(h.resolve(&res.key, ResolveOutcome::Spent).await?)?;
    let spent = h.get_request(&res.key).await?.unwrap();
    assert_eq!(spent.status, RequestStatus::Spent);
    assert!(spent.counts_against_budget);
    assert_eq!(reserved(&h, A).await?, 20_000);
    assert_code(
        &request_rejected(&h, &agent, "fail-3", &x402(5_001)).await?,
        "ERR_OVER_BUDGET",
    );
    request_pending(&h, &agent, A, "fail-4", 5_000).await?;
    assert_eq!(reserved(&h, A).await?, 25_000);
    Ok(())
}

/// `Released` is refused until the authorization's validity window (plus clock skew) has
/// ended, then frees the budget.
#[tokio::test]
async fn released_is_refused_until_the_validity_window_ends() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;
    h.set_signer_mode(SignerMode::Fail).await?;
    let tx = h.request_signature(&agent, "rel-1", &x402(10_000)).await?;
    let res: Reservation = tx.await?.into_result()?.json()?;
    assert_eq!(res.status, RequestStatus::Unknown);
    let (_, valid_before, _) = eip3009(&res);
    assert!(res.release_after >= valid_before);

    let err = rejection(h.resolve(&res.key, ResolveOutcome::Released).await)?;
    assert_code(&err, "ERR_VALIDITY_NOT_ENDED");
    assert_eq!(
        h.get_request(&res.key).await?.unwrap().status,
        RequestStatus::Unknown
    );
    assert_eq!(reserved(&h, A).await?, 10_000);

    // Just before release_after: still refused.
    let now = h.now_secs().await?;
    if res.release_after > now + 20 {
        h.advance_secs(res.release_after - now - 20).await?;
        assert_code(
            &rejection(h.resolve(&res.key, ResolveOutcome::Released).await)?,
            "ERR_VALIDITY_NOT_ENDED",
        );
    }
    let now = h.now_secs().await?;
    h.advance_secs(res.release_after.saturating_sub(now) + 1)
        .await?;
    expect_ok(h.resolve(&res.key, ResolveOutcome::Released).await?)?;
    let released = h.get_request(&res.key).await?.unwrap();
    assert_eq!(released.status, RequestStatus::Released);
    assert!(!released.counts_against_budget);
    assert_eq!(reserved(&h, A).await?, 0);
    Ok(())
}

/// `expire_pending` only after `MPC_TIMEOUT_MS`, by anyone; the reservation turns `unknown`
/// and keeps counting. After the owner releases it, a late MPC callback still records the
/// signature, but the authorization it carries has already expired and the budget stays free.
#[tokio::test]
async fn expire_pending_after_the_timeout_and_a_late_callback_after_release() -> anyhow::Result<()>
{
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;
    let anyone = h.account("anyone").await?;
    h.set_signer_mode(SignerMode::Hold).await?;
    let key = request_pending(&h, &agent, A, "late-1", 10_000).await?;

    assert_code(
        &rejection(h.expire_pending(&anyone, &key).await)?,
        "ERR_MPC_TIMEOUT_NOT_REACHED",
    );
    h.advance_secs(301).await?;
    let res = h.get_request(&key).await?.unwrap();
    assert_eq!(
        res.status,
        RequestStatus::Pending,
        "the mock still holds it"
    );

    expect_ok(h.expire_pending(&anyone, &key).await?)?;
    let res = h.get_request(&key).await?.unwrap();
    assert_eq!(res.status, RequestStatus::Unknown);
    assert!(res.counts_against_budget);
    assert_eq!(reserved(&h, A).await?, 10_000);
    assert_code(
        &rejection(h.expire_pending(&anyone, &key).await)?,
        "ERR_BAD_TRANSITION",
    );

    let now = h.now_secs().await?;
    h.advance_secs(res.release_after.saturating_sub(now) + 1)
        .await?;
    expect_ok(h.resolve(&key, ResolveOutcome::Released).await?)?;
    assert_eq!(reserved(&h, A).await?, 0);

    // The MPC answers late.
    let late = h.respond_for(&key).await?;
    assert_eq!(late.status, RequestStatus::Signed);
    assert!(
        !late.counts_against_budget,
        "a release is not undone by a late signature"
    );
    assert_eq!(reserved(&h, A).await?, 0);
    let (_, valid_before, _) = eip3009(&late);
    assert!(
        valid_before < h.now_secs().await?,
        "the late authorization is already expired (validBefore {valid_before})"
    );
    assert_eq!(
        mpc::recover_address(&late.digest, late.signature.as_ref().unwrap())?,
        h.agent_evm_address(A)
    );
    Ok(())
}

/// A mandate or payee change while a request is pending keeps that reservation; the next
/// request is checked against the new mandate.
#[tokio::test]
async fn policy_change_while_pending_keeps_the_reservation() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;
    let pending = request_pending(&h, &agent, A, "pol-1", 10_000).await?;

    let mut tighter = fixtures::mandate();
    tighter.x402.amount_range.max = U128(5_000);
    tighter.x402.budget = U128(12_000);
    h.set_mandate(A, &tighter).await?;

    let res = h.get_request(&pending).await?.unwrap();
    assert_eq!(res.status, RequestStatus::Pending);
    assert_eq!(res.amount.0, 10_000, "the pending reservation is untouched");
    let budget = h.get_budget(A, Rail::X402).await?.unwrap();
    assert_eq!((budget.budget.0, budget.reserved.0), (12_000, 10_000));

    assert_code(
        &request_rejected(&h, &agent, "pol-2", &x402(6_000)).await?,
        "ERR_OVER_PER_PAYMENT_CAP",
    );
    assert_code(
        &request_rejected(&h, &agent, "pol-3", &x402(3_000)).await?,
        "ERR_OVER_BUDGET",
    );
    request_pending(&h, &agent, A, "pol-4", 2_000).await?;
    assert_eq!(reserved(&h, A).await?, 12_000);

    h.remove_payee(A, &fixtures::pay_to()).await?;
    assert_code(
        &request_rejected(&h, &agent, "pol-5", &x402(1)).await?,
        "ERR_PAYEE_NOT_ALLOWED",
    );

    // The request made under the old mandate still completes.
    let signed = h.respond_for(&pending).await?;
    assert_eq!(signed.status, RequestStatus::Signed);
    let (to, _, _) = eip3009(&signed);
    assert_eq!(to, PAY_TO);
    Ok(())
}

/// `set_mandate` does not restart the budget window or clear what counts in it, even when
/// it changes `period_secs` (which applies from the next boundary).
#[tokio::test]
async fn set_mandate_does_not_restart_the_period() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;
    request_pending(&h, &agent, A, "per-1", 4_000).await?;
    let before = h.get_budget(A, Rail::X402).await?.unwrap();
    assert_eq!(before.period_secs, WEEK);

    h.advance_secs(30).await?;
    let mut shorter = fixtures::mandate();
    shorter.x402.period_secs = 3_600;
    h.set_mandate(A, &shorter).await?;
    h.set_mandate(A, &fixtures::mandate()).await?;
    h.set_mandate(A, &shorter).await?;

    let after = h.get_budget(A, Rail::X402).await?.unwrap();
    assert_eq!(after.period_start_ms, before.period_start_ms);
    assert_eq!(after.period_secs, WEEK, "the current window keeps its end");
    assert_eq!(after.reserved.0, 4_000);
    assert_code(
        &request_rejected(&h, &agent, "per-2", &x402(21_001)).await?,
        "ERR_OVER_PER_PAYMENT_CAP",
    );
    request_pending(&h, &agent, A, "per-3", 10_000).await?;
    request_pending(&h, &agent, A, "per-4", 10_000).await?;
    assert_code(
        &request_rejected(&h, &agent, "per-5", &x402(1_001)).await?,
        "ERR_OVER_BUDGET",
    );
    Ok(())
}

// ---------- revoke ----------

/// Owner revoke: state cleared and the key deleted in the same tx; requests after it fail;
/// an authorization signed before it keeps its signature and validity; one pending at the
/// time comes back `revoked` with its signature (D10).
#[tokio::test]
async fn owner_revoke() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;

    let signed_key = request_pending(&h, &agent, A, "rv-1", 4_000).await?;
    let signed = h.respond_for(&signed_key).await?;
    assert_eq!(signed.status, RequestStatus::Signed);
    let pending = request_pending(&h, &agent, A, "rv-2", 3_000).await?;
    assert!(key_on_contract(&h, &agent).await?);

    let result = h.revoke(A).await?;
    assert_eq!(
        result,
        RevokeResult {
            agent: A.into(),
            revoked: true,
            key_deleted: true
        }
    );
    // DeleteKey ran inside the revoke tx: the key is gone once it returns.
    assert!(!key_on_contract(&h, &agent).await?);
    let record = h.get_agent(A).await?.unwrap();
    assert!(record.revoked && record.public_key.is_none());
    assert!(h.get_mandate(A).await?.is_none());
    assert!(h.get_budget(A, Rail::X402).await?.is_none());

    assert_key_gone(&request_rejected(&h, &agent, "rv-3", &x402(1)).await?);
    assert!(h.get_request(&agent_request(A, "rv-3")).await?.is_none());

    // Signed before the revoke: unchanged, and still valid until its validBefore.
    let after = h.get_request(&signed_key).await?.unwrap();
    assert_eq!(after, signed);
    let (_, valid_before, _) = eip3009(&after);
    assert!(valid_before > h.now_secs().await?);
    assert_eq!(
        mpc::recover_address(&after.digest, after.signature.as_ref().unwrap())?,
        h.agent_evm_address(A)
    );

    // Pending at the revoke: the late callback records `revoked`, signature included.
    let late = h.respond_for(&pending).await?;
    assert_eq!(late.status, RequestStatus::Revoked);
    assert!(late.signature.is_some());

    // A second revoke changes nothing and deletes nothing.
    let again = h.revoke(A).await?;
    assert!(again.revoked && !again.key_deleted);
    Ok(())
}

/// `revoke_self`: the agent revokes itself only, the key is deleted in the same tx, later
/// requests and a second `revoke_self` fail; a signed authorization stays as it was.
#[tokio::test]
async fn self_revoke() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;
    let other = h.setup_agent(B).await?;
    let signed_key = request_pending(&h, &agent, A, "sr-1", 4_000).await?;
    let signed = h.respond_for(&signed_key).await?;

    let result: RevokeResult = expect_ok(
        agent
            .call(h.mandate.id(), "revoke_self")
            .gas(mandate_integration::AGENT_GAS)
            .transact()
            .await?,
    )?
    .json()?;
    assert_eq!(
        result,
        RevokeResult {
            agent: A.into(),
            revoked: true,
            key_deleted: true
        }
    );
    assert!(!key_on_contract(&h, &agent).await?);
    assert!(h.get_agent(A).await?.unwrap().revoked);
    assert!(h.get_mandate(A).await?.is_none());

    assert_key_gone(&request_rejected(&h, &agent, "sr-2", &x402(1)).await?);
    let err = rejection(
        agent
            .call(h.mandate.id(), "revoke_self")
            .gas(mandate_integration::AGENT_GAS)
            .transact()
            .await,
    )?;
    assert_key_gone(&err);

    assert_eq!(h.get_request(&signed_key).await?.unwrap(), signed);
    // B is untouched.
    assert!(!h.get_agent(B).await?.unwrap().revoked);
    assert!(key_on_contract(&h, &other).await?);
    request_pending(&h, &other, B, "sr-b", 1_000).await?;
    Ok(())
}

// ---------- sweep ----------

/// Only the agent's own key, the `set_relayer` account and the owner may sweep; every sweep
/// goes to the Safe.
#[tokio::test]
async fn sweep_callers() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;
    let other_agent = h.setup_agent(B).await?;
    let relayer = h.account("relayer").await?;
    let stranger = h.account("stranger").await?;
    h.set_relayer(Some(&relayer)).await?;

    let cases = [
        (Caller::Agent, "sw-agent"),
        (
            Caller::Relayer {
                account: relayer.id().as_str().parse()?,
            },
            "sw-relayer",
        ),
        (Caller::Owner, "sw-owner"),
    ];
    for (caller, id) in cases {
        let _tx = match &caller {
            Caller::Agent => {
                h.sweep_from(&agent, A, Token::Usdc, SWEEP_AMOUNT, id, None)
                    .transact_async()
                    .await?
            }
            Caller::Relayer { .. } => {
                h.sweep_from(&relayer, A, Token::Usdc, SWEEP_AMOUNT, id, None)
                    .transact_async()
                    .await?
            }
            Caller::Owner => {
                h.owner_sweep(A, Token::Usdc, SWEEP_AMOUNT, id, None)
                    .await?
                    .transact_async()
                    .await?
            }
        };
        let res = sign_now(&h, &sweep_key(A, caller.clone(), id)).await?;
        assert_eq!(res.status, RequestStatus::Signed, "{caller:?}");
        assert_eq!(eip3009(&res).0, SAFE, "{caller:?}");
        assert_eq!(res.rail, None, "sweeps count against no budget");
    }

    // Anyone else, another agent's key, and the relayer once it is removed: rejected.
    let tx = h
        .sweep_from(&stranger, A, Token::Usdc, SWEEP_AMOUNT, "sw-x1", None)
        .transact()
        .await;
    assert_code(&rejection(tx)?, "ERR_SWEEP_CALLER_NOT_ALLOWED");
    let tx = h
        .sweep_from(&other_agent, A, Token::Usdc, SWEEP_AMOUNT, "sw-x2", None)
        .transact()
        .await;
    assert_code(&rejection(tx)?, "ERR_SWEEP_CALLER_NOT_ALLOWED");
    // An agent id that was never added, even from the relayer.
    let tx = h
        .sweep_from(
            &relayer,
            "no-such-agent",
            Token::Usdc,
            SWEEP_AMOUNT,
            "sw-x4",
            None,
        )
        .transact()
        .await;
    assert_code(&rejection(tx)?, "ERR_UNKNOWN_AGENT");
    assert!(h
        .get_request(&sweep_key(
            "no-such-agent",
            Caller::Relayer {
                account: relayer.id().as_str().parse()?,
            },
            "sw-x4",
        ))
        .await?
        .is_none());
    h.set_relayer(None).await?;
    let tx = h
        .sweep_from(&relayer, A, Token::Usdc, SWEEP_AMOUNT, "sw-x3", None)
        .transact()
        .await;
    assert_code(&rejection(tx)?, "ERR_SWEEP_CALLER_NOT_ALLOWED");
    for (caller, id) in [
        (
            Caller::Relayer {
                account: stranger.id().as_str().parse()?,
            },
            "sw-x1",
        ),
        (Caller::Agent, "sw-x2"),
        (
            Caller::Relayer {
                account: relayer.id().as_str().parse()?,
            },
            "sw-x3",
        ),
    ] {
        assert!(h.get_request(&sweep_key(A, caller, id)).await?.is_none());
    }
    Ok(())
}

/// Sweep still works after an owner revoke and after a self-revoke, from the owner and
/// the relayer; the revoked agent's key cannot sweep any more.
#[tokio::test]
async fn sweep_after_owner_revoke_and_self_revoke() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let a = h.setup_agent(A).await?;
    let b = h.setup_agent(B).await?;
    let relayer = h.account("relayer").await?;
    h.set_relayer(Some(&relayer)).await?;

    h.revoke(A).await?;
    expect_ok(
        b.call(h.mandate.id(), "revoke_self")
            .gas(mandate_integration::AGENT_GAS)
            .transact()
            .await?,
    )?;

    let relayer_caller = Caller::Relayer {
        account: relayer.id().as_str().parse()?,
    };
    for (agent_id, key) in [(A, &a), (B, &b)] {
        let id = format!("{agent_id}-relayer");
        let _tx = h
            .sweep_from(&relayer, agent_id, Token::Usdc, SWEEP_AMOUNT, &id, None)
            .transact_async()
            .await?;
        let res = sign_now(&h, &sweep_key(agent_id, relayer_caller.clone(), &id)).await?;
        assert_eq!(res.status, RequestStatus::Signed, "{agent_id} via relayer");
        assert_eq!(eip3009(&res).0, SAFE);

        let id = format!("{agent_id}-owner");
        let _tx = h
            .owner_sweep(agent_id, Token::Eure, SWEEP_AMOUNT, &id, Some(eure_tx()))
            .await?
            .transact_async()
            .await?;
        let res = sign_now(&h, &sweep_key(agent_id, Caller::Owner, &id)).await?;
        assert_eq!(res.status, RequestStatus::Signed, "{agent_id} via owner");

        let tx = h
            .sweep_from(key, agent_id, Token::Usdc, SWEEP_AMOUNT, "own-key", None)
            .transact()
            .await;
        assert_key_gone(&rejection(tx)?);
    }
    Ok(())
}

/// At most one pending sweep per (agent, token), whoever asks; another token, or the same
/// token once the first is signed, is fine.
#[tokio::test]
async fn second_pending_sweep_for_the_same_agent_and_token_is_rejected() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;
    let relayer = h.account("relayer").await?;
    h.set_relayer(Some(&relayer)).await?;
    let relayer_caller = Caller::Relayer {
        account: relayer.id().as_str().parse()?,
    };

    let _first = h
        .sweep_from(&agent, A, Token::Usdc, SWEEP_AMOUNT, "ps-1", None)
        .transact_async()
        .await?;
    let first = sweep_key(A, Caller::Agent, "ps-1");
    h.wait_for_signs(1).await?;

    for tx in [
        h.sweep_from(&agent, A, Token::Usdc, 1, "ps-2", None),
        h.sweep_from(&relayer, A, Token::Usdc, 1, "ps-3", None),
        h.owner_sweep(A, Token::Usdc, 1, "ps-4", None).await?,
    ] {
        assert_code(&rejection(tx.transact().await)?, "ERR_SWEEP_PENDING");
    }

    // EURe is a separate slot.
    let _eure = h
        .sweep_from(&relayer, A, Token::Eure, 1, "ps-5", Some(eure_tx()))
        .transact_async()
        .await?;
    h.wait_for_signs(2).await?;
    let ps5 = h
        .get_request(&sweep_key(A, relayer_caller.clone(), "ps-5"))
        .await?;
    assert_eq!(ps5.map(|r| r.status), Some(RequestStatus::Pending));

    h.respond_for(&first).await?;
    let _again = h
        .sweep_from(&relayer, A, Token::Usdc, 1, "ps-6", None)
        .transact_async()
        .await?;
    h.wait_for_signs(2).await?;
    let ps6 = h.get_request(&sweep_key(A, relayer_caller, "ps-6")).await?;
    assert_eq!(ps6.map(|r| r.status), Some(RequestStatus::Pending));
    Ok(())
}

/// The relayer, the agent and the owner may each use the same `request_id`; every caller
/// gets its own EIP-3009 nonce. Within one caller the id is taken once, across shapes: the
/// agent's sweep cannot reuse its payment's id.
#[tokio::test]
async fn same_request_id_from_relayer_and_agent_gets_different_nonces() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;
    let relayer = h.account("relayer").await?;
    h.set_relayer(Some(&relayer)).await?;
    let relayer_caller = Caller::Relayer {
        account: relayer.id().as_str().parse()?,
    };

    let _tx = h
        .sweep_from(&relayer, A, Token::Usdc, SWEEP_AMOUNT, "same-id", None)
        .transact_async()
        .await?;
    let relayer_sweep = sign_now(&h, &sweep_key(A, relayer_caller, "same-id")).await?;
    let payment_key = request_pending(&h, &agent, A, "same-id", 1_000).await?;
    let payment = h.respond_for(&payment_key).await?;
    let _tx = h
        .owner_sweep(A, Token::Usdc, SWEEP_AMOUNT, "same-id", None)
        .await?
        .transact_async()
        .await?;
    let owner_sweep = sign_now(&h, &sweep_key(A, Caller::Owner, "same-id")).await?;

    let nonces = [
        eip3009(&relayer_sweep).2,
        eip3009(&payment).2,
        eip3009(&owner_sweep).2,
    ];
    assert_ne!(nonces[0], nonces[1]);
    assert_ne!(nonces[0], nonces[2]);
    assert_ne!(nonces[1], nonces[2]);
    for res in [&relayer_sweep, &payment, &owner_sweep] {
        assert_eq!(res.status, RequestStatus::Signed);
    }

    let tx = h
        .sweep_from(&agent, A, Token::Usdc, SWEEP_AMOUNT, "same-id", None)
        .transact()
        .await;
    assert_code(&rejection(tx)?, "ERR_DUPLICATE_REQUEST_ID");
    assert_eq!(h.get_request(&payment_key).await?.unwrap(), payment);
    Ok(())
}

// ---------- the agent key's methods ----------

/// The agent key is added with exactly `request_signature`, `sweep` and `revoke_self`; any
/// other method (owner calls, `resolve_reservation`, `expire_pending`, `link_agent`, the
/// callbacks, `new`) is refused before it runs.
#[tokio::test]
async fn agent_key_cannot_call_other_methods() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;
    h.set_signer_mode(SignerMode::Fail).await?;
    let tx = h.request_signature(&agent, "m-1", &x402(1_000)).await?;
    let unknown: Reservation = tx.await?.into_result()?.json()?;

    let pk = agent.secret_key().public_key();
    let info = h
        .contract_keys()
        .await?
        .into_iter()
        .find(|k| k.public_key == pk)
        .expect("agent key on the contract");
    match info.access_key.permission {
        AccessKeyPermission::FunctionCall(fc) => {
            assert_eq!(fc.receiver_id, h.mandate.id().as_str());
            assert_eq!(fc.method_names, AGENT_METHOD_NAMES.map(String::from));
        }
        other => panic!("agent key must be a function-call key, got {other:?}"),
    }

    let nonce = h.owner_nonce().await?;
    for method in [
        "new",
        "add_agent",
        "set_relayer",
        "set_mandate",
        "add_payee",
        "remove_payee",
        "link_agent",
        "revoke",
        "resolve_reservation",
        "expire_pending",
        "on_signature",
        "on_link_signature",
        "on_agent_key_added",
        "on_agent_key_deleted",
    ] {
        let err = rejection(
            agent
                .call(h.mandate.id(), method)
                .args_json(json!({ "key": unknown.key, "agent": A }))
                .gas(mandate_integration::AGENT_GAS)
                .transact()
                .await,
        )?;
        assert!(err.contains("MethodNameMismatch"), "{method}: {err}");
    }
    assert_eq!(h.owner_nonce().await?, nonce);
    assert_eq!(
        h.get_request(&unknown.key).await?.unwrap().status,
        RequestStatus::Unknown
    );
    assert!(!h.get_agent(A).await?.unwrap().linked);

    // The MPC callback is private for every other account too.
    let stranger = h.account("stranger").await?;
    let err = rejection(
        stranger
            .call(h.mandate.id(), "on_signature")
            .args_json(json!({ "key": unknown.key }))
            .gas(mandate_integration::AGENT_GAS)
            .transact()
            .await,
    )?;
    assert!(err.contains("private"), "{err}");
    Ok(())
}

// ---------- cross-mandate ----------

/// Agent A's key always acts as A: it cannot pay B's payees, spend B's budget, sweep B's
/// float or revoke B, and its request ids live apart from B's.
#[tokio::test]
async fn agent_a_cannot_act_under_b() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let a = h.setup_agent(A).await?;
    let b = h.setup_agent(B).await?;
    h.add_payee(
        B,
        &Payee::X402 {
            pay_to: PAY_TO_B.into(),
        },
    )
    .await?;

    // A naming B (an extra `agent` argument) to pay B's payee.
    let tx = a
        .call(h.mandate.id(), "request_signature")
        .args_json(json!({
            "request_id": "x-1",
            "shape": x402_to(PAY_TO_B, 1_000),
            "agent": B,
        }))
        .gas(mandate_integration::AGENT_GAS)
        .transact()
        .await;
    // Either the extra argument is ignored (and A has no such payee) or refused outright.
    let err = rejection(tx)?;
    assert!(
        err.contains("ERR_PAYEE_NOT_ALLOWED") || err.contains("Failed to deserialize"),
        "{err}"
    );
    assert_code(
        &request_rejected(&h, &a, "x-2", &x402_to(PAY_TO_B, 1_000)).await?,
        "ERR_PAYEE_NOT_ALLOWED",
    );
    for agent in [A, B] {
        for id in ["x-1", "x-2"] {
            assert!(h.get_request(&agent_request(agent, id)).await?.is_none());
        }
    }

    // A's budget is A's: exhausting it leaves B's untouched.
    request_pending(&h, &a, A, "shared-id", 10_000).await?;
    request_pending(&h, &a, A, "x-3", 10_000).await?;
    request_pending(&h, &a, A, "x-4", 5_000).await?;
    assert_code(
        &request_rejected(&h, &a, "x-5", &x402(1)).await?,
        "ERR_OVER_BUDGET",
    );
    assert_eq!(reserved(&h, B).await?, 0);
    // The same request_id under B is B's own request.
    let b_key = request_pending(&h, &b, B, "shared-id", 10_000).await?;
    assert_eq!(h.get_request(&b_key).await?.unwrap().key.agent, B);
    assert_eq!(reserved(&h, A).await?, 25_000);
    assert_eq!(reserved(&h, B).await?, 10_000);

    // A's key sweeping B.
    let tx = h
        .sweep_from(&a, B, Token::Usdc, SWEEP_AMOUNT, "x-sweep", None)
        .transact()
        .await;
    assert_code(&rejection(tx)?, "ERR_SWEEP_CALLER_NOT_ALLOWED");
    assert!(h
        .get_request(&sweep_key(B, Caller::Agent, "x-sweep"))
        .await?
        .is_none());

    // revoke_self from A's key revokes A only.
    expect_ok(
        a.call(h.mandate.id(), "revoke_self")
            .gas(mandate_integration::AGENT_GAS)
            .transact()
            .await?,
    )?;
    assert!(h.get_agent(A).await?.unwrap().revoked);
    assert!(!h.get_agent(B).await?.unwrap().revoked);
    assert!(h.get_mandate(B).await?.is_some());
    Ok(())
}

// ---------- link ----------

/// The agent cannot get the Monerium link message signed through `request_signature`: the
/// `link` shape is refused, so is a `link-` request id, and nothing reaches the MPC.
#[tokio::test]
async fn agent_cannot_request_the_link_message() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;

    assert_code(
        &request_rejected(&h, &agent, "link-req", &Shape::Link).await?,
        "ERR_INVALID_REQUEST_ID",
    );
    assert_code(
        &request_rejected(&h, &agent, "lnk-1", &Shape::Link).await?,
        "ERR_SHAPE_NOT_ALLOWED",
    );
    let sweep_shape = Shape::Sweep {
        token: Token::Usdc,
        amount: U128(SWEEP_AMOUNT),
    };
    assert_code(
        &request_rejected(&h, &agent, "lnk-2", &sweep_shape).await?,
        "ERR_SHAPE_NOT_ALLOWED",
    );
    assert_code(
        &request_rejected(&h, &agent, "link-1", &x402(1_000)).await?,
        "ERR_INVALID_REQUEST_ID",
    );

    assert!(h.pending_signs().await?.is_empty());
    assert!(!h.get_agent(A).await?.unwrap().linked);
    for id in ["link-req", "lnk-1", "lnk-2", "link-1"] {
        assert!(h.get_request(&agent_request(A, id)).await?.is_none());
    }
    assert_eq!(reserved(&h, A).await?, 0);
    Ok(())
}

// ---------- documented sweep error codes ----------

/// docs/interfaces.md §1 and §7: a second pending sweep fails with `ERR_SWEEP_PENDING`.
#[tokio::test]
async fn second_pending_sweep_uses_the_documented_code() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;
    let _first = h
        .sweep_from(&agent, A, Token::Usdc, SWEEP_AMOUNT, "pc-1", None)
        .transact_async()
        .await?;
    h.wait_for_signs(1).await?;
    let tx = h
        .sweep_from(&agent, A, Token::Usdc, 1, "pc-2", None)
        .transact()
        .await;
    assert_code(&rejection(tx)?, "ERR_SWEEP_PENDING");
    Ok(())
}

/// docs/interfaces.md §1 ("Who counts as the caller of a sweep"): another agent's key and
/// any other account fail with `ERR_SWEEP_CALLER_NOT_ALLOWED`.
#[tokio::test]
async fn sweep_by_a_disallowed_caller_uses_the_documented_code() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    h.setup_agent(A).await?;
    let other_agent = h.setup_agent(B).await?;
    let stranger = h.account("stranger").await?;
    for (caller, id) in [(&stranger, "dc-1"), (&other_agent, "dc-2")] {
        let tx = h
            .sweep_from(caller, A, Token::Usdc, SWEEP_AMOUNT, id, None)
            .transact()
            .await;
        assert_code(&rejection(tx)?, "ERR_SWEEP_CALLER_NOT_ALLOWED");
    }
    Ok(())
}

// ---------- shape 3: Monerium payout ----------

/// The documentation IBAN (docs/interfaces.md), not an account of ours.
const IBAN: &str = "DE89370400440532013000";
/// Another documentation IBAN, never allowlisted.
const OTHER_IBAN: &str = "GB33BUKB20201555555555";
const EURE_UNIT: u128 = 1_000_000_000_000_000_000;

fn payout(iban: &str, amount: &str, timestamp: u64) -> Shape {
    Shape::Payout(PayoutRequest {
        iban: iban.into(),
        amount: amount.into(),
        timestamp,
    })
}

fn iban_payee(iban: &str) -> Payee {
    Payee::Sepa { iban: iban.into() }
}

async fn sepa_reserved(h: &Harness, agent: &str) -> anyhow::Result<u128> {
    Ok(h.get_budget(agent, Rail::Sepa)
        .await?
        .map_or(0, |b| b.reserved.0))
}

/// Sends a payout and waits until it is reserved (`pending`, its `sign` call parked).
async fn payout_pending(
    h: &Harness,
    agent: &Account,
    agent_id: &str,
    request_id: &str,
    shape: &Shape,
) -> anyhow::Result<RequestKey> {
    let _tx = h.request_signature(agent, request_id, shape).await?;
    let key = agent_request(agent_id, request_id);
    for _ in 0..60 {
        if h.get_request(&key).await?.is_some() {
            return Ok(key);
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    anyhow::bail!("{request_id} was never reserved")
}

/// Sends a payout, answers its `sign` call and returns the signed reservation.
async fn payout_signed(
    h: &Harness,
    agent: &Account,
    agent_id: &str,
    request_id: &str,
    shape: &Shape,
) -> anyhow::Result<Reservation> {
    let key = payout_pending(h, agent, agent_id, request_id, shape).await?;
    let res = h.respond_for(&key).await?;
    assert_eq!(res.status, RequestStatus::Signed, "{request_id}");
    Ok(res)
}

fn message(res: &Reservation) -> &str {
    match &res.payload {
        SignedPayload::Message { text } => text,
        other => panic!("not a message payload: {other:?}"),
    }
}

/// D3: one agent never gets the same `(iban, amount, timestamp)` signed twice, under any
/// request id and any spelling of the amount (`1.5`, `1.50`, `01.50`), while the first is
/// pending and after it is signed. A different second or amount is a different order.
#[tokio::test]
async fn duplicate_payout_is_rejected() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(A).await?;
    h.add_payee(A, &iban_payee(IBAN)).await?;
    let ts = h.now_secs().await?;

    let first = payout_pending(&h, &agent, A, "po-1", &payout(IBAN, "1.5", ts)).await?;
    let pending = h.get_request(&first).await?.unwrap();
    assert_eq!(pending.status, RequestStatus::Pending);
    assert_eq!(pending.rail, Some(Rail::Sepa));
    assert_eq!(pending.amount.0, 15 * EURE_UNIT / 10);
    let text = message(&pending).to_string();
    assert!(
        text.starts_with(&format!("Send EUR 1.5 to {IBAN} at ")),
        "{text}"
    );

    // While the first is pending.
    assert_code(
        &request_rejected(&h, &agent, "po-2", &payout(IBAN, "1.50", ts)).await?,
        "ERR_DUPLICATE_PAYOUT",
    );
    assert_eq!(h.respond_for(&first).await?.status, RequestStatus::Signed);

    // After it is signed, under new request ids and other spellings of 1.5.
    for (id, amount) in [("po-3", "1.5"), ("po-4", "1.50"), ("po-5", "01.50")] {
        assert_code(
            &request_rejected(&h, &agent, id, &payout(IBAN, amount, ts)).await?,
            "ERR_DUPLICATE_PAYOUT",
        );
    }
    for id in ["po-2", "po-3", "po-4", "po-5"] {
        assert!(h.get_request(&agent_request(A, id)).await?.is_none());
    }
    assert_eq!(sepa_reserved(&h, A).await?, 15 * EURE_UNIT / 10);

    // Another second or another amount is a new order.
    let earlier = payout_signed(&h, &agent, A, "po-6", &payout(IBAN, "1.50", ts - 1)).await?;
    assert_ne!(message(&earlier), text);
    let other = payout_signed(&h, &agent, A, "po-7", &payout(IBAN, "1.51", ts)).await?;
    assert!(message(&other).starts_with(&format!("Send EUR 1.51 to {IBAN} at ")));
    assert_eq!(sepa_reserved(&h, A).await?, 451 * EURE_UNIT / 100);
    Ok(())
}

/// The dedupe is per agent (docs/interfaces.md, shape 3): A and B may both get the same order
/// signed, with the same message, but neither twice.
#[tokio::test]
async fn two_agents_may_sign_the_same_payout() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let a = h.setup_agent(A).await?;
    let b = h.setup_agent(B).await?;
    for agent in [A, B] {
        h.add_payee(agent, &iban_payee(IBAN)).await?;
    }
    let ts = h.now_secs().await?;

    // One at a time: both parked `sign` calls would carry the same digest.
    let signed_a = payout_signed(&h, &a, A, "same", &payout(IBAN, "42.50", ts)).await?;
    let signed_b = payout_signed(&h, &b, B, "same", &payout(IBAN, "42.5", ts)).await?;
    assert_eq!(message(&signed_a), message(&signed_b));
    assert_eq!(signed_a.digest, signed_b.digest);
    assert_ne!(signed_a.signature, signed_b.signature);
    assert_eq!(signed_a.key.agent, A);
    assert_eq!(signed_b.key.agent, B);

    for (agent, id) in [(&a, "again-a"), (&b, "again-b")] {
        assert_code(
            &request_rejected(&h, agent, id, &payout(IBAN, "42.5", ts)).await?,
            "ERR_DUPLICATE_PAYOUT",
        );
    }
    assert_eq!(sepa_reserved(&h, A).await?, 425 * EURE_UNIT / 10);
    assert_eq!(sepa_reserved(&h, B).await?, 425 * EURE_UNIT / 10);
    Ok(())
}

/// End to end: an IBAN not on this agent's allowlist, an invalid or over-cap amount, the SEPA
/// budget, and stale and future timestamps are refused before anything is reserved or sent to
/// the MPC. A refused order does not use up its dedupe key.
#[tokio::test]
async fn payout_checks_end_to_end() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let a = h.setup_agent(A).await?;
    let b = h.setup_agent(B).await?;
    let now = h.now_secs().await?;

    // Not allowlisted: a stranger's IBAN, A's x402 payee, and A's IBAN before it is added.
    let mut refused = vec![
        (
            "ib-1",
            payout(OTHER_IBAN, "10", now),
            "ERR_IBAN_NOT_ALLOWED",
        ),
        ("ib-2", payout(PAY_TO, "10", now), "ERR_IBAN_NOT_ALLOWED"),
        ("ib-3", payout(IBAN, "10", now), "ERR_IBAN_NOT_ALLOWED"),
    ];
    for (id, shape, code) in &refused {
        assert_code(&request_rejected(&h, &a, id, shape).await?, code);
    }
    h.add_payee(A, &iban_payee(IBAN)).await?;
    // B does not inherit A's allowlist.
    assert_code(
        &request_rejected(&h, &b, "ib-b", &payout(IBAN, "10", now)).await?,
        "ERR_IBAN_NOT_ALLOWED",
    );

    // Amounts: malformed or zero, then over the 50 EURe cap.
    for (id, amount) in [
        ("am-1", "1.505"),
        ("am-2", "0.00"),
        ("am-3", ".5"),
        ("am-4", "-1"),
    ] {
        refused.push((id, payout(IBAN, amount, now), "ERR_INVALID_AMOUNT"));
    }
    refused.push((
        "cap-1",
        payout(IBAN, "50.01", now),
        "ERR_OVER_PER_PAYMENT_CAP",
    ));

    // Timestamps: older than max_validity_secs - CLOCK_SKEW_SECS (240 s), or more than
    // CLOCK_SKEW_SECS (60 s) ahead; the margins absorb the blocks until inclusion.
    refused.push(("ts-1", payout(IBAN, "10", now - 300), "ERR_TIMESTAMP_STALE"));
    refused.push((
        "ts-2",
        payout(IBAN, "10", now + 600),
        "ERR_TIMESTAMP_FUTURE",
    ));
    for (id, shape, code) in &refused[3..] {
        assert_code(&request_rejected(&h, &a, id, shape).await?, code);
    }
    for (id, _, _) in &refused {
        assert!(h.get_request(&agent_request(A, id)).await?.is_none());
    }
    assert!(h.get_request(&agent_request(B, "ib-b")).await?.is_none());
    assert!(h.pending_signs().await?.is_empty());
    assert_eq!(sepa_reserved(&h, A).await?, 0);

    // The order refused for its IBAN (`ib-3`) is signed once the IBAN is allowlisted: the
    // refusal did not record it as a duplicate.
    let res = payout_signed(&h, &a, A, "ok-1", &payout(IBAN, "10", now)).await?;
    assert_eq!(res.valid_before, now + 240);
    // At the cap exactly, and a timestamp well inside the window.
    let now = h.now_secs().await?;
    payout_signed(&h, &a, A, "ok-2", &payout(IBAN, "50", now)).await?;
    payout_signed(&h, &a, A, "ok-3", &payout(IBAN, "50", now - 180)).await?;
    assert_eq!(sepa_reserved(&h, A).await?, 110 * EURE_UNIT);

    // Budget: 200 EURe a week, 110 used.
    payout_signed(&h, &a, A, "ok-4", &payout(IBAN, "50", now - 1)).await?;
    assert_code(
        &request_rejected(&h, &a, "bud-1", &payout(IBAN, "40.01", now)).await?,
        "ERR_OVER_BUDGET",
    );
    payout_signed(&h, &a, A, "ok-5", &payout(IBAN, "40", now - 2)).await?;
    assert_code(
        &request_rejected(&h, &a, "bud-2", &payout(IBAN, "0.01", now - 3)).await?,
        "ERR_OVER_BUDGET",
    );
    assert!(h.get_request(&agent_request(A, "bud-1")).await?.is_none());
    assert_eq!(sepa_reserved(&h, A).await?, 200 * EURE_UNIT);
    // The x402 budget is separate.
    assert_eq!(reserved(&h, A).await?, 0);
    Ok(())
}
