//! T1 smoke tests in the sandbox: one x402 request signed end to end, one the MPC fails,
//! one left pending.

use mandate::types::{Rail, RequestStatus, Reservation};
use mandate_integration::fixtures::{agent_request, x402};
use mandate_integration::{mpc, Harness, SignerMode};

const AGENT: &str = "agent-a";

#[tokio::test]
async fn x402_request_is_signed_end_to_end() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    // Owner calls (add_agent, set_mandate, add_payee) each carry a passkey assertion.
    let agent = h.setup_agent(AGENT).await?;
    assert_eq!(h.owner_nonce().await?, 3);

    let tx = h
        .request_signature(&agent, "pay-0001", &x402(10_000))
        .await?;
    let sign = h.wait_for_signs(1).await?.remove(0);
    assert_eq!(sign.predecessor, h.mandate.id().as_str());
    assert_eq!(sign.path, AGENT, "path is the agent id");
    assert_eq!(sign.domain_id, 0);

    let key = agent_request(AGENT, "pay-0001");
    let pending = h.get_request(&key).await?.expect("reservation");
    assert_eq!(pending.status, RequestStatus::Pending);
    assert_eq!(
        pending.digest,
        format!("0x{}", sign.payload),
        "MPC signs the contract's digest"
    );

    h.respond_signed(&sign).await?;
    let returned: Reservation = tx.await?.into_result()?.json()?;
    assert_eq!(returned.status, RequestStatus::Signed);

    let stored = h.get_request(&key).await?.expect("reservation");
    assert_eq!(stored.status, RequestStatus::Signed);
    let sig = stored.signature.as_ref().expect("signature stored");
    assert_eq!(returned.signature.as_ref(), Some(sig));
    assert_eq!(
        mpc::recover_address(&stored.digest, sig)?,
        h.agent_evm_address(AGENT),
        "signature recovers to the agent's derived EOA"
    );
    assert_eq!(
        h.get_budget(AGENT, Rail::X402).await?.unwrap().reserved.0,
        10_000
    );
    assert!(h.pending_signs().await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn failed_mpc_call_leaves_the_reservation_unknown() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(AGENT).await?;
    h.set_signer_mode(SignerMode::Fail).await?;

    let tx = h
        .request_signature(&agent, "pay-0002", &x402(4_000))
        .await?;
    // on_signature never panics, so the tx succeeds and returns the reservation.
    let returned: Reservation = tx.await?.into_result()?.json()?;
    assert_eq!(returned.status, RequestStatus::Unknown);

    let stored = h
        .get_request(&agent_request(AGENT, "pay-0002"))
        .await?
        .unwrap();
    assert_eq!(stored.status, RequestStatus::Unknown);
    assert!(stored.signature.is_none());
    assert!(
        stored.counts_against_budget,
        "unknown still counts as spent"
    );
    assert_eq!(
        h.get_budget(AGENT, Rail::X402).await?.unwrap().reserved.0,
        4_000
    );
    Ok(())
}

#[tokio::test]
async fn unanswered_request_stays_pending() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let agent = h.setup_agent(AGENT).await?;

    let _tx = h
        .request_signature(&agent, "pay-0003", &x402(6_000))
        .await?;
    h.wait_for_signs(1).await?;
    h.advance_blocks(20).await?;

    let stored = h
        .get_request(&agent_request(AGENT, "pay-0003"))
        .await?
        .unwrap();
    assert_eq!(stored.status, RequestStatus::Pending);
    assert!(stored.signature.is_none());
    assert_eq!(
        h.get_budget(AGENT, Rail::X402).await?.unwrap().reserved.0,
        6_000
    );
    assert_eq!(h.pending_signs().await?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn advance_secs_moves_block_time() -> anyhow::Result<()> {
    let h = Harness::new().await?;
    let start = h.now_secs().await?;
    h.advance_secs(400).await?;
    assert!(h.now_secs().await? >= start + 400);
    Ok(())
}

/// SEC-4: `new` is `#[private]`, so nobody can front-run the deploy with their own
/// owner if deploy and init are ever split.
#[tokio::test]
async fn new_is_callable_only_by_the_contract_account() -> anyhow::Result<()> {
    let h = Harness::deployed().await?;
    let err = h
        .init_from(&h.submitter)
        .await?
        .into_result()
        .expect_err("new from another account must fail");
    assert!(format!("{err:?}").contains("private"), "{err:?}");
    h.init_from(h.mandate.as_account()).await?.into_result()?;
    Ok(())
}
