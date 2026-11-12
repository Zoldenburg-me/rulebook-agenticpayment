# PP-W1: one real sandbox webhook event, verified — PASS (contract call not live)

Run 2026-11-09 10:20–10:41 UTC. No credential, token or full email is in this file; the payee is masked as PP3 logs it. Batch, item, transaction, webhook and event ids are sandbox values.

**Setup.** The receiver (`node src/cli/webhook.ts`, `PP_WEBHOOK_REPORT=log`) listened on 127.0.0.1:8789, exposed by a cloudflared quick tunnel (`https://<random>.trycloudflare.com/paypal/webhook`). `node scripts/register-webhook.ts create <url>` subscribed it to the 11 event types in `EVENT_STATUS` on the sandbox app (webhook id `8TV98324RF886052U`). PP3 and the receiver shared one store dir (`PP3_STORE_DIR`).

**What was live and what was not.** The payout, PayPal's webhook delivery through the tunnel, PayPal's `verify-webhook-signature` answer and the receiver's matching of the event to PP3's record were all real. The NEAR side was not: as in PP3's RESULT.md, `scripts/live-sandbox.ts` stubs the NEAR views and signs with a throwaway key, and with `PP_WEBHOOK_REPORT=log` the receiver logs the `report_settlement` call instead of sending it, because no contract with `report_settlement` is deployed on testnet yet.

| # | Step | Result |
|---|---|---|
| 1 | `scripts/live-sandbox.ts`: PP3 submits `Send USD 1.00 to sb…@personal.example.com at 2026-11-09T10:32:20Z ref pp3-live-1794220340` | `submitted`, batch **VBEWE4F5VN6S6**; a resubmission is blocked locally (`PP3_DUPLICATE_REQUEST`) |
| 2 | Batch and item polled until final | item **NDKFTZF9TALM2** `SUCCESS`, transaction 3BS74009A35747359, USD 1.00, fee USD 0.02 (~25 s) |
| 3 | PayPal delivers `PAYMENT.PAYOUTS-ITEM.SUCCEEDED`, event **WH-9L294860G5265764C-28K60750N2490254J** (created 10:32:55Z), through the tunnel | `verify-webhook-signature` → `SUCCESS`. The event matched PP3's record by `sender_item_id = request_id` and `payout_batch_id`, and the receiver logged `report_settlement {"agent":"agent-live","request_id":"pp3-live-1794220340","status":"completed","paypal_id":"NDKFTZF9TALM2"}` (10:33:09Z) |
| 4 | `POST /v1/notifications/webhooks-events/{id}/resend` (PayPal replays the real signed event), with a fresh seen dir and the final logging | verified again: `verified PAYMENT.PAYOUTS-ITEM.SUCCEEDED WH-9L29…254J: reported completed for agent-live/pp3-live-1794220340 (NDKFTZF9TALM2)` |
| 5 | Resend again | `event WH-9L29…254J already handled`: 200, not reported twice |
| 6 | A forged `PAYMENT.PAYOUTS-ITEM.FAILED` for the same item, POSTed through the tunnel with made-up `PAYPAL-*` headers | PayPal answered `verification_status: FAILURE` (debug_id ca57c3390cfae); receiver **400 `unverified`**, dropped, nothing reported |

Receiver log for steps 4–6 (complete):
```
2026-11-09T10:40:25.095Z report (log only, no contract call): {"agent":"agent-live","request_id":"pp3-live-1794220340","status":"completed","paypal_id":"NDKFTZF9TALM2"}
2026-11-09T10:40:25.097Z verified PAYMENT.PAYOUTS-ITEM.SUCCEEDED WH-9L294860G5265764C-28K60750N2490254J: reported completed for agent-live/pp3-live-1794220340 (NDKFTZF9TALM2)
2026-11-09T10:40:37.504Z event WH-9L294860G5265764C-28K60750N2490254J already handled
2026-11-09T10:40:49.153Z dropped: verification 200 FAILURE debug_id ca57c3390cfae
```

Two environment notes: QUIC to Cloudflare failed here, so the tunnel ran with `--protocol http2`. A `~/.cloudflared/config.yml` with ingress rules makes a quick tunnel answer 404 to everything; run it with `--config <empty file>`.

## Not done live
- **`report_settlement` on testnet, and the agent's next payout refused on chain.** This needs the PP-W1 contract deployed (a state change: fresh account, `pnpm deploy-contract`), `set_settlement_reporter` (O1 has no CLI for it yet), an MPC-signed shape 4 order that PP3 submits with real NEAR views, and then an adverse event. The contract tests cover the refusal (`contract/tests/pw1_settlement.rs`).
- **A real adverse event** (`FAILED`, `RETURNED`, `BLOCKED`, a capture reversal or a dispute). The sandbox has no clean way to make a payout fail; `UNCLAIMED` (unregistered receiver) is not adverse, and it takes 30 days to become `RETURNED`. Adverse events are covered offline (`test/webhook.test.ts`).
- **Hosting for judging (Dec 1–15).** The quick tunnel URL changes each run and lasts only while this machine runs it. A stable host (Render, or a named Cloudflare tunnel) is still to be set up, and the webhook re-registered for it.
