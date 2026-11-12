# PP3: PayPal rail, live sandbox payout — PASS

**Rerun 2026-11-05 02:41 UTC** after `sender_batch_id` and `PayPal-Request-Id` became `batchId(agent, request_id)` (64 hex chars): `submitted`, batch **XGE5TQPUBA9ZA**; PayPal's 201 echoed the derived `sender_batch_id` (so the new match check passed); the resubmission was refused locally with no PayPal call; batch and item reached `SUCCESS` (item `2EFQSDXLAMXKU`, USD 1.00, fee USD 0.02). The table below is the first run, with `sender_batch_id = request_id`.

Run 2026-11-05 02:03 UTC with `node scripts/live-sandbox.ts` against `https://api-m.sandbox.paypal.com`. The receiver is the personal sandbox account `PAYPAL_SANDBOX_RECEIVER_EMAIL` from `~/.config/nearh/paypal-sandbox.env`, shown masked as PP3 logs it. No credential, token or full email is in this file. Batch, item and transaction ids are sandbox values.

**What was live and what was stubbed:** no shape 4 contract is deployed yet (PP2 had not merged yet), so the NEAR views were an in-memory stub and a throwaway local secp256k1 key stood in for the MPC-derived agent EOA. The signature was a real one over the EIP-191 hash of the shape 4 text, and `submitPaypalPayout` checked it. Everything from the PayPal side onwards was the real path: the sandbox client, the claim, the POST and PayPal's answer.

| # | Step | Result |
|---|---|---|
| 1 | Signed text | `Send USD 1.00 to sb…@personal.example.com at 2026-11-05T02:03:43Z ref pp3-live-1793844223` |
| 2 | `submitPaypalPayout`: checks, OAuth, claim, `POST /v1/payments/payouts` with `sender_batch_id = sender_item_id = PayPal-Request-Id = pp3-live-1793844223` | `submitted`, **`payout_batch_id` WV574N6ZH2CYA**, `batch_status: PENDING`; recorded in the store |
| 3 | The same order again | `blocked`, `PP3_DUPLICATE_REQUEST` (`submitted, batch WV574N6ZH2CYA`), **no PayPal call** |
| 4 | Poll `GET /v1/payments/payouts/WV574N6ZH2CYA` every 5 s | batch `PENDING` → `PROCESSING` → **`SUCCESS`**; item `PENDING` → **`SUCCESS`** (~15 s; batch final ~25 s) |
| 5 | Final | item `S5WD75AYHNGH4`, transaction `6N080599TG675082H`, amount USD 1.00, fee USD 0.02 |

## Not checked live
- An order signed by the real MPC through a deployed shape 4 contract (needs PP2 deployed on testnet).
- Running through the HTTP service (`pnpm start`); the run called `submitPaypalPayout` directly. The service is covered by the offline tests.
- PayPal's own duplicate `sender_batch_id` refusal (PP-S1 step 4 has it; PP3 refuses locally first, so it never got there).
