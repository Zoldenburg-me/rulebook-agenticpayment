# PP-S1: PayPal sandbox Payouts — PASS (with one receiver caveat)

Run 2026-11-04 22:27 UTC against `https://api-m.sandbox.paypal.com`. Full redacted responses are in [evidence.json](evidence.json).
Client id, secret, access token and the receiver email are withheld; PayPal debug ids, batch/item ids and transaction ids are sandbox values and kept.

## Steps

| # | Call | Result |
|---|---|---|
| 1 | `POST /v1/oauth2/token` (client credentials) | **200**, `expires_in` 32400 s, granted scope includes Payouts. Payouts is enabled for the app |
| 2 | `POST /v1/payments/payouts`, 1 item, 1.00 USD, `recipient_type: EMAIL`, `sender_batch_id: nearh-spike-1793831226`, note "nearh spike" | **201**, `payout_batch_id` **92APWP7M4TFJW**, `batch_status: PENDING` |
| 3 | Poll `GET /v1/payments/payouts/92APWP7M4TFJW` every 5 s | batch `PENDING` → `PROCESSING` (~11 s) → `SUCCESS` (~28 s); item `PENDING` → **`UNCLAIMED`** (~17 s), item error **`RECEIVER_UNREGISTERED`**. Item `KXSH7GDR2795Y`, transaction `52391616XF2822047`, fee 0.02 USD |
| 4 | Same body, **same** `sender_batch_id` | **400** `USER_BUSINESS_ERROR`, details `[{field: "SENDER_BATCH_ID", location: "body", issue: "Batch with given sender_batch_id already exists"}]`, with a `self` link to the original batch 92APWP7M4TFJW. No second payout |
| 5 | Same item (same receiver, amount, `sender_item_id`), **new** `sender_batch_id: nearh-spike-1793831226-b` | **201**, new batch **T2WC4UAVNUJFA**, same path to `SUCCESS` / `UNCLAIMED` in ~28 s. PayPal does **not** dedupe on item content |

### Caveat: receiver not registered
**Rerun (lead, Nov 4 23:4x) with a personal sandbox receiver (`sb-…@personal.example.com`): PASS.** Both items reached **`SUCCESS`** (batch `PENDING` → `PROCESSING` → `SUCCESS`, item `PENDING` → `SUCCESS`); the same `sender_batch_id` was again refused with 400, and the same item under a new `sender_batch_id` was paid again. Batch ids in evidence.json: see evidence.json. The first run (rows 3 and 5 above) sent to a `sb-…@business.example.com` address and ended `UNCLAIMED` / `RECEIVER_UNREGISTERED`: the receiver must be a personal sandbox account, not the business (sender) account.

Other observations:
- PayPal **masks the receiver** in GET responses (17-char masked string, not the address we sent). The rail cannot read back the payee from PayPal; it must store what it sent.
- The sender sandbox account is EUR-funded: each 1.00 USD item shows `currency_conversion` EUR 0.94 → USD 1.02 and `funding_source: BALANCE`.
- Batch `SUCCESS` means the batch was processed, not that the money arrived; the item status is what counts.

## What this means for PP2 / PP3
- **Message fields (PP2):** the order needs `amount` (2-decimal string, USD), `payee` (email; Venmo would be `recipient_type: PHONE` + `recipient_wallet: VENMO`, not tested), `request_id`, timestamp. Map `request_id` → `sender_batch_id` (and `sender_item_id`), note = `ref {request_id}`.
- **Idempotency (PP3):** PayPal refuses a reused `sender_batch_id` with 400 `USER_BUSINESS_ERROR` + `details[].field == "SENDER_BATCH_ID"`. Match on that field/issue, not on the generic error name, which covers other business errors. On that error, follow the `self` link / GET the existing batch rather than treating it as a failure. PayPal's own dedupe window for `sender_batch_id` was not measured; the rail must still dedupe by `request_id` itself, because a new id with identical content is paid again (step 5).
- **Final states:** batch `SUCCESS | DENIED | CANCELED`; item `SUCCESS | FAILED | RETURNED | UNCLAIMED | BLOCKED | REFUNDED | REVERSED | DENIED` (`PENDING`, `ONHOLD` are not final). `UNCLAIMED` is terminal for the API call but can later become `RETURNED` after 30 days; receipts should show it as "sent, unclaimed".
- **Timing:** create returns `PENDING` at once; item final in ~17 s, batch final in ~24–28 s. The rail should return the `payout_batch_id` immediately and poll (or use webhooks, not tested) for the receipt.
- **Fees:** 0.02 USD per item in sandbox; the mandate budget should decide whether fees count against it.

## Not checked
- An item reaching `SUCCESS` (blocked by the receiver caveat above).
- Venmo / phone recipients, multi-item batches, webhooks, cancel of an unclaimed item, insufficient-funds and `DENIED` paths.
- PayPal's dedupe window length for `sender_batch_id`.
- Concurrent submissions of the same `sender_batch_id` (race).

## Reproduce
```sh
node spikes/paypal/payouts.mjs   # Node 22+, no deps
```
Reads `~/.config/nearh/paypal-sandbox.env` (override path with `PAYPAL_ENV_FILE`), refuses unless `PAYPAL_ENV=sandbox`, writes redacted `spikes/paypal/evidence.json`. Sends two 1.00 USD sandbox payouts per run. Exit code 3 with the error name if Payouts is not enabled for the app.
