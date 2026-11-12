# PayPal rail (PP3)

The `pay_paypal` backend. The agent hands it a PayPal payout order the contract signed (shape 4, `contract/src/shapes/paypal.rs`), and PP3 submits it to the PayPal **sandbox** Payouts API, at most once per `(agent, request_id)`, with `sender_batch_id = batchId(agent, request_id)` (hex sha256 of `agent\nrequest_id`, 64 chars). Only PP3 holds the PayPal credentials, never the agent. Modelled on the Monerium rail (nearH M1): same checks-then-claim flow, store, service auth and redaction.

## What it checks before calling PayPal

`submitPaypalPayout` (`src/payout.ts`) takes `{ agent, request_id, payee, amount, timestamp, signature: {r, s, v} }`:

1. Input shape, nothing rewritten: agent id and `request_id` as in the contract (`[A-Za-z0-9._:-]{1,64}`); `payee` a lowercase email or `@` Venmo handle as `normalize_receiver` stores it (sent as recipient type `EMAIL` or `VENMO_HANDLE`, the receiver exactly as signed); `amount` canonical USD (`^(0|[1-9][0-9]*)\.[0-9]{2}$`, not zero); `timestamp` unix seconds. Venmo payouts are not yet exercised against the sandbox.
2. **Once per request_id:** a record for `(agent, request_id)` in the store means `PP3_DUPLICATE_REQUEST`, without calling NEAR or PayPal. PayPal pays the same item again under a new `sender_batch_id` (PP-S1), so this store is what stops a second payout.
3. The text is rebuilt from the fields as `Send USD {amount} to {payee} at {YYYY-MM-DDTHH:MM:SSZ} ref {request_id}` (byte-identical to `paypal_message`), and the signature must recover to the agent EOA (`get_agent`; not revoked) over its EIP-191 hash. A changed amount, payee, timestamp or `request_id`, or another key, fails here (`PP3_BAD_SIGNATURE`).
4. `get_request({agent, caller: agent, request_id})`: a `paypal` shape on the `paypal` rail with status **`signed`**, whose text is the rebuilt text and whose digest is its hash; now ≤ `valid_before`.
5. The payee is on the agent's PayPal payees (`get_payees`) right now.

Any failure is `blocked` with a `PP3_*` code, before any PayPal call. Then PP3 gets an OAuth token (an auth failure leaves the request unclaimed), re-checks that at least `SUBMIT_MARGIN_SECS` (30 s, the POST timeout) are left before `valid_before`, claims the record (`O_EXCL` file create), and POSTs one item: `recipient_type: EMAIL`, `amount {value, currency: USD}`, `receiver`, `sender_item_id = request_id`, `note: ref {request_id}`, with `sender_batch_id` and `PayPal-Request-Id` both `batchId(agent, request_id)`. Both are unique per PayPal account, not per agent, so they are derived from the pair: two agents with the same `request_id` never collide, and PayPal cannot replay one agent's cached answer to another.

| PayPal answer | Result | Record |
|---|---|---|
| 2xx for another `sender_batch_header.sender_batch_id` (or none) | `pending`, `PAYPAL_BATCH_MISMATCH` | `unknown`, the foreign batch id not stored |
| 2xx with this order's `sender_batch_id` and a `payout_batch_id`, not `DENIED` | `submitted` + `payout_batch_id` | `submitted`, batch id stored |
| 400 with `details[].field == "SENDER_BATCH_ID"` "already exists" (PP-S1) | `failed`, `PAYPAL_DUPLICATE_BATCH` | `duplicate_batch`, original batch id from the `self` link |
| 429 | `failed`, `PAYPAL_RATE_LIMITED` | released: no record, the same order can be sent again later |
| other 4xx (and a 429 whose release failed) | `failed`, `PAYPAL_REFUSED` | `refused` |
| 5xx, lost in transit, 2xx without a batch id | `pending`, `PAYPAL_OUTCOME_UNKNOWN` | `unknown` |

A record is never retried, and deleted only on a 429: PayPal created nothing, and a retry carries the same `sender_batch_id`, which PayPal refuses if a batch did exist. PP3 does not back off itself; the caller retries later. An unknown outcome must be checked against the sandbox payouts by hand; a new attempt needs a new `request_id` and a new contract signature. If writing the outcome fails after PayPal answered, the result still goes back, the log line `record-failed <request_id>: ... batch <id>` names the batch, and the record stays `submitting`, which still blocks a resubmission.

`submitted` means PayPal accepted the batch (`PENDING`), not that the money arrived; the item status from `GET /v1/payments/payouts/{batch}` is final in ~15–30 s (see RESULT.md).

## Secrets and redaction

- Credentials come from `PAYPAL_ENV_FILE`, else `~/.config/nearh/paypal-sandbox.env` (names in `.env.example`). They are parsed into a private object, **not** loaded into `process.env`, so no child process inherits them. `PAYPAL_ENV` must be `sandbox`; the base URL is fixed to `api-m.sandbox.paypal.com`, so the secret and token go nowhere else.
- Payees are masked (`su…@example.com`) in every detail, log line and store record. Text from PayPal and thrown errors also go through `scrub`: client id and secret removed by value, anything token-like becomes `<REDACTED>`.

## Running

```sh
cd rails/paypal
export CONTRACT_ID=<contract>.testnet   # NEAR_RPC optional, testnet hosts only
pnpm start                               # POST /payouts on 127.0.0.1:${PP3_PORT:-8788}
pnpm submit '<PaypalOrder JSON>'         # one order, without the service
node scripts/live-sandbox.ts             # live sandbox check with NEAR stubbed (RESULT.md)
```

The service is M1's: 127.0.0.1 only (403 otherwise), `agent`/`request_id` validated before anything is logged (400), a per-agent bearer token from `PP3_AGENT_TOKENS` (`agent=token,...`, 32–256 chars each) compared in constant time (401 before any NEAR or PayPal call or claim), a body over 4096 bytes is 413, a half-sent body submits nothing, a PayPal auth failure is `failed` `PP3_AUTH_FAILED` and an RPC or store failure before the claim is 502 `PP3_ERROR` (both unclaimed, safe to retry). Records go to `PP3_STORE_DIR` (default `rails/paypal/.orders/`, gitignored).

## Settlement webhooks (PP-W1)

`submitted` is not money arrived. The receiver (`src/webhook.ts`, `pnpm webhook`) takes PayPal's webhooks for `PAYMENT.PAYOUTS-ITEM.*` (SUCCEEDED, UNCLAIMED, FAILED, DENIED, RETURNED, BLOCKED, REFUNDED), `PAYMENT.CAPTURE.COMPLETED/REFUNDED/REVERSED` and `CUSTOMER.DISPUTE.CREATED`, and tells the contract through `report_settlement`, signed by the one `settlement_reporter` account. The contract only tightens: `completed` marks the receipt PayPal-confirmed; an adverse status suspends that payee for the agent until the owner calls `reinstate_payee`. Caps, budgets and reservations never move.

For each `POST /paypal/webhook`:
1. All five `PAYPAL-*` signature headers present and the body a JSON object, or **400**, no PayPal call.
2. `POST /v1/notifications/verify-webhook-signature` with the headers, `PAYPAL_WEBHOOK_ID` and the **raw body embedded byte for byte** (re-serialising would break the signature). Anything but `verification_status: SUCCESS` is **400** and dropped; no answer or a 5xx is **503**, so PayPal delivers again. Nothing unverified is ever reported.
3. An event id already handled is 200 `duplicate`; a type outside the list is 200 `ignored`.
4. Matched to exactly one PP3 record in state `submitted` among the agents in `PP3_AGENT_TOKENS`: a payout item by `sender_item_id = request_id` **and** its `payout_batch_id`; a capture by `custom_id`/`invoice_id`, a dispute by its transactions' `custom`/`invoice_number`. No match, or more than one, is 200 `no_order`, not guessed.
5. `report_settlement(agent, request_id, status, paypal_id)` via near-cli-rs as `SETTLEMENT_REPORTER` (legacy keychain). A failed tx is **500** and the event is not marked handled, so the redelivery reports it.

PP3 itself also refuses a suspended payee (`PP3_PAYEE_SUSPENDED`, from `get_suspended_payees`), so an order signed before the suspension is not sent either.

```sh
cloudflared tunnel --config <empty file> --url http://127.0.0.1:8789   # or any public HTTPS host
node scripts/register-webhook.ts create https://<host>/paypal/webhook  # prints the webhook id; also list | delete <id>
export PAYPAL_WEBHOOK_ID=<id> PP3_AGENT_TOKENS=... CONTRACT_ID=<contract>.testnet SETTLEMENT_REPORTER=<reporter>.testnet
pnpm webhook                                                           # 127.0.0.1:${PP_WEBHOOK_PORT:-8789}; PP_WEBHOOK_REPORT=log skips the contract call
```

Handled event ids go to `PP_WEBHOOK_SEEN_DIR` (default `.webhook-seen/`, gitignored). The handler answers after verifying and reporting (a near-cli tx takes a few seconds, inside PayPal's 30 s window), not asynchronously. One real sandbox event, verified, is in [RESULT-webhooks.md](RESULT-webhooks.md).

## Refunds and the Agent Toolkit (PP-T1)

`pnpm refunds` (`src/refund-server.ts`, 127.0.0.1:${PP_REFUND_PORT:-8790}, same per-agent tokens as PP3) serves the merchant-side support agent. The rail runs the agent's PayPal tools (`src/toolkit.ts`): PayPal's tool definitions from `@paypal/agent-toolkit` 1.11.0, copied in rather than depended on (its transitive tree fails `pnpm audit`), and the reads `get_order` and `get_refund` as direct sandbox REST calls with the credentials; the agent never has them.

- `GET /tools?agent=` returns the toolkit's own definitions of `get_order`, `get_refund` and `create_refund`.
- `POST /tools/call {agent, name, arguments}` runs `get_order` or `get_refund` through the toolkit; the answer loses the credentials (by value) and full emails. `create_refund` here is 403: it runs only as a signed order.
- `POST /refunds {agent, request_id, capture_id, amount, signature}` (`src/refund.ts`): the same checks-then-claim flow as payouts. Canonical fields; once per `(agent, request_id)` (`PP_REFUND_STORE_DIR`, default `.refunds/`); the signature recovers to the agent EOA over the rebuilt `Refund USD {amount} of capture {capture_id} ref {request_id}`; `get_request` is a `signed` `refund` on the `paypal_refund` rail with that text and digest, not past `valid_before`. Then, under a per-capture lock, `GET /v2/payments/captures/{id}` (USD, `COMPLETED` or `PARTIALLY_REFUNDED`) and the refunds its order lists for that capture (`COMPLETED` and `PENDING` count): an amount above captured minus refunded is `PP3_REFUND_EXCEEDS_CAPTURE`, before any claim. One `POST /v2/payments/captures/{id}/refund` with `PayPal-Request-Id` = hex sha256 of `refund\nagent\nrequest_id`. A 2xx with a refund id, `COMPLETED`/`PENDING` and the same amount is `refunded`; 4xx `PAYPAL_REFUSED`; 5xx, transit or a mismatched 2xx `PAYPAL_OUTCOME_UNKNOWN` (check the capture's refunds by hand); 429 released. Never retried.
- The per-capture lock is per process: run one refund service per PayPal account. PayPal itself also refuses an over-refund (`422 REFUND_AMOUNT_EXCEEDED`).

`scripts/seed-captures.ts "12.00:Mug" ...` makes refundable sandbox captures (card-funded orders the sandbox captures at once); `scripts/show-captures.ts <id> ...` prints captured, refunded and left as PayPal reports them. Recorded run: [demo/evidence/pt1-refunds.md](../../demo/evidence/pt1-refunds.md).

## Tests

`pnpm test` runs `test/payout.test.ts`, `test/webhook.test.ts` and `test/refund.test.ts` (PP-T1: the message vector shared with refund.rs, tampered fields with zero PayPal calls, non-refund reservations, captured-minus-refunded with pending and other captures' refunds, concurrent refunds of one capture, unreadable or non-USD captures, PayPal's answers, the toolkit's tool set and redaction, the service routes) (PP-W1: fail-closed verification, raw-body embedding, event mapping, dedupe, order matching, redelivery after a failed report, the HTTP route) offline: NEAR is an in-memory stub and PayPal is the sandbox client over a fake `fetch` that records every call. Signatures are real secp256k1 signatures. Covered: the message and digest match paypal.rs's test vector; an accepted payout (body, headers, stored batch id, no full payee anywhere); a tampered amount, payee, `request_id`, timestamp or signature (other key, other message, flipped `v`, malformed), and an attacker's re-signed order, all refused with **zero PayPal calls** and no claim; fields the contract did not reserve; released/unknown/pending/expired/other-shape reservations and revoked/unknown agents; a payee removed from the allowlist; non-canonical input; a Venmo payee (`VENMO_HANDLE`, masked as `@de…`); a resubmitted `request_id` (also with changed fields) refused with no NEAR or PayPal call; concurrent submissions make one POST; the file store across a restart; the derived ids (distinct for two agents with one `request_id`); a 2xx for another `sender_batch_id` refused; PayPal's duplicate-batch answer, a 429 (claim released, then the same order goes through; a failed release stays `refused`), other refusals, 5xx, transit failure, missing batch id and `DENIED`; auth failure (unclaimed, no secret in the error); token caching; expiry during auth; a failed store update; and the HTTP service (routes, auth, 413 counted in bytes, disconnects, 408 for a body that trickles or stalls, invalid `request_id`).

## PP-V1: pay from the owner's PayPal wallet (shape 5, `src/vault.ts`)

On when `PP_OWNER_TOKEN` is set (environment or credentials file). A vaulted MERCHANT token is for charges "directly with a merchant" (PP-V0, `spikes/paypal-vault/RESULT.md`), so a charge never names a third-party payee and is two calls: **Orders v2 CAPTURE on the `vault_id` into the rail's account, then the Payouts call above to the merchant**.

| Route | Auth | Does |
|---|---|---|
| `POST /vault/connect {agent}` | owner token | `POST /v3/vault/setup-tokens` (MERCHANT, IMMEDIATE); returns PayPal's `approve_url` for the owner |
| `POST /vault/confirm {agent}` | owner token | after the owner approved: `POST /v3/vault/payment-tokens`; stores the payment token id in `.vault/` (0600) |
| `GET /vault/status?agent=` | owner token | `none` / `approval_required` / `active` / `revoked`, never a token id |
| `POST /vault/revoke {agent}` | owner token | marks revoked, `DELETE /v3/vault/payment-tokens/{id}`, then `GET` must answer 404 |
| `POST /checkout` | agent token | `chargeCheckout`: same checks as `/payouts` over the shape 5 text `Charge USD {amount} to merchant {payee} for order {order_ref} at {ts} ref {request_id}` and a `paypal_checkout` reservation; vault active; ≥ 60 s left; claim; capture; payout |

The `vault_id` never leaves the vault store: results, logs and order records carry only status, order, capture and batch ids, and PayPal text is scrubbed with the vault id among the secrets. A charge for an agent the contract reports revoked deletes the vault token (second kill switch); the dashboard's Revoke also calls `/vault/revoke`. A captured charge is never released: if the payout then fails, the result is `failed`/`pending` with the `capture_id`, to settle by hand.

Live run (the owner approves in between): `node scripts/vault-sandbox.ts connect`, open the link in `.vault/APPROVE.md`, then `node scripts/vault-sandbox.ts run` (NEAR stubbed with a throwaway agent key, as `live-sandbox.ts`), which writes `evidence-vault.json`.
