# PP-V0: PayPal Vault v3 sandbox spike

## Verdict: **GO for the two-step charge**; direct third-party payee: no

A merchant-initiated charge on the owner's vaulted PayPal wallet works in the sandbox when it pays **the rail's own merchant account**. The rail then pays the merchant through Payouts (PP-S1). That is what PP-V1 built (`rails/paypal/src/vault.ts`, contract shape `paypal_checkout`), and its live sandbox run ([rails/paypal/evidence-vault.json](../../rails/paypal/evidence-vault.json), 2026-11-09, NEAR stubbed) recorded:

| Step | Result |
|---|---|
| Charge USD 25.00 from the vault | order `77N76052YX9609716`, capture `92X151453C0343351`, payout batch `KUJK7ULWWJKMQ` (`PENDING`) |
| Same charge with the merchant swapped after signing | refused by the rail before any PayPal call (`PP3_BAD_SIGNATURE`) |
| Revoke | token status `revoked`; `GET` afterwards → 404 |
| Charge after revoke | refused (`PP3_REQUEST_NOT_FOUND`) |

- **Third-party payee in the order:** not used. The docs scope a `MERCHANT` token to "directly with a merchant"; charging many payees from one saved wallet is the PLATFORM / Multiparty case, which needs partner onboarding and `PayPal-Auth-Assertion`. The rail never sets `payee` on a vault order.
- **The first-token run below got 403 on every charge.** That token (`ksx2gt8h`) came back from a `POST /v3/vault/payment-tokens` that answered 500, and a `GET` on it returned 404, so the token itself was likely broken. The PP-V1 run created a fresh token and its charge was captured, so the 403 was not an account-level block in the sandbox. Whether live PayPal needs reference-transaction approval for the vault is still unchecked.
- **Costs of the two-step charge:** two PayPal fees (the charge plus the 0.02 USD payout seen in PP-S1); the money passes through the rail's account; Payouts receivers must be personal accounts or `UNCLAIMED` follows (PP-S1).

Everything below is the raw spike record: step 1 and the payee probe, then the first-token run of steps 3–6.

Run 2026-11-09 against `https://api-m.sandbox.paypal.com`. Redacted raw responses: [evidence-setup.json](evidence-setup.json) (step 1), [evidence-payee.json](evidence-payee.json) (payee probe), [evidence-resume-attempt1.json](evidence-resume-attempt1.json) and [evidence-resume.json](evidence-resume.json) (first-token run).
Client id, secret, access token, emails and the approve link are withheld. Order, token, customer and merchant ids are sandbox values and are kept.

## Steps

| # | Call | Result |
|---|---|---|
| 0 | `POST /v1/oauth2/token` | **200**. The scope includes `uri.paypal.com/services/vault/payment-tokens/readwrite`, so **Vault is enabled on the app** |
| 1 | `POST /v3/vault/setup-tokens`, `payment_source.paypal` with `usage_type: MERCHANT`, `usage_pattern: IMMEDIATE`, `customer_type: CONSUMER`, `permit_multiple_payment_tokens: true`, return/cancel URLs | **201**, setup token **`9RJ86983E5394083A`**, status **`PAYER_ACTION_REQUIRED`**, customer `CqCpQdOSRi`. A GET just before approval (evidence-payee.json, E) still shows `PAYER_ACTION_REQUIRED` |
| 2 | Buyer approval in a browser | Done by the owner as the sandbox **personal** buyer (the link goes to the untracked `spikes/paypal-vault/APPROVE.md`). Agents never enter PayPal passwords |
| 3 | `GET` setup token → `POST /v3/vault/payment-tokens` (`token.type: SETUP_TOKEN`) → `GET` payment token | First-token run below. Script: `resume.mjs` |
| 4 | `POST /v2/checkout/orders` CAPTURE with `payment_source.paypal.vault_id` + `stored_credential {MERCHANT, SUBSEQUENT, IMMEDIATE}`, payee = own merchant; capture only if not already `COMPLETED` | First-token run: 403. PP-V1: captured (verdict above) |
| 5 | Same as 4 with `purchase_units[0].payee.email_address` = another sandbox account | First-token run: 403. Probe without the vault: see below |
| 6 | `DELETE /v3/vault/payment-tokens/{id}` → `GET` (expect 404) → charge again (expect refusal) | First-token run: 204, 404, 403. PP-V1: revoked, 404 |

## Step 5 research: third-party payee with a MERCHANT token

**From the docs:**
- The Vault v3 schema (`/api/payment-tokens/v3/schema.json`, `usage_type`) says: `MERCHANT` = *"The PayPal Payment Token will be used for future transaction directly with a merchant."* `PLATFORM` = *"…used for future transaction on a platform. A platform is typically a marketplace or a channel that a payer can purchase goods and services from multiple merchants."*
- The Multiparty overview ([save payment methods](https://developer.paypal.com/docs/multiparty/checkout/save-payment-methods/)) says platform-level saving *"supports a payer using a saved payment method with many merchants"*, and merchant-level saving supports *"one merchant"*.
- The Multiparty vault guide ([PayPal wallet, payment tokens API](https://developer.paypal.com/docs/multiparty/checkout/save-payment-methods/purchase-later/payment-tokens-api/paypal/)) puts `PayPal-Auth-Assertion` and `PayPal-Partner-Attribution-Id` (BN code) on every call, uses `usage_type: PLATFORM`, and charges with `payee.merchant_id`. That needs a PayPal Commerce Platform partner account with onboarded sellers, which this app does not have.
- In Orders v2, `payment_instruction.platform_fees` / `disbursement_mode` are *"only applicable to merchants that been enabled for PayPal Complete Payments Platform"*. `payee` itself carries no such restriction in the schema.
- Both vault guides (direct and Multiparty) say: *"You must be approved and have your account configured for billing agreements to set up a reference transaction."* Sandbox issued the setup token without that approval. Live might not.

**Probe, without the vault** (evidence-payee.json, plain REST app, no auth assertion):

| Probe | Result |
|---|---|
| A. Order, no payee | **201** `0CD19809PW434671B` `CREATED`. GET shows the payee = own merchant `7FTRBE8X7TC2Q` (email masked) |
| B. Order, `payee.email_address` = the personal sandbox receiver | **201** `1LG188169J533000F` `CREATED`. GET echoes the given payee email; no `merchant_id` is resolved |
| C. Order, `payee.email_address` = a made-up `@example.com` address | **201** `5D747625W8465312G` `CREATED`. **PayPal does not check the payee when the order is created** |
| D. Capture B without buyer approval | **422** `UNPROCESSABLE_ENTITY` / `ORDER_NOT_APPROVED` |

So a payee order is accepted at create time, but that proves nothing: even a non-existent payee gets 201. The payee is only checked at approval or capture. A capture needs either a buyer click or a `vault_id`. Step 5 of `resume.mjs` is therefore the only real test.

## First-token run: steps 3–6 (2026-11-09, after the owner approved)

- **Attempt 1** ([evidence-resume-attempt1.json](evidence-resume-attempt1.json)). The setup token was already `VAULTED` (approval done). `POST /v3/vault/payment-tokens` returned **500 INTERNAL_SERVER_ERROR**, yet a payment token (`ksx2gt8h`) was then listed for customer `CqCpQdOSRi`.
- **Attempt 2** ([evidence-resume.json](evidence-resume.json), `--payment-token ksx2gt8h`):

| # | Result |
|---|---|
| 3c | `GET /v3/vault/payment-tokens/ksx2gt8h` → **404 TOKEN_NOT_FOUND**, although it was listed by customer id |
| 4 | Merchant-initiated order on the vault_id, own merchant → **403 NOT_AUTHORIZED / PERMISSION_DENIED** |
| 5 | Same with a third-party payee → **403 PERMISSION_DENIED** |
| 6 | DELETE → **204**; GET → 404; charge after delete → 403 |

This run alone suggested the sandbox refuses merchant-initiated vault charges. The PP-V1 run with a fresh token (verdict above) showed it does not.

## Not checked
- Whether live Vault for PayPal wallets needs the reference-transaction approval (sandbox did not ask for it).
- `payee.merchant_id` instead of email; a business-account payee; the PLATFORM flow (no partner account).
- Setup-token expiry before approval, buyer cancel path, webhooks (`VAULT.PAYMENT-TOKEN.CREATED/DELETED`).

## Reproduce
```sh
node spikes/paypal-vault/setup-token.mjs           # step 1, writes APPROVE.md (gitignored)
node spikes/paypal-vault/payee-probe.mjs [setup_token_id]
node spikes/paypal-vault/resume.mjs <setup_token_id>   # after the owner approves; --payment-token <id> re-runs steps 4–6, --keep skips the delete
```
All scripts read `~/.config/nearh/paypal-sandbox.env` (override with `PAYPAL_ENV_FILE`) and refuse to run unless `PAYPAL_ENV=sandbox`. They append redacted output to `evidence-*.json`. Every POST carries a `PayPal-Request-Id`.
