# PP4a live sandbox run (Nov 6 2026)

PayPal sandbox, team business account's REST app, credentials from `~/.config/nearh/paypal-sandbox.env`. Emails are masked (`sb-…@personal.example.com` is the personal sandbox account, `bu…@example.com` the bill-to); no credential or token appears below.

## Command

```sh
node src/cli.ts create --amount 25.00 --service "Weather data API" \
  --description "Weather data API access, November 2026 (nearH PP4 demo supplier)" --due 2026-11-20
```

Calls: `POST /v1/oauth2/token` → `POST /v2/invoicing/invoices` (201, `DRAFT`) → `POST /v2/invoicing/invoices/{id}/send` (200) → `GET /v2/invoicing/invoices/{id}` (200).

## Output (buyer view, stdout)

```json
{
  "invoice_id": "INV2-XYGB-DB4H-V67N-WHRQ",
  "invoice_number": "NEARH-3AEA2BCE-B3A0",
  "status": "SENT",
  "amount": { "currency": "USD", "value": "25.00" },
  "payee": "sb-…@personal.example.com",
  "due_date": "2026-11-20",
  "description": "Weather data API access, November 2026 (nearH PP4 demo supplier)",
  "payer_view_url": "https://www.sandbox.paypal.com/invoice/p/#XYGBDB4HV67NWHRQ"
}
```

## The invoice as PayPal stores it (GET, excerpt)

```json
{
  "id": "INV2-XYGB-DB4H-V67N-WHRQ",
  "status": "SENT",
  "invoicer": { "business_name": "nearH demo supplier", "additional_notes": "PayPal payee: sb-…@personal.example.com" },
  "primary_recipients": [{ "billing_info": { "email_address": "bu…@example.com" } }],
  "detail": {
    "invoice_number": "NEARH-3AEA2BCE-B3A0",
    "invoice_date": "2026-11-06",
    "currency_code": "USD",
    "note": "Weather data API access, November 2026 (nearH PP4 demo supplier)",
    "payment_term": { "term_type": "DUE_ON_DATE_SPECIFIED", "due_date": "2026-11-20" }
  },
  "amount": { "currency_code": "USD", "value": "25.00" }
}
```

PayPal also returned `items[0]` as sent (plus an `ITEM-…` id), a zero tax/discount breakdown, `due_amount` 25.00, `configuration.allow_tip: false`, and `metadata.recipient_view_url` / `invoicer_view_url`.

## Findings

1. **`invoicer` is empty unless the request sets it.** A first run without `invoicer` created and sent the invoice, but the GET showed `"invoicer": {}`: PayPal does not fill in the account's email, and `/v1/identity/oauth2/userinfo` returns only `user_id`, so the supplier cannot learn its own email from the API.
2. **`invoicer.email_address` must be the calling account.** With the personal sandbox email there, the draft was created (201), but send failed: `422 UNPROCESSABLE_ENTITY`, `details[0].issue: USER_NOT_FOUND`, "User is not associated with paypal based on invoicer email." Hence the payee note (README, "Where the payee comes from").
3. Probe and failed-run invoices were deleted (drafts) or cancelled (sent). The first sent invoice from finding 1 (`INV2-GR6U-CN9V-583B-L3Q9`) was cancelled. `INV2-XYGB-DB4H-V67N-WHRQ` above stays `SENT` for PP4.
