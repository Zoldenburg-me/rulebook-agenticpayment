# Demo supplier (PP4a)

The supplier side of PP4: a demo supplier issues a PayPal **sandbox** invoice (Invoicing v2) for a service and hands it to the buyer as JSON. The future `pay_paypal` tool reads that JSON; the buyer agent pays only through a contract-signed payout order (shape 4, `rails/paypal`) and never holds PayPal credentials. Only the supplier and `rails/paypal` do.

## Buyer view

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

`amount.value` is canonical USD (`25.00`), `payee` is lowercased as the contract stores PayPal payees, `due_date` is `YYYY-MM-DD`. `toBuyerInvoice` refuses an invoice that is not in USD or lacks an amount, payee or due date.

**Where the payee comes from.** PayPal accepts only the calling business account as `invoicer.email_address` (send fails with `422 USER_NOT_FOUND` otherwise, see RESULT.md). In our sandbox that account is also the payout sender, and PP-S1 showed a payout to the sender's own account ends `UNCLAIMED`. So the supplier writes the account it wants to be paid at into the invoice as `invoicer.additional_notes: "PayPal payee: <email>"`, visible on the invoice, and `payee` is read from there, else from `invoicer.email_address`. An invoice naming two different payees is refused. With a separate supplier business account, `invoicer.email_address` alone would do.

## Running

```sh
cd supplier
node src/cli.ts create --amount 25.00 --service "Weather data API" \
  --description "Weather data API access, November 2026" --due 2026-11-20
node src/cli.ts get INV2-XXXX-XXXX-XXXX-XXXX
```

`create` makes the draft (`Prefer: return=representation`), sends it (`send_to_recipient: true`; the sandbox delivers no real mail) and prints the buyer view; `--draft` skips the send. `--payee` defaults to `PAYPAL_SANDBOX_RECEIVER_EMAIL` from the credentials file (the personal sandbox account), `--bill-to` to `buyer@example.com`.

Credentials come from `PAYPAL_ENV_FILE`, else `~/.config/nearh/paypal-sandbox.env` (`PAYPAL_ENV=sandbox`, `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`), parsed into a private object and never loaded into `process.env`. The base URL is fixed to `api-m.sandbox.paypal.com`. Errors carry the HTTP status, PayPal's error name, its upper-case issue codes and the debug id, never PayPal's free text, the credentials or the token. The token is fetched once per run and not refreshed (a CLI run is short).

## Tests

`pnpm test` runs `test/invoice.test.ts` against a fake PayPal: request shape, invoice id parsing (body `id` or `self` link), buyer view validation, input refused before any call, and errors that never carry the client id, secret, Basic header or token even when PayPal's answer echoes them. No network.

Poisoned-invoice fixtures for the scam check are in `scamcheck/fixtures/paypal-invoices.json`, tested in `scamcheck/src/paypal-invoices.test.ts`.
