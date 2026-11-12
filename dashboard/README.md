# Dashboard (DB1)

One page for the owner: agents and their status (`active` or `revoked`), mandates and budget use per rail, requests by status, the held queue (approve or reject), resolving `unknown` reservations, Revoke (D1), and a USD view of PayPal payouts (PP5a). Owner calls are signed in the browser with the owner's passkey and relayed by R1's `relayOwnerCall`.

```sh
pnpm install && cd dashboard
cp .env.example .env   # fill it in; never commit it
pnpm start             # http://localhost:5173, bound to 127.0.0.1
```

Testnet only: `CONTRACT_ID` must be a `.testnet` account and `NEAR_RPC` an https testnet host (the O1/R1 allowlist). The page also checks that the RPC's `status.chain_id` and the contract's `get_config().network` are `testnet`, and shows nothing else if not.

## What the server does (`serve.mjs`)

| Route | |
|---|---|
| `GET /`, `/app.js`, `/owner.js`, `/paypal.js`, `/style.css` | the page, with a CSP (`script-src 'self'`, no inline script; `connect-src` is the page itself and the testnet RPC hosts) |
| `GET /config.json` | `{ contract_id, near_rpc, network: "testnet" }` |
| `GET /api/held` | the items of SC1's `held.jsonl` (docs/interfaces.md §6), the path it read, any lines that are not JSON, and `held_nonce` (the greatest `decided_nonce`, 0 if none). The file is `DASHBOARD_HELD_FILE`, else SC1's `SCAMCHECK_HELD_DIR` (from the environment, relative to `scamcheck/`), else `scamcheck/.held/held.jsonl` |
| `GET /api/paypal` | the PayPal rail's (PP3) order records, read only: `{ dir, records, errors }`. `dir` is `PP3_STORE_DIR` (an absolute path, or relative to where the dashboard runs), else `rails/paypal/.orders`. Each record keeps `agent`, `request_id`, `state`, `amount`, `at`, `payout_batch_id`, `batch_status`, `http_status` and `payee_masked` (masked again as the rail masks it); PayPal's `detail` and `debug_id` are left out |
| `POST /api/held/decide` | `{ id, status, assertion }`: checks the owner's passkey assertion (below), then moves one item `held → approved` or `held → rejected`, nothing else, and sets `decided_at` and `decided_nonce` |
| `POST /api/owner-call` | `{ method, args, assertion }` for `revoke` or `resolve_reservation`, passed to `relayOwnerCall` with the `SUBMITTER_*` account; the relayer re-checks the signature and challenge before sending |

It listens on 127.0.0.1 only and accepts only `Host: localhost:<port>` or `127.0.0.1:<port>` (any other is a 421). POSTs need an `Origin` header equal to `http://<that Host>` (else 403) and `application/json`, so another site open in the owner's browser cannot approve a held item.

### The owner origin must be this server

The contract's passkey origin, `get_config().owner.origin`, must be exactly `http://localhost:<DASHBOARD_PORT>` or `http://127.0.0.1:<DASHBOARD_PORT>`: scheme `http`, no trailing slash, and the port the server listens on (default 5173). `serve.mjs` reads `get_config()` at start and refuses to start, naming both values, if the origin is anything else or `get_config()` cannot be read; it checks again on every held decision (403). Open the page on that same origin: the page refuses to sign elsewhere, and the contract refuses an assertion from another origin. Reverse proxies, TLS terminators, other host names and port forwarding to another port are not supported: the browser would report the proxy's origin, which is never one of the two above. A wallet-mode owner has no origin, so nothing is checked.

## Owner calls (`public/owner.js`)

The page reads `get_config()` right before each call and uses `owner_nonce + 1`, `expires_at = now + 300 s`, and the challenge of docs/interfaces.md §2 over `borsh(args)`. It calls `navigator.credentials.get` with `rpId = owner.rp_id` and `userVerification: "required"`, and refuses to sign if the page's origin is not `owner.origin`. The assertion it sends is the authenticator's own `authenticatorData` and `clientDataJSON`, and the signature converted from DER to raw `r || s`, as `Base64VecU8` JSON fields. Serve the page on the contract's owner origin (`DASHBOARD_PORT`), or every call is refused.

**Held decisions** are signed the same way, but checked by `serve.mjs`, not the contract: method `held_decide` (no contract method has that name, so a held signature is never a valid contract call and the other way round), `borsh((id: String, status: u8))` with `approved`=0, `rejected`=1, and the held queue's own nonce, `held_nonce + 1` (the contract's `owner_nonce` is untouched). The server reads `get_config()` from the RPC and runs `assert_owner`'s checks: type, challenge, origin, rpIdHash, user present, nonce greater than `held_nonce`, `expires_at` not passed and at most 600 s ahead, and the P-256 signature against `owner.public_key`. Any failure is a 403 and the file is not touched. So an unsigned decision, one signed for another item or the other decision, an expired one, and a replay (its nonce is no longer greater) are all refused. A wallet-mode owner cannot decide held items here.

Resolve Unknown sends one call per click, `Spent` or `Released`; `Released` stays disabled until `release_after` (re-checked every 15 s). A revoked agent keeps a **Retry key deletion** button: `revoke` again retries a failed `DeleteKey` (D1), or does nothing if the key is gone.

## USD view (PayPal payouts)

Shape 4 (PayPal payout) requests from `list_requests` (`shape: "paypal"`), plus PayPal held-queue items the contract has not seen yet (`shape.type: "paypal"`), each with agent, `request_id`, payee, amount in USD and status. The payee is masked the way rails/paypal masks it (`su…@example.com`), here and in the held queue; it comes from the reservation's signed text (`Send USD … to {payee} at … ref …`) or the held item's `shape.payee`. Once PP3 has a record for `(agent, request_id)`, the row shows its `payout_batch_id` and its state (`submitted`, `unknown`, `refused`, `duplicate_batch`, `submitting`) and PayPal's `batch_status`; before that, `not submitted`. A held PayPal item is approved or rejected like any other held item. The mandates table shows the PayPal rail's cap and budget in USD when the mandate has one. The dashboard holds no PayPal credentials and never calls PayPal.

## Statuses

`allowed` is a `signed` reservation; `pending`, `unknown`, `revoked`, `spent` and `released` are the contract's own. `held` counts held-queue items still waiting, and `blocked` counts held items the owner rejected. Requests the contract refuses (over budget, unknown payee, …) panic and leave no record, so the dashboard cannot list them.

## Tests

`pnpm test`: `node --test` unit tests, then `playwright install chromium` and the Playwright suite.
- `test/unit.test.mjs`: the challenge equals the §2 worked vector; `revoke` and `resolve_reservation` borsh bytes; DER → `r || s`; held items move only `held → approved | rejected`; held decisions: unsigned, signed for another item or decision, expired, TTL over 600 s, another key, replayed or an old nonce are refused, a valid one is accepted, a wallet owner is refused, an id not in SC1's `held-<uuid v4>` format is refused (400) before `get_config` or the file is touched; the server refuses non-testnet config, a foreign `Origin`, a wrong `Host` (421), a POST `Origin` other than its own Host (403), a held assertion whose client origin is not the owner origin, an owner origin it does not serve (it will not start, or a 403 if `get_config()` changes later), a `get_config()` it cannot read at start, a non-JSON body and other owner methods, binds 127.0.0.1 and sends the CSP; the held file follows SC1's `SCAMCHECK_HELD_DIR`.
- `test/dashboard.spec.mjs`: runs `serve.mjs` on a temp copy of `test/fixtures/held.jsonl` with a mocked NEAR RPC and a Chromium virtual authenticator holding a P-256 owner key. Held `held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6` is approved with the passkey and moves to `approved` in the file with `decided_nonce` 1. Revoke: the relayed assertion is checked as `assert_owner` does (type, §2 challenge, origin, rpIdHash, UP and UV flags, nonce, expiry, P-256 signature over `authenticatorData ‖ sha256(clientDataJSON)`), then the badge flips to `revoked` and the button becomes Retry key deletion. The budget period shown is the current window's (`get_budget.period_secs`). Resolve: `Released` disabled before `release_after`, one call per click with nonces 5 then 6. `<img onerror>` and `<script>` in invoice, memo and IBAN render as text and never run. A page origin other than the owner origin is refused before signing; a mainnet RPC is refused. USD view: PayPal reservations show status, masked payee (no full payee anywhere on the page), USD amount, and the batch id and state from `test/fixtures/paypal-orders/`; a held PayPal item from `test/fixtures/held-paypal.jsonl` shows masked in the held queue and the USD view and is approved with the passkey.
- `test/unit.test.mjs` (PayPal): `maskPayee` equals rails/paypal's `maskEmail`; the signed text parses; PP3 records are read without being changed, the payee re-masked, `detail`/`debug_id` dropped, `.tmp` files skipped and a bad file reported; `GET /api/paypal`.

## Not covered

- No live testnet run yet: the tests mock the RPC and the relay.
- Wallet-mode owners: the page signs passkey owner calls only.
- Rewriting `held.jsonl` races with an SC1 append that lands during the rewrite (that append can be lost). The window is one synchronous read–write–rename.
- `list_agents` and `list_requests` read the first 100 entries only.
- The decide endpoint persists the verified passkey assertion with `decided_nonce`. A2 independently verifies that proof against the current owner configuration, the signed held ID/status, expiry and previously consumed nonces before resuming its locally saved payment. Changing only queue status is insufficient. Keep the queue and receipts private; compromising the local executable or signer keys remains outside this file-integrity check.
- `held_decide` and `decided_nonce` are not in docs/interfaces.md §2/§6 yet (lead-only file).
- USD view: `batch_status` is what PayPal answered at submission (`PENDING`); PP3 stores no later item status (`GET /v1/payments/payouts/{batch}`), so the final outcome is not shown. Neither shape 4 nor a PayPal held item is in docs/interfaces.md yet; the held shape assumed is `{ type: "paypal", payee, amount, timestamp }` on `rail: "paypal"` (PaypalRequest's fields).
