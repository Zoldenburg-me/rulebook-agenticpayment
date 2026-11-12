# Monerium rail client (M1)

The `pay_sepa` backend. A2 hands it a payout the contract has signed (shape 3), and M1 submits it to the Monerium **sandbox** as a redeem order (`POST /orders`), at most once per `(agent, request_id)`. Only M1 holds the Monerium API credentials, never the agent.

## What it checks before calling Monerium

`submitPayout` (`src/payout.ts`) takes `{ agent, request_id, iban, amount, memo }`. It takes only the key and the agent's intent from the caller; everything else comes from the contract:

1. Input shape: agent id and `request_id` as in the contract (`[A-Za-z0-9._:-]{1,64}`), IBAN uppercase without spaces, amount as in D9, memo at most 140 characters.
2. **Once per request_id:** if the store has a record for `(agent, request_id)`, it returns `M1_DUPLICATE_REQUEST` without calling NEAR or Monerium.
3. `get_agent`: the agent exists, is not revoked, and has an `evm_address`.
4. `get_request({agent, caller: agent, request_id})`: a `payout` on the `sepa` rail with status **`signed`**. `released`, `unknown`, `pending` or a missing request are refused (docs/interfaces.md §4: M1 never submits a released payout).
5. The signed text is exactly `Send EUR {amount} to {iban} at {YYYY-MM-DDTHH:MM:SSZ}`, and its IBAN and canonical amount equal the ones the agent passed. The digest is the EIP-191 hash of that text, and the signature recovers to the agent EOA.
6. Now ≤ `valid_before`; an expired order is refused.
7. **The IBAN is on the agent's SEPA payees (`get_payees`) right now**, so a payee removed after signing is refused too.

If any check fails, the result is `blocked` with an `M1_*` code and nothing goes to Monerium. Then M1 authenticates and checks the expiry again: an order with less than `SUBMIT_MARGIN_SECS` (30 s, the POST timeout) left before `valid_before` is refused as `M1_ORDER_EXPIRED` **before** the claim, so a signature that ran out during the NEAR reads or authentication never uses up its `request_id`. Then M1 claims the record (`O_EXCL` file create, so only one of two concurrent or restarted M1 processes wins), and POSTs `{address, chain: basesepolia, kind: redeem, currency: eur, amount, counterpart: {iban, name, country}, message, signature, memo}`, the order shape S-b got accepted.

| Monerium answer | Result | Record |
|---|---|---|
| 2xx with an order id, not `rejected` | `submitted` + `monerium_order_id` | `submitted`, order id stored |
| 400 with `message: "Duplicate order"` (S-b; `code` is just the HTTP status) | `failed`, `MONERIUM_DUPLICATE_ORDER` | `duplicate_order` |
| other 4xx | `failed`, `MONERIUM_REFUSED` | `refused` |
| 5xx, lost in transit, 2xx without an order id | `pending`, `MONERIUM_OUTCOME_UNKNOWN` | `unknown` |

A record is never deleted and never retried automatically. A request whose outcome is unknown must be checked against the sandbox orders by hand. A new attempt needs a new `request_id`, and with it a new contract signature. A failed authentication or an order too close to expiry is refused before the claim, so that request can be retried.

### Recovery: the store update fails after Monerium answered

The claim is written before the POST, so it alone stops a resubmission (fail closed). If writing the outcome afterwards fails (disk full, permissions), M1 still returns the result it got, including `monerium_order_id` for an accepted order, and logs `record-failed <request_id>: outcome <state>, order <id>; ... record left as submitting`. The record stays `submitting`, so every later call for that `request_id` is `M1_DUPLICATE_REQUEST` and nothing is posted twice. To repair it, take the order id from that log line (or the sandbox orders) and write it into the record file in `M1_STORE_DIR` by hand.

## Secrets and redaction

- Credentials are read from `MONERIUM_ENV_FILE`, else `~/.config/nearh/monerium-sandbox.env`, else `rails/monerium/.env` (names in `.env.example`). They are parsed into a private object, **not** loaded into `process.env`, so no child process inherits them. O2's sandbox client (`scripts/owner/monerium/src/monerium.ts`) is reused: sandbox URL and Base Sepolia fixed, the token sent only to `api.monerium.dev`.
- Every detail and log line has IBANs redacted with O2's `redactIbans` (`<IBAN …last4>`). The store keeps only the IBAN's last 4 characters.
- Text that comes back from Monerium, and any thrown error, also goes through `scrub`: the client id and secret are removed by value, and anything token-like (20+ characters of token alphabet with a letter and a digit) becomes `<REDACTED>`.

## Running

```sh
cd rails/monerium
export CONTRACT_ID=<contract>.testnet   # NEAR_RPC optional, testnet hosts only
pnpm start                               # POST /payouts on 127.0.0.1:${M1_PORT:-8787}
pnpm submit <agent> <request_id> <iban> <amount> <memo>   # one payout, without the service
```

### Service auth

`pnpm start` refuses to run without `M1_AGENT_TOKENS`: one bearer token per agent, `agent=token` pairs separated by commas, each token 32–256 characters of `[A-Za-z0-9._~+/=-]` (generate one with `openssl rand -base64 32`). It comes from the environment, else from the credentials file (`.env.example`). Each agent's A2 holds only its own token and sends `Authorization: Bearer <token>`.

- The service listens on 127.0.0.1 only and answers 403 to any non-loopback peer.
- `agent` and `request_id` are checked against `[A-Za-z0-9._:-]{1,64}` first (400 otherwise). Only those validated values ever reach a log line or an echoed field, and `submitPayout` itself never logs a malformed `request_id`.
- The token must be the one configured for the payout's `agent`, compared in constant time (SHA-256 of both, `timingSafeEqual`). A missing token, another agent's token, or an agent with no token is 401 before any NEAR or Monerium call and before any claim. So a local caller without that agent's token cannot spend its signed payout or set its memo.
- A client that disconnects or sends a half body gets nothing submitted, and the service keeps serving; a body over 4 KiB is 413.

`pnpm submit` calls `submitPayout` directly with the Monerium credentials, so it needs no token: whoever can run it already holds the sandbox secret. Records go to `M1_STORE_DIR` (default `rails/monerium/.orders/`, gitignored).

## Tests

`pnpm test` runs `test/payout.test.ts`, offline. NEAR is an in-memory view stub, and Monerium is O2's client over a fake `fetch` that records every call. Signatures are real secp256k1 signatures over the EIP-191 digest. Covered:
- an accepted payout: the POST body, the signature recovers to the EOA, the order id is stored, no full IBAN in the store or logs
- D9 amount canonicalisation
- a second submission of the same `request_id` makes no NEAR or Monerium call; three concurrent submissions make one POST; the file store survives a restart and only one of two stores on one dir claims
- an attacker IBAN the contract did not sign, a signed IBAN no longer on the payees (an x402 payee or a spaced IBAN does not count), and a different amount: no HTTP call, IBAN redacted
- released, unknown or pending reservations, a non-payout, a missing request, an expired order, a wrong-key signature, a wrong digest, a malformed signature, extra signed text, a revoked or EOA-less agent, and malformed input: no HTTP call
- 400 `Duplicate order` → `MONERIUM_DUPLICATE_ORDER`, and the `request_id` stays used; another 400 → `MONERIUM_REFUSED`; a 5xx, a transit failure, a 2xx without an id or `rejected` → outcome unknown, never retried
- the client secret and token never appear in results, logs, errors or store files, even when Monerium echoes them back or auth fails
- the HTTP service: `POST /payouts`, 404, bad JSON, 502 on an auth failure
- service auth: no token, another agent's token, a near-miss token or an agent with no token is 401 with no NEAR or Monerium call and no claim; malformed `M1_AGENT_TOKENS` and an empty token set are refused
- a client that disconnects mid-body (and a malformed request) leaves the service up and submits nothing
- a malformed `request_id` (an IBAN, a token, a newline) is 400 at the boundary and appears in no log line, from the service or `submitPayout`
- an order that drops under `SUBMIT_MARGIN_SECS` during authentication is `M1_ORDER_EXPIRED`, never posted or claimed, and the same `request_id` still goes through in time
- a store update that fails after Monerium accepted: the result keeps the order id, the log names it, the claim stays and blocks a second POST

## Live run

Not done yet. The test contract `r1live.nearh-cc1-1793550206.testnet` has `agent-1` linked on the Monerium sandbox (O2), but its EOA `0x4b05…9d15` holds 0 EURe, and `agent-1` has no SEPA payee. Two owner steps are needed first: `add_payee agent-1 {rail: sepa, iban: <team sandbox IBAN …4141>}`, and a float top-up of at least EUR 0.01 to the EOA (the S-b EOA `0xE0A8…e52E` holds the team's 100 sandbox EURe). Then: `request_signature` for the payout with the agent key, and `pnpm submit`.
