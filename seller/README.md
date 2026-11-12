# seller

The demo x402 seller: an Express server with one paywalled route, `GET /weather`, priced in USDC on Base Sepolia (`eip155:84532`). An unpaid request gets `402` with a `PAYMENT-REQUIRED` header; a request with a valid `PAYMENT-SIGNATURE` is verified and settled through the facilitator at `X402_FACILITATOR_URL` (the public x402.org testnet facilitator by default) and gets the weather JSON plus a `PAYMENT-RESPONSE` header. Testnet only.

## Configure

Set these in the repo-root `.env` (shape in [`../.env.example`](../.env.example)). An optional `seller/.env` overrides the root file, and variables already set in the shell win over both. Either file may be missing.

| Variable | Default | Meaning |
|---|---|---|
| `SELLER_PAY_TO` | required | The seller's Base Sepolia address (0x + 40 hex, non-zero). It goes on the mandate allowlist. |
| `SELLER_PORT` | `4021` | Port the server listens on |
| `SELLER_AMOUNT` | `10000` | Price in USDC base units (6 decimals); `10000` is 0.01 USDC |
| `X402_FACILITATOR_URL` | `https://x402.org/facilitator` | Facilitator the seller calls (through `@x402/core`'s `HTTPFacilitatorClient`) to verify and settle payments. Must be `https:`; plain `http:` is accepted only for `localhost`, `127.0.0.1` or `[::1]` (a facilitator in local dev). |

The server exits with an error if a value is missing or invalid. It does not check that the facilitator is reachable: at startup it asks the facilitator for its supported payment kinds, and if that fails it logs the error and keeps running, but `GET /weather` then answers `500` and never serves the resource.

The server listens on `127.0.0.1` only.

## Run

```sh
pnpm --filter seller start
curl -i http://127.0.0.1:4021/weather   # 402 with PAYMENT-REQUIRED
```

## Test

```sh
pnpm --filter seller test
```

Typecheck plus offline tests: the facilitator is an in-process stub and nothing touches the network.
