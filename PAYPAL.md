# PayPal AI Hackathon: the USD rail for the mandate engine

Entry for https://paypalaihackathon.devpost.com. **Deadline: Nov 12 2026, 12:00 PST (21:00 CET).**

## Pitch
PayPal's agent toolkit lets an agent pay, but whoever holds the API key can spend everything. We put a mandate in front of it: an agent gets a **USD spending account** with caps, payees and a budget that the owner sets and revokes in one call. The agent holds no key to funds. Every payment is signed only if a NEAR contract finds that it fits the mandate, and only our PayPal rail service, which alone holds the PayPal credentials, can submit it.

Three PayPal flows under one mandate (contract shape names, as in the code):
- **Payout** (`paypal`, "shape 4"): the buyer agent's `pay_paypal` pays a supplier's PayPal sandbox invoice through the Payouts API.
- **Vaulted-wallet charge** (`paypal_checkout`, "shape 5"): the rail charges the owner's vaulted PayPal wallet into its own merchant account, then pays the merchant out. Revoke deletes the vault token.
- **Refund** (`refund`, "shape 6"): a merchant-side support agent uses PayPal Agent Toolkit tools; `create_refund` runs only as a contract-signed order.

Plus **x402 in PYUSD**: the contract signs EIP-3009 `transferWithAuthorization` for PYUSD on Ethereum Sepolia (PP1, spike PP-S2); the buyer agent's `pay_x402` runs on USDC on Base Sepolia.

Demo beats: a poisoned invoice with a lookalike PayPal payee is held by the AI scam check and, with the check bypassed, refused by the contract (`pnpm demo:paypal --mock`). A prompt-injected "refund all orders" ticket is held by the scam check and, with the check bypassed, refused on chain (live run, [demo/evidence/pt1-refunds.md](demo/evidence/pt1-refunds.md)).

Prizes to aim for: Best Use of Agentic Commerce, Best Use of PayPal + AI, overall.

## Verified facts (Nov 4)
- PYUSD on Ethereum Sepolia `0xCaC524BcA292aaade2DF8A05cC58F0a65B1B3bB9` implements EIP-3009 (`authorizationState` exists); EIP-712 domain name `PayPal USD`, version `1` (domain separator recomputed and matched). Also on Ethereum mainnet and Arbitrum. **Not on Base.**
- x402 is still spec v2. `@x402/evm` 2.30.0 was released Nov 4 2026. The exact EVM scheme takes any EIP-3009 asset with `extra: {name, version}`; the public facilitators may not list PYUSD, so we run our own facilitator on Sepolia.
- PP1 made the x402 asset's EIP-712 domain a mandate field (`usdc_eip712_name`/`usdc_eip712_version`, default `USDC`/`2`).

## Scope
- Testnet and sandbox only (NEAR testnet, Ethereum Sepolia, PayPal sandbox).
- The buyer agent's tool list for this entry is `pay_x402`, `pay_sepa`, `pay_paypal` (with `mode: "checkout"` for the vaulted wallet), `revoke`, `get_receipt`. The merchant-side support agent (PP-T1, `agent/mcp/src/support.ts`) gets PayPal Agent Toolkit tools: `get_order` and `get_refund` pass through the rail, and `create_refund` runs only as a contract-signed shape 6 refund (`Refund USD {amount} of capture {id} ref {request_id}`, per-refund cap and daily refund budget in `mandate.paypal_refund`).

## Task IDs
The IDs the code and docs cite; all are merged.

| ID | Task | Area |
|---|---|---|
| PP-S1 | **PayPal sandbox spike:** one Payouts API payout to a sandbox personal account, duplicate `sender_batch_id` behaviour | `spikes/paypal/` |
| PP-S2 | **PYUSD x402 spike:** EIP-3009 digest for PYUSD on Sepolia, signed by the MPC-derived EOA, settled by a self-hosted `@x402/evm` 2.30 facilitator | `spikes/pyusd-x402/` |
| PP1 | **Asset-agnostic EIP-3009:** the mandate's x402 asset carries its EIP-712 `name`/`version` (USDC/2 stays the default); sweep config the same | `contract/src/shapes/{x402,sweep}.rs`, `state.rs` |
| PP2 | **Shape 4, PayPal payout:** contract builds `Send USD {amt} to {payee} at {RFC3339} ref {request_id}`, checks payee allowlist (PayPal email/Venmo handle), cap, budget, validity window; dedupe as D3 | `contract/src/shapes/paypal.rs` |
| PP3 | **PayPal rail service:** sole holder of the PayPal credentials; accepts only orders whose MPC signature recovers to the agent EOA and whose fields match; submits once per `request_id` | `rails/paypal/` |
| PP4 | **Agent:** `pay_paypal` tool next to `pay_x402`, scam check (NEAR AI Cloud) before each; the agent never holds PayPal keys | `agent/mcp/` |
| PP4a | **Demo supplier:** issues PayPal sandbox invoices (Invoicing v2); poisoned-invoice fixtures; scam-check PayPal rules | `supplier/`, `scamcheck/` |
| PP5a | **Dashboard USD view** of PayPal payouts (Venmo handles masked) | `dashboard/` |
| PP5 | **Demo script + judge README** | `demo/`, `README.md` |
| PP-V0 | **Vault v3 spike:** save a PayPal wallet, merchant-initiated charge, third-party payee, delete | `spikes/paypal-vault/` |
| PP-V1 | **Shape 5, pay from the owner's vaulted PayPal wallet:** contract-signed charge, capture into the rail's account, payout to the merchant; revoke deletes the vault token | `contract/src/shapes/paypal_checkout.rs`, `rails/paypal/src/vault.ts`, `agent/mcp/` |
| PP-W1 | **PayPal webhooks** as tighten-only settlement feedback (`verify-webhook-signature`) | `rails/paypal/src/webhook.ts` |
| PP-T1 | **Shape 6, refunds around PayPal Agent Toolkit tools:** support agent, per-refund cap and daily refund budget | `contract/src/shapes/refund.rs`, `rails/paypal/src/refund.ts`, `agent/mcp/src/support.ts` |
| SC2 | **Scam check default model:** a reasoning model returned empty content; send `reasoning_effort: "none"`, empty answer holds | `scamcheck/` |
| — | **Scam check:** verify NEAR AI's response signature and attestation nonce (`signature_verified`, evidence only) | `scamcheck/src/signature.ts` |
| — | **Security fixes** for PayPal audit 1 and PayPal audit 2 | repo-wide |

## PayPal AI Toolkit (github.com/paypal/AI-Toolkit)
- It's a dev-time plugin for coding agents (Claude Code: `/plugin install paypal@claude-plugins-official`): a PayPal best-practices skill, commands, a pre-write hook, and the sandbox MCP server `https://mcp.sandbox.paypal.com/mcp`, authenticated with a sandbox access token from client credentials.
- How we use it: our coding agents loaded it while writing the PayPal rail and the supplier, for API shapes and pitfalls.
- Rule: **the agent gets PayPal's tools, never PayPal's token.** No runtime agent gets the PayPal MCP server, the client credentials or an access token; that would hand the agent the key, which is exactly the problem our mandate removes. Only the PayPal rail holds the credentials. It submits only contract-signed payout and refund orders, and runs the support agent's PayPal tools itself: the agent sees PayPal's own tool definitions (copied from `@paypal/agent-toolkit` 1.11.0, which is not a dependency: its transitive tree fails `pnpm audit`) and the results of the read tools `get_order` and `get_refund`, which the rail calls directly on the sandbox REST API, and the rail refunds a capture only for a signed shape 6 order whose amount is at most captured minus already refunded (`rails/paypal/src/refund.ts`). Recorded run: [demo/evidence/pt1-refunds.md](demo/evidence/pt1-refunds.md).
- Pitch angle: "PayPal's toolkit lets agents pay; we put a revocable mandate in front of it."
- Demo supplier side (PP4): the supplier, not our agent, issues a PayPal sandbox invoice. Our buyer agent reads it and pays only through a contract-signed payout order.
