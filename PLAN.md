# Plan: the mandate engine for agent spending accounts
The design of nearH, our NEAR Hackathon entry (Nov 1–14 2026), which the PayPal entry extends (PAYPAL.md).

## What we're building
**The company:** a euro account for every AI agent, with a spending limit the owner sets and can revoke at any time. An EU AI startup gives each agent, or each of its customers, an account:
- **Funded in euros:** Monerium EURe, with a real IBAN.
- **Owned by the startup:** its passkey Safe. Zoldenburg never holds funds.
- **Spending under a mandate:** caps, payees, a budget.
- **Paying two ways:** APIs over x402 and suppliers over SEPA.
- **Booked automatically:** every payment yields a receipt.

The account, IBAN and receipts already exist in Zold-app.

**The hackathon entry:** the **mandate engine**, the missing piece.
- A NEAR contract holds the agent's signing power through Chain Signatures. The agent has no key to funds; its only key is a NEAR function-call key that can do nothing but ask the contract.
- The contract signs only payments that fit the mandate. One revoke, a single passkey tap, stops new signing on every rail.
- **Demo story:** an agent pays a US API in USDC and an EU supplier in euros over SEPA. A poisoned invoice tries to redirect both payments, and both are blocked.

**README, first lines:** "Spending limits for AI agents, enforced by NEAR across crypto and SEPA rails. Give AI funds without giving it the keys to everything."

## Design
- **Owner:** the startup (the SME) through its **passkey**, the same P-256 key that owns its Candide passkey Safe on Base Sepolia (threshold 1, Zold-app code).
  - The contract stores the public key and verifies WebAuthn signatures on `set_mandate`, payee changes and `revoke` with `env::p256_verify`.
  - Any NEAR account (our relayer, or `pnpm owner:revoke` run by the owner) may submit a signed owner call and pay its gas, but cannot alter it, so the relayer cannot block a revoke.
  - There is no Zoldenburg key and no upgrade key on the contract. If the passkey spike fails, the fallback owner is a NEAR wallet held by the SME: the owner mode is chosen once at deploy; every owner method takes an `Option<OwnerAssertion>`, which must be `Some` in passkey mode and `None` in wallet mode, where `assert_owner` checks that the predecessor is the owner account. Both modes have their own tests.
- **Agent:** an EOA derived through Chain Signatures from the mandate contract and a path. It is also the agent's own **Monerium-linked address**, so it can sign SEPA payout orders.
- **Funds flow (a float, not a module):**

  | Rail | Where the money sits | Who moves it |
  |---|---|---|
  | x402 | USDC float at the agent EOA on Base Sepolia, at most `float_cap` | The owner tops it up from the Safe with a normal passkey Safe tx. The agent spends it only through contract-signed EIP-3009. |
  | SEPA | EURe float at the same EOA on Base Sepolia (where Zold-app's Monerium sandbox runs), at most `float_cap` | The owner tops it up from the Safe. Monerium burns it when it executes a contract-signed payout order. |

  `float_cap` is an owner-side limit: the top-up script refuses to send more, but the contract cannot see Base balances. What the contract bounds is what it signs: the **budget for each rail** plus the validity window. Leftovers go back to the Safe through the sweep shape.
- **Why NEAR, and not the alternatives:**
  - A Safe Guard, Zodiac or ERC-7579 session-key module works on Base only and cannot police a Monerium payout message, which is a signed text, not a Safe tx.
  - Off-chain policy with a key service (KMS) means Zoldenburg holds a key that can spend.
  - A TEE agent (Shade, OutLayer) attests *which code* asks, not the owner's policy; zk proofs of Base state need a light client on NEAR.
  - A contract holding the signing power through Chain Signatures covers both rails with one policy and one revoke, and nobody holds a spending key.
- **Agent runtime:** the agent's model runs on **NEAR AI Cloud** (TEE inference, with the response signed by the enclave). This reuses the provider and attestation code from `private-ai`. The README claims only the checks that code actually performs; its `chainVerified` flag is still false.
- **Scam check (advisory, never a lock):**
  - Before asking for a signature, the agent sends the invoice, the x402 payment requirements and the payee history to a NEAR AI Cloud model.
  - The model answers `ok` or `suspicious` with a reason: a new IBAN, a changed `payTo`, an amount spike, or urgency wording.
  - A suspicious request waits on the dashboard for the owner.
  - A timeout holds the request; it never passes it.
  - The contract enforces the mandate whatever the model says, because a prompt-injected model is exactly the threat. "The model can only make the agent more careful, never less."
- **Gas:** the x402 facilitator submits EIP-3009 payments, anyone can submit a sweep's EIP-3009 (our relayer does it), and Monerium payouts are API orders with no gas. The agent holds no ETH, except in the sweep fallback below.

## Mandate contract (Rust, near-sdk; MPC call from the shade template)
- **`owner`:** the SME's passkey public key (see Design). Every owner call carries a WebAuthn assertion whose challenge is `sha256("zold-mandate-v1" || contract_id || network || method || borsh(args) || owner_nonce || expires_at)`. One `assert_owner` parses `clientDataJSON` and checks `type == "webauthn.get"`, the `challenge` (strict base64url), the `origin` and `rpIdHash` against stored values, the user-presence flag, that `owner_nonce` is greater than the last one used, and that `expires_at` has not passed, then verifies the signature over `authData || sha256(clientDataJSON)`. `owner_nonce` is one counter, consumed only when a call succeeds; a call signed with an older nonce fails loudly, so the owner re-signs it. It never uses signCount or the signature as a replay key.
- **Which agent is calling:** every agent's function-call key lives on the contract's own account, so the predecessor is always the contract. The contract identifies the agent by `env::signer_account_pk()`, through a key-to-agent map set by `add_agent`. Agent calls take no `agent` argument.
- **`revoke(agent, assertion)`:** an owner call for any agent. **`revoke_self()`:** an agent call that revokes only the calling agent.
- **`set_mandate(agent, Mandate)`:** fields are named after AP2's Open Payment Mandate:
  - `amount_range` and `budget` per rail, in token base units (USDC for `x402`, EURe for `sepa`), with a period;
  - `allowed_payees`: for x402, a `payTo` address allowlist; for SEPA, an IBAN allowlist;
  - `usdc_address`, `eure_address`, `chain_id`, `float_cap`, `max_validity_secs` (the validity rule for shapes 2 and 3, at most 300 s).
- **`add_agent(agent, public_key, sweep_config)`, an owner call:** the contract adds the agent's function-call key on its own account with `method_names = [request_signature, sweep, revoke_self]` and stores `sweep_config` = `{safe_address, usdc_address, eure_address, chain_id}`. It rejects a public key or agent that already exists. The sweep config is separate from the mandate and survives revoke; revoke removes the key-to-agent entry.
- **`set_relayer(account, assertion)`, an owner call:** names the one relayer account allowed to request sweeps; `None` removes it.
- **Entry points:** shape 1 goes through `sweep(agent, token, amount, request_id)`; shapes 2 and 3 go through `request_signature(request_id, Shape)`, where the calling agent sends **decoded fields**. The contract builds every hash itself, so nothing is signed blind. It dedupes `request_id` per (caller, agent), and every EIP-3009 nonce is `keccak(agent, caller, shape, request_id)`, so ids from different callers never collide and no caller can use up another's. Three shapes:
  1. **Sweep to the Safe:** EIP-3009 `transferWithAuthorization` of USDC or EURe from the agent EOA with `to = safe_address`, built from the agent's `sweep_config`, not its mandate, with a fixed validity of 300 s (`SWEEP_VALIDITY_SECS`), so it needs no mandate after revoke. The destination is fixed, so the owner, the agent or the relayer set by `set_relayer` may request it, nobody else, and it works after revoke. Each request costs the contract an MPC fee, so at most one sweep per (agent, token) may be pending. The caller names the amount; too high just fails on chain, and the destination is always the Safe. A sweep just before an x402 payment makes that payment fail on chain, so the owner and relayer sweep only after revoke or when the agent is idle. If a token lacks EIP-3009, the fallback is a contract-built raw transfer: the relayer first sends the agent EOA just enough ETH for that one transfer. Never `permit`.
  2. **x402 payment:**
     - The agent submits the seller's x402 payment requirements `{resourceUrl, scheme, network, asset, payTo, amount}`.
     - The contract checks that `payTo` is allowlisted, `asset` is `usdc_address`, `network` is `chain_id`, and the amount is within the x402 cap and budget. It then builds EIP-3009 `transferWithAuthorization` with `to = payTo` and `value = amount`.
     - Validity is at most `max_validity_secs`. The EIP-3009 nonce follows the rule above, so it is never reused.
  3. **Monerium payout:** the message `Send EUR {amt} to {IBAN} at {RFC3339}`. Checks that the IBAN is allowlisted, that the amount is within the SEPA cap and budget, and that the timestamp is within `max_validity_secs`. The amount is canonicalised, so `1.5` and `1.50` give the same message.
     - **Replay:** the signature is public once the callback lands, so the contract's per-agent `(agent, iban, amount, ts)` dedupe only stops re-signing the same order for the same agent (two agents may each sign it once). Submitting an order also needs the Monerium profile's API credentials, which only the Monerium rail service holds, never the agent. That service submits each signed order once, keyed by `request_id`, and records Monerium's order id. What is left is a replay by whoever holds those credentials, within `max_validity_secs`; S-b checks whether Monerium also refuses a duplicate, and the threat model states the result.
- **Owner-only setup, scripted once (`link_agent`, an owner call):** the Monerium link message `I hereby declare that I am the address owner.` for the agent EOA. The agent can never request it, and the contract records `linked` and refuses a second link signature.
- **Accounting = authorized spend:**
  - The budget is reserved before calling `v1.signer`. A request is checked against the mandate as it stands when the request is made; a later mandate change does not touch a pending reservation, and `set_mandate` does not restart the budget period, so pending and `unknown` reservations keep counting.
  - The callback never panics. If it fails, the reservation is marked `unknown` and counts as spent until the owner resolves it or the period ends. The owner can release it only after the request's validity window has ended, so a signature that arrives later is already expired and cannot be settled. `expire_pending` marks a reservation `unknown` once the MPC timeout has passed. A callback that arrives later still records `signed`. The states are `pending → signed | unknown → (owner) spent | released`, plus `revoked`.
  - "Held" (by the scam check) exists only off chain: a held request has not reached the contract and reserves nothing.
- **Revoke = one owner call, one tx:**
  1. contract `revoke` clears the mandate (the sweep config stays);
  2. the same call runs `delete_key` on the agent's function-call key, which lives on the contract's own account (spike first; if contract-side `delete_key` doesn't work, drop this step and rely on step 1).

  Then the float is swept back to the Safe. README wording: "One NEAR tx stops new signing on every rail. Authorizations already issued stay valid until they expire, and short windows bound that. What is left in the float goes back to the Safe."
- **Contract-account keys:** the deployer's full-access key is deleted at deploy, so nobody can redeploy the contract or sign for an agent. Agents are added later with `add_agent`, which the contract executes itself. The deploy script checks that no full-access key remains, and judges can check with `near account list-keys`.
- **No owner recovery:** with no upgrade key, losing the passkey freezes every mandate. The funds stay in the Safe, and the float can still be swept. The threat model says so.

## Reuse
| Need | Code |
|---|---|
| Buyer agent and MCP | The official x402 client packages (`@x402/fetch`, `@x402/evm`, Apache-2.0). Implement their EVM client signer on the NEAR signer, so every x402 signature comes from `request_signature`. Our own MCP server exposes the four tools. A local policy pre-check gives readable refusals; the contract is the source of truth. Our own closed-source agent payment packages are not used. |
| Demo sellers | A small Express seller on `@x402/express` (Apache-2.0) with the x402.org facilitator on Base Sepolia (proven by S-c); shareme.lol `extend_link` as a second real seller. Sellers stay unmodified; their `payTo` goes on the allowlist. |
| Safe and passkey | Zold-app `wallet/candide.ts` (passkey Safe; the owner tops up the float with it). Check which site (rpId) Zold-app's passkeys belong to; if it differs from the dashboard's, create a fresh passkey Safe from the dashboard's site. |
| Monerium | Zold-app `adapters/monerium-client.ts` (link, orders), the `sepa.ts` payout string, sandbox config |
| Agent model and attestation | `private-ai` NEAR AI Cloud provider and `lib/attestation.ts` |
| MPC call | shade-agent-template `internal/chainsig.rs`; chainsig.js EVM adapter |
| Receipts (after the hackathon) | `sevdesk-monerium` mapping, with agent and mandate IDs in the purpose field |

## Spikes
The IDs the code and docs cite: S-a Chain Signatures (`spikes/chainsig/`), S-b Monerium (`spikes/monerium/`), S-c x402 (`spikes/x402/`), S-e NEAR AI Cloud (`spikes/nearai/`), S-g EURe and EIP-3009 (`spikes/eure/`), S-h passkey owner (`spikes/passkey/`), S-i contract-side `add_key`/`delete_key` (`spikes/deletekey/`).

