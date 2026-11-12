# Interfaces

Shared shapes from [PLAN.md](../PLAN.md). Everything that crosses a package boundary is defined here and in `contract/src/types.rs`, `events.rs` and `errors.rs`. A change to any of it is a `contract/` task.

Code blocks tagged ```` ```json example=<name> ```` are test fixtures: `contract/src/interface_tests.rs` parses each one into its Rust type, serializes it back and requires the same JSON. Edit an example and its type together.

Conventions:
- Contract JSON uses `snake_case`. The only exception is the x402 payment requirements, which keep x402's own `camelCase` names.
- `U128` amounts are decimal strings in token base units: USDC has 6 decimals, EURe has 18.
- EVM addresses are `0x` plus 40 hex digits. The contract compares them in lowercase.
- Hashes, nonces and signature parts are `0x` plus 64 hex digits.
- NEAR public keys use the `ed25519:<base58>` form. Byte fields in owner calls are standard base64 (`Base64VecU8`).
- Times: `*_ms` fields are unix milliseconds (NEAR block time). EVM validity and owner `expires_at` are unix seconds.
- An agent is identified by an `AgentId`, chosen by the owner in `add_agent`: 1–64 characters from `[A-Za-z0-9._:-]` (`ERR_INVALID_AGENT_ID`). The id is also the agent's Chain Signatures derivation path, so it is never reused: a revoked agent's record stays, and `add_agent` with that id fails (`ERR_AGENT_EXISTS`).
- **Testnet only.** The one EVM chain id the contract accepts is Base Sepolia, `BASE_SEPOLIA_CHAIN_ID` = 84532 in `types.rs`. `sweep_config.chain_id` and `mandate.chain_id` must equal it (`ERR_WRONG_NETWORK`). The agent EOA is the same address on every EVM chain, so this check is what keeps the MPC from signing mainnet transfers.

## 1. Contract methods

The agent's function-call key is added with `method_names = ["request_signature", "sweep", "revoke_self"]` (`AGENT_METHOD_NAMES`).

| Method | Who | Arguments | Returns |
|---|---|---|---|
| `new` (init) | deployer, once | `owner: OwnerMode, network: String, mpc_contract: AccountId` | — |
| `add_agent` | owner | `agent, public_key: PublicKey, sweep_config: SweepConfig, evm_address: EvmAddress, assertion` | promise (`AddKey`, then `on_agent_key_added`) |
| `set_relayer` | owner | `account: Option<AccountId>, assertion` | — |
| `set_mandate` | owner | `agent, mandate: Mandate, assertion` | — |
| `add_payee` / `remove_payee` | owner | `agent, payee: Payee, assertion` | — |
| `link_agent` | owner | `agent, assertion` | promise → `Reservation` |
| `revoke` | owner | `agent, assertion` | `RevokeResult` (via `DeleteKey`, then `on_agent_key_deleted`) |
| `resolve_reservation` | owner | `key: RequestKey, outcome: ResolveOutcome, assertion` | — |
| `request_signature` | agent key | `request_id: String, shape: Shape` (`x402` or `payout` only) | promise → `Reservation` |
| `sweep` | agent key, relayer, owner | `agent, token: Token, amount: U128, request_id: String, evm_tx: Option<EvmTxParams>, assertion` | promise → `Reservation` |
| `revoke_self` | agent key | — | `RevokeResult` (like `revoke`) |
| `expire_pending` | anyone | `key: RequestKey` | — |
| `on_agent_key_added`, `on_agent_key_deleted`, `on_signature` | contract (callbacks) | — | — |
| views | anyone | `get_config()`, `get_agent(agent)`, `agent_of_key(public_key)`, `list_agents(from_index, limit)`, `get_mandate(agent)`, `get_payees(agent)`, `get_budget(agent, rail)`, `get_request(key)`, `list_requests(agent, from_index, limit)` | see `types.rs` |

`assertion` is always `Option<OwnerAssertion>` and always the last argument. On owner methods it must be `Some` in passkey mode (`ERR_ASSERTION_REQUIRED`) and `None` in wallet mode (`ERR_ASSERTION_FORBIDDEN`), where the predecessor must be the owner account and attach exactly 1 yoctoNEAR (`ERR_NOT_OWNER`). A function-call key cannot attach a deposit, so the yoctoNEAR proves the owner's full-access key signed; a dashboard or wallet-selector sign-in key on the owner account cannot act as owner. Owner methods are therefore `#[payable]`; passkey mode needs no deposit. `sweep` is the one method where it is optional in passkey mode too (see below).

`new` rejects a wallet owner equal to this contract's own account (`ERR_NOT_OWNER`), and `set_relayer` rejects this contract's own account (`ERR_SWEEP_CALLER_NOT_ALLOWED`): agent calls have this contract as predecessor, so either would let any agent key act as owner or relayer.

Agent calls have this contract as predecessor, because the agent keys live on the contract's own account. The contract finds the agent with `env::signer_account_pk()` in the key-to-agent map (`ERR_UNKNOWN_AGENT_KEY`). For the same reason, `#[private]` does not keep an agent out of the callbacks; the key's `method_names` do.

Who counts as the `caller` of a `sweep`, checked in this order:
1. `assertion` is `Some`: passkey mode only (`ERR_ASSERTION_FORBIDDEN` in wallet mode). `assert_owner` checks it as for any owner method, and the caller is `owner`, whoever submitted the tx.
2. The predecessor is this contract: the caller is the agent, and the signer key must map to `agent` (`ERR_UNKNOWN_AGENT_KEY`, `ERR_SWEEP_CALLER_NOT_ALLOWED`).
3. The predecessor is the relayer: the caller is `relayer`.
4. Wallet mode, and the predecessor is the owner account: the caller is `owner`.
5. Anyone else: `ERR_SWEEP_CALLER_NOT_ALLOWED`.

Agents and the relayer pass `assertion: None`. So in passkey mode the owner can sweep directly through any submitter, with or without a relayer.

**Adding an agent.** `add_agent` rejects an existing agent id, revoked ones included (`ERR_AGENT_EXISTS`), and a key already mapped to an agent (`ERR_KEY_EXISTS`). It writes the record and the key-to-agent entry, logs `agent_added`, and returns the `AddKey` promise followed by `on_agent_key_added`, which returns `true` on success. **A failed `AddKey` retires the agent id:** the callback clears the key-to-agent entry, marks the record revoked with `public_key: null`, logs `agent_add_failed` and returns `false` (never panics). The id may already have been used as a derivation path, so it stays taken; the key is free again for a new id.

**Agent EOA (`evm_address`).** The owner supplies it in `add_agent`. O1 derives it off chain from the MPC derivation of (this contract's account id, `agent`), as spike S-a does. The contract checks only the format (`0x` + 40 hex digits, `ERR_INVALID_ADDRESS`), stores it lowercase in `AgentRecord.evm_address`, and does not verify the derivation. That is safe: every authorization is signed by the MPC key derived from (contract, `agent`), so its signature recovers to the real derived address. A wrong `evm_address` only makes those authorizations fail on chain; it cannot send funds anywhere else. Records written by `add_agent` always have `evm_address` set.

**Revoke result.** `revoke` and `revoke_self` clear the state first (mandate, payees and key-to-agent entry; the record stays with `revoked: true`, `public_key: null` and its sweep config) and log `agent_revoked`, then delete the key in a second receipt (spikes/deletekey). The two are not atomic, so neither method returns the bare `DeleteKey` promise: `on_agent_key_deleted` runs after it, never fails, and returns a `RevokeResult` whose `key_deleted` says whether the `DeleteKey` receipt succeeded.

**Second revoke and `DeleteKey` retry.** The contract remembers a revoked agent's key until a `DeleteKey` of it succeeds. Calling `revoke` on an agent that is already revoked:
- if an earlier `DeleteKey` failed, sends `DeleteKey` for that key again and returns its `RevokeResult` as above, with no second `agent_revoked` event. It skips the retry if that key now belongs to a live agent (it was re-added under a new id), so a live agent's key is never deleted;
- otherwise (key already gone) succeeds at once with `key_deleted: false` and no key action.

`revoke_self` cannot run twice: once revoked, the key no longer maps to an agent (`ERR_UNKNOWN_AGENT_KEY`). Clients (O1, R1, DB1, A2) read `RevokeResult.revoked` or `get_agent(..).revoked`, and `list-keys` for the key; they never read a tx status as "nothing changed".

```json example=revoke_result
{ "agent": "agent-1", "revoked": true, "key_deleted": true }
```

### Init

```json example=owner_mode:passkey
{ "mode": "passkey", "public_key": "A2D+1LolWp0xyWHrdMY1bWjASbiSO2H6bOZpYi5g8p+2", "rp_id": "localhost", "origin": "http://localhost:5173" }
```

```json example=owner_mode:wallet
{ "mode": "wallet", "account": "sme-owner.testnet" }
```

`public_key` is the passkey's 33-byte compressed SEC1 P-256 key, checked with `env::p256_verify`. That host function is in near-sdk 5.30 with no feature flag, and the unit-test mock VM implements it. `network` is the string that goes into owner challenges (`testnet`). `mpc_contract` is `v1.signer-prod.testnet`.

### Mandate, sweep config, payees

```json example=mandate
{
  "x402": { "amount_range": { "min": "1", "max": "1000000" }, "budget": "20000000", "period_secs": 604800 },
  "sepa": { "amount_range": { "min": "1", "max": "50000000000000000000" }, "budget": "200000000000000000000", "period_secs": 604800 },
  "usdc_address": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
  "eure_address": "0x29f37f6adca168b79b8d9567eab9be3fbf21db85",
  "chain_id": 84532,
  "float_cap": { "usdc": "25000000", "eure": "250000000000000000000" },
  "max_validity_secs": 300,
  "usdc_eip712_name": "USDC",
  "usdc_eip712_version": "2"
}
```

These are the demo numbers: $1 per call and $20 a week on x402, and €50 per payment and €200 a week on SEPA.
- `amount_range` and `budget` are in each rail's token base units (D8).
- **Budget window (D7).** Each rail has fixed windows that run back to back from the agent's first `set_mandate` at time `start`: window k is `[start + k·period, start + (k+1)·period)`. A reservation counts in the window it was made in (`Reservation.period_start_ms`), and `BudgetView.reserved` sums the counting reservations of the current window. A later `set_mandate` does not restart the window. If it changes `period_secs`, the current window keeps its end, and the new length applies from the next boundary. C3 stores `(window_start_ms, window_secs)` per (agent, rail) and rolls it forward at request time: while `now ≥ window_start + window_secs`, `window_start += window_secs` and `window_secs` takes the mandate's current `period_secs`, computed in O(1) after the first step.
- `set_mandate` needs a live agent (`ERR_UNKNOWN_AGENT`, `ERR_AGENT_REVOKED`). It checks, in this order: `chain_id` is `BASE_SEPOLIA_CHAIN_ID` (`ERR_WRONG_NETWORK`); `usdc_address` and `eure_address` are well-formed (`ERR_INVALID_ADDRESS`, stored lowercase); then the checks below (`ERR_INVALID_MANDATE`).
- `max_validity_secs` must be between `MIN_VALIDITY_SECS` (120) and `MAX_VALIDITY_CAP_SECS` (300) (`ERR_INVALID_MANDATE`).
- `usdc_address`, `eure_address` and `chain_id` must equal the agent's `sweep_config` (`ERR_INVALID_MANDATE`), so the two never disagree. Shapes 2 and 3 read them from the mandate, the sweep from the sweep config.
- `usdc_eip712_name` and `usdc_eip712_version` are the EIP-712 domain `name` and `version` of the `usdc_address` token (PP1): `USDC` / `2` for USDC (the default when the JSON leaves them out), `PayPal USD` / `1` for PYUSD (spikes/pyusd-x402). Each must be 1–32 (name) or 1–8 (version) bytes of printable ASCII (`ERR_WRONG_ASSET`), and both must equal the sweep config's (`ERR_INVALID_MANDATE`). `add_agent` checks the sweep config's the same way.
- Each rail needs `amount_range.min ≤ amount_range.max` and `period_secs > 0` (`ERR_INVALID_MANDATE`).
- `float_cap` is stored for the owner scripts (O3). The contract cannot see Base balances, so it doesn't enforce the cap.

```json example=sweep_config
{ "safe_address": "0x5afe000000000000000000000000000000000001", "usdc_address": "0x036cbd53842c5426634e7929541ec2318f3dcf7e", "eure_address": "0x29f37f6adca168b79b8d9567eab9be3fbf21db85", "chain_id": 84532, "usdc_eip712_name": "USDC", "usdc_eip712_version": "2" }
```

`add_agent` checks the sweep config: `chain_id` is `BASE_SEPOLIA_CHAIN_ID` (`ERR_WRONG_NETWORK`), and the three addresses are well-formed (`ERR_INVALID_ADDRESS`); it stores them lowercase.

The payee allowlist (AP2's `allowed_payees`) is changed only with `add_payee` and `remove_payee` (D5), so a payee change leaves the budget alone. `get_payees` returns the list. Both methods need a live agent (`ERR_UNKNOWN_AGENT`, `ERR_AGENT_REVOKED`) and validate the payee first:
- x402 `pay_to`: `0x` + 40 hex digits (`ERR_INVALID_ADDRESS`), stored lowercase.
- IBAN: uppercase, no spaces, 15–34 characters: two letters, two digits, then letters or digits (`ERR_INVALID_IBAN`). The checksum is not checked.

Adding a payee that is already listed changes nothing and logs nothing. Removing one that is not listed fails (`ERR_PAYEE_NOT_ALLOWED` for x402, `ERR_IBAN_NOT_ALLOWED` for SEPA), so the owner sees a typo. Revoke clears the agent's payees.

```json example=payee:x402
{ "rail": "x402", "pay_to": "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f" }
```

```json example=payee:sepa
{ "rail": "sepa", "iban": "DE89370400440532013000" }
```

(`DE89370400440532013000` is the standard documentation example IBAN, not an account of ours.)

## 2. Owner calls (WebAuthn)

Every owner method is authorized by one assertion over this challenge, exactly as PLAN.md gives it:

```
challenge = sha256("zold-mandate-v1" || contract_id || network || method || borsh(args) || owner_nonce || expires_at)
```

Encoding of each part:
- `"zold-mandate-v1"`, `contract_id` (e.g. `mandate-demo.testnet`), `network` (`testnet`) and `method` (e.g. `set_relayer`): raw UTF-8 bytes, with no length prefix and no separator. `contract_id` and `network` are fixed for a deployment, and the owner method names (the table below, including `sweep`) are prefix-free, so the concatenation is unambiguous. A new owner method must keep that property.
- `borsh(args)`: the borsh encoding of the method's arguments, without `assertion`, as a tuple in parameter order:

  | Method | `args` |
  |---|---|
  | `add_agent` | `(agent: String, public_key: PublicKey, sweep_config: SweepConfig, evm_address: String)` |
  | `set_relayer` | `(account: Option<AccountId>)` |
  | `set_mandate` | `(agent: String, mandate: Mandate)` |
  | `add_payee`, `remove_payee` | `(agent: String, payee: Payee)` |
  | `link_agent`, `revoke` | `(agent: String)` |
  | `resolve_reservation` | `(key: RequestKey, outcome: ResolveOutcome)` |
  | `sweep` (passkey owner) | `(agent: String, token: Token, amount: U128, request_id: String, evm_tx: Option<EvmTxParams>)` |

  Borsh rules:
  - `String` and `AccountId`: u32 LE length, then the bytes.
  - `U128`: 16 bytes LE. `u64`: 8 bytes LE. `u32`: 4 bytes LE.
  - `Option`: `0`, or `1` followed by the value.
  - Structs: fields in declaration order.
  - Enums: a u8 variant index in declaration order, then the fields. `Payee`: `x402`=0, `sepa`=1. `Caller`: `agent`=0, `owner`=1, `relayer`=2. `ResolveOutcome`: `spent`=0, `released`=1. `Token`: `usdc`=0, `eure`=1.
  - `PublicKey`: borsh of a `Vec<u8>`: u32 LE length (33 for ed25519), then the curve byte (`0` for ed25519), then the 32 key bytes.
- `owner_nonce` and `expires_at`: u64, 8 bytes LE (borsh).

`clientDataJSON.challenge` is the 32-byte digest in base64url, with no padding.

**Worked vector (C2 tests against it):** `set_relayer(Some("relayer-demo.testnet"))` on `mandate-demo.testnet`, `testnet`, `owner_nonce = 1`, `expires_at = 1793600000`:
- preimage (hex): `7a6f6c642d6d616e646174652d76316d616e646174652d64656d6f2e746573746e6574746573746e65747365745f72656c61796572011400000072656c617965722d64656d6f2e746573746e65740100000000000000002ae86a00000000`
- challenge (hex): `ec27a25ee1455067baa5daecd431d5c72f6b40842bf3c0df9a8c284b17bd72c5`
- base64url: `7CeiXuFFUGe6pdrs1DHVxy9rQIQr88DfmowoSxe9csU`

```json example=assertion
{
  "authenticator_data": "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAA==",
  "client_data_json": "{\"type\":\"webauthn.get\",\"challenge\":\"7CeiXuFFUGe6pdrs1DHVxy9rQIQr88DfmowoSxe9csU\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}",
  "signature": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==",
  "owner_nonce": 1,
  "expires_at": 1793600000
}
```

`assert_owner` (C2) checks, in this order:
1. `clientDataJSON.type == "webauthn.get"`.
2. `challenge`, decoded as strict base64url, equals the recomputed digest.
3. `origin` equals the stored origin.
4. `authenticatorData[0..32] == sha256(rp_id)`.
5. The user-presence flag (bit 0 of byte 32) is set.
6. `owner_nonce` is greater than the stored nonce.
7. `expires_at` has not passed (`ERR_ASSERTION_EXPIRED`) and is at most `MAX_ASSERTION_TTL_SECS` (600) after block time (`ERR_ASSERTION_TTL_TOO_LONG`). A failed owner call is public on chain and replayable until `expires_at`, because the nonce is consumed only on success, so the window stays short.
8. `p256_verify(signature, sha256(authenticatorData || sha256(clientDataJSON)), public_key)`.

`signature` is the raw 64-byte `r || s`; the client converts the browser's DER form. **Both S forms are accepted** (`s` and `n − s`): real passkeys produce high-S signatures (spikes/passkey), and `p256_verify` accepts both. Nobody normalises S. Malleability is harmless because replay protection is `owner_nonce`, never the signature bytes. `owner_nonce` is one counter for all owner methods, and it is consumed only when the call succeeds. An older nonce fails with `ERR_ASSERTION_STALE_NONCE`, and the owner re-signs. `signCount` is never used. (The signature in the example above is a placeholder.)

## 3. Shapes

`request_signature(request_id, shape)` takes the decoded fields, and the contract builds every hash itself.
- `request_id`: 1–64 characters from `[A-Za-z0-9._:-]` (`ERR_INVALID_REQUEST_ID`). It is deduped per (caller, agent). The lower-case prefix `link-` is reserved for the ids `link_agent` picks itself (`link-<ms>`): `request_signature` and `sweep` (every caller) reject a `request_id` starting with `link-` with `ERR_INVALID_REQUEST_ID`.
- **Request cap.** Reservations are never removed, and the contract pays their storage. So an agent's own key may store at most `MAX_AGENT_REQUESTS` (64) requests over the agent's lifetime, final ones included; the next fails with `ERR_OVER_BUDGET` (detail names `MAX_AGENT_REQUESTS`). That bounds the storage one agent key can lock at about 0.55 NEAR (about 850 bytes per reservation at the longest ids). Like the key's gas allowance, the owner tops it up by adding a new agent. Relayer and owner requests do not count.
- `CLOCK_SKEW_SECS` = 60 is the one allowed clock difference between NEAR block time and the client, the facilitator or Monerium. Every validity window below includes it, so no window is longer than its cap.
- Every EIP-3009 nonce is `keccak256(borsh((agent: String, caller: Caller, shape: u8, request_id: String)))` (D3), with `shape` from `ShapeKind::tag()`: 1 sweep, 2 x402, 3 payout, 4 link, 5 paypal, 6 paypal_checkout, 7 refund.
- Every signature comes from the MPC with `domain_id: 0` and path = `agent`.

The PayPal shapes, which prose calls shapes 4, 5 and 6 (payout, vaulted-wallet charge, refund; tags 5, 6 and 7), are defined in `contract/src/shapes/paypal.rs`, `paypal_checkout.rs` and `refund.rs`, with their order texts and the rail's checks in `rails/paypal/README.md` (overview: [PAYPAL.md](../PAYPAL.md)). This file covers nearH's shapes.

### Shape 1: sweep (`sweep` only)

```json example=shape:sweep
{ "type": "sweep", "token": "usdc", "amount": "19990000" }
```

Every sweep goes to `sweep_config.safe_address`, needs no mandate, works after revoke and counts against no budget (D8). Never `permit`.
- **USDC:** EIP-3009 `transferWithAuthorization` from the agent EOA to the Safe, with `validAfter = now − CLOCK_SKEW_SECS` and `validBefore = validAfter + SWEEP_VALIDITY_SECS` (300 s). `evm_tx` must be `None` (`ERR_EVM_TX_FORBIDDEN`).
- **EURe:** EURe has no EIP-3009 (spikes/eure), so the contract builds a raw ERC-20 `transfer(safe_address, amount)` as an EIP-1559 (type 2) transaction from the agent EOA. `evm_tx` is required (`ERR_EVM_TX_REQUIRED`) and supplies only what the contract cannot know:

  ```json example=evm_tx
  { "nonce": 0, "gas_limit": 80000, "max_fee_per_gas": "2000000000", "max_priority_fee_per_gas": "1000000" }
  ```

  - `nonce` is the agent EOA's next account nonce on Base; gas fees are in wei. `gas_limit ≤ MAX_SWEEP_GAS_LIMIT` (150 000) and `max_priority_fee_per_gas ≤ max_fee_per_gas`, else `ERR_INVALID_EVM_TX`.
  - The contract fixes the rest: `chain_id = sweep_config.chain_id`, `to = sweep_config.eure_address`, `value = 0`, `data = 0xa9059cbb ‖ pad32(safe_address) ‖ pad32(amount)`, empty access list. The digest sent to the MPC is `keccak256(0x02 ‖ rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, []]))`.
  - The payload is `SignedPayload::Eip1559Tx` (§4). The submitter (R1 or O3) appends `y_parity = v − 27`, `r`, `s`, and broadcasts it.
  - Gas: PLAN.md has the relayer send the agent EOA just enough ETH for this one tx first (`gas_limit × max_fee_per_gas`). The agent holds no other ETH, so a high fee only makes the tx fail; it can't drain anything. Nothing on chain expires this tx; it is dead once the EOA nonce passes it, and either way it can only move EURe to the Safe.

### Shape 2: x402 payment

The seller's payment requirements, as the agent decoded them (x402 v2 names):

```json example=x402_requirements
{ "resourceUrl": "http://localhost:4021/weather", "scheme": "exact", "network": "eip155:84532", "asset": "0x036cbd53842c5426634e7929541ec2318f3dcf7e", "payTo": "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f", "amount": "10000", "maxTimeoutSeconds": 240 }
```

```json example=shape:x402
{ "type": "x402", "resourceUrl": "http://localhost:4021/weather", "scheme": "exact", "network": "eip155:84532", "asset": "0x036cbd53842c5426634e7929541ec2318f3dcf7e", "payTo": "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f", "amount": "10000", "maxTimeoutSeconds": 240 }
```

Where the fields come from. The seller (`seller/`, on `@x402/express`) answers an unpaid request with `402` and a `PAYMENT-REQUIRED` header: base64 JSON `{x402Version: 2, error, resource: {url, description, mimeType}, accepts: [{scheme, network, amount, asset, payTo, maxTimeoutSeconds, extra}]}`.
- **`resourceUrl`** is not in the `accepts` entry. x402 v2 puts it in the envelope, so the agent sets `resourceUrl = resource.url`. The other fields come from the `accepts` entry the agent pays.
- **`extra`** (`{name: "USDC", version: "2"}`) is in the seller's `accepts` entry but not in this shape. The contract fixes the EIP-712 name and version itself.
- **Address case.** The seller sends `asset` and `payTo` exactly as configured. It does not normalize them. `asset` is the checksummed USDC constant (`0x036CbD53842c5426634e7929541eC2318f3dCF7e`), and `payTo` is `SELLER_PAY_TO` verbatim, in whichever case it was written. So the agent may submit checksummed, lower-case or mixed-case addresses. The examples here are lower-case. The contract compares both without regard to case. It lower-cases `payTo` and matches it against the allowlist ignoring case, and it matches `asset` against `usdc_address` ignoring case. The `to` and `verifyingContract` it signs over and returns in the payload are lower-case.

Checks (C5):
- `scheme == "exact"`;
- `payTo` is on the allowlist;
- `asset == usdc_address`;
- `network == "eip155:" + chain_id`;
- `amount` is within `x402.amount_range` and the budget;
- `maxTimeoutSeconds ≥ 1` (`ERR_INVALID_TIMEOUT`).

A long `maxTimeoutSeconds` is **clamped, not rejected**, because sellers stay unmodified (PLAN.md). The contract builds `TransferWithAuthorization` with `to = payTo`, `value = amount`, the EIP-712 domain `{name: usdc_eip712_name, version: usdc_eip712_version, chainId, verifyingContract: usdc_address}` from the mandate (`USDC` / `2` by default), and:
- `validAfter = now − CLOCK_SKEW_SECS`;
- `validBefore = now + min(maxTimeoutSeconds, max_validity_secs − CLOCK_SKEW_SECS)`.

So `validBefore − validAfter ≤ max_validity_secs` always holds. With the demo mandate (300 s), a seller asking for 60 s gets 60 s past block time, and one asking for 3600 s gets 240 s.

The client builds the x402 `paymentPayload` from the seller's `accepts` entry, `extra` included, plus the signature (see spikes/x402). `extra` must equal the mandate asset's EIP-712 domain, `{name: usdc_eip712_name, version: usdc_eip712_version}` (for USDC `{name: "USDC", version: "2"}`, for PYUSD `{name: "PayPal USD", version: "1"}`), because the contract signs that domain.

### Shape 3: Monerium payout

```json example=shape:payout
{ "type": "payout", "iban": "DE89370400440532013000", "amount": "42.50", "timestamp": 1793700000 }
```

The contract signs (EIP-191 `personal_sign`) the message

```
Send EUR {amount} to {iban} at {RFC3339}
```

For the example above, it signs `Send EUR 42.5 to DE89370400440532013000 at 2026-11-03T10:00:00Z`.
- **Canonical amount (D9):** the input must match `^[0-9]+(\.[0-9]{1,2})?$`. It is rendered with no leading zeros in the integer part, no trailing zeros and no trailing dot: `007.50` → `7.5`, `1.50` → `1.5`, `2.00` → `2`, `0.50` → `0.5`, `42.5` stays. This matches Zold-app's `moneriumAmountString`. Anything else is `ERR_INVALID_AMOUNT`: `.5`, `5.`, a sign, an exponent, spaces, a comma, 3+ decimals, and zero (`0`, `0.00`). The cap and budget use `amount × 10^18` EURe base units.
- **Timestamp:** `timestamp` is unix seconds, rendered in UTC as `YYYY-MM-DDTHH:MM:SSZ`. It is accepted when `now − (max_validity_secs − CLOCK_SKEW_SECS) ≤ timestamp ≤ now + CLOCK_SKEW_SECS` (`ERR_TIMESTAMP_STALE`, `ERR_TIMESTAMP_FUTURE`). The contract would sign a given timestamp only during a window of at most `max_validity_secs`, never 2×. `valid_before = timestamp + max_validity_secs − CLOCK_SKEW_SECS`. C6 confirms that this byte format matches the order S-b got accepted.
- **Memo:** `pay_sepa.memo` is not part of the signed message. A2 passes it with the signed order to M1, which sets it on the Monerium order; a held item carries it (§6).
- **Checks:** the IBAN is on the allowlist; the amount is within `sepa.amount_range` and the budget; this agent has not had `(iban, amount, timestamp)` signed before (`ERR_DUPLICATE_PAYOUT`, D3). The dedupe key is `keccak256(borsh(("nearh:payout-dedupe:v1", agent, iban, canonical_amount, timestamp)))`: per agent, domain-separated, and length-prefixed by borsh, so two agents paying the same IBAN and amount in the same second are both signed.

### Owner-only: link (`link_agent` only)

```json example=shape:link
{ "type": "link" }
```

The contract signs `I hereby declare that I am the address owner.` with EIP-191, once per agent (`ERR_ALREADY_LINKED`). `request_signature` refuses both `sweep` and `link` with `ERR_SHAPE_NOT_ALLOWED`. An unknown `type` fails argument parsing.

`link_agent` sets `linked` when it sends the request. A failed or wrong-key MPC callback resets it so the owner can link again, if the link reservation is `pending`, `unknown` or `released`, and logs `agent_unlinked` (§5). Resolving a link reservation to `released` does not reset `linked` by itself: the MPC callback may still bring a valid signature (which records `signed`), and resetting earlier would allow a second link signature. A `spent` or `signed` link keeps `linked`.

## 4. Requests and reservations

```json example=request_key
{ "agent": "agent-1", "caller": { "kind": "agent" }, "request_id": "inv-2026-0042" }
```

`caller` is `{"kind":"agent"}`, `{"kind":"owner"}` or `{"kind":"relayer","account":"relayer-demo.testnet"}`.

**Status transitions** (`RequestStatus::can_become`):

```
pending ──callback ok──▶ signed                (revoked, if the agent was revoked meanwhile; D10)
pending ──callback failed / expire_pending──▶ unknown
unknown ──owner resolve_reservation──▶ spent | released   (released only after release_after)
unknown | spent | released ──late callback──▶ signed | revoked
signed, revoked: final
```

- `pending`, `signed`, `unknown`, `spent` and `revoked` count against the budget.
- A `released` reservation does not count. After a release, `counts_against_budget` stays false, even if a late callback records `signed`.
- `release_after` decides when `released` is allowed (`ERR_VALIDITY_NOT_ENDED` before it):
  - x402 and USDC sweep: `valid_before`. USDC enforces `validBefore` on chain, so a late signature is already expired.
  - Payout: `max(valid_before, timestamp + PAYOUT_RELEASE_DELAY_SECS)` (300 s for now). Nothing on chain expires a signed payout order; only Monerium's own timestamp tolerance does, and S-b has not measured it yet. When it does, `PAYOUT_RELEASE_DELAY_SECS` becomes that tolerance. Until then, **M1 must refuse to submit a payout whose reservation is `released`** (it reads `get_request` first). C3/C6 and T2 test both: release refused before `release_after`, and M1 refusing a released payout.
  - Link and EURe sweep: `0`; they count against no budget.
- A failed callback on a reservation that is already `unknown` (after `expire_pending`) is a no-op: not a transition and not `ERR_BAD_TRANSITION`.
- `expire_pending(key)` works once `created_at_ms + MPC_TIMEOUT_MS` (300 s) has passed (`ERR_MPC_TIMEOUT_NOT_REACHED`).
- "Held" exists only off chain (§6).

`on_signature` returns the `Reservation`, so the agent gets the signature as the result of its `request_signature` tx:

```json example=reservation
{
  "key": { "agent": "agent-1", "caller": { "kind": "agent" }, "request_id": "pay-0001" },
  "shape": "x402",
  "rail": "x402",
  "amount": "10000",
  "period_start_ms": 1793550000000,
  "created_at_ms": 1793555551000,
  "valid_before": 1793555881,
  "release_after": 1793555881,
  "digest": "0x720dffe2a39e40e2513eaf70b1d55c4b0b4667c34d2812e2113bebc6834cb5ed",
  "payload": {
    "kind": "eip3009",
    "asset": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
    "chain_id": 84532,
    "from": "0xbbc0320e02d371a71f18a40b7b15404df218d880",
    "to": "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f",
    "value": "10000",
    "valid_after": 1793555521,
    "valid_before": 1793555881,
    "nonce": "0x1fc1b8c54141f9488ae59cb01f3500d4b02062c27a2fc5839004370c81a716c7"
  },
  "status": "signed",
  "counts_against_budget": true,
  "signature": {
    "r": "0xc36c8c02881c3a55099ebaf50a5aabc502c9195659ec6b69e3376bacaa84d383",
    "s": "0x3b537f6c4f6d41969f2585b99c74638ad0d4c24c45fcd2f143a94d9825e20263",
    "v": 28
  }
}
```

(The field values come from the S-c run. That run used `now − 60 … now + 300`, a 360 s window; C5 builds at most `max_validity_secs`.)

A payout that became `unknown`. The digest is the EIP-191 hash of the text; `valid_before = 1793700000 + 300 − 60`, `release_after = 1793700000 + 300`:

```json example=reservation:payout
{
  "key": { "agent": "agent-1", "caller": { "kind": "agent" }, "request_id": "inv-2026-0042" },
  "shape": "payout",
  "rail": "sepa",
  "amount": "42500000000000000000",
  "period_start_ms": 1793550000000,
  "created_at_ms": 1793700010000,
  "valid_before": 1793700240,
  "release_after": 1793700300,
  "digest": "0x7292cb34abf39914f4e4b4ad39d14974b6311ebc7cebce59c89d35d8f2834659",
  "payload": { "kind": "message", "text": "Send EUR 42.5 to DE89370400440532013000 at 2026-11-03T10:00:00Z" },
  "status": "unknown",
  "counts_against_budget": true,
  "signature": null
}
```

A pending EURe sweep requested by the relayer (10 EURe, the `evm_tx` example above). The digest is the keccak256 of the unsigned type-2 tx:

```json example=reservation:sweep_eure
{
  "key": { "agent": "agent-1", "caller": { "kind": "relayer", "account": "relayer-demo.testnet" }, "request_id": "sweep-eure-0001" },
  "shape": "sweep",
  "rail": null,
  "amount": "0",
  "period_start_ms": 1793550000000,
  "created_at_ms": 1793700010000,
  "valid_before": 0,
  "release_after": 0,
  "digest": "0x2d7d3f98d690daa7f5305927d06b2a2b577de2dc0f911e74722703abe95ff378",
  "payload": {
    "kind": "eip1559_tx",
    "chain_id": 84532,
    "nonce": 0,
    "max_priority_fee_per_gas": "1000000",
    "max_fee_per_gas": "2000000000",
    "gas_limit": 80000,
    "to": "0x29f37f6adca168b79b8d9567eab9be3fbf21db85",
    "value": "0",
    "data": "0xa9059cbb0000000000000000000000005afe0000000000000000000000000000000000010000000000000000000000000000000000000000000000008ac7230489e80000"
  },
  "status": "pending",
  "counts_against_budget": true,
  "signature": null
}
```

- For a payout or the link, `payload` is `{"kind":"message","text":...}`; for the EURe sweep it is `eip1559_tx`; otherwise `eip3009`.
- `v = 27 + recovery_id` from the MPC response, never derived from the `big_r` prefix.
- The agent EOA (`from`) is `derive(contract_id, agent)` on the MPC and is stored in `AgentRecord.evm_address`, supplied by the owner in `add_agent` (§1, "Agent EOA").

## 5. Events (NEP-297)

Every state change logs `EVENT_JSON:` followed by one object with `standard: "zold-mandate"`, `version: "1.0.0"`, `event` and `data`. A rejected call panics with `"{CODE}: {detail}"` (§7) and logs nothing.

```json example=event:agent_added
{ "standard": "zold-mandate", "version": "1.0.0", "event": "agent_added", "data": { "agent": "agent-1", "public_key": "ed25519:EuRa2phH1QCNW9fkjXArT71XybokoeCCR8z6RA5eXMvJ", "sweep_config": { "safe_address": "0x5afe000000000000000000000000000000000001", "usdc_address": "0x036cbd53842c5426634e7929541ec2318f3dcf7e", "eure_address": "0x29f37f6adca168b79b8d9567eab9be3fbf21db85", "chain_id": 84532, "usdc_eip712_name": "USDC", "usdc_eip712_version": "2" } } }
```

```json example=event:agent_add_failed
{ "standard": "zold-mandate", "version": "1.0.0", "event": "agent_add_failed", "data": { "agent": "agent-1", "public_key": "ed25519:EuRa2phH1QCNW9fkjXArT71XybokoeCCR8z6RA5eXMvJ" } }
```

```json example=event:relayer_set
{ "standard": "zold-mandate", "version": "1.0.0", "event": "relayer_set", "data": { "account": "relayer-demo.testnet" } }
```

```json example=event:mandate_set
{ "standard": "zold-mandate", "version": "1.0.0", "event": "mandate_set", "data": { "agent": "agent-1", "mandate": { "x402": { "amount_range": { "min": "1", "max": "1000000" }, "budget": "20000000", "period_secs": 604800 }, "sepa": { "amount_range": { "min": "1", "max": "50000000000000000000" }, "budget": "200000000000000000000", "period_secs": 604800 }, "usdc_address": "0x036cbd53842c5426634e7929541ec2318f3dcf7e", "eure_address": "0x29f37f6adca168b79b8d9567eab9be3fbf21db85", "chain_id": 84532, "float_cap": { "usdc": "25000000", "eure": "250000000000000000000" }, "max_validity_secs": 300, "usdc_eip712_name": "USDC", "usdc_eip712_version": "2" } } }
```

```json example=event:payee_added
{ "standard": "zold-mandate", "version": "1.0.0", "event": "payee_added", "data": { "agent": "agent-1", "payee": { "rail": "sepa", "iban": "DE89370400440532013000" } } }
```

```json example=event:payee_removed
{ "standard": "zold-mandate", "version": "1.0.0", "event": "payee_removed", "data": { "agent": "agent-1", "payee": { "rail": "x402", "pay_to": "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f" } } }
```

```json example=event:signature_requested
{ "standard": "zold-mandate", "version": "1.0.0", "event": "signature_requested", "data": { "key": { "agent": "agent-1", "caller": { "kind": "agent" }, "request_id": "pay-0001" }, "shape": "x402", "rail": "x402", "amount": "10000", "digest": "0x720dffe2a39e40e2513eaf70b1d55c4b0b4667c34d2812e2113bebc6834cb5ed", "valid_before": 1793555881 } }
```

```json example=event:signature_recorded
{ "standard": "zold-mandate", "version": "1.0.0", "event": "signature_recorded", "data": { "key": { "agent": "agent-1", "caller": { "kind": "relayer", "account": "relayer-demo.testnet" }, "request_id": "sweep-0001" }, "status": "signed", "signature": { "r": "0xc36c8c02881c3a55099ebaf50a5aabc502c9195659ec6b69e3376bacaa84d383", "s": "0x3b537f6c4f6d41969f2585b99c74638ad0d4c24c45fcd2f143a94d9825e20263", "v": 28 } } }
```

```json example=event:request_unknown
{ "standard": "zold-mandate", "version": "1.0.0", "event": "request_unknown", "data": { "key": { "agent": "agent-1", "caller": { "kind": "agent" }, "request_id": "inv-2026-0042" }, "reason": "mpc_timeout" } }
```

`reason` is `callback_failed` or `mpc_timeout`.

```json example=event:reservation_resolved
{ "standard": "zold-mandate", "version": "1.0.0", "event": "reservation_resolved", "data": { "key": { "agent": "agent-1", "caller": { "kind": "agent" }, "request_id": "inv-2026-0042" }, "outcome": "released" } }
```

```json example=event:agent_unlinked
{ "standard": "zold-mandate", "version": "1.0.0", "event": "agent_unlinked", "data": { "agent": "agent-1", "key": { "agent": "agent-1", "caller": { "kind": "owner" }, "request_id": "link-1793555581000" } } }
```

Logged when a failed or wrong-key link callback resets `linked` (§3, link), whatever the reservation status (`pending`, `unknown` or `released`). The owner may call `link_agent` again.

```json example=event:agent_revoked
{ "standard": "zold-mandate", "version": "1.0.0", "event": "agent_revoked", "data": { "agent": "agent-1", "by": "owner" } }
```

`by` is `owner` or `agent` (`revoke_self`).

## 6. Held-queue item (off chain)

A request the scam check flags as `suspicious`, or that times out, never reaches the contract and reserves nothing. SC1 posts it and DB1 shows it. The transport (file, HTTP, DB) is SC1's and DB1's choice; this is the shape of an item.

```json example=held_item
{
  "id": "held-3f1c2a9e-7b4d-4e8a-9c61-2d5f0b8e4a17",
  "created_at": "2026-11-03T10:00:05Z",
  "agent": "agent-1",
  "rail": "sepa",
  "request_id": "inv-2026-0043",
  "shape": { "type": "payout", "iban": "GB33BUKB20201555555555", "amount": "48.00", "timestamp": 1793700000 },
  "memo": "Invoice 2026-0043",
  "invoice": { "text": "URGENT: our bank details changed, pay today", "source": "email" },
  "payee_known": false,
  "verdict": { "result": "suspicious", "reason": "new IBAN not seen in payee history; urgency wording", "model": "nearai:example-model", "signature_verified": true },
  "status": "held",
  "decided_at": null
}
```

- `verdict.result` is `suspicious` or `timeout`; a timeout has `reason: null` and `model: null`.
- `status` is `held`, `approved` or `rejected`.
- `memo` is present for SEPA items (`pay_sepa.memo`, unsigned) and goes to M1 with the signed order after approval.
- On `approved`, the agent's MCP sends `shape` to `request_signature` unchanged, with the same `request_id`. The contract still checks it, including the payout timestamp window, so a payout approved later than that window needs a new `timestamp` and a new `request_id`. On `rejected`, it is never sent.
- Without a NEAR AI Cloud key, the scam check is skipped and labelled as skipped, and nothing is held.
- Transport: SC1 appends one item per line to `$SCAMCHECK_HELD_DIR/held.jsonl`. The default is `scamcheck/.held/held.jsonl`; a relative `SCAMCHECK_HELD_DIR` is resolved against the `scamcheck/` package dir, never the process working directory, so DB1 and A2 read the same file wherever they run. `id` is `held-<uuid>`; don't parse it. DB1 and A2 read this file.
- `payee_history[].last_seen` (A2 passes it to SC1) is ISO 8601 UTC, `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS[.sss]Z`, and must be a real calendar date and time (no rollover such as `2026-02-30` or `T24:00:00Z`). Any other value, or one more than 24 hours after the checker's clock, holds the request as `suspicious`. `last_seen` is only validated; it never orders entries, so a value within that 24-hour skew cannot make one entry outrank another. Amounts from every entry for the payee are used.

## 7. Error codes

A failing call panics with `"{CODE}: {detail}"`, where `detail` names the decoded field that failed. The codes are in `contract/src/errors.rs`:

| Area | Codes |
|---|---|
| Stubs | `ERR_NOT_IMPLEMENTED` |
| Owner calls | `ERR_ASSERTION_REQUIRED`, `ERR_ASSERTION_FORBIDDEN`, `ERR_NOT_OWNER`, `ERR_ASSERTION_MALFORMED`, `ERR_ASSERTION_BAD_TYPE`, `ERR_ASSERTION_BAD_CHALLENGE`, `ERR_ASSERTION_BAD_ORIGIN`, `ERR_ASSERTION_BAD_RP_ID_HASH`, `ERR_ASSERTION_NO_USER_PRESENCE`, `ERR_ASSERTION_STALE_NONCE`, `ERR_ASSERTION_EXPIRED`, `ERR_ASSERTION_TTL_TOO_LONG`, `ERR_ASSERTION_BAD_SIGNATURE` |
| Agents | `ERR_NOT_AGENT_KEY`, `ERR_UNKNOWN_AGENT_KEY`, `ERR_UNKNOWN_AGENT`, `ERR_AGENT_EXISTS`, `ERR_KEY_EXISTS`, `ERR_INVALID_AGENT_ID`, `ERR_AGENT_REVOKED`, `ERR_NO_MANDATE`, `ERR_INVALID_MANDATE`, `ERR_INVALID_ADDRESS` |
| Requests | `ERR_INVALID_REQUEST_ID`, `ERR_DUPLICATE_REQUEST_ID`, `ERR_SHAPE_NOT_ALLOWED`, `ERR_REQUEST_NOT_FOUND`, `ERR_BAD_TRANSITION`, `ERR_MPC_TIMEOUT_NOT_REACHED`, `ERR_VALIDITY_NOT_ENDED`, `ERR_BELOW_MINIMUM`, `ERR_OVER_PER_PAYMENT_CAP`, `ERR_OVER_BUDGET` |
| Sweep | `ERR_SWEEP_CALLER_NOT_ALLOWED`, `ERR_SWEEP_PENDING`, `ERR_EVM_TX_REQUIRED`, `ERR_EVM_TX_FORBIDDEN`, `ERR_INVALID_EVM_TX` |
| x402 | `ERR_PAYEE_NOT_ALLOWED`, `ERR_WRONG_SCHEME`, `ERR_WRONG_ASSET`, `ERR_WRONG_NETWORK` (also a `sweep_config` or `mandate` chain id other than 84532), `ERR_INVALID_TIMEOUT` |
| Payout | `ERR_IBAN_NOT_ALLOWED`, `ERR_INVALID_IBAN`, `ERR_INVALID_AMOUNT`, `ERR_TIMESTAMP_STALE`, `ERR_TIMESTAMP_FUTURE`, `ERR_DUPLICATE_PAYOUT` |
| Link | `ERR_ALREADY_LINKED` |
| PayPal and settlement | `ERR_PAYPAL_PAYEE_NOT_ALLOWED`, `ERR_INVALID_PAYPAL_PAYEE`, `ERR_INVALID_ORDER_REF`, `ERR_INVALID_CAPTURE_ID`, `ERR_NOT_SETTLEMENT_REPORTER`, `ERR_INVALID_SETTLEMENT`, `ERR_PAYEE_SUSPENDED`, `ERR_PAYEE_NOT_SUSPENDED` |

## 8. Agent MCP tools

The agent's MCP exposes these four tools and, in the PayPal entry, `pay_paypal` (`agent/mcp/src/policy.ts`), and nothing else. There is no `set_mandate`, no payee change, no link and no top-up. Before every payment it runs the scam check (§6), and the contract decides whatever the scam check says. The schemas are JSON Schema (`inputSchema` / `outputSchema` as in MCP); A2 implements them.

```json example=mcp:pay_x402
{
  "name": "pay_x402",
  "description": "Pay for an HTTP resource that answers 402 with x402 payment requirements, within the mandate.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "url": { "type": "string", "format": "uri" },
      "method": { "type": "string", "enum": ["GET", "POST"], "default": "GET" },
      "body": { "type": "string" },
      "reason": { "type": "string", "description": "Why the agent is paying; goes to the scam check." }
    },
    "required": ["url", "reason"],
    "additionalProperties": false
  },
  "outputSchema": {
    "type": "object",
    "properties": {
      "status": { "type": "string", "enum": ["paid", "held", "blocked", "pending", "failed"] },
      "request_id": { "type": "string" },
      "amount": { "type": "string", "description": "USDC base units" },
      "pay_to": { "type": "string" },
      "tx_hash": { "type": "string" },
      "error_code": { "type": "string", "description": "ERR_* from the contract when blocked" },
      "detail": { "type": "string" },
      "response": { "type": "string", "description": "The paid resource's body" }
    },
    "required": ["status", "request_id"]
  }
}
```

```json example=mcp:pay_sepa
{
  "name": "pay_sepa",
  "description": "Pay an invoice in euros over SEPA through Monerium, within the mandate.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "iban": { "type": "string", "pattern": "^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$" },
      "amount": { "type": "string", "pattern": "^[0-9]+(\\.[0-9]{1,2})?$", "description": "Decimal euros" },
      "memo": { "type": "string", "maxLength": 140, "description": "Not signed; set on the Monerium order by M1" },
      "invoice": { "type": "string", "description": "The invoice text as received; goes to the scam check." },
      "reason": { "type": "string" }
    },
    "required": ["iban", "amount", "memo", "reason"],
    "additionalProperties": false
  },
  "outputSchema": {
    "type": "object",
    "properties": {
      "status": { "type": "string", "enum": ["submitted", "held", "blocked", "pending", "failed"] },
      "request_id": { "type": "string" },
      "monerium_order_id": { "type": "string" },
      "error_code": { "type": "string" },
      "detail": { "type": "string" }
    },
    "required": ["status", "request_id"]
  }
}
```

```json example=mcp:revoke
{
  "name": "revoke",
  "description": "Revoke this agent's own mandate and key (revoke_self). It cannot be undone by the agent.",
  "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
  "outputSchema": {
    "type": "object",
    "properties": {
      "revoked": { "type": "boolean", "description": "From RevokeResult or get_agent, never from the tx status" },
      "key_deleted": { "type": "boolean" },
      "tx_hash": { "type": "string" }
    },
    "required": ["revoked"]
  }
}
```

```json example=mcp:get_receipt
{
  "name": "get_receipt",
  "description": "Look up one payment by request_id.",
  "inputSchema": {
    "type": "object",
    "properties": { "request_id": { "type": "string" } },
    "required": ["request_id"],
    "additionalProperties": false
  },
  "outputSchema": {
    "type": "object",
    "properties": {
      "request_id": { "type": "string" },
      "rail": { "type": "string", "enum": ["x402", "sepa"] },
      "status": { "type": "string", "enum": ["held", "blocked", "pending", "signed", "unknown", "spent", "released", "revoked"] },
      "amount": { "type": "string" },
      "payee": { "type": "string", "description": "payTo address or IBAN" },
      "tx_hash": { "type": "string" },
      "monerium_order_id": { "type": "string" },
      "reservation": { "type": "object", "description": "The contract's Reservation (§4), when it exists" }
    },
    "required": ["request_id", "status"]
  }
}
```

## 9. Decisions

Lead decisions on the C1 review, following PLAN.md. The owner may override any of them.

1. **No low-S requirement.** Owner signatures are accepted in either S form (S-h: real passkeys produce high-S). Replay protection is `owner_nonce`. (§2)
2. **Owner can sweep in passkey mode.** `sweep` takes `assertion: Option<OwnerAssertion>`: `Some` lets the passkey owner sweep through any submitter, and the wallet owner calls with `None`. Agents and the relayer pass `None`. This matches PLAN.md: "the owner, the agent or the relayer". (§1)
3. **EURe sweep interface settled in C1.** The EURe sweep is a contract-built EIP-1559 raw ERC-20 `transfer(safe_address, amount)`. The caller supplies `EvmTxParams` (nonce, gas limit, fees), the contract fixes chain id, `to`, value and calldata, and the relayer funds that one tx's gas. USDC keeps EIP-3009. (§3, §4)
4. **Budget windows (D7).** Fixed windows run back to back from the first `set_mandate`: window k = `[start + k·period, start + (k+1)·period)`. A reservation counts in the window it was made in. A later `set_mandate` doesn't restart the window, and a changed `period_secs` applies from the next boundary. (§1)
5. **Payout timestamp.** It is accepted when `now − (max_validity_secs − 60) ≤ ts ≤ now + 60`, so the total window never exceeds `max_validity_secs`. 60 s is `CLOCK_SKEW_SECS`. (§3)
6. **Revoke result.** `revoke` and `revoke_self` return a `RevokeResult` from a callback that never fails, not the bare `DeleteKey` promise (S-i). Clients check state, not tx status. (§1)
7. **x402 timeout is clamped.** validity = `min(maxTimeoutSeconds, max_validity_secs)`, applied as `validBefore = now + min(maxTimeoutSeconds, max_validity_secs − 60)` with `validAfter = now − 60`, so `validBefore − validAfter ≤ max_validity_secs`. Sellers stay unmodified. (§3)

Follow-ons from the same review (C1 author's choices; the lead may change them):
- **Released payouts:** `release_after` for a payout waits at least `PAYOUT_RELEASE_DELAY_SECS` past its timestamp, and M1 refuses a released payout (review finding M1). (§4)
- `MIN_VALIDITY_SECS` = 120, so the payout timestamp window and an x402 authorization still last at least 60 s after the skew is subtracted. `MAX_ASSERTION_TTL_SECS` = 600. `request_id` charset `[A-Za-z0-9._:-]`. The mandate's token addresses and chain id must equal the sweep config's.
