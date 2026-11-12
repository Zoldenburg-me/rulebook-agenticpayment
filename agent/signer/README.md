# agent/signer

The agent's x402 signer (A1). `@x402/fetch` pays an x402 seller, and every signature comes from the mandate contract's `request_signature` (shape 2, docs/interfaces.md §3), which checks the mandate, builds the EIP-3009 `transferWithAuthorization` itself and has `v1.signer-prod.testnet` sign it. Testnet only. It uses the open `@x402/core`, `@x402/evm` and `@x402/fetch` 2.30.0 packages (Apache-2.0).

- `NearX402Signer` has the agent EOA as `address`. `connect()` finds the agent by its key (`agent_of_key`) and reads the EOA from `get_agent`: the MPC-derived address the owner registered in `add_agent`. An `expectedAddress` (`AGENT_EVM_ADDRESS`) must match it. It refuses an RPC whose `status.chain_id` is not `testnet` and a `contractId` that does not end in `.testnet`; `allowNonTestnet: true` turns both checks off, for a local sandbox only.
- `signX402(shape)` sends `request_signature` with a fresh `request_id` (`x402-<ms base36>-<16 hex>`), signed with the agent's function-call key, and waits for the MPC callback. If `send_tx` times out first, it polls the tx until the deadline (default 120 s). It then checks the returned `Reservation` before handing anything out: it must be `signed`, and its payload must have `from` = the agent EOA, `to` = `payTo`, the same `value`, `asset` and chain, and a signature that recovers to the agent EOA under USDC's EIP-712 domain. A contract rejection comes back with the contract's error code (`ERR_PAYEE_NOT_ALLOWED: …`).
- Settlement window: a seller `maxTimeoutSeconds` under `minSignSeconds + settleMarginSeconds` (default 15 + 30 s) is refused with `SettlementWindowError` (`window-too-short`) before `request_signature`, so nothing is reserved. A signed authorization with less than `settleMarginSeconds` left is refused with `SettlementWindowError` (`expires-too-soon`); that reservation stays `signed` and counts toward the budget.
- Txs from one agent key are sent one at a time in this process (nonce lookup through `send_tx`), so concurrent payments never share or reorder a nonce. Time queued behind another payment counts toward the deadline.
- `NearExactEvmScheme` replaces `@x402/evm`'s `ExactEvmScheme` for `exact` on Base Sepolia. The stock scheme picks its own nonce and validity window and asks the signer to sign that message. The contract picks both itself (nonce per D3, window `now − 60 … now + min(maxTimeoutSeconds, max_validity_secs − 60)`), so a caller-built message can never be signed as it is. The scheme sends the payment requirements instead and returns the contract-built authorization. For the same reason, `NearX402Signer.signTypedData` always throws. The scheme refuses an EIP-712 domain other than `{name: "USDC", version: "2"}` (the only one the contract signs), Permit2 requirements and x402 v1.
- `nearX402Fetch(signer)` is `wrapFetchWithPayment` with that scheme registered for `eip155:84532` only. `x402Client`'s default spend controls stay on: default assets only, and at most $1 a payment.

```ts
import { httpRpc, NearX402Signer, nearX402Fetch, parseNearKey } from "@nearh/agent-signer";

const signer = await NearX402Signer.connect({
  near: httpRpc("https://rpc.testnet.near.org"),
  contractId: "nearh-c4b-1793824007.testnet",
  key: parseNearKey("nearh-c4b-1793824007.testnet", process.env.AGENT_NEAR_PRIVATE_KEY!),
});
const res = await nearX402Fetch(signer)("http://localhost:4021/weather");
```

## Configure

The CLI reads the repo-root `.env` and `agent/.env` (shape in [`../.env.example`](../.env.example) and [`../../.env.example`](../../.env.example)):

| Variable | Meaning |
|---|---|
| `MANDATE_CONTRACT_ID` | The mandate contract (`.testnet`). The agent key lives on its account |
| `AGENT_NEAR_PRIVATE_KEY` | The agent's function-call key, `ed25519:…` (O1 writes it to `~/.nearh-owner/<contract>/agents/<agent>.json`) |
| `AGENT_EVM_ADDRESS` | Optional; must equal the contract's `evm_address` for the agent |
| `NEAR_RPC` | Default `https://rpc.testnet.near.org`; testnet hosts only |

## Run

```sh
pnpm --filter seller start                                    # SE1 on :4021, SELLER_PAY_TO on the agent's allowlist
pnpm --filter @nearh/agent-signer pay http://localhost:4021/weather
```

The agent EOA needs USDC on Base Sepolia (the float) and no ETH: the facilitator pays the gas.

## Test

```sh
pnpm --filter @nearh/agent-signer test
```

Typecheck plus offline tests. `@x402/fetch` pays the SE1 app (`seller/src/app.ts`, in process on 127.0.0.1) through `NearX402Signer`. Behind it are a fake NEAR RPC and a facilitator stub. The fake NEAR RPC checks the signed tx (ed25519 signature by the agent key, signer and receiver the contract, zero deposit, increasing nonce), applies the C5 checks and builds the EIP-712 digest. It signs with T1's mock MPC key (`contract/tests/integration/src/mpc.rs`: root `0x42…42`, epsilon per (contract, agent)), in the MPC's response format, and returns the `Reservation`. The facilitator stub recovers the signature itself. Cases:
- the payment settles, and `request_signature` carries exactly the seller's requirements;
- a `send_tx` timeout is followed by polling;
- an MPC that never answers hits the deadline, and no payment is sent;
- a failed MPC (`unknown`) sends no payment;
- a `payTo` that is not allowlisted is rejected by the contract;
- a signed `to` that differs from `payTo` is refused;
- a signature from another key is refused;
- a non-USDC domain, Permit2 and other networks are refused before any NEAR call;
- two concurrent payments get distinct, ordered nonces, with the fake answering both access-key queries together and accepting the txs in reverse;
- a too-short seller window is refused before any NEAR call; an authorization signed with too little time left is refused;
- a non-testnet RPC or contract id is refused by `connect`.

The near-workspaces sandbox (T1) is not driven from these tests; they reuse its mock key and response format.

## Live run (2026-11-04)

Contract `nearh-c4b-1793824007.testnet` (C4b, `mpc_contract` `v1.signer-prod.testnet`), agent `agent-1`, EOA `0xB1375297BD48C99F2AaC965B5671ca50D7bb20dB`. SE1 ran locally with `SELLER_PAY_TO=0x5afe000000000000000000000000000000000003`, the one x402 payee on agent-1's allowlist, and the x402.org facilitator. The EOA was first funded with 0.03 test USDC from the S-a spike's EOA (MPC-signed EIP-3009, Base `0x73b7ca2c89aa3bb1e5a57e3ff1f430adc22854cb3fb7b3053f4880eb0956836e`).

```
agent     : agent-1
agent EOA : 0xB1375297BD48C99F2AaC965B5671ca50D7bb20dB
signed    : x402-mw2paqc4-d6b6c983cee78a86 NEAR tx 93ALc2wcWjefsYBNmgfGPqyRkf64HBWY5eaTeT1zGh5C window 1793832014..1793832314
status    : 200 (12.9s)
settlement: {"success":true,"payer":"0xB1375297BD48C99F2AaC965B5671ca50D7bb20dB","transaction":"0x06141c58533fc8d7aa76c343bbc581616fb63e7e9ff2b5a470222c2e8dd8cdf0","network":"eip155:84532"}
body      : {"location":"Berlin","forecast":"light rain","temperatureC":11,"windKph":14,"source":"nearH demo fixture"}
```

The NEAR tx is final with `SuccessValue` (receipts: contract → `v1.signer-prod.testnet` → `on_signature`). The Base tx has status 1, block 54551062. The window is 300 s (`max_validity_secs`). An earlier run of the same command settled too (`x402-mw2p93or-cefe4eadd74e6bf0`, Base `0x77430b0710cac2c6b0a01098822fb133e90b6e0b4b95080557d1270e0c68874e`, 35.4 s); that CLI version did not print the NEAR tx. Explorers: `https://testnet.nearblocks.io/txns/<hash>`, `https://sepolia.basescan.org/tx/<hash>`.

## Not checked

- The per-key serialization and the window checks on testnet (offline only; the live run above predates them).
- Nonce coordination across processes sharing one agent key. Run one signer process per key.
- Driving the near-workspaces sandbox with the real contract wasm from these tests.
- A rejected request on testnet (for example a `payTo` that is not allowlisted). It is covered offline only; the contract's own rejection tests are in C5 and T2.
- A late MPC answer after the client's deadline. The reservation then becomes `signed` on chain, but no payment was sent. `signed` is final, so it counts against the window's budget; A2 can read it with `get_request`.
