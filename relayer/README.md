# Relayer (R1)

Submits what others signed and pays the gas. It never changes what it relays: before each send it checks the payload against the signature, and it refuses anything that does not match.

| Path | Input | What the relayer checks before sending | Sends |
|---|---|---|---|
| **Owner call** on NEAR | `{ method, args, assertion }`, signed by the owner (O1, DB1) | `method` is an owner method and `args` has exactly its fields; the challenge in `client_data_json` equals `sha256("zold-mandate-v1" ‖ contract ‖ network ‖ method ‖ borsh(args) ‖ owner_nonce ‖ expires_at)` computed from those args (docs/interfaces.md §2); the P-256 signature verifies against the owner key in `get_config`; the nonce is unused and the assertion has not expired | `method({...args, assertion})` from the submitter account. Afterwards it waits until `owner_nonce` reaches the assertion's nonce |
| **USDC sweep** on Base Sepolia | the reservation key `{ agent, caller, request_id }` | It reads the reservation from `get_request` and the destination from `get_agent`: shape `sweep`, signed; the EIP-712 digest of the payload equals the stored digest; the signature recovers to the agent EOA; `from` is the agent EOA, `to` is its Safe, `asset` is its USDC; `valid_after` < now < `valid_before`; `authorizationState` is unused | `transferWithAuthorization` exactly as signed, from the relayer EOA. Afterwards: the EOA → Safe `Transfer` log |
| **EURe sweep** (raw-transfer fallback) | the reservation key | As above for the type-2 tx: its hash equals the stored digest and recovers to the agent EOA; `to` is EURe, `value` 0, `data` is `transfer(Safe, amount)` with `amount` > 0; the agent EOA's EURe `balanceOf` is at least `amount` (otherwise the tx would revert and burn the top-up); gas limit and fee within the contract's caps; the agent EOA's next nonce is the tx's; the base fee is not above its max fee | First, if needed, ETH to the agent EOA: `gas_limit × max_fee_per_gas` plus twice the tx's L1 data fee (Base is an OP-stack chain; the fee is quoted by `GasPriceOracle.getL1Fee` for the exact signed tx), less what the EOA already holds (at most 150 000 × 100 gwei = 0.015 ETH, plus 2 × at most 0.001 ETH of L1 fee). Then the MPC-signed tx, byte for byte. Afterwards: the `Transfer` log. If the sweep fails after the top-up, the error names the funding tx |

`pnpm sweep` can also **request** a sweep as the relayer (`set_relayer` names it), with `assertion: None`. For EURe it fills `evm_tx` from Base: the agent EOA's pending nonce, fees of `2 × base fee + priority fee`, and a fixed gas limit of 100 000 (not an estimate: the EOA has no ETH yet, and a node may refuse to estimate for it). Gas or fees over the contract's caps, an amount of 0, and an amount above the EOA's EURe balance are refused before the NEAR call.

The top-up is sized at `max_fee_per_gas`, but the tx pays only `base fee + priority fee`, so a little ETH stays on the agent EOA after each EURe sweep. That is expected: the next top-up subtracts the EOA's balance, so it is never paid twice.

**Once only.** Each item is claimed in a journal directory (`RELAYER_JOURNAL`, mode 700; one mode-600 file per id, created exclusively, so two relayer processes cannot both claim it) before its tx goes out and is never released, even on error: a tx that may have been broadcast is checked by hand, not resent. Ids: `owner:<contract>:<owner_nonce>:<sha256 of the signed authData ‖ sha256(clientDataJSON)>` (a call the contract rejects leaves the nonce unused, so the owner's next call at that nonce gets a new id; a malleated signature on the same call does not), `usdc-sweep:<eoa>:<nonce>`, `eure-gas:<eoa>:<tx nonce>`, `eure-sweep:<eoa>:<tx nonce>`. The chain checks above (nonce used, authorization used, EOA nonce moved, EOA already funded) refuse a resend even with a fresh journal.

**Clearing a claim by hand.** A send can fail after its claim but before anything is broadcast (an RPC error, an underpriced tx). The item then stays refused as `already relayed`. To retry it, first confirm on the explorer that no tx went out (for an owner call, that `owner_nonce` has not moved; for a sweep, that the EOA nonce or `authorizationState` has not moved), then delete that id's file: `rm "$RELAYER_JOURNAL/$(printf %s '<id>' | shasum -a 256 | cut -d' ' -f1)"`. Never delete a claim for a tx that may have been broadcast.

**Testnet only.** `NEAR_RPC` must be an https testnet host (same allowlist as O1), accounts must be `.testnet`, and every Base send first checks `eth_chainId` = 84532.

## Setup

Node ≥ 22.18 (runs the `.ts` files directly). Dependencies: `@noble/curves` and `@noble/hashes` only. NEAR txs are built and signed here (borsh + ed25519) and sent with `send_tx`; the access-key nonce is read at `optimistic` and never reused within a process; Base txs are EIP-1559, signed with secp256k1. It reuses O1's borsh encoders and challenge through the workspace dependency `@nearh/owner-near` (`scripts/owner/near/src`): a change to O1's borsh layout or challenge changes what the relayer verifies, and the relayer's tests run against it.

```sh
pnpm install && cd relayer
cp .env.example .env   # fill it in; never commit it
```

| Command | What it does |
|---|---|
| `pnpm owner-call <signed-call.json>` | Relays one owner-signed call |
| `pnpm sweep <agent> <usdc\|eure> <amount in base units> <request_id>` | Requests a sweep as the relayer, waits for the signature, submits it |
| `pnpm submit-sweep <request-key.json>` | Submits an already signed sweep requested by the agent, the owner or the relayer |
| `pnpm typecheck` | `tsc --noEmit` over `src/` and `test/` |
| `pnpm test` | Type-check, then the unit tests (below) |

## Tests

`pnpm test` runs `pnpm typecheck` first, then the tests offline against fake NEAR and Base RPCs (`test/fakes.ts`), which record every tx and `eth_call` sent and keep ERC-20 balances per token.
- `test/owner-call.test.ts`: a signed `set_relayer` goes out once with exactly `{...args, assertion}`, signed by the submitter's ed25519 key; a second relay sends nothing. **Tampered calls are refused with no tx sent**: changed arg, method, nonce or expiry, an extra arg, a flipped signature byte, changed authenticator data. Also refused: another key's signature, a used nonce, an expired assertion, a wallet-mode contract, a non-owner method. A call the contract rejects is reported as rejected and not retried, but it does not block the owner's next call at the same nonce, while a high-s copy of the same signature is still refused; the file journal stops a resend after a restart, and two journals on one directory cannot both claim an id. Back-to-back calls use increasing NEAR nonces when the node still reports the old one. The `sweep` and `resolve_reservation` borsh layouts sign and verify.
- `test/sweep.test.ts`: the EIP-3009 digest, signature recovery and EURe tx digest equal the vectors in docs/interfaces.md §4. **USDC:** submitted once, exactly the signed authorization; a second run is refused by the journal and, with a fresh journal, by `authorizationState`. A payload changed after signing, another signer, a destination other than the Safe, another token, an expired, pending or non-sweep reservation, and a non-Base-Sepolia RPC all send nothing. `valid_after` not yet passed sends nothing. **EURe:** at zero ETH the top-up is exactly `gas_limit × max_fee_per_gas` plus twice the L1 fee the fake GasPriceOracle quotes for the exact signed tx, and an L1 fee over 0.001 ETH funds nothing; then the signed tx goes out unchanged; a partly funded EOA gets only the gap and a funded one nothing; a crash after funding does not fund again; once the EOA nonce has moved nothing is sent. **The top-up is capped at one tx**: gas or fee over the contract's caps, a transfer to another address, another token, ETH value, a changed payload, a base fee above the max fee, an amount of 0, a `v` other than 27/28, and an EURe balance below the amount all fund nothing and send nothing; USDC in the EOA does not count, since the balance is read from `sweep_config.eure_address`. When the sweep fails after funding, the error names the funding tx. `requestSweep` sends one `sweep` call with `evm_tx` from Base and refuses fees over the cap, an amount of 0 and an amount above the EOA's EURe balance.

The EIP-1559 signing was also checked once, outside the repo, against viem's `signTransaction` (byte-equal signed txs).

## Testnet run (2026-11-03)

- NEAR: a `set_relayer` with a forged assertion, sent with the relayer's own tx code (bypassing its checks) from `nearh-cc1-1793550206.testnet` to `nearh-o1b-1793574016.testnet`, was **rejected by the contract**: `ERR_ASSERTION_BAD_CHALLENGE`, tx `FYQX7GtPvipM5V56q2H7XSbAXsyeyCARa8kTCYB93Sxc`. `owner_nonce` stayed 2 and `relayer` stayed `null`. This also shows the NEAR tx encoding and signing are accepted by testnet.

## R1b testnet run against C4b (2026-11-04)

`relayer/` at `main` aa41885 against the C4b contract `nearh-c4b-1793824007.testnet` (scripts/owner/near/README.md, C4b redeploy). The submitter and the `set_relayer` account are both `nearh-c4b-sub-1793824007.testnet`; the relayer EOA is `0x35480C5ac634ccE6976E18E0Bd605d1c5c7A53af`. agent-1's EOA is `0xb1375297bd48c99f2aac965b5671ca50d7bb20db` and its `sweep_config.safe_address` is the owner's passkey Safe `0xaa9b16Bcb70292BA34d4284Ba1A118566Ef9ebB9` (counterfactual). Owner calls were signed with the O1 software owner key into `{ method, args, assertion }` files by a local helper (outside the repo), then sent with `pnpm owner-call <file>`. Explorers: `https://testnet.nearblocks.io/txns/<hash>`, `https://sepolia.basescan.org/tx/<hash>`.

| Leg | Result | Tx |
|---|---|---|
| (1) Relayed owner call lands | `add_payee agent-1 x402 0x5afe…0003`, owner nonce 4: landed; `get_payees agent-1` lists it | NEAR `BSBPmaBb2UaU7RfHzzootrc4NJUCYQyHojVFdBrT1Bdx` |
| (2) Tampered owner call rejected | An `add_payee` signed by the owner key with `origin: https://evil.example` in `client_data_json` passes the relayer (it does not check the origin) and **the contract rejects it**: `ERR_ASSERTION_BAD_ORIGIN: client_data_json.origin`. `owner_nonce` stayed 4 and `get_payees` still lists only `…0003`. Also, an `add_payee` with `pay_to` changed after signing was refused by the relayer (`the assertion does not sign these add_payee args`), no tx sent | NEAR `FZEuCcu2vQp3mgKBBnnfyatkKQYFBu2FPJqbGNSfz6Sp` |
| (3) USDC EIP-3009 sweep into the Safe | `pnpm sweep agent-1 usdc 50000 r1b-3-1`: the relayer account requested the sweep, the MPC signed, the relayer submitted `transferWithAuthorization` from its EOA. Status 1, `AuthorizationUsed` and `Transfer` of 0.05 USDC from agent-1's EOA to the Safe; the Safe's USDC balance is 0.05. agent-1's EOA held 0 ETH throughout | Base `0x009bc4f41751ff829b3224eca2624a18cb0c60e423ff5c0a6f456ab0141bdf7b` |
| (4) EURe fallback at 0 ETH | **Blocked**: no EOA we control holds EURe (`0x29f3…db85`): agent-1's EOA, the relayer EOA and the S-a spike's EOA all read `balanceOf` 0. Getting sandbox EURe needs the agent EOA linked to a Monerium sandbox profile, which needs a message signature the contract does not produce. The relayer would refuse the sweep before funding (EURe balance below the amount). The same code path ran on USDC in [LIVE.md](LIVE.md) (d) | none |

agent-1's 0.05 USDC came from the S-a spike's EOA in one MPC-signed transfer: NEAR `sign` `424CPKbmvYp1MPeUJq9UbvvvCcJg9FkVqCvsfgC7gtBm`, Base `0xcb8dadeed600c4d371a7fa81ee642776a644f23091fccec29e5889b5bc96202f`. A first bad-origin relay at owner nonce 5 was also rejected by the contract, but its hash was cut from the output; the leg (2) row is the rerun, a new signed call at the same nonce.

## Not covered

- The live legs are recorded in [LIVE.md](LIVE.md); the fallback leg there moved USDC through the raw-transfer path, not EURe.
- The EURe pre-check reads `balanceOf`; it does not simulate the transfer, so a paused token still fails only on chain.
- No HTTP endpoint: the dashboard (DB1) hands a signed call to `pnpm owner-call` or calls `relayOwnerCall` directly.
- The relayer does not re-check the rest of `assert_owner` (origin, rpIdHash, user presence, TTL cap); the contract does, and a call that fails there is reported as rejected.
- Node strips the types at run time; `tsc` only runs as `pnpm typecheck` (part of `pnpm test`).
