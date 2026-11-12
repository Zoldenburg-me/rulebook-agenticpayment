# Relayer live testnet legs (2026-11-03)

The four R1 legs, run with this branch's `relayer/` against NEAR testnet and Base Sepolia. Explorers: `https://testnet.nearblocks.io/txns/<hash>` and `https://sepolia.basescan.org/tx/<hash>`.

## Setup

| What | Id |
|---|---|
| Mandate contract (fresh, built from `main` at 30fac95, wasm sha256 `6739a298…b248d781`) | `r1live.nearh-cc1-1793550206.testnet` |
| Submitter for owner calls, and the `set_relayer` account (requests sweeps) | `r1relayer.nearh-cc1-1793550206.testnet` |
| Relayer EOA (pays `transferWithAuthorization` gas and the fallback top-up) | `0x35480C5ac634ccE6976E18E0Bd605d1c5c7A53af` |
| Sweep destination of every agent (`sweep_config.safe_address`) | `0xbBc0320E02d371a71F18A40B7B15404DF218D880` |

**The sweep destination is not a Safe.** O3's passkey Safe is not wired to this contract yet, so every agent's `safe_address` is the S-a spike's EOA, `derive(nearh-cc1-1793550206.testnet, "nearh-sa-test")`. It is an EOA controlled through Chain Signatures, and it also funded the agent EOAs below, so the test USDC went out and came back.

The owner is the O1 test software P-256 key (outside the repo). Setup used the O1 scripts (`scripts/owner/near`):

| Step | NEAR tx | Owner nonce |
|---|---|---|
| `deploy-contract`: deploy + `new` | `Dk8eNtRnJnqxPLtUoxMB1S813QmpXZjowiSMF9QBfGwh` | |
| `deploy-contract`: delete the deployer's full-access key | `2NyEN2n89MN6BP34EudizPjHjMo1iWU6Cx7BPTNG3Znr` | |
| `add-agent agent-1`: EOA `0x4b05d2f98ff1be125a4c9f99a12a39f50c699d15` | `GnZfBjeTa6AqTGGqRY4rggznc2a5y2e9ueyRgLCto1Sm` | 1 |
| `add-agent agent-fb`: EOA `0xccf5a0156aa776b5c63a8a1c3d9149a23fdb4fd8` | `5BHPwmutc4jmhE4x7NFDrBF3wiz8coFzsgBFaFSjCHCT` | 2 |
| `set-relayer r1relayer.nearh-cc1-1793550206.testnet` | `H18Ju4wsW5T7XRqMdrUHGBKyodgAZkhEymR4C3Yp7rjr` | 3 |
| `add-agent agent-fb2`: EOA `0xff2302056c9f4442dc0edf1acfaf312fd1565701` | `GvBScpr4bNrhktTPjtoZGMt3njxh5eP7etVndhC5SDF8` | 6 |

Each agent EOA matched the MPC's `derived_public_key` view. `agent-1` has the default sweep config (USDC `0x036c…cf7e`, EURe `0x29f3…db85`). **`agent-fb` and `agent-fb2` have `eure_address` set to the USDC address.** We hold no sandbox EURe, so leg (d) runs the EURe raw-transfer path (MPC-signed type-2 `transfer(Safe, amount)` from an EOA with no ETH) on USDC. The relayer code is the same for either token.

Each agent EOA got 0.05 USDC from the S-a EOA, in an MPC-signed transfer (NEAR `sign` tx / Base tx):

| Agent | NEAR `sign` | Base transfer |
|---|---|---|
| agent-1 | `5bApi93boRANUA76iLvahHTV558fvXoQYwHTB7ktphnw` | `0x8d4c5c24a4b719b1df4b83877d6924bb04e970d941550f8b4da82d5c76d28df8` |
| agent-fb | `8LPVbRfTBNiNdPJ6ssTLqVbwXPbw1z8c7t15mLy4Wnqv` | `0xec8e71acc4a1d27bc962ec49f21362d3173896c24c7ab91852a828870b5828e1` |
| agent-fb2 | `9QtpM77vZnUPArEpwR2G9kcku1LDHoEvvCD9FXoojf5x` | `0x4fff5d573ef9d1ef9af5c9533476edb8d935b879f28b7f96bcef2fae4a4aac49` |

Owner calls for legs (a) and (b) were signed with the O1 key into `{ method, args, assertion }` files by a local helper (O1's `buildAssertion` and borsh encoders), then sent with `pnpm owner-call <file>`.

## (a) A relayed owner call lands

| Call | NEAR tx | Result |
|---|---|---|
| `set_mandate agent-1 scripts/owner/near/examples/mandate.json`, owner nonce 4 | `fR6kGVWezLKr2Grr8f2Gt97DRceXeyKgNTxH5hwt4cb` | landed; `get_mandate agent-1` equals the file |
| `add_payee agent-1 x402 0x5afe…0002`, owner nonce 5 (after the fix below) | `ChgtL2wVxdZr3XC2Z98fKQPvBur61VpPirWG6rNf8WFt` | landed; `get_payees agent-1` lists it |

Proves: the relayer's NEAR tx encoding and signing are accepted, the challenge it recomputes equals the one the contract checks, and the submitter (not the owner) pays.

## (b) A tampered owner call is rejected

1. **Changed after signing, refused by the relayer.** An `add_payee agent-1` signed for `0x5afe…0002` with `pay_to` changed to `0xbad0…0bad` in the file: `Error: the assertion does not sign these add_payee args`. No tx was sent and nothing was claimed in the journal.
2. **Passes the relayer, rejected by the contract.** An `add_payee agent-1` signed by the real owner key with `origin: https://evil.example` in `client_data_json` (the relayer does not check the origin; README "Not covered"). Relayed as tx `7pY8ib8sri1xsMNtYkuABLxWUKaqfdbqppitreRbR4My`, it failed with `ERR_ASSERTION_BAD_ORIGIN: client_data_json.origin`. `owner_nonce` stayed 4 and `get_payees agent-1` stayed empty.

**Bug found and fixed in this PR.** After step 2, the owner's next valid call (nonce 5, since the rejected call did not use it up) was refused by the relayer: `already relayed: owner:<contract>:5`. The journal id was the nonce alone, so one rejected call blocked every later owner call until someone deleted the claim by hand. The id now also contains `sha256(authData ‖ sha256(clientDataJSON))`, the message the owner signed: a new call at the same nonce gets its own id, and the same call is still refused, even with a high-s copy of its signature. Tests: `test/owner-call.test.ts` "a call the contract rejected does not block the owner's next call at the same nonce" (fails before the fix) and "the same signed call with a malleated (high-s) signature is still refused by the journal". The nonce-5 call in (a) went through with the fixed relayer.

## (c) A relayed USDC sweep (EIP-3009) lands on Base Sepolia

`pnpm sweep agent-1 usdc 50000 r1live-c-1`: the relayer account requested the sweep, waited for the MPC signature, checked it, and submitted `transferWithAuthorization`.

- Reservation `{ agent-1, relayer r1relayer…, r1live-c-1 }`: `signed`, digest `0x35b5c34c1e81026690a58f92edbeb8b134ce9e8ba20a800738ce18536d10a246`, `from` the agent-1 EOA, `to` the sweep destination, 50000, EIP-3009 nonce `0xaa12af9b…d2fdaedd`.
- Base tx `0x8786a3f2639af6466e639c3cdaf0cc22d7a060f68dc278b4b99e2bf48a443189`: sent from the relayer EOA, status 1, `Transfer` of 0.05 USDC from agent-1's EOA to the sweep destination. The agent EOA held no ETH before or after.

Proves: the contract's EIP-712 digest, the MPC signature (recovering to the agent EOA) and the relayer's calldata are all accepted by Base Sepolia USDC, and the relayer paid the gas.

## (d) Fallback: an agent EOA at 0 ETH gets one tx of gas, then its sweep lands

**First attempt (agent-fb) failed: second bug, fixed in this PR.** `pnpm sweep agent-fb eure 50000 r1live-d-1`: the relayer funded the EOA with exactly `gas_limit × max_fee_per_gas` = 100 000 × 0.011 gwei = 1.1e12 wei (tx `0x832a4b9aa129e73c0ebd772a45eeb5fb0be140d9267a42593c3b2085e0a0f4fa`), then the node refused the signed sweep: `insufficient funds for gas * price + value: have 1100000000000 want 1118214626933`. Base is an OP-stack chain: the sender must also cover the tx's **L1 data fee** (here about 1.8e10 wei). The relayer now asks `GasPriceOracle.getL1Fee` (predeploy `0x4200…000F`) for the exact signed tx and adds twice that fee to the top-up, as margin in case the fee moves (refused above 0.001 ETH). Tests in `test/sweep.test.ts`: the top-up is `gas_limit × max_fee_per_gas + 2 × L1 fee`, the quote is for the exact signed tx, the gap case includes it, and an L1 fee over the cap funds nothing. Three tests fail without the fix.

The broadcast funding claim stays in the journal (README "Clearing a claim by hand"), so agent-fb's fallback sweep was not retried. Its 0.05 USDC was swept back by the relayer through EIP-3009 instead: `r1live-d1-recover`, Base tx `0x410bd1c22b32b4b142dd0dde63549a0c2e7cd279d2460d4af1318addfe894af4`. Its EOA keeps the 1.1e12 wei.

**Rerun with the fix (agent-fb2, a fresh EOA at 0 ETH).** `pnpm sweep agent-fb2 eure 50000 r1live-d-2`:

| Step | Base tx | Details |
|---|---|---|
| ETH balance of `0xff23…5701` before | | 0 |
| Relayer → agent EOA: gas for one tx | `0x4af3e2907428551549d434553f5a7d06876b551c61495e1c4047cfa10dcb7c6b` | 1 137 658 613 002 wei = 1.1e12 + 2 × 1.88e10 L1 fee |
| Agent EOA → USDC `transfer(destination, 50000)`, the MPC-signed tx byte for byte (nonce 0, gas limit 100 000, max fee 0.011 gwei) | `0x28ea95face005a96654566ecd298c5c60850761475bf6a7cb303015a54e35ab2` | status 1, gas used 40 247, L1 fee 1.23e10 wei, `Transfer` of 0.05 USDC to the destination |
| ETH balance after | | 883 876 421 411 wei (the tx paid base + priority fee, not the max fee; README) |

Reservation `{ agent-fb2, relayer r1relayer…, r1live-d-2 }`: `signed`, `eip1559_tx`, digest `0x0b87af07a7ccc0edad11487e06899df4f2f9f08a13c5d2183968cd1137661f10`.

Proves: the contract-built type-2 tx and its MPC signature are a valid Base Sepolia tx from the agent EOA, and the relayer funds one tx (gas plus L1 fee) and no more.

## State at the end

- Contract: `owner_nonce` 6, `relayer` `r1relayer.nearh-cc1-1793550206.testnet`, no full-access key.
- USDC: the three agent EOAs hold 0; the sweep destination got back the 0.15 USDC it sent out.
- ETH: agent-1 0; agent-fb 1.1e12 wei; agent-fb2 8.8e11 wei. Relayer EOA about 0.001996 ETH.

## Not covered

- Real EURe: leg (d) used USDC as the "EURe" token. The EURe-specific part, the `balanceOf` pre-check on `sweep_config.eure_address`, ran against USDC.
- A real Safe as the sweep destination (O3). Here it is an EOA.
- The NEAR tx hashes of the three relayer `sweep` requests: `pnpm sweep` does not print them and the explorer API had not indexed the account when this was written. The reservations above are readable with `get_request`.
- The helpers that signed owner-call files and moved USDC from the S-a EOA are not in the repo.
