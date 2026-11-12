# S-c: x402 via signer-prod — PASS

Build an EIP-3009 `transferWithAuthorization` (USDC, Base Sepolia) for the S-a derived EOA, have `v1.signer-prod.testnet` sign its EIP-712 digest, and settle it through the x402.org facilitator (x402 v2, scheme `exact`, network `eip155:84532`).

**Status:** PASS. The facilitator's `/settle` put the MPC-signed authorization on chain: Base Sepolia tx [`0x04717e9e60de0408c1f41ac0a01703710b819fc8a43428dc2f31244c85cee79e`](https://sepolia.basescan.org/tx/0x04717e9e60de0408c1f41ac0a01703710b819fc8a43428dc2f31244c85cee79e) (block 53168628, status success), 0.01 USDC from the agent EOA to our own payee EOA. The fallback submitter was not needed.

- Agent EOA: `0xbBc0320E02d371a71F18A40B7B15404DF218D880` (path `nearh-sa-test`), funded with 20 test USDC, 0 ETH.
- payTo: `0xEea5E3Bcc1E058aef9586a1c5C4cADc9CFDbC74F` (path `nearh-sc-payee`, same NEAR account), so the test USDC stays with us.

## Run it

Use the same NEAR testnet account and keychain setup as S-a (`spikes/chainsig/RESULT.md`). Then:

```sh
cd spikes/x402
pnpm install --ignore-workspace
NEAR_ACCOUNT_ID=<name>.testnet node x402.mjs
```

The S-a account here is `nearh-cc1-1793550206.testnet`. Its derived EOA for path `nearh-sa-test` is the address above. The script exits with code 2 and prints the funding hint if the balance is below `AMOUNT`, before it spends an MPC call. `DRY_RUN=1` signs and calls `/verify` only. Optional env: `CHAINSIG_PATH` (default `nearh-sa-test`), `PAYEE_PATH` (default `nearh-sc-payee`; `payTo` is our own derived address for that path), `AMOUNT` (default `10000` = 0.01 USDC), `FACILITATOR_URL` (default `https://x402.org/facilitator`), `MPC_CONTRACT` (must end in `.testnet`), `NEAR_RPC`, `BASE_SEPOLIA_RPC`. The script never prints the key.

## Recorded settled run (2026-11-01)

```
mpc contract      : v1.signer-prod.testnet
from (agent EOA)  : 0xbBc0320E02d371a71F18A40B7B15404DF218D880 (nearh-sa-test)
payTo             : 0xEea5E3Bcc1E058aef9586a1c5C4cADc9CFDbC74F (nearh-sc-payee)
usdc balance      : 20000000
authorization     : {"from":"0xbBc0320E02d371a71F18A40B7B15404DF218D880","to":"0xEea5E3Bcc1E058aef9586a1c5C4cADc9CFDbC74F","value":"10000","validAfter":"1793555521","validBefore":"1793555881","nonce":"0x1fc1b8c54141f9488ae59cb01f3500d4b02062c27a2fc5839004370c81a716c7"}
domain separator  : 0x71f17a3b2ff373b803d70a5a07c046c1a2bc8e89c09ef722fcb047abe94c9818 (= on-chain DOMAIN_SEPARATOR)
struct hash       : 0x4e9fdad91dbc78a21d2d7038267e7065ce0a9d50489740ab9261c964d3a6e873
eip-712 digest    : 0x720dffe2a39e40e2513eaf70b1d55c4b0b4667c34d2812e2113bebc6834cb5ed
near tx           : FRsN6TSatnRCx3Dk5QiakVr4PkGCvNtnaFvMVYEgucmF (11.8s)
signature (65B)   : 0xc36c8c02881c3a55099ebaf50a5aabc502c9195659ec6b69e3376bacaa84d3833b537f6c4f6d41969f2585b99c74638ad0d4c24c45fcd2f143a94d9825e202631c
recovered = from  : true
facilitator /verify: 200 {"isValid":true,"payer":"0xbBc0320E02d371a71F18A40B7B15404DF218D880"}
facilitator /settle: 200 {"success":true,"transaction":"0x04717e9e60de0408c1f41ac0a01703710b819fc8a43428dc2f31244c85cee79e","network":"eip155:84532","payer":"0xbBc0320E02d371a71F18A40B7B15404DF218D880"}
base sepolia tx   : 0x04717e9e60de0408c1f41ac0a01703710b819fc8a43428dc2f31244c85cee79e status=success block=53168628
payTo balance     : 10000
PASS
```

The settle tx was sent by the facilitator's EOA `0xd407e409e34e0b9afb99ecceb609bdbcd5e7f1bf` to the USDC contract (gas used 102876, 2 logs). The agent EOA held 0 ETH at settle time; the facilitator paid gas.

The earlier dry run (before funding) got `/verify` → `isValid:false, invalid_exact_evm_insufficient_balance` for a signature over a different nonce. Unverified: we assume the signature had already passed validation then, but that depends on the facilitator's check order, which we did not test.

## For C5 (digest to match)

The digest above is the standard EIP-712 hash, `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`:

- Domain: `{name: "USDC", version: "2", chainId: 84532, verifyingContract: 0x036CbD53842c5426634e7929541eC2318f3dCF7e}`. The separator above equals the token's on-chain `DOMAIN_SEPARATOR()`.
- Type: `TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)`.
- Message: the `authorization` line above. C5 can rebuild the digest from these exact fields and assert it equals `0x720dffe2a39e40e2513eaf70b1d55c4b0b4667c34d2812e2113bebc6834cb5ed` (struct hash `0x4e9fdad9…e873`).
- **Validity window.** This run used `validAfter = now - 60` and `validBefore = now + 300`, so `validBefore - validAfter` = 1793555881 - 1793555521 = **360 s**. That exceeds PLAN.md's shape 2 cap (`max_validity_secs` ≤ 300 s); the facilitator accepted it anyway (and `maxTimeoutSeconds` was 300). C5 must enforce `validBefore - validAfter ≤ max_validity_secs`, so its own validity check would reject this recorded vector. C5's "hash matches the S-c tx" test must therefore call the digest builder directly with the recorded fields above, bypassing the validity check. The script's defaults are now `validAfter = now - 30`, `validBefore = now + 240` (270 s) for anyone re-running it; the recorded run predates that change.
- **What C5 changes.** The spike uses a random nonce. A C5-shaped authorization changes the `nonce` (to `keccak(agent, caller, shape, request_id)`, D3) and the validity window (within `max_validity_secs`, using C5's own clock skew from NEAR block time). `to` and `value` come from the contract's own checks (allowlisted `payTo`, cap), not from the agent's request as-is.

## What we learned

- **x402.org is on v2.** `/supported` lists `{x402Version: 2, scheme: "exact", network: "eip155:84532"}` (v1 `base-sepolia` is still listed). The `/verify` and `/settle` body is `{x402Version: 2, paymentPayload: {x402Version, resource, accepted, payload: {signature, authorization}}, paymentRequirements: {scheme, network, amount, asset, payTo, maxTimeoutSeconds, extra: {name: "USDC", version: "2"}}}`, with all authorization numbers as decimal strings.
- **MPC output drops straight in.** Same conversion as S-a (`r = big_r x`, `s`, `v = 27 + recovery_id`; never the `big_r` prefix); the facilitator accepts the 65-byte `r‖s‖v`. This run had `recovery_id` 1 (`v = 0x1c`).
- **Order of checks (unverified).** Unfunded, the facilitator reports `insufficient_balance` from its simulation. We assume a bad signature would show up as a different reason, but that depends on the facilitator's check order, which we did not test. Funded, `/verify` and `/settle` both succeed and USDC accepts the signature on chain.
- **Gas.** The agent EOA needs no ETH: the facilitator sent and paid for the settle tx. The PLAN.md assumption holds.
- **Latency.** The MPC `sign` call took 11.8 s; verify, settle and the receipt added a few seconds.

## Not checked

- Non-interactive funding: the Coinbase CDP Faucet API and Circle's `POST /v1/faucet/drips` both need API keys we don't have; `faucet.circle.com` has a captcha, so a human funded the EOA.
- The `@zold/accept` `viem/submitter.ts` fallback: not exercised, because `/settle` worked.
- Replay: we did not resubmit the same authorization to see the facilitator's error for a used nonce.
- Calling `sign` from the contract (C3), as in S-a, and the contract-derived nonce (D3).
