# Spike S-g: Does EURe (Monerium) on Base Sepolia support EIP-3009?

**Checked:** 01.11.2026 (Europe/Berlin), by a reviewer

## Question
Does Monerium EURe on Base Sepolia implement EIP-3009 `transferWithAuthorization` (needed by x402's `exact` EVM scheme)?

## Answer
**NO.** EURe does not implement EIP-3009, on Base Sepolia or on Base mainnet. It does implement **EIP-2612 `permit`** (plus EIP-712 `DOMAIN_SEPARATOR`, `nonces`, `eip712Domain`/EIP-5267).

## Addresses
| Network | Proxy (EURe) | Implementation | Notes |
|---|---|---|---|
| Base Sepolia | [0x29F37F6adCa168B79B8d9567eab9BE3fBF21db85](https://base-sepolia.blockscout.com/address/0x29F37F6adCa168B79B8d9567eab9BE3fBF21db85) ([basescan](https://sepolia.basescan.org/address/0x29F37F6adCa168B79B8d9567eab9BE3fBF21db85)) | [0x7B3279AF55e9eAA5b813aC2e8F864cCbf0AAb224](https://base-sepolia.blockscout.com/address/0x7B3279AF55e9eAA5b813aC2e8F864cCbf0AAb224) (verified, "Token") | Probable Monerium sandbox token: 267 holders, about 1.1 billion EURe supply |
| Base Sepolia (2nd) | [0xbf6e2966A9C3D99C9E4D069E04f7Bdb9C8aa762C](https://base-sepolia.blockscout.com/address/0xbf6e2966A9C3D99C9E4D069E04f7Bdb9C8aa762C) | 0x89aB57C789B8a9eA44296cC63b0071bF73B22C1F (verified, "Token") | Same address as mainnet, 4 holders, 5,894 EURe. Rarely used. |
| Base mainnet | [0xbf6e2966A9C3D99C9E4D069E04f7Bdb9C8aa762C](https://basescan.org/address/0xbf6e2966a9c3d99c9e4d069e04f7bdb9c8aa762c) | [0x89aB57C789B8a9eA44296cC63b0071bF73B22C1F](https://basescan.org/address/0x89ab57c789b8a9ea44296cc63b0071bf73b22c1f) | Labelled "Monerium: EURe Token" on BaseScan |
| (ref) Ethereum Sepolia | 0x67b34b93ac295c985e856E5B8A20D83026b580Eb | — | No code at this address on Base Sepolia |

All of these are ERC1967 (UUPS) proxies. The implementation was read from the EIP-1967 slot `0x3608…2bbc` with `eth_getStorageAt`. 18 decimals, name "Monerium EURe", symbol "EURe".
TODO: confirm with Monerium's sandbox docs which Base Sepolia address their sandbox mints to. 0x29F3… is the likely one, judging by usage.

## Evidence
1. **Verified ABI (Blockscout) of both implementations** lists these functions: ADMIN_ROLE, DOMAIN_SEPARATOR, allowance, approve, balanceOf, burn, eip712Domain, getPermitDigest, mint, nonces, **permit**, recover, setValidator, transfer, transferFrom, upgradeToAndCall, validator, ... It has **no** `transferWithAuthorization`, `receiveWithAuthorization`, `authorizationState` or `cancelAuthorization`.
2. **Bytecode selector scan** (looked for `PUSH4 <selector>` in the implementation runtime code) on sepolia.base.org and mainnet.base.org gave identical results on all three deployments:
   - transferWithAuthorization `0xe3ee160e`: absent
   - receiveWithAuthorization `0xef55bec6`: absent
   - authorizationState `0xe94a0102`: absent
   - cancelAuthorization `0x5a049a70`: absent
   - permit `0xd505accf`: present
   - DOMAIN_SEPARATOR `0x3644e515`: present
   - nonces `0x7ecebe00`: present
   - eip712Domain `0x84b0196e`: present
3. **Live eth_call:**
   - `authorizationState(0,0)` reverts.
   - `DOMAIN_SEPARATOR()` returns on Base Sepolia 0x29F3… (`0xba0326c4…1555`), Base Sepolia 0xbf6e… (`0xdde0d74f…2e7d`) and Base mainnet (`0x697897ef…a23c`).
   - `nonces(0)` returns 0.
4. Mainnet and testnet run the same implementation code (same 13,328-byte runtime and the same ABI), so **mainnet does not differ**.
5. Extra: the token has a `validator` hook (Monerium compliance/blacklist checks on transfers). Transfers to or from blocked addresses can revert, and the facilitator needs to handle that.

## Implications for x402 / SEPA plan
- The x402 `exact` scheme on EVM uses EIP-3009 `transferWithAuthorization` (that's why USDC/EURC work out of the box). **EURe cannot be used with stock x402 `exact` facilitators.**
- Options:
  1. **Permit-based flow:** the payer signs an EIP-2612 `permit(owner, facilitator/spender, value, deadline)`, and the facilitator calls `permit` then `transferFrom`. This needs a custom facilitator or scheme. Check whether the current x402 spec/SDK has a permit or Permit2 variant. It also loses EIP-3009's random-nonce and replay semantics, because permit uses sequential nonces, so concurrent payments from one payer can collide.
  2. **Permit2 (Uniswap)** with a one-time approve, then signature transfers. Works for any ERC-20, but needs one on-chain approve per user.
  3. **Settle x402 in EURC** (Circle, implements EIP-3009; on Base Sepolia, for example 0x808456652fdb597867f38412077A9182bf77359F). Use EURe/Monerium only for the SEPA on-ramp and off-ramp, with a swap or treasury bridge in between.
- Recommendation: for the hackathon demo, use **EURC for x402 payments** or build a **permit+transferFrom custom facilitator** for EURe. Don't assume EIP-3009 for EURe.

## Sources
- Blockscout Base Sepolia API: `/api/v2/smart-contracts/{addr}`, `/api/v2/tokens?q=EURe`, `/api/v2/search?q=Monerium`
- RPC: https://sepolia.base.org, https://mainnet.base.org (eth_getCode, eth_getStorageAt, eth_call)
- BaseScan mainnet label: https://basescan.org/address/0xbf6e2966a9c3d99c9e4d069e04f7bdb9c8aa762c
- EURe contracts list: https://pharos.watch/stablecoin/eure-monerium/
- EIP-3009: https://eips.ethereum.org/EIPS/eip-3009 · EIP-2612: https://eips.ethereum.org/EIPS/eip-2612
- Check script: /workspace/chk.py


## Lead note: what this means for PLAN.md
In PLAN.md, x402 settles in **USDC** (EIP-3009), not EURe, so the x402 path is unaffected. EURe is only moved by Monerium payouts (shape 3, a signed text order, not a token transfer) and by the **sweep** (shape 1). So the S-g fallback applies: **the EURe sweep is a contract-built raw `transfer`**, with the relayer funding that one tx's gas (C4, R1). Never `permit` (PLAN.md, shape 1).

Reproduce: the selector scan needs only an RPC. `cast code 0x7B3279AF55e9eAA5b813aC2e8F864cCbf0AAb224 --rpc-url https://sepolia.base.org | grep -c e3ee160e` gives 0. (The reviewer's helper script is not in this repo.)

Source: the reviewer's report, committed verbatim above this note.
