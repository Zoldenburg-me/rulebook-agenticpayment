# PP-S2: PYUSD x402 on Ethereum Sepolia: PASS

This spike builds an EIP-3009 `transferWithAuthorization` for PYUSD on Ethereum Sepolia, from the S-a derived EOA. `v1.signer-prod.testnet` signs its EIP-712 digest. The spike then settles it twice: once with our own submitter (the team testnet funder pays gas, standing in for a self-hosted facilitator), and once as a second payment through the `@x402/evm` 2.30.0 facilitator `verify`/`settle`, with the funder as the facilitator signer.

**Status: PASS.** Both paths put an MPC-signed authorization on chain and moved 0.01 PYUSD from the agent EOA to payTo. The agent EOA holds 0 ETH.

**Main finding:** PYUSD does **not revert** when an authorization is reused. It emits `AuthorizationAlreadyUsed(address,bytes32)`, returns success and moves no tokens. A tx's `status == success` therefore does not prove the payment happened. See [Replay](#replay-pyusd-does-not-revert).

- Token: PYUSD `0xCaC524BcA292aaade2DF8A05cC58F0a65B1B3bB9`, chain id 11155111, 6 decimals. It sits behind a zos-style proxy; the implementation is `0xc804f2e8ae84f6cfa01d9d33ef107323bf0f9a59` (slot `keccak("org.zeppelinos.proxy.implementation")`, not EIP-1967).
- Agent EOA: `0xbBc0320E02d371a71F18A40B7B15404DF218D880` (path `nearh-sa-test`, predecessor `nearh-cc1-1793550206.testnet`), 0 ETH.
- payTo: `0xEea5E3Bcc1E058aef9586a1c5C4cADc9CFDbC74F` (path `nearh-sc-payee`).
- Submitter / facilitator signer: team testnet funder `0x3D958091Ec4Da82b55193F23e8A1d190B21ba62e`.

## Transactions (Ethereum Sepolia)

| What | Tx | Result |
|---|---|---|
| Step 1: funder → agent EOA, 20 PYUSD (ERC-20 `transfer`) | [`0xc0f718df…7d68`](https://sepolia.etherscan.io/tx/0xc0f718df79a8b8928136ce3e2f76f11a88d7d59b307bda40b1943694839f7d68) | success, gas 155296 |
| Run 1, own submitter | [`0x02da53ee…0cce`](https://sepolia.etherscan.io/tx/0x02da53eece3f70032de1f9c9f07c9b337d37a218ff63cdb242a97fc48c190cce) | success, block 12065493, payTo +10000 |
| Run 1, `@x402/evm` settle | [`0xab90a0a3…6d94`](https://sepolia.etherscan.io/tx/0xab90a0a33ffe6b473ff633228d8c14a00c8deb20f025a45295b75df6f58a6d94) | success, block 12065495, payTo +10000 |
| Run 2 (recorded below), own submitter | [`0x07a0bc18…b344`](https://sepolia.etherscan.io/tx/0x07a0bc1842fd91473862c5c21cf86db765e4d07416089442275a18be5fecb344) | success, block 12065509, payTo +10000 |
| Run 2, replay of the same authorization, own submitter | [`0x0547bd1d…b0bf`](https://sepolia.etherscan.io/tx/0x0547bd1d39b41d100fdc89caef7626a66e4ea70c4008d4c8524f4e93cbdbb0bf) | **success**, gas 33688, only `AuthorizationAlreadyUsed`, payTo +0 |
| Run 2, `@x402/evm` settle | [`0x57a63ad4…fea4`](https://sepolia.etherscan.io/tx/0x57a63ad4bace5f28bd05d26691d27757cea474719a83ae3df74a1a5bbe08fea4) | success, block 12065512, payTo +10000 |
| Run 2, `@x402/evm` replay settle | [`0x6a18b6ba…bb26`](https://sepolia.etherscan.io/tx/0x6a18b6ba2bdc62d5109ff725987da4c780db2c6f8cc894d4783ae2a9b2a1bb26) | tx success, only `AuthorizationAlreadyUsed`, payTo +0; facilitator returns `success:false, invalid_exact_evm_transfer_event_mismatch` |

Run 1 had the replay check only as `eth_call`; Run 2 also broadcast the replays. The agent EOA went from 20 PYUSD to 19.96 PYUSD (4 × 0.01) and payTo ended at 0.04 PYUSD.

## Run it

Use the same NEAR testnet account and keychain setup as S-a (`spikes/chainsig/RESULT.md`). The funder key must be in `~/.config/nearh/testnet-funder.key` (0600, `0x…` hex); the script reads it at runtime and never prints it. Tested with Node 26.7.0.

```sh
cd spikes/pyusd-x402
pnpm install --ignore-workspace
NEAR_ACCOUNT_ID=nearh-cc1-1793550206.testnet node pyusd-x402.mjs
```

If the agent EOA holds less than `2 × AMOUNT`, the funder first sends it 20 PYUSD. Each run makes 2 MPC `sign` calls and spends about 0.0016 NEAR. It sends 4 Sepolia txs (2 settles, 2 replays), all paid by the funder. Optional env: `SKIP_X402=1` (own submitter only), `AMOUNT` (default `10000` = 0.01 PYUSD), `CHAINSIG_PATH`, `PAYEE_PATH`, `FUNDER_KEY_FILE`, `MPC_CONTRACT` (must end in `.testnet`), `NEAR_RPC`, `SEPOLIA_RPC` (default `https://ethereum-sepolia-rpc.publicnode.com`; `sepolia.drpc.org` now answers "chain is not available on free plan").

## Recorded run (2026-11-04, run 2)

```
mpc contract      : v1.signer-prod.testnet
from (agent EOA)  : 0xbBc0320E02d371a71F18A40B7B15404DF218D880 (nearh-sa-test)
payTo             : 0xEea5E3Bcc1E058aef9586a1c5C4cADc9CFDbC74F (nearh-sc-payee)
submitter (funder): 0x3D958091Ec4Da82b55193F23e8A1d190B21ba62e
domain separator  : 0x299bc5624e503ead448a8620a85ecf64a3be318a90c1a987563385c582d4e6cd (= on-chain DOMAIN_SEPARATOR)
agent pyusd / eth : 19980000 / 0

[own] authorization : {"from":"0xbBc0320E02d371a71F18A40B7B15404DF218D880","to":"0xEea5E3Bcc1E058aef9586a1c5C4cADc9CFDbC74F","value":"10000","validAfter":"1793832722","validBefore":"1793832992","nonce":"0xcca2cda195b032738e79e9df1381c1bf11a789b84c08dcd2d8aa1d360ed410a6"}
[own] struct hash   : 0x9bc908640d226a8ecd5cc95ae9b05c268d85dbbb94cb2dda90d90141329a2bdb
[own] eip-712 digest: 0x4587c66d146de4b7fafd2a09a33a44d00b7121995e84a5459f55e7643d44d607
[own] near tx       : Bz3NXqoDqM1PzDZwf1kCKXeyTRrkdxxkLp1MyVXCAwTL (11.8s)
[own] signature 65B : 0xeea1d1852f2d099979515eb9a803c14838930b5fe56798cab00797c340ba43bc2c65905dda1018689b7ef93179f3266c07f70886e7a175bbd2bc876a1677a1f21c (recovery_id 1)
[own] recovered=from: true
[own] simulate (v,r,s)  : ok
[own] simulate (bytes)  : ok
[own] settle tx       : 0x07a0bc1842fd91473862c5c21cf86db765e4d07416089442275a18be5fecb344 status=success block=12065509 gasUsed=177406 events=AuthorizationUsed,Transfer
[own] payTo delta     : 10000
[own] authorizationState(from, nonce): true
[own] replay eth_call (v,r,s): no revert
[own] replay eth_call (bytes): no revert
[own] replay tx       : 0x0547bd1d39b41d100fdc89caef7626a66e4ea70c4008d4c8524f4e93cbdbb0bf status=success gasUsed=33688 events=AuthorizationAlreadyUsed
[own] replay payTo delta: 0 (no-op, as expected for PYUSD)
[own] PASS

[x402] authorization : {"from":"0xbBc0320E02d371a71F18A40B7B15404DF218D880","to":"0xEea5E3Bcc1E058aef9586a1c5C4cADc9CFDbC74F","value":"10000","validAfter":"1793832751","validBefore":"1793833021","nonce":"0x2b54dc3bc1eefd4ce00bb81bc7b851119bf6c5ecbc8f8fcab5623f15ee898d84"}
[x402] struct hash   : 0xfe5c9f1c68e0699ae3daeb60132018cb415a0313d50cdd146e9a5c1bad66d1f7
[x402] eip-712 digest: 0x810e3c7fcd2dfdf871acb22b1b5e3b0a064a2f10f6342a13edccaa62014396ef
[x402] near tx       : HR2Mo3jhZcGDD4Ph73B8D3wR39L8xmgDsX4VRU6PJiWr (11.0s)
[x402] signature 65B : 0x58828a4b21804543751599e3833f9c909fc7af08e9fd40fabd9d6700d6ab52bc205534d45e5d007566d2677cd32ab461aee6fb70da526461359914a3580342871b (recovery_id 0)
[x402] recovered=from: true
[x402] verify         : {"isValid":true,"payer":"0xbBc0320E02d371a71F18A40B7B15404DF218D880"}
[x402] settle         : {"success":true,"transaction":"0x57a63ad4bace5f28bd05d26691d27757cea474719a83ae3df74a1a5bbe08fea4","network":"eip155:11155111","payer":"0xbBc0320E02d371a71F18A40B7B15404DF218D880"}
[x402] settle tx      : 0x57a63ad4bace5f28bd05d26691d27757cea474719a83ae3df74a1a5bbe08fea4 status=success block=12065512 events=AuthorizationUsed,Transfer
[x402] payTo delta    : 10000
[x402] authorizationState(from, nonce): true
[x402] replay verify  : {"isValid":true,"payer":"0xbBc0320E02d371a71F18A40B7B15404DF218D880"}
[x402] replay settle  : {"success":false,"errorReason":"invalid_exact_evm_transfer_event_mismatch","transaction":"0x6a18b6ba2bdc62d5109ff725987da4c780db2c6f8cc894d4783ae2a9b2a1bb26","network":"eip155:11155111","payer":"0xbBc0320E02d371a71F18A40B7B15404DF218D880"}
[x402] replay tx      : 0x6a18b6ba2bdc62d5109ff725987da4c780db2c6f8cc894d4783ae2a9b2a1bb26 status=success events=AuthorizationAlreadyUsed payTo delta=0
[x402] PASS

agent pyusd after : 19960000  payTo pyusd after: 40000
```

(The etherscan URLs the script prints after each tx hash are left out above.)

## For PP1 (what changes versus USDC)

- **EIP-712 domain:** `{name: "PayPal USD", version: "1", chainId: 11155111, verifyingContract: 0xCaC524BcA292aaade2DF8A05cC58F0a65B1B3bB9}`. USDC on Base Sepolia uses `{name: "USDC", version: "2", chainId: 84532, …}`. The recomputed separator `0x299bc562…e6cd` equals the on-chain `DOMAIN_SEPARATOR()`.
- **Type and digest are unchanged:** `TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)`, digest `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`. PP1's "PYUSD digest matches PP-S2's tx" test can rebuild the `[own]` vector above. Its authorization fields give struct hash `0x9bc90864…2bdb` and digest `0x4587c66d146de4b7fafd2a09a33a44d00b7121995e84a5459f55e7643d44d607`, settled in `0x07a0bc18…b344`. That window is 270 s (≤ 300 s), so it should also pass PP1's own validity check.
- **Decimals:** 6, same as USDC, so 10000 = 0.01 PYUSD.
- **`transferWithAuthorization` form:** the implementation has both overloads. We found their selectors in the implementation bytecode, and both passed a dry `eth_call` before submission:
  - `transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)`, selector `0xe3ee160e`, the (v,r,s) form. **We submitted with this one.** `@x402/evm` also uses it for a 65-byte ECDSA signature.
  - `transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,bytes)`, selector `0xcf092995`.
  - Also present: `receiveWithAuthorization` (v,r,s), `authorizationState(address,bytes32)`, and `cancelAuthorization` in both forms.
- **MPC output is unchanged:** `r = big_r x`, `s`, `v = 27 + recovery_id`. This run produced both `recovery_id` 1 and 0, and both settled.
- **x402 requirements:** `{scheme: "exact", network: "eip155:11155111", asset: <PYUSD>, extra: {name: "PayPal USD", version: "1"}}`.

## Replay: PYUSD does not revert

USDC's FiatToken source reverts here with `FiatTokenV2: authorization is used or canceled`; S-c did not test that on chain. The PYUSD (Paxos) implementation instead **emits `AuthorizationAlreadyUsed(authorizer, nonce)`** (topic `0xd309466d…84cb`) and **returns successfully without transferring**. We saw this on chain (`0x0547bd1d…`, status success, gas 33688, payTo +0), and `eth_call` of both overloads returns `0x` on publicnode, Tenderly and 1rpc.

There was no revert, so there is no revert reason to record. Consequences:

- **Whoever confirms a PYUSD payment must check for the `Transfer` event (from, to, value), or the balance change. Receipt status is not enough.** This applies to the seller, the relayer and any receipt logic in PP1, PP4 and PP5. A submitter that sees `status: success` would wrongly report a replayed or already-settled authorization as paid.
- `@x402/evm` 2.30.0 `verify` returns `isValid: true` for an already-used authorization: its simulation does not revert. Its `settle` broadcasts anyway (the funder pays ~34k gas), then checks the logs and returns `success: false, errorReason: "invalid_exact_evm_transfer_event_mismatch"`. With the stock facilitator a replay therefore costs facilitator gas but is not reported as paid. A seller that trusts `verify` alone before serving the resource would be fooled.
- Replay is harmless to the payer: the nonce is spent once and nothing moves twice.

## Not checked

- PYUSD's verified Solidity source. We identified the overloads by selector scan of the implementation bytecode plus dry `eth_call`, and the replay event by matching its topic to `AuthorizationAlreadyUsed(address,bytes32)`. The behaviour is from on-chain results, not from reading the source.
- Whether an expired or not-yet-valid authorization also returns silently instead of reverting. We only tested reuse of a used nonce.
- Facilitator `verify`'s behaviour once `authorizationState` is true: we did not read its code beyond the settle path.
- PYUSD on any chain other than Ethereum Sepolia; mainnet PYUSD; Paxos faucet funding (the team funder already held PYUSD).
- The contract-derived nonce (D3) and calling `sign` from the mandate contract (C3); this spike signs from a plain NEAR account with a random nonce, as S-c did.
- MPC latency: one sign took 22.3 s, the other three 11–12 s.
