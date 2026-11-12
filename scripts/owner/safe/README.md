# Owner Safe scripts (O3)

The owner's passkey Safe on Base Sepolia and the agent's float: top it up from the Safe, at most `float_cap`, and sweep it back.

- **The Safe** is a Safe smart account (Candide `abstractionkit`, ERC-4337) owned by one WebAuthn passkey. Every Safe tx is one UserOperation, signed with one passkey tap and gas-sponsored by Candide's public Base Sepolia paymaster. The first top-up also deploys the Safe.
- **Taps** happen in the owner's own browser. A script that needs one serves a one-shot page on `http://localhost:5174/?t=<random token>` and prints the link. The page shows a summary of the tx (the challenge itself is the Safe operation hash), runs WebAuthn and posts the result back. No private key reaches the script.
- **`float_cap`** comes from the agent's mandate (`get_mandate`) on the NEAR contract. The contract cannot see Base balances, so this script is the only place the cap is enforced (PLAN.md, D8).

## Setup

Needs Node ≥ 22.18 (it runs the `.ts` files directly). The scripts reuse `../near` for NEAR config, views and the owner assertion; both are workspace packages, so one `pnpm install` at the repo root installs them:

```sh
pnpm install && cd scripts/owner/safe
export CONTRACT_ID=<contract>.testnet SUBMITTER_ACCOUNT_ID=<submitter>.testnet   # see .env.example
```

| Command | What it does | What it checks |
|---|---|---|
| `pnpm passkey` | One tap: creates the passkey (rpId `localhost`), and writes `$OWNER_KEY_DIR/safe-passkey.json` (credential id, P-256 point, Safe address; mode 600, never overwritten). Prints the Safe address to use as `SAFE_ADDRESS` in O1's `add-agent` | Refuses if the file already exists |
| `pnpm topup <agent> <usdc\|eure> <amount>` | One tap: the Safe sends `amount` (decimal, e.g. `2.5`) of the mandate's token to the agent EOA | Before the tap: the agent exists, is not revoked, sweeps to this Safe and has a mandate; **the EOA balance plus `amount` is at most `float_cap`**, else it refuses; the Safe holds `amount`. After the tap and before sending, it checks the cap again with a fresh balance. One top-up per agent and token at a time (lock file `topup-<agent>-<token>.lock` in the key dir; once a transfer is submitted, an error or Ctrl-C, including a failed `Transfer`-log check, keeps the lock until the owner has checked the EOA and deletes it; a missing `userOp` hash does not prove nothing was sent, since the bundler may have accepted it, so check the EOA and the Safe's nonce on basescan first). Afterwards: the tx has the Safe → EOA `Transfer` log |
| `pnpm sweep <agent> usdc <amount\|all> [request_id]` | Calls the contract's `sweep` as the owner (assertion signed with O1's owner key, submitted by `SUBMITTER_ACCOUNT_ID`), waits for the MPC signature, then one tap: the Safe submits the signed EIP-3009 `transferWithAuthorization` | The reservation is a signed USDC transfer from the agent EOA to this Safe for exactly `amount`, not expired. Afterwards: the tx has the EOA → Safe `Transfer` log |
| `pnpm test` | Unit tests (below) | |

The sweep needs no mandate and works after revoke. A **EURe** sweep is a raw tx from the agent EOA and needs that EOA to hold gas, so the relayer (R1) funds and submits it; `sweep … eure` refuses and says so.

## Tests

`pnpm test` (and `pnpm -r test` at the root, which CI runs):
- `test/float.test.ts`: **a top-up above `float_cap` is refused**, including when the float already holds part of the cap (20 + 5.000001 USDC against 25). A top-up that lands exactly on the cap passes, and a zero top-up is refused. The cap is checked again after the tap: a balance that grew while the owner tapped stops the send. A second top-up on the same lock is refused. The lock is released on success and on an error before submission, and kept on an error after it. Amounts parse into base units and refuse signs, exponents, hex and extra decimals.
- `test/sweep.test.ts`: the borsh `sweep` args the owner assertion signs (docs/interfaces.md §2). The `transferWithAuthorization` calldata for the S-c settled authorization. The reservation check refuses a wrong `to`, a wrong amount, an unsigned reservation, a non-sweep shape and an expired authorization. A transfer counts only with a matching `Transfer` log (token, direction, amount). Passkey SPKI → (x, y) refuses anything but an uncompressed P-256 key.

## Base Sepolia run

The passkey exists and its Safe `0xaa9b16Bcb70292BA34d4284Ba1A118566Ef9ebB9` (counterfactual, not deployed yet) is agent-1's sweep destination on the C4b contract `nearh-c4b-1793824007.testnet`. The contract's `sweep` is wired: an agent-signed sweep there returned a signed EIP-3009 authorization to this Safe (scripts/owner/near/README.md, C4b redeploy), and the relayer submitted a relayer-requested one that moved 0.05 USDC into it (relayer/README.md, R1b run).

Pending: the top-up and its refusal, and `pnpm sweep` from this script (each needs the passkey tap).

## Not covered

- Recovery: the Safe has one passkey and no recovery module. The passkey is bound to `localhost`, so it signs only on localhost pages, not on the dashboard's site (DB1); any page on any localhost port can ask for it, and each use needs the owner's tap. Fine for testnet funds; not a production setup.
- Top-ups read the token address from the mandate, sweeps from `sweep_config`; the contract keeps the two equal (`ERR_INVALID_MANDATE`).
- The cap holds against this script's own runs (lock + re-check after the tap). A transfer to the EOA from elsewhere after the last check can still push it over; only the script enforces the cap (D8).
- Before the Safe's first UserOperation, `safe-passkey.json` is the only record of its address. Keep it.
- EURe sweep submission (R1). No TypeScript type-check runs; Node strips the types at run time.
