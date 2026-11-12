# S-i result: contract-side `add_key` / `delete_key`

**Pass.** A contract with no full-access key on its account adds a function-call key on its own account from inside an owner method (`add_agent`) and deletes it from inside another (`revoke`). The agent can also delete its own key with `revoke_self`. Each of these calls changes contract state and adds or deletes the key in the same transaction. No fallback is needed: D1 revoke step 2 (`delete_key`) stays.

## Reproduce

```sh
spikes/deletekey/run.sh            # needs cargo-near, near-cli-rs, python3, curl
```

It builds the wasm, creates a fresh owner account (faucet) and the contract account `dk.<owner>`, deploys with `new(owner)`, deletes the deployer's full-access key, then runs add A, add B, an attempt to call a method the agent key is not allowed to call, revoke A and revoke_self B. After each step it prints `near account list-keys` and the receipts of each tx (from `EXPERIMENTAL_tx_status`), and it exits non-zero if the keys, the refusal or a tx status are not what it expects. Agent keys go to `~/.nearh-spike-deletekey/<owner>/`, outside the repo, and the script's output filters out private keys and seed phrases.

## Run on testnet (2026-11-01)

Owner `nearh-cc2-si-1793551152.testnet`, contract `dk.nearh-cc2-si-1793551152.testnet`, wasm sha256 `3ba1b060…a288b`.

| Step | Tx | What it shows |
|---|---|---|
| Deploy + `new(owner)` | `FdRc1FwKSvwz5mUnLY4foTyJWuz2L9CgxgEpB3cNVWRa` | Code deployed, state initialized |
| Delete the deployer's full-access key | `JBkcEPq1DhfHwTEmQDp4dG3hbXD5Xt6ACDJhwbtar9az` | `list-keys` is now empty |
| `add_agent(A)` by the owner | `DmtXbvqHbfJEPMvno3R56xzVjLGMhRwWV7opDFeMznzw` | Receipt 1: FunctionCall (state write, log `add_agent agent-A`). Receipt 2: contract → itself `AddKey`. Both succeed. |
| `add_agent(B)` by the owner | `9WGQfnk1PjkTYMyMDbWeF4ZiqVXbo4s6sbYPdwz6Rz2k` | Same as A |
| B's key calls `add_agent` | none (client-side refusal: near-cli refused to send it) | `Transaction method name <add_agent> isn't allowed by the access key`. The chain enforces the same rule (a function-call key only allows its listed methods), but this run did not test it on chain because no tx was sent. |
| `revoke(A)` by the owner | `EFymWpkrKC1C7nRb2YrGxuCyAUiVRdJ1yXwPzUwjf2rv` | Receipt 1: FunctionCall (state entry removed, log `revoke agent-A`). Receipt 2: `DeleteKey` A. Both succeed. |
| `revoke_self()` signed by B's own key | `HfgF3Bav4SDxnDt8FFyrQb3Ty6HmSzLE2fTHF6Dk8MWR` | The FunctionCall (log `revoke_self agent-B`) runs, then `DeleteKey` of B. The calling key deletes itself. |

Explorer: `https://testnet.nearblocks.io/txns/<hash>`.

`list-keys` after `add_agent` A and B (public keys only):

```
| 1 | ed25519:EuRa2phH1QCNW9fkjXArT71XybokoeCCR8z6RA5eXMvJ | only do ["request_signature", "sweep", "revoke_self"] function calls on dk.nearh-cc2-si-1793551152.testnet with an allowance of 0.25 NEAR |
| 2 | ed25519:FKjZCiPS2gqYZ3D3tAXSBPo3JTtf5D4j8bDjftv2Bvu7 | only do ["request_signature", "sweep", "revoke_self"] function calls on dk.nearh-cc2-si-1793551152.testnet with an allowance of 0.25 NEAR |
```

After `revoke(A)` only B is listed. At the end (`near account list-keys dk.nearh-cc2-si-1793551152.testnet network-config testnet now`):

```
+---+------------+-------+-------------+
| # | Public Key | Nonce | Permissions |
+---+------------+-------+-------------+
+---+------------+-------+-------------+
```

No keys are left, so there is no full-access key. `agent_of(B)` returns `null`, so the state was cleared as well.

## What we learned (for C2 and O1)

- **The calls work in one tx alongside other logic, but in two receipts.** A method's state change runs in the FunctionCall receipt, and the `AddKey` or `DeleteKey` runs in a second receipt from the contract to itself, in the same transaction. For revoke this means one owner call and one tx, as D1 requires. The two steps are not atomic: if the key receipt fails, the state change from the first receipt stays committed. C2 must handle both directions:
  - **`add_agent`:** if `AddKey` fails (for example `LackBalanceForState`, or the key is already on the account), the map keeps an agent with no key, and a later revoke's `DeleteKey` of that key fails. C2 must do one of two things: write the key-to-agent entry only in a `#[private]` callback (`.then(Self::ext(current_account_id()).on_key_added(..))`) that runs after `AddKey` succeeds (`is_promise_success()`), or have the callback remove the entry when `AddKey` fails. T2 tests the failure path.
  - **`revoke`:** clear the state first (mandate and map entry), then delete the key, and treat a missing key as already revoked. A failed `DeleteKey` then leaves the mandate cleared, which is the safe direction. Rejecting a key that is already registered (spike: `key already registered`) only catches keys the map knows about; it does not prevent a map/account mismatch.
- **The tx status follows the returned key action.** Because the method returns the `AddKey`/`DeleteKey` promise, the tx shows `Failure` if that receipt fails, even though the state change in the first receipt already committed. O1 and R1 must not read "tx failed" as "nothing changed"; they check the state (`agent_of`, mandate) and `list-keys` instead.
- `Promise::new(env::current_account_id()).add_access_key_allowance(pk, Allowance::limited(..), current_account_id, "request_signature,sweep,revoke_self")` in near-sdk 5.30 gives exactly the three-method key that O1 checks with `list-keys`.
- `revoke_self` can use `env::signer_account_pk()` to find the calling key and delete it. A function-call key may delete itself through the contract.
- The function-call key's allowance (0.25 NEAR here) only pays gas and comes out of the contract account's balance. C2 should choose the amount on purpose.
- With no keys left, nobody can redeploy the contract or add a key except through the contract's own methods. The spike's `add_agent` is owner-gated by `predecessor_account_id`. The real contract gates it with the passkey (S-h).

## Not checked

- Atomicity under failure: we did not force an `AddKey` or `DeleteKey` failure, so the "state stays changed" and "tx shows `Failure`" points above come from NEAR's receipt model and were not observed.
- `run.sh` now exits non-zero if a `list-keys` result, the method-not-allowed refusal or a tx status does not match what is expected. Those checks were added after the recorded run and have not been run against testnet (no new txs for this fix); the recorded output above is the evidence for this run.
- Gas and allowance tuning, a key added with a nonce, and a contract upgrade path. The spike has no upgrade method; the real contract would need one, gated by the owner, if we ever want one.
- An earlier partial run left `dk.nearh-cc2-si-1793551114.testnet`. It has no full-access key, but agent key A is still on it. It is unused.
