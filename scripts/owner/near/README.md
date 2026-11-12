# Owner NEAR scripts (O1)

TypeScript scripts for the owner side of the mandate contract on NEAR testnet: deploy and `new`, then delete the deployer's full-access key; `add_agent`, `set_relayer`, `set_mandate`, `add_payee` and `owner:revoke`.

Every owner call carries a WebAuthn assertion over the challenge in [docs/interfaces.md §2](../../../docs/interfaces.md), signed with the owner's P-256 key and the current `owner_nonce + 1`, and is submitted by any NEAR account (`SUBMITTER_ACCOUNT_ID`). Here the owner key is a **software P-256 key** kept outside the repo, in `$OWNER_KEY_DIR/<contract>/owner-p256.json` (default `~/.nearh-owner`). The assertion bytes are the ones an authenticator signs, so the contract cannot tell the two apart. The real passkey path belongs to the dashboard (DB1).

After each tx a script reads the contract's views and the account's access keys and fails if they are not what it expects. It never uses the tx status as the result (docs/interfaces.md §1).

## Setup

Needs Node ≥ 22.18 (runs the `.ts` files directly), pnpm and near-cli-rs (`near`). Transactions go through near-cli-rs with the legacy keychain (`~/.near-credentials`), as in spikes/deletekey; views use plain JSON-RPC over https (`NEAR_RPC` must be https on a testnet host listed in `TESTNET_RPC_HOSTS`, `src/near.ts`). The only dependencies are `@noble/curves` and `@noble/hashes`.

```sh
# two fresh testnet accounts from the faucet: the contract, and a submitter that pays gas
near account create-account sponsor-by-faucet-service <contract>.testnet autogenerate-new-keypair save-to-legacy-keychain network-config testnet create
near account create-account sponsor-by-faucet-service <submitter>.testnet autogenerate-new-keypair save-to-legacy-keychain network-config testnet create
(cd contract && cargo near build non-reproducible-wasm)   # target/near/mandate/mandate.wasm

cd scripts/owner/near
export CONTRACT_ID=<contract>.testnet SUBMITTER_ACCOUNT_ID=<submitter>.testnet SAFE_ADDRESS=0x...
```

See `.env.example` for every variable.

| Command | What it does | What it checks afterwards |
|---|---|---|
| `pnpm keygen` | Creates the software owner key for `CONTRACT_ID` (refuses to overwrite) | |
| `pnpm deploy-contract [wasm]` | Deploys the contract with `new(passkey owner, "testnet", MPC)`, then deletes every full-access key on the account. It refuses an account that already has code, and deletes nothing unless the deploy tx went through and `get_config` equals exactly what `new` was called with | `get_config`; `view_access_key_list` shows no full-access key |
| `pnpm add-agent <agent> [ed25519:<pk>]` | Derives `evm_address` = derive(contract, agent) off chain (S-a) and cross-checks it against the MPC's `derived_public_key` view, then calls `add_agent`. Without a key, it generates one into `$OWNER_KEY_DIR/<contract>/agents/<agent>.json`, or reuses the file an earlier failed run left there. Agent ids must match the contract's rule (1–64 of `[A-Za-z0-9._:-]`), which also keeps the file inside that directory | `get_agent` (key, lowercase `evm_address`, sweep config), `agent_of_key`, and that the key is function-call only, on the contract, with exactly `["request_signature","sweep","revoke_self"]` |
| `pnpm set-relayer <account.testnet \| none>` | `set_relayer` | `get_config.relayer` |
| `pnpm set-mandate <agent> <mandate.json>` | `set_mandate` (example: `examples/mandate.json`) | `get_mandate` equals the file by value (key order does not matter), with addresses lowercased |
| `pnpm add-payee <agent> x402 <0x…> \| sepa <IBAN>` | `add_payee` | `get_payees` lists it |
| `pnpm owner:revoke <agent>` | `revoke` | `get_agent` shows `revoked: true, public_key: null`; mandate and payees are gone; the key is off the account. If the state is revoked but the key is still there, it exits 1 and says to run it again (the contract retries the `DeleteKey`). On that rerun `get_agent` has no key, so it checks the key from the local key file; with no key file it exits 1 if any agent-method function-call key that `agent_of_key` maps to no agent is left |
| `pnpm list-keys` | Prints the contract's access keys (public keys and permissions) | |
| `pnpm test` | Unit tests (below) | |

## Tests

`pnpm test` (and `pnpm -r test` once the workspace lists this package):
- `test/challenge.test.ts`: the preimage, challenge and base64url equal the worked vector in docs/interfaces.md §2, which `contract/tests/c2_owner.rs` asserts. The full assertion for that vector, signed with the contract tests' key (`0x11 × 32`), is **byte-equal** (authenticatorData, clientDataJSON, signature) to the one `c2_owner.rs`'s `Signing::sign` builds and the contract accepts in `valid_assertion_is_accepted_from_any_submitter_and_consumes_the_nonce`. Both sides sign with RFC 6979 and no S normalisation, so the signatures match exactly. Also: the signature verifies as `p256_verify(sha256(authData ‖ sha256(clientDataJSON)))`, and each bound field changes the challenge.
- `test/borsh.test.ts`: the borsh args of `add_agent`, `set_relayer` (Some and None), `set_mandate`, `add_payee` (x402 and sepa) and `revoke` are byte-equal to `borsh::to_vec` of the contract's own types with the c2_owner.rs fixture values. The expected hex was printed by a scratch program that links the `mandate` crate; that program is not in the repo. Out-of-range numbers and unsupported keys throw instead of being truncated.
- `test/derive.test.ts`: the agent EOA derivation reproduces spike S-a's recorded address.
- `test/guards.test.ts`: agent ids outside the contract's rule (`../x`, `a/b`, ...) are refused before any file path is built. `NEAR_RPC` must parse as https with a hostname on `TESTNET_RPC_HOSTS` (mainnet lookalikes such as `?x=testnet` or `testnet@` are refused), and accounts must be `.testnet`.
- `test/revoke-check.test.ts`: owner:revoke's key check: a first run, a rerun after a failed `DeleteKey` where the key is still present, and the fail-closed scan when no key is known.

## Testnet run (2026-11-01)

Fresh faucet accounts: contract `nearh-o1-1793573321.testnet`, submitter (also the relayer) `nearh-o1-sub-1793573321.testnet`. Wasm built from `main` at 7b0d4df, sha256 `f185f11c…ae91490`. `SAFE_ADDRESS` was the placeholder `0x5afe…0001`; no funds moved.

| Step | Tx | State checked |
|---|---|---|
| `deploy-contract`: deploy + `new` | `2UGVCewD4xtgqbMoBP7LfN1LW3irVpBrVHojr5iSxXVt` | `get_config`: passkey owner, rp `localhost`, origin `http://localhost:5173`, network `testnet`, MPC `v1.signer-prod.testnet` |
| `deploy-contract`: delete the deployer's full-access key `ed25519:Fvi7wULmqZRpozRpK3boh7EZqLNYfgQeEakYhiLLUQz1` | `5R4Nz4ez5ANhkQMN1iBSVVQpzJxW28KnMAfaJEVPQtcD` | no access keys left |
| `add-agent agent-1` (owner_nonce 1) | `6NkhgGyARkcNuT4yYViT8VkF9A394inptLPu27dx2c99` | key `ed25519:AGjsCedupTLgA8aVpEeGJ68jh1qzbFScfWY7BtyeP8wv`, EOA `0xe0273e7e2da6020d3b7bcbaebd49f6f4945b90cc` (equal to the MPC view) |
| `set-relayer nearh-o1-sub-1793573321.testnet` (2) | `CxSEuaCrcs43ji8daE2quDBH2thUQwWKbs2JAicSnDir` | `get_config.relayer` |
| `set-mandate agent-1 examples/mandate.json` (3) | `4HuN3Nxxr99Hff9V1XspoQEfp7nYjktzZgdAHbP8RARD` | `get_mandate` |
| `add-payee agent-1 x402 0x5AFE…0002` (4) | `HRfyeeesnwm8x7FyCghAKUMm8Rktc3wGCa2wWz98Voit` | `get_payees`, address stored lowercase |
| `add-payee agent-1 sepa DE89370400440532013000` (5) | `FZRiwDrYKUzAiF5f4AwV3E16YDpYqcZJncWrv9wtqKLX` | `get_payees` |
| `add-agent agent-2` (6) | `87VgowBafJRQbicPmfJvwq9E6kG1PPnvzx2ZUrYm7ZyQ` | key `ed25519:4WRisfDe9DdScLQkMMB5zfWQKFhE2xe7L29MfJz8xxKv`, EOA `0xdde99fb37fa1186b41ea01ef7e2c0d2a843df54e` |
| `set-mandate agent-2` (7) | `38jJnu98Cfdtbji2c7qNCZWgQmao7c9QgoqNnsjMyq9V` | `get_mandate` |
| `owner:revoke agent-2` (8) | `CwskQK8kH7jd6txm7ds1fv3L8BwkLwL5t5KTQfAWWRdj` | `revoked: true`, `public_key: null`, mandate and payees cleared, key off the account |

Explorer: `https://testnet.nearblocks.io/txns/<hash>`. Every owner call was submitted by the submitter account, not by the owner.

`near account list-keys nearh-o1-1793573321.testnet network-config testnet now` at the end of the run: no full-access key, and agent-1's key has exactly the three methods (agent-2's key was deleted by the revoke):

```
+---+------------------------------------------------------+-----------------+---------------------------------------------------------------------------------------------------------------------------------+
| # | Public Key                                           | Nonce           | Permissions                                                                                                                     |
+---+------------------------------------------------------+-----------------+---------------------------------------------------------------------------------------------------------------------------------+
| 1 | ed25519:AGjsCedupTLgA8aVpEeGJ68jh1qzbFScfWY7BtyeP8wv | 275813892000000 | only do ["request_signature", "sweep", "revoke_self"] function calls on nearh-o1-1793573321.testnet with an allowance of 1 NEAR |
+---+------------------------------------------------------+-----------------+---------------------------------------------------------------------------------------------------------------------------------+
```

Before the revoke, `list-keys` showed both agent keys, each `function-call on nearh-o1-1793573321.testnet ["request_signature","sweep","revoke_self"]`.

### Second run after the review fixes (2026-11-02)

- `deploy-contract` against `nearh-o1-1793573321.testnet`, which already has code, is refused before any tx: `already has code; deploy-contract only deploys to a fresh account`.
- Fresh contract `nearh-o1b-1793574016.testnet`: deploy + `new` `8b9j63Lohew5RgSGjKbEVanDH9EzepM5aW669rHkB8Xc`, then deletion of the deployer key `ed25519:Dbz4rXFyJ3Dr3d3UvsbY9MBi3QkMX8fq38HYYrrd24DD` `6GN4ydoH7nwTgzkPkT386U4m7WC1abxXgwEaR9dnQzbD`. No access keys were left.
- `add-agent agent-1` without `SAFE_ADDRESS` fails after generating the key. The rerun with it set reuses that key (`ed25519:5xXhgkCn4Y6sj6i5bFxWV8oBSZaegHddK8XUBtvRVF8m`) and passes.
- `set-mandate` with the mandate file's fields in reverse order, tx `FxgU3EHBmqfDbGXzXJFp7QpujNKAe6qdbnTkBdE1W8M`, PASS.
- `list-keys` at the end: only the agent key, function-call on the contract with `["request_signature","sweep","revoke_self"]`.

## C4b testnet redeploy with the passkey Safe (2026-11-04)

Redeploy with sweep wired, so that agent-1's `sweep_config.safe_address` is the owner's passkey Safe `0xaa9b16Bcb70292BA34d4284Ba1A118566Ef9ebB9` (Base Sepolia, counterfactual, from scripts/owner/safe) and not the placeholder `0x5afe…0001`. The NEAR owner is still a software P-256 key (`pnpm keygen`); the passkey only owns the Safe. No funds moved.

Fresh faucet accounts: contract `nearh-c4b-1793824007.testnet`, submitter (also the relayer) `nearh-c4b-sub-1793824007.testnet`. Wasm built from `main` at 6c2e570 (`cargo near build non-reproducible-wasm`), sha256 `1a0c6924465d39c263d488cac2deeb1e0cc8cac3903ddf3edf72f073cbe916ec`.

| Step | Tx | State checked |
|---|---|---|
| `deploy-contract`: deploy + `new` | `2etAnBEt962h4FMfSaLQMz9LN8BmVNtcE25AhnDXiDTq` | `get_config`: passkey owner, rp `localhost`, origin `http://localhost:5173`, network `testnet`, MPC `v1.signer-prod.testnet` |
| `deploy-contract`: delete the deployer's full-access key `ed25519:3kwFZ6xiPSKrtV4d2GernPnFf5twnfZzSVy3iMXz5cGJ` | `CMuM91XWkVKQEENMiKLdH9T4nawARWsA5kGwozNfQrHS` | no access keys left |
| `set-relayer nearh-c4b-sub-1793824007.testnet` (owner_nonce 1) | `Eu5xmEK6wqFbNu6zeyy6nTMM183B5Z38CQMgejVAS84s` | `get_config.relayer` |
| `add-agent agent-1` with `SAFE_ADDRESS=0xaa9b…ebB9` (2) | `7a6nVukzMCxMrr4rb3Kye9heL5WMdTAccPG8KLL82Dfu` | key `ed25519:FfjiL8AC3RRZsht2cacaN4QhYwsmeCyeZ2wDV5VB5o1D`, EOA `0xb1375297bd48c99f2aac965b5671ca50d7bb20db` (equal to the MPC view), `sweep_config.safe_address` `0xaa9b16bcb70292ba34d4284ba1a118566ef9ebb9` |
| `set-mandate agent-1 examples/mandate.json` (3) | `5ShJJWQTUSzuSqA5ncGKSSR4fDfVFv6jB9MZcFuPWnPy` | `get_mandate` |

`near account list-keys nearh-c4b-1793824007.testnet network-config testnet now` after the sweep: no full-access key, only agent-1's key with the three methods:

```
| # | Public Key                                           | Nonce           | Permissions                                                                                                                                       |
| 1 | ed25519:FfjiL8AC3RRZsht2cacaN4QhYwsmeCyeZ2wDV5VB5o1D | 276244305000001 | only do ["request_signature", "sweep", "revoke_self"] function calls on nearh-c4b-1793824007.testnet with an allowance of 0.9985190630481705 NEAR |
```

**Sweep as the agent.** One `sweep` signed with agent-1's function-call key (near-cli `sign-with-access-key-file`), args `{"agent":"agent-1","token":"usdc","amount":"1000000","request_id":"c4b-sweep-1","evm_tx":null,"assertion":null}`, 300 Tgas, no deposit. It succeeded first try. The MPC signed and the call returned a reservation with `status: "signed"`, `shape: "sweep"`, caller `agent`, and an EIP-3009 payload `from` the agent EOA `0xb137…20db`, `to` the Safe `0xaa9b…ebb9`, asset USDC `0x036c…cf7e`, chain 84532, value `1000000`, a 300 s validity window, and a signature (`v` 27). `get_request` for that key reads back `signed`, with the same `to` and value. The sweep tx hash was not captured: the CLI output was cut before the hash, and the nearblocks indexer still listed no txs for the account when this was written. It is the only tx signed by agent-1's key (`Nonce` 276244305000001 above).

Not done here: the signed authorization was not submitted on Base Sepolia (the agent EOA holds no USDC and the Safe is still counterfactual); no EURe sweep, and no relayer or owner sweep.

## Not covered

- The real passkey (DB1 signs in the browser) and wallet-mode owners. The scripts refuse a wallet-mode contract.
- `remove_payee`, `link_agent` (O2), `resolve_reservation` and owner `sweep` (O3).
- Negative paths on chain (stale nonce, tampered assertion). The contract's unit tests cover them; this run did not exercise them.
- No TypeScript type-check runs (no `tsc` in the repo); Node strips the types at run time.
