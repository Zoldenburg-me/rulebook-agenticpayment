# S-a: Chain Signatures harness — PASS

Derive the EOA for a (predecessor, path) on `v1.signer-prod.testnet`, request one secp256k1 signature, recover the address from it.

## Run it

Tested with Node 26.7.0 (needs top-level await; near-api-js 7) and near-cli-rs 0.30.1 (the `near` command below is near-cli-rs, not the old JS near-cli).

You need a NEAR testnet account with a little NEAR and its key in the legacy keychain (`~/.near-credentials/testnet/<account>.json`). Create one with:

```sh
near account create-account sponsor-by-faucet-service <name>.testnet \
  autogenerate-new-keypair save-to-legacy-keychain network-config testnet create
```

Then:

```sh
cd spikes/chainsig
pnpm install --ignore-workspace
NEAR_ACCOUNT_ID=<name>.testnet node chainsig.mjs
```

Optional env: `CHAINSIG_PATH` (default `nearh-sa-test`), `MPC_CONTRACT` (default `v1.signer-prod.testnet`), `NEAR_RPC`. The script reads the key from the keychain file and never prints it.

## Recorded run (2026-11-01)

```
mpc contract      : v1.signer-prod.testnet
predecessor, path : nearh-cc1-1793550206.testnet , nearh-sa-test
derived address   : 0xbBc0320E02d371a71F18A40B7B15404DF218D880
local KDF matches : true
near tx           : 7vJfqwcDstofCZDKuBSP9vGP731ttuajN5jcTdTt3gyE (11.4s)
raw mpc response  : {"scheme":"Secp256k1","big_r":{"affine_point":"025650b556dbf54a03596dd195c0d850ccb07ba2c0c5af0233477d9c2f6d67639c"},"s":{"scalar":"2c67c30ea3bf01f0e8a66e4b4c337d87d477d7a7f8b8c89d70a9a1b3ee3b2424"},"recovery_id":1}
message           : nearH S-a chainsig spike 2026-11-01T16:25:05.678Z
eip-191 hash      : 0x22a1ab81c83f48e33f8ead18349e9264e180d08a1db20f745a979ee357a6c5be
signature (65B)   : 0x5650b556dbf54a03596dd195c0d850ccb07ba2c0c5af0233477d9c2f6d67639c2c67c30ea3bf01f0e8a66e4b4c337d87d477d7a7f8b8c89d70a9a1b3ee3b24241c
recovered address : 0xbBc0320E02d371a71F18A40B7B15404DF218D880
PASS
```

## What we learned

- **Call shape.** `sign` takes `{"request": {"payload_v2": {"Ecdsa": "<32-byte hex, no 0x>"}, "path": "<path>", "domain_id": 0}}` with a deposit of 1 yoctoNEAR. We attached 300 Tgas; the whole tx burnt about 8.5 Tgas (≈0.0008 NEAR) over 4 receipts. The call returned after 11.4 s (one run).
- **Response.** `{"scheme":"Secp256k1","big_r":{"affine_point":"02|03" + x},"s":{"scalar":hex},"recovery_id":0|1}`. The EVM signature is `r = x of big_r` (drop the 1-byte prefix), `s = scalar`, `v = 27 + recovery_id` (yParity = `recovery_id`). The contract (C3) must parse this JSON in its callback; this is the format to code against.
- **The `big_r` prefix is not the recovery id.** In this run the prefix is `02` (even y) but `recovery_id` is 1, because the MPC normalises to low-s. Rebuilding R from the prefix recovers the wrong address. Callers (S-c, C3) must take `v` from `recovery_id` in the response.
- **Payload is signed as-is.** The MPC signs the 32 bytes it is given, with no prefixing. Here we passed an EIP-191 hash; for EIP-3009 the contract passes the EIP-712 digest it builds itself.
- **Derivation.** `epsilon = sha3_256("near-mpc-recovery v0.1.0 epsilon derivation:" + predecessor + "," + path)` as a big-endian scalar; `derived = root_public_key + epsilon·G`; address = last 20 bytes of `keccak256(x‖y)`. The local computation matched the contract's `derived_public_key` view (`{path, predecessor, domain_id: 0}`), so callers can derive offline from the root key (`public_key` view).
- **The predecessor is what counts.** The address depends on the account that calls `sign`. For the mandate contract the predecessor is the contract account, so each agent's EOA is `derive(contract_id, path)`; the path should be stable per agent (e.g. the agent id).
- **Security consequences for C3.** The MPC signs any 32 bytes, and every agent shares one predecessor (the contract), so:
  - The contract builds every digest itself from checked fields; it never forwards a caller-supplied payload to `sign`. Otherwise an agent could get a raw EVM tx or any EIP-712 digest signed and sweep its EOA.
  - The derivation path comes from the key-to-agent map (keyed by `env::signer_account_pk()`), never from call arguments. Otherwise agent A could sign on agent B's path.
  - Paths are never reused: a revoked agent's path stays retired. Otherwise a new agent inherits the old EOA, its Monerium link, balance and any still-valid EIP-3009 authorizations.

## Not checked

- Calling `sign` from a contract (cross-contract promise and callback). That is C3's job; the args and response above are the same.
- Gas a contract must forward to `sign`; we only know 300 Tgas from an account works and ~8.5 Tgas is burnt.
- MPC timeouts or failures; one run only.

## Fallback

None needed.
