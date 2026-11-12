# S-h result: passkey owner via `env::p256_verify`

**Decision: GO.** The owner is the passkey, verified with `env::p256_verify`. No fallback is needed (neither the `p256` crate nor a NEAR wallet owner).

A real passkey assertion passes `cargo test --test real_assertion` in near-workspaces, and the same assertion verifies on testnet. The assertion itself is kept out of the repo (see [Real passkey capture](#real-passkey-capture)).

## What `env::p256_verify` takes (near-sdk 5.30.0, `near-sys` 0.4.0)

`p256_verify(signature: &[u8; 64], prehash: &[u8; 32], public_key: &[u8; 33]) -> bool`

| Input | Encoding | What a browser gives | Conversion (off-chain, in the dashboard / owner script) |
|---|---|---|---|
| signature | raw `r ‖ s`, 32 bytes each, big-endian | ASN.1 DER | DER → raw (`der_to_raw` in `tests/common/mod.rs`) |
| public key | 33-byte **compressed** SEC1 | `getPublicKey()` = 91-byte SPKI DER (uncompressed point) | strip the 26-byte SPKI prefix, compress (`spki_to_compressed`) |
| message | a 32-byte **prehash**; the host does not hash | `authenticatorData`, `clientDataJSON` | contract computes `sha256(authData ‖ sha256(clientDataJSON))` |

- **Low-S:** the host accepts both `s` and `n − s`. Authenticators do not normalise S (the real assertion below **is high-S**), so the contract must **not** require low-S (`p256_signature_is_low_s`). That is safe because PLAN's replay protection is `owner_nonce`, never the signature bytes.
- A DER signature or an uncompressed key is rejected (returns false, no panic).
- Contract: `src/lib.rs`, `verify_webauthn(public_key, authenticator_data, client_data_json, signature)` (all base64) → bool. It checks the signature only; the `clientDataJSON`/rpIdHash/flags/nonce checks are C2's `assert_owner`. `tests/real_assertion.rs` already does them off-chain, which shows what C2 must do.
- `p256_verify` is not behind a feature flag in near-sdk 5.30. The host build needs `near-sdk` with `unit-testing` as a dev-dependency (otherwise near-sdk's `compile_error!` fires).

## Where it runs

| Network | nearcore | Result |
|---|---|---|
| testnet | 2.14.0-rc.5, protocol 88 | **works.** Deploy tx `DqsvD6yFvas9noNi2XnQtUtmc97SvTQNV8c3X4vS9eZQ` put the contract on `nearh-cc2-sh-1793553359.testnet` (a deploy, it returns nothing). Read-only view calls of `verify_webauthn` on that account: software vector → `true`, same vector with authData flipped → `false` (`./testnet.sh`), the **real passkey assertion → `true`** |
| near-workspaces sandbox | 2.14.0, protocol 88 (pinned by near-sandbox 0.4.0) | **works.** `cargo test --test software_key`: valid → true, high-S twin → true; tampered authData, tampered clientDataJSON, wrong key, DER signature, uncompressed key → false. **`cargo test --test real_assertion`: real passkey → true, tampered clientDataJSON → false** |
| mainnet | 2.14.0, protocol 86 | not tested (out of scope, testnet only) |

## Real passkey capture

- `page/index.html` + `page/server.mjs` (no deps, binds 127.0.0.1:8787). The page was exposed **tailnet-only**
  with `tailscale serve --bg --https=8443 http://127.0.0.1:8787` (no funnel) and opened on the node's
  `https://<node>.<tailnet>.ts.net:8443/` name, so rpId = that node name and the origin includes `:8443`.
  This passkey exists only for the spike; it is not the dashboard's or Zold-app's passkey.
- Tap 1 creates an ES256 passkey; tap 2 signs `sha256("zold-mandate-v1 S-h spike test challenge")` and POSTs the blob to `/save`, which writes `fixtures/assertion.json` (public key, authData, clientDataJSON, DER signature: nothing secret).

### The captured assertion (2026-11-01 18:33 UTC, kept local)

The real assertion was captured on the lead's machine and verified on-chain: `cargo test --test real_assertion`
in the near-workspaces sandbox, plus the testnet view calls above. A reviewer independently re-verified it
off-chain (node `crypto`, challenge, origin, rpIdHash, flags, high-S) and with their own testnet view calls.

`fixtures/assertion.json` and `fixtures/assertion-contract-args.json` are **not in the repo** (`fixtures/.gitignore`):
the rpId is signed (rpIdHash in authData, origin inside clientDataJSON), it contains a personal machine name,
and it cannot be redacted without breaking the signature. Without the file, `tests/real_assertion.rs` prints
`skipped: no real assertion fixture; see RESULT.md` and passes, so CI and fresh clones pass. To trace it:

| | |
|---|---|
| `fixtures/assertion.json` sha256 | `8a680d2b61aa68a4b4d424590d75acacf4acbc790be1f22442146f7135cfb846` |
| credential public key (compressed SEC1, hex) | `02acb646c9504762811b02466ee1788210b83b096df04bb52a09394b751adaf4ec` |
| same, base64 (the contract's `public_key` arg) | `Aqy2RslQR2KBGwJGbuF4ghC4Owlt8Eu1Kgk5S3Ua2vTs` |

What it showed:

- Browser on macOS (Chromium), a synced passkey: flags `0x1d` = UP | UV | BE | BS.
- `signCount` is **0**, as is normal for synced passkeys. This confirms PLAN: never use signCount as a replay key.
- The signature is **high-S** (`low_s=false`), so requiring low-S would have rejected a real passkey.
- `clientDataJSON` = `{"type":"webauthn.get","challenge":"<b64url>","origin":"https://…:8443","crossOrigin":false}`: the challenge is unpadded base64url and the origin includes the port. C2 should compare the stored origin byte-for-byte.
- authenticatorData is 37 bytes (no extensions).

The software-key test and `fixtures/software-vector.json` use the neutral rpId `localhost` and origin `https://localhost:8443`.

## Zold-app's rpId (PLAN.md Reuse row)

**Unknown from public info.** Zold-app's `services/api/src/config/security.ts` sets `rpId: process.env.RP_ID ?? "localhost"`, and `.env.example` does not set `RP_ID`. So the rpId is whatever the deployment sets. The README links `https://zoldhq.com`, but nothing public says that is the passkey rpId.
It matters: a passkey only signs for its own rpId. Unless the dashboard is served from Zold-app's rpId (or a subdomain of it), the owner cannot reuse the Zold-app passkey Safe signer. PLAN's fallback applies: create a fresh passkey Safe from the dashboard's site. The owner should confirm `RP_ID` on the deployed Zold-app.

## Reproduce

```bash
cd spikes/passkey
# Intel Mac only (see below): point near-workspaces at a self-built sandbox
export NEAR_SANDBOX_BIN_PATH=$HOME/.nearh-sandbox/nearcore/target/release/near-sandbox
cargo test --test software_key            # software P-256 key, near-workspaces sandbox
cargo test --test real_assertion          # needs a local fixtures/assertion.json from the page; skips without it
./testnet.sh                              # deploy + verify on testnet (faucet account)
node page/server.mjs & tailscale serve --bg --https=8443 http://127.0.0.1:8787   # capture page
```

### Intel Mac: building the sandbox

near-sandbox 0.4.0 downloads binaries only for linux-x86_64, linux-aarch64 and darwin-arm64. On x86_64 macOS:

```bash
git clone --depth 1 --branch 2.14.0 https://github.com/near/nearcore ~/.nearh-sandbox/nearcore
CC_x86_64_apple_darwin=$PWD/cc-wrap.sh make -C ~/.nearh-sandbox/nearcore sandbox-release
```

Apple clang 17 rejects the `.cfi_*` directives in `blst` 0.3.11's portable-mode assembly
("invalid CFI advance_loc expression"). `cc-wrap.sh` (in this folder; run the commands from `spikes/passkey`) handles `.S` files only:
it preprocesses them with the same flags, drops the `.cfi_*` lines (they carry unwind info only), then assembles.
Every other file goes to `/usr/bin/cc` unchanged. Flags stay quoted (paths with spaces work), a preprocessor
failure is returned as the exit code, and the temp directory is removed on exit. The build takes about 35 minutes on this Mac.

## Open

- Nothing for S-h. For C2: port `verify_webauthn` into `assert_owner` together with the clientDataJSON/rpIdHash/UP/nonce checks that `tests/real_assertion.rs` runs off-chain; a real-passkey regression fixture for C2 needs a capture on a neutral rpId (e.g. `localhost`).
- The owner should confirm Zold-app's deployed `RP_ID` (see above).
