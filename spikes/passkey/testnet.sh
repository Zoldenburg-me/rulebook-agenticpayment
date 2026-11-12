#!/usr/bin/env bash
# S-h spike on NEAR testnet: deploy verify_webauthn and call it with the software
# vector (fixtures/software-vector.json) and, if present, the real passkey assertion
# (fixtures/assertion.json, converted to the contract's encoding).
# Keys: a faucet account in the legacy keychain (~/.near-credentials); never printed.
set -euo pipefail
cd "$(dirname "$0")"

NET=testnet
ACCOUNT=${ACCOUNT:-nearh-sh-$(date +%s).testnet}
WASM=target/near/passkey_spike.wasm

redact() { perl -pe 's/(ed25519|secp256k1)(:|%3A)[1-9A-HJ-NP-Za-km-z]{32,}/$1$2<redacted>/gi' | grep -v -i -E 'seed|private' || true; }
view() { # view <args-json-file> <label>
  printf '%s: ' "$2"
  near contract call-function as-read-only "$ACCOUNT" verify_webauthn json-args "$(cat "$1")" \
    network-config $NET now 2>&1 | redact | grep -E '^(true|false)$|Error|error' || true
}

cargo near build non-reproducible-wasm 2>&1 | grep -E 'SHA-256 checksum hex|successfully'
[ -f fixtures/software-vector.json ] ||
  cargo test --test software_key -- --ignored write_software_vector >/dev/null 2>&1

near account create-account sponsor-by-faucet-service "$ACCOUNT" autogenerate-new-keypair \
  save-to-legacy-keychain network-config $NET create 2>&1 | redact | grep -E 'created|Error' || true
sleep 3
near contract deploy "$ACCOUNT" use-file $WASM without-init-call \
  network-config $NET sign-with-legacy-keychain send 2>&1 | redact | grep -E 'Transaction ID|deployed|Error' || true

echo "account: $ACCOUNT"
view fixtures/software-vector.json "software vector (expect true)"
python3 - fixtures/software-vector.json > /tmp/sh-tampered.json <<'PY'
import base64, json, sys
v = json.load(open(sys.argv[1]))
ad = bytearray(base64.b64decode(v["authenticator_data"])); ad[32] ^= 1
v["authenticator_data"] = base64.b64encode(ad).decode()
print(json.dumps(v))
PY
view /tmp/sh-tampered.json "tampered authData (expect false)"

if [ -f fixtures/assertion.json ]; then
  cargo test --test real_assertion -- --ignored write_contract_args >/dev/null 2>&1
  view fixtures/assertion-contract-args.json "real passkey assertion (expect true)"
fi
