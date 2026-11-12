#!/usr/bin/env bash
# S-i spike, end to end on NEAR testnet:
#   owner account (faucet) -> contract subaccount -> deploy + init
#   -> delete the deployer's full-access key -> contract adds agent keys A, B
#   -> owner revoke(A) deletes A -> agent B's own key calls revoke_self, deleting B.
# Keys: owner/contract in the legacy keychain (~/.near-credentials), agent keys in
# $KEYDIR (outside the repo). Output is filtered so no private key is ever printed.
set -euo pipefail
cd "$(dirname "$0")"

NET=testnet
OWNER=${OWNER:-nearh-si-$(date +%s).testnet}
CONTRACT=dk.$OWNER
KEYDIR=${KEYDIR:-$HOME/.nearh-spike-deletekey}/$OWNER
WASM=target/near/deletekey_spike.wasm
RPC=https://rpc.testnet.near.org

# Allowlist: only print lines matching known-safe output patterns (SEC-3).
# Everything else is dropped.
SAFE_LINE='^(===|PASS|FAIL|Transaction ID:|  (receipt|tx status)|A=|B=|DELETE_DEPLOY_KEY_TX=|ADD_[AB]_TX=|REVOKE_A_TX=|REVOKE_SELF_B_TX=|ed25519:<redacted>|$|only do .* function calls|\||isn.t allowed by the access key)'
redact() { perl -pe 's/(ed25519|secp256k1)(:|%3A)[1-9A-HJ-NP-Za-km-z]{32,}/$1$2<redacted>/gi' | grep -E "$SAFE_LINE" || true; }
step() { printf '\n=== %s\n' "$*"; }
near_() { near "$@" 2>&1 | redact; }
keys_raw() { near account list-keys "$1" network-config $NET now 2>&1; } # internal only, never echoed
fp() { printf 'ed25519:...%s' "${1: -6}"; } # print form of a public key: last 6 chars only
call() { # call <signer-args...> -- method json
  local method=$1 args=$2; shift 2
  near contract call-function as-transaction "$CONTRACT" "$method" json-args "$args" \
    prepaid-gas '30 Tgas' attached-deposit '0 NEAR' "$@" 2>&1 | redact
}
receipts() { # print every receipt's actions and outcome for a tx hash
  curl -s $RPC -H 'content-type: application/json' -d \
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"EXPERIMENTAL_tx_status\",\"params\":{\"tx_hash\":\"$1\",\"sender_account_id\":\"$2\",\"wait_until\":\"FINAL\"}}" |
  python3 -c '
import json,sys
r=json.load(sys.stdin)["result"]
outs={o["id"]:o["outcome"] for o in r["receipts_outcome"]}
for rc in r["receipts"]:
    a=rc["receipt"].get("Action")
    if not a: continue
    acts=[next(iter(x)) if isinstance(x,dict) else x for x in a["actions"]]
    o=outs[rc["receipt_id"]]
    print("  receipt", rc["receipt_id"][:8], rc["predecessor_id"], "->", rc["receiver_id"], acts,
          "status=" + next(iter(o["status"])), "logs=" + str(o["logs"]))
print("  tx status:", next(iter(r["status"])))'
}
fail() { echo "FAIL: $*" >&2; exit 1; }
expect_keys() { # expect_keys <pk...>: exactly these keys, each function-call only
  local raw n; raw=$(keys_raw "$CONTRACT"); redact <<<"$raw" # compare raw, print redacted
  n=$(grep -c 'ed25519:' <<<"$raw" || true); [ "$n" = "$#" ] || fail "expected $# keys, got $n"
  for k in "$@"; do
    grep -F "$k" <<<"$raw" | grep -qF 'only do ["request_signature", "sweep", "revoke_self"] function calls' ||
      fail "key $(fp "$k") missing or not function-call only"
  done
}
expect_ok() { # expect_ok <tx> <sender>: print receipts, fail unless the tx succeeded
  local out; out=$(receipts "$1" "$2"); echo "$out"
  grep -q 'tx status: SuccessValue' <<<"$out" || fail "tx $1 did not succeed"
}
txid() { grep -o 'Transaction ID: [1-9A-HJ-NP-Za-km-z]*' | tail -1 | cut -d' ' -f3; }

step "build"
cargo near build non-reproducible-wasm 2>&1 | grep -E 'SHA-256 checksum hex|successfully'

step "create owner $OWNER (faucet) and contract account $CONTRACT"
near_ account create-account sponsor-by-faucet-service "$OWNER" autogenerate-new-keypair \
  save-to-legacy-keychain network-config $NET create
sleep 3
near_ account create-account fund-myself "$CONTRACT" '5 NEAR' autogenerate-new-keypair \
  save-to-legacy-keychain sign-as "$OWNER" network-config $NET sign-with-legacy-keychain send

step "deploy + init(owner)"
near_ contract deploy "$CONTRACT" use-file $WASM with-init-call new json-args "{\"owner\":\"$OWNER\"}" \
  prepaid-gas '30 Tgas' attached-deposit '0 NEAR' network-config $NET sign-with-legacy-keychain send

DEPLOY_PK=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['public_key'])" \
  "$HOME/.near-credentials/$NET/$CONTRACT.json")
step "delete the deployer's full-access key $(fp "$DEPLOY_PK")"
OUT=$(near_ account delete-keys "$CONTRACT" public-keys "$DEPLOY_PK" network-config $NET sign-with-legacy-keychain send)
echo "$OUT"; echo "DELETE_DEPLOY_KEY_TX=$(echo "$OUT" | txid)"
rm -f "$HOME/.near-credentials/$NET/$CONTRACT.json" # now a dead key
step "list-keys after deploy (expect none)"
expect_keys

step "generate agent keys A and B in $KEYDIR"
mkdir -p "$KEYDIR/a" "$KEYDIR/b"; chmod 700 "$KEYDIR" "$KEYDIR/a" "$KEYDIR/b" # only our own folder
near account create-account fund-later use-auto-generation save-to-folder "$KEYDIR/a" >/dev/null 2>&1
near account create-account fund-later use-auto-generation save-to-folder "$KEYDIR/b" >/dev/null 2>&1
KA=$(ls "$KEYDIR"/a/*.json); KB=$(ls "$KEYDIR"/b/*.json)
pk() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['public_key'])" "$1"; }
PKA=$(pk "$KA"); PKB=$(pk "$KB"); echo "A=$(fp "$PKA")"; echo "B=$(fp "$PKB")"

OWNER_SIGN=(sign-as "$OWNER" network-config $NET sign-with-legacy-keychain send)
for n in A B; do
  P=$([ $n = A ] && echo "$PKA" || echo "$PKB")
  step "owner add_agent($n)"
  OUT=$(call add_agent "{\"agent\":\"agent-$n\",\"public_key\":\"$P\"}" "${OWNER_SIGN[@]}")
  echo "$OUT"; T=$(echo "$OUT" | txid); echo "ADD_${n}_TX=$T"; expect_ok "$T" "$OWNER"
done
step "list-keys after add_agent (expect A and B, function-call only)"
expect_keys "$PKA" "$PKB"

step "agent B's key calls add_agent (expect near-cli to refuse: method not allowed)"
OUT=$(call add_agent "{\"agent\":\"evil\",\"public_key\":\"$PKA\"}" \
  sign-as "$CONTRACT" network-config $NET sign-with-access-key-file "$KB" send || true)
echo "$OUT"; grep -q "isn't allowed by the access key" <<<"$OUT" || fail "add_agent by agent key was not refused"

step "owner revoke(A): state cleared + delete_key, one tx"
OUT=$(call revoke "{\"public_key\":\"$PKA\"}" "${OWNER_SIGN[@]}")
echo "$OUT"; T=$(echo "$OUT" | txid); echo "REVOKE_A_TX=$T"; expect_ok "$T" "$OWNER"
step "list-keys after revoke(A) (expect B only)"
expect_keys "$PKB"

step "agent B calls revoke_self with its own key"
OUT=$(call revoke_self '{}' sign-as "$CONTRACT" network-config $NET sign-with-access-key-file "$KB" send)
echo "$OUT"; T=$(echo "$OUT" | txid); echo "REVOKE_SELF_B_TX=$T"; expect_ok "$T" "$CONTRACT"
step "list-keys at the end (expect none)"
expect_keys
echo "PASS"
