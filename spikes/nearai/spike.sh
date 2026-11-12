#!/usr/bin/env bash
set -euo pipefail

# S-e: NEAR AI Cloud spike
# Tests: attestation report + per-response signature verification (ECDSA)
# Uses verifyReport + verifySignedResponse from private-ai/lib/attestation.ts (a private library)
# Requirements: python3, node 22+, /tmp/private-ai with npm install done.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="$PROJECT_DIR/.env"
PYAI="/tmp/private-ai"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Safety: reject world-writable or unowned private-ai (SEC-3)
if [ ! -d "$PYAI" ]; then echo "FAIL: $PYAI not found"; exit 1; fi
owner=$(stat -c '%u' "$PYAI" 2>/dev/null || stat -f '%u' "$PYAI" 2>/dev/null || :)
if [ "$owner" != "$(id -u)" ]; then
  echo "FAIL: $PYAI must be owned by the current user"
  exit 1
fi
if [ -n "$(find "$PYAI" -path "$PYAI/node_modules" -prune -o \( -perm -0002 -o -perm -0020 \) -print -quit 2>/dev/null)" ]; then
  echo "FAIL: $PYAI has group- or world-writable files or directories"
  exit 1
fi

# Record SHAs for traceability
NEARH_SHA=$(git -C "$SCRIPT_DIR/../.." rev-parse HEAD 2>/dev/null || echo "unknown")
PYAI_SHA=$(git -C "$PYAI" rev-parse HEAD 2>/dev/null || echo "unknown")

KEY=$(grep -m1 '^NEAR_AI_API_KEY=' "$ENV_FILE" 2>/dev/null | sed 's/^NEAR_AI_API_KEY=//' | sed "s/^['\"]//;s/['\"]$//" || true)
if [ -z "$KEY" ]; then
  echo "FAIL: NEAR_AI_API_KEY not found in $ENV_FILE"
  exit 1
fi
printf 'Authorization: Bearer %s' "$KEY" > "$TMPDIR/hdr"
chmod 600 "$TMPDIR/hdr"

BASE="https://cloud-api.near.ai/v1"

echo "=== S-e NEAR AI Cloud Spike ==="
echo "nearH SHA: $NEARH_SHA"
echo "private-ai SHA: $PYAI_SHA"
echo ""

# 1. Pick attested model
echo "--- Listing attested models ---"
LIST=$(curl -s -H @"$TMPDIR/hdr" -H "Accept: application/json" "$BASE/model/list?limit=500")
MODEL=$(echo "$LIST" | python3 -c "
import sys, json
d = json.load(sys.stdin)
atts = [m['modelId'] for m in d.get('models',[]) if m.get('metadata',{}).get('attestationSupported')]
for p in ['deepseek-ai/DeepSeek-V4.1-Flash-1017','Qwen/Qwen3.8-27B','z-ai/glm-5.3']:
  if p in atts: print(p); exit()
print(atts[0] if atts else '')
")
echo "Attested models available: $(echo "$LIST" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len([m for m in d.get('models',[]) if m.get('metadata',{}).get('attestationSupported')]))")"
echo "Selected: $MODEL"

# 2. Attestation report
NONCE=$(python3 -c "import secrets; print(secrets.token_hex(32))")
curl -s -H @"$TMPDIR/hdr" -H "Accept: application/json" \
  --data-urlencode "model=$MODEL" \
  --data-urlencode "provider=near" \
  --data-urlencode "nonce=$NONCE" \
  --data-urlencode "signing_algo=ecdsa" \
  --data-urlencode "include_tls_fingerprint=false" \
  -G "$BASE/attestation/report" \
  > "$TMPDIR/report.json"
echo "Report received: $(python3 -c "import json; print(len(json.load(open('$TMPDIR/report.json'))['model_attestations']), 'entries')" 2>/dev/null)"

# 3. Send completion (preserve raw bytes - use -d @file not -d "$var")
echo ""
echo "--- Sending completion ---"
printf '%s' "{\"model\":\"${MODEL}\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with exactly the word: pineapple\"}],\"max_tokens\":20}" > "$TMPDIR/req.txt"
HTTP_CODE=$(curl -s -S -w "%{http_code}" \
  -H "Content-Type: application/json" \
  -H "Accept-Encoding: identity" \
  -H "x-no-aliasing: true" \
  -H @"$TMPDIR/hdr" \
  -d @"$TMPDIR/req.txt" \
  -o "$TMPDIR/resp.txt" \
  "$BASE/chat/completions")
echo "HTTP: $HTTP_CODE"
if [ "$HTTP_CODE" != "200" ]; then echo "FAIL: completion returned $HTTP_CODE"; exit 1; fi

CHAT_ID=$(python3 -c "import json; print(json.load(open('$TMPDIR/resp.txt'))['id'])" 2>/dev/null || echo "")
if [ -z "$CHAT_ID" ]; then echo "FAIL: no chat id in response"; exit 1; fi
echo "Chat ID: $CHAT_ID"

# 4. Fetch signature (retry up to 3x)
echo ""
echo "--- Fetching signature ---"
SIG_OK="no"
for i in 1 2 3; do
  curl -s -H @"$TMPDIR/hdr" -H "Accept: application/json" \
    --data-urlencode "model=$MODEL" \
    --data-urlencode "signing_algo=ecdsa" \
    -G "$BASE/signature/$CHAT_ID" > "$TMPDIR/sig.json"
  SIG_OK=$(python3 -c "import json; d=json.load(open('$TMPDIR/sig.json')); print('yes' if d.get('text') else 'no')" 2>/dev/null || echo "no")
  [ "$SIG_OK" = "yes" ] && break
  [ $i -lt 3 ] && sleep 2
done
echo "Signature present: $SIG_OK"
if [ "$SIG_OK" != "yes" ]; then echo "FAIL: no signature returned"; exit 1; fi

# 5. Verify report and signature (MODEL, NONCE, TMPDIR passed as env vars, not code)
echo ""
echo "--- Verification ---"
cd "$PYAI"

set +e
export MODEL NONCE TMPDIR
npx tsx -e "
import { verifyReport, verifySignedResponse } from '/tmp/private-ai/lib/attestation.ts'
import { sha256 } from '@noble/hashes/sha2'
import { bytesToHex } from '@noble/hashes/utils'
import * as fs from 'fs'

const T = process.env.TMPDIR!
const model = process.env.MODEL!
const nonce = process.env.NONCE!

const report = JSON.parse(fs.readFileSync(T + '/report.json','utf8'))
const entries = (report.model_attestations || []) as any[]
const e = entries.find((a: any) => a.model_name === model)
if (!e) { console.log('FAIL: no attestation entry for ' + model); process.exit(1) }
const att = verifyReport(e, nonce)
console.log('report:', att.ok ? 'PASS' : 'FAIL')
att.checks.forEach((c: any) => {
  const detail = c.detail ? (' ' + c.detail) : ''
  console.log(' ', c.ok ? '#' : 'x', c.name + detail)
})
console.log('gateway_attestation present:', (report.gateway_attestation ? 'yes' : 'no'))

if (!att.ok) { console.log('signatureVerified: false'); process.exit(1) }

const sig = JSON.parse(fs.readFileSync(T + '/sig.json','utf8'))
const reqBytes = fs.readFileSync(T + '/req.txt') as Buffer
const respBytes = fs.readFileSync(T + '/resp.txt') as Buffer
const reqSha = bytesToHex(sha256(reqBytes))
const respSha = bytesToHex(sha256(respBytes))

console.log('signature_kind:', sig.signature_kind || '(none)')
const v = verifySignedResponse({ text: sig.text, signature: sig.signature }, att.signingAddress, { reqSha256: reqSha, respSha256: respSha, model: model })
console.log('signature:', v.ok ? 'PASS' : 'FAIL')
v.checks.forEach((c: any) => console.log(' ', c.ok ? '#' : 'x', c.name))
console.log('signatureVerified:', v.ok ? 'true' : 'false')
console.log('chainVerified: false')

if (!v.ok) process.exit(1)
" > "$TMPDIR/tsx_out" 2>&1
TSX_EXIT=$?
set -e

TSX_OUT=$(grep -vE 'Warning|Experimental|ExperimentalWarning|^npm ' < "$TMPDIR/tsx_out" || true)
echo "$TSX_OUT"

if [ "$TSX_EXIT" -ne 0 ]; then
  echo ""
  echo "RESULT: FAIL"
  exit 1
fi

echo ""
echo "RESULT: PASS"
exit 0