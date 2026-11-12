# S-e NEAR AI Cloud — Result

**Status: PASS**

## What was tested

Full attestation + response signature verification against `https://cloud-api.near.ai/v1` using `verifyReport` and `verifySignedResponse` from `private-ai/lib/attestation.ts` (a private library, not published).

## Flow

1. List attested models from `/model/list` — **17 attested models** available
2. Pick `deepseek-ai/DeepSeek-V4.1-Flash-1017` (attested)
3. Fetch ECDSA attestation report from `/attestation/report?model=…&provider=near&nonce=…&signing_algo=ecdsa` — **1 model_attestation entry** + gateway_attestation present
4. `verifyReport` checks:
   - nonce echoed ✓
   - signing_algo ecdsa ✓
   - signing address format (20 bytes) ✓
   - TDX quote parses (v4) ✓
   - debug mode off ✓
   - report_data binds signer+nonce ✓
   - GPU evidence nonce ✓
5. Send completion with `x-no-aliasing: true`, preserve exact request/response bytes
6. Fetch response signature from `/signature/{chat_id}?model=…&signing_algo=ecdsa` — **signature_kind: provider_tee**
7. `verifySignedResponse` checks:
   - signature recovers (EIP-191, secp256k1) ✓
   - signer is attested enclave ✓
   - signed hashes match relay hashes (`model:sha256(req):sha256(resp)`) ✓

## Verdict

| Check | Result |
|---|---|---|
| Report verification | ✅ PASS (7/7) |
| Signature verification | ✅ PASS (3/3) |
| **signatureVerified** | ✅ **true** |
| **chainVerified** | ❌ **false** (Intel DCAP TCB/advisory not checked locally) |
| Gateway report | ❌ not verified |
| NVIDIA evidence | ⚠️ nonce match only, payload not parsed |

The NEAR AI Cloud attestation + response signature flow works end-to-end for attested models. The `private-ai` library's `verifyReport` and `verifySignedResponse` functions validate all local checks. Full `chainVerified` requires a DCAP quote verifier (e.g., `dcap-qvl`) which was not run.

## Security notes

- The API key is read from `.env` without `source` (grep + sed), stored in a temp file (mode 600), and fed to curl via `-H @"$TMPDIR/hdr"` — never on the command line.
- Response headers are not printed.
- Temp files are cleaned up by a trap on EXIT.

## Run log

The raw log of the run at head `ed0118e` is not published. All figures cited above (17 attested models, quote parses v4, 7/7 report checks, 3/3 signature checks, `provider_tee`) appear in that log.

## Reproducible command

```bash
cd nearH && bash spikes/nearai/spike.sh
```

Requires: python3, node 22+, the private `private-ai` library cloned at `/tmp/private-ai` at commit `6654709` with `npm install`. The `private-ai` provider wrapper itself was not exercised — only `lib/attestation.ts` is imported directly.

## Fallback

No fallback needed — the attestation flow works. The Privacy & Private AI track can proceed during the hackathon with `chainVerified: false` noted in the README. For production, add DCAP quote verification for complete `chainVerified`.