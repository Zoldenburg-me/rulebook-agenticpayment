import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { attestedSigner, recoverPersonalSign, signatureMatches, verifyCompletionSignature } from "./signature.ts";
import { checkScam, type CheckParams } from "./check.ts";

// A live checkScam call to NEAR AI Cloud (the request and response bytes, the completion's signature
// and the model's attestation entry, fields the verifier reads only), recorded 2026-11-09. No key:
// the auth header is never recorded.
const fx = JSON.parse(readFileSync(new URL("../fixtures/nearai-signed-completion.json", import.meta.url), "utf8")) as {
  model: string; nonce: string; request: string; response: string; params: unknown;
  verdict: { result: string; reason: string };
  signature: { text: string; signature: string; signing_address: string; signing_algo: string };
  report: { model_attestations: { model_name: string; signing_address: string; request_nonce: string; intel_quote: string }[] };
};
const SIGNER = fx.signature.signing_address;
const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v));

test("recorded completion: attested signer and signature verify", () => {
  assert.equal(attestedSigner(fx.report, fx.model, fx.nonce), SIGNER);
  assert.equal(recoverPersonalSign(fx.signature.text, fx.signature.signature), SIGNER);
  assert.equal(signatureMatches(fx.signature, SIGNER, fx.model, fx.request, fx.response), true);
});

test("a changed request, response or model breaks the hash check", () => {
  assert.equal(signatureMatches(fx.signature, SIGNER, fx.model, fx.request + " ", fx.response), false);
  assert.equal(signatureMatches(fx.signature, SIGNER, fx.model, fx.request, fx.response.replace('\\"ok\\"', '\\"no\\"')), false);
  assert.equal(signatureMatches(fx.signature, SIGNER, "other/model", fx.request, fx.response), false);
});

test("a signature from another key, or over other text, does not verify", () => {
  assert.equal(signatureMatches(fx.signature, "0x" + "11".repeat(20), fx.model, fx.request, fx.response), false);
  const tampered = { ...fx.signature, signature: fx.signature.signature.slice(0, 10) + (fx.signature.signature[10] === "0" ? "1" : "0") + fx.signature.signature.slice(11) };
  assert.equal(signatureMatches(tampered, SIGNER, fx.model, fx.request, fx.response), false);
  assert.equal(signatureMatches({ ...fx.signature, signing_algo: "ed25519" }, SIGNER, fx.model, fx.request, fx.response), false);
  assert.equal(signatureMatches({ ...fx.signature, signature: "0x1234" }, SIGNER, fx.model, fx.request, fx.response), false);
  assert.equal(signatureMatches({}, SIGNER, fx.model, fx.request, fx.response), false);
});

test("attestation must echo our nonce and bind the signer in the quote's report_data", () => {
  assert.equal(attestedSigner(fx.report, fx.model, "ab".repeat(32)), undefined);
  assert.equal(attestedSigner(fx.report, "other/model", fx.nonce), undefined);
  // The API's signing_address field alone is not trusted: it must match report_data.
  const swapped = clone(fx.report);
  swapped.model_attestations[0].signing_address = "0x" + "11".repeat(20);
  assert.equal(attestedSigner(swapped, fx.model, fx.nonce), undefined);
  // A quote whose report_data was altered.
  const altered = clone(fx.report);
  const q = altered.model_attestations[0].intel_quote;
  const at = (48 + 520) * 2;
  altered.model_attestations[0].intel_quote = q.slice(0, at) + (q[at] === "0" ? "1" : "0") + q.slice(at + 1);
  assert.equal(attestedSigner(altered, fx.model, fx.nonce), undefined);
  assert.equal(attestedSigner({}, fx.model, fx.nonce), undefined);
});

// Serves the recorded completion, echoing whatever nonce the verifier sends into the report and
// the quote's report_data (the recorded quote binds the recorded nonce).
function recordedFetch(opts: { signature?: unknown; signatureStatus?: number } = {}) {
  const calls: string[] = [];
  const fetch = (async (input: string | URL) => {
    const url = new URL(String(input));
    calls.push(url.pathname);
    if (url.pathname.endsWith("/chat/completions")) return new Response(fx.response, { status: 200 });
    if (url.pathname.endsWith("/attestation/report")) {
      const nonce = url.searchParams.get("nonce")!;
      const report = clone(fx.report);
      report.model_attestations[0].request_nonce = nonce;
      report.model_attestations[0].intel_quote = report.model_attestations[0].intel_quote.split(fx.nonce).join(nonce);
      return new Response(JSON.stringify(report), { status: 200 });
    }
    if (url.pathname.startsWith("/v1/signature/")) {
      return new Response(JSON.stringify(opts.signature ?? fx.signature), { status: opts.signatureStatus ?? 200 });
    }
    return new Response(null, { status: 404 });
  }) as typeof globalThis.fetch;
  return { fetch, calls };
}

const base = { baseUrl: "https://cloud-api.near.ai/v1", apiKey: "test-key", model: fx.model,
  chatId: JSON.parse(fx.response).id, request: fx.request, response: fx.response };

test("verifyCompletionSignature: true for the recorded completion, false on any failure", async () => {
  assert.equal(await verifyCompletionSignature({ ...base, fetch: recordedFetch().fetch }), true);
  assert.equal(await verifyCompletionSignature({ ...base, response: fx.response + "\n", fetch: recordedFetch().fetch }), false);
  assert.equal(await verifyCompletionSignature({ ...base, fetch: recordedFetch({ signatureStatus: 404 }).fetch }), false);
  assert.equal(await verifyCompletionSignature({ ...base, fetch: (async () => { throw new Error("offline"); }) as typeof globalThis.fetch }), false);
});

test("checkScam on the recorded call: signature_verified true; a failed verification never changes the verdict", async () => {
  const params = fx.params as CheckParams;
  const ok = { result: fx.verdict.result, reason: fx.verdict.reason, model: fx.model };
  // Replays the live call: checkScam sends byte-identical request JSON, so the signature verifies.
  assert.deepEqual(await checkScam(params, { apiKey: "test-key", model: fx.model, fetch: recordedFetch().fetch }), { ...ok, signature_verified: true });
  // Signature unavailable, or signed over a different request: same verdict, signature_verified false.
  for (const fetch of [recordedFetch({ signatureStatus: 404 }).fetch, recordedFetch({ signature: { ...fx.signature, text: fx.signature.text.replace(/:[0-9a-f]{64}:/, `:${"0".repeat(64)}:`) } }).fetch]) {
    assert.deepEqual(await checkScam(params, { apiKey: "test-key", model: fx.model, fetch }), { ...ok, signature_verified: false });
  }
  const changed = await checkScam({ ...params, memo: "changed" }, { apiKey: "test-key", model: fx.model, fetch: recordedFetch().fetch });
  assert.deepEqual(changed, { ...ok, signature_verified: false });
  // No completion id (as in every mock without one): nothing more is fetched.
  const noId = recordedFetch();
  const bare = (async (input: string | URL, init?: RequestInit) => String(input).endsWith("/chat/completions")
    ? new Response(JSON.stringify({ choices: [{ message: { content: '{"result":"suspicious","reason":"x"}' } }] }), { status: 200 })
    : noId.fetch(input, init)) as typeof globalThis.fetch;
  assert.deepEqual(await checkScam(params, { apiKey: "test-key", model: fx.model, fetch: bare }), { result: "suspicious", reason: "x", model: fx.model, signature_verified: false });
  assert.deepEqual(noId.calls, []);
});
