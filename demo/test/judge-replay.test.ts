// The judge page's replay and server: both stories run with no network and no credential, every
// refusal carries the contract's or the rail's real code, and the server serves only its own files.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { MockMandateContract } from "../src/mock-contract.ts";
import { replay } from "../src/judge-replay.ts";
import { EVIDENCE, judgeServer } from "../src/judge-server.ts";

const realFetch = globalThis.fetch;
const outbound: string[] = [];
before(() => {
  globalThis.fetch = (async (u: any) => {
    outbound.push(String(u));
    throw new Error(`no network in the replay: ${u}`);
  }) as typeof fetch;
});
after(() => {
  globalThis.fetch = realFetch;
});

const codes = (steps: { beat: string; code?: string; outcome: string }[]) => steps.map((s) => [s.beat, s.outcome, s.code ?? null]);
const FULL_EMAIL = /[A-Za-z0-9._%+-]{3,}@[A-Za-z0-9-]+\./;

test("Anya: payout, pay-once, lookalike held and refused, refund, injected ticket held, fooled AI refused", async () => {
  const r = await replay("anya");
  assert.equal(r.mode, "replay");
  assert.deepEqual(codes(r.steps), [
    ["anya-pay", "paid", null],
    ["anya-pay", "refused", "PP3_DUPLICATE_REQUEST"],
    ["anya-poisoned", "held", null],
    ["anya-poisoned", "refused", "ERR_PAYPAL_PAYEE_NOT_ALLOWED"],
    ["anya-refund", "refunded", null],
    ["anya-injected", "held", null],
    ["anya-onchain", "refused", "ERR_OVER_PER_PAYMENT_CAP"],
  ]);
  assert.match(r.steps[5].text, /bulk-refund wording in ticket text/);
  for (const s of r.steps) assert.doesNotMatch(s.text, FULL_EMAIL, "payees are masked");
  assert.deepEqual(outbound, []);
});

test("Hank: fake held and refused, bait over the cap, real card charged, swap refused, revoke", async () => {
  const r = await replay("hank");
  assert.deepEqual(codes(r.steps), [
    ["hank-listings", "info", null],
    ["hank-fake", "held", null],
    ["hank-fake", "refused", "ERR_PAYPAL_PAYEE_NOT_ALLOWED"],
    ["hank-bait", "refused", "ERR_OVER_PER_PAYMENT_CAP"],
    ["hank-buy", "paid", null],
    ["hank-swap", "refused", "PP3_BAD_SIGNATURE"],
    ["hank-revoke", "revoked", null],
    ["hank-revoke", "refused", "ERR_AGENT_REVOKED"],
  ]);
  assert.match(r.steps[4].text, /Charge USD 84\.00 to merchant sa…@cardvault\.example/);
  assert.match(r.steps[6].text, /answers 404/);
  for (const s of r.steps) assert.doesNotMatch(s.text, FULL_EMAIL, "payees are masked");
  assert.deepEqual(outbound, []);
});

test("mock contract shapes 5 and 6: merchant, order_ref, refund cap and budget, shared PayPal budget", () => {
  const now = () => Math.floor(Date.now() / 1000);
  const c = new MockMandateContract("a1", now);
  const rail = (max: string, budget: string) => ({ amount_range: { min: "100", max }, budget, period_secs: 86400 });
  c.ownerSetMandate({ paypal: rail("10000", "15000"), max_validity_secs: 300 }, ["shop@x.example"]);
  const co = (amount: string, payee = "shop@x.example", order_ref = "ORD-1") => ({ payee, amount, order_ref, timestamp: now() });
  assert.deepEqual(c.requestRefund("r0", { capture_id: "ABCDEFGHIJ12", amount: "1.00" }), { ok: false, error: "ERR_SHAPE_NOT_ALLOWED" });
  assert.deepEqual(c.requestCheckout("c1", co("5.00", "shop@x.examp1e")), { ok: false, error: "ERR_PAYPAL_PAYEE_NOT_ALLOWED" });
  assert.deepEqual(c.requestCheckout("c2", co("5.00", "shop@x.example", "bad ref")), { ok: false, error: "ERR_INVALID_ORDER_REF" });
  assert.deepEqual(c.requestCheckout("c3", co("100.01")), { ok: false, error: "ERR_OVER_PER_PAYMENT_CAP" });
  const ok = c.requestCheckout("c4", co("84.00"));
  assert.ok(ok.ok && ok.text.startsWith("Charge USD 84.00 to merchant shop@x.example for order ORD-1 at "));
  assert.deepEqual(c.requestCheckout("c4", co("1.00")), { ok: false, error: "ERR_DUPLICATE_REQUEST_ID" });
  // Shapes 4 and 5 share the PayPal rail's budget: 84 + 67 > 150.
  assert.deepEqual(c.requestSignature("p1", { payee: "shop@x.example", amount: "67.00", timestamp: now() }), { ok: false, error: "ERR_OVER_BUDGET" });

  const d = new MockMandateContract("a2", now);
  d.ownerSetMandate({ paypal: rail("5000", "10000"), paypal_refund: rail("3000", "6000"), max_validity_secs: 300 }, []);
  assert.deepEqual(d.requestRefund("f1", { capture_id: "short", amount: "1.00" }), { ok: false, error: "ERR_INVALID_CAPTURE_ID" });
  assert.deepEqual(d.requestRefund("f2", { capture_id: "ABCDEFGHIJ12", amount: "30.01" }), { ok: false, error: "ERR_OVER_PER_PAYMENT_CAP" });
  const f3 = d.requestRefund("f3", { capture_id: "ABCDEFGHIJ12", amount: "30.00" });
  assert.ok(f3.ok && f3.text === "Refund USD 30.00 of capture ABCDEFGHIJ12 ref f3");
  assert.equal(d.requestRefund("f4", { capture_id: "ABCDEFGHIJ12", amount: "30.00" }).ok, true);
  assert.deepEqual(d.requestRefund("f5", { capture_id: "ABCDEFGHIJ12", amount: "1.00" }), { ok: false, error: "ERR_OVER_BUDGET" });
  d.ownerRevoke();
  assert.deepEqual(d.requestRefund("f6", { capture_id: "ABCDEFGHIJ12", amount: "1.00" }), { ok: false, error: "ERR_AGENT_REVOKED" });
});

test("server: page, evidence allowlist and replay; read-only", async () => {
  const server = judgeServer().listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const get = (p: string, init?: RequestInit) => realFetch(base + p, init);
    const home = await get("/");
    assert.equal(home.status, 200);
    assert.match(home.headers.get("content-security-policy") ?? "", /connect-src 'self'/);
    assert.match(await home.text(), /We built a verifiable rulebook for agentic payments\./);
    assert.equal((await get("/evidence/demo/evidence/pt1-refunds.md")).status, 200);
    for (const p of ["/evidence/.env", "/evidence/package.json", "/evidence/rails/paypal/.env", "/serve.mjs", "/api/replay/nobody"]) assert.equal((await get(p)).status, 404, p);
    assert.equal((await get("/api/replay/anya", { method: "POST" })).status, 405);
    const r = await (await get("/api/replay/hank")).json();
    assert.equal(r.steps.at(-1).code, "ERR_AGENT_REVOKED");
  } finally {
    server.close();
  }
});

test("evidence files and the page hold no credential and no full payee email", () => {
  const root = fileURLToPath(new URL("../../", import.meta.url));
  const page = ["demo/judge/index.html", "demo/judge/app.js", "demo/judge/stories.js"];
  for (const f of [...EVIDENCE, ...page]) {
    const text = readFileSync(root + f, "utf8");
    assert.doesNotMatch(text, /ed25519:[1-9A-HJ-NP-Za-km-z]{40,}|secp256k1:[1-9A-HJ-NP-Za-km-z]{40,}|A21AA[A-Za-z0-9_-]{20,}|Bearer [A-Za-z0-9._-]{20,}|PAYPAL_CLIENT_SECRET=\S|NEAR_AI_API_KEY=\S/, f);
    if (!f.endsWith(".rs") && !f.endsWith(".ts")) assert.doesNotMatch(text, /[A-Za-z0-9._%+-]{3,}@(?!paypal\b)[A-Za-z0-9-]+\.[a-z]/, `${f}: payees masked`);
  }
});
