// `pnpm demo:paypal --mock` end to end, in-process: no credentials, no network.
import assert from "node:assert/strict";
import { after, test } from "node:test";
import { submitPaypalPayout } from "@nearh/rails-paypal/src/payout.ts";
import { memoryStore } from "@nearh/rails-paypal/src/store.ts";
import { sandboxClient } from "@nearh/rails-paypal/src/paypal.ts";
import { MockMandateContract } from "../src/mock-contract.ts";
import { mockPaypal } from "../src/mock-paypal.ts";
import { livePayPaypal } from "../src/pay-paypal.ts";
import { lookalike, runPaypalDemo } from "../src/paypal-demo.ts";

// The mock injects SC1's settings; it must not touch the environment (PayPal audit 1 C1/H1).
const envBefore = { held: process.env.SCAMCHECK_HELD_DIR, key: process.env.NEAR_AI_API_KEY };
after(() => assert.deepEqual({ held: process.env.SCAMCHECK_HELD_DIR, key: process.env.NEAR_AI_API_KEY }, envBefore));

const now = () => Math.floor(Date.now() / 1000);
const PAYEE = "billing@acme-supplies.example";
const mandate = { paypal: { amount_range: { min: "100", max: "5000" }, budget: "6000", period_secs: 604800 }, max_validity_secs: 300 };

test("mock demo: one payout through the mandate, the poisoned invoice held and refused by the contract", async () => {
  const lines: string[] = [];
  const s = await runPaypalDemo({ mock: true, log: (l) => lines.push(l) });
  assert.equal(s.paid.status, "submitted");
  assert.match(s.paid.payout_batch_id ?? "", /^[A-Z0-9]{13}$/);
  assert.equal(s.paid.scam_check.result, "ok");
  assert.equal(s.poisoned.status, "held");
  assert.equal(s.poisoned.scam_check.result, "suspicious");
  assert.equal(s.poisoned.signed_text, undefined, "a held payment is never signed");
  assert.equal(s.contractOnPoisoned, "ERR_PAYPAL_PAYEE_NOT_ALLOWED");
  assert.deepEqual(s.dashboard.payouts.map((p) => [p.request_id, p.state, p.amount]), [[s.paid.request_id, "submitted", "25.00"]]);
  assert.deepEqual(s.dashboard.held.map((h) => h.request_id), [s.poisoned.request_id]);

  const out = lines.join("\n");
  for (const step of ["[1]", "[2]", "[3]", "[4]", "[5]"]) assert.ok(out.includes(step), `step ${step} narrated`);
  assert.ok(!out.includes("billing@"), "payees are masked in every line");
  assert.ok(!/mock-client-(id|secret)|MOCK-[A-F0-9]{24}|Bearer|Basic /.test(out), "no credential or token is printed");
});

test("lookalike payee: an l in the domain becomes I, else an extra .co label", () => {
  assert.equal(lookalike(PAYEE), "billing@acme-suppIies.example");
  assert.equal(lookalike("sb-x@sandbox.paypal.test"), "sb-x@sandbox.paypaI.test");
  assert.equal(lookalike("sb-x@nearh.dev"), "sb-x@nearh.dev.co");
});

test("mock contract applies the mandate: cap, budget, payee, request_id, revoke", () => {
  const c = new MockMandateContract("agent-1", now);
  const req = (amount: string, payee = PAYEE) => ({ payee, amount, timestamp: now() });
  assert.equal(c.requestSignature("r0", req("1.00")).ok, false, "no mandate yet");
  c.ownerSetMandate(mandate, [PAYEE]);
  assert.deepEqual(c.requestSignature("r1", req("50.01")), { ok: false, error: "ERR_OVER_PER_PAYMENT_CAP" });
  assert.deepEqual(c.requestSignature("r2", req("0.99")), { ok: false, error: "ERR_BELOW_MINIMUM" });
  assert.deepEqual(c.requestSignature("r3", req("5.00", lookalike(PAYEE))), { ok: false, error: "ERR_PAYPAL_PAYEE_NOT_ALLOWED" });
  assert.deepEqual(c.requestSignature("r4", { payee: PAYEE, amount: "5.00", timestamp: now() - 600 }), { ok: false, error: "ERR_TIMESTAMP_STALE" });
  assert.equal(c.requestSignature("r5", req("50.00")).ok, true);
  assert.deepEqual(c.requestSignature("r5", req("1.00")), { ok: false, error: "ERR_DUPLICATE_REQUEST_ID" });
  assert.deepEqual(c.requestSignature("r6", req("10.01")), { ok: false, error: "ERR_OVER_BUDGET" });
  assert.equal(c.requestSignature("r7", req("10.00")).ok, true);
  c.ownerRevoke();
  assert.deepEqual(c.requestSignature("r8", req("1.00")), { ok: false, error: "ERR_AGENT_REVOKED" });
});

test("the real PayPal rail accepts the mock contract's order once and refuses a tampered one before PayPal", async () => {
  const c = new MockMandateContract("agent-1", now);
  c.ownerSetMandate(mandate, [PAYEE]);
  const pp = mockPaypal();
  const deps = { near: c.views(), paypal: sandboxClient({ PAYPAL_ENV: "sandbox", PAYPAL_CLIENT_ID: "id-1234", PAYPAL_CLIENT_SECRET: "secret-1234" }, pp.fetch), store: memoryStore(), now };
  const ts = now();
  const signed = c.requestSignature("r1", { payee: PAYEE, amount: "25.00", timestamp: ts });
  assert.ok(signed.ok);
  const order = { agent: "agent-1", request_id: "r1", payee: PAYEE, amount: "25.00", timestamp: ts, signature: signed.signature };

  const tampered = await submitPaypalPayout(deps, { ...order, amount: "49.00" });
  assert.equal(tampered.status, "blocked");
  assert.equal(pp.payouts.length, 0, "no PayPal payout for a tampered order");

  assert.equal((await submitPaypalPayout(deps, order)).status, "submitted");
  const again = await submitPaypalPayout(deps, order);
  assert.equal(again.status, "blocked");
  assert.equal(pp.payouts.length, 1, "submitted once");
});

test("live mode refuses without a testnet contract, and the live adapter waits for PP4", async () => {
  await assert.rejects(runPaypalDemo({ mock: false, log: () => {}, env: {} }), /CONTRACT_ID/);
  await assert.rejects(runPaypalDemo({ mock: false, log: () => {}, env: { CONTRACT_ID: "mandate.near" } }), /testnet/i);
  await assert.rejects(livePayPaypal(), /PP4/);
});
