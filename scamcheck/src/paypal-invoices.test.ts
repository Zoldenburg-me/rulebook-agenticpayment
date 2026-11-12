// PP4's poisoned-invoice inputs (fixtures/paypal-invoices.json) run through the scam check as the
// agent would pass a PayPal invoice. Each poisoned invoice is the baseline with a few fields
// changed. Every one must be `suspicious` from the deterministic rules alone, before the model,
// even when the model would answer ok.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkScam, type CheckParams, type PayeeEntry } from "./check.ts";

type BuyerInvoice = {
  invoice_id: string;
  invoice_number: string;
  status: string;
  amount: { currency: "USD"; value: string };
  payee: string;
  due_date: string;
  description: string;
  payer_view_url: string | null;
};
type Fixtures = {
  context: { allowlisted_payees: string[]; payee_history: PayeeEntry[] };
  baseline: BuyerInvoice;
  poisoned: { name: string; attack: string; invoice: Partial<BuyerInvoice> }[];
};

const fixtures: Fixtures = JSON.parse(readFileSync(new URL("../fixtures/paypal-invoices.json", import.meta.url), "utf8"));
const poisoned = (name: string): BuyerInvoice => {
  const p = fixtures.poisoned.find((f) => f.name === name);
  if (!p) throw new Error(`no fixture ${name}`);
  return { ...fixtures.baseline, ...p.invoice };
};

/** CheckParams for a PayPal invoice, as the agent passes it. */
function toCheckParams(inv: BuyerInvoice): CheckParams {
  return {
    agent: "agent-1",
    rail: "paypal",
    request_id: inv.invoice_id,
    shape: { type: "paypal", payee: inv.payee, amount: inv.amount.value },
    memo: `PayPal invoice ${inv.invoice_number}`,
    invoice: {
      text: `${inv.description}\nPay to: ${inv.payee}\nAmount: USD ${inv.amount.value}\nDue: ${inv.due_date}`,
      source: `paypal-invoice:${inv.invoice_id}`,
    },
    payee_known: fixtures.context.allowlisted_payees.includes(inv.payee.toLowerCase()),
    payee_history: fixtures.context.payee_history,
  };
}

/** A model that always answers ok: a suspicious verdict can only come from the deterministic rules. */
let modelCalls = 0;
const okModel = (async () => {
  modelCalls++;
  return new Response(JSON.stringify({ choices: [{ message: { content: '{"result":"ok","reason":"looks fine"}' } }] }), { status: 200 });
}) as typeof globalThis.fetch;

async function withKey<T>(fn: () => Promise<T>): Promise<T> {
  const prev = process.env.NEAR_AI_API_KEY;
  process.env.NEAR_AI_API_KEY = "test-key";
  try {
    return await fn();
  } finally {
    if (prev === undefined) delete process.env.NEAR_AI_API_KEY;
    else process.env.NEAR_AI_API_KEY = prev;
  }
}

const NOW = () => Date.parse("2026-11-06T12:00:00Z");

test("baseline PayPal invoice passes the deterministic rules and reaches the model", async () => {
  modelCalls = 0;
  const v = await withKey(() => checkScam(toCheckParams(fixtures.baseline), { fetch: okModel, now: NOW }));
  assert.equal(v.result, "ok");
  assert.equal(modelCalls, 1);
});

// [fixture, reason with the agent's payee_known, reason if the agent wrongly marks the payee known]
const caught: [string, RegExp, RegExp][] = [
  ["changed_payee", /unknown payee/, /changed PayPal payee/],
  ["lookalike_payee", /unknown payee/, /lookalike PayPal payee/],
  ["lookalike_payee_domain", /unknown payee/, /lookalike PayPal payee/],
  ["urgency_wording", /urgency/, /urgency/],
  ["social_engineering", /social-engineering/, /social-engineering/],
  ["amount_spike", /amount spike: 2500 vs typical 25/, /amount spike/],
];
for (const [name, reason, reasonIfKnown] of caught) {
  test(`poisoned PayPal invoice ${name} is suspicious before the model`, async () => {
    modelCalls = 0;
    const v = await withKey(() => checkScam(toCheckParams(poisoned(name)), { fetch: okModel, now: NOW }));
    assert.equal(v.result, "suspicious");
    assert.match(v.reason!, reason);
    assert.equal(modelCalls, 0);
  });
  test(`poisoned PayPal invoice ${name} is suspicious even if the agent marks the payee known`, async () => {
    modelCalls = 0;
    const params = { ...toCheckParams(poisoned(name)), payee_known: true };
    const v = await withKey(() => checkScam(params, { fetch: okModel, now: NOW }));
    assert.equal(v.result, "suspicious");
    assert.match(v.reason!, reasonIfKnown);
    assert.equal(modelCalls, 0);
  });
}

test("every poisoned fixture is covered here", () => {
  assert.deepEqual(fixtures.poisoned.map((f) => f.name).sort(), caught.map(([n]) => n).sort());
});
