// PP-W1 receiver tests, offline: PayPal is the sandbox client over a fake fetch; the store is PP3's
// memory store. Every event must pass PayPal's verify call before anything is reported.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { SANDBOX_BASE, sandboxClient } from "../src/paypal.ts";
import { memoryStore, type OrderRecord } from "../src/store.ts";
import { trickle } from "./trickle.ts";
import { EVENT_STATUS, handleWebhook, memorySeen, verifyBody, webhookServer, type Report, type WebhookDeps } from "../src/webhook.ts";

const WEBHOOK_ID = "8PT597110X687430LKGECATA";
const SECRET = "sk-test-secret-value-0000000000";
const HEADERS = {
  "paypal-auth-algo": "SHA256withRSA",
  "paypal-cert-url": "https://api.sandbox.paypal.com/v1/notifications/certs/CERT-360caa42-fca2a594-a5cafa77",
  "paypal-transmission-id": "103e3700-8b0c-11e6-8695-6b62a8a99ac4",
  "paypal-transmission-sig": "t8hlRk64rpEImZMKqgtp5dlWaT1W8ed/mf8Msos341QInVn3BMQubjAhM/cxP2Ou+0ZtbXe7Xkb1Dk+JG9lM0g==",
  "paypal-transmission-time": "2026-11-09T12:00:00Z",
};

let verifyAnswer: { status: number; body: unknown } | "throw";
let verifyCalls: string[];
let reports: Report[];
let reportFails: boolean;
let store: ReturnType<typeof memoryStore>;
let logs: string[];

function client() {
  const fetcher = (async (url: string, init: RequestInit) => {
    assert.ok(url.startsWith(SANDBOX_BASE));
    const path = new URL(url).pathname;
    if (path === "/v1/oauth2/token") return new Response(JSON.stringify({ access_token: "A21AAtoken", expires_in: 32400 }), { status: 200 });
    assert.equal(path, "/v1/notifications/verify-webhook-signature");
    verifyCalls.push(String(init.body));
    if (verifyAnswer === "throw") throw new Error("socket hang up");
    return new Response(JSON.stringify(verifyAnswer.body), { status: verifyAnswer.status });
  }) as typeof fetch;
  return sandboxClient({ PAYPAL_ENV: "sandbox", PAYPAL_CLIENT_ID: "client-id-xyz", PAYPAL_CLIENT_SECRET: SECRET }, fetcher);
}

function deps(over: Partial<WebhookDeps> = {}): WebhookDeps {
  return {
    paypal: client(),
    webhookId: WEBHOOK_ID,
    store,
    agents: ["agent-a", "agent-b"],
    seen: memorySeen(),
    report: async (r) => {
      if (reportFails) throw new Error("near tx failed");
      reports.push(r);
    },
    log: (l) => logs.push(l),
    secrets: [SECRET],
    ...over,
  };
}

const record = (over: Partial<OrderRecord> = {}): OrderRecord => ({
  agent: "agent-a", request_id: "inv-1", state: "submitted", payee_masked: "su…@example.com", amount: "1.00", at: "2026-11-09T12:00:00.000Z",
  payout_batch_id: "XGE5TQPUBA9ZA", ...over,
});

/** A payout item event as PayPal sends it (spacing kept, so re-serialising would change the bytes). */
const itemEvent = (type = "PAYMENT.PAYOUTS-ITEM.SUCCEEDED", over: Record<string, unknown> = {}) =>
  `{"id": "WH-7Y7254563A4550640-11V2185806837105M", "event_type": "${type}", "resource_type": "payouts_item",
   "resource": {"payout_item_id": "2EFQSDXLAMXKU", "transaction_status": "SUCCESS", "payout_batch_id": "XGE5TQPUBA9ZA",
   "payout_item": {"sender_item_id": "inv-1", "receiver": "supplier@example.com", "amount": {"value": "1.00", "currency": "USD"}}, ${Object.entries(over).map(([k, v]) => `"${k}": ${JSON.stringify(v)}`).join(", ")}
   "links": []}}`;

beforeEach(() => {
  verifyAnswer = { status: 200, body: { verification_status: "SUCCESS" } };
  verifyCalls = [];
  reports = [];
  reportFails = false;
  store = memoryStore();
  store.claim(record());
  logs = [];
});

test("a verified payout item event is reported for the PP3 order it names", async () => {
  const out = await handleWebhook(deps(), HEADERS, itemEvent());
  assert.deepEqual(out, { status: 200, result: "reported_completed" });
  assert.deepEqual(reports, [{ agent: "agent-a", request_id: "inv-1", status: "completed", paypal_id: "2EFQSDXLAMXKU" }]);
  assert.ok(!logs.join("\n").includes("supplier@example.com"), "no payee in the log");
});

test("the verify call carries the raw body byte for byte, the webhook id and the five headers", async () => {
  const raw = itemEvent();
  await handleWebhook(deps(), HEADERS, raw);
  assert.equal(verifyCalls.length, 1);
  const sent = verifyCalls[0];
  assert.ok(sent.endsWith(`"webhook_event":${raw}}`), "event embedded as received");
  const parsed = JSON.parse(sent);
  assert.equal(parsed.webhook_id, WEBHOOK_ID);
  assert.equal(parsed.auth_algo, HEADERS["paypal-auth-algo"]);
  assert.equal(parsed.cert_url, HEADERS["paypal-cert-url"]);
  assert.equal(parsed.transmission_id, HEADERS["paypal-transmission-id"]);
  assert.equal(parsed.transmission_sig, HEADERS["paypal-transmission-sig"]);
  assert.equal(parsed.transmission_time, HEADERS["paypal-transmission-time"]);
  // A header value cannot break out of its string.
  const evil = verifyBody({ ...HEADERS, "paypal-auth-algo": '","webhook_id":"X' }, WEBHOOK_ID, "{}");
  assert.equal(JSON.parse(evil).webhook_id, WEBHOOK_ID);
});

test("fail closed: unverified, missing headers or bad JSON are dropped and never reported", async () => {
  for (const body of [{ verification_status: "FAILURE" }, {}, { name: "VALIDATION_ERROR" }]) {
    verifyAnswer = { status: 200, body };
    assert.deepEqual(await handleWebhook(deps(), HEADERS, itemEvent()), { status: 400, result: "unverified" });
  }
  verifyAnswer = { status: 400, body: { name: "VALIDATION_ERROR" } };
  assert.equal((await handleWebhook(deps(), HEADERS, itemEvent())).result, "unverified");
  for (const k of Object.keys(HEADERS)) {
    const h: Record<string, string | undefined> = { ...HEADERS, [k]: undefined };
    verifyCalls = [];
    assert.deepEqual(await handleWebhook(deps(), h, itemEvent()), { status: 400, result: "unverified" });
    assert.deepEqual(verifyCalls, [], `no verify call without ${k}`);
  }
  for (const raw of ["not json", "[]", "null"]) {
    assert.equal((await handleWebhook(deps(), HEADERS, raw)).status, 400);
  }
  assert.deepEqual(reports, []);
});

test("verify unavailable is a 5xx (PayPal redelivers) and nothing is reported or marked seen", async () => {
  const seen = memorySeen();
  verifyAnswer = "throw";
  assert.deepEqual(await handleWebhook(deps({ seen }), HEADERS, itemEvent()), { status: 503, result: "verify_unavailable" });
  verifyAnswer = { status: 503, body: {} };
  assert.deepEqual(await handleWebhook(deps({ seen }), HEADERS, itemEvent()), { status: 503, result: "verify_unavailable" });
  assert.deepEqual(reports, []);
  verifyAnswer = { status: 200, body: { verification_status: "SUCCESS" } };
  assert.equal((await handleWebhook(deps({ seen }), HEADERS, itemEvent())).result, "reported_completed");
});

test("each event type maps to its settlement status; adverse ones are reported as such", async () => {
  for (const [type, status] of Object.entries(EVENT_STATUS).filter(([t]) => t.startsWith("PAYMENT.PAYOUTS-ITEM."))) {
    reports = [];
    const out = await handleWebhook(deps(), HEADERS, itemEvent(type));
    assert.equal(out.result, `reported_${status}`, type);
    assert.equal(reports[0].status, status);
  }
  assert.equal(EVENT_STATUS["PAYMENT.CAPTURE.REVERSED"], "reversed");
  assert.equal(EVENT_STATUS["CUSTOMER.DISPUTE.CREATED"], "disputed");
});

test("a redelivered event is reported once", async () => {
  const d = deps();
  await handleWebhook(d, HEADERS, itemEvent());
  assert.deepEqual(await handleWebhook(d, HEADERS, itemEvent()), { status: 200, result: "duplicate" });
  assert.equal(reports.length, 1);
});

test("a failed report is a 500 and the event is not marked handled, so the redelivery reports it", async () => {
  const d = deps();
  reportFails = true;
  assert.deepEqual(await handleWebhook(d, HEADERS, itemEvent()), { status: 500, result: "report_failed" });
  reportFails = false;
  assert.equal((await handleWebhook(d, HEADERS, itemEvent())).result, "reported_completed");
});

test("an event that matches no submitted PP3 order is ignored", async () => {
  // Another batch id for the same request_id (not our payout).
  store.update(record({ payout_batch_id: "OTHERBATCH01" }));
  assert.equal((await handleWebhook(deps(), HEADERS, itemEvent())).result, "no_order");
  // An order that never got past `unknown`.
  store.update(record({ state: "unknown" }));
  assert.equal((await handleWebhook(deps(), HEADERS, itemEvent().replace("WH-7Y", "WH-8Y"))).result, "no_order");
  // An agent PP3 does not serve.
  store.update(record());
  assert.equal((await handleWebhook(deps({ agents: ["agent-b"] }), HEADERS, itemEvent().replace("WH-7Y", "WH-9Y"))).result, "no_order");
  // A non-settlement event type.
  assert.equal((await handleWebhook(deps(), HEADERS, itemEvent("PAYMENT.PAYOUTSBATCH.SUCCESS"))).result, "ignored");
  assert.deepEqual(reports, []);
});

test("capture and dispute events report only when they name a submitted order", async () => {
  const capture = (type: string, custom_id?: string) =>
    JSON.stringify({ id: `WH-C-${type.replaceAll(".", "-")}`, event_type: type, resource: { id: "8MC585209K746392H", ...(custom_id ? { custom_id } : {}) } });
  assert.equal((await handleWebhook(deps(), HEADERS, capture("PAYMENT.CAPTURE.REVERSED"))).result, "no_order");
  assert.equal((await handleWebhook(deps(), HEADERS, capture("PAYMENT.CAPTURE.REFUNDED", "inv-1"))).result, "reported_refunded");
  const dispute = JSON.stringify({
    id: "WH-D-1", event_type: "CUSTOMER.DISPUTE.CREATED",
    resource: { dispute_id: "PP-D-27803", disputed_transactions: [{ invoice_number: "inv-1" }] },
  });
  assert.equal((await handleWebhook(deps(), HEADERS, dispute)).result, "reported_disputed");
  assert.deepEqual(reports.map((r) => [r.status, r.paypal_id]), [["refunded", "8MC585209K746392H"], ["disputed", "PP-D-27803"]]);
  // The same request_id for two agents is ambiguous without a batch id: ignored, not guessed.
  store.claim(record({ agent: "agent-b" }));
  assert.equal((await handleWebhook(deps(), HEADERS, capture("PAYMENT.CAPTURE.REVERSED", "inv-1").replace("WH-C-", "WH-C2-"))).result, "no_order");
});

test("a webhook body that trickles or stalls is 408 within the deadline and reports nothing (PayPal audit 2 M1)", async () => {
  const reported: Report[] = [];
  const s = webhookServer({ ...deps(), report: async (r) => void reported.push(r) }, { bodyTimeoutMs: 300, idleTimeoutMs: 150 });
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const port = (s.address() as any).port;
  const head = "POST /paypal/webhook HTTP/1.1\r\nhost: x\r\ncontent-length: 1000\r\n\r\n";
  try {
    for (const every of [50, 60_000]) {
      const { answer, ms } = await trickle(port, head, every);
      assert.match(answer, /^HTTP\/1\.1 408 /);
      assert.ok(ms < 2_000, `${ms} ms`);
    }
    assert.match((await trickle(port, head.replace("1000", "70000"), 60_000)).answer, /^HTTP\/1\.1 413 /);
    assert.deepEqual(reported, []);
  } finally {
    s.close();
  }
  const d = webhookServer(deps());
  assert.ok(d.requestTimeout > 0 && d.requestTimeout <= 15_000 && d.headersTimeout > 0 && d.headersTimeout <= d.requestTimeout);
});

test("the HTTP route: POST /paypal/webhook only, body limit, verification result as status", async () => {
  const s = webhookServer(deps());
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(s.address() as any).port}`;
  try {
    assert.equal((await fetch(`${base}/other`, { method: "POST", body: "{}" })).status, 404);
    assert.equal((await fetch(`${base}/paypal/webhook`)).status, 404);
    assert.equal((await fetch(`${base}/paypal/webhook`, { method: "POST", body: "x".repeat(70_000) })).status, 413);
    assert.equal((await fetch(`${base}/paypal/webhook`, { method: "POST", body: itemEvent() })).status, 400);
    const ok = await fetch(`${base}/paypal/webhook`, { method: "POST", headers: HEADERS, body: itemEvent() });
    assert.equal(ok.status, 200);
    assert.deepEqual(await ok.json(), { result: "reported_completed" });
  } finally {
    s.close();
  }
});
