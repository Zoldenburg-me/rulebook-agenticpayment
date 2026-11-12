// PP-T1 refunds with NEAR and PayPal mocked: the contract views are an in-memory `Near`, PayPal is
// the sandbox client over a fake fetch that keeps one capture's refunds and records every call.
// Signatures are real secp256k1 signatures over the EIP-191 digest of the shape 6 text.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import type { AddressInfo } from "node:net";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { publicKeyToAddress } from "@nearh/owner-near/src/derive.ts";
import { SANDBOX_BASE, sandboxClient } from "../src/paypal.ts";
import { eip191Digest, type Reservation } from "../src/payout.ts";
import { refundMessage, refundRequestId, submitRefund, type RefundDeps, type RefundOrder } from "../src/refund.ts";
import { refundServer } from "../src/refund-server.ts";
import { memoryStore, type Store } from "../src/store.ts";
import { MANDATED_TOOL, READ_TOOLS, toolkit } from "../src/toolkit.ts";

const AGENT = "support-1";
const CAPTURE = "4E871663M29867546";
const OTHER = "5RT48122BA4404726";
const ORDER = "3M977226H0197750E";
const NOW = 1_793_831_226;
const KEY = secp256k1.utils.randomSecretKey();
const ADDRESS = publicKeyToAddress(secp256k1.getPublicKey(KEY, false));
const CLIENT_ID = "client-id-do-not-print-3e1d";
const SECRET = "client-secret-do-not-print-7f3a";
const TOKEN = "access-token-do-not-print-91bc";

function sign(t: string, key = KEY) {
  const sig = secp256k1.sign(eip191Digest(t), key, { prehash: false, format: "recovered" });
  return { r: `0x${bytesToHex(sig.slice(1, 33))}`, s: `0x${bytesToHex(sig.slice(33))}`, v: 27 + sig[0] };
}

const text = (amount = "4.00", capture = CAPTURE, id = "rf-1") => refundMessage(amount, capture, id);

function reservation(t = text(), over: Partial<Reservation> = {}, id = "rf-1"): Reservation {
  return {
    key: { agent: AGENT, caller: { kind: "agent" }, request_id: id },
    shape: "refund",
    rail: "paypal_refund",
    valid_before: NOW + 240,
    digest: `0x${bytesToHex(eip191Digest(t))}`,
    payload: { kind: "message", text: t },
    status: "signed",
    signature: sign(t),
    ...over,
  };
}

type Refund = { id: string; status: string; amount: { value: string; currency_code: string }; links: { rel: string; href: string }[] };
const refundOf = (capture: string, value: string, status = "COMPLETED", id = `R${Math.random().toString().slice(2, 17)}`): Refund =>
  ({ id, status, amount: { value, currency_code: "USD" }, links: [{ rel: "up", href: `https://api.sandbox.paypal.com/v2/payments/captures/${capture}` }] });

let chain: { agent: any; requests: Map<string, Reservation> };
let calls: { method: string; path: string; headers: Record<string, string>; body: any }[];
let pp: { capture: any; captureStatus: number; orderStatus: number; refunds: Refund[]; post: "ok" | "throw" | { status: number; body?: any }; token: number };
let logs: string[];

function fakePaypal() {
  const fetcher = (async (url: string, init: RequestInit) => {
    assert.ok(url.startsWith(SANDBOX_BASE), "only the sandbox is ever called");
    const path = new URL(url).pathname;
    const method = String(init.method);
    calls.push({ method, path, headers: init.headers as Record<string, string>, body: path === "/v1/oauth2/token" ? String(init.body) : init.body ? JSON.parse(String(init.body)) : undefined });
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
    if (path === "/v1/oauth2/token") return json(pp.token, pp.token === 200 ? { access_token: TOKEN, expires_in: 32400 } : { error: "invalid_client" });
    if (method === "GET" && path === `/v2/payments/captures/${CAPTURE}`) {
      const refunded = pp.refunds.filter((r) => r.links[0].href.endsWith(CAPTURE) && r.status === "COMPLETED").length > 0;
      return json(pp.captureStatus, { status: refunded ? "PARTIALLY_REFUNDED" : "COMPLETED", ...pp.capture });
    }
    if (method === "GET" && path.startsWith("/v2/payments/captures/")) return json(404, { name: "RESOURCE_NOT_FOUND" });
    if (method === "GET" && path === `/v2/checkout/orders/${ORDER}`) {
      return json(pp.orderStatus, { id: ORDER, purchase_units: [{ payments: { captures: [{ id: CAPTURE }, { id: OTHER }], refunds: pp.refunds } }] });
    }
    if (method === "GET" && path.startsWith("/v2/payments/refunds/")) {
      const r = pp.refunds.find((x) => path.endsWith(`/${x.id}`));
      return r ? json(200, r) : json(404, { name: "RESOURCE_NOT_FOUND" });
    }
    if (method === "POST" && path === `/v2/payments/captures/${CAPTURE}/refund`) {
      if (pp.post === "throw") throw new Error(`socket hang up, bearer ${TOKEN}`);
      if (pp.post !== "ok") return json(pp.post.status, pp.post.body ?? {});
      const body = JSON.parse(String(init.body));
      const r = refundOf(CAPTURE, body.amount.value, "COMPLETED", `7X${pp.refunds.length}856342N1619400`);
      pp.refunds.push(r);
      return json(201, r);
    }
    return json(404, {});
  }) as typeof fetch;
  return sandboxClient({ PAYPAL_ENV: "sandbox", PAYPAL_CLIENT_ID: CLIENT_ID, PAYPAL_CLIENT_SECRET: SECRET }, fetcher);
}

function deps(store: Store = memoryStore(), now = NOW): RefundDeps {
  return {
    near: {
      getAgent: async (agent) => (agent === AGENT ? chain.agent : null),
      getRequest: async (key) => chain.requests.get(key.request_id) ?? null,
      getPayees: async () => [],
      getSuspendedPayees: async () => [],
    },
    paypal: fakePaypal(),
    store,
    now: () => now,
    log: (l) => logs.push(l),
    secrets: [CLIENT_ID, SECRET],
  };
}

const order = (over: Partial<RefundOrder> = {}): RefundOrder => ({ agent: AGENT, request_id: "rf-1", capture_id: CAPTURE, amount: "4.00", signature: sign(text()), ...over });
const posts = () => calls.filter((c) => c.method === "POST" && c.path.endsWith("/refund"));
const paypalCalls = () => calls.filter((c) => c.path !== "/v1/oauth2/token");
const code = (r: unknown) => (r as any).error_code;

beforeEach(() => {
  chain = { agent: { evm_address: ADDRESS, revoked: false }, requests: new Map([["rf-1", reservation()]]) };
  calls = [];
  logs = [];
  pp = {
    capture: { id: CAPTURE, amount: { currency_code: "USD", value: "12.00" }, supplementary_data: { related_ids: { order_id: ORDER } } },
    captureStatus: 200,
    orderStatus: 200,
    refunds: [],
    post: "ok",
    token: 200,
  };
});

test("the message and digest are refund.rs's happy_path vector", () => {
  const t = refundMessage("4.00", CAPTURE, "refund-0001");
  assert.equal(t, "Refund USD 4.00 of capture 4E871663M29867546 ref refund-0001");
  assert.equal(bytesToHex(eip191Digest(t)), "2e3ba4ba32bf1c828ac702efb64d757e9aad22437c76ec48639752bb4d6f94ed");
});

test("a signed refund within what the capture has left is posted once, idempotently, and recorded", async () => {
  const store = memoryStore();
  const r = await submitRefund(deps(store), order());
  assert.deepEqual(r, { status: "refunded", request_id: "rf-1", capture_id: CAPTURE, amount: "4.00", refund_id: "7X0856342N1619400", refund_status: "COMPLETED" });
  assert.deepEqual(paypalCalls().map((c) => `${c.method} ${c.path}`), [
    `GET /v2/payments/captures/${CAPTURE}`,
    `GET /v2/checkout/orders/${ORDER}`,
    `POST /v2/payments/captures/${CAPTURE}/refund`,
  ]);
  const p = posts()[0];
  assert.deepEqual(p.body, { amount: { value: "4.00", currency_code: "USD" }, note_to_payer: "ref rf-1" });
  assert.equal(p.headers["PayPal-Request-Id"], refundRequestId(AGENT, "rf-1"));
  assert.match(refundRequestId(AGENT, "rf-1"), /^[0-9a-f]{64}$/);
  assert.notEqual(refundRequestId(AGENT, "rf-1"), refundRequestId("support-2", "rf-1"));
  const rec = store.get(AGENT, "rf-1") as any;
  assert.equal(rec.state, "submitted");
  assert.equal(rec.refund_id, "7X0856342N1619400");
  assert.equal(rec.capture_id, CAPTURE);
  assert.ok(!logs.join("\n").includes(TOKEN) && !JSON.stringify(rec).includes(TOKEN));
});

for (const [name, over] of [
  ["amount", { amount: "9.00" }],
  ["capture", { capture_id: OTHER }],
  ["request_id", { request_id: "rf-2" }],
  ["signature (another key)", { signature: sign(text(), secp256k1.utils.randomSecretKey()) }],
  ["signature (a shape 4 payout text)", { signature: sign("Send USD 4.00 to supplier@example.com at 2026-11-04T22:27:06Z ref rf-1") }],
  ["signature (malformed)", { signature: { r: "0xzz", s: "0x01", v: 27 } }],
] as const) {
  test(`a tampered ${name} is refused before any PayPal call`, async () => {
    chain.requests.set("rf-2", reservation(text("4.00", CAPTURE, "rf-2"), {}, "rf-2"));
    const store = memoryStore();
    const r = await submitRefund(deps(store), order(over as Partial<RefundOrder>));
    assert.equal(code(r), "PP3_BAD_SIGNATURE");
    assert.deepEqual(calls, [], "zero PayPal calls, not even the token");
    assert.equal(store.records.size, 0);
  });
}

test("reservations that are not a signed shape 6 refund of this text are refused before PayPal", async () => {
  const cases: [() => void, string][] = [
    [() => chain.requests.delete("rf-1"), "PP3_REQUEST_NOT_FOUND"],
    [() => chain.requests.set("rf-1", reservation(text(), { shape: "paypal", rail: "paypal" })), "PP3_NOT_A_REFUND"],
    [() => chain.requests.set("rf-1", reservation(text(), { rail: "paypal" })), "PP3_NOT_A_REFUND"],
    [() => chain.requests.set("rf-1", reservation(text(), { status: "pending", signature: null })), "PP3_NOT_SIGNED"],
    [() => chain.requests.set("rf-1", reservation(text(), { status: "released" })), "PP3_NOT_SIGNED"],
    [() => chain.requests.set("rf-1", reservation(text("3.00"))), "PP3_ORDER_MISMATCH"],
    [() => chain.requests.set("rf-1", reservation(text(), { digest: `0x${"00".repeat(32)}` })), "PP3_BAD_SIGNATURE"],
    [() => chain.requests.set("rf-1", reservation(text(), { valid_before: NOW - 1 })), "PP3_ORDER_EXPIRED"],
    [() => (chain.agent = { evm_address: ADDRESS, revoked: true }), "PP3_AGENT_REVOKED"],
    [() => (chain.agent = null), "PP3_UNKNOWN_AGENT"],
  ];
  for (const [arrange, want] of cases) {
    chain = { agent: { evm_address: ADDRESS, revoked: false }, requests: new Map([["rf-1", reservation()]]) };
    calls = [];
    arrange();
    assert.equal(code(await submitRefund(deps(), order())), want, want);
    assert.deepEqual(calls, [], `${want}: no PayPal call`);
  }
});

test("non-canonical input is refused as is, nothing rewritten", async () => {
  for (const over of [{ amount: "4" }, { amount: "04.00" }, { amount: "0.00" }, { capture_id: CAPTURE.toLowerCase() }, { capture_id: `${CAPTURE}/refund` }, { capture_id: "../../v1/payments/payouts" }, { request_id: "a b" }, { agent: "" }, { signature: undefined as any }]) {
    assert.equal(code(await submitRefund(deps(), order(over))), "PP3_INVALID_INPUT", JSON.stringify(over));
  }
  assert.deepEqual(calls, []);
});

test("more than captured minus already refunded is refused before the POST, and nothing is claimed", async () => {
  // 12.00 captured; 3.00 completed and 1.00 pending count; a failed one and another capture's do not.
  pp.refunds = [refundOf(CAPTURE, "3.00"), refundOf(CAPTURE, "1.00", "PENDING"), refundOf(CAPTURE, "5.00", "FAILED"), refundOf(OTHER, "7.00")];
  const t = text("8.01");
  chain.requests.set("rf-1", reservation(t));
  const store = memoryStore();
  const r = await submitRefund(deps(store), order({ amount: "8.01", signature: sign(t) }));
  assert.equal(code(r), "PP3_REFUND_EXCEEDS_CAPTURE");
  assert.match((r as any).detail, /captured USD 12\.00, refunded 4\.00, 8\.00 left/);
  assert.equal(posts().length, 0);
  assert.equal(store.records.size, 0);
  // Exactly what is left goes through.
  const t2 = text("8.00", CAPTURE, "rf-2");
  chain.requests.set("rf-2", reservation(t2, {}, "rf-2"));
  assert.equal((await submitRefund(deps(store), order({ request_id: "rf-2", amount: "8.00", signature: sign(t2) }))).status, "refunded");
});

test("two concurrent refunds of one capture cannot both pass the check", async () => {
  const t1 = text("7.00", CAPTURE, "rf-1");
  const t2 = text("7.00", CAPTURE, "rf-2");
  chain.requests.set("rf-1", reservation(t1));
  chain.requests.set("rf-2", reservation(t2, {}, "rf-2"));
  const d = deps();
  const [a, b] = await Promise.all([
    submitRefund(d, order({ amount: "7.00", signature: sign(t1) })),
    submitRefund(d, order({ request_id: "rf-2", amount: "7.00", signature: sign(t2) })),
  ]);
  assert.deepEqual([a.status, b.status].sort(), ["blocked", "refunded"]);
  assert.equal(code([a, b].find((x) => x.status === "blocked")), "PP3_REFUND_EXCEEDS_CAPTURE");
  assert.equal(posts().length, 1);
});

test("a capture that cannot be read, is not USD, not refundable or fully refunded is not refunded", async () => {
  const cases: [() => void, string, string][] = [
    [() => (pp.capture.id = OTHER), "blocked", "PP3_CAPTURE_MISMATCH"],
    [() => (pp.capture.amount.currency_code = "EUR"), "blocked", "PP3_CAPTURE_NOT_USD"],
    [() => (pp.capture.status = "PENDING"), "blocked", "PP3_CAPTURE_NOT_REFUNDABLE"],
    [() => (pp.capture.status = "DECLINED"), "blocked", "PP3_CAPTURE_NOT_REFUNDABLE"],
    [() => (pp.capture.status = "REFUNDED"), "blocked", "PP3_REFUND_EXCEEDS_CAPTURE"],
    [() => (pp.capture.supplementary_data = undefined), "blocked", "PP3_CAPTURE_UNVERIFIABLE"],
    // PayPal says partially refunded, but the order lists no refund of it: fail closed.
    [() => (pp.capture.status = "PARTIALLY_REFUNDED"), "blocked", "PP3_CAPTURE_UNVERIFIABLE"],
    [() => (pp.refunds = [{ ...refundOf(CAPTURE, "1.00"), amount: { value: "1", currency_code: "USD" } }]), "blocked", "PP3_CAPTURE_UNVERIFIABLE"],
    [() => (pp.captureStatus = 500), "failed", "PP3_CAPTURE_UNAVAILABLE"],
    [() => (pp.orderStatus = 500), "failed", "PP3_CAPTURE_UNAVAILABLE"],
  ];
  for (const [arrange, status, want] of cases) {
    pp.capture = { id: CAPTURE, amount: { currency_code: "USD", value: "12.00" }, supplementary_data: { related_ids: { order_id: ORDER } } };
    pp.captureStatus = 200;
    pp.orderStatus = 200;
    pp.refunds = [];
    calls = [];
    arrange();
    const store = memoryStore();
    const r = await submitRefund(deps(store), order());
    assert.deepEqual([r.status, code(r)], [status, want], want);
    assert.equal(posts().length, 0, want);
    assert.equal(store.records.size, 0, `${want}: unclaimed`);
  }
  const t = text("4.00", "9AB12345CD6789012");
  chain.requests.set("rf-1", reservation(t));
  assert.equal(code(await submitRefund(deps(), order({ capture_id: "9AB12345CD6789012", signature: sign(t) }))), "PP3_CAPTURE_NOT_FOUND");
});

test("a request_id is handed to PayPal once, even with changed fields", async () => {
  const store = memoryStore();
  assert.equal((await submitRefund(deps(store), order())).status, "refunded");
  calls = [];
  for (const over of [{}, { amount: "1.00", signature: sign(text("1.00")) }]) {
    assert.equal(code(await submitRefund(deps(store), order(over))), "PP3_DUPLICATE_REQUEST");
  }
  assert.deepEqual(calls, []);
});

test("PayPal's answers map to refused, unknown or released; none is retried", async () => {
  const cases: [typeof pp.post, string, string, string | undefined][] = [
    [{ status: 422, body: { name: "UNPROCESSABLE_ENTITY", details: [{ issue: "REFUND_AMOUNT_EXCEEDED" }] } }, "failed", "PAYPAL_REFUSED", "refused"],
    [{ status: 500 }, "pending", "PAYPAL_OUTCOME_UNKNOWN", "unknown"],
    ["throw", "pending", "PAYPAL_OUTCOME_UNKNOWN", "unknown"],
    [{ status: 201, body: { id: "7X2856342N1619400", status: "COMPLETED", amount: { value: "40.00", currency_code: "USD" } } }, "pending", "PAYPAL_OUTCOME_UNKNOWN", "unknown"],
    [{ status: 201, body: { status: "COMPLETED" } }, "pending", "PAYPAL_OUTCOME_UNKNOWN", "unknown"],
    [{ status: 429 }, "failed", "PAYPAL_RATE_LIMITED", undefined],
  ];
  for (const [answer, status, want, state] of cases) {
    pp.post = answer;
    pp.refunds = [];
    calls = [];
    const store = memoryStore();
    const r = await submitRefund(deps(store), order());
    assert.deepEqual([r.status, code(r)], [status, want], want);
    assert.equal(posts().length, 1);
    assert.equal(store.get(AGENT, "rf-1")?.state, state, want);
    assert.ok(!JSON.stringify(r).includes(TOKEN), "no token in the result");
  }
  assert.match(String((await submitRefund(deps(), order())).status), /refunded|failed|pending/);
});

test("an auth failure is failed and unclaimed; expiry during auth is refused", async () => {
  pp.token = 401;
  const store = memoryStore();
  const r = await submitRefund(deps(store), order());
  assert.equal(code(r), "PP3_AUTH_FAILED");
  assert.ok(!(r as any).detail.includes(SECRET) && !(r as any).detail.includes(CLIENT_ID));
  assert.equal(store.records.size, 0);
  pp.token = 200;
  // 20 s left: under the 30 s POST margin, so it is not claimed.
  assert.equal(code(await submitRefund(deps(store, NOW + 220), order())), "PP3_ORDER_EXPIRED");
  assert.equal(posts().length, 0);
  assert.equal(store.records.size, 0);
});

test("the rail offers PayPal's get_order, get_refund and create_refund, and runs only the reads", async () => {
  const creds = { PAYPAL_ENV: "sandbox", PAYPAL_CLIENT_ID: CLIENT_ID, PAYPAL_CLIENT_SECRET: SECRET };
  const kit = toolkit(creds, fakePaypal());
  assert.deepEqual(kit.tools().map((t) => t.function.name).sort(), [...READ_TOOLS, MANDATED_TOOL].sort());
  const create = kit.tools().find((t) => t.function.name === MANDATED_TOOL)!;
  assert.ok(JSON.stringify(create.function.parameters).includes("capture_id"), "PayPal's own schema");
  await assert.rejects(kit.call(MANDATED_TOOL, { capture_id: CAPTURE }), /not a read tool/);
  await assert.rejects(kit.call("pay_order", {}), /not a read tool/);
  await assert.rejects(kit.call("toString", {}), /not a read tool/);
  assert.throws(() => toolkit({ ...creds, PAYPAL_ENV: "live" }), /sandbox/);
  // The id goes into the URL path, so anything off PayPal's pattern never leaves the rail.
  await assert.rejects(kit.call("get_order", { id: `${ORDER}/../../v1/payments/payouts` }), /needs id/);
  await assert.rejects(kit.call("get_refund", { refund_id: 7 }), /needs refund_id/);
  assert.equal(paypalCalls().length, 0);

  // A read is one sandbox GET; its answer loses credentials and full emails.
  pp.refunds.push({ ...refundOf(CAPTURE, "1.00", "COMPLETED", "7X0856342N1619400"), payer: { email_address: "buyer.person@example.com" }, echo: `${CLIENT_ID} ${SECRET}` } as any);
  const out = await kit.call("get_order", { id: ORDER });
  assert.ok(out.includes(ORDER) && out.includes("7X0856342N1619400"));
  assert.ok(!out.includes(CLIENT_ID) && !out.includes(SECRET) && !out.includes("buyer.person@"));
  assert.ok((await kit.call("get_refund", { refund_id: "7X0856342N1619400" })).includes('"value":"1.00"'));
  assert.deepEqual(paypalCalls().map((c) => `${c.method} ${c.path}`), [`GET /v2/checkout/orders/${ORDER}`, "GET /v2/payments/refunds/7X0856342N1619400"]);
  await assert.rejects(kit.call("get_refund", { refund_id: "9Z0000000000000000" }), /get_refund failed: HTTP 404/);
  assert.ok(calls.every((c) => !JSON.stringify(c.body ?? "").includes(TOKEN)));
});

test("the refund service: per-agent token, reads through the toolkit, create_refund only as a signed order", async () => {
  const token = "t".repeat(40);
  const kit = { tools: () => [{ type: "function" as const, function: { name: "get_order" } }, { type: "function" as const, function: { name: MANDATED_TOOL } }], call: async (n: string) => `ran ${n}` };
  const srv = refundServer(deps(), kit, new Map([[AGENT, token]]));
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  const auth = { authorization: `Bearer ${token}`, "content-type": "application/json" };
  try {
    assert.equal((await fetch(`${base}/tools?agent=${AGENT}`)).status, 401);
    assert.equal((await fetch(`${base}/tools?agent=${AGENT}`, { headers: { authorization: `Bearer ${"x".repeat(40)}` } })).status, 401);
    const tools = await (await fetch(`${base}/tools?agent=${AGENT}`, { headers: auth })).json();
    assert.deepEqual(tools.tools.map((t: any) => t.function.name), ["get_order", MANDATED_TOOL]);
    const call = (body: unknown) => fetch(`${base}/tools/call`, { method: "POST", headers: auth, body: JSON.stringify(body) });
    assert.deepEqual(await (await call({ agent: AGENT, name: "get_order", arguments: { id: ORDER } })).json(), { name: "get_order", content: "ran get_order" });
    assert.equal((await call({ agent: AGENT, name: MANDATED_TOOL, arguments: { capture_id: CAPTURE } })).status, 403);
    assert.equal((await call({ agent: AGENT, name: "pay_order", arguments: {} })).status, 404);
    assert.equal((await call({ agent: "support-2", name: "get_order", arguments: {} })).status, 401);
    const r = await (await fetch(`${base}/refunds`, { method: "POST", headers: auth, body: JSON.stringify(order()) })).json();
    assert.equal(r.status, "refunded");
    assert.equal((await fetch(`${base}/payouts`, { method: "POST", headers: auth, body: "{}" })).status, 404);
  } finally {
    srv.close();
  }
});
