// PP-V1 rail with NEAR and PayPal mocked: connect (setup token -> approve -> payment token), the
// shape 5 charge (Orders v2 capture on the vault_id, then Payouts to the merchant), and revoke
// (DELETE, then GET 404). The vault_id must never appear in a result, a log line or an order record.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { publicKeyToAddress } from "@nearh/owner-near/src/derive.ts";
import { SANDBOX_BASE, sandboxClient } from "../src/paypal.ts";
import { batchId, eip191Digest, type Payee, type Reservation } from "../src/payout.ts";
import { server } from "../src/server.ts";
import { memoryStore } from "../src/store.ts";
import {
  chargeCheckout,
  checkoutMessage,
  checkoutRequestId,
  confirmVault,
  connectVault,
  memoryVaultStore,
  revokeVault,
  vaultStatus,
  type CheckoutOrder,
  type VaultDeps,
} from "../src/vault.ts";

const AGENT = "agent-1";
const MERCHANT = "merchant@example.com";
const ATTACKER = "attacker@example.com";
const TS = 1_793_831_226;
const NOW = TS + 10;
const KEY = secp256k1.utils.randomSecretKey();
const ADDRESS = publicKeyToAddress(secp256k1.getPublicKey(KEY, false));
const VAULT_ID = "7test0vault00id9";
const SETUP_ID = "9RJ86983E5394083A";
const ORDER_ID = "1653574570330000C";
const CAPTURE_ID = "0PL46169Y5983610B";
const BATCH = "92APWP7M4TFJW";
const OWNER_TOKEN = "owner-token-0123456789-abcdefghijklmnop";
const AGENT_TOKEN = "agent-token-0123456789-abcdefghijklmnop";

function sign(t: string, key = KEY) {
  const sig = secp256k1.sign(eip191Digest(t), key, { prehash: false, format: "recovered" });
  return { r: `0x${bytesToHex(sig.slice(1, 33))}`, s: `0x${bytesToHex(sig.slice(33))}`, v: 27 + sig[0] };
}
const text = (over: Partial<{ amount: string; payee: string; ref: string; id: string }> = {}) =>
  checkoutMessage(over.amount ?? "25.00", over.payee ?? MERCHANT, over.ref ?? "ORD-42", TS, over.id ?? "chk-1");

function reservation(t = text(), over: Partial<Reservation> = {}): Reservation {
  return {
    key: { agent: AGENT, caller: { kind: "agent" }, request_id: "chk-1" },
    shape: "paypal_checkout",
    rail: "paypal",
    valid_before: TS + 240,
    digest: `0x${bytesToHex(eip191Digest(t))}`,
    payload: { kind: "message", text: t },
    status: "signed",
    signature: sign(t),
    ...over,
  };
}

type Reply = { status: number; body?: unknown };
let chain: { agent: any; requests: Map<string, Reservation>; payees: Payee[]; suspended: Payee[] };
let calls: { method: string; path: string; headers: Record<string, string>; body: any }[];
let replies: Record<string, Reply>;
let logs: string[];
let tokenDeleted: boolean;

function deps(): VaultDeps {
  const fetcher = (async (url: string, init: RequestInit) => {
    assert.ok(url.startsWith(SANDBOX_BASE));
    const path = new URL(url).pathname;
    const method = String(init.method);
    calls.push({ method, path, headers: init.headers as Record<string, string>, body: path === "/v1/oauth2/token" || !init.body ? undefined : JSON.parse(String(init.body)) });
    let r: Reply | undefined;
    if (path === "/v1/oauth2/token") r = { status: 200, body: { access_token: "tok-do-not-print-1234", expires_in: 32400 } };
    else if (method === "DELETE" && path === `/v3/vault/payment-tokens/${VAULT_ID}`) {
      tokenDeleted = true;
      r = { status: 204 };
    } else if (method === "GET" && path === `/v3/vault/payment-tokens/${VAULT_ID}`) {
      r = tokenDeleted ? { status: 404, body: { name: "RESOURCE_NOT_FOUND" } } : { status: 200, body: { id: VAULT_ID } };
    } else r = replies[`${method} ${path}`];
    if (!r) throw new Error(`unexpected ${method} ${path}`);
    return new Response(r.status === 204 ? null : JSON.stringify(r.body ?? {}), { status: r.status });
  }) as typeof fetch;
  return {
    near: {
      getAgent: async (a) => (a === AGENT ? chain.agent : null),
      getRequest: async (k) => chain.requests.get(k.request_id) ?? null,
      getPayees: async () => chain.payees,
      getSuspendedPayees: async () => chain.suspended,
    },
    paypal: sandboxClient({ PAYPAL_ENV: "sandbox", PAYPAL_CLIENT_ID: "cid-0000", PAYPAL_CLIENT_SECRET: "sec-0000" }, fetcher),
    store: memoryStore(),
    vaults: memoryVaultStore(),
    secrets: ["cid-0000", "sec-0000"],
    now: () => NOW,
    log: (l) => logs.push(l),
  };
}

const completedOrder = { status: 201, body: { id: ORDER_ID, status: "COMPLETED", purchase_units: [{ payments: { captures: [{ id: CAPTURE_ID, status: "COMPLETED" }] } }] } };
const payoutOk = { status: 201, body: { batch_header: { payout_batch_id: BATCH, batch_status: "PENDING", sender_batch_header: { sender_batch_id: batchId(AGENT, "chk-1") } } } };

beforeEach(() => {
  chain = { agent: { evm_address: ADDRESS, revoked: false }, requests: new Map([["chk-1", reservation()]]), payees: [{ rail: "paypal", receiver: MERCHANT }], suspended: [] };
  calls = [];
  logs = [];
  tokenDeleted = false;
  replies = {
    "POST /v3/vault/setup-tokens": { status: 201, body: { id: SETUP_ID, status: "PAYER_ACTION_REQUIRED", links: [{ rel: "approve", href: `https://www.sandbox.paypal.com/agreements/approve?approval_session_id=${SETUP_ID}` }] } },
    [`GET /v3/vault/setup-tokens/${SETUP_ID}`]: { status: 200, body: { id: SETUP_ID, status: "APPROVED" } },
    "POST /v3/vault/payment-tokens": { status: 201, body: { id: VAULT_ID, customer: { id: "CqCpQdOSRi" } } },
    "POST /v2/checkout/orders": completedOrder,
    "POST /v1/payments/payouts": payoutOk,
  };
});

async function connected(): Promise<VaultDeps> {
  const d = deps();
  const c = await connectVault(d, AGENT);
  assert.equal(c.ok && c.status, "approval_required");
  const f = await confirmVault(d, AGENT);
  assert.equal(f.ok && f.status, "active");
  calls = [];
  return d;
}

const order = (over: Partial<CheckoutOrder> = {}): CheckoutOrder => ({
  agent: AGENT,
  request_id: "chk-1",
  payee: MERCHANT,
  amount: "25.00",
  order_ref: "ORD-42",
  timestamp: TS,
  signature: sign(text()),
  ...over,
});
const code = (r: any) => r.error_code;
const paypalWrites = () => calls.filter((c) => c.path !== "/v1/oauth2/token");

test("the message is byte-for-byte paypal_checkout.rs's", () => {
  assert.equal(
    checkoutMessage("25.00", "merchant@example.com", "ORD-2026-0042", TS, "chk-0001"),
    "Charge USD 25.00 to merchant merchant@example.com for order ORD-2026-0042 at 2026-11-04T22:27:06Z ref chk-0001",
  );
});

test("connect returns the approve link only; confirm stores the payment token and status never shows it", async () => {
  const d = deps();
  assert.deepEqual(vaultStatus(d, AGENT), { agent: AGENT, status: "none" });
  const c = await connectVault(d, AGENT);
  assert.ok(c.ok && c.approve_url?.startsWith("https://www.sandbox.paypal.com/"));
  const setup = calls.find((x) => x.path === "/v3/vault/setup-tokens")!;
  assert.equal(setup.body.payment_source.paypal.usage_type, "MERCHANT");
  assert.ok(setup.headers["PayPal-Request-Id"]);
  // Not approved yet: refused, nothing stored.
  replies[`GET /v3/vault/setup-tokens/${SETUP_ID}`] = { status: 200, body: { status: "PAYER_ACTION_REQUIRED" } };
  assert.equal(code(await confirmVault(d, AGENT)), "VAULT_NOT_APPROVED");
  replies[`GET /v3/vault/setup-tokens/${SETUP_ID}`] = { status: 200, body: { status: "APPROVED" } };
  const f = await confirmVault(d, AGENT);
  assert.deepEqual(f, { ok: true, agent: AGENT, status: "active" });
  const st = vaultStatus(d, AGENT);
  assert.equal(st.status, "active");
  for (const out of [c, f, st, logs]) assert.ok(!JSON.stringify(out).includes(VAULT_ID), "no vault_id in results or logs");
  assert.equal(code(await connectVault(d, AGENT)), "VAULT_ALREADY_ACTIVE");
});

test("a $25 charge within the mandate captures on the vault_id into the rail account, then pays the merchant", async () => {
  const d = await connected();
  const r = await chargeCheckout(d, order());
  assert.deepEqual(r, { status: "submitted", request_id: "chk-1", paypal_order_id: ORDER_ID, capture_id: CAPTURE_ID, payout_batch_id: BATCH, batch_status: "PENDING" });
  const [o, p] = paypalWrites();
  assert.equal(o.path, "/v2/checkout/orders");
  assert.equal(o.headers["PayPal-Request-Id"], checkoutRequestId(AGENT, "chk-1"));
  assert.equal(o.body.payment_source.paypal.vault_id, VAULT_ID);
  assert.deepEqual(o.body.payment_source.paypal.stored_credential, { payment_initiator: "MERCHANT", usage: "SUBSEQUENT", usage_pattern: "IMMEDIATE" });
  assert.equal(o.body.purchase_units[0].payee, undefined, "no third-party payee in the order (PP-V0: 422)");
  assert.deepEqual(o.body.purchase_units[0].amount, { currency_code: "USD", value: "25.00" });
  assert.equal(p.path, "/v1/payments/payouts");
  assert.equal(p.body.items[0].receiver, MERCHANT);
  assert.equal(p.body.sender_batch_header.sender_batch_id, batchId(AGENT, "chk-1"));
  const rec = (d.store as any).records.values().next().value;
  for (const out of [r, logs, rec]) assert.ok(!JSON.stringify(out).includes(VAULT_ID), "no vault_id in the result, logs or order record");
  assert.ok(!JSON.stringify(logs).includes(MERCHANT), "payee masked in logs");
  // Same request again: refused locally, no PayPal call.
  calls = [];
  assert.equal(code(await chargeCheckout(d, order())), "PP3_DUPLICATE_REQUEST");
  assert.deepEqual(paypalWrites(), []);
});

test("an order that comes back APPROVED is captured explicitly", async () => {
  const d = await connected();
  replies["POST /v2/checkout/orders"] = { status: 201, body: { id: ORDER_ID, status: "APPROVED" } };
  replies[`POST /v2/checkout/orders/${ORDER_ID}/capture`] = completedOrder;
  const r = await chargeCheckout(d, order());
  assert.equal(r.status, "submitted");
  assert.deepEqual(paypalWrites().map((c) => c.path), ["/v2/checkout/orders", `/v2/checkout/orders/${ORDER_ID}/capture`, "/v1/payments/payouts"]);
});

test("a swapped merchant is refused before any PayPal call", async () => {
  const d = await connected();
  // The agent signed nothing for the attacker: the signature over the attacker's text is not the contract's.
  assert.equal(code(await chargeCheckout(d, order({ payee: ATTACKER }))), "PP3_BAD_SIGNATURE");
  // Even an agent signature over the swapped text fails: the contract signed the real merchant.
  assert.equal(code(await chargeCheckout(d, order({ payee: ATTACKER, signature: sign(text({ payee: ATTACKER })) }))), "PP3_ORDER_MISMATCH");
  // And a merchant removed from the allowlist after signing is refused.
  chain.payees = [];
  assert.equal(code(await chargeCheckout(d, order())), "PP3_PAYEE_NOT_ALLOWED");
  assert.deepEqual(paypalWrites(), []);
});

test("over cap or expired orders never reach PayPal; a shape 4 reservation is not a checkout", async () => {
  const d = await connected();
  chain.requests.set("chk-1", reservation(text(), { valid_before: NOW - 1 }));
  assert.equal(code(await chargeCheckout(d, order())), "PP3_ORDER_EXPIRED");
  chain.requests.set("chk-1", reservation(text(), { valid_before: NOW + 59 }));
  assert.equal(code(await chargeCheckout(d, order())), "PP3_ORDER_EXPIRED", "two POSTs must fit before valid_before");
  chain.requests.set("chk-1", reservation(text(), { shape: "paypal" }));
  assert.equal(code(await chargeCheckout(d, order())), "PP3_NOT_A_PAYPAL_CHECKOUT");
  // Over cap: the contract never signs it, so the only signed reservation holds another text.
  chain.requests.set("chk-1", reservation());
  assert.equal(code(await chargeCheckout(d, order({ amount: "50.01", signature: sign(text({ amount: "50.01" })) }))), "PP3_ORDER_MISMATCH");
  assert.deepEqual(paypalWrites(), []);
});

test("no active vault: blocked, nothing charged", async () => {
  const d = deps();
  assert.equal(code(await chargeCheckout(d, order())), "VAULT_NOT_ACTIVE");
  assert.deepEqual(paypalWrites(), []);
});

test("revoke deletes the payment token (GET then 404) and later charges are refused", async () => {
  const d = await connected();
  const r = await revokeVault(d, AGENT);
  assert.deepEqual(r, { ok: true, agent: AGENT, status: "revoked", token_http_after: 404 });
  assert.deepEqual(paypalWrites().map((c) => `${c.method} ${c.path}`), [`DELETE /v3/vault/payment-tokens/${VAULT_ID}`, `GET /v3/vault/payment-tokens/${VAULT_ID}`]);
  calls = [];
  assert.equal(code(await chargeCheckout(d, order())), "VAULT_NOT_ACTIVE");
  assert.deepEqual(paypalWrites(), []);
  assert.ok(!JSON.stringify([r, logs]).includes(VAULT_ID));
});

test("a contract revoke also makes the rail delete the vault token on the next charge", async () => {
  const d = await connected();
  chain.agent = { evm_address: ADDRESS, revoked: true };
  assert.equal(code(await chargeCheckout(d, order())), "PP3_AGENT_REVOKED");
  assert.equal(vaultStatus(d, AGENT).status, "revoked");
  assert.ok(tokenDeleted);
  assert.ok(!paypalWrites().some((c) => c.path.startsWith("/v2/") || c.path.startsWith("/v1/payments")), "nothing charged");
});

test("a refused charge is failed and claimed; a capture whose payout fails is reported with the capture id", async () => {
  let d = await connected();
  replies["POST /v2/checkout/orders"] = { status: 422, body: { name: "UNPROCESSABLE_ENTITY", details: [{ issue: "BILLING_AGREEMENT_NOT_FOUND" }] } };
  const r = await chargeCheckout(d, order());
  assert.equal(code(r), "PAYPAL_CHARGE_REFUSED");
  assert.equal(code(await chargeCheckout(d, order())), "PP3_DUPLICATE_REQUEST", "never retried");
  d = await connected();
  replies["POST /v2/checkout/orders"] = completedOrder;
  replies["POST /v1/payments/payouts"] = { status: 429, body: { name: "RATE_LIMIT_REACHED" } };
  const p = await chargeCheckout(d, order());
  assert.equal(p.status, "failed");
  assert.equal((p as any).capture_id, CAPTURE_ID);
  assert.equal(code(await chargeCheckout(d, order())), "PP3_DUPLICATE_REQUEST", "a captured charge is never released on a payout 429");
});

test("service: /vault/* needs the owner token, /checkout the agent token", async () => {
  const d = deps();
  const s = server(d, new Map([[AGENT, AGENT_TOKEN]]), {}, { deps: d, ownerToken: OWNER_TOKEN }).listen(0, "127.0.0.1");
  await new Promise((r) => s.once("listening", r));
  const base = `http://127.0.0.1:${(s.address() as any).port}`;
  const post = (path: string, body: unknown, token: string) =>
    fetch(base + path, { method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(body) });
  try {
    assert.equal((await post("/vault/connect", { agent: AGENT }, AGENT_TOKEN)).status, 401, "the agent cannot connect or revoke");
    assert.equal((await post("/vault/revoke", { agent: AGENT }, AGENT_TOKEN)).status, 401);
    const c = await post("/vault/connect", { agent: AGENT }, OWNER_TOKEN);
    assert.equal(c.status, 200);
    assert.ok(((await c.json()) as any).approve_url);
    assert.equal((await post("/vault/confirm", { agent: AGENT }, OWNER_TOKEN)).status, 200);
    const st = await fetch(`${base}/vault/status?agent=${AGENT}`, { headers: { authorization: `Bearer ${OWNER_TOKEN}` } });
    const stText = await st.text();
    assert.equal(JSON.parse(stText).status, "active");
    assert.ok(!stText.includes(VAULT_ID));
    assert.equal((await post("/checkout", order(), OWNER_TOKEN)).status, 401, "checkout takes the agent's token");
    const ch = await post("/checkout", order(), AGENT_TOKEN);
    const chText = await ch.text();
    assert.equal(JSON.parse(chText).status, "submitted");
    assert.ok(!chText.includes(VAULT_ID));
    const rv = await post("/vault/revoke", { agent: AGENT }, OWNER_TOKEN);
    assert.equal(((await rv.json()) as any).token_http_after, 404);
  } finally {
    s.close();
  }
});
