// PP3 with NEAR and PayPal mocked: the contract views are an in-memory `Near`, and PayPal is the
// sandbox client over a fake fetch that records every call. Signatures are real secp256k1
// signatures over the EIP-191 digest of the shape 4 text.
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, test } from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { publicKeyToAddress } from "@nearh/owner-near/src/derive.ts";
import { SANDBOX_BASE, sandboxClient } from "../src/paypal.ts";
import {
  batchId,
  eip191Digest,
  isCanonicalAmount,
  isCanonicalVenmo,
  maskEmail,
  paypalMessage,
  scrub,
  submitPaypalPayout,
  SUBMIT_MARGIN_SECS,
  type Deps,
  type Payee,
  type PaypalOrder,
  type Reservation,
} from "../src/payout.ts";
import { parseAgentTokens, server } from "../src/server.ts";
import { trickle } from "./trickle.ts";
import { fileStore, memoryStore, type Store } from "../src/store.ts";

const AGENT = "agent-1";
/** Documentation-style receivers, not accounts of ours. */
const PAYEE = "supplier@example.com";
const ATTACKER = "attacker@example.com";
const TS = 1_793_831_226; // 2026-11-04T22:27:06Z, as paypal.rs's tests
const NOW = TS + 30;
const KEY = secp256k1.utils.randomSecretKey();
const ADDRESS = publicKeyToAddress(secp256k1.getPublicKey(KEY, false));
const CLIENT_ID = "client-id-do-not-print-3e1d";
const SECRET = "client-secret-do-not-print-7f3a";
const TOKEN = "access-token-do-not-print-91bc";
const BATCH = "92APWP7M4TFJW";

function sign(t: string, key = KEY) {
  const sig = secp256k1.sign(eip191Digest(t), key, { prehash: false, format: "recovered" });
  return { r: `0x${bytesToHex(sig.slice(1, 33))}`, s: `0x${bytesToHex(sig.slice(33))}`, v: 27 + sig[0] };
}

const signedText = (over: Partial<{ amount: string; payee: string; ts: number; id: string }> = {}) =>
  paypalMessage(over.amount ?? "1.00", over.payee ?? PAYEE, over.ts ?? TS, over.id ?? "inv-1");

function reservation(t = signedText(), over: Partial<Reservation> = {}): Reservation {
  return {
    key: { agent: AGENT, caller: { kind: "agent" }, request_id: "inv-1" },
    shape: "paypal",
    rail: "paypal",
    valid_before: TS + 240,
    digest: `0x${bytesToHex(eip191Digest(t))}`,
    payload: { kind: "message", text: t },
    status: "signed",
    signature: sign(t),
    ...over,
  };
}

type Reply = { status: number; body?: unknown; headers?: Record<string, string> } | "throw";
let chain: { agent: any; requests: Map<string, Reservation>; payees: Payee[]; suspended: Payee[]; calls: string[] };
let calls: { path: string; method: string; headers: Record<string, string>; body: any }[];
let logs: string[];
let post: Reply;
let token: Reply;

function paypal() {
  const fetcher = (async (url: string, init: RequestInit) => {
    assert.ok(url.startsWith(SANDBOX_BASE), "only the sandbox is ever called");
    const path = new URL(url).pathname;
    calls.push({ path, method: String(init.method), headers: init.headers as Record<string, string>, body: path === "/v1/oauth2/token" ? String(init.body) : JSON.parse(String(init.body)) });
    const r = path === "/v1/oauth2/token" ? token : post;
    if (r === "throw") throw new Error(`socket hang up, bearer ${TOKEN}`);
    return new Response(JSON.stringify(r.body ?? {}), { status: r.status, headers: r.headers });
  }) as typeof fetch;
  return sandboxClient({ PAYPAL_ENV: "sandbox", PAYPAL_CLIENT_ID: CLIENT_ID, PAYPAL_CLIENT_SECRET: SECRET }, fetcher);
}

function deps(store: Store = memoryStore()): Deps {
  return {
    near: {
      getAgent: async (agent) => (chain.calls.push(`get_agent ${agent}`), agent === AGENT ? chain.agent : null),
      getRequest: async (key) => (chain.calls.push(`get_request ${key.request_id}`), chain.requests.get(key.request_id) ?? null),
      getPayees: async (agent) => (chain.calls.push(`get_payees ${agent}`), chain.payees),
      getSuspendedPayees: async (agent) => (chain.calls.push(`get_suspended_payees ${agent}`), chain.suspended),
    },
    paypal: paypal(),
    secrets: [CLIENT_ID, SECRET],
    store,
    now: () => NOW,
    log: (l) => logs.push(l),
  };
}

const order = (over: Partial<PaypalOrder> = {}): PaypalOrder => ({
  agent: AGENT,
  request_id: "inv-1",
  payee: PAYEE,
  amount: "1.00",
  timestamp: TS,
  signature: sign(signedText()),
  ...over,
});
const payoutPosts = () => calls.filter((c) => c.path === "/v1/payments/payouts");
const SBID = batchId(AGENT, "inv-1");
const accepted = (sender_batch_id = SBID, payout_batch_id = BATCH) =>
  ({ status: 201, body: { batch_header: { payout_batch_id, batch_status: "PENDING", sender_batch_header: { sender_batch_id } } }, headers: { "paypal-debug-id": "f1e2d3c4b5a69" } });
const created = accepted();

function reset() {
  chain = { agent: { evm_address: ADDRESS, revoked: false }, requests: new Map([["inv-1", reservation()]]), payees: [{ rail: "paypal", receiver: PAYEE }], suspended: [], calls: [] };
  calls = [];
  logs = [];
  post = created;
  token = { status: 200, body: { access_token: TOKEN, token_type: "Bearer", expires_in: 32400 } };
}
beforeEach(reset);

const code = (r: unknown) => (r as any).error_code;

test("the message is byte-for-byte paypal.rs's (same text and digest as its happy_path test)", () => {
  const t = paypalMessage("1.00", PAYEE, TS, "inv-2026-0042");
  assert.equal(t, "Send USD 1.00 to supplier@example.com at 2026-11-04T22:27:06Z ref inv-2026-0042");
  assert.equal(bytesToHex(eip191Digest(t)), "93a3d0f96e79b1166369480f28cc76d1e61202632b09d66839b21cd231d0a7c1");
});

test("an accepted payout posts once with sender_batch_id = batchId(agent, request_id) and stores PayPal's batch id", async () => {
  const store = memoryStore();
  const r = await submitPaypalPayout(deps(store), order());
  assert.deepEqual(r, { status: "submitted", request_id: "inv-1", payout_batch_id: BATCH, batch_status: "PENDING" });
  assert.equal(payoutPosts().length, 1);
  const p = payoutPosts()[0];
  assert.equal(p.method, "POST");
  assert.match(SBID, /^[0-9a-f]{64}$/);
  assert.equal(p.headers["PayPal-Request-Id"], SBID);
  assert.equal(p.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(p.body.sender_batch_header.sender_batch_id, SBID);
  assert.deepEqual(p.body.items, [{ recipient_type: "EMAIL", amount: { value: "1.00", currency: "USD" }, receiver: PAYEE, note: "ref inv-1", sender_item_id: "inv-1" }]);
  const rec = store.get(AGENT, "inv-1")!;
  assert.equal(rec.state, "submitted");
  assert.equal(rec.payout_batch_id, BATCH);
  assert.equal(rec.debug_id, "f1e2d3c4b5a69");
  assert.equal(rec.payee_masked, "su…@example.com");
  assert.ok(!JSON.stringify(rec).includes(PAYEE), "the store keeps no full payee");
  assert.ok(!logs.join("\n").includes(PAYEE), "logs keep no full payee");
});

// Tampering: every field is bound by the signature, and every refusal is before any PayPal call.
for (const [name, over, want] of [
  ["amount", { amount: "2.00" }, "PP3_BAD_SIGNATURE"],
  ["payee", { payee: ATTACKER }, "PP3_BAD_SIGNATURE"],
  ["request_id", { request_id: "inv-2" }, "PP3_BAD_SIGNATURE"],
  ["timestamp", { timestamp: TS + 1 }, "PP3_BAD_SIGNATURE"],
  ["signature (another key)", { signature: sign(signedText(), secp256k1.utils.randomSecretKey()) }, "PP3_BAD_SIGNATURE"],
  ["signature (other message)", { signature: sign(signedText({ amount: "2.00" })) }, "PP3_BAD_SIGNATURE"],
  ["signature (flipped v)", { signature: { ...sign(signedText()), v: 55 - sign(signedText()).v } }, "PP3_BAD_SIGNATURE"],
  ["signature (malformed)", { signature: { r: "0xzz", s: "0x01", v: 27 } }, "PP3_BAD_SIGNATURE"],
] as const) {
  test(`a tampered ${name} is refused before any PayPal call`, async () => {
    chain.requests.set("inv-2", reservation(signedText({ id: "inv-2" })));
    const store = memoryStore();
    const r = await submitPaypalPayout(deps(store), order(over as Partial<PaypalOrder>));
    assert.equal(r.status, "blocked");
    assert.equal(code(r), want);
    assert.deepEqual(calls, [], "zero PayPal calls, not even the token");
    assert.equal(store.records.size, 0, "nothing claimed");
    assert.ok(!JSON.stringify(r).includes(ATTACKER) && !logs.join("\n").includes(ATTACKER), "the payee is masked");
  });
}

test("an attacker who re-signs the tampered order with their own key is refused: the key is not the agent EOA", async () => {
  const evil = secp256k1.utils.randomSecretKey();
  const t = signedText({ payee: ATTACKER, amount: "50.00" });
  const r = await submitPaypalPayout(deps(), order({ payee: ATTACKER, amount: "50.00", signature: sign(t, evil) }));
  assert.equal(code(r), "PP3_BAD_SIGNATURE");
  assert.deepEqual(calls, []);
});

test("a valid agent signature over fields the contract did not sign (or did not reserve) is refused", async () => {
  // The agent EOA signed it, but the contract's reservation for inv-1 holds another text.
  const t = signedText({ amount: "2.00" });
  chain.requests.set("inv-1", reservation(signedText()));
  assert.equal(code(await submitPaypalPayout(deps(), order({ amount: "2.00", signature: sign(t) }))), "PP3_ORDER_MISMATCH");
  chain.requests.set("inv-1", reservation(t, { digest: `0x${"00".repeat(32)}` }));
  assert.equal(code(await submitPaypalPayout(deps(), order({ amount: "2.00", signature: sign(t) }))), "PP3_BAD_SIGNATURE");
  chain.requests.delete("inv-1");
  assert.equal(code(await submitPaypalPayout(deps(), order())), "PP3_REQUEST_NOT_FOUND");
  assert.deepEqual(calls, []);
});

test("released, unknown or pending reservations, other shapes, expiry, a revoked or unknown agent: no PayPal call", async () => {
  const cases: [() => void, string, Partial<PaypalOrder>?][] = [
    [() => chain.requests.set("inv-1", reservation(undefined, { status: "released" })), "PP3_NOT_SIGNED"],
    [() => chain.requests.set("inv-1", reservation(undefined, { status: "unknown" })), "PP3_NOT_SIGNED"],
    [() => chain.requests.set("inv-1", reservation(undefined, { status: "pending", signature: null })), "PP3_NOT_SIGNED"],
    [() => chain.requests.set("inv-1", reservation(undefined, { shape: "payout", rail: "sepa" })), "PP3_NOT_A_PAYPAL_PAYOUT"],
    [() => chain.requests.set("inv-1", reservation(undefined, { valid_before: NOW - 1 })), "PP3_ORDER_EXPIRED"],
    [() => (chain.agent = { evm_address: ADDRESS, revoked: true }), "PP3_AGENT_REVOKED"],
    [() => (chain.agent = { evm_address: null, revoked: false }), "PP3_UNKNOWN_AGENT"],
    [() => {}, "PP3_UNKNOWN_AGENT", { agent: "agent-9" }],
  ];
  for (const [setup, want, over] of cases) {
    reset();
    setup();
    const r = await submitPaypalPayout(deps(), order(over));
    assert.equal(code(r), want);
    assert.deepEqual(calls, [], want);
  }
});

test("a signed payee that is no longer on the agent's PayPal payees is refused (a SEPA payee does not count)", async () => {
  chain.payees = [{ rail: "sepa", iban: "DE89370400440532013000" }];
  const r = await submitPaypalPayout(deps(), order());
  assert.equal(code(r), "PP3_PAYEE_NOT_ALLOWED");
  assert.ok(!(r as any).detail.includes(PAYEE));
  assert.deepEqual(calls, []);
});

test("PP-W1: a payee suspended after an adverse PayPal settlement is refused before any PayPal call", async () => {
  chain.suspended = [{ rail: "paypal", receiver: PAYEE }];
  const r = await submitPaypalPayout(deps(), order());
  assert.equal(code(r), "PP3_PAYEE_SUSPENDED");
  assert.ok(!(r as any).detail.includes(PAYEE));
  assert.deepEqual(calls, []);
});

test("non-canonical input is refused before NEAR or PayPal: nothing is rewritten", async () => {
  for (const over of [
    { amount: "1" }, { amount: "1.0" }, { amount: "01.00" }, { amount: "0.00" }, { amount: "1.000" }, { amount: " 1.00" }, { amount: 1 as any },
    { payee: "Supplier@Example.com" }, { payee: " supplier@example.com" }, { payee: "supplier@example" }, { payee: "a..b@example.com" },
    { timestamp: -1 }, { timestamp: 1.5 }, { timestamp: "1793831226" as any },
    { signature: undefined as any },
    { request_id: "" }, { request_id: "x".repeat(65) }, { request_id: "a b" }, { agent: "a/b" },
  ]) {
    const r = await submitPaypalPayout(deps(), order(over));
    assert.equal(code(r), "PP3_INVALID_INPUT", JSON.stringify(over));
  }
  for (const payee of ["@Demo-Supplier", "@abcd", `@${"a".repeat(31)}`, "@demo.supplier", " @demo-supplier"]) {
    assert.equal(code(await submitPaypalPayout(deps(), order({ payee }))), "PP3_INVALID_INPUT", payee);
  }
  assert.deepEqual(chain.calls, []);
  assert.deepEqual(calls, []);
});

test("a resubmitted request_id is refused locally: no NEAR, no PayPal call, whatever the new fields", async () => {
  const store = memoryStore();
  assert.equal((await submitPaypalPayout(deps(store), order())).status, "submitted");
  calls = [];
  chain.calls = [];
  for (const over of [{}, { amount: "2.00" }, { payee: ATTACKER }]) {
    const r = await submitPaypalPayout(deps(store), order(over));
    assert.equal(code(r), "PP3_DUPLICATE_REQUEST");
    assert.ok((r as any).detail.includes(BATCH));
  }
  assert.deepEqual(calls, []);
  assert.deepEqual(chain.calls, []);
});

test("three concurrent submissions of one request_id make one POST", async () => {
  const store = memoryStore();
  const rs = await Promise.all([1, 2, 3].map(() => submitPaypalPayout(deps(store), order())));
  assert.equal(rs.filter((r) => r.status === "submitted").length, 1);
  assert.equal(rs.filter((r) => code(r) === "PP3_DUPLICATE_REQUEST").length, 2);
  assert.equal(payoutPosts().length, 1);
});

test("the file store survives a restart, and of two stores on one dir only one claims", async () => {
  const dir = mkdtempSync(join(tmpdir(), "pp3-"));
  try {
    assert.equal((await submitPaypalPayout(deps(fileStore(dir)), order())).status, "submitted");
    calls = [];
    assert.equal(code(await submitPaypalPayout(deps(fileStore(dir)), order())), "PP3_DUPLICATE_REQUEST");
    assert.deepEqual(calls, []);
    const files = readdirSync(dir);
    assert.equal(files.length, 1);
    const raw = readFileSync(join(dir, files[0]), "utf8");
    assert.equal(JSON.parse(raw).payout_batch_id, BATCH);
    assert.ok(!raw.includes(PAYEE) && !raw.includes(TOKEN) && !raw.includes(SECRET));
    const [a, b] = [fileStore(dir), fileStore(dir)];
    const rec = { agent: AGENT, request_id: "inv-x", state: "submitting" as const, payee_masked: "x", amount: "1.00", at: "" };
    assert.deepEqual([a.claim(rec), b.claim(rec)], [true, false]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("PayPal's duplicate sender_batch_id refusal is recognised by field, and the request_id stays used", async () => {
  post = {
    status: 400,
    body: {
      name: "USER_BUSINESS_ERROR",
      details: [{ field: "SENDER_BATCH_ID", location: "body", issue: "Batch with given sender_batch_id already exists" }],
      links: [{ href: `${SANDBOX_BASE}/v1/payments/payouts/${BATCH}`, rel: "self", method: "GET" }],
    },
  };
  const store = memoryStore();
  const r = await submitPaypalPayout(deps(store), order());
  assert.equal(r.status, "failed");
  assert.equal(code(r), "PAYPAL_DUPLICATE_BATCH");
  assert.ok((r as any).detail.includes(SBID), "the detail names the derived sender_batch_id");
  assert.equal(payoutPosts()[0].body.sender_batch_header.sender_batch_id, SBID);
  assert.equal(store.get(AGENT, "inv-1")!.state, "duplicate_batch");
  assert.equal(store.get(AGENT, "inv-1")!.payout_batch_id, BATCH);
  calls = [];
  assert.equal(code(await submitPaypalPayout(deps(store), order())), "PP3_DUPLICATE_REQUEST");
  assert.deepEqual(calls, []);
});

test("another business error is PAYPAL_REFUSED; 5xx, transit failure, 2xx without a batch id are unknown and never retried", async () => {
  const cases: [Reply, string, string][] = [
    [{ status: 400, body: { name: "USER_BUSINESS_ERROR", details: [{ field: "items[0].amount", issue: "bad" }] } }, "PAYPAL_REFUSED", "refused"],
    [{ status: 422, body: { name: "INSUFFICIENT_FUNDS" } }, "PAYPAL_REFUSED", "refused"],
    [{ status: 503, body: {} }, "PAYPAL_OUTCOME_UNKNOWN", "unknown"],
    ["throw", "PAYPAL_OUTCOME_UNKNOWN", "unknown"],
    [{ status: 201, body: { batch_header: { sender_batch_header: { sender_batch_id: SBID } } } }, "PAYPAL_OUTCOME_UNKNOWN", "unknown"],
    [{ status: 201, body: { batch_header: { payout_batch_id: BATCH, batch_status: "DENIED", sender_batch_header: { sender_batch_id: SBID } } } }, "PAYPAL_OUTCOME_UNKNOWN", "unknown"],
    [{ status: 201, body: { batch_header: {} } }, "PAYPAL_BATCH_MISMATCH", "unknown"],
  ];
  for (const [reply, want, state] of cases) {
    reset();
    post = reply;
    const store = memoryStore();
    const r = await submitPaypalPayout(deps(store), order());
    assert.equal(code(r), want, JSON.stringify(reply));
    assert.equal(store.get(AGENT, "inv-1")!.state, state);
    assert.equal(payoutPosts().length, 1);
    assert.ok(!JSON.stringify(r).includes(TOKEN), "a transit error carrying the token is scrubbed");
    calls = [];
    assert.equal(code(await submitPaypalPayout(deps(store), order())), "PP3_DUPLICATE_REQUEST");
    assert.deepEqual(calls, []);
  }
});

test("two agents with the same request_id get distinct sender_batch_ids and PayPal-Request-Ids", async () => {
  const A2 = "agent-2";
  const t = signedText();
  chain.agent = { evm_address: ADDRESS, revoked: false };
  const d = deps();
  const getAgent = d.near.getAgent;
  d.near.getAgent = async (agent) => (agent === A2 ? chain.agent : getAgent(agent));
  d.near.getRequest = async (key) => ({ ...reservation(t), key });
  assert.equal((await submitPaypalPayout(d, order())).status, "submitted");
  post = accepted(batchId(A2, "inv-1"), "5UXD2E8A7EBQJ");
  assert.equal((await submitPaypalPayout(d, order({ agent: A2 }))).status, "submitted");
  const [a, b] = payoutPosts();
  assert.notEqual(a.body.sender_batch_header.sender_batch_id, b.body.sender_batch_header.sender_batch_id);
  assert.notEqual(a.headers["PayPal-Request-Id"], b.headers["PayPal-Request-Id"]);
  assert.equal(b.body.sender_batch_header.sender_batch_id, batchId(A2, "inv-1"));
  // The id is unambiguous: the separator keeps ("a", "b:c") and ("a:b", "c") apart too.
  assert.notEqual(batchId("a", "b:c"), batchId("a:b", "c"));
});

test("a 2xx for another sender_batch_id (a replayed cached 201) is refused, never recorded as submitted", async () => {
  // PayPal replays agent-2's 201 for this order: same payout_batch_id shape, other sender_batch_id.
  post = accepted(batchId("agent-2", "inv-1"));
  const store = memoryStore();
  const r = await submitPaypalPayout(deps(store), order());
  assert.equal(r.status, "pending");
  assert.equal(code(r), "PAYPAL_BATCH_MISMATCH");
  assert.ok(!("payout_batch_id" in r));
  const rec = store.get(AGENT, "inv-1")!;
  assert.equal(rec.state, "unknown");
  assert.equal(rec.payout_batch_id, undefined, "the other batch's id is not stored as ours");
  calls = [];
  assert.equal(code(await submitPaypalPayout(deps(store), order())), "PP3_DUPLICATE_REQUEST");
  assert.deepEqual(calls, []);
  // A 2xx with no sender_batch_header at all fails closed the same way.
  reset();
  post = { status: 201, body: { batch_header: { payout_batch_id: BATCH, batch_status: "PENDING" } } };
  assert.equal(code(await submitPaypalPayout(deps(), order())), "PAYPAL_BATCH_MISMATCH");
});

test("a 429 releases the claim: nothing is recorded, and the same order goes through later", async () => {
  const dir = mkdtempSync(join(tmpdir(), "pp3-"));
  try {
    for (const store of [memoryStore(), fileStore(dir)]) {
      reset();
      post = { status: 429, body: { name: "RATE_LIMIT_REACHED" } };
      const r = await submitPaypalPayout(deps(store), order());
      assert.equal(r.status, "failed");
      assert.equal(code(r), "PAYPAL_RATE_LIMITED");
      assert.equal(store.get(AGENT, "inv-1"), undefined);
      post = created;
      assert.equal((await submitPaypalPayout(deps(store), order())).status, "submitted");
      assert.equal(payoutPosts().length, 2);
      assert.equal(payoutPosts()[1].headers["PayPal-Request-Id"], SBID, "the retry reuses the same ids");
    }
    // If the release fails, the 429 is recorded refused and the request_id stays used (fails closed).
    reset();
    post = { status: 429, body: {} };
    const store = memoryStore();
    const stuck: Store = { ...store, release: () => { throw new Error("EACCES"); } };
    assert.equal(code(await submitPaypalPayout(deps(stuck), order())), "PAYPAL_REFUSED");
    assert.equal(store.get(AGENT, "inv-1")!.state, "refused");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a failed authentication leaves the request unclaimed and never carries the credentials", async () => {
  token = { status: 401, body: { error: "invalid_client", error_description: `bad ${CLIENT_ID}:${SECRET}` } };
  const store = memoryStore();
  // A result, not a throw (PayPal audit 1 H2): fail closed for every caller, no payout.
  const r = await submitPaypalPayout(deps(store), order());
  assert.equal(r.status, "failed");
  assert.equal(code(r), "PP3_AUTH_FAILED");
  const detail = (r as any).detail as string;
  assert.ok(/authentication failed/.test(detail), detail);
  assert.ok(!detail.includes(SECRET) && !detail.includes(CLIENT_ID), detail);
  assert.equal(store.records.size, 0);
  assert.equal(payoutPosts().length, 0);
  // The token request uses Basic auth and the form body; the secret is in no log.
  const auth = calls.find((c) => c.path === "/v1/oauth2/token")!;
  assert.equal(auth.body, "grant_type=client_credentials");
  assert.ok(auth.headers.Authorization.startsWith("Basic "));
  assert.ok(!logs.join("\n").includes(SECRET));
  reset();
  assert.equal((await submitPaypalPayout(deps(store), order())).status, "submitted", "the same request_id goes through later");
});

test("the client token is cached until shortly before expiry", async () => {
  let clock = 0;
  const fetcher = (async (url: string) => {
    calls.push({ path: new URL(url).pathname, method: "", headers: {}, body: null });
    return new Response(JSON.stringify({ access_token: TOKEN, expires_in: 600 }), { status: 200 });
  }) as typeof fetch;
  const c = sandboxClient({ PAYPAL_ENV: "sandbox", PAYPAL_CLIENT_ID: CLIENT_ID, PAYPAL_CLIENT_SECRET: SECRET }, fetcher, () => clock);
  await c.authenticate();
  clock = 200_000;
  await c.authenticate();
  assert.equal(calls.length, 1);
  clock = 301_000;
  await c.authenticate();
  assert.equal(calls.length, 2);
  assert.throws(() => sandboxClient({ PAYPAL_ENV: "live", PAYPAL_CLIENT_ID: "a", PAYPAL_CLIENT_SECRET: "b" }), /sandbox/);
  assert.throws(() => sandboxClient({ PAYPAL_ENV: "sandbox", PAYPAL_CLIENT_ID: "a" }), /PAYPAL_CLIENT_SECRET/);
});

test("an order that drops under SUBMIT_MARGIN_SECS during authentication is refused unclaimed", async () => {
  const store = memoryStore();
  let clock = NOW;
  const d = { ...deps(store), now: () => clock };
  const inner = d.paypal;
  d.paypal = { ...inner, authenticate: async () => { await inner.authenticate(); clock = TS + 240 - SUBMIT_MARGIN_SECS + 1; } };
  assert.equal(code(await submitPaypalPayout(d, order())), "PP3_ORDER_EXPIRED");
  assert.equal(payoutPosts().length, 0);
  assert.equal(store.get(AGENT, "inv-1"), undefined);
  clock = NOW;
  d.paypal = inner;
  assert.equal((await submitPaypalPayout(d, order())).status, "submitted");
});

test("an accepted payout is still reported with its batch id when the store update fails, and is never resubmitted", async () => {
  const store = memoryStore();
  const failing: Store = { ...store, update: () => { throw new Error("ENOSPC: no space left on device"); } };
  const r = await submitPaypalPayout(deps(failing), order());
  assert.deepEqual(r, { status: "submitted", request_id: "inv-1", payout_batch_id: BATCH, batch_status: "PENDING" });
  assert.ok(logs.some((l) => l.includes("record-failed inv-1") && l.includes(BATCH)));
  assert.equal(store.get(AGENT, "inv-1")!.state, "submitting");
  calls = [];
  assert.equal(code(await submitPaypalPayout(deps(failing), order())), "PP3_DUPLICATE_REQUEST");
  assert.deepEqual(calls, []);
});

test("scrub and maskEmail keep no payee, secret or token", () => {
  assert.equal(maskEmail("sb-abc123@personal.example.com"), "sb…@personal.example.com");
  assert.equal(maskEmail("a@example.com"), "a…@example.com");
  assert.equal(maskEmail("@demo-supplier"), "@de…");
  const out = scrub(`to ${PAYEE} with ${SECRET} and A21AAabc123def456ghi789jkl`, [SECRET]);
  assert.ok(!out.includes(PAYEE) && !out.includes(SECRET) && !out.includes("A21AAabc123def456ghi789jkl"), out);
});

const A1_TOKEN = "a1-bearer-token-0123456789abcdefghijklmn";
const A2_TOKEN = "a2-bearer-token-0123456789abcdefghijklmn";
test("a Venmo payee the contract signed is sent as VENMO_HANDLE, the handle as signed and masked everywhere (PayPal audit 2 L3)", async () => {
  const venmo = "@demo-supplier";
  const t = signedText({ payee: venmo });
  chain.requests.set("inv-1", reservation(t));
  chain.payees = [{ rail: "paypal", receiver: venmo }];
  const store = memoryStore();
  const r = await submitPaypalPayout(deps(store), order({ payee: venmo, signature: sign(t) }));
  assert.equal(r.status, "submitted");
  const [p] = payoutPosts();
  assert.equal(p.body.items[0].recipient_type, "VENMO_HANDLE");
  assert.equal(p.body.items[0].receiver, venmo);
  assert.equal(store.get(AGENT, "inv-1")!.payee_masked, "@de…");
  assert.ok(!logs.join("\n").includes(venmo), logs.join("\n"));
  // An email order still goes out as EMAIL, and a Venmo payee off the allowlist is refused, masked.
  reset();
  await submitPaypalPayout(deps(), order());
  assert.equal(payoutPosts()[0].body.items[0].recipient_type, "EMAIL");
  reset();
  chain.requests.set("inv-1", reservation(t));
  const off = await submitPaypalPayout(deps(), order({ payee: venmo, signature: sign(t) }));
  assert.equal(code(off), "PP3_PAYEE_NOT_ALLOWED");
  assert.ok(!JSON.stringify(off).includes(venmo) && !logs.join("\n").includes(venmo));
  assert.deepEqual(payoutPosts(), []);
});

test("the Venmo grammar is the contract's normalize_receiver, on its shared vectors", () => {
  const vectors = JSON.parse(readFileSync(new URL("../../../contract/tests/vectors/paypal.json", import.meta.url), "utf8")) as { receivers: { input: string; output: string | null }[] };
  const handles = vectors.receivers.filter((v) => v.input.trim().startsWith("@"));
  assert.ok(handles.length >= 3);
  // A canonical input (already the stored form) is accepted exactly when the contract stores it unchanged.
  for (const { input, output } of handles) assert.equal(isCanonicalVenmo(input), output === input, JSON.stringify(input));
});

const tokens = () => parseAgentTokens(`${AGENT}=${A1_TOKEN}, agent-2=${A2_TOKEN}`);

async function listen(d: Deps, limits = {}) {
  const s = server(d, tokens(), limits).listen(0, "127.0.0.1");
  await new Promise((r) => s.once("listening", r));
  const port = (s.address() as any).port as number;
  const url = `http://127.0.0.1:${port}`;
  const pay = (body: unknown, tok = A1_TOKEN) =>
    fetch(`${url}/payouts`, { method: "POST", headers: tok ? { authorization: `Bearer ${tok}` } : {}, body: typeof body === "string" ? body : JSON.stringify(body) });
  return { s, port, url, pay };
}

test("the service answers POST /payouts with the pay_paypal result and refuses anything else", async () => {
  const { s, url, pay } = await listen(deps());
  try {
    const ok = await pay(order());
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).payout_batch_id, BATCH);
    assert.equal((await fetch(`${url}/other`, { method: "POST", body: "{}" })).status, 404);
    assert.equal((await pay("nope")).status, 400);
    assert.equal((await pay(JSON.stringify({ ...order(), pad: "x".repeat(5000) }))).status, 413);
    // MAX_BODY counts bytes: under 4096 characters, but over 4096 bytes of UTF-8.
    const wide = JSON.stringify({ ...order(), pad: "é".repeat(2000) });
    assert.ok(wide.length < 4096 && Buffer.byteLength(wide) > 4096);
    assert.equal((await pay(wide)).status, 413);
  } finally {
    s.close();
  }
  // A fresh service (no cached token) whose PayPal authentication fails: 502, nothing claimed.
  reset();
  token = { status: 401, body: { error: "invalid_client" } };
  const t2 = signedText({ id: "inv-2" });
  chain.requests.set("inv-2", reservation(t2));
  const { s: s2, pay: pay2 } = await listen(deps());
  try {
    const failed = await pay2(order({ request_id: "inv-2", signature: sign(t2) }));
    assert.equal(failed.status, 200);
    const body = await failed.json();
    assert.equal(body.status, "failed");
    assert.equal(body.error_code, "PP3_AUTH_FAILED");
  } finally {
    s2.close();
  }
});

test("the service needs the order agent's own bearer token: another agent's or none is 401 and touches nothing", async () => {
  const store = memoryStore();
  const { s, pay } = await listen(deps(store));
  try {
    for (const t of ["", A2_TOKEN, `${A1_TOKEN}x`, A1_TOKEN.slice(0, -1)]) {
      assert.equal((await pay(order(), t)).status, 401);
    }
    assert.equal((await pay(order({ agent: "agent-3" }), A1_TOKEN)).status, 401);
    assert.deepEqual(calls, []);
    assert.deepEqual(chain.calls, []);
    assert.equal(store.records.size, 0);
    assert.equal((await pay(order())).status, 200);
    assert.ok(!logs.join("\n").includes(A1_TOKEN) && !logs.join("\n").includes(A2_TOKEN));
  } finally {
    s.close();
  }
  assert.throws(() => server(deps(), new Map()), /PP3_AGENT_TOKENS/);
  for (const bad of ["agent-1", "agent-1=short", "a/b=" + A1_TOKEN, `agent-1=${A1_TOKEN},agent-1=${A2_TOKEN}`]) {
    assert.throws(() => parseAgentTokens(bad), /PP3_AGENT_TOKENS/, bad);
  }
});

test("a client that disconnects mid-body does not take the service down and submits nothing", async () => {
  const { s, port, pay } = await listen(deps());
  try {
    await new Promise<void>((done) => {
      const c = connect(port, "127.0.0.1", () => {
        c.write(`POST /payouts HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\ncontent-length: 500\r\nauthorization: Bearer ${A1_TOKEN}\r\n\r\n{"agent":"agent-1",`);
        setTimeout(() => (c.destroy(), done()), 20);
      });
      c.on("error", () => done());
    });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(calls, []);
    assert.equal((await (await pay(order())).json()).status, "submitted");
  } finally {
    s.close();
  }
});

test("a body that trickles or stalls is 408 within the deadline and submits nothing (PayPal audit 2 M2)", async () => {
  const { s, port, pay } = await listen(deps(), { bodyTimeoutMs: 300, idleTimeoutMs: 150 });
  const head = `POST /payouts HTTP/1.1\r\nhost: x\r\ncontent-length: 4000\r\nauthorization: Bearer ${A1_TOKEN}\r\n\r\n`;
  try {
    const slow = await trickle(port, head, 50); // under the idle limit, over the whole-body deadline
    assert.match(slow.answer, /^HTTP\/1\.1 408 /);
    assert.ok(slow.ms < 2_000, `${slow.ms} ms`);
    const stalled = await trickle(port, head, 60_000); // headers, then nothing
    assert.match(stalled.answer, /^HTTP\/1\.1 408 /);
    assert.ok(stalled.ms < 1_000, `${stalled.ms} ms`);
    assert.deepEqual(calls, []);
    // A declared length over the cap is refused before any body is read.
    const big = await trickle(port, head.replace("4000", "5000"), 60_000);
    assert.match(big.answer, /^HTTP\/1\.1 413 /);
    assert.equal((await (await pay(order())).json()).status, "submitted");
  } finally {
    s.close();
  }
  // The defaults: Node's own request and header timeouts are set.
  const d = server(deps(), tokens());
  assert.ok(d.requestTimeout > 0 && d.requestTimeout <= 15_000 && d.headersTimeout > 0 && d.headersTimeout <= d.requestTimeout);
});

test("an invalid request_id is 400 at the boundary and never reaches a log line", async () => {
  const leak = "tok_0123456789abcdef\nforged log line";
  const { s, pay } = await listen(deps());
  try {
    for (const bad of [{ request_id: leak }, { request_id: 42 as any }, { agent: leak }]) {
      const r = await pay(order(bad));
      assert.equal(r.status, 400);
      assert.ok(!(await r.text()).includes("tok_0123456789abcdef"));
    }
  } finally {
    s.close();
  }
  assert.equal(code(await submitPaypalPayout(deps(), order({ request_id: leak }))), "PP3_INVALID_INPUT");
  assert.ok(!logs.join("\n").includes("forged"));
  assert.deepEqual(calls, []);
});

test("the amount grammar is the contract's amount_to_cents, on its shared vectors (PayPal audit 1 H3)", () => {
  const vectors = JSON.parse(readFileSync(new URL("../../../contract/tests/vectors/paypal.json", import.meta.url), "utf8")) as { amounts: { amount: string; cents: number | null }[] };
  assert.ok(vectors.amounts.length > 10);
  for (const { amount, cents } of vectors.amounts) assert.equal(isCanonicalAmount(amount), cents !== null, JSON.stringify(amount));
});

test("PayPal error text that echoes the payee or a lookalike never carries the full email (PayPal audit 1 L3)", async () => {
  const echoed = [PAYEE, PAYEE.toUpperCase(), "Supplier.Billing+tag@Sub.Example.co.uk"];
  post = { status: 422, body: { name: "RECEIVER_UNREGISTERED", message: `Receiver ${echoed[0]} is unregistered`, details: [{ field: "items[0].receiver", issue: `${echoed[1]} / ${echoed[2]} cannot receive`, description: `contact ${echoed[0]}` }] } };
  const store = memoryStore();
  const r = await submitPaypalPayout(deps(store), order());
  assert.equal(code(r), "PAYPAL_REFUSED");
  const out = JSON.stringify(r) + JSON.stringify(store.get(AGENT, "inv-1")) + logs.join("\n");
  for (const e of echoed) assert.ok(!out.toLowerCase().includes(e.toLowerCase()), `${e} leaked: ${out}`);
});
