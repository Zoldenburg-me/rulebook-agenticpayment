// M1 with NEAR and the Monerium sandbox mocked: the contract views are an in-memory `Near`, and
// Monerium is O2's sandbox client over a fake fetch that records every call. Signatures are real
// secp256k1 signatures over the EIP-191 digest of the payout text.
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, test } from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { publicKeyToAddress } from "@nearh/owner-near/src/derive.ts";
import { sandboxClient } from "@nearh/owner-monerium/src/monerium.ts";
import { canonicalAmount, eip191Digest, orderSignature, scrub, submitPayout, SUBMIT_MARGIN_SECS, type Deps, type Payee, type Reservation } from "../src/payout.ts";
import { parseAgentTokens, server } from "../src/server.ts";
import { fileStore, memoryStore, type Store } from "../src/store.ts";

const AGENT = "agent-1";
/** Documentation IBANs (docs/interfaces.md), not accounts of ours. */
const IBAN = "DE89370400440532013000";
const ATTACKER = "GB33BUKB20201555555555";
const TS = 1793700000; // 2026-11-03T10:00:00Z
const NOW = TS + 30;
const KEY = secp256k1.utils.randomSecretKey();
const ADDRESS = publicKeyToAddress(secp256k1.getPublicKey(KEY, false));
const SECRET = "client-secret-do-not-print-7f3a";
const TOKEN = "access-token-do-not-print-91bc";
const ORDER_ID = "32298aa0-cbd1-425d-9ba5-012295db6b80";

const text = (amount: string, iban: string) => `Send EUR ${amount} to ${iban} at 2026-11-03T10:00:00Z`;

function sign(t: string, key = KEY) {
  const sig = secp256k1.sign(eip191Digest(t), key, { prehash: false, format: "recovered" });
  return { r: `0x${bytesToHex(sig.slice(1, 33))}`, s: `0x${bytesToHex(sig.slice(33))}`, v: 27 + sig[0] };
}

function reservation(t = text("0.01", IBAN), over: Partial<Reservation> = {}): Reservation {
  return {
    key: { agent: AGENT, caller: { kind: "agent" }, request_id: "inv-1" },
    shape: "payout",
    rail: "sepa",
    valid_before: TS + 240,
    digest: `0x${bytesToHex(eip191Digest(t))}`,
    payload: { kind: "message", text: t },
    status: "signed",
    signature: sign(t),
    ...over,
  };
}

type Reply = { status: number; body?: unknown } | "throw";
let chain: { agent: any; requests: Map<string, Reservation>; payees: Payee[]; calls: string[] };
let calls: { path: string; body: any }[];
let logs: string[];
let post: Reply;
let token: Reply;

function monerium() {
  const fetcher = (async (url: string, init: RequestInit) => {
    const path = new URL(url).pathname;
    calls.push({ path, body: path === "/auth/token" ? String(init.body) : JSON.parse(String(init.body)) });
    const r = path === "/auth/token" ? token : post;
    if (r === "throw") throw new Error(`socket hang up, bearer ${TOKEN}`);
    return new Response(JSON.stringify(r.body ?? {}), { status: r.status });
  }) as typeof fetch;
  return sandboxClient({ MONERIUM_ENVIRONMENT: "sandbox", MONERIUM_CLIENT_ID: "client-id", MONERIUM_CLIENT_SECRET: SECRET }, fetcher);
}

function deps(store: Store = memoryStore()): Deps {
  return {
    near: {
      getAgent: async (agent) => (chain.calls.push(`get_agent ${agent}`), agent === AGENT ? chain.agent : null),
      getRequest: async (key) => (chain.calls.push(`get_request ${key.request_id}`), chain.requests.get(key.request_id) ?? null),
      getPayees: async (agent) => (chain.calls.push(`get_payees ${agent}`), chain.payees),
    },
    monerium: monerium(),
    secrets: ["client-id", SECRET],
    store,
    now: () => NOW,
    log: (l) => logs.push(l),
  };
}

const input = (over = {}) => ({ agent: AGENT, request_id: "inv-1", iban: IBAN, amount: "0.01", memo: "Invoice 1", ...over });
const orderPosts = () => calls.filter((c) => c.path === "/orders");

beforeEach(() => {
  chain = { agent: { evm_address: ADDRESS, revoked: false }, requests: new Map([["inv-1", reservation()]]), payees: [{ rail: "sepa", iban: IBAN }], calls: [] };
  calls = [];
  logs = [];
  post = { status: 200, body: { id: ORDER_ID, state: "placed" } };
  token = { status: 200, body: { access_token: TOKEN } };
});

test("an accepted payout posts the contract-signed order once and stores Monerium's order id", async () => {
  const store = memoryStore();
  const r = await submitPayout(deps(store), input());
  assert.deepEqual(r, { status: "submitted", request_id: "inv-1", monerium_order_id: ORDER_ID });
  assert.equal(orderPosts().length, 1);
  const body = orderPosts()[0].body;
  assert.equal(body.message, text("0.01", IBAN));
  assert.equal(body.amount, "0.01");
  assert.equal(body.address, ADDRESS);
  assert.equal(body.chain, "basesepolia");
  assert.equal(body.kind, "redeem");
  assert.equal(body.memo, "Invoice 1");
  assert.deepEqual(body.counterpart.identifier, { standard: "iban", iban: IBAN });
  assert.equal(orderSignature(reservation().signature!, eip191Digest(body.message), ADDRESS), body.signature);
  const rec = store.get(AGENT, "inv-1")!;
  assert.equal(rec.state, "submitted");
  assert.equal(rec.monerium_order_id, ORDER_ID);
  assert.equal(rec.iban_last4, "3000");
  assert.ok(!JSON.stringify(rec).includes(IBAN), "the store keeps no full IBAN");
  assert.ok(!logs.join("\n").includes(IBAN), "logs keep no full IBAN");
});

test("the amount the agent passes is canonicalised (D9): 00.01 matches a signed 0.01, 0.010 is not an amount", async () => {
  assert.equal((await submitPayout(deps(), input({ amount: "0.010" }))).status, "blocked");
  assert.equal((await submitPayout(deps(), input({ amount: "00.01" }))).status, "submitted");
  for (const [i, o] of [["007.50", "7.5"], ["1.50", "1.5"], ["2.00", "2"], ["0.50", "0.5"], ["42.5", "42.5"]]) assert.equal(canonicalAmount(i), o);
  for (const bad of [".5", "5.", "-1", "1e2", "1,5", "0", "0.00", " 1", "1.555"]) assert.equal(canonicalAmount(bad), undefined, bad);
});

test("a second submission of the same request_id is refused without calling NEAR or Monerium", async () => {
  const d = deps();
  assert.equal((await submitPayout(d, input())).status, "submitted");
  calls = [];
  chain.calls = [];
  const again = await submitPayout(d, input());
  assert.equal(again.status, "blocked");
  assert.equal((again as any).error_code, "M1_DUPLICATE_REQUEST");
  assert.match((again as any).detail, new RegExp(ORDER_ID));
  assert.deepEqual(calls, []);
  assert.deepEqual(chain.calls, []);
});

test("concurrent submissions of one request_id post once", async () => {
  const d = deps();
  const rs = await Promise.all([submitPayout(d, input()), submitPayout(d, input()), submitPayout(d, input())]);
  assert.equal(rs.filter((r) => r.status === "submitted").length, 1);
  assert.equal(rs.filter((r) => (r as any).error_code === "M1_DUPLICATE_REQUEST").length, 2);
  assert.equal(orderPosts().length, 1);
});

test("the file store survives a restart: a new M1 process refuses the request_id with no HTTP call", async () => {
  const dir = mkdtempSync(join(tmpdir(), "m1-store-"));
  try {
    assert.equal((await submitPayout(deps(fileStore(dir)), input())).status, "submitted");
    calls = [];
    const r = await submitPayout(deps(fileStore(dir)), input());
    assert.equal((r as any).error_code, "M1_DUPLICATE_REQUEST");
    assert.deepEqual(calls, []);
    const files = readdirSync(dir);
    assert.equal(files.length, 1);
    const saved = readFileSync(join(dir, files[0]), "utf8");
    assert.equal(JSON.parse(saved).monerium_order_id, ORDER_ID);
    for (const s of [IBAN, SECRET, TOKEN]) assert.ok(!saved.includes(s));
    // Two stores on one dir: only one claim wins.
    const [a, b] = [fileStore(dir), fileStore(dir)];
    const rec = { agent: AGENT, request_id: "inv-x", state: "submitting" as const, iban_last4: "3000", amount: "1", at: "" };
    assert.deepEqual([a.claim(rec), b.claim(rec)], [true, false]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an attacker IBAN the contract did not sign never reaches Monerium", async () => {
  const r = await submitPayout(deps(), input({ iban: ATTACKER }));
  assert.equal(r.status, "blocked");
  assert.equal((r as any).error_code, "M1_ORDER_MISMATCH");
  assert.ok(!(r as any).detail.includes(ATTACKER), "the IBAN is redacted in the detail");
  assert.match((r as any).detail, /<IBAN …5555>/);
  assert.deepEqual(calls, []);
  // The request was not claimed: the honest hand-over still goes through.
  assert.equal((await submitPayout(deps(), input())).status, "submitted");
});

test("a signed order to an IBAN that is not on the agent's payees never reaches Monerium", async () => {
  // E.g. the payee was removed after signing, or the contract signed against a stale allowlist.
  chain.requests.set("inv-1", reservation(text("0.01", ATTACKER)));
  const r = await submitPayout(deps(), input({ iban: ATTACKER }));
  assert.equal((r as any).error_code, "M1_IBAN_NOT_ALLOWED");
  assert.ok(!(r as any).detail.includes(ATTACKER));
  // An x402 payee with the same text, or a differently formatted IBAN, does not count.
  chain.payees = [{ rail: "x402", pay_to: ATTACKER }, { rail: "sepa", iban: "GB33 BUKB 2020 1555 5555 55" }];
  assert.equal((await submitPayout(deps(), input({ iban: ATTACKER }))).status, "blocked");
  assert.deepEqual(calls, []);
  assert.ok(!logs.join("\n").includes(ATTACKER));
});

test("an amount other than the signed one never reaches Monerium", async () => {
  const r = await submitPayout(deps(), input({ amount: "50" }));
  assert.equal((r as any).error_code, "M1_ORDER_MISMATCH");
  assert.deepEqual(calls, []);
});

test("only a signed, live payout of a live agent is submitted", async () => {
  const cases: [string, () => void][] = [
    ["M1_NOT_SIGNED", () => chain.requests.set("inv-1", reservation(undefined, { status: "released" }))],
    ["M1_NOT_SIGNED", () => chain.requests.set("inv-1", reservation(undefined, { status: "unknown", signature: null }))],
    ["M1_NOT_SIGNED", () => chain.requests.set("inv-1", reservation(undefined, { status: "pending", signature: null }))],
    ["M1_NOT_A_PAYOUT", () => chain.requests.set("inv-1", reservation(undefined, { shape: "x402", rail: "x402" }))],
    ["M1_REQUEST_NOT_FOUND", () => chain.requests.clear()],
    ["M1_ORDER_EXPIRED", () => chain.requests.set("inv-1", reservation(undefined, { valid_before: NOW - 1 }))],
    ["M1_BAD_SIGNATURE", () => chain.requests.set("inv-1", reservation(undefined, { signature: sign(text("0.01", IBAN), secp256k1.utils.randomSecretKey()) }))],
    ["M1_BAD_SIGNATURE", () => chain.requests.set("inv-1", reservation(undefined, { digest: `0x${"00".repeat(32)}` }))],
    ["M1_BAD_SIGNATURE", () => chain.requests.set("inv-1", reservation(undefined, { signature: { r: "0x1", s: "0x1", v: 29 } }))],
    ["M1_ORDER_MISMATCH", () => chain.requests.set("inv-1", reservation(`${text("0.01", IBAN)} extra`))],
    ["M1_AGENT_REVOKED", () => (chain.agent = { evm_address: ADDRESS, revoked: true })],
    ["M1_UNKNOWN_AGENT", () => (chain.agent = { evm_address: null, revoked: false })],
  ];
  for (const [code, setup] of cases) {
    beforeEachReset();
    setup();
    const r = await submitPayout(deps(), input());
    assert.equal((r as any).error_code, code, code);
    assert.deepEqual(calls, [], `${code}: no Monerium call`);
  }
  for (const bad of [{ agent: "a/b" }, { request_id: "" }, { request_id: "x".repeat(65) }, { iban: "de89370400440532013000" }, { memo: "m".repeat(141) }]) {
    const r = await submitPayout(deps(), input(bad));
    assert.equal((r as any).error_code, "M1_INVALID_INPUT");
  }
  assert.deepEqual(calls, []);
});

function beforeEachReset() {
  chain = { agent: { evm_address: ADDRESS, revoked: false }, requests: new Map([["inv-1", reservation()]]), payees: [{ rail: "sepa", iban: IBAN }], calls: [] };
  calls = [];
}

test("Monerium's 400 Duplicate order maps to MONERIUM_DUPLICATE_ORDER and the request_id stays used", async () => {
  post = { status: 400, body: { code: 400, status: "Bad Request", message: "Duplicate order" } };
  const store = memoryStore();
  const r = await submitPayout(deps(store), input());
  assert.equal(r.status, "failed");
  assert.equal((r as any).error_code, "MONERIUM_DUPLICATE_ORDER");
  assert.equal(store.get(AGENT, "inv-1")!.state, "duplicate_order");
  calls = [];
  assert.equal(((await submitPayout(deps(store), input())) as any).error_code, "M1_DUPLICATE_REQUEST");
  assert.deepEqual(calls, []);
});

test("other refusals: a 400 with another message is MONERIUM_REFUSED, a 5xx or lost answer is outcome unknown", async () => {
  post = { status: 400, body: { code: 400, message: `Invalid counterpart ${ATTACKER}` } };
  const store = memoryStore();
  let r: any = await submitPayout(deps(store), input());
  assert.equal(r.error_code, "MONERIUM_REFUSED");
  assert.ok(!r.detail.includes(ATTACKER));
  assert.equal(store.get(AGENT, "inv-1")!.state, "refused");

  for (const reply of [{ status: 502, body: {} }, "throw" as const, { status: 200, body: { state: "placed" } }, { status: 200, body: { id: ORDER_ID, state: "rejected" } }]) {
    beforeEachReset();
    post = reply;
    const s = memoryStore();
    r = await submitPayout(deps(s), input());
    assert.equal(r.status, "pending");
    assert.equal(r.error_code, "MONERIUM_OUTCOME_UNKNOWN");
    assert.equal(s.get(AGENT, "inv-1")!.state, "unknown");
    // Never retried automatically: the outcome must be checked by hand.
    calls = [];
    assert.equal(((await submitPayout(deps(s), input())) as any).error_code, "M1_DUPLICATE_REQUEST");
    assert.deepEqual(calls, []);
  }
});

test("credentials never appear in results, logs, errors or the store", async () => {
  const outputs: string[] = [];
  const dir = mkdtempSync(join(tmpdir(), "m1-creds-"));
  try {
    // Accepted, refused with the token echoed back, lost in transit (the error names the token).
    for (const [i, reply] of [{ status: 200, body: { id: ORDER_ID } }, { status: 400, body: { message: `bad ${TOKEN} ${SECRET}` } }, "throw" as const].entries()) {
      post = reply;
      chain.requests.set(`inv-${i}`, reservation(undefined, { key: { agent: AGENT, caller: { kind: "agent" }, request_id: `inv-${i}` } }));
      outputs.push(JSON.stringify(await submitPayout(deps(fileStore(dir)), input({ request_id: `inv-${i}` }))));
    }
    // Auth refused: thrown before anything is claimed, so the request can be retried.
    token = { status: 401, body: { error: "invalid_client", error_description: `bad secret ${SECRET}` } };
    chain.requests.set("inv-9", reservation());
    const d = deps(fileStore(dir));
    await assert.rejects(submitPayout(d, input({ request_id: "inv-9" })), (e: any) => (outputs.push(String(e.message)), true));
    assert.equal(d.store.get(AGENT, "inv-9"), undefined);
    for (const f of readdirSync(dir)) outputs.push(readFileSync(join(dir, f), "utf8"));
    outputs.push(...logs);
    const all = outputs.join("\n");
    assert.ok(all.length > 0);
    for (const s of [SECRET, TOKEN]) assert.ok(!all.includes(s), `output contains ${s}`);
    assert.ok(!all.includes(IBAN));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  // Without the exact values, the token-like pattern alone still hides a long random credential.
  const raw = "Q2xpZW50U2VjcmV0OnhZejEyMw4rT9";
  for (const secret of [raw, ORDER_ID.replace(/-/g, ""), "fake_tok_0123456789abcdefghij"]) {
    const out = scrub(`refused: ${secret} (HTTP 401)`);
    assert.ok(!out.includes(secret.slice(4, -4)), out);
    assert.match(out, /^refused: .*\(HTTP 401\)$/);
  }
  assert.equal(scrub("Duplicate order"), "Duplicate order");
  // The secret only goes to the token endpoint, the token only as a bearer header to the sandbox.
  assert.ok(calls.filter((c) => c.path !== "/auth/token").every((c) => !JSON.stringify(c.body).includes(SECRET)));
});

const A1_TOKEN = "a1-bearer-token-0123456789abcdefghijklmn";
const A2_TOKEN = "a2-bearer-token-0123456789abcdefghijklmn";
const tokens = () => parseAgentTokens(`${AGENT}=${A1_TOKEN}, agent-2=${A2_TOKEN}`);

async function listen(d: Deps) {
  const s = server(d, tokens()).listen(0, "127.0.0.1");
  await new Promise((r) => s.once("listening", r));
  const port = (s.address() as any).port as number;
  const url = `http://127.0.0.1:${port}`;
  const pay = (body: unknown, token = A1_TOKEN) =>
    fetch(`${url}/payouts`, { method: "POST", headers: token ? { authorization: `Bearer ${token}` } : {}, body: typeof body === "string" ? body : JSON.stringify(body) });
  return { s, port, url, pay };
}

test("the service answers POST /payouts with the pay_sepa result and refuses anything else", async () => {
  const { s, url, pay } = await listen(deps());
  try {
    const ok = await pay(input());
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).monerium_order_id, ORDER_ID);
    assert.equal((await fetch(`${url}/orders`, { method: "POST", body: "{}" })).status, 404);
    assert.equal((await pay("nope")).status, 400);
    token = { status: 401, body: { error: "invalid_client" } };
    chain.requests.set("inv-2", reservation());
    const failed = await pay(input({ request_id: "inv-2" }));
    assert.equal(failed.status, 502);
    assert.equal((await failed.json()).error_code, "M1_ERROR");
  } finally {
    s.close();
  }
});

test("the service needs the payout agent's own bearer token: another agent's or none is 401 and touches nothing", async () => {
  const store = memoryStore();
  const { s, pay } = await listen(deps(store));
  try {
    for (const t of ["", A2_TOKEN, `${A1_TOKEN}x`, A1_TOKEN.slice(0, -1)]) {
      const r = await pay(input(), t);
      assert.equal(r.status, 401, `token ${t.slice(-4)}`);
    }
    // An agent with no configured token is refused even with a valid token of another agent.
    assert.equal((await pay(input({ agent: "agent-3" }), A1_TOKEN)).status, 401);
    assert.deepEqual(calls, []);
    assert.deepEqual(chain.calls, []);
    assert.equal(store.records.size, 0, "nothing claimed: the agent's own hand-over still goes through");
    assert.equal((await pay(input())).status, 200);
    assert.ok(!logs.join("\n").includes(A1_TOKEN) && !logs.join("\n").includes(A2_TOKEN));
  } finally {
    s.close();
  }
  assert.throws(() => server(deps(), new Map()), /M1_AGENT_TOKENS/);
  for (const bad of ["agent-1", "agent-1=short", "a/b=" + A1_TOKEN, `agent-1=${A1_TOKEN},agent-1=${A2_TOKEN}`]) {
    assert.throws(() => parseAgentTokens(bad), /M1_AGENT_TOKENS/, bad);
  }
});

test("a client that disconnects mid-body does not take the service down", async () => {
  const { s, port, pay } = await listen(deps());
  try {
    for (let i = 0; i < 3; i++) {
      await new Promise<void>((done) => {
        const c = connect(port, "127.0.0.1", () => {
          c.write(`POST /payouts HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\ncontent-length: 500\r\nauthorization: Bearer ${A1_TOKEN}\r\n\r\n{"agent":"agent-1",`);
          setTimeout(() => (c.destroy(), done()), 20);
        });
        c.on("error", () => done());
      });
    }
    // A malformed request line, then a reset socket: still serving.
    await new Promise<void>((done) => {
      const c = connect(port, "127.0.0.1", () => (c.write("garbage\r\n\r\n"), setTimeout(() => (c.destroy(), done()), 20)));
      c.on("error", () => done());
    });
    await new Promise((r) => setTimeout(r, 50));
    assert.deepEqual(calls, [], "a half-sent payout is never submitted");
    const ok = await pay(input());
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).status, "submitted");
  } finally {
    s.close();
  }
});

test("an invalid request_id is refused at the boundary and never reaches a log line", async () => {
  const leak = "DE89370400440532013000-tok_0123456789abcdef\nforged log line";
  const { s, pay } = await listen(deps());
  try {
    for (const bad of [{ request_id: leak }, { request_id: 42 }, { request_id: "x".repeat(65) }, { agent: leak }]) {
      const r = await pay(input(bad));
      assert.equal(r.status, 400);
      assert.ok(!(await r.text()).includes("tok_0123456789abcdef"));
    }
    // Also through the 502 path and an unauthorised call: only validated ids are logged.
    token = { status: 401, body: { error: "invalid_client" } };
    assert.equal((await pay(input({ request_id: leak }), "")).status, 400);
    assert.deepEqual(calls, []);
  } finally {
    s.close();
  }
  // submitPayout itself (the CLI path) does not log a malformed request_id either.
  const r = await submitPayout(deps(), input({ request_id: leak }));
  assert.equal((r as any).error_code, "M1_INVALID_INPUT");
  const all = logs.join("\n");
  assert.ok(!all.includes("tok_0123456789abcdef") && !all.includes("forged") && !all.includes(IBAN), all);
});

test("an order that expires while M1 authenticates is refused before the claim and leaves the request_id unused", async () => {
  const store = memoryStore();
  let clock = NOW;
  const d = { ...deps(store), now: () => clock };
  // Authentication takes until the order has less than SUBMIT_MARGIN_SECS left.
  const inner = d.monerium;
  d.monerium = { ...inner, authenticate: async () => { await inner.authenticate(); clock = TS + 240 - SUBMIT_MARGIN_SECS + 1; } };
  const r = await submitPayout(d, input());
  assert.equal(r.status, "blocked");
  assert.equal((r as any).error_code, "M1_ORDER_EXPIRED");
  assert.equal(orderPosts().length, 0, "never posted");
  assert.equal(store.get(AGENT, "inv-1"), undefined, "not claimed");
  // Still before the margin: the same request_id goes through.
  clock = NOW;
  d.monerium = inner;
  assert.equal((await submitPayout(d, input())).status, "submitted");
});

test("an accepted order is still reported with its id when the store update fails, and is never resubmitted", async () => {
  const store = memoryStore();
  const failing: Store = { ...store, update: () => { throw new Error("ENOSPC: no space left on device"); } };
  const r = await submitPayout(deps(failing), input());
  assert.deepEqual(r, { status: "submitted", request_id: "inv-1", monerium_order_id: ORDER_ID });
  assert.ok(logs.some((l) => l.includes("record-failed inv-1") && l.includes(ORDER_ID)), "the order id is logged for recovery");
  // The claim stays: the same request_id is refused without another POST.
  assert.equal(store.get(AGENT, "inv-1")!.state, "submitting");
  calls = [];
  assert.equal(((await submitPayout(deps(failing), input())) as any).error_code, "M1_DUPLICATE_REQUEST");
  assert.deepEqual(calls, []);
  // Same for a refusal: the result comes back, the claim stays.
  beforeEachReset();
  post = { status: 400, body: { message: "nope" } };
  const s2 = memoryStore();
  assert.equal(((await submitPayout(deps({ ...s2, update: failing.update }), input())) as any).error_code, "MONERIUM_REFUSED");
  assert.equal(s2.get(AGENT, "inv-1")!.state, "submitting");
});
