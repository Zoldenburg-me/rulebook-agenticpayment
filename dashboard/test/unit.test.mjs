// Owner-call encoding (docs/interfaces.md §2) and the held endpoint of the shipped server.

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { createServer, request } from "node:http";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { b64url, derToRaw, heldDecideArgs, ownerChallenge, resolveArgs, revokeArgs, Writer } from "../public/owner.js";
import { formatUsd, maskPayee, parsePaypalText } from "../public/paypal.js";
import { assertOwnerOrigin, decideHeld, defaultHeldFile, defaultPaypalStoreDir, readPaypalStore, startServer } from "../serve.mjs";
import { maskEmail, paypalMessage } from "../../rails/paypal/src/payout.ts";

const hex = (b) => Buffer.from(b).toString("hex");
const FIXTURE = new URL("./fixtures/held.jsonl", import.meta.url);

test("challenge matches the §2 worked vector (set_relayer)", async () => {
  const args = new Writer().u8(1).string("relayer-demo.testnet").done();
  const c = await ownerChallenge("mandate-demo.testnet", "testnet", "set_relayer", args, 1, 1793600000);
  assert.equal(hex(c), "ec27a25ee1455067baa5daecd431d5c72f6b40842bf3c0df9a8c284b17bd72c5");
  assert.equal(b64url(c), "7CeiXuFFUGe6pdrs1DHVxy9rQIQr88DfmowoSxe9csU");
});

test("revoke and resolve_reservation args are the contract's borsh tuples", () => {
  assert.equal(hex(revokeArgs("agent-1")), "07000000" + hex(Buffer.from("agent-1")));
  const s = (x) => hex(Buffer.from([x.length, 0, 0, 0])) + hex(Buffer.from(x));
  const agentKey = { agent: "agent-1", caller: { kind: "agent" }, request_id: "inv-2026-0042" };
  assert.equal(hex(resolveArgs(agentKey, "spent")), s("agent-1") + "00" + s("inv-2026-0042") + "00");
  const relayerKey = { agent: "agent-1", caller: { kind: "relayer", account: "relayer-demo.testnet" }, request_id: "sweep-1" };
  assert.equal(hex(resolveArgs(relayerKey, "released")), s("agent-1") + "02" + s("relayer-demo.testnet") + s("sweep-1") + "01");
  assert.throws(() => resolveArgs(agentKey, "Spent"), /unknown outcome/);
  assert.throws(() => resolveArgs({ ...agentKey, caller: { kind: "x" } }, "spent"), /unknown caller/);
});

test("DER signatures become raw 64-byte r||s", () => {
  const r = Buffer.alloc(32, 0x81); // high bit set: DER adds a 0x00 pad
  const s = Buffer.concat([Buffer.from([0x00, 0x00]), Buffer.alloc(30, 0x11)]); // short: DER drops leading zeros
  const der = Buffer.concat([Buffer.from([0x30, 2 + 33 + 2 + 30, 0x02, 33, 0x00]), r, Buffer.from([0x02, 30]), s.subarray(2)]);
  assert.equal(hex(derToRaw(der)), hex(Buffer.concat([r, s])));
  assert.throws(() => derToRaw(der.subarray(0, der.length - 1)), /malformed/);
  assert.throws(() => derToRaw(Buffer.concat([der, Buffer.from([0])])), /malformed/);
});

function tempHeld() {
  const file = join(mkdtempSync(join(tmpdir(), "db1-")), "held.jsonl");
  copyFileSync(FIXTURE, file);
  return file;
}
const items = (file) => readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));

test("held items move only held → approved | rejected, each with a greater nonce", () => {
  const file = tempHeld();
  assert.equal(decideHeld(file, "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", "approved", 1, new Date("2026-11-03T11:00:00.123Z")).status, "approved");
  const [a, b] = items(file);
  assert.deepEqual([a.status, a.decided_at, a.decided_nonce, b.status], ["approved", "2026-11-03T11:00:00Z", 1, "held"]);
  assert.throws(() => decideHeld(file, "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", "rejected", 2), /already approved/);
  assert.throws(() => decideHeld(file, "held-1c7d2e3f-4051-4b62-9c73-8d94ea5fb607", "held", 2), /approved or rejected/);
  assert.throws(() => decideHeld(file, "held-ffffffff-ffff-4fff-bfff-ffffffffffff", "rejected", 2), /no held item/);
  assert.throws(() => decideHeld(file, "held-1c7d2e3f-4051-4b62-9c73-8d94ea5fb607", "rejected", 1), /stale owner_nonce/);
  assert.equal(items(file)[1].status, "held");
});

test("held decision args are borsh((id: String, status: u8))", () => {
  assert.equal(hex(heldDecideArgs("held-0001", "approved")), "09000000" + hex(Buffer.from("held-0001")) + "00");
  assert.equal(hex(heldDecideArgs("held-0001", "rejected")).slice(-2), "01");
  assert.throws(() => heldDecideArgs("held-0001", "held"), /approved or rejected/);
});

test("the server refuses cross-origin and non-testnet use", async () => {
  await assert.rejects(startServer({ port: 0, contractId: "mandate.near", nearRpc: "https://rpc.testnet.near.org" }), /testnet account/);
  await assert.rejects(startServer({ port: 0, contractId: "m.testnet", nearRpc: "https://rpc.mainnet.near.org" }), /testnet RPC/);

  const heldFile = tempHeld();
  const getConfig = async () => ({ owner: { mode: "wallet", account: "owner.testnet" }, owner_nonce: 0, network: "testnet" });
  const s = await startServer({ port: 0, contractId: "m.testnet", nearRpc: "https://rpc.testnet.near.org", heldFile, relay: async () => ({ ok: true }), getConfig });
  assert.equal(s.server.address().address, "127.0.0.1");
  const base = `http://127.0.0.1:${s.port}`;
  const post = (path, body, headers = {}) =>
    fetch(base + path, { method: "POST", headers: { "content-type": "application/json", origin: base, ...headers }, body: JSON.stringify(body) });
  try {
    assert.equal((await post("/api/held/decide", { id: "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", status: "approved" }, { origin: "https://evil.example" })).status, 403);
    assert.equal((await post("/api/held/decide", { id: "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", status: "approved" }, { "content-type": "text/plain" })).status, 415);
    assert.equal((await post("/api/owner-call", { method: "set_mandate", args: {}, assertion: {} })).status, 400);
    assert.equal(items(heldFile)[0].status, "held");
    const page = await fetch(base + "/");
    assert.match(page.headers.get("content-security-policy"), /script-src 'self';/);
    assert.equal((await fetch(base + "/../serve.mjs")).status, 404);
  } finally {
    await s.close();
  }
});

test("the held file follows SC1's SCAMCHECK_HELD_DIR from the env only, never scamcheck/.env", () => {
  const dir = mkdtempSync(join(tmpdir(), "db1-sc1-"));
  assert.equal(defaultHeldFile(dir, {}), join(dir, ".held", "held.jsonl"));
  writeFileSync(join(dir, ".env"), "NEAR_AI_API_KEY=x\nSCAMCHECK_HELD_DIR=queue\n");
  assert.equal(defaultHeldFile(dir, {}), join(dir, ".held", "held.jsonl"));
  assert.equal(defaultHeldFile(dir, { SCAMCHECK_HELD_DIR: "queue" }), join(dir, "queue", "held.jsonl"));
  assert.equal(defaultHeldFile(dir, { SCAMCHECK_HELD_DIR: "/abs/q" }), "/abs/q/held.jsonl");
});

// A passkey owner as the contract reports it, and an authenticator that signs like a browser.
const CONTRACT = "m.testnet";
const sha = (b) => createHash("sha256").update(b).digest();
/** A port that was free a moment ago, so a test can put it in the owner origin before starting. */
async function freePort() {
  const s = createServer();
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}
function passkeyOwner(ORIGIN = "http://localhost:5173") {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { x, y } = publicKey.export({ format: "jwk" });
  const compressed = Buffer.concat([Buffer.from([Buffer.from(y, "base64url")[31] & 1 ? 3 : 2]), Buffer.from(x, "base64url")]);
  const config = { owner: { mode: "passkey", public_key: compressed.toString("base64"), rp_id: "localhost", origin: ORIGIN }, owner_nonce: 7, network: "testnet" };
  const assert_ = async (id, status, owner_nonce, expires_at = Math.floor(Date.now() / 1000) + 300, origin = ORIGIN) => {
    const challenge = await ownerChallenge(CONTRACT, "testnet", "held_decide", heldDecideArgs(id, status), owner_nonce, expires_at);
    const client_data_json = JSON.stringify({ type: "webauthn.get", challenge: b64url(challenge), origin, crossOrigin: false });
    const authData = Buffer.concat([sha("localhost"), Buffer.from([0x05, 0, 0, 0, 0])]);
    const signature = sign("sha256", Buffer.concat([authData, sha(Buffer.from(client_data_json))]), { key: privateKey, dsaEncoding: "ieee-p1363" });
    return { authenticator_data: authData.toString("base64"), client_data_json, signature: signature.toString("base64"), owner_nonce, expires_at };
  };
  return { config, assertion: assert_ };
}

test("a held decision needs the owner's passkey, bound to the item, the decision and a fresh nonce", async () => {
  const heldFile = tempHeld();
  const port = await freePort();
  const owner = passkeyOwner(`http://localhost:${port}`);
  const s = await startServer({ port, contractId: CONTRACT, nearRpc: "https://rpc.testnet.near.org", heldFile, getConfig: async () => owner.config });
  const base = `http://localhost:${port}`;
  const decide = async (body) => {
    const res = await fetch(base + "/api/held/decide", { method: "POST", headers: { "content-type": "application/json", origin: base }, body: JSON.stringify(body) });
    return [res.status, (await res.json()).error ?? ""];
  };
  const statuses = () => items(heldFile).map((i) => i.status);
  try {
    // Unsigned.
    assert.deepEqual(await decide({ id: "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", status: "approved" }), [403, "held decision refused: no owner assertion"]);
    // Signed for another item, or for the other decision.
    assert.match((await decide({ id: "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", status: "approved", assertion: await owner.assertion("held-1c7d2e3f-4051-4b62-9c73-8d94ea5fb607", "approved", 1) }))[1], /different item, decision/);
    assert.match((await decide({ id: "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", status: "approved", assertion: await owner.assertion("held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", "rejected", 1) }))[1], /different item, decision/);
    // Expired, or valid longer than the contract allows.
    assert.match((await decide({ id: "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", status: "approved", assertion: await owner.assertion("held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", "approved", 1, 1000) }))[1], /expired/);
    const far = Math.floor(Date.now() / 1000) + 3600;
    assert.match((await decide({ id: "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", status: "approved", assertion: await owner.assertion("held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", "approved", 1, far) }))[1], /TTL too long/);
    // Signed on another origin (a page that is not the owner origin).
    const elsewhere = await owner.assertion("held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", "approved", 1, undefined, `http://127.0.0.1:${port}`);
    assert.deepEqual(await decide({ id: "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", status: "approved", assertion: elsewhere }), [403, "held decision refused: client_data_json.origin"]);
    // Signed by another key.
    const other = await passkeyOwner(`http://localhost:${port}`).assertion("held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", "approved", 1);
    assert.match((await decide({ id: "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", status: "approved", assertion: other }))[1], /bad signature/);
    assert.deepEqual(statuses(), ["held", "held"]);

    // Valid.
    const good = await owner.assertion("held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", "approved", 1);
    assert.equal((await decide({ id: "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", status: "approved", assertion: good }))[0], 200);
    assert.deepEqual(statuses(), ["approved", "held"]);
    assert.deepEqual(items(heldFile)[0].assertion, good);
    assert.equal((await (await fetch(base + "/api/held")).json()).held_nonce, 1);

    // Replayed, and an old nonce on the next item.
    assert.match((await decide({ id: "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", status: "approved", assertion: good }))[1], /stale owner_nonce 1/);
    assert.match((await decide({ id: "held-1c7d2e3f-4051-4b62-9c73-8d94ea5fb607", status: "rejected", assertion: await owner.assertion("held-1c7d2e3f-4051-4b62-9c73-8d94ea5fb607", "rejected", 1) }))[1], /stale owner_nonce 1/);
    assert.equal((await decide({ id: "held-1c7d2e3f-4051-4b62-9c73-8d94ea5fb607", status: "rejected", assertion: await owner.assertion("held-1c7d2e3f-4051-4b62-9c73-8d94ea5fb607", "rejected", 2) }))[0], 200);
    assert.deepEqual(statuses(), ["approved", "rejected"]);
  } finally {
    await s.close();
  }
});

test("a wallet-mode owner cannot decide held items through the dashboard", async () => {
  const heldFile = tempHeld();
  const getConfig = async () => ({ owner: { mode: "wallet", account: "owner.testnet" }, owner_nonce: 0, network: "testnet" });
  const s = await startServer({ port: 0, contractId: CONTRACT, nearRpc: "https://rpc.testnet.near.org", heldFile, getConfig });
  const base = `http://127.0.0.1:${s.port}`;
  try {
    const assertion = await passkeyOwner().assertion("held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", "approved", 1);
    const res = await fetch(base + "/api/held/decide", { method: "POST", headers: { "content-type": "application/json", origin: base }, body: JSON.stringify({ id: "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", status: "approved", assertion }) });
    assert.equal(res.status, 403);
    assert.equal(items(heldFile)[0].status, "held");
  } finally {
    await s.close();
  }
});

test("a held decision for an id SC1 could not have issued is refused before anything runs", async () => {
  const heldFile = tempHeld();
  const before = readFileSync(heldFile, "utf8");
  const port = await freePort();
  const owner = passkeyOwner(`http://localhost:${port}`);
  let configCalls = 0;
  const getConfig = async () => (configCalls++, owner.config);
  const s = await startServer({ port, contractId: CONTRACT, nearRpc: "https://rpc.testnet.near.org", heldFile, getConfig });
  configCalls = 0; // the start-up owner-origin check reads get_config once
  const base = `http://localhost:${port}`;
  const decide = (id) =>
    fetch(base + "/api/held/decide", { method: "POST", headers: { "content-type": "application/json", origin: base }, body: JSON.stringify({ id, status: "approved" }) });
  const bad = ["", "held-", "held-0001", "x".repeat(10_000), `held-${randomUUID()}\n`, ` held-${randomUUID()}`, `held-${randomUUID().toUpperCase()}`, "held-0b6c1d2e-3f40-1a51-8b62-7c83d94ea5f6", 42, null, ["held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6"]];
  try {
    for (const id of bad) {
      const res = await decide(id);
      assert.equal(res.status, 400, JSON.stringify(id));
      assert.match((await res.json()).error, /held id/);
    }
    assert.equal(configCalls, 0);
    assert.equal(readFileSync(heldFile, "utf8"), before);
    // An id in SC1's format gets past the check (and is then refused for having no assertion).
    assert.equal((await decide(`held-${randomUUID()}`)).status, 403);
  } finally {
    await s.close();
  }
});

/** A raw request, so the test can send any Host header (fetch always sends the URL's). */
function rawGet(port, host) {
  return new Promise((ok, fail) => {
    request({ host: "127.0.0.1", port, path: "/api/held", headers: { host } }, (res) => {
      res.resume();
      ok(res.statusCode);
    })
      .on("error", fail)
      .end();
  });
}

test("the server is bound to its own origin: Host, POST Origin, and the contract's owner origin", async () => {
  const heldFile = tempHeld();
  const port = await freePort();
  const owner = passkeyOwner(`http://localhost:${port}`);
  const start = (config, opts = {}) =>
    startServer({ port, contractId: CONTRACT, nearRpc: "https://rpc.testnet.near.org", heldFile, getConfig: async () => config, ...opts });

  // The owner origin must be exactly one this server serves: another port, scheme or host (a
  // reverse proxy's name) refuses to start, and so does a get_config that cannot be read.
  for (const origin of [`http://localhost:${port + 1}`, `https://localhost:${port}`, "https://dashboard.example", `http://localhost:${port}/`]) {
    await assert.rejects(start({ ...owner.config, owner: { ...owner.config.owner, origin } }), /owner origin is .* but this dashboard serves only/);
  }
  await assert.rejects(
    startServer({ port, contractId: CONTRACT, nearRpc: "https://rpc.testnet.near.org", heldFile, getConfig: async () => { throw new Error("rpc down"); } }),
    /cannot check the owner origin: get_config failed: rpc down/,
  );
  assert.throws(() => assertOwnerOrigin({ owner: { mode: "passkey", origin: "http://localhost:5174" } }, 5173), /DASHBOARD_PORT/);
  assertOwnerOrigin({ owner: { mode: "passkey", origin: "http://127.0.0.1:5173" } }, 5173);
  assertOwnerOrigin({ owner: { mode: "wallet", account: "owner.testnet" } }, 5173);

  // The owner origin moves after start (get_config is read again per decision): refused.
  let config = owner.config;
  const s = await startServer({ port, contractId: CONTRACT, nearRpc: "https://rpc.testnet.near.org", heldFile, getConfig: async () => config });
  const base = `http://localhost:${port}`;
  const decide = (assertion, headers = {}) =>
    fetch(base + "/api/held/decide", { method: "POST", headers: { "content-type": "application/json", origin: base, ...headers }, body: JSON.stringify({ id: "held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", status: "approved", assertion }) });
  try {
    assert.equal(await rawGet(port, `localhost:${port}`), 200);
    assert.equal(await rawGet(port, `127.0.0.1:${port}`), 200);
    for (const host of [`evil.example:${port}`, `localhost:${port + 1}`, "localhost", `dashboard.example`]) assert.equal(await rawGet(port, host), 421, host);

    const good = await owner.assertion("held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", "approved", 1);
    for (const origin of ["https://evil.example", `http://127.0.0.1:${port}`, "null"]) assert.equal((await decide(good, { origin })).status, 403, origin);

    const proxied = passkeyOwner("https://dashboard.example");
    config = proxied.config;
    const res = await decide(await proxied.assertion("held-0b6c1d2e-3f40-4a51-8b62-7c83d94ea5f6", "approved", 1));
    assert.equal(res.status, 403);
    assert.match((await res.json()).error, /owner origin is "https:\/\/dashboard.example", but this dashboard serves only/);
    assert.equal(items(heldFile)[0].status, "held");

    config = owner.config;
    assert.equal((await decide(good)).status, 200);
  } finally {
    await s.close();
  }
});

test("PayPal payees are masked exactly as rails/paypal masks them", () => {
  // Venmo handles (5–30 characters, contract/src/shapes/paypal.rs) too: no suffix, as PP3 (PayPal audit 2 L2).
  for (const p of ["supplier@example.com", "a@example.com", "no-at-sign", "x.y+z@sub.example.org", "", "@demo-supplier", "@abcdefgh", "@abcde"]) {
    assert.equal(maskPayee(p), maskEmail(p), p);
  }
  assert.equal(maskPayee(maskPayee("supplier@example.com")), "su…@example.com");
  assert.equal(maskPayee("@demo-supplier"), "@de…");
  assert.equal(maskPayee("@abcdefgh"), "@ab…");
  assert.equal(maskPayee("@demo-supplier@example.com"), "@d…@example.com");
  assert.equal(formatUsd("4250"), "42.50 USD");
  assert.equal(formatUsd("5"), "0.05 USD");
  const text = paypalMessage("42.50", "supplier@example.com", 1793959200, "inv-2026-0042");
  assert.deepEqual(parsePaypalText(text), { amount: "42.50", payee: "supplier@example.com", at: "2026-11-06T10:00:00Z", request_id: "inv-2026-0042" });
  assert.equal(parsePaypalText("Send EUR 1.00 to x"), null);
});

test("PP3's order records are read only, with the payee masked and PayPal's text left out", async () => {
  const dir = mkdtempSync(join(tmpdir(), "db1-pp3-"));
  const name = (id) => createHash("sha256").update(`agent-1\n${id}`).digest("hex");
  const rec = { agent: "agent-1", request_id: "pp-1", state: "refused", payee_masked: "supplier@example.com", amount: "1.00", at: "2026-11-06T10:00:00.000Z", http_status: 422, debug_id: "dbg", detail: "PayPal said supplier@example.com" };
  writeFileSync(join(dir, `${name("pp-1")}.json`), JSON.stringify(rec));
  writeFileSync(join(dir, `${name("pp-2")}.json.tmp`), "{}");
  writeFileSync(join(dir, `${name("pp-3")}.json`), "not json");
  const before = readFileSync(join(dir, `${name("pp-1")}.json`), "utf8");
  const { records, errors } = readPaypalStore(dir);
  assert.deepEqual(records, [{ agent: "agent-1", request_id: "pp-1", state: "refused", amount: "1.00", at: rec.at, http_status: 422, payee_masked: "su…@example.com" }]);
  assert.equal(errors.length, 1);
  assert.match(errors[0], /is not a PayPal order record/);
  assert.equal(readFileSync(join(dir, `${name("pp-1")}.json`), "utf8"), before);
  assert.deepEqual(readPaypalStore(join(dir, "missing")), { records: [], errors: [] });
  assert.equal(defaultPaypalStoreDir({}), fileURLToPath(new URL("../../rails/paypal/.orders", import.meta.url)));
  assert.equal(defaultPaypalStoreDir({ PP3_STORE_DIR: "/abs/orders" }), "/abs/orders");

  const getConfig = async () => ({ owner: { mode: "wallet", account: "owner.testnet" }, owner_nonce: 0, network: "testnet" });
  const s = await startServer({ port: 0, contractId: "m.testnet", nearRpc: "https://rpc.testnet.near.org", heldFile: tempHeld(), paypalStoreDir: dir, relay: async () => ({}), getConfig });
  try {
    const body = await (await fetch(`http://127.0.0.1:${s.port}/api/paypal`)).json();
    assert.equal(body.dir, dir);
    assert.deepEqual(body.records, records);
    assert.ok(!JSON.stringify(body).includes("supplier@example.com"));
  } finally {
    await s.close();
  }
});

test("PP3's store reader skips symlinks, non-regular and oversized files, and checks field types", () => {
  const dir = mkdtempSync(join(tmpdir(), "db1-pp3-"));
  const outside = mkdtempSync(join(tmpdir(), "db1-pp3-outside-"));
  const name = (id) => join(dir, `${createHash("sha256").update(`agent-1\n${id}`).digest("hex")}.json`);
  const rec = (id, extra = {}) => ({ agent: "agent-1", request_id: id, state: "submitted", payee_masked: "su…@example.com", amount: "1.00", at: "2026-11-06T10:00:00.000Z", ...extra });
  // A valid record behind a symlink is not read.
  writeFileSync(join(outside, "rec.json"), JSON.stringify(rec("link")));
  symlinkSync(join(outside, "rec.json"), name("link"));
  // A FIFO is not opened for reading (and does not hang the reader).
  execFileSync("mkfifo", [name("fifo")]);
  // Over 64 KiB, even if valid JSON.
  writeFileSync(name("big"), JSON.stringify(rec("big", { pad: "x".repeat(64 * 1024) })));
  // Required fields of the wrong type drop the row.
  writeFileSync(name("bad-state"), JSON.stringify(rec("bad-state", { state: { html: "<b>" } })));
  writeFileSync(name("bad-amount"), JSON.stringify(rec("bad-amount", { amount: 100 })));
  writeFileSync(name("no-payee"), JSON.stringify(rec("no-payee", { payee_masked: undefined })));
  writeFileSync(name("array"), JSON.stringify([rec("array")]));
  writeFileSync(name("null"), "null");
  // Optional fields of the wrong type are left out; the rest of the row stays.
  writeFileSync(name("opt"), JSON.stringify(rec("opt", { payout_batch_id: 7, batch_status: ["PENDING"], http_status: "201" })));
  writeFileSync(name("ok"), JSON.stringify(rec("ok", { payout_batch_id: "B1", batch_status: "SUCCESS", http_status: 201 })));

  const { records, errors } = readPaypalStore(dir);
  const ids = records.map((r) => r.request_id).sort();
  assert.deepEqual(ids, ["ok", "opt"]);
  assert.deepEqual(records.find((r) => r.request_id === "opt"), rec("opt"));
  assert.deepEqual(records.find((r) => r.request_id === "ok"), rec("ok", { payout_batch_id: "B1", batch_status: "SUCCESS", http_status: 201 }));
  assert.equal(errors.length, 8);
  for (const e of errors) assert.match(e, /is not a PayPal order record/);
});

test("PP-V1: /api/vault proxies status, connect, confirm and revoke to the rail; off without PP_OWNER_TOKEN", async () => {
  const getConfig = async () => ({ owner: { mode: "wallet", account: "owner.testnet" }, owner_nonce: 0, network: "testnet" });
  const calls = [];
  const vault = async (op, agent) => {
    calls.push(`${op} ${agent}`);
    if (op === "status") return { status: 200, body: { agent, status: "active" } };
    if (op === "connect") return { status: 409, body: { ok: false, error_code: "VAULT_ALREADY_ACTIVE", detail: "revoke the current PayPal connection first" } };
    return { status: 200, body: { ok: true, agent, status: "revoked", token_http_after: 404 } };
  };
  const s = await startServer({ port: 0, contractId: "m.testnet", nearRpc: "https://rpc.testnet.near.org", heldFile: tempHeld(), relay: async () => ({}), getConfig, vault });
  const off = await startServer({ port: 0, contractId: "m.testnet", nearRpc: "https://rpc.testnet.near.org", heldFile: tempHeld(), relay: async () => ({}), getConfig, vault: undefined });
  const base = `http://127.0.0.1:${s.port}`;
  const post = (path, body, origin = base) => fetch(base + path, { method: "POST", headers: { "content-type": "application/json", origin }, body: JSON.stringify(body) });
  try {
    assert.deepEqual(await (await fetch(`${base}/api/vault?agent=agent-1`)).json(), { agent: "agent-1", status: "active" });
    const c = await post("/api/vault/connect", { agent: "agent-1" });
    assert.equal(c.status, 409);
    assert.match((await c.json()).error, /revoke the current/);
    assert.equal((await (await post("/api/vault/revoke", { agent: "agent-1" })).json()).token_http_after, 404);
    assert.equal((await post("/api/vault/revoke", { agent: "agent-1" }, "https://evil.example")).status, 403);
    assert.equal((await post("/api/vault/revoke", { agent: "bad agent" })).status, 400);
    assert.equal((await post("/api/vault/set_mandate", { agent: "agent-1" })).status, 404);
    assert.deepEqual(calls, ["status agent-1", "connect agent-1", "revoke agent-1"]);
    assert.equal((await fetch(`http://127.0.0.1:${off.port}/api/vault?agent=agent-1`)).status, 503);
  } finally {
    await s.close();
    await off.close();
  }
});
