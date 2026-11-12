import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { credentialFor } from "./mpc.mjs";
import { sandboxClient, RUN_JOURNAL, PAYOUT_LOCK, takePayoutLock, canonicalAmount, eurCents, ibanFor, refusalCode, payoutMessage, replayResult, assertNoPayoutAttempt, journalEvents } from "./monerium.mjs";

const env = { MONERIUM_ENVIRONMENT: "sandbox", MONERIUM_CLIENT_ID: "test-client", MONERIUM_CLIENT_SECRET: "test-secret" };

test("canonical money and the contract's exact second-resolution payout format", () => {
  assert.equal(canonicalAmount("000.50"), "0.5");
  assert.equal(canonicalAmount("1.00"), "1");
  const message = payoutMessage("0.10", "XX00000000000000", "2026-11-03T10:00:00Z");
  assert.equal(message, "Send EUR 0.1 to XX00000000000000 at 2026-11-03T10:00:00Z");
  for (const amount of ["0", "0.001", "1.01", "-1", ".5", "1e0", "1 "]) assert.throws(() => canonicalAmount(amount));
  assert.throws(() => payoutMessage("0.01", "XX00000000000000", "2026-02-30T10:00:00Z"));
});

test("funding compares whole cents, never rounding a balance up", () => {
  assert.equal(eurCents("99.99"), 9999n);
  assert.equal(eurCents("100"), 10000n);
  assert.equal(eurCents(0.01), 1n);
  assert.equal(eurCents("0.009"), 0n);
  assert.ok(eurCents("0.009") < eurCents(canonicalAmount("0.01")));
  for (const amount of [undefined, null, "", "-1", "1e2", "NaN", "0x10", " 1", Number.NaN]) assert.equal(eurCents(amount), null);
});

test("refuses production, another chain, or an unauthenticated request", async () => {
  assert.throws(() => sandboxClient({ ...env, MONERIUM_ENVIRONMENT: "production" }));
  assert.throws(() => sandboxClient({ ...env, MONERIUM_BASE_URL: "https://api.monerium.app" }));
  assert.throws(() => sandboxClient({ ...env, MONERIUM_CHAIN: "base" }));
  await assert.rejects(sandboxClient(env).request("GET", "/addresses"), /Authenticate/);
});

test("auth failure and recorded evidence contain no secret, token, or raw partner description", async () => {
  const events = [];
  const client = sandboxClient(env, async (url, options) => {
    assert.equal(url, "https://api.monerium.dev/auth/token");
    assert.equal(options.redirect, "error");
    assert.equal(options.body.get("client_secret"), "test-secret");
    return new Response(JSON.stringify({ error: "unauthorized_client", error_description: "test-secret private IBAN" }), { status: 400 });
  }, event => events.push(event));
  await assert.rejects(client.authenticate(), /HTTP 400, unauthorized_client/);
  assert.equal(events.length, 1);
  assert.equal(events[0].error, "unauthorized_client");
  assert.doesNotMatch(JSON.stringify(events), /test-secret|private IBAN|error_description/);
});

test("network failures are surfaced without exposing transport errors", async () => {
  const client = sandboxClient(env, async () => { throw new Error("test-secret"); });
  await assert.rejects(client.authenticate(), error => {
    assert.match(error.message, /outcome unknown/);
    assert.doesNotMatch(error.message, /test-secret/);
    return true;
  });
});

test("authenticated requests cannot send the token to another origin", async () => {
  let calls = 0;
  const client = sandboxClient(env, async (url, options) => {
    calls++;
    assert.ok(url.startsWith("https://api.monerium.dev/"));
    assert.equal(options.redirect, "error");
    if (calls === 1) return new Response(JSON.stringify({ access_token: "private-token" }));
    assert.equal(options.headers.authorization, "Bearer private-token");
    return new Response(JSON.stringify({ addresses: [] }));
  });
  await client.authenticate();
  await assert.rejects(client.request("GET", "//attacker.invalid"), /Invalid API path/);
  assert.deepEqual((await client.request("GET", "/addresses")).body, { addresses: [] });
  assert.equal(calls, 2);
});

test("only a duplicate-specific rejection proves replay refusal", () => {
  const first = { ok: true, status: 201, body: { id: "order-a", state: "placed" } };
  assert.equal(replayResult(first, { ok: false, status: 409, body: { error: "duplicate order" } }), "rejected_duplicate");
  for (const status of [400, 401, 403, 429, 500]) {
    assert.equal(replayResult(first, { ok: false, status, body: { error: "insufficient funds" } }), "inconclusive");
  }
  assert.equal(replayResult(first, { ok: true, status: 200, body: { id: "order-a" } }), "idempotent_same_order");
  assert.equal(replayResult(first, { ok: true, status: 200, body: { id: "order-b" } }), "accepted_new_order");
  assert.equal(replayResult({ ...first, body: { id: "order-a", state: "rejected" } }, { ok: false, status: 409, body: { error: "duplicate" } }), "inconclusive");
});

test("an earlier payout attempt blocks rerunning even when its response was lost", () => {
  assert.doesNotThrow(() => assertNoPayoutAttempt([{ step: "preflight" }]));
  assert.throws(() => assertNoPayoutAttempt([{ step: "payout_attempt" }, { step: "run", result: "incomplete" }]), /already attempted/);
});

test("the published evidence never blocks a payout; only the untracked run journal does", () => {
  const ignored = readFileSync(new URL("./.gitignore", import.meta.url), "utf8").split("\n").map(line => line.trim());
  assert.notEqual(RUN_JOURNAL, "evidence.ndjson");
  assert.ok(ignored.includes(RUN_JOURNAL) && ignored.includes(PAYOUT_LOCK));
  assert.ok(!ignored.includes("evidence.ndjson") && !ignored.includes("*.ndjson"));
  // The published run contains a payout attempt; the runner reads it only as published evidence.
  const published = journalEvents(readFileSync(new URL("./evidence.ndjson", import.meta.url), "utf8"));
  assert.throws(() => assertNoPayoutAttempt(published), /already attempted/);
  assert.doesNotMatch(readFileSync(new URL("./spike.mjs", import.meta.url), "utf8"), /evidence\.ndjson/);
});

test("the payout lock is exclusive-create: a second runner cannot take it", () => {
  const lock = join(mkdtempSync(join(tmpdir(), "monerium-spike-")), PAYOUT_LOCK);
  assert.doesNotThrow(() => takePayoutLock(lock));
  assert.throws(() => takePayoutLock(lock), /already attempted/);
});

test("every published evidence line the runner did not write is marked manual", () => {
  const source = ["./spike.mjs", "./mpc.mjs"].map(f => readFileSync(new URL(f, import.meta.url), "utf8")).join("\n");
  const runnerSteps = new Set([...source.matchAll(/step: "([a-z_]+)"/g)].map(m => m[1]));
  const published = journalEvents(readFileSync(new URL("./evidence.ndjson", import.meta.url), "utf8"));
  for (const event of published) {
    if (event.manual === true) { assert.match(event.note, /^Hand-added/); continue; }
    assert.ok(event.endpoint || runnerSteps.has(event.step), `unmarked hand-added line: ${event.step}`);
  }
});

test("the recorded duplicate refusal keeps Monerium's code and message, never an IBAN, hex value or UUID", () => {
  const body = { code: 400, status: "Bad Request", message: "Duplicate order for DE89 3704 0044 0532 0130 00 from 0xAbC123 (5f0c2a5e-1111-4222-8333-944455556666)",
    errors: { signature: "0xdeadbeef" }, details: { iban: "DE89370400440532013000" } };
  const code = refusalCode(body);
  assert.deepEqual(Object.keys(code), ["code", "status", "message"]);
  assert.equal(code.code, 400);
  assert.equal(code.message, "Duplicate order for <IBAN> from <HEX> (<UUID>)");
  assert.doesNotMatch(JSON.stringify(code), /DE89|deadbeef|AbC123|5f0c2a5e/);
  assert.deepEqual(refusalCode({ message: { nested: "DE89370400440532013000" } }), {});
  assert.equal(refusalCode({ message: "Duplicate order to de89 3704 0044 0532 0130 00" }).message, "Duplicate order to <IBAN>");
  assert.equal(refusalCode({ message: "Duplicate order" }).message, "Duplicate order");
  assert.ok(refusalCode({ message: "x".repeat(500) }).message.length <= 200);
});

test("only an IBAN paying into this address on Base Sepolia under this profile counts as ours", () => {
  const addr = "0xE0A8bb55759D9565113E125f5f2937Bf2f85e52E";
  const mine = { iban: "XX00000000000001", address: addr.toLowerCase(), chain: "basesepolia", profile: "p1" };
  assert.equal(ibanFor([mine], addr, "p1"), mine);
  assert.equal(ibanFor([{ ...mine, chain: "gnosis" }], addr, "p1"), undefined);
  assert.equal(ibanFor([{ ...mine, address: "0x0000000000000000000000000000000000000001" }], addr, "p1"), undefined);
  assert.equal(ibanFor([{ ...mine, profile: "p2" }], addr, "p1"), undefined);
});

test("a key file may omit account_id (near-cli-rs) but never name another account", () => {
  assert.equal(credentialFor({ private_key: "ed25519:x" }, "me.testnet"), true);
  assert.equal(credentialFor({ account_id: "me.testnet", private_key: "ed25519:x" }, "me.testnet"), true);
  assert.equal(credentialFor({ account_id: "other.testnet", private_key: "ed25519:x" }, "me.testnet"), false);
  assert.equal(credentialFor({ account_id: "me.testnet" }, "me.testnet"), false);
});
