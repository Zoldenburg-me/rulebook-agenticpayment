// PP-S1 throwaway spike: PayPal sandbox Payouts API, duplicate sender_batch_id behaviour.
// Never imported. Run: node spikes/paypal/payouts.mjs
// Reads credentials at runtime from ~/.config/nearh/paypal-sandbox.env (override with PAYPAL_ENV_FILE).
// Prints and writes only redacted output: no client id, secret, token or full receiver email.
import { readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const BASE = "https://api-m.sandbox.paypal.com";
const ENV_FILE = process.env.PAYPAL_ENV_FILE ?? join(homedir(), ".config/nearh/paypal-sandbox.env");
const OUT = join(dirname(fileURLToPath(import.meta.url)), "evidence.json");
const POLL_MS = 120_000;
const FINAL_BATCH = new Set(["SUCCESS", "DENIED", "CANCELED"]);
const FINAL_ITEM = new Set(["SUCCESS", "FAILED", "RETURNED", "UNCLAIMED", "BLOCKED", "REFUNDED", "REVERSED", "DENIED"]);

function loadEnv(path) {
  const env = {};
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
  return env;
}

const env = loadEnv(ENV_FILE);
if (env.PAYPAL_ENV !== "sandbox") {
  console.error("refusing to run: PAYPAL_ENV must be 'sandbox'");
  process.exit(2);
}
for (const k of ["PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_SECRET", "PAYPAL_SANDBOX_RECEIVER_EMAIL"]) {
  if (!env[k]) {
    console.error(`missing ${k} in env file`);
    process.exit(2);
  }
}
const secrets = [env.PAYPAL_CLIENT_ID, env.PAYPAL_CLIENT_SECRET];
const receiver = env.PAYPAL_SANDBOX_RECEIVER_EMAIL;

// Redact: drop tokens and links, mask emails as sb-…@…, scrub any credential substring.
function redact(v) {
  if (Array.isArray(v)) return v.map(redact);
  if (v && typeof v === "object") {
    const o = {};
    for (const [k, x] of Object.entries(v)) {
      if (/token|authorization|secret|client_id|links/i.test(k)) continue;
      o[k] = redact(x);
    }
    return o;
  }
  if (typeof v === "string") {
    let s = v;
    for (const sec of secrets) if (sec) s = s.split(sec).join("[redacted]");
    return s.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, (e) => (e.startsWith("sb-") ? "sb-…@…" : "…@…"));
  }
  return v;
}

const evidence = { ranAt: new Date().toISOString(), base: BASE, steps: [] };
const record = (step, data) => {
  const r = redact({ step, ...data });
  evidence.steps.push(r);
  console.log(JSON.stringify(r));
  writeFileSync(OUT, JSON.stringify(evidence, null, 2) + "\n");
};

async function call(method, path, { token, body, form } = {}) {
  const headers = { Accept: "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";
  if (form) {
    headers.Authorization = "Basic " + Buffer.from(`${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_CLIENT_SECRET}`).toString("base64");
    headers["Content-Type"] = "application/x-www-form-urlencoded";
  }
  const res = await fetch(BASE + path, {
    method,
    headers,
    redirect: "error",
    body: body ? JSON.stringify(body) : form,
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 500) }; }
  return { status: res.status, debugId: res.headers.get("paypal-debug-id"), json };
}

const isPermissionError = (r) =>
  r.status === 401 || r.status === 403 ||
  /AUTHORIZATION_ERROR|PERMISSION_DENIED|NOT_AUTHORIZED|INSUFFICIENT_PERMISSIONS/i.test(r.json?.name ?? "");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function poll(token, batchId, label) {
  const t0 = Date.now();
  let last;
  while (Date.now() - t0 < POLL_MS) {
    const r = await call("GET", `/v1/payments/payouts/${batchId}`, { token });
    const batch = r.json?.batch_header?.batch_status;
    const item = r.json?.items?.[0]?.transaction_status;
    if (!last || last.batch !== batch || last.item !== item) {
      record(`${label}:poll`, { status: r.status, elapsedMs: Date.now() - t0, batch_status: batch, item_status: item });
    }
    last = { batch, item, r };
    if (r.status !== 200) break;
    if (FINAL_BATCH.has(batch) && FINAL_ITEM.has(item)) {
      record(`${label}:final`, { elapsedMs: Date.now() - t0, response: r.json });
      return { final: true, batch, item };
    }
    await sleep(5000);
  }
  record(`${label}:timeout`, { elapsedMs: Date.now() - t0, last_batch_status: last?.batch, last_item_status: last?.item, response: last?.r.json });
  return { final: false, ...last };
}

// 1. token
const tok = await call("POST", "/v1/oauth2/token", { form: "grant_type=client_credentials" });
record("1:oauth", { status: tok.status, debugId: tok.debugId, token_type: tok.json.token_type, expires_in: tok.json.expires_in, scopeHasPayouts: /payouts/i.test(tok.json.scope ?? ""), error: tok.json.error, error_description: tok.json.error_description });
if (tok.status !== 200) process.exit(1);
const token = tok.json.access_token;

const senderBatchId = `nearh-spike-${Math.floor(Date.now() / 1000)}`;
const item = (id) => ({
  recipient_type: "EMAIL",
  amount: { value: "1.00", currency: "USD" },
  note: "nearh spike",
  sender_item_id: `${id}-1`,
  receiver,
});
const body = {
  sender_batch_header: { sender_batch_id: senderBatchId, email_subject: "nearh spike", email_message: "nearh spike" },
  items: [item(senderBatchId)],
};

// 2. create payout
const create = await call("POST", "/v1/payments/payouts", { token, body });
record("2:create", { sender_batch_id: senderBatchId, status: create.status, debugId: create.debugId, response: create.json });
if (isPermissionError(create)) {
  console.error(`STOP: Payouts not permitted for this app (${create.status} ${create.json?.name}). Owner must enable Payouts in the app's features.`);
  process.exit(3);
}
if (create.status !== 201) process.exit(1);
const batchId = create.json.batch_header.payout_batch_id;

// 3. poll to final
await poll(token, batchId, "3");

// 4. same body, same sender_batch_id
const dup = await call("POST", "/v1/payments/payouts", { token, body });
record("4:resubmit-same-sender_batch_id", { sender_batch_id: senderBatchId, status: dup.status, debugId: dup.debugId, response: dup.json });

// 5. same item, new sender_batch_id
const newId = `${senderBatchId}-b`;
const body2 = { ...body, sender_batch_header: { ...body.sender_batch_header, sender_batch_id: newId } };
const again = await call("POST", "/v1/payments/payouts", { token, body: body2 });
record("5:same-item-new-sender_batch_id", { sender_batch_id: newId, status: again.status, debugId: again.debugId, response: again.json });
if (again.status === 201) await poll(token, again.json.batch_header.payout_batch_id, "5");

console.log(`evidence written to ${OUT}`);
