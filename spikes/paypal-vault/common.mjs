// PP-V0 throwaway spike helpers: sandbox env, redaction, REST call, evidence file. Never imported outside this folder.
// Reads credentials at runtime from ~/.config/nearh/paypal-sandbox.env (override with PAYPAL_ENV_FILE).
// Prints and writes only redacted output: no client id, secret, access token or full email.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

export const BASE = "https://api-m.sandbox.paypal.com";
export const DIR = dirname(fileURLToPath(import.meta.url));
const ENV_FILE = process.env.PAYPAL_ENV_FILE ?? join(homedir(), ".config/nearh/paypal-sandbox.env");

function loadEnv(path) {
  const env = {};
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m) env[m[1]] = m[2].replace(/^["']|["']$/g, "");
  }
  return env;
}

export const env = loadEnv(ENV_FILE);
if (env.PAYPAL_ENV !== "sandbox") {
  console.error("refusing to run: PAYPAL_ENV must be 'sandbox'");
  process.exit(2);
}
for (const k of ["PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_SECRET"]) {
  if (!env[k]) {
    console.error(`missing ${k} in env file`);
    process.exit(2);
  }
}
const secrets = [env.PAYPAL_CLIENT_ID, env.PAYPAL_CLIENT_SECRET, env.PAYPAL_SANDBOX_RECEIVER_PASSWORD];
let accessToken;

// Redact: drop tokens, auth and links; mask emails as sb-…@… ; scrub any credential substring.
export function redact(v) {
  if (Array.isArray(v)) return v.map(redact);
  if (v && typeof v === "object") {
    const o = {};
    for (const [k, x] of Object.entries(v)) {
      if (/access_token|authorization|secret|client_id|password|links/i.test(k)) continue;
      o[k] = redact(x);
    }
    return o;
  }
  if (typeof v === "string") {
    let s = v;
    for (const sec of [...secrets, accessToken]) if (sec) s = s.split(sec).join("[redacted]");
    return s.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, (e) => (e.startsWith("sb-") ? "sb-…@…" : "…@…"));
  }
  return v;
}

// Evidence file per script; appends to an existing one so a resumed run keeps the earlier steps.
export function evidence(name) {
  const out = join(DIR, name);
  const ev = existsSync(out) ? JSON.parse(readFileSync(out, "utf8")) : { base: BASE, runs: [] };
  const run = { ranAt: new Date().toISOString(), steps: [] };
  ev.runs.push(run);
  return (step, data) => {
    const r = redact({ step, ...data });
    run.steps.push(r);
    console.log(JSON.stringify(r));
    writeFileSync(out, JSON.stringify(ev, null, 2) + "\n");
  };
}

export async function call(method, path, { body, form, requestId } = {}) {
  const headers = { Accept: "application/json" };
  if (form) {
    headers.Authorization = "Basic " + Buffer.from(`${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_CLIENT_SECRET}`).toString("base64");
    headers["Content-Type"] = "application/x-www-form-urlencoded";
  } else if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }
  if (body) headers["Content-Type"] = "application/json";
  if (method === "POST" && !form) headers["PayPal-Request-Id"] = requestId ?? randomUUID();
  const res = await fetch(BASE + path, { method, headers, redirect: "error", body: body ? JSON.stringify(body) : form });
  const text = await res.text();
  let json;
  try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text.slice(0, 500) }; }
  return { status: res.status, debugId: res.headers.get("paypal-debug-id"), json };
}

// Client-credentials token, kept in memory only. Returns the redacted record fields.
export async function login() {
  const r = await call("POST", "/v1/oauth2/token", { form: "grant_type=client_credentials" });
  if (r.status === 200) accessToken = r.json.access_token;
  const scope = r.json.scope ?? "";
  return {
    status: r.status,
    debugId: r.debugId,
    expires_in: r.json.expires_in,
    scopeHasVault: /vault/i.test(scope),
    vaultScopes: scope.split(" ").filter((s) => /vault/i.test(s)),
    error: r.json.error,
    error_description: r.json.error_description,
  };
}

// Pick the approve link out of a setup-token / order response (never written to evidence).
export const linkOf = (json, rel) => json?.links?.find((l) => l.rel === rel)?.href;
