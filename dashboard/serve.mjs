// DB1 dashboard server: serves the page, the held queue (docs/interfaces.md §6), PP3's PayPal
// order records (read-only) and relays passkey-signed owner calls through R1's relayOwnerCall.
// Listens on 127.0.0.1 only.

import { createHash, ECDH } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readdirSync, readFileSync, readSync, renameSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { b64url, HELD_DECIDE_METHOD, heldDecideArgs, ownerChallenge } from "./public/owner.js";
import { maskPayee } from "./public/paypal.js";

const here = dirname(fileURLToPath(import.meta.url));
const PUBLIC = join(here, "public");
const FILES = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/app.js": ["app.js", "text/javascript; charset=utf-8"],
  "/owner.js": ["owner.js", "text/javascript; charset=utf-8"],
  "/paypal.js": ["paypal.js", "text/javascript; charset=utf-8"],
  "/style.css": ["style.css", "text/css; charset=utf-8"],
};
// Same allowlist as O1 and R1 (scripts/owner/near/src/near.ts).
export const TESTNET_RPC_HOSTS = ["rpc.testnet.near.org", "archival-rpc.testnet.near.org", "test.rpc.fastnear.com"];
/** PP-V1 vault operations the page may ask the PayPal rail for. */
export const VAULT_OPS = ["connect", "confirm", "revoke"];
const AGENT_ID = /^[A-Za-z0-9._:-]{1,64}$/;

/**
 * The PayPal rail's owner routes (rails/paypal/src/server.ts `/vault/*`), called with PP_OWNER_TOKEN,
 * which stays in this process. Undefined when PP_OWNER_TOKEN is unset: the card shows "rail off".
 * The answer is the rail's: a status, or for connect PayPal's approve link. The rail never sends the vault id.
 */
export function railVault(env = process.env) {
  const token = env.PP_OWNER_TOKEN;
  if (!token) return undefined;
  const base = new URL(env.PP3_URL || "http://127.0.0.1:8788/payouts");
  if (base.protocol !== "http:" || !["127.0.0.1", "[::1]"].includes(base.hostname)) throw new Error("PP3_URL must be a loopback http URL");
  return async (op, agent) => {
    const url = new URL(op === "status" ? `/vault/status?agent=${encodeURIComponent(agent)}` : `/vault/${op}`, base);
    const res = await fetch(url, {
      method: op === "status" ? "GET" : "POST",
      headers: { authorization: `Bearer ${token}`, ...(op === "status" ? {} : { "content-type": "application/json" }) },
      body: op === "status" ? undefined : JSON.stringify({ agent }),
      redirect: "error",
      signal: AbortSignal.timeout(45_000),
    });
    const body = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    return { status: res.status, body };
  };
}

/** The owner methods the page signs. */
const OWNER_METHODS = ["revoke", "resolve_reservation"];
const MAX_BODY = 64 * 1024;
/** Same cap as the contract's MAX_ASSERTION_TTL_SECS. */
const MAX_ASSERTION_TTL_SECS = 600;
/** SC1 issues held ids as `held-${randomUUID()}` (scamcheck/src/check.ts); nothing else is a held id. */
const HELD_ID = /^held-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * The only origins this server answers on: it listens on 127.0.0.1:<port> and accepts the Host
 * names 127.0.0.1 and localhost. The contract's passkey origin (get_config().owner.origin) must be
 * one of these, exactly; a reverse proxy or another port is not supported.
 */
export function ownerOrigins(port) {
  return [`http://127.0.0.1:${port}`, `http://localhost:${port}`];
}

/** Throws unless a passkey owner's origin is one this server, listening on `port`, serves. */
export function assertOwnerOrigin(config, port) {
  if (config?.owner?.mode !== "passkey") return;
  const origins = ownerOrigins(port);
  if (!origins.includes(config.owner.origin)) {
    throw new Error(
      `the contract's owner origin is ${JSON.stringify(config.owner.origin)}, but this dashboard serves only ${origins.join(" and ")}: set DASHBOARD_PORT to the origin's port, or change the owner origin (a reverse proxy is not supported)`,
    );
  }
}

export function assertTestnetConfig({ contractId, nearRpc }) {
  if (!/^[a-z0-9._-]+\.testnet$/.test(contractId ?? "")) throw new Error(`CONTRACT_ID must be a .testnet account, got "${contractId}"`);
  let url;
  try {
    url = new URL(nearRpc);
  } catch {}
  if (!url || url.protocol !== "https:" || url.username || url.password || !TESTNET_RPC_HOSTS.includes(url.hostname)) {
    throw new Error(`NEAR_RPC must be an https testnet RPC (${TESTNET_RPC_HOSTS.join(", ")}), got ${nearRpc}`);
  }
}

/**
 * SC1's file: $SCAMCHECK_HELD_DIR/held.jsonl, a relative dir resolved against scamcheck/. SC1
 * reads no scamcheck/.env (PayPal audit 1 C1), so neither does this.
 */
export function defaultHeldFile(scamcheckDir = resolve(here, "..", "scamcheck"), env = process.env) {
  return resolve(scamcheckDir, env.SCAMCHECK_HELD_DIR || ".held", "held.jsonl");
}

/** PP3's store (rails/paypal/src/config.ts): $PP3_STORE_DIR, else rails/paypal/.orders. */
export function defaultPaypalStoreDir(env = process.env) {
  return resolve(env.PP3_STORE_DIR || resolve(here, "..", "rails", "paypal", ".orders"));
}

/**
 * The OrderRecord fields the page shows, with their types; `detail` and `debug_id` (PayPal's text)
 * stay out. A record missing a required field, or holding one of the wrong type, is dropped; an
 * optional field of the wrong type is left out.
 */
const isString = (v) => typeof v === "string";
const PAYPAL_REQUIRED = { agent: isString, request_id: isString, state: isString, payee_masked: isString, amount: isString, at: isString };
const PAYPAL_OPTIONAL = { payout_batch_id: isString, batch_status: isString, http_status: Number.isInteger };
/** PP3's records are a few hundred bytes; anything larger is not one. */
const MAX_PAYPAL_RECORD = 64 * 1024;

/** A regular file's text, at most `max` bytes; a symlink (O_NOFOLLOW) or anything else throws. */
function readRegularFile(path, max) {
  // O_NONBLOCK so opening a FIFO does not wait for a writer.
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    if (!fstatSync(fd).isFile()) throw new Error("not a regular file");
    const buf = Buffer.alloc(max + 1);
    let n = 0;
    for (let r; n < buf.length && (r = readSync(fd, buf, n, buf.length - n, n)) > 0; ) n += r;
    if (n > max) throw new Error(`over ${max} bytes`);
    return buf.toString("utf8", 0, n);
  } finally {
    closeSync(fd);
  }
}

/**
 * PP3's order records (rails/paypal/src/store.ts fileStore: one `<sha256>.json` per (agent,
 * request_id)), read only. The payee is masked again as the rail masks it, in case a record holds more.
 */
export function readPaypalStore(dir) {
  let names;
  try {
    names = readdirSync(dir);
  } catch (e) {
    if (e.code === "ENOENT") return { records: [], errors: [] };
    throw e;
  }
  const records = [];
  const errors = [];
  for (const name of names.filter((n) => /^[0-9a-f]{64}\.json$/.test(n)).sort()) {
    try {
      const r = JSON.parse(readRegularFile(join(dir, name), MAX_PAYPAL_RECORD));
      if (!Object.entries(PAYPAL_REQUIRED).every(([k, ok]) => ok(r[k]))) throw new Error("wrong fields");
      const out = {};
      for (const [k, ok] of Object.entries({ ...PAYPAL_REQUIRED, ...PAYPAL_OPTIONAL })) if (ok(r[k])) out[k] = r[k];
      out.payee_masked = maskPayee(r.payee_masked);
      records.push(out);
    } catch {
      errors.push(`${dir}: ${name} is not a PayPal order record`);
    }
  }
  return { records, errors };
}

function readHeld(file) {
  let raw;
  try {
    raw = readFileSync(file, "utf8");
  } catch (e) {
    if (e.code === "ENOENT") return { items: [], errors: [] };
    throw e;
  }
  return readHeldText(raw, file);
}

function readHeldText(raw, file) {
  const items = [];
  const errors = [];
  raw.split("\n").forEach((line, i) => {
    if (!line.trim()) return;
    try {
      items.push(JSON.parse(line));
    } catch {
      errors.push(`${file}: line ${i + 1} is not JSON`);
    }
  });
  return { items, errors };
}

/** The held queue's owner nonce: the greatest `decided_nonce` in the file, 0 if none. */
export function heldNonce(items) {
  return items.reduce((n, i) => (Number.isSafeInteger(i.decided_nonce) && i.decided_nonce > n ? i.decided_nonce : n), 0);
}

/**
 * held → approved | rejected, and only from held. Rewrites the file atomically. `nonce` is the
 * verified assertion's owner_nonce: it must exceed every earlier decision's (no replay) and is
 * stored on the item as `decided_nonce`. `id` is not validated here: it is only compared, never
 * used as a path, and the HTTP handler (the only caller) checks it first.
 */
export function decideHeld(file, id, status, nonce, now = new Date(), assertion) {
  if (status !== "approved" && status !== "rejected") throw httpError(400, `status must be approved or rejected, got ${JSON.stringify(status)}`);
  const raw = readFileSync(file, "utf8");
  const last = heldNonce(readHeldText(raw, file).items);
  if (!Number.isSafeInteger(nonce) || nonce <= last) throw httpError(409, `stale owner_nonce ${nonce}: the held queue is at ${last}`);
  const lines = raw.split("\n");
  let found;
  const out = lines.map((line) => {
    if (!line.trim()) return line;
    let item;
    try {
      item = JSON.parse(line);
    } catch {
      return line;
    }
    if (item.id !== id) return line;
    if (found) throw httpError(409, `held id ${id} appears twice`);
    if (item.status !== "held") throw httpError(409, `${id} is already ${item.status}`);
    found = { ...item, status, decided_at: now.toISOString().replace(/\.\d{3}Z$/, "Z"), decided_nonce: nonce, ...(assertion ? { assertion } : {}) };
    return JSON.stringify(found);
  });
  if (!found) throw httpError(404, `no held item ${id}`);
  const tmp = `${file}.${process.pid}.tmp`;
  writeFileSync(tmp, out.join("\n"));
  renameSync(tmp, file);
  return found;
}

const sha256 = (b) => createHash("sha256").update(b).digest();

/**
 * The checks of the contract's assert_owner (docs/interfaces.md §2, steps 1–8) for a signed
 * held decision: `config` is the contract's get_config(), `minNonce` the held queue's nonce.
 * Throws 403 on any failure.
 */
export async function verifyHeldDecision({ config, contractId, id, status, assertion: a, minNonce, nowSecs, port }) {
  const deny = (why) => {
    throw httpError(403, `held decision refused: ${why}`);
  };
  if (config?.owner?.mode !== "passkey") deny("the contract has no passkey owner");
  if (!a || typeof a !== "object") deny("no owner assertion");
  const { public_key, rp_id, origin } = config.owner;
  if (port !== undefined) {
    try {
      assertOwnerOrigin(config, port);
    } catch (e) {
      deny(e.message);
    }
  }
  let client;
  try {
    client = JSON.parse(a.client_data_json);
  } catch {
    deny("client_data_json is not JSON");
  }
  if (client?.type !== "webauthn.get") deny("client_data_json.type");
  if (!Number.isSafeInteger(a.owner_nonce) || !Number.isSafeInteger(a.expires_at)) deny("owner_nonce and expires_at must be integers");
  let args;
  try {
    args = heldDecideArgs(id, status);
  } catch (e) {
    throw httpError(400, e.message);
  }
  const challenge = await ownerChallenge(contractId, config.network, HELD_DECIDE_METHOD, args, a.owner_nonce, a.expires_at);
  if (client.challenge !== b64url(challenge)) deny("the assertion is for a different item, decision or nonce");
  if (client.origin !== origin) deny("client_data_json.origin");
  const authData = Buffer.from(a.authenticator_data ?? "", "base64");
  if (authData.length < 37 || !authData.subarray(0, 32).equals(sha256(rp_id))) deny("authenticator_data.rp_id_hash");
  if (!(authData[32] & 0x01)) deny("user not present");
  if (a.owner_nonce <= minNonce) deny(`stale owner_nonce ${a.owner_nonce}: the held queue is at ${minNonce}`);
  if (a.expires_at <= nowSecs) deny("assertion expired");
  if (a.expires_at > nowSecs + MAX_ASSERTION_TTL_SECS) deny("assertion TTL too long");
  const sig = Buffer.from(a.signature ?? "", "base64");
  if (sig.length !== 64) deny("signature must be 64 bytes r || s");
  let key;
  try {
    const point = ECDH.convertKey(Buffer.from(public_key, "base64"), "prime256v1", undefined, undefined, "uncompressed");
    key = await globalThis.crypto.subtle.importKey("raw", point, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  } catch {
    deny("owner public_key is not a P-256 key");
  }
  const signed = Buffer.concat([authData, sha256(Buffer.from(a.client_data_json, "utf8"))]);
  // subtle.verify hashes `signed` once more: p256_verify(sig, sha256(signed), key).
  if (!(await globalThis.crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, signed))) deny("bad signature");
}

function httpError(status, message) {
  return Object.assign(new Error(message), { status });
}

function readBody(req) {
  return new Promise((ok, fail) => {
    const chunks = [];
    let n = 0;
    req.on("data", (c) => {
      n += c.length;
      if (n > MAX_BODY) {
        fail(httpError(413, "body too large"));
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => {
      try {
        ok(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch {
        fail(httpError(400, "body is not JSON"));
      }
    });
    req.on("error", fail);
  });
}

async function realRelay(call) {
  const { relayOwnerCall } = await import("@nearh/relayer/src/owner-call.ts");
  const { nearConfig, nearSigner } = await import("@nearh/relayer/src/config.ts");
  return relayOwnerCall({ ...nearConfig(), submitter: nearSigner("SUBMITTER") }, call);
}

/** The contract's get_config() through the (allowlisted) testnet RPC. */
async function rpcGetConfig(nearRpc, contractId) {
  const res = await fetch(nearRpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "dashboard",
      method: "query",
      params: { request_type: "call_function", finality: "final", account_id: contractId, method_name: "get_config", args_base64: btoa("{}") },
    }),
  });
  const body = await res.json();
  if (body.error || body.result?.error) throw new Error(`get_config: ${JSON.stringify(body.error ?? body.result.error)}`);
  return JSON.parse(Buffer.from(body.result.result).toString("utf8"));
}

/**
 * Starts the server. `relay` submits a signed owner call (default: R1's relayOwnerCall with the
 * SUBMITTER_* account from the environment); `getConfig` reads the contract's get_config() (default:
 * the NEAR RPC); tests pass their own. Before it resolves, it checks that a passkey owner's origin
 * is one of ownerOrigins(port) and refuses to start if not (`checkOwnerOrigin: false` skips this).
 */
export async function startServer({
  port = 5173,
  contractId,
  nearRpc,
  heldFile = defaultHeldFile(),
  paypalStoreDir = defaultPaypalStoreDir(),
  relay = realRelay,
  getConfig = () => rpcGetConfig(nearRpc, contractId),
  checkOwnerOrigin = true,
  vault = railVault(),
}) {
  assertTestnetConfig({ contractId, nearRpc });
  const rpcOrigins = TESTNET_RPC_HOSTS.map((h) => `https://${h}`).join(" ");
  const csp = `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self' ${rpcOrigins}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`;
  let listenPort = port;

  const server = createServer(async (req, res) => {
    const send = (status, body, type = "application/json") => {
      res.writeHead(status, {
        "content-type": type,
        "content-security-policy": csp,
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "cache-control": "no-store",
      });
      res.end(type === "application/json" ? JSON.stringify(body) : body);
    };
    try {
      // A page on another origin (or a rebound DNS name) must not read or change the queue.
      const origins = ownerOrigins(listenPort);
      const self = `http://${req.headers.host}`;
      if (!origins.includes(self)) throw httpError(421, "unexpected Host header");
      const url = new URL(req.url, self);
      if (req.method === "POST") {
        if (req.headers.origin !== self) throw httpError(403, "cross-origin request refused");
        if (!(req.headers["content-type"] ?? "").startsWith("application/json")) throw httpError(415, "send application/json");
      }

      if (req.method === "GET" && Object.hasOwn(FILES, url.pathname)) {
        const [name, type] = FILES[url.pathname];
        return send(200, readFileSync(join(PUBLIC, name)), type);
      }
      if (req.method === "GET" && url.pathname === "/config.json") {
        return send(200, { contract_id: contractId, near_rpc: nearRpc, network: "testnet" });
      }
      if (req.method === "GET" && url.pathname === "/api/held") {
        const { items, errors } = readHeld(heldFile);
        return send(200, { file: heldFile, items, errors, held_nonce: heldNonce(items) });
      }
      if (req.method === "GET" && url.pathname === "/api/paypal") {
        return send(200, { dir: paypalStoreDir, ...readPaypalStore(paypalStoreDir) });
      }
      if (url.pathname === "/api/vault" || url.pathname.startsWith("/api/vault/")) {
        const op = url.pathname === "/api/vault" ? (req.method === "GET" ? "status" : "") : url.pathname.slice("/api/vault/".length);
        if (!(op === "status" || (req.method === "POST" && VAULT_OPS.includes(op)))) throw httpError(404, "not found");
        if (!vault) throw httpError(503, "PayPal vault routes are off (set PP_OWNER_TOKEN and PP3_URL)");
        const agent = op === "status" ? url.searchParams.get("agent") : (await readBody(req))?.agent;
        if (typeof agent !== "string" || !AGENT_ID.test(agent)) throw httpError(400, "agent must be 1-64 chars of [A-Za-z0-9._:-]");
        let answer;
        try {
          answer = await vault(op, agent);
        } catch (e) {
          throw httpError(502, `PayPal rail unreachable: ${e.message}`);
        }
        if (answer.status === 200) return send(200, answer.body);
        throw httpError(answer.status === 409 ? 409 : 502, String(answer.body?.detail ?? answer.body?.error ?? `PayPal rail HTTP ${answer.status}`).slice(0, 300));
      }
      if (req.method === "POST" && url.pathname === "/api/held/decide") {
        // Only the owner's passkey decides: the assertion is bound to this id, this status and a
        // nonce above every earlier decision's, so it cannot be replayed or reused for another item.
        const { id, status, assertion } = await readBody(req);
        if (typeof id !== "string" || !HELD_ID.test(id)) throw httpError(400, "id must be a held id (held-<uuid>)");
        let config;
        try {
          config = await getConfig();
        } catch (e) {
          throw httpError(502, `get_config failed: ${e.message}`);
        }
        const minNonce = heldNonce(readHeld(heldFile).items);
        await verifyHeldDecision({ config, contractId, id, status, assertion, minNonce, nowSecs: Math.floor(Date.now() / 1000), port: listenPort });
        return send(200, decideHeld(heldFile, id, status, assertion.owner_nonce, new Date(), assertion));
      }
      if (req.method === "POST" && url.pathname === "/api/owner-call") {
        const call = await readBody(req);
        if (!OWNER_METHODS.includes(call?.method)) throw httpError(400, `the dashboard relays ${OWNER_METHODS.join(" and ")} only`);
        try {
          return send(200, await relay(call));
        } catch (e) {
          throw httpError(502, `relay failed: ${e.message}`);
        }
      }
      throw httpError(404, "not found");
    } catch (e) {
      send(e.status ?? 500, { error: e.message });
    }
  });

  await new Promise((ok, fail) => {
    server.once("error", fail);
    server.listen(port, "127.0.0.1", () => {
      listenPort = server.address().port;
      ok();
    });
  });
  const close = () => new Promise((r) => server.close(r));
  if (checkOwnerOrigin) {
    try {
      let config;
      try {
        config = await getConfig();
      } catch (e) {
        throw new Error(`cannot check the owner origin: get_config failed: ${e.message}`);
      }
      assertOwnerOrigin(config, listenPort);
    } catch (e) {
      await close();
      throw e;
    }
  }
  return { server, port: listenPort, close };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const s = await startServer({
    port: Number(process.env.DASHBOARD_PORT || 5173),
    contractId: process.env.CONTRACT_ID,
    nearRpc: process.env.NEAR_RPC || "https://rpc.testnet.near.org",
    heldFile: process.env.DASHBOARD_HELD_FILE || defaultHeldFile(),
    paypalStoreDir: defaultPaypalStoreDir(),
  });
  console.log(`dashboard: http://localhost:${s.port} (bound to 127.0.0.1)`);
}
