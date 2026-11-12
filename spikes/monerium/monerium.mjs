import { closeSync, openSync } from "node:fs";

export const API = "https://api.monerium.dev";
export const CHAIN = "basesepolia";
export const LINK_MESSAGE = "I hereby declare that I am the address owner.";
// evidence.ndjson is the published, tracked record; the runner only writes the untracked journal.
export const RUN_JOURNAL = "evidence.local.ndjson";
// Created with O_EXCL before the first payout POST and never removed by the runner: two runners cannot both pass.
export const PAYOUT_LOCK = "evidence.local.payout.lock";

export function assertNoPayoutAttempt(events) {
  if (events.some(event => event.step === "payout_attempt")) {
    throw new Error(`A payout was already attempted; inspect sandbox orders before archiving ${RUN_JOURNAL} for another run`);
  }
}

export function takePayoutLock(path) {
  try { closeSync(openSync(path, "wx", 0o600)); }
  catch (error) {
    if (error.code === "EEXIST") throw new Error(`A payout was already attempted (${PAYOUT_LOCK} exists); inspect sandbox orders before removing it`);
    throw error;
  }
}

export function journalEvents(text) {
  return text.trim().split("\n").filter(Boolean).map(line => JSON.parse(line));
}

// Whole cents, rounded down, so a balance can never round up past the amount it must cover.
export function eurCents(input) {
  const text = typeof input === "number" ? String(input) : input;
  if (typeof text !== "string" || !/^[0-9]+(\.[0-9]+)?$/.test(text)) return null;
  const [whole, fraction = ""] = text.split(".");
  return BigInt(whole) * 100n + BigInt(fraction.slice(0, 2).padEnd(2, "0"));
}

export function canonicalAmount(input) {
  if (!/^[0-9]+(\.[0-9]{1,2})?$/.test(input)) throw new Error("Invalid EUR amount");
  const [whole, fraction = ""] = input.split(".");
  const cents = BigInt(whole) * 100n + BigInt(fraction.padEnd(2, "0"));
  if (cents < 1n || cents > 100n) throw new Error("Spike amount must be between EUR 0.01 and EUR 1");
  return `${cents / 100n}${cents % 100n ? `.${(cents % 100n).toString().padStart(2, "0").replace(/0+$/, "")}` : ""}`;
}

export function payoutMessage(amount, iban, timestamp) {
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}$/.test(iban)) throw new Error("Set a sandbox recipient IBAN without spaces");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(timestamp) ||
      !Number.isFinite(Date.parse(timestamp)) || new Date(timestamp).toISOString().replace(".000Z", "Z") !== timestamp) {
    throw new Error("Timestamp must be UTC RFC3339 with seconds");
  }
  return `Send EUR ${canonicalAmount(amount)} to ${iban} at ${timestamp}`;
}

export function safeError(body) {
  const known = ["invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_request"];
  if (known.includes(body?.error)) return body.error;
  const text = JSON.stringify(body);
  if (/duplicate|replay|already (?:been )?(?:used|submitted|processed|exists)/i.test(text)) return "duplicate";
  return "unclassified";
}

// Monerium's own refusal fields, for the record: IBANs, hex values and UUIDs are redacted.
export function refusalCode(body) {
  const redact = (v) => typeof v === "number" ? v : typeof v === "string"
    ? v.replace(/\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/gi, "<IBAN>").replace(/0x[0-9a-f]+/gi, "<HEX>")
      .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<UUID>").slice(0, 200)
    : undefined;
  const out = {};
  for (const key of ["code", "status", "message"]) if (redact(body?.[key]) !== undefined) out[key] = redact(body[key]);
  return out;
}

// The IBAN Monerium attributes to this address on our chain, if one is issued.
export function ibanFor(list, address, profile) {
  return list.find(i => typeof i?.iban === "string" && i.address?.toLowerCase() === address.toLowerCase() &&
    i.chain === CHAIN && (!profile || !i.profile || i.profile === profile));
}

export function replayResult(first, replay) {
  if (!first.ok || ![200, 201, 202].includes(first.status) || !first.body?.id || first.body.state === "rejected") return "inconclusive";
  if ([400, 409, 422].includes(replay.status) && safeError(replay.body) === "duplicate") return "rejected_duplicate";
  if (replay.ok && replay.body?.id === first.body.id) return "idempotent_same_order";
  if (replay.ok && replay.body?.id && replay.body.id !== first.body.id) return "accepted_new_order";
  return "inconclusive";
}

export function sandboxClient(env, fetcher = fetch, record = () => {}) {
  if (env.MONERIUM_ENVIRONMENT !== "sandbox") throw new Error("MONERIUM_ENVIRONMENT must be sandbox");
  if (!env.MONERIUM_CLIENT_ID || !env.MONERIUM_CLIENT_SECRET) throw new Error("Set sandbox credentials in rails/monerium/.env");
  if (env.MONERIUM_BASE_URL && env.MONERIUM_BASE_URL !== API) throw new Error("Only the sandbox API is allowed");
  if (env.MONERIUM_CHAIN && env.MONERIUM_CHAIN !== CHAIN) throw new Error("Only Base Sepolia is allowed");
  let token;
  async function request(method, path, body) {
    if (!/^\/[a-z0-9/?=&%-]+$/i.test(path) || path.startsWith("//")) throw new Error("Invalid API path");
    const auth = path === "/auth/token";
    let res;
    try {
      res = await fetcher(`${API}${path}`, {
        method, redirect: "error", signal: AbortSignal.timeout(30_000),
        headers: {
          accept: "application/vnd.monerium.api-v2+json",
          ...(auth ? {} : { authorization: `Bearer ${token}` }),
          ...(body ? { "content-type": auth ? "application/x-www-form-urlencoded" : "application/json" } : {}),
        },
        body: body ? (auth ? body : JSON.stringify(body)) : undefined,
      });
    } catch {
      throw new Error(`Sandbox ${method} request failed; outcome unknown, inspect the sandbox before retrying`);
    }
    const text = await res.text();
    let data;
    try { data = text ? JSON.parse(text) : {}; }
    catch { throw new Error(`Sandbox returned non-JSON (HTTP ${res.status}); response withheld`); }
    record({ endpoint: path.split("?")[0], method, status: res.status, ...(res.ok ? {} : { error: safeError(data) }) });
    return { ok: res.ok, status: res.status, body: data };
  }
  return {
    async authenticate() {
      const res = await request("POST", "/auth/token", new URLSearchParams({
        grant_type: "client_credentials", client_id: env.MONERIUM_CLIENT_ID, client_secret: env.MONERIUM_CLIENT_SECRET,
      }));
      if (!res.ok || typeof res.body.access_token !== "string" || !res.body.access_token) {
        throw new Error(`Sandbox authentication failed (HTTP ${res.status}, ${safeError(res.body)}); use a sandbox Private application`);
      }
      token = res.body.access_token;
    },
    async request(method, path, body) {
      if (!token) throw new Error("Authenticate before accessing the sandbox");
      return request(method, path, body);
    },
  };
}
