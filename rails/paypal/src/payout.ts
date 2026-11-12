// PP3: the `pay_paypal` backend. It takes a PayPal payout order the contract signed (shape 4,
// contract/src/shapes/paypal.rs), checks it, and POSTs it to the PayPal sandbox Payouts API with
// `sender_batch_id = batchId(agent, request_id)`, at most once per (agent, request_id). It trusts nothing the
// caller passes beyond the order fields and the signature:
// - the fields must already be in canonical form, and the message is rebuilt from them byte for
//   byte as `Send USD {amount} to {payee} at {YYYY-MM-DDTHH:MM:SSZ} ref {request_id}`;
// - the signature must recover to the agent EOA (`get_agent`) over the EIP-191 hash of that text;
// - the contract's reservation (`get_request`) must be a `signed` shape 4 payout of that same text
//   and digest, not past `valid_before`;
// - the payee must be on the agent's PayPal payees (`get_payees`) at submission time.
// Any failed check returns `blocked` before PayPal is called. Payees are masked in every detail,
// log line and store record; the PayPal credentials and token stay inside the sandbox client.

import { createHash } from "node:crypto";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { publicKeyToAddress } from "@nearh/owner-near/src/derive.ts";
import type { Client } from "./paypal.ts";
import type { OrderRecord, Store } from "./store.ts";

export type Signature = { r: string; s: string; v: number };
export type RequestKey = { agent: string; caller: { kind: "agent" }; request_id: string };
export type Reservation = {
  key: RequestKey;
  shape: string;
  rail: string | null;
  valid_before: number;
  digest: string;
  payload: { kind: string; text?: string };
  status: string;
  signature: Signature | null;
};
export type Agent = { evm_address: string | null; revoked: boolean };
export type Payee = { rail: "paypal"; receiver: string } | { rail: "sepa"; iban: string } | { rail: "x402"; pay_to: string };

/** The contract views PP3 reads; config.ts wires them to NEAR RPC. */
export type Near = {
  getAgent(agent: string): Promise<Agent | null>;
  getRequest(key: RequestKey): Promise<Reservation | null>;
  getPayees(agent: string): Promise<Payee[]>;
  /** PP-W1: payees an adverse PayPal settlement suspended (`get_suspended_payees`). */
  getSuspendedPayees(agent: string): Promise<Payee[]>;
};

/** The signed order as the agent hands it over: shape 4's fields plus the MPC signature. */
export type PaypalOrder = {
  agent: string;
  request_id: string;
  /** Normalised PayPal email, as the contract signed it. */
  payee: string;
  /** Canonical USD amount, `^(0|[1-9][0-9]*)\.[0-9]{2}$`. */
  amount: string;
  /** Unix seconds, the order's `timestamp`. */
  timestamp: number;
  signature: Signature;
};

/** `pay_paypal`'s output shape. */
export type PayoutResult =
  | { status: "submitted"; request_id: string; payout_batch_id: string; batch_status: string }
  | { status: "blocked" | "failed" | "pending"; request_id: string; error_code: string; detail: string };

export type Deps = {
  near: Near;
  paypal: Client;
  store: Store;
  /** Unix seconds. */
  now?: () => number;
  log?: (line: string) => void;
  /** Credential values to scrub from anything PayPal sends back (client id and secret). */
  secrets?: string[];
};

/** As the contract's `validate_request_id`; also the agent id shape. */
export const AGENT_ID = /^[A-Za-z0-9._:-]{1,64}$/;
/** As `amount_to_cents` in paypal.rs: exactly what goes into `amount.value` (contract/tests/vectors/paypal.json). */
const AMOUNT = /^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/;
export const isCanonicalAmount = (amount: string) => AMOUNT.test(amount) && amount !== "0.00";
const BATCH_ID = /^[A-Z0-9]{8,30}$/;
const MAX_EMAIL_LEN = 254;
/**
 * Seconds a signed order must still have left when PP3 claims it: the 30 s POST timeout, so the
 * payout cannot be created after `valid_before`. Closer orders are refused unclaimed.
 */
export const SUBMIT_MARGIN_SECS = 30;

/** As `normalize_receiver`'s Venmo branch in paypal.rs: `@` and 5-30 of `[a-z0-9_-]`, already lowercased. */
export function isCanonicalVenmo(handle: string): boolean {
  return /^@[a-z0-9_-]{5,30}$/.test(handle);
}

/** As `valid_email` in paypal.rs, on an already lowercased string. */
export function isCanonicalEmail(email: string): boolean {
  if (email.length > MAX_EMAIL_LEN) return false;
  const at = email.indexOf("@");
  if (at < 1 || email.indexOf("@", at + 1) !== -1) return false;
  const local = email.slice(0, at);
  const labels = email.slice(at + 1).split(".");
  const localOk = local.length <= 64 && /^[a-z0-9._%+-]+$/.test(local) && !local.startsWith(".") && !local.endsWith(".") && !local.includes("..");
  const domainOk = labels.length >= 2 && labels.every((l) => /^[a-z0-9-]{1,63}$/.test(l) && !l.startsWith("-") && !l.endsWith("-"));
  return localOk && domainOk;
}

/**
 * The `sender_batch_id` and `PayPal-Request-Id` of an order: hex sha256 of `agent\nrequest_id`
 * (64 chars). Both are unique per PayPal account, not per agent, so a bare `request_id` would let
 * two agents collide, and PayPal could replay agent A's cached 201 to agent B.
 */
export function batchId(agent: string, requestId: string): string {
  return createHash("sha256").update(`${agent}\n${requestId}`).digest("hex");
}

/** As `rfc3339_utc` in payout.rs: `YYYY-MM-DDTHH:MM:SSZ`. */
export function rfc3339(secs: number): string {
  return new Date(secs * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
}

/** The shape 4 text, as `paypal_message` in paypal.rs. */
export function paypalMessage(amount: string, payee: string, timestamp: number, requestId: string): string {
  return `Send USD ${amount} to ${payee} at ${rfc3339(timestamp)} ref ${requestId}`;
}

/** EIP-191 personal_sign hash of `text`. */
export function eip191Digest(text: string): Uint8Array {
  const m = utf8ToBytes(text);
  return keccak_256(concatBytes(utf8ToBytes(`\x19Ethereum Signed Message:\n${m.length}`), m));
}

/** True if `sig` over `digest` recovers to `address`. Malformed signatures are false, never a throw. */
export function recoversTo(sig: Signature, digest: Uint8Array, address: string): boolean {
  const word = (hex: unknown) => {
    const h = typeof hex === "string" ? hex.replace(/^0x/, "").toLowerCase() : "";
    return /^[0-9a-f]{1,64}$/.test(h) ? h.padStart(64, "0") : undefined;
  };
  const r = word(sig?.r);
  const s = word(sig?.s);
  if (!r || !s || (sig.v !== 27 && sig.v !== 28)) return false;
  try {
    const pub = secp256k1.recoverPublicKey(hexToBytes(`0${sig.v - 27}${r}${s}`), digest, { prehash: false });
    return publicKeyToAddress(secp256k1.Point.fromBytes(pub).toBytes(false)) === address.toLowerCase();
  } catch {
    return false;
  }
}

/** `su…@example.com`: at most the first 2 characters of the local part, the domain kept. A Venmo handle keeps its first 2: `@de…`. */
export function maskEmail(email: string): string {
  const at = email.lastIndexOf("@");
  if (at < 0) return "…";
  if (at === 0) return `@${email.slice(1, 3)}…`;
  return `${email.slice(0, Math.min(2, at))}…${email.slice(at)}`;
}

/** Every email in `text` masked; for PP3's own log lines and details. */
export function maskEmails(text: string): string {
  return text.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, maskEmail);
}

/**
 * For text that came from PayPal or a thrown error (details, logs, errors): emails masked, then the given secret
 * values removed, then anything token-like (20+ chars of token alphabet holding a letter and a
 * digit) becomes `<REDACTED>`, so a refusal that echoes a credential cannot carry it out.
 * Known trade-offs: a long non-secret mixed string (a base64 blob, a hash) is redacted too, and an
 * all-digit or all-letter run is kept; PayPal tokens and our PayPal-Request-Ids hold both.
 */
export function scrub(text: string, secrets: (string | undefined)[] = []): string {
  let out = text;
  for (const s of secrets) if (s && s.length >= 4) out = out.split(s).join("<REDACTED>");
  out = maskEmails(out);
  return out.replace(/[A-Za-z0-9._~+\/=-]{20,}/g, (m) => (/[0-9]/.test(m) && /[A-Za-z]/.test(m) ? "<REDACTED>" : m));
}

/** PayPal's refusal of a reused sender_batch_id (PP-S1 step 4): match the field, not the error name. */
function isDuplicateBatch(a: { status: number; body: any }): boolean {
  return (
    a.status === 400 &&
    Array.isArray(a.body?.details) &&
    a.body.details.some((d: any) => d?.field === "SENDER_BATCH_ID" && /already exists/i.test(String(d?.issue ?? "")))
  );
}

/** The batch id in a `self` link (`…/v1/payments/payouts/{id}`), if PayPal sent one. */
function selfBatchId(body: any): string | undefined {
  for (const l of Array.isArray(body?.links) ? body.links : []) {
    const m = /\/v1\/payments\/payouts\/([A-Z0-9]{8,30})(?:[/?]|$)/.exec(String(l?.href ?? ""));
    if (m) return m[1];
  }
  return undefined;
}

export async function submitPaypalPayout(deps: Deps, order: PaypalOrder): Promise<PayoutResult> {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const log = (line: string) => deps.log?.(maskEmails(line));
  const request_id = typeof order?.request_id === "string" ? order.request_id : "";
  const blocked = (error_code: string, detail: string): PayoutResult => {
    // An invalid request_id is caller text: it never goes into a log line.
    log(`blocked ${AGENT_ID.test(request_id) ? request_id : "<invalid request_id>"}: ${error_code}`);
    return { status: "blocked", request_id, error_code, detail: maskEmails(detail) };
  };

  // 1. Shape of the order: canonical fields only, nothing is rewritten.
  const { agent, payee, amount, timestamp, signature } = order ?? ({} as PaypalOrder);
  if (typeof agent !== "string" || !AGENT_ID.test(agent)) return blocked("PP3_INVALID_INPUT", "agent must be 1-64 chars of [A-Za-z0-9._:-]");
  if (!AGENT_ID.test(request_id)) return blocked("PP3_INVALID_INPUT", "request_id must be 1-64 chars of [A-Za-z0-9._:-]");
  // The two receivers the contract's normalize_receiver signs; each goes out as its recipient type.
  const venmo = typeof payee === "string" && isCanonicalVenmo(payee);
  if (typeof payee !== "string" || !(venmo || isCanonicalEmail(payee))) {
    return blocked("PP3_INVALID_INPUT", "payee must be a lowercase PayPal email or @ Venmo handle as the contract signs it");
  }
  if (typeof amount !== "string" || !isCanonicalAmount(amount)) {
    return blocked("PP3_INVALID_INPUT", "amount must be canonical USD with exactly 2 decimals, above zero");
  }
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) return blocked("PP3_INVALID_INPUT", "timestamp must be unix seconds");
  if (!signature || typeof signature !== "object") return blocked("PP3_INVALID_INPUT", "signature {r, s, v} is required");

  // 2. At most once per request_id: a known request never reaches NEAR or PayPal again.
  const seen = deps.store.get(agent, request_id);
  if (seen) {
    return blocked(
      "PP3_DUPLICATE_REQUEST",
      `request ${request_id} was already handed to PP3 (${seen.state}${seen.payout_batch_id ? `, batch ${seen.payout_batch_id}` : ""}); not submitted again`,
    );
  }

  // 3-5. Signature, the contract's record of the same order, and the payee as it stands now.
  const text = paypalMessage(amount, payee, timestamp, request_id);
  const checked = await checkSignedOrder(deps, { agent, request_id, payee, text, signature, shape: "paypal" }, blocked);
  if ("result" in checked) return checked.result;
  const res = checked.res;

  // 6. Authenticate first, so an auth failure leaves the request unclaimed and retryable.
  // Fails closed with a result, not a throw, so every caller (CLI, demo, service) gets the same answer.
  try {
    await deps.paypal.authenticate();
  } catch (e: any) {
    const detail = scrub(String(e?.message ?? e), deps.secrets).slice(0, 300);
    log(`failed ${request_id}: PP3_AUTH_FAILED`);
    return { status: "failed", request_id, error_code: "PP3_AUTH_FAILED", detail: `${detail}; nothing was submitted, retry later with the same order` };
  }
  if (now() + SUBMIT_MARGIN_SECS > res.valid_before) {
    return blocked("PP3_ORDER_EXPIRED", `request ${request_id} expires at ${res.valid_before}, too close to submit`);
  }
  const base: OrderRecord = { agent, request_id, state: "submitting", payee_masked: maskEmail(payee), amount, at: new Date(now() * 1000).toISOString() };
  if (!deps.store.claim(base)) return blocked("PP3_DUPLICATE_REQUEST", `request ${request_id} is already being submitted; not submitted again`);
  // The claim already blocks any resubmission, so a failed update must not turn an accepted payout
  // into an error: the result (with the batch id) still goes back and the log names it.
  const finish = (r: Partial<OrderRecord>) => {
    try {
      deps.store.update({ ...base, ...r });
    } catch (e: any) {
      const id = r.payout_batch_id ? `batch ${r.payout_batch_id}` : "no batch id";
      log(`record-failed ${request_id}: outcome ${r.state}, ${id}; the store update failed (${scrub(String(e?.message ?? e), deps.secrets).slice(0, 200)}), record left as submitting`);
    }
  };

  return sendPayout(deps, { agent, request_id, payee, amount, timestamp, venmo }, base, finish, log, true);
}

/**
 * Steps 3-5 of both PayPal shapes: the signature recovers to the agent EOA (not revoked) over the
 * EIP-191 hash of `text`; the contract's reservation is a `signed` `shape` request on the PayPal
 * rail with that text and digest, not past `valid_before`; the payee is allowlisted and not suspended.
 */
export async function checkSignedOrder(
  deps: Deps,
  o: { agent: string; request_id: string; payee: string; text: string; signature: Signature; shape: "paypal" | "paypal_checkout" },
  blocked: (error_code: string, detail: string) => PayoutResult,
): Promise<{ res: Reservation } | { result: PayoutResult }> {
  const { agent, request_id, payee, text, signature, shape } = o;
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  // 3. The signature recovers to the agent EOA over the message rebuilt from the fields.
  const digest = eip191Digest(text);
  const record = await deps.near.getAgent(agent);
  if (!record) return { result: blocked("PP3_UNKNOWN_AGENT", `no agent ${agent} on the contract`) };
  if (record.revoked) return { result: blocked("PP3_AGENT_REVOKED", `agent ${agent} is revoked`) };
  if (!record.evm_address || !/^0x[0-9a-f]{40}$/i.test(record.evm_address)) return { result: blocked("PP3_UNKNOWN_AGENT", `agent ${agent} has no evm_address`) };
  if (!recoversTo(signature, digest, record.evm_address)) {
    return { result: blocked("PP3_BAD_SIGNATURE", "the signature does not recover to the agent EOA over this order's message") };
  }

  // 4. The contract's record of the same order.
  const res = await deps.near.getRequest({ agent, caller: { kind: "agent" }, request_id });
  if (!res) return { result: blocked("PP3_REQUEST_NOT_FOUND", `no agent request ${request_id} for ${agent}`) };
  if (res.shape !== shape || res.rail !== "paypal" || res.payload?.kind !== "message" || typeof res.payload.text !== "string") {
    return {
      result:
        shape === "paypal"
          ? blocked("PP3_NOT_A_PAYPAL_PAYOUT", `request ${request_id} is not a PayPal payout`)
          : blocked("PP3_NOT_A_PAYPAL_CHECKOUT", `request ${request_id} is not a PayPal checkout charge`),
    };
  }
  if (res.status !== "signed" || !res.signature) return { result: blocked("PP3_NOT_SIGNED", `request ${request_id} is ${res.status}, not signed`) };
  if (res.payload.text !== text) return { result: blocked("PP3_ORDER_MISMATCH", "the order's fields are not the ones the contract signed") };
  if (res.digest?.toLowerCase() !== `0x${bytesToHex(digest)}`) return { result: blocked("PP3_BAD_SIGNATURE", "the reservation digest is not the hash of its text") };
  if (now() > res.valid_before) return { result: blocked("PP3_ORDER_EXPIRED", `request ${request_id} expired at ${res.valid_before}`) };

  // 5. The allowed set as it stands now (a payee removed after signing is refused).
  const payees = await deps.near.getPayees(agent);
  if (!payees.some((p) => p.rail === "paypal" && p.receiver === payee)) {
    return { result: blocked("PP3_PAYEE_NOT_ALLOWED", `payee ${maskEmail(payee)} is not on ${agent}'s PayPal payees`) };
  }
  // PP-W1: an order signed before a failed, returned or reversed payout or a dispute is not sent.
  const suspended = await deps.near.getSuspendedPayees(agent);
  if (suspended.some((p) => p.rail === "paypal" && p.receiver === payee)) {
    return { result: blocked("PP3_PAYEE_SUSPENDED", `payee ${maskEmail(payee)} is suspended for ${agent} after an adverse PayPal settlement`) };
  }

  return { res };
}

/**
 * POSTs one Payouts item for an order that passed every check and is claimed in the store, and
 * records the outcome with `finish`. `releaseOn429` lets a rate-limited order be sent again; the
 * checkout path passes false, because its charge has already been captured.
 */
export async function sendPayout(
  deps: Deps,
  o: { agent: string; request_id: string; payee: string; amount: string; timestamp: number; venmo: boolean },
  base: OrderRecord,
  finish: (r: Partial<OrderRecord>) => void,
  log: (line: string) => void,
  releaseOn429: boolean,
): Promise<PayoutResult> {
  const { agent, request_id, payee, amount, timestamp, venmo } = o;
  const sender_batch_id = batchId(agent, request_id);
  const body = {
    sender_batch_header: {
      sender_batch_id,
      email_subject: "You have a payout",
      email_message: `ref ${request_id}`,
    },
    items: [
      {
        // Venmo: US-only, USD-only (PayPal Payouts); the receiver is the handle exactly as signed.
        recipient_type: venmo ? "VENMO_HANDLE" : "EMAIL",
        amount: { value: amount, currency: "USD" },
        receiver: payee,
        note: `ref ${request_id}`,
        sender_item_id: request_id,
      },
    ],
  };
  log(`submitting ${request_id}: USD ${amount} to ${maskEmail(payee)} signed at ${rfc3339(timestamp)}`);
  let answer;
  try {
    answer = await deps.paypal.request("POST", "/v1/payments/payouts", body, { "PayPal-Request-Id": sender_batch_id });
  } catch (e: any) {
    const detail = `PayPal did not answer (${scrub(String(e?.message ?? e), deps.secrets).slice(0, 200)}); check the sandbox payouts before anything else`;
    finish({ state: "unknown", detail });
    return { status: "pending", request_id, error_code: "PAYPAL_OUTCOME_UNKNOWN", detail };
  }
  const debug_id = typeof answer.debugId === "string" && /^[A-Za-z0-9]{1,64}$/.test(answer.debugId) ? answer.debugId : undefined;

  if (answer.ok) {
    const id = answer.body?.batch_header?.payout_batch_id;
    const batch_status = String(answer.body?.batch_header?.batch_status ?? "");
    // A 2xx for another batch (a replayed PayPal-Request-Id) is not this order's payout: fail closed.
    if (answer.body?.batch_header?.sender_batch_header?.sender_batch_id !== sender_batch_id) {
      const detail = `PayPal answered HTTP ${answer.status} for another sender_batch_id, not ${sender_batch_id}; check the sandbox payouts before anything else`;
      finish({ state: "unknown", http_status: answer.status, debug_id, detail });
      return { status: "pending", request_id, error_code: "PAYPAL_BATCH_MISMATCH", detail };
    }
    if (typeof id === "string" && BATCH_ID.test(id) && batch_status !== "DENIED") {
      finish({ state: "submitted", payout_batch_id: id, batch_status, http_status: answer.status, debug_id });
      log(`submitted ${request_id}: batch ${id} ${batch_status}`);
      return { status: "submitted", request_id, payout_batch_id: id, batch_status };
    }
    const detail = `PayPal answered HTTP ${answer.status} without an accepted batch id; check the sandbox payouts before anything else`;
    finish({ state: "unknown", http_status: answer.status, debug_id, detail });
    return { status: "pending", request_id, error_code: "PAYPAL_OUTCOME_UNKNOWN", detail };
  }

  if (isDuplicateBatch(answer)) {
    const original = selfBatchId(answer.body);
    const detail = `PayPal refused sender_batch_id ${sender_batch_id} as already used${original ? ` (batch ${original})` : ""}: this order was submitted before`;
    finish({ state: "duplicate_batch", http_status: 400, debug_id, detail, ...(original ? { payout_batch_id: original } : {}) });
    return { status: "failed", request_id, error_code: "PAYPAL_DUPLICATE_BATCH", detail };
  }
  const name = typeof answer.body?.name === "string" ? `, ${scrub(answer.body.name, deps.secrets).slice(0, 80)}` : "";
  const detail = `PayPal refused the payout (HTTP ${answer.status}${name}${debug_id ? `, debug_id ${scrub(debug_id, deps.secrets)}` : ""})`;
  if (answer.status === 429 && releaseOn429) {
    // Rate limited: PayPal created nothing, and a retry reuses the same sender_batch_id, which
    // PayPal refuses if a batch did exist. So the claim is released and the request_id stays usable.
    try {
      deps.store.release(agent, request_id);
      log(`rate-limited ${request_id}: claim released, retry later`);
      return { status: "failed", request_id, error_code: "PAYPAL_RATE_LIMITED", detail: `${detail}; nothing was submitted, retry later with the same order` };
    } catch (e: any) {
      log(`release-failed ${request_id}: ${scrub(String(e?.message ?? e), deps.secrets).slice(0, 200)}`);
    }
  }
  if (answer.status >= 500) {
    finish({ state: "unknown", http_status: answer.status, debug_id, detail });
    return { status: "pending", request_id, error_code: "PAYPAL_OUTCOME_UNKNOWN", detail };
  }
  finish({ state: "refused", http_status: answer.status, debug_id, detail });
  return { status: "failed", request_id, error_code: "PAYPAL_REFUSED", detail };
}
