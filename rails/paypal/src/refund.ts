// PP-T1: the refund backend. It takes a refund order the contract signed (shape 6,
// contract/src/shapes/refund.rs) and refunds the capture in the PayPal sandbox at most once per
// (agent, request_id). As PP3 for payouts, it trusts nothing the caller passes beyond the order
// fields and the signature:
// - the fields must already be in canonical form, and the text is rebuilt from them byte for
//   byte as `Refund USD {amount} of capture {capture_id} ref {request_id}`;
// - the signature must recover to the agent EOA (`get_agent`) over the EIP-191 hash of that text;
// - the contract's reservation (`get_request`) must be a `signed` shape 6 refund of that same
//   text and digest on the `paypal_refund` rail, not past `valid_before`;
// - the amount must be at most what the capture has left: captured minus already refunded, read
//   from PayPal (`GET /v2/payments/captures/{id}`, then the refunds its order lists for it).
// Any failed check returns `blocked` before the refund POST. The PayPal credentials and token stay
// inside the sandbox client; the agent process never has them.

import { createHash } from "node:crypto";
import { bytesToHex } from "@noble/hashes/utils.js";
import { AGENT_ID, eip191Digest, isCanonicalAmount, recoversTo, scrub, SUBMIT_MARGIN_SECS, type Near, type Signature } from "./payout.ts";
import type { Client } from "./paypal.ts";
import type { OrderRecord, Store } from "./store.ts";

/** The signed refund order as the agent hands it over: shape 6's fields plus the MPC signature. */
export type RefundOrder = {
  agent: string;
  request_id: string;
  /** PayPal capture id, 10-32 of `[A-Z0-9]`, as the contract signed it. */
  capture_id: string;
  /** Canonical USD amount, `^(0|[1-9][0-9]*)\.[0-9]{2}$`. */
  amount: string;
  signature: Signature;
};

export type RefundResult =
  | { status: "refunded"; request_id: string; capture_id: string; amount: string; refund_id: string; refund_status: string }
  | { status: "blocked" | "failed" | "pending"; request_id: string; error_code: string; detail: string };

export type RefundDeps = {
  near: Near;
  paypal: Client;
  /** One record per (agent, request_id); a separate directory from the payout orders. */
  store: Store;
  /** Unix seconds. */
  now?: () => number;
  log?: (line: string) => void;
  /** Credential values to scrub from anything PayPal sends back (client id and secret). */
  secrets?: string[];
};

/** As `validate_capture_id` in refund.rs. */
export const CAPTURE_ID = /^[A-Z0-9]{10,32}$/;
const REFUND_ID = /^[A-Z0-9]{10,32}$/;
/** Capture states a refund can come from; PayPal refuses the others anyway. */
const REFUNDABLE = new Set(["COMPLETED", "PARTIALLY_REFUNDED"]);
/** Refund states that took (or may still take) money off the capture. */
const REFUND_COUNTS = new Set(["COMPLETED", "PENDING"]);

/** Refund record: an order record plus the capture and PayPal's refund id. No payer data. */
export type RefundRecord = OrderRecord & { capture_id: string; refund_id?: string; refund_status?: string };

/** The shape 6 text, as `refund_message` in refund.rs. */
export function refundMessage(amount: string, captureId: string, requestId: string): string {
  return `Refund USD ${amount} of capture ${captureId} ref ${requestId}`;
}

/**
 * The refund's `PayPal-Request-Id`: hex sha256 of `refund\nagent\nrequest_id`. Unique per PayPal
 * account, so derived from the pair (two agents never share one), and tagged so it never equals a
 * payout's `batchId`. A resend with the same id returns PayPal's first answer, never a second refund.
 */
export function refundRequestId(agent: string, requestId: string): string {
  return createHash("sha256").update(`refund\n${agent}\n${requestId}`).digest("hex");
}

/** Cents of a canonical USD string, or undefined. */
export function cents(value: unknown): bigint | undefined {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/.test(value)) return undefined;
  return BigInt(value.replace(".", ""));
}

const usd = (c: bigint) => `${c / 100n}.${String(c % 100n).padStart(2, "0")}`;

export type Refundable =
  | { ok: true; captured: bigint; refunded: bigint; left: bigint }
  | { ok: false; status: "blocked" | "failed"; error_code: string; detail: string };

/**
 * What the capture has left to refund, from PayPal. `GET /v2/payments/captures/{id}` gives the
 * captured amount, its status and its order; it does not give the refunded total, so the order's
 * refunds whose `up` link is this capture are summed (COMPLETED and PENDING). Fails closed: a
 * capture that is not USD, not refundable, or whose refunds cannot be read is not refunded.
 */
export async function refundable(paypal: Client, captureId: string): Promise<Refundable> {
  const capture = await paypal.request("GET", `/v2/payments/captures/${captureId}`);
  if (capture.status === 404) return { ok: false, status: "blocked", error_code: "PP3_CAPTURE_NOT_FOUND", detail: `no capture ${captureId} on this merchant account` };
  if (!capture.ok) return { ok: false, status: "failed", error_code: "PP3_CAPTURE_UNAVAILABLE", detail: `PayPal answered HTTP ${capture.status} for capture ${captureId}; nothing was refunded, retry later` };
  const c = capture.body ?? {};
  if (c.id !== captureId) return { ok: false, status: "blocked", error_code: "PP3_CAPTURE_MISMATCH", detail: `PayPal returned another capture for ${captureId}` };
  if (c.amount?.currency_code !== "USD") return { ok: false, status: "blocked", error_code: "PP3_CAPTURE_NOT_USD", detail: `capture ${captureId} is not in USD` };
  const captured = cents(c.amount?.value);
  if (captured === undefined) return { ok: false, status: "blocked", error_code: "PP3_CAPTURE_UNREADABLE", detail: `capture ${captureId} has no readable amount` };
  if (c.status === "REFUNDED") return { ok: true, captured, refunded: captured, left: 0n };
  if (!REFUNDABLE.has(c.status)) return { ok: false, status: "blocked", error_code: "PP3_CAPTURE_NOT_REFUNDABLE", detail: `capture ${captureId} is ${String(c.status).slice(0, 40)}` };
  const orderId = c.supplementary_data?.related_ids?.order_id;
  if (typeof orderId !== "string" || !/^[A-Z0-9]{10,36}$/.test(orderId)) {
    return { ok: false, status: "blocked", error_code: "PP3_CAPTURE_UNVERIFIABLE", detail: `capture ${captureId} names no order, so its refunds cannot be read` };
  }
  const order = await paypal.request("GET", `/v2/checkout/orders/${orderId}`);
  if (!order.ok) return { ok: false, status: "failed", error_code: "PP3_CAPTURE_UNAVAILABLE", detail: `PayPal answered HTTP ${order.status} for the capture's order; nothing was refunded, retry later` };
  const units = Array.isArray(order.body?.purchase_units) ? order.body.purchase_units : [];
  const ofCapture = (r: any) =>
    Array.isArray(r?.links) && r.links.some((l: any) => l?.rel === "up" && new RegExp(`/v2/payments/captures/${captureId}$`).test(String(l?.href ?? "")));
  const listed = units.some((u: any) => (u?.payments?.captures ?? []).some((x: any) => x?.id === captureId));
  if (!listed) return { ok: false, status: "blocked", error_code: "PP3_CAPTURE_UNVERIFIABLE", detail: `the capture's order does not list capture ${captureId}` };
  let refunded = 0n;
  for (const u of units) {
    for (const r of Array.isArray(u?.payments?.refunds) ? u.payments.refunds : []) {
      if (!ofCapture(r) || !REFUND_COUNTS.has(r?.status)) continue;
      const v = cents(r?.amount?.value);
      if (v === undefined || r?.amount?.currency_code !== "USD") {
        return { ok: false, status: "blocked", error_code: "PP3_CAPTURE_UNVERIFIABLE", detail: `a refund of capture ${captureId} has no readable USD amount` };
      }
      refunded += v;
    }
  }
  // PARTIALLY_REFUNDED with nothing found means the refund list is not what PayPal counts: fail closed.
  if (c.status === "PARTIALLY_REFUNDED" && refunded === 0n) {
    return { ok: false, status: "blocked", error_code: "PP3_CAPTURE_UNVERIFIABLE", detail: `capture ${captureId} is partially refunded but its refunds were not found` };
  }
  return { ok: true, captured, refunded, left: captured > refunded ? captured - refunded : 0n };
}

/** One check-then-refund at a time per capture in this process, so two orders cannot both pass the "left" check. */
const captureLocks = new Map<string, Promise<unknown>>();
async function withCaptureLock<T>(captureId: string, f: () => Promise<T>): Promise<T> {
  const prev = captureLocks.get(captureId) ?? Promise.resolve();
  const run = prev.then(f, f);
  const settled = run.catch(() => {});
  captureLocks.set(captureId, settled);
  try {
    return await run;
  } finally {
    if (captureLocks.get(captureId) === settled) captureLocks.delete(captureId);
  }
}

export async function submitRefund(deps: RefundDeps, order: RefundOrder): Promise<RefundResult> {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const log = (line: string) => deps.log?.(line);
  const request_id = typeof order?.request_id === "string" ? order.request_id : "";
  const blocked = (error_code: string, detail: string): RefundResult => {
    // An invalid request_id is caller text: it never goes into a log line.
    log(`refund blocked ${AGENT_ID.test(request_id) ? request_id : "<invalid request_id>"}: ${error_code}`);
    return { status: "blocked", request_id, error_code, detail };
  };

  // 1. Shape of the order: canonical fields only, nothing is rewritten.
  const { agent, capture_id, amount, signature } = order ?? ({} as RefundOrder);
  if (typeof agent !== "string" || !AGENT_ID.test(agent)) return blocked("PP3_INVALID_INPUT", "agent must be 1-64 chars of [A-Za-z0-9._:-]");
  if (!AGENT_ID.test(request_id)) return blocked("PP3_INVALID_INPUT", "request_id must be 1-64 chars of [A-Za-z0-9._:-]");
  if (typeof capture_id !== "string" || !CAPTURE_ID.test(capture_id)) return blocked("PP3_INVALID_INPUT", "capture_id must be 10-32 of [A-Z0-9]");
  if (typeof amount !== "string" || !isCanonicalAmount(amount)) return blocked("PP3_INVALID_INPUT", "amount must be canonical USD with exactly 2 decimals, above zero");
  if (!signature || typeof signature !== "object") return blocked("PP3_INVALID_INPUT", "signature {r, s, v} is required");

  // 2. At most once per request_id: a known request never reaches NEAR or PayPal again.
  const seen = deps.store.get(agent, request_id) as RefundRecord | undefined;
  if (seen) {
    return blocked("PP3_DUPLICATE_REQUEST", `refund ${request_id} was already handed to the rail (${seen.state}${seen.refund_id ? `, refund ${seen.refund_id}` : ""}); not submitted again`);
  }

  // 3. The signature recovers to the agent EOA over the text rebuilt from the fields.
  const text = refundMessage(amount, capture_id, request_id);
  const digest = eip191Digest(text);
  const record = await deps.near.getAgent(agent);
  if (!record) return blocked("PP3_UNKNOWN_AGENT", `no agent ${agent} on the contract`);
  if (record.revoked) return blocked("PP3_AGENT_REVOKED", `agent ${agent} is revoked`);
  if (!record.evm_address || !/^0x[0-9a-f]{40}$/i.test(record.evm_address)) return blocked("PP3_UNKNOWN_AGENT", `agent ${agent} has no evm_address`);
  if (!recoversTo(signature, digest, record.evm_address)) {
    return blocked("PP3_BAD_SIGNATURE", "the signature does not recover to the agent EOA over this order's message");
  }

  // 4. The contract's record of the same order.
  const res = await deps.near.getRequest({ agent, caller: { kind: "agent" }, request_id });
  if (!res) return blocked("PP3_REQUEST_NOT_FOUND", `no agent request ${request_id} for ${agent}`);
  if (res.shape !== "refund" || res.rail !== "paypal_refund" || res.payload?.kind !== "message" || typeof res.payload.text !== "string") {
    return blocked("PP3_NOT_A_REFUND", `request ${request_id} is not a PayPal refund`);
  }
  if (res.status !== "signed" || !res.signature) return blocked("PP3_NOT_SIGNED", `request ${request_id} is ${res.status}, not signed`);
  if (res.payload.text !== text) return blocked("PP3_ORDER_MISMATCH", "the order's fields are not the ones the contract signed");
  if (res.digest?.toLowerCase() !== `0x${bytesToHex(digest)}`) return blocked("PP3_BAD_SIGNATURE", "the reservation digest is not the hash of its text");
  if (now() > res.valid_before) return blocked("PP3_ORDER_EXPIRED", `request ${request_id} expired at ${res.valid_before}`);

  // 5. Authenticate first, so an auth failure leaves the request unclaimed and retryable.
  try {
    await deps.paypal.authenticate();
  } catch (e: any) {
    const detail = scrub(String(e?.message ?? e), deps.secrets).slice(0, 300);
    log(`refund failed ${request_id}: PP3_AUTH_FAILED`);
    return { status: "failed", request_id, error_code: "PP3_AUTH_FAILED", detail: `${detail}; nothing was refunded, retry later with the same order` };
  }

  return withCaptureLock(capture_id, async (): Promise<RefundResult> => {
    // 6. Captured minus already refunded, from PayPal, right before the POST.
    let left: Refundable;
    try {
      left = await refundable(deps.paypal, capture_id);
    } catch (e: any) {
      const detail = `PayPal did not answer for capture ${capture_id} (${scrub(String(e?.message ?? e), deps.secrets).slice(0, 200)}); nothing was refunded, retry later`;
      return { status: "failed", request_id, error_code: "PP3_CAPTURE_UNAVAILABLE", detail };
    }
    if (!left.ok) {
      log(`refund ${left.status} ${request_id}: ${left.error_code}`);
      return { status: left.status, request_id, error_code: left.error_code, detail: left.detail };
    }
    const want = BigInt(amount.replace(".", ""));
    if (want > left.left) {
      return blocked("PP3_REFUND_EXCEEDS_CAPTURE", `capture ${capture_id}: captured USD ${usd(left.captured)}, refunded ${usd(left.refunded)}, ${usd(left.left)} left; USD ${amount} not refunded`);
    }
    if (now() + SUBMIT_MARGIN_SECS > res.valid_before) {
      return blocked("PP3_ORDER_EXPIRED", `request ${request_id} expires at ${res.valid_before}, too close to submit`);
    }
    const base: RefundRecord = { agent, request_id, state: "submitting", payee_masked: "capture payer", amount, capture_id, at: new Date(now() * 1000).toISOString() };
    if (!deps.store.claim(base)) return blocked("PP3_DUPLICATE_REQUEST", `refund ${request_id} is already being submitted; not submitted again`);
    const finish = (r: Partial<RefundRecord>) => {
      try {
        deps.store.update({ ...base, ...r } as RefundRecord);
      } catch (e: any) {
        log(`record-failed ${request_id}: outcome ${r.state}, ${r.refund_id ? `refund ${r.refund_id}` : "no refund id"}; the store update failed (${scrub(String(e?.message ?? e), deps.secrets).slice(0, 200)}), record left as submitting`);
      }
    };

    // 7. One POST. The PayPal-Request-Id makes a lost-answer resend return the same refund, never a second.
    log(`refunding ${request_id}: USD ${amount} of capture ${capture_id} (${usd(left.left)} left)`);
    let answer;
    try {
      answer = await deps.paypal.request(
        "POST",
        `/v2/payments/captures/${capture_id}/refund`,
        { amount: { value: amount, currency_code: "USD" }, note_to_payer: `ref ${request_id}` },
        { "PayPal-Request-Id": refundRequestId(agent, request_id), Prefer: "return=representation" },
      );
    } catch (e: any) {
      const detail = `PayPal did not answer (${scrub(String(e?.message ?? e), deps.secrets).slice(0, 200)}); check the capture's refunds before anything else`;
      finish({ state: "unknown", detail });
      return { status: "pending", request_id, error_code: "PAYPAL_OUTCOME_UNKNOWN", detail };
    }
    const debug_id = typeof answer.debugId === "string" && /^[A-Za-z0-9]{1,64}$/.test(answer.debugId) ? answer.debugId : undefined;
    if (answer.ok) {
      const id = answer.body?.id;
      const st = String(answer.body?.status ?? "");
      const sameAmount = answer.body?.amount?.value === amount && answer.body?.amount?.currency_code === "USD";
      if (typeof id === "string" && REFUND_ID.test(id) && REFUND_COUNTS.has(st) && sameAmount) {
        finish({ state: "submitted", refund_id: id, refund_status: st, http_status: answer.status, debug_id });
        log(`refunded ${request_id}: refund ${id} ${st}`);
        return { status: "refunded", request_id, capture_id, amount, refund_id: id, refund_status: st };
      }
      const detail = `PayPal answered HTTP ${answer.status} without a matching refund; check the capture's refunds before anything else`;
      finish({ state: "unknown", http_status: answer.status, debug_id, detail, ...(typeof id === "string" && REFUND_ID.test(id) ? { refund_id: id } : {}) });
      return { status: "pending", request_id, error_code: "PAYPAL_OUTCOME_UNKNOWN", detail };
    }
    const issue = Array.isArray(answer.body?.details) && typeof answer.body.details[0]?.issue === "string" ? `, ${scrub(answer.body.details[0].issue, deps.secrets).slice(0, 80)}` : "";
    const detail = `PayPal refused the refund (HTTP ${answer.status}${issue}${debug_id ? `, debug_id ${debug_id}` : ""})`;
    if (answer.status === 429) {
      // Rate limited: nothing was refunded; the same order may be sent again later.
      try {
        deps.store.release(agent, request_id);
        return { status: "failed", request_id, error_code: "PAYPAL_RATE_LIMITED", detail: `${detail}; nothing was refunded, retry later with the same order` };
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
  });
}
