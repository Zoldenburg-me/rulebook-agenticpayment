// PP-W1: PayPal webhooks as tighten-only settlement feedback. PayPal POSTs an event; we verify it with
// PayPal (`POST /v1/notifications/verify-webhook-signature`, the raw body embedded byte for byte) and drop
// anything that does not come back `SUCCESS`. A verified event is matched to an order PP3 submitted, and
// the settlement reporter calls the contract's `report_settlement`, which can only mark a receipt
// PayPal-confirmed or suspend the payee. Nothing here can raise a cap or release budget.

import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync, existsSync } from "node:fs";
import type { Server } from "node:http";
import { join } from "node:path";
import { boundedServer, closeAfter, readBody, type Limits } from "./http.ts";
import type { Client } from "./paypal.ts";
import { AGENT_ID, scrub } from "./payout.ts";
import type { Store } from "./store.ts";

/** The contract's `SettlementStatus` (contract/src/settlement.rs). */
export type SettlementStatus = "completed" | "unclaimed" | "failed" | "returned" | "blocked" | "refunded" | "reversed" | "disputed";

/** The event types we subscribe to, and what each reports. */
export const EVENT_STATUS: Record<string, SettlementStatus> = {
  "PAYMENT.PAYOUTS-ITEM.SUCCEEDED": "completed",
  "PAYMENT.PAYOUTS-ITEM.UNCLAIMED": "unclaimed",
  "PAYMENT.PAYOUTS-ITEM.FAILED": "failed",
  "PAYMENT.PAYOUTS-ITEM.DENIED": "failed",
  "PAYMENT.PAYOUTS-ITEM.RETURNED": "returned",
  "PAYMENT.PAYOUTS-ITEM.BLOCKED": "blocked",
  "PAYMENT.PAYOUTS-ITEM.REFUNDED": "refunded",
  "PAYMENT.CAPTURE.COMPLETED": "completed",
  "PAYMENT.CAPTURE.REFUNDED": "refunded",
  "PAYMENT.CAPTURE.REVERSED": "reversed",
  "CUSTOMER.DISPUTE.CREATED": "disputed",
};

/** PayPal's signature headers, all required. */
const HEADERS = ["paypal-auth-algo", "paypal-cert-url", "paypal-transmission-id", "paypal-transmission-sig", "paypal-transmission-time"] as const;
/** As the contract's `validate_paypal_id`. */
const PAYPAL_ID = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_BODY = 64 * 1024;

export type Report = { agent: string; request_id: string; status: SettlementStatus; paypal_id: string };

/** Event ids already handled; PayPal redelivers until it gets a 2xx. */
export type Seen = { has(id: string): boolean; add(id: string): void };

export type WebhookDeps = {
  paypal: Client;
  /** The id PayPal gave our webhook subscription (`PAYPAL_WEBHOOK_ID`). */
  webhookId: string;
  /** PP3's order store: a report is sent only for an order PP3 submitted. */
  store: Store;
  /** The agents PP3 serves (`PP3_AGENT_TOKENS`); the store is keyed by (agent, request_id). */
  agents: string[];
  seen: Seen;
  /** Calls `report_settlement` as the settlement reporter; throws if the tx failed. */
  report(r: Report): Promise<void>;
  log?: (line: string) => void;
  secrets?: string[];
};

export type Outcome = { status: number; result: string };

export function memorySeen(): Seen {
  const ids = new Set<string>();
  return { has: (id) => ids.has(id), add: (id) => void ids.add(id) };
}

/** One empty file per handled event id (hashed) in `dir`. */
export function fileSeen(dir: string): Seen {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = (id: string) => join(dir, createHash("sha256").update(id).digest("hex"));
  return {
    has: (id) => existsSync(path(id)),
    add: (id) => writeFileSync(path(id), "", { mode: 0o600 }),
  };
}

/**
 * The body of the verify call with the event embedded exactly as received: re-serialising it would change
 * the bytes PayPal signed. The header values go through JSON.stringify, so they cannot break out.
 */
export function verifyBody(headers: Record<string, string>, webhookId: string, raw: string): string {
  const f = (k: string, v: string) => `${JSON.stringify(k)}:${JSON.stringify(v)}`;
  return `{${[
    f("auth_algo", headers["paypal-auth-algo"]),
    f("cert_url", headers["paypal-cert-url"]),
    f("transmission_id", headers["paypal-transmission-id"]),
    f("transmission_sig", headers["paypal-transmission-sig"]),
    f("transmission_time", headers["paypal-transmission-time"]),
    f("webhook_id", webhookId),
  ].join(",")},"webhook_event":${raw}}`;
}

/** The (request_id candidates, PayPal id, payout batch) an event's resource names. */
function locate(eventType: string, resource: any): { ids: string[]; paypalId: unknown; batch?: unknown } {
  if (eventType.startsWith("PAYMENT.PAYOUTS-ITEM.")) {
    // PP3 sends sender_item_id = request_id; the batch id ties the item to PP3's record.
    return { ids: [resource?.payout_item?.sender_item_id], paypalId: resource?.payout_item_id, batch: resource?.payout_batch_id };
  }
  if (eventType.startsWith("PAYMENT.CAPTURE.")) {
    return { ids: [resource?.custom_id, resource?.invoice_id], paypalId: resource?.id };
  }
  // CUSTOMER.DISPUTE.CREATED
  const txs = Array.isArray(resource?.disputed_transactions) ? resource.disputed_transactions : [];
  return { ids: txs.flatMap((t: any) => [t?.custom, t?.invoice_number]), paypalId: resource?.dispute_id };
}

/**
 * Handles one delivery. Fail closed: missing headers, a verify call that does not answer `SUCCESS`, or
 * JSON we cannot read are dropped with a 4xx and never reported. A verify call with no answer, or a
 * failed report, is a 5xx so PayPal delivers again; the event is marked handled only after that.
 */
export async function handleWebhook(d: WebhookDeps, headers: Record<string, string | string[] | undefined>, raw: string): Promise<Outcome> {
  // Our own lines carry only validated ids; text from PayPal or an error goes through `scrub` (`safe`).
  const log = (l: string) => d.log?.(l);
  const safe = (t: unknown) => scrub(String(t), d.secrets).slice(0, 300);
  const h: Record<string, string> = {};
  for (const k of HEADERS) {
    const v = headers[k];
    if (typeof v !== "string" || !v || v.length > 2048) {
      log(`dropped: missing ${k}`);
      return { status: 400, result: "unverified" };
    }
    h[k] = v;
  }
  let event: any;
  try {
    event = JSON.parse(raw);
  } catch {
    log("dropped: body is not JSON");
    return { status: 400, result: "unverified" };
  }
  if (typeof event !== "object" || event === null || Array.isArray(event)) {
    log("dropped: body is not a JSON object");
    return { status: 400, result: "unverified" };
  }

  let answer;
  try {
    await d.paypal.authenticate();
    answer = await d.paypal.request("POST", "/v1/notifications/verify-webhook-signature", verifyBody(h, d.webhookId, raw));
  } catch (e: any) {
    log(`verify call failed, PayPal will redeliver: ${safe(e?.message ?? e)}`);
    return { status: 503, result: "verify_unavailable" };
  }
  if (!answer.ok || answer.body?.verification_status !== "SUCCESS") {
    log(`dropped: verification ${answer.status} ${safe(answer.body?.verification_status ?? answer.body?.name ?? "")} debug_id ${safe(answer.debugId ?? "-")}`);
    return { status: answer.status >= 500 ? 503 : 400, result: answer.status >= 500 ? "verify_unavailable" : "unverified" };
  }

  // Verified: from here on the event is PayPal's.
  const id = typeof event.id === "string" ? event.id : "";
  const type = typeof event.event_type === "string" ? event.event_type : "";
  if (!PAYPAL_ID.test(id)) {
    log("verified event without a usable id: ignored");
    return { status: 200, result: "ignored" };
  }
  if (d.seen.has(id)) {
    log(`event ${id} already handled`);
    return { status: 200, result: "duplicate" };
  }
  const status = EVENT_STATUS[type];
  if (!status) {
    log(`verified ${type} ${id}: not a settlement event, ignored`);
    d.seen.add(id);
    return { status: 200, result: "ignored" };
  }

  const where = locate(type, event.resource);
  const matches: { agent: string; request_id: string }[] = [];
  for (const requestId of new Set(where.ids.filter((v): v is string => typeof v === "string" && AGENT_ID.test(v)))) {
    for (const agent of d.agents) {
      const rec = d.store.get(agent, requestId);
      if (!rec || rec.state !== "submitted") continue;
      if (where.batch !== undefined && rec.payout_batch_id !== where.batch) continue;
      matches.push({ agent, request_id: requestId });
    }
  }
  if (matches.length !== 1 || typeof where.paypalId !== "string" || !PAYPAL_ID.test(where.paypalId)) {
    log(`verified ${type} ${id}: ${matches.length === 0 ? "no submitted PP3 order matches" : matches.length > 1 ? "matches several orders" : "no usable PayPal id"}, ignored`);
    d.seen.add(id);
    return { status: 200, result: "no_order" };
  }

  const report: Report = { ...matches[0], status, paypal_id: where.paypalId };
  try {
    await d.report(report);
  } catch (e: any) {
    log(`report ${report.agent}/${report.request_id} ${status} failed, PayPal will redeliver: ${safe(e?.message ?? e)}`);
    return { status: 500, result: "report_failed" };
  }
  d.seen.add(id);
  log(`verified ${type} ${id}: reported ${status} for ${report.agent}/${report.request_id} (${report.paypal_id})`);
  return { status: 200, result: `reported_${status}` };
}

/** `POST /paypal/webhook`. Public behind a tunnel: every request is untrusted until PayPal verifies it. */
export function webhookServer(d: WebhookDeps, limits: Partial<Limits> = {}): Server {
  const l: Limits = { ...limits, maxBody: MAX_BODY };
  return boundedServer(l, (req, res) => {
    res.on("error", () => {});
    const reply = (status: number, result: string) => {
      if (res.headersSent || res.writableEnded || res.destroyed) return;
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify({ result }));
    };
    const handle = async () => {
      if (req.method !== "POST" || req.url !== "/paypal/webhook") return reply(404, "not_found");
      const raw = await readBody(req, l);
      if (raw === undefined) return;
      if (raw === "too_large" || raw === "timeout") closeAfter(req, res);
      if (raw === "too_large") return reply(413, "too_large");
      if (raw === "timeout") return reply(408, "timeout");
      const out = await handleWebhook(d, req.headers, raw);
      reply(out.status, out.result);
    };
    handle().catch(() => reply(500, "internal_error"));
  });
}
