// PP-V1: pay from the owner's vaulted PayPal wallet under the mandate (shape 5,
// contract/src/shapes/paypal_checkout.rs). PP-V0 showed that a merchant-initiated charge on a
// MERCHANT payment token completes into our own merchant account. A third-party payee in the order is
// not used: the docs scope a MERCHANT token to one merchant (spikes/paypal-vault/RESULT.md). So a charge
// is two PayPal calls:
// 1. Orders v2 CAPTURE on the vault_id into the rail's merchant account (`PayPal-Request-Id` per order);
// 2. the PP3 Payouts call to the merchant the contract signed (`sender_batch_id = batchId(agent, request_id)`).
// The vault_id (payment token id) lives only in the vault store here. It is never returned, logged or
// put in an error: results carry the token status, and every PayPal text goes through `scrub` with the
// vault id among the secrets.
//
// Owner side: `connectVault` creates a setup token and returns PayPal's approve link; the owner
// approves on PayPal's page; `confirmVault` turns the approved setup token into a payment token.
// `revokeVault` DELETEs the payment token and checks that a GET then answers 404. A charge for a
// revoked agent also deletes the token, so the contract revoke and the vault delete both stop spending.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  AGENT_ID,
  batchId,
  checkSignedOrder,
  isCanonicalAmount,
  isCanonicalEmail,
  isCanonicalVenmo,
  maskEmail,
  maskEmails,
  rfc3339,
  scrub,
  sendPayout,
  SUBMIT_MARGIN_SECS,
  type Deps,
  type PayoutResult,
  type Signature,
} from "./payout.ts";
import type { OrderRecord } from "./store.ts";

/** What the owner sees of a vault: never the token ids. */
export type VaultStatus = "none" | "approval_required" | "active" | "revoked";

/** Stored per agent, file mode 0600. `vault_id` is the payment token id and never leaves this module. */
export type VaultRecord = {
  agent: string;
  status: Exclude<VaultStatus, "none">;
  setup_token_id?: string;
  vault_id?: string;
  updated_at: string;
};

export type VaultStore = {
  get(agent: string): VaultRecord | undefined;
  put(record: VaultRecord): void;
};

export function memoryVaultStore(): VaultStore & { records: Map<string, VaultRecord> } {
  const records = new Map<string, VaultRecord>();
  return { records, get: (a) => records.get(a), put: (r) => void records.set(r.agent, { ...r }) };
}

export function fileVaultStore(dir: string): VaultStore {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = (agent: string) => join(dir, `${createHash("sha256").update(agent).digest("hex")}.json`);
  return {
    get(agent) {
      try {
        return JSON.parse(readFileSync(path(agent), "utf8"));
      } catch (e: any) {
        if (e?.code === "ENOENT") return undefined;
        throw new Error("cannot read the vault record; refusing to charge");
      }
    },
    put(record) {
      const p = path(record.agent);
      writeFileSync(`${p}.tmp`, JSON.stringify(record), { mode: 0o600 });
      renameSync(`${p}.tmp`, p);
    },
  };
}

export type VaultDeps = Deps & {
  vaults: VaultStore;
  /** Where PayPal sends the owner after approving or cancelling (the page need not load). */
  returnUrl?: string;
  cancelUrl?: string;
};

/** The signed charge as the agent hands it over: shape 5's fields plus the MPC signature. */
export type CheckoutOrder = {
  agent: string;
  request_id: string;
  /** The merchant's normalised PayPal email or Venmo handle, as the contract signed it. */
  payee: string;
  amount: string;
  /** The merchant's order reference, 1-64 of `[A-Za-z0-9._:-]`. */
  order_ref: string;
  timestamp: number;
  signature: Signature;
};

export type CheckoutResult =
  | {
      status: "submitted";
      request_id: string;
      paypal_order_id: string;
      capture_id: string;
      payout_batch_id: string;
      batch_status: string;
    }
  | { status: "blocked" | "failed" | "pending"; request_id: string; error_code: string; detail: string; paypal_order_id?: string; capture_id?: string };

/** Shape 5's text, as `checkout_message` in paypal_checkout.rs. */
export function checkoutMessage(amount: string, payee: string, orderRef: string, timestamp: number, requestId: string): string {
  return `Charge USD ${amount} to merchant ${payee} for order ${orderRef} at ${rfc3339(timestamp)} ref ${requestId}`;
}

/** `PayPal-Request-Id` of the Orders call; another namespace than the payout's `batchId`. */
export function checkoutRequestId(agent: string, requestId: string): string {
  return createHash("sha256").update(`checkout\n${agent}\n${requestId}`).digest("hex");
}

const PAYPAL_ID = /^[A-Za-z0-9-]{6,64}$/;
const DEFAULT_RETURN = "https://example.com/nearh-vault/return";
const DEFAULT_CANCEL = "https://example.com/nearh-vault/cancel";

function stamp(d: Deps): string {
  return new Date((d.now?.() ?? Math.floor(Date.now() / 1000)) * 1000).toISOString();
}

function vaultSecrets(d: Deps, v?: VaultRecord): string[] {
  return [...(d.secrets ?? []), v?.vault_id, v?.setup_token_id].filter((s): s is string => !!s);
}

/** The owner-facing status of an agent's vault. */
export function vaultStatus(d: VaultDeps, agent: string): { agent: string; status: VaultStatus; updated_at?: string } {
  const v = d.vaults.get(agent);
  return v ? { agent, status: v.status, updated_at: v.updated_at } : { agent, status: "none" };
}

type OwnerResult = { ok: true; agent: string; status: VaultStatus; approve_url?: string; detail?: string } | { ok: false; agent: string; error_code: string; detail: string };

/** Step 1: a setup token for the owner to approve. Returns PayPal's approve link (for the owner only). */
export async function connectVault(d: VaultDeps, agent: string): Promise<OwnerResult> {
  if (!AGENT_ID.test(agent)) return { ok: false, agent: "", error_code: "PP3_INVALID_INPUT", detail: "agent must be 1-64 chars of [A-Za-z0-9._:-]" };
  if (d.vaults.get(agent)?.status === "active") return { ok: false, agent, error_code: "VAULT_ALREADY_ACTIVE", detail: "revoke the current PayPal connection first" };
  await d.paypal.authenticate();
  const body = {
    payment_source: {
      paypal: {
        description: `nearh agent ${agent} spending account (sandbox)`,
        usage_pattern: "IMMEDIATE",
        usage_type: "MERCHANT",
        customer_type: "CONSUMER",
        permit_multiple_payment_tokens: true,
        experience_context: {
          brand_name: "nearh sandbox",
          shipping_preference: "NO_SHIPPING",
          return_url: d.returnUrl ?? DEFAULT_RETURN,
          cancel_url: d.cancelUrl ?? DEFAULT_CANCEL,
        },
      },
    },
  };
  const a = await d.paypal.request("POST", "/v3/vault/setup-tokens", body, { "PayPal-Request-Id": createHash("sha256").update(`setup\n${agent}\n${stamp(d)}`).digest("hex") });
  const id = a.body?.id;
  const approve = Array.isArray(a.body?.links) ? a.body.links.find((l: any) => l?.rel === "approve")?.href : undefined;
  if (!a.ok || typeof id !== "string" || !PAYPAL_ID.test(id) || typeof approve !== "string" || !approve.startsWith("https://")) {
    return { ok: false, agent, error_code: "VAULT_SETUP_FAILED", detail: `PayPal refused the setup token (HTTP ${a.status})` };
  }
  d.vaults.put({ agent, status: "approval_required", setup_token_id: id, updated_at: stamp(d) });
  d.log?.(`vault ${agent}: setup token created, owner approval required`);
  return { ok: true, agent, status: "approval_required", approve_url: approve };
}

/** Step 3, after the owner approved on PayPal's page: the payment token, stored here only. */
export async function confirmVault(d: VaultDeps, agent: string): Promise<OwnerResult> {
  const v = d.vaults.get(agent);
  if (!v || v.status !== "approval_required" || !v.setup_token_id) {
    return { ok: false, agent, error_code: "VAULT_NOT_PENDING", detail: "no setup token awaiting approval; connect first" };
  }
  await d.paypal.authenticate();
  const g = await d.paypal.request("GET", `/v3/vault/setup-tokens/${v.setup_token_id}`);
  const st = String(g.body?.status ?? "");
  if (!g.ok || !["APPROVED", "VAULTED"].includes(st)) {
    return { ok: false, agent, error_code: "VAULT_NOT_APPROVED", detail: `the owner has not approved on PayPal yet (HTTP ${g.status}, ${st || "no status"})` };
  }
  const p = await d.paypal.request(
    "POST",
    "/v3/vault/payment-tokens",
    { payment_source: { token: { id: v.setup_token_id, type: "SETUP_TOKEN" } } },
    { "PayPal-Request-Id": createHash("sha256").update(`token\n${agent}\n${v.setup_token_id}`).digest("hex") },
  );
  const vaultId = p.body?.id;
  if (!p.ok || typeof vaultId !== "string" || !PAYPAL_ID.test(vaultId)) {
    // PP-V0 attempt 1: a 500 here can still have created a token; it is not guessed, the owner reconnects.
    return { ok: false, agent, error_code: "VAULT_TOKEN_FAILED", detail: `PayPal did not return a payment token (HTTP ${p.status}); connect again` };
  }
  d.vaults.put({ agent, status: "active", setup_token_id: v.setup_token_id, vault_id: vaultId, updated_at: stamp(d) });
  d.log?.(`vault ${agent}: payment token stored`);
  return { ok: true, agent, status: "active" };
}

/** DELETE the payment token, then GET it: 404 means it is gone. Marks the vault revoked either way. */
export async function revokeVault(d: VaultDeps, agent: string): Promise<OwnerResult & { token_http_after?: number }> {
  const v = d.vaults.get(agent);
  if (!v || v.status === "revoked") return { ok: true, agent, status: v ? "revoked" : "none" };
  // Marked first: even if PayPal is unreachable, this rail never charges the token again.
  d.vaults.put({ ...v, status: "revoked", updated_at: stamp(d) });
  if (!v.vault_id) return { ok: true, agent, status: "revoked", detail: "no payment token had been created" };
  await d.paypal.authenticate();
  const del = await d.paypal.request("DELETE", `/v3/vault/payment-tokens/${v.vault_id}`);
  const after = await d.paypal.request("GET", `/v3/vault/payment-tokens/${v.vault_id}`);
  d.log?.(`vault ${agent}: revoked, DELETE ${del.status}, GET after ${after.status}`);
  if (after.status !== 404) {
    return { ok: false, agent, error_code: "VAULT_DELETE_UNCONFIRMED", detail: `DELETE answered ${del.status}, GET answered ${after.status}, not 404; delete the token in the sandbox by hand` };
  }
  return { ok: true, agent, status: "revoked", token_http_after: after.status };
}

/** A captured charge's capture id, if the order (or its capture call) completed. */
function completedCapture(body: any): string | undefined {
  if (body?.status !== "COMPLETED") return undefined;
  const c = body?.purchase_units?.[0]?.payments?.captures?.[0];
  return c?.status === "COMPLETED" && typeof c.id === "string" && PAYPAL_ID.test(c.id) ? c.id : undefined;
}

/**
 * `pay_paypal_checkout`'s backend. Checks as PP3 (canonical fields, once per request_id, signature,
 * the contract's signed shape 5 reservation, payee allowlisted and not suspended), then the vault
 * must be active; then the charge and the payout. Never retried: a claimed request stays claimed.
 */
export async function chargeCheckout(d: VaultDeps, order: CheckoutOrder): Promise<CheckoutResult> {
  const now = d.now ?? (() => Math.floor(Date.now() / 1000));
  const vault0 = d.vaults.get(typeof order?.agent === "string" ? order.agent : "");
  const secrets = vaultSecrets(d, vault0);
  const log = (line: string) => d.log?.(scrub(maskEmails(line), secrets));
  const request_id = typeof order?.request_id === "string" ? order.request_id : "";
  const blocked = (error_code: string, detail: string): PayoutResult => {
    log(`blocked checkout ${AGENT_ID.test(request_id) ? request_id : "<invalid request_id>"}: ${error_code}`);
    return { status: "blocked", request_id, error_code, detail: maskEmails(detail) };
  };

  const { agent, payee, amount, order_ref, timestamp, signature } = order ?? ({} as CheckoutOrder);
  if (typeof agent !== "string" || !AGENT_ID.test(agent)) return blocked("PP3_INVALID_INPUT", "agent must be 1-64 chars of [A-Za-z0-9._:-]") as CheckoutResult;
  if (!AGENT_ID.test(request_id)) return blocked("PP3_INVALID_INPUT", "request_id must be 1-64 chars of [A-Za-z0-9._:-]") as CheckoutResult;
  const venmo = typeof payee === "string" && isCanonicalVenmo(payee);
  if (typeof payee !== "string" || !(venmo || isCanonicalEmail(payee))) {
    return blocked("PP3_INVALID_INPUT", "payee must be a lowercase PayPal email or @ Venmo handle as the contract signs it") as CheckoutResult;
  }
  if (typeof amount !== "string" || !isCanonicalAmount(amount)) return blocked("PP3_INVALID_INPUT", "amount must be canonical USD with exactly 2 decimals, above zero") as CheckoutResult;
  if (typeof order_ref !== "string" || !AGENT_ID.test(order_ref)) return blocked("PP3_INVALID_INPUT", "order_ref must be 1-64 chars of [A-Za-z0-9._:-]") as CheckoutResult;
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) return blocked("PP3_INVALID_INPUT", "timestamp must be unix seconds") as CheckoutResult;
  if (!signature || typeof signature !== "object") return blocked("PP3_INVALID_INPUT", "signature {r, s, v} is required") as CheckoutResult;

  const seen = d.store.get(agent, request_id);
  if (seen) return blocked("PP3_DUPLICATE_REQUEST", `request ${request_id} was already handed to PP3 (${seen.state}); not charged again`) as CheckoutResult;

  const text = checkoutMessage(amount, payee, order_ref, timestamp, request_id);
  const checked = await checkSignedOrder(d, { agent, request_id, payee, text, signature, shape: "paypal_checkout" }, blocked);
  if ("result" in checked) {
    // Second kill switch: the owner revoked the agent on the contract, so the vault token goes too.
    if ((checked.result as any).error_code === "PP3_AGENT_REVOKED" && d.vaults.get(agent)?.status === "active") {
      await revokeVault(d, agent).catch((e) => log(`vault ${agent}: revoke after contract revoke failed (${scrub(String(e?.message ?? e), secrets).slice(0, 200)})`));
    }
    return checked.result as CheckoutResult;
  }
  const res = checked.res;

  const vault = d.vaults.get(agent);
  if (!vault || vault.status !== "active" || !vault.vault_id) {
    return blocked("VAULT_NOT_ACTIVE", `no active PayPal connection for ${agent}; the owner connects one on the dashboard`) as CheckoutResult;
  }

  try {
    await d.paypal.authenticate();
  } catch (e: any) {
    log(`failed checkout ${request_id}: PP3_AUTH_FAILED`);
    return { status: "failed", request_id, error_code: "PP3_AUTH_FAILED", detail: `${scrub(String(e?.message ?? e), secrets).slice(0, 300)}; nothing was charged, retry later with the same order` };
  }
  // Two POSTs of up to 30 s each must fit before valid_before.
  if (now() + 2 * SUBMIT_MARGIN_SECS > res.valid_before) {
    return blocked("PP3_ORDER_EXPIRED", `request ${request_id} expires at ${res.valid_before}, too close to charge`) as CheckoutResult;
  }
  const base: OrderRecord = { agent, request_id, state: "submitting", payee_masked: maskEmail(payee), amount, at: new Date(now() * 1000).toISOString() };
  if (!d.store.claim(base)) return blocked("PP3_DUPLICATE_REQUEST", `request ${request_id} is already being charged; not charged again`) as CheckoutResult;
  let extra: Partial<OrderRecord> = {};
  const finish = (r: Partial<OrderRecord>) => {
    extra = { ...extra, ...r };
    try {
      d.store.update({ ...base, ...extra });
    } catch (e: any) {
      log(`record-failed checkout ${request_id}: outcome ${extra.state}; the store update failed (${scrub(String(e?.message ?? e), secrets).slice(0, 200)})`);
    }
  };

  // 1. Pull the amount from the owner's wallet into the rail's merchant account.
  log(`charging ${request_id}: USD ${amount} from the vault for ${maskEmail(payee)} order ${order_ref}`);
  const orderBody = {
    intent: "CAPTURE",
    purchase_units: [
      {
        reference_id: order_ref,
        custom_id: request_id,
        description: `nearh agent ${agent} order ${order_ref}`.slice(0, 127),
        amount: { currency_code: "USD", value: amount },
      },
    ],
    payment_source: {
      paypal: { vault_id: vault.vault_id, stored_credential: { payment_initiator: "MERCHANT", usage: "SUBSEQUENT", usage_pattern: "IMMEDIATE" } },
    },
  };
  let o;
  try {
    o = await d.paypal.request("POST", "/v2/checkout/orders", orderBody, { "PayPal-Request-Id": checkoutRequestId(agent, request_id), Prefer: "return=representation" });
  } catch (e: any) {
    const detail = `PayPal did not answer the charge (${scrub(String(e?.message ?? e), secrets).slice(0, 200)}); check the sandbox orders before anything else`;
    finish({ state: "unknown", detail });
    return { status: "pending", request_id, error_code: "PAYPAL_OUTCOME_UNKNOWN", detail };
  }
  const orderId = typeof o.body?.id === "string" && PAYPAL_ID.test(o.body.id) ? o.body.id : undefined;
  let captureId = o.ok ? completedCapture(o.body) : undefined;
  if (o.ok && orderId && !captureId && o.body?.status !== "COMPLETED") {
    try {
      const c = await d.paypal.request("POST", `/v2/checkout/orders/${orderId}/capture`, {}, { "PayPal-Request-Id": `${checkoutRequestId(agent, request_id)}-c` });
      captureId = c.ok ? completedCapture(c.body) : undefined;
    } catch {
      // Falls through to an unknown outcome below.
    }
  }
  if (!captureId) {
    const name = typeof o.body?.name === "string" ? `, ${scrub(o.body.name, secrets).slice(0, 80)}` : "";
    const issue = typeof o.body?.details?.[0]?.issue === "string" ? `, ${scrub(o.body.details[0].issue, secrets).slice(0, 80)}` : "";
    const detail = `PayPal did not complete the charge (HTTP ${o.status}${name}${issue})`;
    const unknown = o.status >= 500 || (o.ok && !!orderId);
    finish({ state: unknown ? "unknown" : "refused", http_status: o.status, detail });
    return unknown
      ? { status: "pending", request_id, error_code: "PAYPAL_OUTCOME_UNKNOWN", detail: `${detail}; check the sandbox order before anything else`, ...(orderId ? { paypal_order_id: orderId } : {}) }
      : { status: "failed", request_id, error_code: "PAYPAL_CHARGE_REFUSED", detail };
  }
  log(`charged ${request_id}: order ${orderId} capture ${captureId}`);
  finish({ detail: `captured ${captureId} on order ${orderId}` });

  // 2. Pay the merchant the contract signed. The charge is captured, so a 429 does not release the claim.
  const paid = await sendPayout(d, { agent, request_id, payee, amount, timestamp, venmo }, { ...base, ...extra }, finish, log, false);
  if (paid.status === "submitted") {
    return { status: "submitted", request_id, paypal_order_id: orderId!, capture_id: captureId, payout_batch_id: paid.payout_batch_id, batch_status: paid.batch_status };
  }
  return {
    status: paid.status === "blocked" ? "failed" : paid.status,
    request_id,
    error_code: paid.error_code,
    detail: `${paid.detail}; the charge ${captureId} is captured in the rail account, pay the merchant or refund the owner by hand`,
    paypal_order_id: orderId,
    capture_id: captureId,
  };
}
