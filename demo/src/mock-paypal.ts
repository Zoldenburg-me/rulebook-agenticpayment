// --mock only: a fake PayPal sandbox behind a `fetch`. It answers the calls the demo supplier
// (Invoicing v2) and the PayPal rail make: Payouts v1; for the judge page's replay also a vaulted
// wallet charge (Orders v2 with a vault_id, Vault v3 delete) and refunds (Payments v2). Response
// shapes as recorded in supplier/RESULT.md, spikes/paypal/RESULT.md, spikes/paypal-vault/RESULT.md
// and demo/evidence/pt1-refunds.md. Nothing leaves the process.

import { randomBytes } from "node:crypto";

export type MockPaypal = {
  fetch: typeof fetch;
  calls: string[];
  payouts: any[];
  /** A vault payment token the owner saved (Vault v3), chargeable until deleted. */
  seedVaultToken: (vaultId: string) => void;
  /** A completed capture of `orderId` for USD `value`, refundable. */
  seedCapture: (captureId: string, orderId: string, value: string) => void;
};

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "paypal-debug-id": "f00dmock0001" } });
const upper = (n: number) => randomBytes(n).toString("hex").toUpperCase().slice(0, n);

export function mockPaypal(): MockPaypal {
  const calls: string[] = [];
  const payouts: any[] = [];
  const invoices = new Map<string, any>();
  const batches = new Set<string>();
  const vaultTokens = new Set<string>();
  const captures = new Map<string, { orderId: string; value: string; refunds: { id: string; value: string }[] }>();
  const cents = (v: string) => BigInt(v.replace(".", ""));
  const usd = (c: bigint) => `${c / 100n}.${String(c % 100n).padStart(2, "0")}`;

  const fake = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input));
    const method = init.method ?? "GET";
    const path = url.pathname;
    calls.push(`${method} ${path}`);
    if (url.origin !== "https://api-m.sandbox.paypal.com") return json(404, { name: "NOT_SANDBOX" });
    const body = typeof init.body === "string" && init.body.startsWith("{") ? JSON.parse(init.body) : undefined;

    if (method === "POST" && path === "/v1/oauth2/token") {
      return json(200, { access_token: `MOCK-${upper(24)}`, token_type: "Bearer", expires_in: 32400 });
    }
    if (method === "POST" && path === "/v2/invoicing/invoices") {
      const id = `INV2-${upper(4)}-${upper(4)}-${upper(4)}-${upper(4)}`;
      invoices.set(id, {
        id,
        status: "DRAFT",
        detail: { ...body.detail, metadata: { recipient_view_url: `https://www.sandbox.paypal.com/invoice/p/#${id.replace(/^INV2-|-/g, "")}` } },
        invoicer: body.invoicer,
        primary_recipients: body.primary_recipients,
        items: body.items,
        amount: { currency_code: "USD", value: body.items[0].unit_amount.value },
      });
      return json(201, invoices.get(id));
    }
    const send = /^\/v2\/invoicing\/invoices\/(INV2[-A-Z0-9]+)\/send$/.exec(path);
    if (method === "POST" && send && invoices.has(send[1])) {
      invoices.get(send[1]).status = "SENT";
      return json(200, { href: `https://www.sandbox.paypal.com/invoice/p/#${send[1]}` });
    }
    const get = /^\/v2\/invoicing\/invoices\/(INV2[-A-Z0-9]+)$/.exec(path);
    if (method === "GET" && get && invoices.has(get[1])) return json(200, invoices.get(get[1]));
    if (method === "POST" && path === "/v1/payments/payouts") {
      const sbid = body.sender_batch_header.sender_batch_id;
      if (batches.has(sbid)) return json(400, { name: "USER_BUSINESS_ERROR", details: [{ field: "SENDER_BATCH_ID", issue: "Batch with given sender_batch_id already exists" }] });
      batches.add(sbid);
      payouts.push(body);
      const payout_batch_id = upper(13);
      return json(201, {
        batch_header: { payout_batch_id, batch_status: "PENDING", sender_batch_header: body.sender_batch_header },
        links: [{ href: `https://api.sandbox.paypal.com/v1/payments/payouts/${payout_batch_id}`, rel: "self", method: "GET" }],
      });
    }
    if (method === "POST" && path === "/v2/checkout/orders") {
      const vaultId = body?.payment_source?.paypal?.vault_id;
      if (!vaultTokens.has(vaultId)) return json(422, { name: "UNPROCESSABLE_ENTITY", details: [{ issue: "PAYMENT_SOURCE_INFO_CANNOT_BE_VERIFIED" }] });
      const id = upper(17);
      const capture_id = upper(17);
      captures.set(capture_id, { orderId: id, value: body.purchase_units[0].amount.value, refunds: [] });
      return json(201, { id, status: "COMPLETED", purchase_units: [{ payments: { captures: [{ id: capture_id, status: "COMPLETED", amount: body.purchase_units[0].amount }] } }] });
    }
    const token = /^\/v3\/vault\/payment-tokens\/([A-Za-z0-9-]+)$/.exec(path);
    if (token && method === "DELETE") {
      vaultTokens.delete(token[1]);
      return new Response(null, { status: 204 });
    }
    if (token && method === "GET") return vaultTokens.has(token[1]) ? json(200, { id: token[1] }) : json(404, { name: "RESOURCE_NOT_FOUND" });
    const capture = /^\/v2\/payments\/captures\/([A-Z0-9]+)$/.exec(path);
    if (capture && method === "GET") {
      const c = captures.get(capture[1]);
      if (!c) return json(404, { name: "RESOURCE_NOT_FOUND" });
      const refunded = c.refunds.reduce((a, r) => a + cents(r.value), 0n);
      const status = refunded === 0n ? "COMPLETED" : refunded >= cents(c.value) ? "REFUNDED" : "PARTIALLY_REFUNDED";
      return json(200, { id: capture[1], status, amount: { currency_code: "USD", value: c.value }, supplementary_data: { related_ids: { order_id: c.orderId } } });
    }
    const order = /^\/v2\/checkout\/orders\/([A-Z0-9]+)$/.exec(path);
    if (order && method === "GET") {
      const own = [...captures].filter(([, c]) => c.orderId === order[1]);
      if (own.length === 0) return json(404, { name: "RESOURCE_NOT_FOUND" });
      const up = (id: string) => [{ rel: "up", method: "GET", href: `https://api.sandbox.paypal.com/v2/payments/captures/${id}` }];
      return json(200, {
        id: order[1],
        status: "COMPLETED",
        purchase_units: [{
          payments: {
            captures: own.map(([id, c]) => ({ id, status: "COMPLETED", amount: { currency_code: "USD", value: c.value } })),
            refunds: own.flatMap(([id, c]) => c.refunds.map((r) => ({ id: r.id, status: "COMPLETED", amount: { currency_code: "USD", value: r.value }, links: up(id) }))),
          },
        }],
      });
    }
    const refund = /^\/v2\/payments\/captures\/([A-Z0-9]+)\/refund$/.exec(path);
    if (refund && method === "POST") {
      const c = captures.get(refund[1]);
      if (!c) return json(404, { name: "RESOURCE_NOT_FOUND" });
      const value = body.amount.value;
      const left = cents(c.value) - c.refunds.reduce((a, r) => a + cents(r.value), 0n);
      if (cents(value) > left) return json(422, { name: "UNPROCESSABLE_ENTITY", details: [{ issue: "REFUND_AMOUNT_EXCEEDED" }] });
      const id = upper(17);
      c.refunds.push({ id, value });
      return json(201, { id, status: "COMPLETED", amount: { currency_code: "USD", value: usd(cents(value)) } });
    }
    return json(404, { name: "RESOURCE_NOT_FOUND" });
  }) as typeof fetch;

  return {
    fetch: fake,
    calls,
    payouts,
    seedVaultToken: (vaultId) => void vaultTokens.add(vaultId),
    seedCapture: (captureId, orderId, value) => void captures.set(captureId, { orderId, value, refunds: [] }),
  };
}
