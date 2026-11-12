// PP-T1: seeds refundable sandbox captures for the refund demo. Each order is paid with a PayPal
// sandbox test card (`payment_source.card`), which the sandbox captures at once, so no buyer has to
// approve in a browser. Sandbox only (the client's base URL is fixed to it).
//
//   node scripts/seed-captures.ts "12.00:Ceramic mug" "18.00:Tea set" ...  > orders.json
//
// Prints [{ order_id, capture_id, amount, description }]. Nothing secret is printed.
import { randomUUID } from "node:crypto";
import { credentialsFile, readCredentials } from "../src/config.ts";
import { sandboxClient } from "../src/paypal.ts";
import { isCanonicalAmount } from "../src/payout.ts";

/** A Visa test card from PayPal's sandbox card generator; it moves no real money. */
const SANDBOX_CARD = { number: "4032039317984658", expiry: "2030-12", security_code: "123", name: "Sandbox Buyer" };

const items = process.argv.slice(2).map((a) => {
  const [amount, ...rest] = a.split(":");
  if (!isCanonicalAmount(amount)) throw new Error(`amount must be canonical USD: ${amount}`);
  return { amount, description: rest.join(":").slice(0, 120) || "Demo order" };
});
if (items.length === 0) throw new Error('usage: seed-captures.ts "12.00:Ceramic mug" ...');

const paypal = sandboxClient(readCredentials(credentialsFile()));
await paypal.authenticate();
const out = [];
for (const { amount, description } of items) {
  const a = await paypal.request(
    "POST",
    "/v2/checkout/orders",
    { intent: "CAPTURE", purchase_units: [{ amount: { currency_code: "USD", value: amount }, description }], payment_source: { card: SANDBOX_CARD } },
    { "PayPal-Request-Id": `pt1-seed-${randomUUID()}` },
  );
  const capture = a.body?.purchase_units?.[0]?.payments?.captures?.[0];
  if (!a.ok || a.body?.status !== "COMPLETED" || capture?.status !== "COMPLETED") {
    throw new Error(`order for ${amount} not captured: HTTP ${a.status} ${String(a.body?.status ?? a.body?.name ?? "")}`);
  }
  out.push({ order_id: a.body.id, capture_id: capture.id, amount, description });
}
console.log(JSON.stringify(out, null, 2));
