// PP-V0 step 5 without the vault: does Orders v2 accept purchase_units[].payee naming another sandbox account
// on a plain (non-partner) REST app, with no PayPal-Auth-Assertion? Creates orders only; nothing is captured.
//   node spikes/paypal-vault/payee-probe.mjs [setup_token_id]
// Optional setup_token_id: also GETs that setup token to record its status before the owner approves it.
import { call, login, evidence, env } from "./common.mjs";

const record = evidence("evidence-payee.json");
const amount = { currency_code: "USD", value: "1.00" };
const payee = process.env.PAYEE_EMAIL ?? env.PAYPAL_SANDBOX_RECEIVER_EMAIL;
if (!payee) {
  console.error("missing PAYEE_EMAIL / PAYPAL_SANDBOX_RECEIVER_EMAIL");
  process.exit(2);
}

record("0:oauth", await login());

const order = async (label, unit) => {
  const body = { intent: "CAPTURE", purchase_units: [{ amount, ...unit }] };
  const o = await call("POST", "/v2/checkout/orders", { body });
  record(`${label}:create`, { status: o.status, debugId: o.debugId, request: body, response: o.json });
  if (o.status !== 201) return o;
  const g = await call("GET", `/v2/checkout/orders/${o.json.id}`);
  record(`${label}:get`, { status: g.status, debugId: g.debugId, payee: g.json?.purchase_units?.[0]?.payee, order_status: g.json?.status });
  return o;
};

// A. control: no payee (funds would go to the app's own merchant)
await order("A-no-payee", { reference_id: "probe-self" });
// B. payee = other sandbox account by email
const b = await order("B-payee-email", { reference_id: "probe-payee", payee: { email_address: payee } });
// C. payee = email that is not a PayPal account: is the payee checked at create or only at approve/capture?
await order("C-payee-unknown", { reference_id: "probe-unknown", payee: { email_address: `nearh-nobody-${Date.now()}@example.com` } });
// D. capture B without buyer approval: what blocks a payee charge without a buyer
if (b.status === 201) {
  const c = await call("POST", `/v2/checkout/orders/${b.json.id}/capture`, { body: {} });
  record("D-capture-unapproved", { status: c.status, debugId: c.debugId, response: c.json });
}

const setupId = process.argv[2];
if (setupId) {
  const st = await call("GET", `/v3/vault/setup-tokens/${setupId}`);
  record("E-setup-token-before-approval", { status: st.status, debugId: st.debugId, response: st.json });
}
