// PP-V0 steps 3-6, run AFTER the owner approved the setup token (see APPROVE.md).
//   node spikes/paypal-vault/resume.mjs <setup_token_id>                 # steps 3..6
//   node spikes/paypal-vault/resume.mjs --payment-token <vault_id>       # re-run 4..6 with an existing token
// Optional: PAYEE_EMAIL=<sandbox business email> for step 5 (default PAYPAL_SANDBOX_RECEIVER_EMAIL from the env file).
// The step-5 payee must not be the buyer who approved (PayPal refuses paying yourself).
// Each charge is 1.00 USD in the sandbox. Step 6 deletes the token; pass --keep to skip it.
import { call, login, evidence, env } from "./common.mjs";

const args = process.argv.slice(2);
const keep = args.includes("--keep");
const pi = args.indexOf("--payment-token");
let vaultId = pi >= 0 ? args[pi + 1] : undefined;
const setupId = vaultId ? undefined : args.find((a) => !a.startsWith("--"));
if (!vaultId && !setupId) {
  console.error("usage: resume.mjs <setup_token_id> | --payment-token <vault_id> [--keep]");
  process.exit(2);
}
const payee = process.env.PAYEE_EMAIL ?? env.PAYPAL_SANDBOX_RECEIVER_EMAIL;
const record = evidence("evidence-resume.json");
const amount = { currency_code: "USD", value: "1.00" };
// Agent-initiated charge with the buyer absent = merchant-initiated stored credential.
const mit = { payment_initiator: "MERCHANT", usage: "SUBSEQUENT", usage_pattern: "IMMEDIATE" };

record("0:oauth", await login());

// 3. setup token -> payment token (vault_id)
if (setupId) {
  const st = await call("GET", `/v3/vault/setup-tokens/${setupId}`);
  record("3a:get-setup-token", { status: st.status, debugId: st.debugId, response: st.json });
  if (st.json?.status !== "APPROVED") console.error(`warning: setup token status is ${st.json?.status}, expected APPROVED`);
  const pt = await call("POST", "/v3/vault/payment-tokens", {
    body: { payment_source: { token: { id: setupId, type: "SETUP_TOKEN" } } },
    requestId: `pp-v0-pt-${setupId}`,
  });
  record("3b:create-payment-token", { status: pt.status, debugId: pt.debugId, response: pt.json });
  if (pt.status !== 200 && pt.status !== 201) process.exit(1);
  vaultId = pt.json.id;
}
const got = await call("GET", `/v3/vault/payment-tokens/${vaultId}`);
record("3c:get-payment-token", { status: got.status, debugId: got.debugId, response: got.json });
const buyer = got.json?.payment_source?.paypal?.email_address;
if (buyer && payee && buyer.toLowerCase() === payee.toLowerCase()) {
  console.error("warning: step-5 payee is the buyer; set PAYEE_EMAIL to a different sandbox account");
}

// Create an order on the vaulted token; capture only if PayPal did not already complete it.
async function charge(label, unit) {
  const body = { intent: "CAPTURE", purchase_units: [{ amount, ...unit }], payment_source: { paypal: { vault_id: vaultId, stored_credential: mit } } };
  const o = await call("POST", "/v2/checkout/orders", { body });
  record(`${label}:create-order`, { status: o.status, debugId: o.debugId, request: body, response: o.json });
  if (o.status >= 300 || o.json.status === "COMPLETED") return o;
  const c = await call("POST", `/v2/checkout/orders/${o.json.id}/capture`, { body: {} });
  record(`${label}:capture`, { status: c.status, debugId: c.debugId, response: c.json });
  return c;
}

// 4. merchant-initiated charge to the app's own merchant account, no buyer interaction
await charge("4", { reference_id: "pp-v0-self", description: "PP-V0 vaulted charge, own merchant" });

// 5. same token, third-party payee
if (payee) await charge("5", { reference_id: "pp-v0-payee", description: "PP-V0 vaulted charge, third-party payee", payee: { email_address: payee } });
else record("5:skipped", { reason: "no PAYEE_EMAIL / PAYPAL_SANDBOX_RECEIVER_EMAIL" });

// 6. delete token, then GET must be 404
if (!keep) {
  const d = await call("DELETE", `/v3/vault/payment-tokens/${vaultId}`);
  record("6a:delete-payment-token", { status: d.status, debugId: d.debugId, response: d.json });
  const g = await call("GET", `/v3/vault/payment-tokens/${vaultId}`);
  record("6b:get-after-delete", { status: g.status, debugId: g.debugId, response: g.json });
  const o = await call("POST", "/v2/checkout/orders", {
    body: { intent: "CAPTURE", purchase_units: [{ amount }], payment_source: { paypal: { vault_id: vaultId } } },
  });
  record("6c:charge-after-delete", { status: o.status, debugId: o.debugId, response: o.json });
}
