// PP-V0 step 1: create a Vault v3 setup token (PayPal wallet, usage_type MERCHANT) and write the approve link
// to APPROVE.md (gitignored). Run: node spikes/paypal-vault/setup-token.mjs
// Then the OWNER opens the link and logs in as the sandbox personal buyer. Agents never do that step.
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { DIR, call, login, evidence, linkOf } from "./common.mjs";

const record = evidence("evidence-setup.json");
const RETURN = "https://example.com/nearh-vault/return";
const CANCEL = "https://example.com/nearh-vault/cancel";

record("0:oauth", await login());

const body = {
  payment_source: {
    paypal: {
      description: "nearh agent spending account (sandbox spike)",
      usage_pattern: "IMMEDIATE",
      usage_type: "MERCHANT",
      customer_type: "CONSUMER",
      permit_multiple_payment_tokens: true,
      experience_context: {
        brand_name: "nearh sandbox",
        shipping_preference: "NO_SHIPPING",
        return_url: RETURN,
        cancel_url: CANCEL,
      },
    },
  },
};
const r = await call("POST", "/v3/vault/setup-tokens", { body });
record("1:setup-token", { status: r.status, debugId: r.debugId, request: body, response: r.json });
if (r.status !== 200 && r.status !== 201) {
  console.error(`STOP: setup-token failed (${r.status} ${r.json?.name ?? ""}). If this is a permission error, Vault is not enabled on the app.`);
  process.exit(3);
}

const approve = linkOf(r.json, "approve");
writeFileSync(
  join(DIR, "APPROVE.md"),
  `# PP-V0 owner step (sandbox only, not committed)\n\n` +
    `1. Open this link in a browser and log in as the **sandbox personal buyer** (sb-…@personal.example.com):\n\n   ${approve}\n\n` +
    `2. Approve. PayPal redirects to ${RETURN}?approval_token_id=...; the page will not load, that is fine.\n` +
    `3. Step 5 pays a third-party payee: PAYEE_EMAIL (default PAYPAL_SANDBOX_RECEIVER_EMAIL) must NOT be the buyer you log in as.\n   If you approve with that same personal account, set PAYEE_EMAIL to another sandbox account (ideally a second business account).\n4. Run: \`[PAYEE_EMAIL=...] node spikes/paypal-vault/resume.mjs ${r.json.id}\`\n\n` +
    `Setup token id: ${r.json.id} (status at creation: ${r.json.status})\n`,
);
console.log(`setup token ${r.json.id} ${r.json.status}; approve link written to spikes/paypal-vault/APPROVE.md`);
