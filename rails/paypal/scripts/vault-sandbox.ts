// PP-V1 live run against the PayPal sandbox, in two steps around the owner's approval click.
//   node scripts/vault-sandbox.ts connect   creates a setup token; writes the approve link to .vault/APPROVE.md
//   (owner: open the link, log in as the sandbox personal buyer, approve)
//   node scripts/vault-sandbox.ts run       payment token -> $25 charge + payout -> swapped merchant -> revoke -> GET 404
// No shape 5 contract is deployed yet, so NEAR is an in-memory stub and a throwaway local key stands in
// for the MPC-derived agent EOA; everything else is the real rail path. Reads PAYPAL_ENV_FILE or
// ~/.config/nearh/paypal-sandbox.env. Prints and saves ids only: no credentials, token, vault_id or full email.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { publicKeyToAddress } from "@nearh/owner-near/src/derive.ts";
import { credentialsFile, readCredentials } from "../src/config.ts";
import { sandboxClient } from "../src/paypal.ts";
import { eip191Digest, maskEmails } from "../src/payout.ts";
import { memoryStore } from "../src/store.ts";
import { chargeCheckout, checkoutMessage, confirmVault, connectVault, fileVaultStore, revokeVault, vaultStatus, type VaultDeps } from "../src/vault.ts";

const DIR = fileURLToPath(new URL("..", import.meta.url));
const VAULT_DIR = process.env.PP_VAULT_DIR || join(DIR, ".vault");
const creds = readCredentials(credentialsFile());
const merchant = (creds.PAYPAL_SANDBOX_RECEIVER_EMAIL ?? "").trim().toLowerCase();
if (!merchant) throw new Error("PAYPAL_SANDBOX_RECEIVER_EMAIL missing in the credentials file");
const agent = "agent-vault-live";
const key = secp256k1.utils.randomSecretKey();
const evm = publicKeyToAddress(secp256k1.getPublicKey(key, false));
const sign = (t: string) => {
  const raw = secp256k1.sign(eip191Digest(t), key, { prehash: false, format: "recovered" });
  return { r: `0x${bytesToHex(raw.slice(1, 33))}`, s: `0x${bytesToHex(raw.slice(33))}`, v: 27 + raw[0] };
};
const signed = new Map<string, string>();
const d: VaultDeps = {
  near: {
    getAgent: async () => ({ evm_address: evm, revoked: false }),
    getRequest: async (k) => {
      const t = signed.get(k.request_id);
      if (!t) return null;
      return { key: k, shape: "paypal_checkout", rail: "paypal", valid_before: Math.floor(Date.now() / 1000) + 240, digest: `0x${bytesToHex(eip191Digest(t))}`, payload: { kind: "message", text: t }, status: "signed", signature: sign(t) };
    },
    getPayees: async () => [{ rail: "paypal", receiver: merchant }],
    getSuspendedPayees: async () => [],
  },
  paypal: sandboxClient(creds),
  store: memoryStore(),
  vaults: fileVaultStore(VAULT_DIR),
  secrets: [creds.PAYPAL_CLIENT_ID, creds.PAYPAL_CLIENT_SECRET].filter((v): v is string => !!v),
  log: (l) => console.log(`log ${l}`),
};
const out = (label: string, v: unknown) => console.log(maskEmails(`${label} ${JSON.stringify(v)}`));

if (process.argv[2] === "connect") {
  const c = await connectVault(d, agent);
  if (!c.ok) {
    out("connect", c);
    process.exit(1);
  }
  mkdirSync(VAULT_DIR, { recursive: true, mode: 0o700 });
  writeFileSync(join(VAULT_DIR, "APPROVE.md"), `# PP-V1 owner step (sandbox, not committed)\n\nOpen and approve as the sandbox personal buyer:\n\n${c.approve_url}\n\nThen: node rails/paypal/scripts/vault-sandbox.ts run\n`, { mode: 0o600 });
  out("connect", { status: c.status, approve_link_file: ".vault/APPROVE.md" });
} else if (process.argv[2] === "run") {
  const evidence: Record<string, unknown> = { ranAt: new Date().toISOString(), agent, base: "https://api-m.sandbox.paypal.com" };
  if (vaultStatus(d, agent).status !== "active") {
    const f = await confirmVault(d, agent);
    out("confirm", f);
    evidence.confirm = f;
    if (!f.ok) process.exit(1);
  }
  const now = Math.floor(Date.now() / 1000);
  const id = `pv1-live-${now}`;
  const t = checkoutMessage("25.00", merchant, "ORD-PV1-25", now, id);
  signed.set(id, t);
  const charge = await chargeCheckout(d, { agent, request_id: id, payee: merchant, amount: "25.00", order_ref: "ORD-PV1-25", timestamp: now, signature: sign(t) });
  out("charge", charge);
  evidence.charge = { message: maskEmails(t), result: charge };
  // A poisoned invoice swaps the merchant: the contract signed only the real one, so the rail refuses.
  const swapped = await chargeCheckout(d, { agent, request_id: id + "-swap", payee: "attacker@example.com", amount: "25.00", order_ref: "ORD-PV1-25", timestamp: now, signature: sign(t) });
  out("swapped", swapped);
  evidence.swapped_merchant = swapped;
  const r = await revokeVault(d, agent);
  out("revoke", r);
  evidence.revoke = r;
  const after = await chargeCheckout(d, { agent, request_id: id + "-after", payee: merchant, amount: "1.00", order_ref: "ORD-PV1-1", timestamp: now, signature: sign(checkoutMessage("1.00", merchant, "ORD-PV1-1", now, id + "-after")) });
  out("after-revoke", after);
  evidence.charge_after_revoke = after;
  writeFileSync(join(DIR, "evidence-vault.json"), maskEmails(JSON.stringify(evidence, null, 1)) + "\n");
  out("evidence", "rails/paypal/evidence-vault.json");
} else {
  console.error("usage: node scripts/vault-sandbox.ts connect|run");
  process.exit(2);
}
