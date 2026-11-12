// PP3 live check against the PayPal sandbox: one real payout through submitPaypalPayout, then
// the same request_id again (must be refused locally), then a poll of the batch to a final state.
// No shape 4 contract is deployed yet, so NEAR is an in-memory stub and a throwaway local key
// stands in for the MPC-derived agent EOA. Everything after the NEAR reads is the real path:
// the sandbox client, the claim, the POST and PayPal's answer.
// Run: node scripts/live-sandbox.ts   (reads PAYPAL_ENV_FILE or ~/.config/nearh/paypal-sandbox.env)
// Prints only masked output: no credentials, token or full receiver email.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { publicKeyToAddress } from "@nearh/owner-near/src/derive.ts";
import { credentialsFile, readCredentials } from "../src/config.ts";
import { sandboxClient } from "../src/paypal.ts";
import { eip191Digest, maskEmails, paypalMessage, submitPaypalPayout, type Deps } from "../src/payout.ts";
import { fileStore } from "../src/store.ts";

const creds = readCredentials(credentialsFile());
const receiver = (creds.PAYPAL_SANDBOX_RECEIVER_EMAIL ?? "").trim().toLowerCase();
if (!receiver) throw new Error("PAYPAL_SANDBOX_RECEIVER_EMAIL missing in the credentials file");

const agent = "agent-live";
const key = secp256k1.utils.randomSecretKey();
const evm = publicKeyToAddress(secp256k1.getPublicKey(key, false));
const now = Math.floor(Date.now() / 1000);
const request_id = `pp3-live-${now}`;
const amount = "1.00";
const text = paypalMessage(amount, receiver, now, request_id);
const digest = eip191Digest(text);
const raw = secp256k1.sign(digest, key, { prehash: false, format: "recovered" });
const signature = { r: `0x${bytesToHex(raw.slice(1, 33))}`, s: `0x${bytesToHex(raw.slice(33))}`, v: 27 + raw[0] };

const paypal = sandboxClient(creds);
const out = (label: string, v: unknown) => console.log(maskEmails(`${label} ${JSON.stringify(v)}`));
const d: Deps = {
  near: {
    getAgent: async () => ({ evm_address: evm, revoked: false }),
    getRequest: async () => ({
      key: { agent, caller: { kind: "agent" }, request_id },
      shape: "paypal",
      rail: "paypal",
      valid_before: now + 240,
      digest: `0x${bytesToHex(digest)}`,
      payload: { kind: "message", text },
      status: "signed",
      signature,
    }),
    getPayees: async () => [{ rail: "paypal", receiver }],
    getSuspendedPayees: async () => [],
  },
  paypal,
  // PP3_STORE_DIR lets the PP-W1 webhook receiver read the record (RESULT.md there).
  store: fileStore(process.env.PP3_STORE_DIR || mkdtempSync(join(tmpdir(), "pp3-live-"))),
  secrets: [creds.PAYPAL_CLIENT_ID, creds.PAYPAL_CLIENT_SECRET].filter((v): v is string => !!v),
  log: (l) => console.log(`log ${l}`),
};

const order = { agent, request_id, payee: receiver, amount, timestamp: now, signature };
out("message", text);
const first = await submitPaypalPayout(d, order);
out("submit", first);
out("resubmit", await submitPaypalPayout(d, order));
if (first.status !== "submitted") process.exit(1);

const FINAL_BATCH = new Set(["SUCCESS", "DENIED", "CANCELED"]);
const FINAL_ITEM = new Set(["SUCCESS", "FAILED", "RETURNED", "UNCLAIMED", "BLOCKED", "REFUNDED", "REVERSED", "DENIED"]);
for (let i = 0; i < 24; i++) {
  await new Promise((r) => setTimeout(r, 5000));
  const g = await paypal.request("GET", `/v1/payments/payouts/${first.payout_batch_id}`);
  const batch = g.body?.batch_header?.batch_status;
  const item = g.body?.items?.[0]?.transaction_status;
  out("poll", { http: g.status, batch, item, debug_id: g.debugId });
  if (FINAL_BATCH.has(batch) && FINAL_ITEM.has(item)) {
    const it = g.body.items[0];
    out("final", { payout_batch_id: first.payout_batch_id, sender_batch_id: g.body.batch_header.sender_batch_header?.sender_batch_id, batch, item, payout_item_id: it.payout_item_id, transaction_id: it.transaction_id, fee: it.payout_item_fee, amount: it.payout_item?.amount });
    break;
  }
}
