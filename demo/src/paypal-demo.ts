// `pnpm demo:paypal [--mock]`: the PayPal story end to end, narrated.
//   1. The owner's mandate on the contract allows one PayPal payee up to a cap.
//   2. The demo supplier issues a PayPal sandbox invoice (Invoicing v2).
//   3. The buyer agent reads it, runs the scam check and pays through `pay_paypal`: the contract
//      signs a payout order, and only the PayPal rail (rails/paypal) submits it to PayPal Payouts.
//   4. A poisoned invoice (lookalike payee) is held by the scam check, and the contract refuses it
//      even if the scam check is bypassed.
//   5. The dashboard's USD view (dashboard/, PP5a) reads both from the rail's records and the held queue.
// --mock replaces NEAR, Chain Signatures, PayPal and the scam-check model with in-process fakes
// (no credentials, no network). Payees are masked in every line; no credential is ever printed.

import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readPaypalStore } from "@nearh/dashboard/decisions";
import { assertTestnet, assertTestnetRpc, view, type Config } from "@nearh/owner-near/src/near.ts";
import { sandboxClient as railClient } from "@nearh/rails-paypal/src/paypal.ts";
import { maskEmail, maskEmails } from "@nearh/rails-paypal/src/payout.ts";
import { fileStore } from "@nearh/rails-paypal/src/store.ts";
import { credentialsFile, readCredentials } from "@nearh/supplier/src/cli.ts";
import { issueInvoice, type BuyerInvoice } from "@nearh/supplier/src/invoice.ts";
import { sandboxClient as supplierClient, type Client as SupplierClient } from "@nearh/supplier/src/paypal.ts";
import { MockMandateContract, usd, type MockMandate } from "./mock-contract.ts";
import { mockPaypal } from "./mock-paypal.ts";
import { heldPath } from "scamcheck";
import { livePayPaypal, mockPayPaypal, type PayPaypal, type PayPaypalResult } from "./pay-paypal.ts";

export type DemoSummary = {
  mode: "mock" | "live";
  paid: PayPaypalResult;
  poisoned: PayPaypalResult;
  /** The contract's answer to the poisoned order with the scam check bypassed (mock only). */
  contractOnPoisoned?: string;
  dashboard: { payouts: { request_id: string; state: string; amount: string; payee_masked: string; payout_batch_id?: string }[]; held: { request_id: string; payee: string; amount: string; reason: string | null }[] };
};

const AGENT = "agent-1";
/** Documentation-style payee (example domain) for --mock; live uses the sandbox personal account. */
const MOCK_PAYEE = "billing@acme-supplies.example";
const MANDATE: MockMandate = {
  paypal: { amount_range: { min: "100", max: "5000" }, budget: "10000", period_secs: 7 * 24 * 3600 },
  max_validity_secs: 300,
};

/** A lookalike of `email`: an `l` in the domain becomes a capital `I`, else an extra `.co` label. */
export function lookalike(email: string): string {
  const at = email.lastIndexOf("@");
  const domain = email.slice(at + 1);
  const swapped = domain.includes("l") ? domain.replace("l", "I") : `${domain}.co`;
  return `${email.slice(0, at)}@${swapped}`;
}

const dueIn = (days: number) => new Date(Date.now() + days * 86_400_000).toISOString().slice(0, 10);

type Ctx = {
  supplier: SupplierClient;
  pay: PayPaypal;
  payee: string;
  storeDir: string;
  heldFile: string;
  contract?: MockMandateContract;
};

async function setupMock(log: (s: string) => void, workDir: string): Promise<Ctx> {
  const paypal = mockPaypal();
  const fakeCreds = { PAYPAL_ENV: "sandbox", PAYPAL_CLIENT_ID: "mock-client-id", PAYPAL_CLIENT_SECRET: "mock-client-secret" };
  const now = () => Math.floor(Date.now() / 1000);
  const contract = new MockMandateContract(AGENT, now);
  const storeDir = join(workDir, "paypal-orders");
  const heldDir = join(workDir, "held");
  const okModel = (async () =>
    new Response(JSON.stringify({ choices: [{ message: { content: '{"result":"ok","reason":"matches the payee history"}' } }] }), { status: 200 })) as typeof fetch;

  log("[1] Owner sets the mandate (mock contract; on testnet this is set_mandate + add_payee, signed with the owner's passkey)");
  contract.ownerSetMandate(MANDATE, [MOCK_PAYEE]);
  return {
    supplier: supplierClient(fakeCreds, paypal.fetch),
    payee: MOCK_PAYEE,
    storeDir,
    heldFile: join(heldDir, "held.jsonl"),
    contract,
    pay: mockPayPaypal({
      contract,
      rail: { paypal: railClient(fakeCreds, paypal.fetch), store: fileStore(storeDir), secrets: [fakeCreds.PAYPAL_CLIENT_ID, fakeCreds.PAYPAL_CLIENT_SECRET] },
      payeeHistory: [{ payee: MOCK_PAYEE, amounts: ["25.00", "25.00", "30.00"], last_seen: dueIn(-8) }],
      now,
      modelFetch: okModel,
      // A placeholder key and endpoint: the model call goes to okModel, so no real key is ever read.
      scamcheck: { apiKey: "mock-near-ai-key", baseUrl: "https://mock-near-ai.invalid/v1", heldDir },
    }),
  };
}

async function setupLive(log: (s: string) => void, env: NodeJS.ProcessEnv): Promise<Ctx> {
  const rpc = env.NEAR_RPC || "https://rpc.testnet.near.org";
  assertTestnetRpc(rpc);
  if (!env.CONTRACT_ID) throw new Error("set CONTRACT_ID (the mandate contract on NEAR testnet)");
  const contractId = assertTestnet("CONTRACT_ID", env.CONTRACT_ID);
  const agent = env.DEMO_AGENT || AGENT;
  const creds = readCredentials(credentialsFile(env));
  const payee = (env.DEMO_PAYPAL_PAYEE || creds.PAYPAL_SANDBOX_RECEIVER_EMAIL || "").toLowerCase();
  if (!payee) throw new Error("set DEMO_PAYPAL_PAYEE or PAYPAL_SANDBOX_RECEIVER_EMAIL in the PayPal credentials file");

  log(`[1] Owner's mandate on ${contractId} for ${agent} (read with get_mandate / get_payees; set it with the owner scripts first)`);
  const cfg = { rpc, contractId } as Config;
  const mandate = await view(cfg, contractId, "get_mandate", { agent });
  const payees: any[] = await view(cfg, contractId, "get_payees", { agent });
  const rail = mandate?.paypal;
  if (!rail) throw new Error(`the mandate for ${agent} has no PayPal rail`);
  if (!payees.some((p) => p.rail === "paypal" && p.receiver === payee)) throw new Error(`${maskEmail(payee)} is not on ${agent}'s PayPal payees`);
  log(`    PayPal payee ${maskEmail(payee)} allowed, USD ${usd(rail.amount_range.min)}-${usd(rail.amount_range.max)} per payment, budget USD ${usd(rail.budget)} per ${rail.period_secs / 86400} days`);
  const pay = await livePayPaypal();
  return {
    supplier: supplierClient(creds),
    pay,
    payee,
    storeDir: resolve(env.PP3_STORE_DIR || fileURLToPath(new URL("../../rails/paypal/.orders", import.meta.url))),
    heldFile: heldPath({ heldDir: env.SCAMCHECK_HELD_DIR }),
  };
}

function describe(r: PayPaypalResult, log: (s: string) => void): void {
  log(`    scam check: ${r.scam_check.result}${r.scam_check.reason ? ` (${r.scam_check.reason})` : ""}`);
  if (r.signed_text) log(`    contract signed: "${maskEmails(r.signed_text)}"`);
  if (r.status === "submitted") log(`    PayPal rail submitted it: payout batch ${r.payout_batch_id}, ${r.batch_status}`);
  else if (r.status === "held") log(`    HELD for the owner (${r.held_id}); nothing was signed`);
  else log(`    ${r.status.toUpperCase()}: ${r.error_code}${r.detail ? ` (${maskEmails(r.detail)})` : ""}`);
}

function readHeld(file: string) {
  let raw = "";
  try {
    raw = readFileSync(file, "utf8");
  } catch {
    return [];
  }
  return raw.split("\n").filter(Boolean).flatMap((l) => {
    try {
      return [JSON.parse(l)];
    } catch {
      return [];
    }
  });
}

export async function runPaypalDemo(opts: { mock: boolean; log?: (s: string) => void; env?: NodeJS.ProcessEnv }): Promise<DemoSummary> {
  const log = opts.log ?? ((s: string) => console.log(s));
  const env = opts.env ?? process.env;
  const mode = opts.mock ? "mock" : "live";
  log(`nearH x PayPal demo (${mode}${opts.mock ? ": NEAR, Chain Signatures, PayPal and the scam-check model are in-process fakes" : ": NEAR testnet + PayPal sandbox"})`);
  const ctx = opts.mock ? await setupMock(log, mkdtempSync(join(tmpdir(), "nearh-paypal-demo-"))) : await setupLive(log, env);
  if (ctx.contract) {
    const m = ctx.contract.getMandate()!;
    log(`    PayPal payee ${maskEmail(ctx.payee)} allowed, USD ${usd(m.paypal.amount_range.min)}-${usd(m.paypal.amount_range.max)} per payment, budget USD ${usd(m.paypal.budget)} per 7 days`);
    log(`    agent ${ctx.contract.agent} signs through the contract only; its EOA ${ctx.contract.evmAddress.slice(0, 6)}…${ctx.contract.evmAddress.slice(-4)} holds no PayPal key`);
  }

  log("[2] Supplier issues a PayPal sandbox invoice (Invoicing API: create + send)");
  const invoice: BuyerInvoice = await issueInvoice(ctx.supplier, {
    amount: "25.00",
    service: "Weather data API",
    description: `Weather data API access, ${new Date().toISOString().slice(0, 7)}`,
    dueDate: dueIn(10),
    payee: ctx.payee,
    billTo: "buyer@example.com",
  });
  log(`    ${invoice.invoice_id} (${invoice.status}): USD ${invoice.amount.value} to ${maskEmail(invoice.payee)}, due ${invoice.due_date}`);

  log("[3] Buyer agent pays it with pay_paypal: scam check -> contract-signed payout order -> PayPal rail -> PayPal Payouts");
  const paid = await ctx.pay({ invoice, reason: "monthly weather data" });
  describe(paid, log);

  log("[4] A poisoned invoice arrives: same supplier and amount, lookalike payee");
  const poisonedInvoice = await issueInvoice(ctx.supplier, {
    amount: "25.00",
    service: "Weather data API",
    description: `Weather data API access, ${new Date().toISOString().slice(0, 7)}`,
    dueDate: dueIn(10),
    payee: lookalike(ctx.payee),
    billTo: "buyer@example.com",
  });
  log(`    ${poisonedInvoice.invoice_id}: USD ${poisonedInvoice.amount.value} to ${maskEmail(poisonedInvoice.payee)}`);
  const poisoned = await ctx.pay({ invoice: poisonedInvoice, reason: "monthly weather data" });
  describe(poisoned, log);
  let contractOnPoisoned: string | undefined;
  if (ctx.contract) {
    const direct = ctx.contract.requestSignature(`pp-bypass-${Date.now().toString(36)}`, {
      payee: poisonedInvoice.payee,
      amount: poisonedInvoice.amount.value,
      timestamp: Math.floor(Date.now() / 1000),
    });
    contractOnPoisoned = direct.ok ? "signed" : direct.error;
    log(`    with the scam check bypassed, the contract still refuses to sign: ${contractOnPoisoned}`);
  }

  log("[5] Dashboard USD view (dashboard/, the same readers as GET /api/paypal and /api/held)");
  const store = readPaypalStore(ctx.storeDir);
  const payouts = store.records.map((r: any) => ({ request_id: r.request_id, state: r.state, amount: r.amount, payee_masked: r.payee_masked, payout_batch_id: r.payout_batch_id }));
  const held = readHeld(ctx.heldFile)
    .filter((h) => h.rail === "paypal" && h.status === "held")
    .map((h) => ({ request_id: h.request_id, payee: maskEmail(String(h.shape?.payee ?? "")), amount: String(h.shape?.amount ?? ""), reason: h.verdict?.reason ?? null }));
  log("    PayPal payouts (rail records):");
  for (const p of payouts) log(`      ${p.request_id}  USD ${p.amount}  ${p.payee_masked}  ${p.state}  batch ${p.payout_batch_id ?? "-"}`);
  log("    Held for the owner:");
  for (const h of held) log(`      ${h.request_id}  USD ${h.amount}  ${h.payee}  held (${h.reason})`);
  log(`    Page: PP3_STORE_DIR=${ctx.storeDir} DASHBOARD_HELD_FILE=${ctx.heldFile} pnpm --filter @nearh/dashboard start${opts.mock ? " (the page itself needs a testnet CONTRACT_ID in dashboard/.env; its USD rows come from the contract's list_requests)" : ""}`);
  log("Done: one payout through the mandate, one poisoned invoice stopped.");
  return { mode, paid, poisoned, contractOnPoisoned, dashboard: { payouts, held } };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const mock = process.argv.slice(2).includes("--mock");
  runPaypalDemo({ mock }).then(
    (s) => process.exit(s.paid.status === "submitted" && s.poisoned.status !== "submitted" ? 0 : 1),
    (e: Error) => {
      console.error(`demo:paypal: ${maskEmails(e.message)}`);
      process.exit(1);
    },
  );
}
