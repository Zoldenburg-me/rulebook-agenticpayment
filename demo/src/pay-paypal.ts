// The one place the demo calls the buyer agent's `pay_paypal` tool (PP4, agent/mcp). Everything
// else in demo/ goes through `PayPaypal`, so swapping the mock for the real tool is one function.
//
// mock: the same steps PP4 runs, with the external parts replaced: SC1's scam check (real
//   deterministic rules, stubbed model answer), the mock contract (mock-contract.ts) instead of
//   `request_signature` + Chain Signatures, then the real rails/paypal `submitPaypalPayout` over a
//   fake PayPal sandbox.
// live: PP4's `pay_paypal` (agent/mcp) is merged but not wired into this adapter yet, so `livePayPaypal` refuses.

import { randomBytes } from "node:crypto";
import { submitPaypalPayout, type Deps } from "@nearh/rails-paypal/src/payout.ts";
import type { BuyerInvoice } from "@nearh/supplier/src/invoice.ts";
import { checkAndHold, type PayeeEntry, type ScamcheckConfig } from "scamcheck";
import type { MockMandateContract } from "./mock-contract.ts";

export type PayPaypalInput = { invoice: BuyerInvoice; reason: string };
export type PayPaypalResult = {
  status: "submitted" | "held" | "blocked" | "failed" | "pending";
  request_id: string;
  scam_check: { result: string; reason: string | null };
  /** The shape 4 text the contract signed (full payee: mask before printing). */
  signed_text?: string;
  held_id?: string;
  payout_batch_id?: string;
  batch_status?: string;
  error_code?: string;
  detail?: string;
};
export type PayPaypal = (input: PayPaypalInput) => Promise<PayPaypalResult>;

export type MockPayContext = {
  contract: MockMandateContract;
  rail: Omit<Deps, "near">;
  payeeHistory: PayeeEntry[];
  now: () => number;
  /** SC1's model call; the mock answers `ok`, so only the deterministic rules can hold. */
  modelFetch: typeof fetch;
  /** SC1's settings, injected: the demo never writes process.env or reads scamcheck/.env. */
  scamcheck: ScamcheckConfig;
};

export const newRequestId = () => `pp-${Date.now().toString(36)}-${randomBytes(4).toString("hex")}`;

export function mockPayPaypal(ctx: MockPayContext): PayPaypal {
  return async ({ invoice, reason }) => {
    const request_id = newRequestId();
    const timestamp = ctx.now();
    const payee = invoice.payee;
    const amount = invoice.amount.value;

    // 1. Scam check (SC1) before anything is signed.
    const check = await checkAndHold(
      {
        agent: ctx.contract.agent,
        rail: "paypal",
        request_id,
        shape: { type: "paypal", payee, amount, timestamp },
        memo: `PayPal invoice ${invoice.invoice_number}: ${reason}`,
        invoice: {
          text: `${invoice.description}\nPay to: ${payee}\nAmount: USD ${amount}\nDue: ${invoice.due_date}`,
          source: `paypal-invoice:${invoice.invoice_id}`,
        },
        payee_known: ctx.contract.getPayees().some((p) => p.rail === "paypal" && p.receiver === payee),
        payee_history: ctx.payeeHistory,
      },
      { ...ctx.scamcheck, fetch: ctx.modelFetch },
    );
    const scam_check = { result: check.verdict.result, reason: check.verdict.reason };
    if (check.status === "held") return { status: "held", request_id, scam_check, held_id: check.item?.id };

    // 2. The contract signs only what fits the mandate.
    const signed = ctx.contract.requestSignature(request_id, { payee, amount, timestamp });
    if (!signed.ok) return { status: "blocked", request_id, scam_check, error_code: signed.error };

    // 3. The PayPal rail re-checks the signed order against the contract and submits it once.
    const out = await submitPaypalPayout(
      { ...ctx.rail, near: ctx.contract.views(), now: ctx.now },
      { agent: ctx.contract.agent, request_id, payee, amount, timestamp, signature: signed.signature },
    );
    if (out.status === "submitted") {
      return { status: "submitted", request_id, scam_check, signed_text: signed.text, payout_batch_id: out.payout_batch_id, batch_status: out.batch_status };
    }
    return { status: out.status, request_id, scam_check, signed_text: signed.text, error_code: out.error_code, detail: out.detail };
  };
}

export async function livePayPaypal(): Promise<PayPaypal> {
  throw new Error(
    "live mode does not call the agent's pay_paypal tool (PP4, agent/mcp) yet; run `pnpm demo:paypal --mock`",
  );
}
