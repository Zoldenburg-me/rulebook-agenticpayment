// The demo supplier's side of PP4: issue a PayPal sandbox invoice (Invoicing v2) for a service,
// and hand it to the buyer as plain data. The buyer agent reads `BuyerInvoice` and pays it only
// through a contract-signed payout order (shape 4); it never gets PayPal credentials.

import { randomUUID } from "node:crypto";
import { answerError, type Answer, type Client } from "./paypal.ts";

export type InvoiceInput = {
  /** USD, canonical: digits with exactly two decimals, more than zero (e.g. "25.00"). */
  amount: string;
  /** What the service is; shown to the buyer and to the scam check. 1-1000 characters (it is also the item description). */
  description: string;
  /** YYYY-MM-DD, not before the invoice date. */
  dueDate: string;
  /**
   * The PayPal email the buyer pays (by payout). Written to the invoice as
   * `invoicer.additional_notes: "PayPal payee: <email>"`, not as `invoicer.email_address`: PayPal
   * only accepts the calling business account there (send fails with USER_NOT_FOUND), and that
   * account is also our payout sender, which cannot pay itself (PP-S1: UNCLAIMED). In the sandbox
   * it is a personal account.
   */
  payee: string;
  /** Shown as the invoicer's business name; at most 300 characters. */
  supplierName?: string;
  /** Who the invoice is billed to (a sandbox account email). */
  billTo: string;
  /** Line item name; 1-200 characters. */
  service?: string;
  /** YYYY-MM-DD; defaults to today (UTC). */
  invoiceDate?: string;
  /** Unique per PayPal account; defaults to NEARH-<uuid prefix>. */
  invoiceNumber?: string;
};

/** What the buyer (and the future pay_paypal tool) reads. */
export type BuyerInvoice = {
  invoice_id: string;
  invoice_number: string;
  status: string;
  amount: { currency: "USD"; value: string };
  /** The PayPal email to pay, lowercased as the contract stores payees. */
  payee: string;
  due_date: string;
  description: string;
  /** PayPal-hosted page for the recipient, if PayPal returned one. */
  payer_view_url: string | null;
};

const AMOUNT = /^(0|[1-9][0-9]*)\.[0-9]{2}$/;
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const INVOICE_ID = /^INV2(-[A-Z0-9]{4}){4}$/;
const PAYEE_NOTE = /^PayPal payee: (\S+)$/;
// Invoicing v2 maxLength values (developer.paypal.com/api/invoicing/v2/schema.json):
// items[].description 1000 (detail.note allows 4000, but the description goes into both),
// items[].name 200, invoicer.business_name 300.
const MAX_DESCRIPTION = 1000;
const MAX_SERVICE = 200;
const MAX_SUPPLIER_NAME = 300;

function isDate(s: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s)) && new Date(s).toISOString().startsWith(s);
}

export function validateInput(input: InvoiceInput, today = new Date().toISOString().slice(0, 10)): void {
  if (!AMOUNT.test(input.amount) || Number(input.amount) <= 0) throw new Error(`amount must be USD with two decimals and above zero, got ${JSON.stringify(input.amount)}`);
  if (!input.description.trim() || input.description.length > MAX_DESCRIPTION) throw new Error(`description must be 1-${MAX_DESCRIPTION} characters`);
  if (input.service !== undefined && (!input.service.trim() || input.service.length > MAX_SERVICE)) throw new Error(`service must be 1-${MAX_SERVICE} characters`);
  if (input.supplierName !== undefined && (!input.supplierName.trim() || input.supplierName.length > MAX_SUPPLIER_NAME)) throw new Error(`supplier name must be 1-${MAX_SUPPLIER_NAME} characters`);
  if (!isDate(input.dueDate)) throw new Error(`due date must be YYYY-MM-DD, got ${JSON.stringify(input.dueDate)}`);
  const invoiceDate = input.invoiceDate ?? today;
  if (!isDate(invoiceDate)) throw new Error(`invoice date must be YYYY-MM-DD, got ${JSON.stringify(invoiceDate)}`);
  if (input.dueDate < invoiceDate) throw new Error("due date is before the invoice date");
  if (!EMAIL.test(input.payee)) throw new Error("payee must be an email address");
  if (!EMAIL.test(input.billTo)) throw new Error("bill-to must be an email address");
}

/** The POST /v2/invoicing/invoices body. */
export function invoiceRequest(input: InvoiceInput, today = new Date().toISOString().slice(0, 10)) {
  validateInput(input, today);
  return {
    detail: {
      invoice_number: input.invoiceNumber ?? `NEARH-${randomUUID().slice(0, 13).toUpperCase()}`,
      invoice_date: input.invoiceDate ?? today,
      currency_code: "USD",
      note: input.description,
      payment_term: { term_type: "DUE_ON_DATE_SPECIFIED", due_date: input.dueDate },
    },
    invoicer: { business_name: input.supplierName ?? "nearH demo supplier", additional_notes: `PayPal payee: ${input.payee}` },
    primary_recipients: [{ billing_info: { email_address: input.billTo } }],
    items: [
      {
        name: input.service ?? "Service",
        description: input.description,
        quantity: "1",
        unit_amount: { currency_code: "USD", value: input.amount },
        unit_of_measure: "QUANTITY",
      },
    ],
    configuration: { allow_tip: false, partial_payment: { allow_partial_payment: false } },
  };
}

/**
 * The invoice id from a create answer: the body's `id` (with `Prefer: return=representation`),
 * else the last path segment of the `self` link PayPal returns by default. Throws if neither is an
 * invoice id.
 */
export function parseInvoiceId(body: any): string {
  const candidates: unknown[] = [body?.id];
  const href = typeof body?.href === "string" ? body.href : body?.links?.find?.((l: any) => l?.rel === "self")?.href;
  if (typeof href === "string") candidates.push(href.split("?")[0].split("/").pop());
  const id = candidates.find((c): c is string => typeof c === "string" && INVOICE_ID.test(c));
  if (!id) throw new Error("PayPal create answer has no invoice id");
  return id;
}

/** The buyer view of a PayPal invoice resource. Throws if a field the buyer needs is missing. */
export function toBuyerInvoice(inv: any): BuyerInvoice {
  const id = parseInvoiceId({ id: inv?.id });
  const d = inv?.detail ?? {};
  const currency = inv?.amount?.currency_code ?? d.currency_code;
  const value = inv?.amount?.value;
  const noted = typeof inv?.invoicer?.additional_notes === "string" ? inv.invoicer.additional_notes.match(PAYEE_NOTE)?.[1] : undefined;
  const invoicerEmail = inv?.invoicer?.email_address;
  const payee = noted ?? invoicerEmail;
  const due = d.payment_term?.due_date;
  const description = d.note ?? inv?.items?.[0]?.description;
  if (currency !== "USD") throw new Error(`invoice ${id} is not in USD`);
  if (typeof value !== "string" || !AMOUNT.test(value) || Number(value) <= 0) throw new Error(`invoice ${id} has no canonical USD amount above zero`);
  if (typeof payee !== "string" || !EMAIL.test(payee)) throw new Error(`invoice ${id} names no PayPal payee`);
  if (noted && typeof invoicerEmail === "string" && invoicerEmail.toLowerCase() !== noted.toLowerCase()) {
    throw new Error(`invoice ${id} names two payees`);
  }
  if (typeof due !== "string" || !isDate(due)) throw new Error(`invoice ${id} has no due date`);
  if (typeof description !== "string") throw new Error(`invoice ${id} has no description`);
  return {
    invoice_id: id,
    invoice_number: String(d.invoice_number ?? ""),
    status: String(inv.status ?? "UNKNOWN"),
    amount: { currency: "USD", value },
    payee: payee.toLowerCase(),
    due_date: due,
    description,
    payer_view_url: typeof d.metadata?.recipient_view_url === "string" ? d.metadata.recipient_view_url : null,
  };
}

function check(what: string, a: Answer, client: Client): Answer {
  if (!a.ok) throw answerError(what, a, client.scrub);
  return a;
}

export async function getInvoice(client: Client, id: string): Promise<BuyerInvoice> {
  if (!INVOICE_ID.test(id)) throw new Error("not a PayPal invoice id");
  const a = check("PayPal get invoice", await client.request("GET", `/v2/invoicing/invoices/${id}`), client);
  return toBuyerInvoice(a.body);
}

/**
 * Creates the draft, sends it (status SENT; the sandbox delivers no real mail) and
 * returns the buyer view. `send: false` leaves it a DRAFT.
 */
export async function issueInvoice(client: Client, input: InvoiceInput, opts: { send?: boolean; today?: string } = {}): Promise<BuyerInvoice> {
  const body = invoiceRequest(input, opts.today);
  const created = check(
    "PayPal create invoice",
    await client.request("POST", "/v2/invoicing/invoices", body, { Prefer: "return=representation" }),
    client,
  );
  const id = parseInvoiceId(created.body);
  if (opts.send !== false) {
    check(
      "PayPal send invoice",
      await client.request("POST", `/v2/invoicing/invoices/${id}/send`, { send_to_invoicer: false, send_to_recipient: true }),
      client,
    );
  }
  return getInvoice(client, id);
}
