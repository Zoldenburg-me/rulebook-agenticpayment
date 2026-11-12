// PP-T1: the support agent's PayPal tools run here, in the rail, with the sandbox credentials.
// The agent gets the tool definitions and the results of the read tools, never the credentials
// or a token. The definitions are PayPal's own, copied from @paypal/agent-toolkit 1.11.0 (ISC);
// the package itself is not a dependency (its langchain/ai/mathjs/zod 3 tree fails
// `pnpm audit`). The two reads are the same REST calls the toolkit makes, through
// `sandboxClient`. `create_refund` is offered but never executed here: a refund goes through a
// contract-signed shape 6 order (`submitRefund`), so the mandate's cap and budget apply.

import { assertSandbox, sandboxClient, type Client, type Credentials } from "./paypal.ts";
import { maskEmails, scrub } from "./payout.ts";

/** Tools the rail runs for the agent: reads only. */
export const READ_TOOLS = ["get_order", "get_refund"] as const;
/** The one write tool: offered to the model, executed only through `POST /refunds`. */
export const MANDATED_TOOL = "create_refund";
/** Longest tool answer passed back to the agent. */
const MAX_RESULT = 8_000;

export type ToolDef = { type: "function"; function: { name: string; description?: string; parameters?: unknown } };
export type Toolkit = {
  /** PayPal's definitions of the read tools and `create_refund`. */
  tools(): ToolDef[];
  /** Runs one read tool; anything else throws. Output carries no credential and no full email. */
  call(name: string, args: unknown): Promise<string>;
};

const SCHEMA = "http://json-schema.org/draft-07/schema#";
const PAYMENT_ID = "^[A-Za-z0-9_-]{15,32}$";
const ORDER_ID = "^[A-Z0-9]{17,32}$";

/** PayPal's tool definitions, as @paypal/agent-toolkit 1.11.0 `getTools()` returns them. */
const DEFS: ToolDef[] = [
  {
    type: "function",
    function: {
      name: "get_order",
      description:
        "\nRetrieves the order details from PayPal for a given order ID.\n\nThis tool is used to retrieve details of an existing order in PayPal. It provides information about the order, including items, amounts, status, and other relevant details.\n",
      parameters: {
        type: "object",
        properties: { id: { type: "string", pattern: ORDER_ID, description: "The order id generated during create call" } },
        required: ["id"],
        additionalProperties: false,
        $schema: SCHEMA,
      },
    },
  },
  {
    type: "function",
    function: {
      name: "create_refund",
      description:
        "\nInitiate a refund for a PayPal payment capture.\nIf you have an order ID instead of a capture ID, first use the get order tool to obtain the capture ID from the order details.\nThis function allows you to return funds to a customer by refunding a previously captured payment. You can issue a full refund or specify a partial amount. If multiple captures exist for an order, request clarification on which specific capture to refund.\nRequired parameters:\n- Capture ID: The ID of the capture to refund\n- Amount (optional): For partial refunds, specify the amount to refund (must be less than or equal to the captured amount)\n- Note to Payer (optional): Additional explanation visible to the customer\nResponse details include:\n- Refund ID and status\n- Refunded amount and currency\n\n",
      parameters: {
        type: "object",
        properties: {
          capture_id: { type: "string", pattern: PAYMENT_ID, description: "The ID of the capture to refund." },
          amount: {
            type: "object",
            properties: { currency_code: { type: "string" }, value: { type: "string" } },
            required: ["currency_code", "value"],
            additionalProperties: false,
            description: "The amount to refund. If not specified, the full captured amount is refunded.",
          },
          invoice_id: { type: "string", pattern: "^[A-Za-z0-9_-]{1,127}$", description: "The invoice ID that is used to track this payment." },
          note_to_payer: { type: "string", description: "A note to the payer." },
        },
        required: ["capture_id"],
        additionalProperties: false,
        $schema: SCHEMA,
      },
    },
  },
  {
    type: "function",
    function: {
      name: "get_refund",
      description:
        "\nRetrieve detailed information about a PayPal payment refund.\nIf you have an order ID instead of a refund ID, first use the get order tool to obtain the refund ID from the order details. \nThis function returns comprehensive details about a refund, including its current status (completed, pending, cancelled), refunded amount, and processing information.\nWhen multiple refunds exist for an order or capture, request clarification on which specific refund to retrieve. \nResponse details include:\n- Refund status and ID\n- Refunded amount and currency\n- Reason for refund (if provided)\n- Source transaction details\n",
      parameters: {
        type: "object",
        properties: { refund_id: { type: "string", pattern: PAYMENT_ID, description: "The ID of the refund to get details for." } },
        required: ["refund_id"],
        additionalProperties: false,
        $schema: SCHEMA,
      },
    },
  },
];

/** Each read tool's one argument, its pattern (it goes into the URL path) and the path. */
const READS: Record<(typeof READ_TOOLS)[number], { arg: string; pattern: RegExp; path: (id: string) => string }> = {
  get_order: { arg: "id", pattern: new RegExp(ORDER_ID), path: (id) => `/v2/checkout/orders/${id}` },
  get_refund: { arg: "refund_id", pattern: new RegExp(PAYMENT_ID), path: (id) => `/v2/payments/refunds/${id}` },
};

/** The tools as the agent may use them. `client` is for tests (a fake fetch). */
export function toolkit(creds: Credentials, client: Client = sandboxClient(creds)): Toolkit {
  const { id, secret } = assertSandbox(creds);
  return {
    tools: () => DEFS,
    async call(name, args) {
      if (!Object.hasOwn(READS, name)) throw new Error(`${name} is not a read tool the rail runs`);
      if (!args || typeof args !== "object" || Array.isArray(args)) throw new Error("tool arguments must be a JSON object");
      const read = READS[name as keyof typeof READS];
      const value = (args as Record<string, unknown>)[read.arg];
      if (typeof value !== "string" || !read.pattern.test(value)) throw new Error(`${name} needs ${read.arg} matching ${read.pattern.source}`);
      try {
        await client.authenticate();
        const a = await client.request("GET", read.path(value));
        if (!a.ok) throw new Error(`HTTP ${a.status}${typeof a.body?.name === "string" ? ` ${a.body.name}` : ""}${a.debugId ? ` (debug id ${a.debugId})` : ""}`);
        // PayPal's answer holds ids, amounts and payer details: the credentials are removed by
        // value and emails masked; the generic token redaction of `scrub` would eat the ids.
        return maskEmails(JSON.stringify(a.body).split(id).join("<REDACTED>").split(secret).join("<REDACTED>")).slice(0, MAX_RESULT);
      } catch (e: any) {
        throw new Error(`${name} failed: ${scrub(String(e?.message ?? e), [id, secret]).slice(0, 300)}`);
      }
    },
  };
}
