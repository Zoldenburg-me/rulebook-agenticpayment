// The supplier against a fake PayPal sandbox: a fetch that records every call. Credentials and
// the token are marker strings, so any leak into a result or error shows up as a test failure.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { getInvoice, invoiceRequest, issueInvoice, parseInvoiceId, toBuyerInvoice, type InvoiceInput } from "../src/invoice.ts";
import { PaypalError, SANDBOX_BASE, assertSandbox, sandboxClient } from "../src/paypal.ts";

const CLIENT_ID = "client-id-do-not-print-3e1d";
const SECRET = "client-secret-do-not-print-7f3a";
const TOKEN = "access-token-do-not-print-91bc";
const CREDS = { PAYPAL_ENV: "sandbox", PAYPAL_CLIENT_ID: CLIENT_ID, PAYPAL_CLIENT_SECRET: SECRET };
const ID = "INV2-AB12-CD34-EF56-GH78";
const TODAY = "2026-11-06";
const INPUT: InvoiceInput = {
  amount: "25.00",
  description: "Weather data API, November",
  dueDate: "2026-11-20",
  payee: "Supplier@Example.com",
  billTo: "buyer@example.com",
  service: "Weather API",
  invoiceNumber: "NEARH-TEST-1",
};

/** An invoice resource as GET /v2/invoicing/invoices/{id} returns it. */
const resource = (over: Record<string, unknown> = {}) => ({
  id: ID,
  status: "SENT",
  detail: {
    invoice_number: "NEARH-TEST-1",
    invoice_date: TODAY,
    currency_code: "USD",
    note: INPUT.description,
    payment_term: { term_type: "DUE_ON_DATE_SPECIFIED", due_date: "2026-11-20" },
    metadata: { recipient_view_url: `https://www.sandbox.paypal.com/invoice/p/#${ID}` },
  },
  invoicer: { business_name: "nearH demo supplier", additional_notes: "PayPal payee: Supplier@Example.com" },
  amount: { currency_code: "USD", value: "25.00" },
  ...over,
});

type Reply = { status: number; body?: unknown; headers?: Record<string, string> } | "throw";
let calls: { method: string; path: string; headers: Record<string, string>; body: any }[];
let replies: Record<string, Reply>;

function fake(): typeof fetch {
  return (async (url: string, init: RequestInit) => {
    assert.ok(url.startsWith(SANDBOX_BASE + "/"), "only the sandbox is ever called");
    const path = new URL(url).pathname;
    const method = String(init.method);
    const raw = init.body === undefined ? undefined : String(init.body);
    calls.push({ method, path, headers: init.headers as Record<string, string>, body: raw && path !== "/v1/oauth2/token" ? JSON.parse(raw) : raw });
    const r = replies[`${method} ${path}`];
    if (!r) throw new Error(`unexpected ${method} ${path}`);
    if (r === "throw") throw new Error(`socket hang up, Authorization: Bearer ${TOKEN}, secret ${SECRET}`);
    return new Response(JSON.stringify(r.body ?? {}), { status: r.status, headers: r.headers });
  }) as typeof fetch;
}

const client = () => sandboxClient(CREDS, fake());

function assertNoSecret(text: string) {
  for (const s of [CLIENT_ID, SECRET, TOKEN, Buffer.from(`${CLIENT_ID}:${SECRET}`).toString("base64")]) {
    assert.ok(!text.includes(s), `leaked ${s.slice(-4)} in: ${text}`);
  }
}

async function rejectsClean(p: Promise<unknown>, pattern: RegExp) {
  await assert.rejects(p, (err: Error) => {
    assertNoSecret(err.message);
    assertNoSecret(String(err.stack));
    assert.match(err.message, pattern);
    return true;
  });
}

function reset() {
  calls = [];
  replies = {
    "POST /v1/oauth2/token": { status: 200, body: { access_token: TOKEN, expires_in: 32400 } },
    "POST /v2/invoicing/invoices": { status: 201, body: resource({ status: "DRAFT" }) },
    [`POST /v2/invoicing/invoices/${ID}/send`]: { status: 200, body: { href: `${SANDBOX_BASE}/invoice/p/#${ID}` } },
    [`GET /v2/invoicing/invoices/${ID}`]: { status: 200, body: resource() },
  };
}

beforeEach(reset);

test("request body: USD, one item, due date, payee as invoicer, bill-to, no tips or partial payments", () => {
  assert.deepEqual(invoiceRequest(INPUT, TODAY), {
    detail: {
      invoice_number: "NEARH-TEST-1",
      invoice_date: TODAY,
      currency_code: "USD",
      note: INPUT.description,
      payment_term: { term_type: "DUE_ON_DATE_SPECIFIED", due_date: "2026-11-20" },
    },
    invoicer: { business_name: "nearH demo supplier", additional_notes: "PayPal payee: Supplier@Example.com" },
    primary_recipients: [{ billing_info: { email_address: "buyer@example.com" } }],
    items: [
      {
        name: "Weather API",
        description: INPUT.description,
        quantity: "1",
        unit_amount: { currency_code: "USD", value: "25.00" },
        unit_of_measure: "QUANTITY",
      },
    ],
    configuration: { allow_tip: false, partial_payment: { allow_partial_payment: false } },
  });
  const { detail } = invoiceRequest({ ...INPUT, invoiceNumber: undefined }, TODAY);
  assert.match(detail.invoice_number, /^NEARH-[0-9A-F-]{13}$/);
  assert.notEqual(detail.invoice_number, invoiceRequest({ ...INPUT, invoiceNumber: undefined }, TODAY).detail.invoice_number);
});

test("bad input is refused before any PayPal call", async () => {
  const bad: [Partial<InvoiceInput>, RegExp][] = [
    [{ amount: "25" }, /amount/],
    [{ amount: "25.0" }, /amount/],
    [{ amount: "0.00" }, /amount/],
    [{ amount: "-1.00" }, /amount/],
    [{ amount: "025.00" }, /amount/],
    [{ amount: "1e3" }, /amount/],
    [{ description: "  " }, /description/],
    [{ description: "x".repeat(1001) }, /description must be 1-1000/],
    [{ service: "" }, /service/],
    [{ service: "x".repeat(201) }, /service must be 1-200/],
    [{ supplierName: "x".repeat(301) }, /supplier name must be 1-300/],
    [{ dueDate: "20.11.2026" }, /due date/],
    [{ dueDate: "2026-02-30" }, /due date/],
    [{ dueDate: "2026-11-05" }, /before the invoice date/],
    [{ billTo: "not-an-email" }, /bill-to/],
    [{ payee: "" }, /payee/],
    [{ payee: "@venmo-handle" }, /payee/],
  ];
  for (const [over, pattern] of bad) {
    await assert.rejects(issueInvoice(client(), { ...INPUT, ...over }, { today: TODAY }), pattern, JSON.stringify(over));
  }
  assert.equal(calls.length, 0);
});

test("issue: token, create with return=representation, send, read back; returns the buyer view", async () => {
  const inv = await issueInvoice(client(), INPUT, { today: TODAY });
  assert.deepEqual(inv, {
    invoice_id: ID,
    invoice_number: "NEARH-TEST-1",
    status: "SENT",
    amount: { currency: "USD", value: "25.00" },
    payee: "supplier@example.com",
    due_date: "2026-11-20",
    description: INPUT.description,
    payer_view_url: `https://www.sandbox.paypal.com/invoice/p/#${ID}`,
  });
  assert.deepEqual(calls.map((c) => `${c.method} ${c.path}`), [
    "POST /v1/oauth2/token",
    "POST /v2/invoicing/invoices",
    `POST /v2/invoicing/invoices/${ID}/send`,
    `GET /v2/invoicing/invoices/${ID}`,
  ]);
  const [auth, create, send, get] = calls;
  assert.equal(auth.headers.Authorization, "Basic " + Buffer.from(`${CLIENT_ID}:${SECRET}`).toString("base64"));
  assert.equal(auth.body, "grant_type=client_credentials");
  for (const c of [create, send, get]) assert.equal(c.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(create.headers.Prefer, "return=representation");
  assert.deepEqual(create.body, invoiceRequest(INPUT, TODAY));
  assert.deepEqual(send.body, { send_to_invoicer: false, send_to_recipient: true });
  assertNoSecret(JSON.stringify(inv));
});

test("draft: no send call", async () => {
  replies[`GET /v2/invoicing/invoices/${ID}`] = { status: 200, body: resource({ status: "DRAFT" }) };
  const inv = await issueInvoice(client(), INPUT, { today: TODAY, send: false });
  assert.equal(inv.status, "DRAFT");
  assert.ok(!calls.some((c) => c.path.endsWith("/send")));
});

test("invoice id: from the body, else from the self link; anything else throws", () => {
  assert.equal(parseInvoiceId({ id: ID }), ID);
  assert.equal(parseInvoiceId({ rel: "self", href: `${SANDBOX_BASE}/v2/invoicing/invoices/${ID}`, method: "GET" }), ID);
  assert.equal(parseInvoiceId({ links: [{ rel: "self", href: `${SANDBOX_BASE}/v2/invoicing/invoices/${ID}?x=1` }] }), ID);
  for (const body of [{}, null, { id: "" }, { id: "INV2-AB12" }, { id: "../oauth2/token" }, { href: `${SANDBOX_BASE}/v2/invoicing/invoices/` }, { id: 42 }]) {
    assert.throws(() => parseInvoiceId(body), /no invoice id/, JSON.stringify(body));
  }
});

test("create answered with only a link still resolves the invoice", async () => {
  replies["POST /v2/invoicing/invoices"] = { status: 201, body: { rel: "self", href: `${SANDBOX_BASE}/v2/invoicing/invoices/${ID}`, method: "GET" } };
  assert.equal((await issueInvoice(client(), INPUT, { today: TODAY })).invoice_id, ID);
});

test("buyer view refuses an invoice missing what the buyer needs", () => {
  const cases: [Record<string, unknown>, RegExp][] = [
    [{ amount: { currency_code: "EUR", value: "25.00" } }, /not in USD/],
    [{ amount: { currency_code: "USD", value: "25" } }, /amount/],
    [{ amount: { currency_code: "USD", value: "0.00" } }, /amount above zero/],
    [{ amount: undefined }, /amount/],
    [{ invoicer: {} }, /names no PayPal payee/],
    [{ invoicer: { additional_notes: "PayPal payee: not-an-email" } }, /names no PayPal payee/],
    [{ invoicer: { additional_notes: "PayPal payee: a@example.com", email_address: "b@example.com" } }, /two payees/],
    [{ detail: { ...resource().detail, payment_term: {} } }, /due date/],
    [{ id: "nope" }, /no invoice id/],
  ];
  for (const [over, pattern] of cases) assert.throws(() => toBuyerInvoice(resource(over)), pattern, JSON.stringify(over));
});

test("PayPal's field limits are accepted at the boundary", () => {
  const body = invoiceRequest({ ...INPUT, description: "x".repeat(1000), service: "s".repeat(200), supplierName: "n".repeat(300) }, TODAY);
  assert.equal(body.items[0].description.length, 1000);
  assert.equal(body.detail.note.length, 1000);
});

test("buyer view: payee from the payee note, else the invoicer email; same email in both is fine", () => {
  assert.equal(toBuyerInvoice(resource({ invoicer: { email_address: "Real@Supplier.example" } })).payee, "real@supplier.example");
  assert.equal(
    toBuyerInvoice(resource({ invoicer: { email_address: "supplier@example.com", additional_notes: "PayPal payee: Supplier@Example.com" } })).payee,
    "supplier@example.com",
  );
});

test("get refuses a malformed id before calling PayPal", async () => {
  await assert.rejects(getInvoice(client(), "../../v1/oauth2/token"), /not a PayPal invoice id/);
  assert.equal(calls.length, 0);
});

test("errors carry status, PayPal error name and debug id, never credentials or the token", async () => {
  // Auth refused, with the client id echoed in the body.
  replies["POST /v1/oauth2/token"] = { status: 401, body: { error: "invalid_client", error_description: `bad ${CLIENT_ID}` }, headers: { "paypal-debug-id": "dbg1" } };
  await rejectsClean(issueInvoice(client(), INPUT, { today: TODAY }), /authentication failed \(HTTP 401, invalid_client, debug id dbg1\)/);

  // Create refused; the body echoes the token and secret.
  reset();
  replies["POST /v2/invoicing/invoices"] = {
    status: 422,
    body: { name: "UNPROCESSABLE_ENTITY", message: `token ${TOKEN} secret ${SECRET}`, details: [{ issue: "DUPLICATE_INVOICE_NUMBER", description: `dup ${SECRET}` }, { issue: `x ${TOKEN}` }] },
    headers: { "paypal-debug-id": "dbg2" },
  };
  await rejectsClean(issueInvoice(client(), INPUT, { today: TODAY }), /create invoice failed \(HTTP 422, UNPROCESSABLE_ENTITY \[DUPLICATE_INVOICE_NUMBER\], debug id dbg2\)/);

  // A PaypalError carries the status for callers.
  reset();
  replies[`POST /v2/invoicing/invoices/${ID}/send`] = { status: 403, body: { name: "NOT_AUTHORIZED" } };
  await assert.rejects(issueInvoice(client(), INPUT, { today: TODAY }), (err: unknown) => err instanceof PaypalError && err.status === 403);

  // Error names that are not code-shaped are dropped, like free text.
  reset();
  replies["POST /v2/invoicing/invoices"] = { status: 400, body: { name: `Bad ${SECRET} input`, details: [{ issue: "INVALID_STRING_LENGTH" }] } };
  await rejectsClean(issueInvoice(client(), INPUT, { today: TODAY }), /create invoice failed \(HTTP 400 \[INVALID_STRING_LENGTH\]\)$/);
  reset();
  replies["POST /v1/oauth2/token"] = { status: 401, body: { error: "invalid client, see https://example.com" } };
  await rejectsClean(issueInvoice(client(), INPUT, { today: TODAY }), /authentication failed \(HTTP 401\)$/);

  // Network failure whose message echoes the bearer header.
  reset();
  replies[`GET /v2/invoicing/invoices/${ID}`] = "throw";
  await rejectsClean(issueInvoice(client(), INPUT, { today: TODAY }), /no answer from the sandbox/);

  // Non-JSON error body containing the secret.
  const c = sandboxClient(CREDS, (async (url: string, init: RequestInit) => {
    if (new URL(url).pathname === "/v1/oauth2/token") return new Response(JSON.stringify({ access_token: TOKEN }), { status: 200 });
    return new Response(`<html>oops ${SECRET} Bearer ${TOKEN}</html>`, { status: 500 });
  }) as typeof fetch);
  const a = await c.request("POST", "/v2/invoicing/invoices", {});
  assertNoSecret(JSON.stringify(a.body));
  await rejectsClean(issueInvoice(c, INPUT, { today: TODAY }), /HTTP 500/);
});

test("a body read that times out or resets is a PaypalError, not the raw error", async () => {
  const c = sandboxClient(CREDS, (async (url: string) => {
    if (new URL(url).pathname === "/v1/oauth2/token") return new Response(JSON.stringify({ access_token: TOKEN }), { status: 200 });
    const body = new ReadableStream({
      start(ctl) {
        ctl.error(new DOMException(`The operation timed out. Bearer ${TOKEN}`, "TimeoutError"));
      },
    });
    return new Response(body, { status: 200, headers: { "paypal-debug-id": "dbg3" } });
  }) as typeof fetch);
  await assert.rejects(c.request("GET", `/v2/invoicing/invoices/${ID}?x=1`), (err: unknown) => {
    assert.ok(err instanceof PaypalError);
    assert.equal(err.message, `PayPal GET /v2/invoicing/invoices/${ID}: answer cut off (HTTP 200)`);
    assert.equal(err.debugId, "dbg3");
    assertNoSecret(err.message);
    return true;
  });
});

test("only sandbox credentials are accepted; the message names no value", () => {
  assert.throws(() => assertSandbox({ ...CREDS, PAYPAL_ENV: "live" }), /must be 'sandbox'/);
  assert.throws(() => assertSandbox({ ...CREDS, PAYPAL_CLIENT_SECRET: "" }), /must be set/);
  try {
    assertSandbox({ ...CREDS, PAYPAL_ENV: "live" });
  } catch (err) {
    assertNoSecret((err as Error).message);
  }
});

test("the token is fetched once and reused", async () => {
  const c = client();
  await getInvoice(c, ID);
  await getInvoice(c, ID);
  assert.equal(calls.filter((x) => x.path === "/v1/oauth2/token").length, 1);
});

test("a token inside PayPal's expiry margin is fetched again (PayPal audit 1 M2)", async () => {
  replies["POST /v1/oauth2/token"] = { status: 200, body: { access_token: TOKEN, expires_in: 300 } };
  const c = client();
  await getInvoice(c, ID);
  await getInvoice(c, ID);
  assert.equal(calls.filter((x) => x.path === "/v1/oauth2/token").length, 2);
});
