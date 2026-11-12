// PP4: pay_paypal over a mocked contract and PP3, with SC1's real rules (the model mocked to `ok`,
// so a hold can only come from the deterministic PayPal rules) on PP4a's poisoned invoices.
import { strict as assert } from 'node:assert';
import { test, type TestContext } from 'node:test';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { NearX402Signer } from '@nearh/agent-signer';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { checkAndHold, type CheckParams, type CheckResult } from '../../../scamcheck/src/check.ts';
import { Buyer, checkoutMessage, paypalMessage, type Dependencies, type HeldDecision, type PaypalOrder } from '../src/buyer.ts';
import { ReceiptStore } from '../src/store.ts';
import { createServer } from '../src/server.ts';
import { pp3Client, pp3Endpoint } from '../src/runtime.ts';
import { payPaypalInvoice } from '../src/pay-paypal.ts';

type Invoice = { invoice_id: string; invoice_number: string; status: string; amount: { currency: 'USD'; value: string }; payee: string; due_date: string; description: string; payer_view_url: string | null };
const fixtures = JSON.parse(readFileSync(new URL('../../../scamcheck/fixtures/paypal-invoices.json', import.meta.url), 'utf8')) as {
  context: { allowlisted_payees: string[]; payee_history: { payee: string; amounts: string[] }[] };
  baseline: Invoice; poisoned: { name: string; invoice: Partial<Invoice> }[];
};
const baseline = fixtures.baseline;
const PAYEE = baseline.payee;
const AGENT = 'agent-1.mandate-test.testnet';
// Fake values that only stand in for credentials; the tests assert they never leave.
const PP3_TOKEN = 'pp3-token-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const NEAR_KEY = 'ed25519:FakeAgentKeyDoNotUse1234567890abcdefghij';
const NEAR_AI_KEY = 'fake-near-ai-key-for-tests';
const SIG = { r: `0x${'1'.repeat(64)}`, s: `0x${'2'.repeat(64)}`, v: 27 };
const okModel = (async () => new Response(JSON.stringify({ choices: [{ message: { content: '{"result":"ok","reason":"fine"}' } }] }), { status: 200 })) as typeof fetch;

function withEnv(t: TestContext, values: Record<string, string | undefined>) {
  const previous = Object.fromEntries(Object.keys(values).map(k => [k, process.env[k]]));
  t.after(() => { for (const [k, v] of Object.entries(previous)) if (v === undefined) delete process.env[k]; else process.env[k] = v; });
  for (const [k, v] of Object.entries(values)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
}

async function fixture(t: TestContext, overrides: Partial<Dependencies> = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'nearh-pp4-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  withEnv(t, { NEAR_AI_API_KEY: NEAR_AI_KEY, SCAMCHECK_HELD_DIR: join(dir, 'held') });
  const store = new ReceiptStore(join(dir, 'receipts'));
  // Past payments to the supplier, as the fixture's payee history (25, 25, 30 USD).
  for (const [i, amount] of fixtures.context.payee_history[0].amounts.entries()) {
    store.put({ request_id: `old-${i}`, agent: AGENT, rail: 'paypal', status: 'signed', outcome: 'paid', payee: PAYEE, amount, invoice_id: `INV2-OLD0-0000-0000-000${i}`, created_at: '2026-11-01T00:00:00.000Z', completed_at: '2026-11-01T00:00:00.000Z' });
  }
  const signatures: { request_id: string; shape: Record<string, unknown> }[] = [];
  const orders: PaypalOrder[] = [];
  const checks: CheckParams[] = [];
  const settings: { rail: string; check: 'real' | CheckResult['status'] } = { rail: 'submitted', check: 'real' };
  const reserved = new Set<string>();
  const modes: string[] = [];
  const rail = async (order: PaypalOrder): Promise<Record<string, unknown>> => {
    orders.push(order);
    const { request_id } = order;
    if (orders.filter(o => o.request_id === request_id).length > 1) return { status: 'blocked', request_id, error_code: 'PP3_DUPLICATE_REQUEST', detail: 'already handed to PP3' };
    switch (settings.rail) {
      case 'submitted': return { status: 'submitted', request_id, payout_batch_id: 'BATCH12345678', batch_status: 'PENDING' };
      case 'no-batch': return { status: 'submitted', request_id };
      case 'denied': return { status: 'submitted', request_id, payout_batch_id: 'BATCH12345678', batch_status: 'DENIED' };
      case 'other-id': return { status: 'submitted', request_id: 'pay-someone-else', payout_batch_id: 'BATCH12345678', batch_status: 'PENDING' };
      case 'refused': return { status: 'failed', request_id, error_code: 'PAYPAL_REFUSED', detail: `PayPal refused the payout to ${order.payee} (HTTP 422) token ${PP3_TOKEN}` };
      case 'blocked': return { status: 'blocked', request_id, error_code: 'PP3_PAYEE_NOT_ALLOWED', detail: 'payee removed' };
      case 'dup-batch': return { status: 'failed', request_id, error_code: 'PAYPAL_DUPLICATE_BATCH', detail: 'PayPal refused sender_batch_id as already used (batch BATCH12345678): this order was submitted before' };
      case 'dup-request': return { status: 'blocked', request_id, error_code: 'PP3_DUPLICATE_REQUEST', detail: 'request was already handed to PP3; not submitted again' };
      case 'failed-batch': return { status: 'failed', request_id, error_code: 'PAYPAL_REFUSED', payout_batch_id: 'BATCH12345678' };
      case 'pending': return { status: 'pending', request_id, error_code: 'PAYPAL_OUTCOME_UNKNOWN', detail: 'check the sandbox payouts' };
      default: throw new Error('socket hang up');
    }
  };
  const buyer = new Buyer({
    signer: { agent: AGENT } as unknown as NearX402Signer,
    store, allowedOrigins: [], secrets: [PP3_TOKEN, NEAR_KEY, NEAR_AI_KEY],
    view: async method => {
      if (method === 'get_payees') return fixtures.context.allowlisted_payees.map(receiver => ({ rail: 'paypal', receiver }));
      if (method === 'get_request') return null;
      throw new Error(`Unexpected view ${method}`);
    },
    // The contract's shape 4 checks that matter here: allowlist, cap, request_id dedupe.
    call: async (method, args) => {
      assert.equal(method, 'request_signature');
      const { request_id, shape } = args as { request_id: string; shape: { type: string; payee: string; amount: string; timestamp: number; order_ref?: string } };
      signatures.push({ request_id, shape });
      if (reserved.has(request_id)) throw new Error('ERR_DUPLICATE_REQUEST_ID');
      if (!fixtures.context.allowlisted_payees.includes(shape.payee)) throw new Error('Smart contract panicked: ERR_PAYPAL_PAYEE_NOT_ALLOWED');
      if (Number(shape.amount) > 50) throw new Error('Smart contract panicked: ERR_OVER_PER_PAYMENT_CAP');
      reserved.add(request_id);
      const text = shape.type === 'paypal_checkout'
        ? checkoutMessage(shape.amount, shape.payee, String(shape.order_ref), shape.timestamp, request_id)
        : paypalMessage(shape.amount, shape.payee, shape.timestamp, request_id);
      return { hash: 'near-tx-1', value: { shape: shape.type, rail: 'paypal', status: 'signed', signature: SIG, payload: { kind: 'message', text } } };
    },
    submit: async () => { throw new Error('SEPA rail must not be used'); },
    paypalRail: (mode = 'payout') => (modes.push(mode), rail),
    balance: async () => { throw new Error('PayPal has no agent EOA float'); },
    check: async params => {
      checks.push(params);
      if (settings.check === 'real') return checkAndHold(params, { fetch: okModel });
      const verdict = { result: settings.check === 'approved' ? 'ok' as const : 'skipped' as const, reason: null };
      return { status: settings.check, verdict };
    },
    readHeld: async () => [],
    verifySettlement: async () => { throw new Error('no settlement check on PayPal'); },
    verifyDecision: async () => {},
    ...overrides,
  });
  return { buyer, store, settings, signatures, orders, checks, modes, dir };
}

const poisoned = (name: string): Invoice => ({ ...baseline, ...fixtures.poisoned.find(p => p.name === name)!.invoice });

test('happy path: scam check, contract-signed shape 4 order, one PP3 hand-off, paid on the accepted batch', async t => {
  const f = await fixture(t);
  const result = await f.buyer.payPaypal({ invoice: baseline });
  assert.equal(result.status, 'paid', JSON.stringify(result));
  assert.equal(result.payout_batch_id, 'BATCH12345678');
  assert.equal(result.amount, '25.00');
  assert.equal(result.pay_to, 'bi…@acme-supplies.example');
  assert.equal(result.scam_check, 'ok');
  assert.equal(f.checks.length, 1);
  assert.equal(f.checks[0].rail, 'paypal');
  assert.equal(f.checks[0].payee_known, true);
  assert.deepEqual(f.signatures.map(s => s.request_id), [result.request_id]);
  const shape = f.signatures[0].shape;
  assert.deepEqual(Object.keys(shape).sort(), ['amount', 'payee', 'timestamp', 'type']);
  assert.equal(shape.type, 'paypal');
  assert.equal(shape.payee, PAYEE);
  assert.ok(Math.abs(Number(shape.timestamp) - Date.now() / 1000) < 5);
  assert.deepEqual(f.orders, [{ agent: AGENT, request_id: result.request_id, payee: PAYEE, amount: '25.00', timestamp: shape.timestamp, signature: SIG }]);
  const receipt = f.store.get(result.request_id)!;
  assert.equal(receipt.outcome, 'paid');
  assert.equal(receipt.payout_batch_id, 'BATCH12345678');
  assert.equal(receipt.invoice_id, baseline.invoice_id);
  const shown = await f.buyer.getReceipt(result.request_id);
  assert.equal(shown.payee, 'bi…@acme-supplies.example');
  assert.equal(shown.payout_batch_id, 'BATCH12345678');
});

for (const { name } of fixtures.poisoned) {
  test(`poisoned invoice ${name} is held by the scam check and never signed or sent to PP3`, async t => {
    const f = await fixture(t);
    const result = await f.buyer.payPaypal({ invoice: poisoned(name) });
    assert.equal(result.status, 'held', JSON.stringify(result));
    assert.equal(result.scam_check, 'suspicious');
    assert.equal(f.signatures.length, 0);
    assert.equal(f.orders.length, 0);
    assert.equal(f.store.get(result.request_id)?.status, 'held');
  });
}

test('a swapped payee that passes the scam check is still blocked by the contract, PP3 never called', async t => {
  const f = await fixture(t);
  f.settings.check = 'approved';
  const result = await f.buyer.payPaypal({ invoice: poisoned('changed_payee') });
  assert.equal(result.status, 'blocked', JSON.stringify(result));
  assert.equal(result.error_code, 'ERR_PAYPAL_PAYEE_NOT_ALLOWED');
  assert.equal(f.orders.length, 0);
});

test('without a NEAR AI key the scam check skips, so nothing is signed', async t => {
  const f = await fixture(t);
  delete process.env.NEAR_AI_API_KEY;
  const result = await f.buyer.payPaypal({ invoice: baseline });
  assert.equal(result.status, 'blocked', JSON.stringify(result));
  assert.equal(result.error_code, 'ERR_SCAM_CHECK_UNAVAILABLE');
  assert.equal(f.signatures.length, 0);
  assert.equal(f.orders.length, 0);
});

test('PP3 refusal is failed, PP3 blocked is blocked, and neither is paid', async t => {
  const f = await fixture(t);
  f.settings.rail = 'refused';
  const refused = await f.buyer.payPaypal({ invoice: baseline });
  assert.equal(refused.status, 'failed', JSON.stringify(refused));
  assert.equal(refused.error_code, 'PAYPAL_REFUSED');
  assert.equal(f.store.get(refused.request_id)?.outcome, 'failed');
  f.settings.rail = 'blocked';
  const blocked = await f.buyer.payPaypal({ invoice: { ...baseline, invoice_id: 'INV2-AAAA-BBBB-CCCC-0099' } });
  assert.equal(blocked.status, 'blocked');
  assert.equal(blocked.error_code, 'PP3_PAYEE_NOT_ALLOWED');
});

for (const mode of ['pending', 'throw', 'no-batch', 'denied']) {
  test(`PP3 ${mode} is uncertain, never paid, and never resubmitted`, async t => {
    const f = await fixture(t);
    f.settings.rail = mode;
    const result = await f.buyer.payPaypal({ invoice: baseline });
    assert.equal(result.status, 'uncertain', JSON.stringify(result));
    if (mode !== 'denied') assert.equal(result.payout_batch_id, undefined);
    assert.equal(f.store.get(result.request_id)?.outcome, 'uncertain');
    await f.buyer.getReceipt(result.request_id);
    await f.buyer.processDecisions();
    const again = await f.buyer.payPaypal({ invoice: baseline });
    assert.equal(again.status, 'blocked');
    assert.equal(again.error_code, 'DUPLICATE_INVOICE');
    assert.equal(again.request_id, result.request_id);
    assert.equal(f.orders.length, 1);
    assert.equal(f.signatures.length, 1);
  });
}

// A duplicate answer (or any batch id) means a payout may exist: fail closed, the invoice stays open.
for (const [mode, code] of [['dup-batch', 'PAYPAL_DUPLICATE_BATCH'], ['dup-request', 'PP3_DUPLICATE_REQUEST'], ['failed-batch', 'PAYPAL_REFUSED']]) {
  test(`PP3 ${code}${mode === 'failed-batch' ? ' with a batch id' : ''} is uncertain and the invoice is not paid again`, async t => {
    const f = await fixture(t);
    f.settings.rail = mode;
    const result = await f.buyer.payPaypal({ invoice: baseline });
    assert.equal(result.status, 'uncertain', JSON.stringify(result));
    assert.equal(result.error_code, code);
    assert.equal(f.store.get(result.request_id)?.outcome, 'uncertain');
    f.settings.rail = 'submitted';
    const again = await f.buyer.payPaypal({ invoice: baseline });
    assert.equal(again.status, 'blocked');
    assert.equal(again.error_code, 'DUPLICATE_INVOICE');
    assert.equal(again.request_id, result.request_id);
    assert.equal(f.signatures.length, 1);
    assert.equal(f.orders.length, 1);
  });
}

test('email masking applies to PayPal results only', async t => {
  const f = await fixture(t);
  const text = JSON.stringify({ detail: 'contact ops@seller.example' });
  assert.equal(f.buyer.redact(text), text);
  assert.ok(!f.buyer.redact(text, { emails: true }).includes('ops@seller.example'));
});

test('a PP3 answer for another request_id is not evidence of payment', async t => {
  const f = await fixture(t);
  f.settings.rail = 'other-id';
  const result = await f.buyer.payPaypal({ invoice: baseline });
  assert.equal(result.status, 'uncertain', JSON.stringify(result));
  assert.equal(f.store.get(result.request_id)?.outcome, 'uncertain');
});

test('duplicate: a paid invoice is not paid again, and PP3 refuses a resubmitted request_id', async t => {
  const f = await fixture(t);
  const first = await f.buyer.payPaypal({ invoice: baseline });
  assert.equal(first.status, 'paid');
  const second = await f.buyer.payPaypal({ invoice: baseline });
  assert.equal(second.status, 'blocked');
  assert.equal(second.error_code, 'DUPLICATE_INVOICE');
  assert.equal(f.orders.length, 1);
  assert.equal(f.signatures.length, 1);
  // PP3's own dedupe: the same request_id handed over again is blocked, not paid.
  const rail = await (f.buyer as unknown as { deps: Dependencies }).deps.paypalRail!()(f.orders[0]);
  assert.equal(rail.error_code, 'PP3_DUPLICATE_REQUEST');
  // A refused payment may be paid again under a fresh request_id.
  const g = await fixture(t);
  g.settings.rail = 'refused';
  const refused = await g.buyer.payPaypal({ invoice: baseline });
  g.settings.rail = 'submitted';
  const retry = await g.buyer.payPaypal({ invoice: baseline });
  assert.equal(retry.status, 'paid');
  assert.notEqual(retry.request_id, refused.request_id);
});

test('held invoice paid only after a verified owner approval, under a fresh request id', async t => {
  let decisions: HeldDecision[] = [];
  const f = await fixture(t, { readHeld: async () => decisions });
  const held = await f.buyer.payPaypal({ invoice: poisoned('urgency_wording') });
  assert.equal(held.status, 'held');
  const saved = f.store.get(held.request_id)!;
  const item = { id: saved.held_id!, agent: AGENT, rail: 'paypal', request_id: held.request_id, shape: saved.shape!, status: 'approved' as const, decided_at: new Date().toISOString(), created_at: new Date().toISOString(), invoice: { text: '', source: 'test' }, payee_known: true, payee_history: [], verdict: { result: 'suspicious' as const, reason: 'urgency' } };
  decisions = [{ ...item, shape: { ...saved.shape, payee: 'attacker@mailbox.example' } }];
  await f.buyer.processDecisions();
  assert.equal(f.store.get(held.request_id)?.status, 'blocked');
  assert.equal(f.orders.length, 0);

  const second = await fixture(t, { readHeld: async () => decisions });
  const held2 = await second.buyer.payPaypal({ invoice: poisoned('urgency_wording') });
  const saved2 = second.store.get(held2.request_id)!;
  decisions = [{ ...item, id: saved2.held_id!, request_id: held2.request_id, shape: saved2.shape! }];
  await Promise.all([second.buyer.processDecisions(), second.buyer.processDecisions()]);
  await second.buyer.processDecisions();
  const original = second.store.get(held2.request_id)!;
  assert.ok(original.replacement_request_id);
  const replacement = second.store.get(original.replacement_request_id)!;
  assert.equal(replacement.outcome, 'paid');
  assert.equal(replacement.approved_from_request_id, held2.request_id);
  assert.equal(replacement.invoice_id, poisoned('urgency_wording').invoice_id);
  assert.deepEqual(second.orders.map(o => o.request_id), [replacement.request_id]);
  assert.equal(second.orders[0].payee, PAYEE);
  // The held invoice was paid through its replacement; it is not paid a second time.
  const again = await second.buyer.payPaypal({ invoice: poisoned('urgency_wording') });
  assert.equal(again.error_code, 'DUPLICATE_INVOICE');
});

test('invoice input is validated before any receipt, check or signature', async t => {
  const f = await fixture(t);
  for (const invoice of [
    { ...baseline, amount: { currency: 'EUR', value: '25.00' } },
    { ...baseline, amount: { currency: 'USD', value: '25' } },
    { ...baseline, amount: { currency: 'USD', value: '0.00' } },
    { ...baseline, status: 'PAID' },
    { ...baseline, invoice_id: 'not-an-invoice' },
  ]) await assert.rejects(f.buyer.payPaypal({ invoice }));
  await assert.rejects(f.buyer.payPaypal({ invoice: baseline, payee: 'x@y.example' }));
  assert.equal(f.checks.length, 0);
  assert.equal(f.signatures.length, 0);
});

test('no credential or full payee in any MCP output, including a rail refusal that echoes them', async t => {
  const f = await fixture(t);
  const server = createServer(f.buyer);
  const client = new Client({ name: 'pp4-test', version: '1' });
  const [left, right] = InMemoryTransport.createLinkedPair();
  t.after(async () => { await client.close(); await server.close(); });
  await Promise.all([server.connect(left), client.connect(right)]);
  assert.ok((await client.listTools()).tools.some(tool => tool.name === 'pay_paypal'));
  const outputs: string[] = [];
  const paid = await client.callTool({ name: 'pay_paypal', arguments: { invoice: baseline } });
  outputs.push(JSON.stringify(paid));
  const id = (paid.structuredContent as { request_id: string }).request_id;
  outputs.push(JSON.stringify(await client.callTool({ name: 'get_receipt', arguments: { request_id: id } })));
  f.settings.rail = 'refused';
  outputs.push(JSON.stringify(await client.callTool({ name: 'pay_paypal', arguments: { invoice: { ...baseline, invoice_id: 'INV2-AAAA-BBBB-CCCC-0098' } } })));
  outputs.push(JSON.stringify(await client.callTool({ name: 'pay_paypal', arguments: { invoice: poisoned('changed_payee') } })));
  assert.equal((paid.structuredContent as { status: string }).status, 'paid');
  assert.match(outputs[2], /PAYPAL_REFUSED/);
  for (const text of outputs) {
    for (const secret of [PP3_TOKEN, NEAR_KEY, NEAR_AI_KEY, PAYEE, 'acme-payments@mailbox.example']) assert.ok(!text.includes(secret), `${secret} leaked: ${text}`);
  }
  // The order handed to PP3 carries no credential either: the token travels only in PP3's auth header.
  for (const order of f.orders) assert.ok(!JSON.stringify(order).includes(PP3_TOKEN));
});

test('programmatic entry pays and returns redacted output', async t => {
  const f = await fixture(t);
  const result = await payPaypalInvoice(baseline, { buyer: f.buyer });
  assert.equal(result.status, 'paid');
  assert.ok(!JSON.stringify(result).includes(PAYEE));
});

test('PP3 client: loopback endpoint, bearer token, pre-claim refusals failed, others uncertain', async () => {
  assert.throws(() => pp3Endpoint('https://rail.example/payouts'));
  assert.throws(() => pp3Endpoint('http://127.0.0.1:8788/other'));
  const order: PaypalOrder = { agent: AGENT, request_id: 'pay-1', payee: PAYEE, amount: '25.00', timestamp: 1, signature: SIG };
  const seen: RequestInit[] = [];
  const answer = (status: number, body?: unknown) => pp3Client('http://127.0.0.1:8788/payouts', PP3_TOKEN, (async (_url: string | URL | Request, init?: RequestInit) => {
    seen.push(init!);
    return new Response(body === undefined ? 'oops' : JSON.stringify(body), { status });
  }) as typeof fetch);
  const ok = await answer(200, { status: 'submitted', request_id: 'pay-1', payout_batch_id: 'BATCH12345678' })(order);
  assert.equal(ok.status, 'submitted');
  assert.equal(new Headers(seen[0].headers).get('authorization'), `Bearer ${PP3_TOKEN}`);
  assert.equal(seen[0].redirect, 'error');
  assert.equal((await answer(401, { error: 'no' })(order)).status, 'failed');
  assert.equal((await answer(502, { status: 'failed', request_id: 'pay-1', error_code: 'PP3_ERROR', detail: 'rpc' })(order)).status, 'failed');
  await assert.rejects(answer(500, { error: 'internal error' })(order));
  await assert.rejects(answer(200)(order));
});

test('maskEmail masks a Venmo handle as PP3 and the dashboard do (PayPal audit 2 L2)', async () => {
  const { maskEmail: agentMask } = await import('../src/policy.ts');
  const { maskEmail: railMask } = await import('../../../rails/paypal/src/payout.ts');
  for (const p of ['@demo-supplier', '@abcde', 'supplier@example.com', 'a@example.com', 'none']) assert.equal(agentMask(p), railMask(p), p);
  assert.equal(agentMask('@demo-supplier'), '@de…');
});

// PP-V1: pay_paypal with mode checkout (pay_paypal_checkout): shape 5, the rail's /checkout.
test('checkout mode: scam check, shape 5 signed with the invoice id as order_ref, one /checkout hand-off', async t => {
  const f = await fixture(t);
  const { orders } = f;
  f.settings.rail = 'submitted';
  const result = await f.buyer.payPaypal({ invoice: baseline, mode: 'checkout' });
  assert.equal(result.status, 'paid', JSON.stringify(result));
  assert.equal(f.checks.length, 1, 'the scam check ran before the request');
  assert.deepEqual(f.modes, ['checkout']);
  const shape = f.signatures[0].shape;
  assert.equal(shape.type, 'paypal_checkout');
  assert.equal(shape.order_ref, baseline.invoice_id);
  assert.equal(orders.length, 1);
  assert.equal(orders[0].order_ref, baseline.invoice_id);
  assert.ok(!JSON.stringify(orders[0]).includes('vault'), 'the agent never handles a vault id');
});

test('checkout mode: a poisoned invoice is held by the scam check; a swapped merchant past it is blocked by the contract', async t => {
  const f = await fixture(t);
  const held = await f.buyer.payPaypal({ invoice: poisoned('changed_payee'), mode: 'checkout' });
  assert.equal(held.status, 'held', JSON.stringify(held));
  assert.equal(f.signatures.length, 0);
  const g = await fixture(t);
  g.settings.check = 'approved';
  const blocked = await g.buyer.payPaypal({ invoice: poisoned('changed_payee'), mode: 'checkout' });
  assert.equal(blocked.status, 'blocked');
  assert.equal(blocked.error_code, 'ERR_PAYPAL_PAYEE_NOT_ALLOWED');
  assert.equal(g.orders.length, 0);
});

test('checkout mode: a capture id on a failed payout is uncertain, never failed', async t => {
  const f = await fixture(t, {
    paypalRail: () => async order => ({ status: 'failed', request_id: order.request_id, error_code: 'PAYPAL_RATE_LIMITED', capture_id: '0PL46169Y5983610B', detail: 'charge captured' }),
  });
  const result = await f.buyer.payPaypal({ invoice: baseline, mode: 'checkout' });
  assert.equal(result.status, 'uncertain', JSON.stringify(result));
  assert.equal(result.capture_id, '0PL46169Y5983610B');
});

test('pp3Endpoint accepts /checkout only when asked', () => {
  assert.throws(() => pp3Endpoint('http://127.0.0.1:8788/checkout'));
  assert.equal(pp3Endpoint('http://127.0.0.1:8788/checkout', '/checkout'), 'http://127.0.0.1:8788/checkout');
  assert.ok(pp3Client('http://127.0.0.1:8788/checkout', PP3_TOKEN, fetch, '/checkout'));
});
