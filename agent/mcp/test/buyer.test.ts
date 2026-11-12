import { strict as assert } from 'node:assert';
import { test, type TestContext } from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NearX402Signer } from '@nearh/agent-signer';
import { encodePaymentRequiredHeader, encodePaymentResponseHeader } from '@x402/core/http';
import { FakeNear, CONTRACT, PAY_TO, USDC } from '../../signer/test/fake-near.ts';
import { Buyer, type Dependencies, type HeldDecision } from '../src/buyer.ts';
import { checkAndHold } from '../../../scamcheck/src/check.ts';
import { ReceiptStore } from '../src/store.ts';
import { createServer } from '../src/server.ts';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import type { CheckResult } from '../../../scamcheck/src/check.ts';

const requirements = { scheme: 'exact', network: 'eip155:84532' as const, asset: USDC, payTo: PAY_TO, amount: '10000', maxTimeoutSeconds: 300, extra: { name: 'USDC', version: '2' } };
const url = 'https://seller.example/weather';
const payment = { url, reason: 'Weather for the trip' };
const sepa = { iban: 'GB33BUKB20201555555555', amount: '1.50', memo: 'invoice', reason: 'Supplier invoice' };

async function fixture(t: TestContext, overrides: Partial<Dependencies> = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'nearh-a2-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const near = new FakeNear();
  let sendAttempts = 0;
  const rpc: typeof near.rpc = async (method, params) => { if (method === 'send_tx') sendAttempts++; return near.rpc(method, params); };
  const signer = await NearX402Signer.connect({ near: rpc, key: near.key.key, contractId: CONTRACT });
  const calls: { method: string; args: object }[] = [];
  let checks = 0;
  let paidRequests = 0;
  let railCalls = 0;
  const settings = { verdict: 'approved' as CheckResult['status'], payTo: PAY_TO, rail: 'submitted', balance: '100000000000000000000' };
  const store = new ReceiptStore(dir);
  const buyer = new Buyer({
    signer, store, allowedOrigins: ['https://seller.example'],
    view: async (method: string, args: object) => {
      calls.push({ method, args });
      if (method === 'get_payees') return [{ rail: 'x402', pay_to: PAY_TO }, { rail: 'sepa', iban: sepa.iban }];
      if (method === 'get_request') return null;
      if (method === 'get_mandate') return { max_validity_secs: 300 };
      throw new Error(`Unexpected view ${method}`);
    },
    call: async (method: string, args: object) => {
      calls.push({ method, args });
      if (method === 'revoke_self') return { hash: 'near-revoke', value: { agent: signer.agent, revoked: true, key_deleted: false } };
      return { hash: 'near-payout', value: { shape: 'payout', status: 'signed', signature: { r: '0x1', s: '0x2', v: 27 }, payload: { kind: 'message', text: 'signed' } } };
    },
    check: async params => {
      checks++;
      const verdict = { result: settings.verdict === 'held' ? 'suspicious' as const : 'ok' as const, reason: null };
      return { status: settings.verdict, verdict, ...(settings.verdict === 'held' ? { item: { ...params, id: `held-${params.request_id}`, created_at: new Date().toISOString(), verdict, status: 'held' as const, decided_at: null } } : {}) };
    },
    verifySettlement: async () => true,
    verifyDecision: async () => { assert.equal(settings.verdict, 'held'); },
    fetch: async (input, init) => {
      assert.equal(input instanceof Request ? input.url : String(input), url);
      if (new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined)).has('payment-signature')) {
        paidRequests++;
        return new Response('weather', { headers: { 'payment-response': encodePaymentResponseHeader({ success: true, network: 'eip155:84532', transaction: `0x${'ab'.repeat(32)}` }) } });
      }
      return new Response('', { status: 402, headers: { 'payment-required': encodePaymentRequiredHeader({ x402Version: 2, resource: { url }, accepts: [{ ...requirements, payTo: settings.payTo }] }) } });
    },
    submit: async (body) => { railCalls++; assert.equal(body.agent, signer.agent); return { status: settings.rail, request_id: body.request_id, monerium_order_id: 'order-1' }; },
    balance: async () => BigInt(settings.balance),
    ...overrides,
  });
  return { buyer, near, settings, store, dir, calls, attempts: () => sendAttempts, stats: () => ({ checks, paidRequests, railCalls }) };
}

test('MCP lists exactly the five contract-approved tools and refuses owner tools', async t => {
  const { buyer } = await fixture(t);
  const server = createServer(buyer);
  const client = new Client({ name: 'a2-test', version: '1' });
  const [left, right] = InMemoryTransport.createLinkedPair();
  t.after(async () => { await client.close(); await server.close(); });
  await Promise.all([server.connect(left), client.connect(right)]);
  assert.deepEqual((await client.listTools()).tools.map(tool => tool.name).sort(), ['get_receipt', 'pay_paypal', 'pay_sepa', 'pay_x402', 'revoke']);
  assert.equal((await client.callTool({ name: 'top_up', arguments: {} })).isError, true);
  assert.equal((await client.callTool({ name: 'revoke', arguments: { agent: 'other' } })).isError, true);
});

test('suspicious x402 request is held without signing or retrying payment', async t => {
  const { buyer, settings, near, stats } = await fixture(t);
  settings.verdict = 'held';
  const result = await buyer.payX402(payment);
  assert.equal(result.status, 'held', JSON.stringify(result));
  assert.equal(near.requests.length, 0);
  assert.deepEqual(stats(), { checks: 1, paidRequests: 0, railCalls: 0 });
  assert.equal((await buyer.getReceipt(result.request_id)).status, 'held');
});

test('scam ok cannot bypass contract rejection of swapped payTo', async t => {
  const { buyer, settings, near, stats, attempts } = await fixture(t);
  settings.payTo = '0x1111111111111111111111111111111111111111';
  const result = await buyer.payX402(payment);
  assert.equal(result.status, 'blocked', JSON.stringify(result));
  assert.equal(result.error_code, 'ERR_PAYEE_NOT_ALLOWED');
  assert.equal(attempts(), 1);
  assert.equal(near.requests.length, 0);
  assert.equal(stats().paidRequests, 0);
});

test('open x402 client uses A1, records the NEAR signature and Base settlement separately', async t => {
  const { buyer, near, store } = await fixture(t);
  const result = await buyer.payX402(payment);
  assert.equal(result.status, 'paid', JSON.stringify(result));
  assert.equal(result.response, 'weather');
  assert.equal(near.requests.length, 1);
  assert.equal(near.requests[0].request_id, result.request_id);
  const receipt = await buyer.getReceipt(result.request_id);
  assert.equal(receipt.status, 'signed');
  assert.equal(receipt.tx_hash, `0x${'ab'.repeat(32)}`);
  assert.ok(receipt.near_tx_hash);
  assert.equal(new ReceiptStore(store.dir).get(result.request_id)?.outcome, 'paid');
});

test('SEPA requests payout signature before M1, with canonical amount and server-side timestamp', async t => {
  const { buyer, calls, stats } = await fixture(t);
  const result = await buyer.paySepa(sepa);
  assert.equal(result.status, 'submitted');
  const call = calls.find(c => c.method === 'request_signature');
  assert.ok(call);
  const { timestamp, ...shape } = (call.args as { shape: { timestamp: number } }).shape;
  assert.deepEqual({ ...call.args, shape }, { request_id: result.request_id, shape: { type: 'payout', iban: sepa.iban, amount: '1.5' } });
  assert.ok(Math.abs(timestamp - Math.floor(Date.now() / 1000)) <= 2, 'server-side timestamp');
  assert.equal(stats().railCalls, 1);
  assert.equal((await buyer.getReceipt(result.request_id)).monerium_order_id, 'order-1');
});

test('held SEPA never signs or calls M1; low float gives owner notice without top-up', async t => {
  const { buyer, settings, calls, stats } = await fixture(t);
  settings.verdict = 'held';
  assert.equal((await buyer.paySepa(sepa)).status, 'held');
  assert.equal(calls.some(c => c.method === 'request_signature'), false);
  assert.equal(stats().railCalls, 0);
  settings.verdict = 'approved';
  settings.balance = '0';
  const low = await buyer.paySepa(sepa);
  assert.equal(low.status, 'blocked');
  assert.equal(low.error_code, 'LOW_FLOAT');
  assert.match(String(low.detail), /owner/i);
  assert.equal(stats().railCalls, 0);
});

test('self-revoke uses no agent argument and reports state even when key deletion fails', async t => {
  const { buyer, calls } = await fixture(t);
  assert.deepEqual(await buyer.revoke(), { revoked: true, key_deleted: false, tx_hash: 'near-revoke' });
  assert.deepEqual(calls.find(c => c.method === 'revoke_self')?.args, {});
});

test('real SC1 timeout holds before any signature, and without a key explicitly skips', async t => {
  const previousKey = process.env.NEAR_AI_API_KEY;
  const previousDir = process.env.SCAMCHECK_HELD_DIR;
  t.after(() => {
    if (previousKey === undefined) delete process.env.NEAR_AI_API_KEY; else process.env.NEAR_AI_API_KEY = previousKey;
    if (previousDir === undefined) delete process.env.SCAMCHECK_HELD_DIR; else process.env.SCAMCHECK_HELD_DIR = previousDir;
  });
  const f = await fixture(t, { check: params => checkAndHold(params, { fetch: async () => { throw new DOMException('Timeout', 'AbortError'); } }) });
  process.env.SCAMCHECK_HELD_DIR = f.dir;
  process.env.NEAR_AI_API_KEY = 'offline-test-key';
  assert.equal((await f.buyer.payX402(payment)).status, 'held');
  assert.equal(f.attempts(), 0);
  delete process.env.NEAR_AI_API_KEY;
  const skipped = await f.buyer.payX402(payment);
  assert.equal(skipped.status, 'paid');
  assert.equal(skipped.scam_check, 'skipped');
});

test('SEPA contract rejection after scam ok never calls M1', async t => {
  const f = await fixture(t, { call: async () => { throw new Error('ERR_IBAN_NOT_ALLOWED: iban not in mandate'); } });
  const result = await f.buyer.paySepa(sepa);
  assert.equal(result.status, 'blocked');
  assert.equal(result.error_code, 'ERR_IBAN_NOT_ALLOWED');
  assert.equal(f.stats().checks, 1);
  assert.equal(f.stats().railCalls, 0);
});

test('unsigned payout never reaches M1; its uncertain outcome is retained', async t => {
  const f = await fixture(t, { call: async () => ({ hash: 'near-timeout', value: { shape: 'payout', status: 'unknown', signature: null } }) });
  const result = await f.buyer.paySepa(sepa);
  assert.equal(result.status, 'pending');
  assert.equal(f.stats().railCalls, 0);
  assert.equal((await f.buyer.getReceipt(result.request_id)).status, 'unknown');
});

test('uncertain M1 transport is never resubmitted by receipt lookup or decision polling', async t => {
  let submits = 0;
  const f = await fixture(t, { submit: async () => { submits++; throw new Error('M1 timeout'); }, readHeld: async () => [] });
  const result = await f.buyer.paySepa(sepa);
  assert.equal(result.status, 'pending');
  assert.equal((await f.buyer.getReceipt(result.request_id)).status, 'signed');
  await f.buyer.processDecisions();
  assert.equal(submits, 1);
  assert.equal(new ReceiptStore(f.dir).get(result.request_id)?.outcome, 'pending');
});

test('receipt follows the contract status after restart and isolates another agent', async t => {
  const f = await fixture(t, { view: async () => ({ status: 'unknown', rail: 'sepa' }) });
  const receipt = await f.buyer.getReceipt('old-request');
  assert.equal(receipt.status, 'unknown');
  f.store.put({ request_id: 'other-agent', agent: 'someone-else', status: 'signed', rail: 'sepa' });
  await assert.rejects(f.buyer.getReceipt('other-agent'), /another agent/);
  await assert.rejects(f.buyer.getReceipt('../outside'), /Invalid|invalid|format/);
});

test('held approval creates one linked fresh payout reservation without replaying the old id', async t => {
  let decisions: HeldDecision[] = [];
  const f = await fixture(t, { readHeld: async () => decisions });
  f.settings.verdict = 'held';
  const held = await f.buyer.paySepa(sepa);
  const saved = f.store.get(held.request_id)!;
  decisions = [{ id: saved.held_id!, agent: saved.agent, rail: 'sepa', request_id: held.request_id, shape: saved.shape!, memo: sepa.memo, status: 'approved', decided_at: new Date().toISOString(), created_at: new Date().toISOString(), invoice: { text: '', source: 'test' }, payee_known: true, payee_history: [], verdict: { result: 'suspicious', reason: 'test' } }];
  await Promise.all([f.buyer.processDecisions(), f.buyer.processDecisions()]);
  await f.buyer.processDecisions();
  const original = f.store.get(held.request_id)!;
  assert.ok(original.replacement_request_id);
  assert.notEqual(original.replacement_request_id, held.request_id);
  const replacement = f.store.get(original.replacement_request_id)!;
  assert.equal(replacement.approved_from_request_id, held.request_id);
  assert.deepEqual(f.calls.find(c => c.method === 'request_signature')?.args, { request_id: replacement.request_id, shape: replacement.shape });
  assert.equal(replacement.shape?.iban, saved.shape?.iban);
  assert.equal(replacement.shape?.amount, saved.shape?.amount);
  assert.equal(f.stats().railCalls, 1);
});

test('owner rejection of a held payment never signs; tampered approval fails closed', async t => {
  let decisions: HeldDecision[] = [];
  const f = await fixture(t, { readHeld: async () => decisions });
  f.settings.verdict = 'held';
  const held = await f.buyer.paySepa(sepa);
  const saved = f.store.get(held.request_id)!;
  const item = { id: saved.held_id!, agent: saved.agent, rail: 'sepa', request_id: held.request_id, shape: saved.shape!, status: 'rejected' as const, decided_at: new Date().toISOString(), created_at: new Date().toISOString(), invoice: { text: '', source: 'test' }, payee_known: true, payee_history: [], verdict: { result: 'suspicious' as const, reason: 'test' } };
  decisions = [item];
  await f.buyer.processDecisions();
  assert.equal((await f.buyer.getReceipt(held.request_id)).status, 'blocked');
  assert.equal(f.stats().railCalls, 0);
  const tampered = await f.buyer.paySepa(sepa);
  decisions = [{ ...item, request_id: tampered.request_id, status: 'approved', shape: { ...saved.shape, amount: '999' } }];
  await f.buyer.processDecisions();
  assert.equal(f.store.get(tampered.request_id)?.status, 'blocked');
  assert.equal(f.stats().railCalls, 0);
});

test('x402 cannot follow a redirect, return a fake paid result, or auto retry a signature', async t => {
  const f = await fixture(t, { fetch: async input => {
    assert.ok(input instanceof Request);
    assert.equal(input.redirect, 'error');
    return new Response('free resource');
  } });
  const result = await f.buyer.payX402(payment);
  assert.equal(result.status, 'failed');
  assert.equal(f.attempts(), 0);
  await assert.rejects(f.buyer.payX402({ url: 'http://169.254.169.254/metadata', reason: 'ssrf' }), /origin/);
  await assert.rejects(f.buyer.paySepa({ ...sepa, top_up: true }), /Unrecognized/);
  await assert.rejects(f.buyer.paySepa({ ...sepa, amount: '0' }), /greater than zero/);
});

test('receipt refresh preserves payment completion while NEAR lookup is in flight', async t => {
  let finishView!: (value: unknown) => void;
  const lookup = new Promise<unknown>(resolve => { finishView = resolve; });
  const f = await fixture(t, { view: async () => lookup });
  const initial = { request_id: 'refresh-race', agent: 'agent-1', rail: 'sepa' as const, status: 'pending' as const };
  f.store.put(initial);
  const refresh = f.buyer.getReceipt(initial.request_id);
  f.store.put({ ...initial, status: 'signed', outcome: 'submitted', monerium_order_id: 'accepted-order', near_tx_hash: 'near-completed', tx_hash: 'base-completed' });
  finishView({ rail: 'sepa', status: 'signed' });
  const receipt = await refresh;
  assert.equal(receipt.outcome, 'submitted');
  assert.equal(receipt.monerium_order_id, 'accepted-order');
  assert.equal(receipt.near_tx_hash, 'near-completed');
  assert.equal(receipt.tx_hash, 'base-completed');
  assert.equal(new ReceiptStore(f.dir).get(initial.request_id)?.monerium_order_id, 'accepted-order');
});

for (const failure of ['oversized', 'interrupted'] as const) {
  test(`settlement survives ${failure} paid resource body`, async t => {
    let attempts = 0;
    const f = await fixture(t, { fetch: async input => {
      assert.ok(input instanceof Request);
      if (!input.headers.has('payment-signature')) {
        return new Response('', { status: 402, headers: { 'payment-required': encodePaymentRequiredHeader({ x402Version: 2, resource: { url }, accepts: [requirements] }) } });
      }
      attempts++;
      const body = failure === 'oversized' ? 'x'.repeat(64_001) : new ReadableStream({ pull(controller) { controller.error(new Error('Interrupted body')); } });
      return new Response(body, { headers: { 'payment-response': encodePaymentResponseHeader({ success: true, network: 'eip155:84532', transaction: `0x${'ab'.repeat(32)}` }) } });
    } });
    const result = await f.buyer.payX402(payment);
    assert.equal(result.status, 'paid');
    assert.equal(result.tx_hash, `0x${'ab'.repeat(32)}`);
    assert.match(String(result.detail), /resource/i);
    assert.equal(result.response, undefined);
    assert.equal(attempts, 1);
    const receipt = await f.buyer.getReceipt(result.request_id);
    assert.equal(receipt.outcome, 'paid');
    assert.equal(receipt.tx_hash, result.tx_hash);
    assert.equal(new ReceiptStore(f.dir).get(result.request_id)?.outcome, 'paid');
  });
}

test('unconfirmed or forged settlement header stays pending and is excluded from payee history', async t => {
  const histories: unknown[] = [];
  let confirmed = false;
  const f = await fixture(t, {
    verifySettlement: async () => confirmed,
    check: async params => { histories.push(params.payee_history); return { status: 'approved', verdict: { result: 'ok', reason: null } }; },
  });
  const first = await f.buyer.payX402(payment);
  assert.equal(first.status, 'pending');
  assert.equal(first.tx_hash, `0x${'ab'.repeat(32)}`);
  assert.equal(f.store.get(first.request_id)?.outcome, 'pending');
  assert.equal((await f.buyer.payX402(payment)).status, 'pending');
  assert.deepEqual(histories, [[], []]);
  confirmed = true;
  assert.equal((await f.buyer.getReceipt(first.request_id)).outcome, 'paid');
});

test('low float emits an owner notice without signing', async t => {
  const notices: string[] = [];
  const f = await fixture(t, { notifyOwner: message => { notices.push(message); } });
  f.settings.balance = '0';
  const result = await f.buyer.payX402(payment);
  assert.equal(result.error_code, 'LOW_FLOAT');
  assert.equal(f.attempts(), 0);
  assert.equal(notices.length, 1);
  assert.match(notices[0], /owner|float/i);
});

for (const failure of ['payees', 'balance', 'window'] as const) {
  test(`pre-sign ${failure} failure is failed rather than uncertain`, async t => {
    const f = await fixture(t, failure === 'payees' ? { view: async () => { throw new Error('View unavailable'); } } : failure === 'balance' ? { balance: async () => { throw new Error('Base unavailable'); } } : {
      fetch: async () => new Response('', { status: 402, headers: { 'payment-required': encodePaymentRequiredHeader({ x402Version: 2, resource: { url }, accepts: [{ ...requirements, maxTimeoutSeconds: 1 }] }) } }),
    });
    const result = await f.buyer.payX402(payment);
    assert.equal(result.status, 'failed');
    assert.notEqual(f.store.get(result.request_id)?.status, 'unknown');
    assert.equal(f.attempts(), 0);
  });
}

test('scam history uses recorded completion time rather than lookup time', async t => {
  let history: unknown;
  const f = await fixture(t, { check: async params => { history = params.payee_history; return { status: 'approved', verdict: { result: 'ok', reason: null } }; } });
  f.store.put({ request_id: 'older-payment', agent: 'agent-1', rail: 'x402', status: 'signed', outcome: 'paid', amount: '10000', payee: PAY_TO, created_at: '2026-11-01T00:00:00.000Z', completed_at: '2026-11-01T00:01:00.000Z' });
  assert.equal((await f.buyer.payX402(payment)).status, 'paid');
  assert.deepEqual(history, [{ payee: PAY_TO, amounts: ['10000'], last_seen: '2026-11-01T00:01:00.000Z' }]);
});

test('receipt without a local file derives SEPA rail from payout shape', async t => {
  const f = await fixture(t, { view: async () => ({ shape: 'payout', status: 'signed' }) });
  assert.equal((await f.buyer.getReceipt('old-payout')).rail, 'sepa');
});

test('seller resource URL mismatch fails before signing', async t => {
  const f = await fixture(t, { fetch: async () => new Response('', { status: 402, headers: { 'payment-required': encodePaymentRequiredHeader({ x402Version: 2, resource: { url: 'https://different.example/invoice' }, accepts: [requirements] }) } }) });
  const result = await f.buyer.payX402(payment);
  assert.equal(result.status, 'failed');
  assert.equal(f.attempts(), 0);
});

test('bad held decision is blocked while a later valid approval is processed', async t => {
  let decisions: HeldDecision[] = [];
  const f = await fixture(t, { readHeld: async () => decisions });
  f.settings.verdict = 'held';
  const bad = await f.buyer.paySepa(sepa);
  const good = await f.buyer.paySepa(sepa);
  decisions = [bad, good].map(result => {
    const receipt = f.store.get(result.request_id)!;
    return { id: receipt.held_id!, agent: receipt.agent, rail: receipt.rail, request_id: receipt.request_id, shape: result === bad ? { ...receipt.shape, amount: '999' } : receipt.shape!, status: 'approved', decided_at: new Date().toISOString(), created_at: new Date().toISOString(), invoice: { text: '', source: 'test' }, payee_known: true, payee_history: [], verdict: { result: 'suspicious', reason: 'test' } };
  });
  await f.buyer.processDecisions();
  assert.equal(f.store.get(bad.request_id)?.status, 'blocked');
  assert.equal(f.store.get(f.store.get(good.request_id)!.replacement_request_id!)?.outcome, 'submitted');
  assert.equal(f.stats().railCalls, 1);
});

test('stale payout approval creates a fresh timestamp and request id with audit links and no replay', async t => {
  let decisions: HeldDecision[] = [];
  const f = await fixture(t, { readHeld: async () => decisions });
  f.settings.verdict = 'held';
  const result = await f.buyer.paySepa(sepa);
  const receipt = f.store.get(result.request_id)!;
  const shape = { ...receipt.shape, timestamp: Math.floor(Date.now() / 1000) - 1000 };
  f.store.put({ ...receipt, shape });
  decisions = [{ id: receipt.held_id!, agent: receipt.agent, rail: receipt.rail, request_id: receipt.request_id, shape, status: 'approved', decided_at: new Date().toISOString(), created_at: new Date().toISOString(), invoice: { text: '', source: 'test' }, payee_known: true, payee_history: [], verdict: { result: 'suspicious', reason: 'test' } }];
  await f.buyer.processDecisions();
  const original = f.store.get(result.request_id)!;
  assert.ok(original.replacement_request_id);
  const replacement = f.store.get(original.replacement_request_id)!;
  assert.notEqual(replacement.request_id, result.request_id);
  assert.equal(replacement.approved_from_request_id, result.request_id);
  assert.deepEqual(original.shape, shape);
  assert.equal(replacement.shape?.iban, receipt.shape?.iban);
  assert.equal(replacement.shape?.amount, receipt.shape?.amount);
  assert.ok(Number(replacement.shape?.timestamp) > Number(shape.timestamp));
  assert.ok(Number(replacement.shape?.timestamp) <= Math.floor(Date.now() / 1000));
  assert.equal(replacement.outcome, 'submitted');
  await f.buyer.processDecisions();
  assert.equal(f.calls.filter(call => call.method === 'request_signature').length, 1);
  assert.equal(f.stats().railCalls, 1);
});

test('owner proof verification failure prevents a forged file approval from signing', async t => {
  let decisions: HeldDecision[] = [];
  const f = await fixture(t, { readHeld: async () => decisions, verifyDecision: async () => { throw new Error('No valid owner assertion'); } });
  f.settings.verdict = 'held';
  const result = await f.buyer.paySepa(sepa);
  const receipt = f.store.get(result.request_id)!;
  decisions = [{ id: receipt.held_id!, agent: receipt.agent, rail: receipt.rail, request_id: receipt.request_id, shape: receipt.shape!, status: 'approved', decided_at: new Date().toISOString(), created_at: new Date().toISOString(), invoice: { text: '', source: 'forged file' }, payee_known: true, payee_history: [], verdict: { result: 'suspicious', reason: null } }];
  await f.buyer.processDecisions();
  assert.equal(f.store.get(result.request_id)?.status, 'blocked');
  assert.equal(f.stats().railCalls, 0);
});


for (const unavailable of ['unmined', 'RPC failure']) test(`pending ${unavailable} settlement preserves content for later confirmed receipt`, async t => {
  let confirmed = false;
  const f = await fixture(t, { verifySettlement: async () => {
    if (!confirmed && unavailable === 'RPC failure') throw new Error('Base RPC unavailable');
    return confirmed;
  } });
  const result = await f.buyer.payX402(payment);
  assert.equal(result.status, 'pending');
  assert.equal(result.response, undefined);
  assert.equal(new ReceiptStore(f.dir).get(result.request_id)?.response, 'weather');
  assert.equal((await f.buyer.getReceipt(result.request_id)).response, undefined);
  confirmed = true;
  const receipt = await f.buyer.getReceipt(result.request_id);
  assert.equal(receipt.outcome, 'paid');
  assert.equal(receipt.response, 'weather');
  assert.equal(receipt.detail, undefined);
  assert.equal(f.stats().paidRequests, 1);
  assert.equal(f.near.requests.length, 1);
});

test('equivalent canonical seller URLs are accepted before signing', async t => {
  const f = await fixture(t);
  const result = await f.buyer.payX402({ ...payment, url: 'https://SELLER.EXAMPLE:443/weather' });
  assert.equal(result.status, 'paid');
  assert.equal(f.near.requests.length, 1);
});


for (const delivery of ['oversized', 'interrupted', 'http503']) test(`later settlement confirmation retains ${delivery} delivery evidence`, async t => {
  let confirmed = false;
  let purchases = 0;
  const f = await fixture(t, {
    verifySettlement: async () => confirmed,
    fetch: async input => {
      assert.ok(input instanceof Request);
      if (!input.headers.has('payment-signature')) {
        return new Response('', { status: 402, headers: { 'payment-required': encodePaymentRequiredHeader({ x402Version: 2, resource: { url }, accepts: [requirements] }) } });
      }
      purchases++;
      const body = delivery === 'oversized' ? 'x'.repeat(64_001) : delivery === 'interrupted'
        ? new ReadableStream({ pull(controller) { controller.error(new Error('Interrupted body')); } }) : 'Service unavailable';
      return new Response(body, { status: delivery === 'http503' ? 503 : 200, headers: { 'payment-response': encodePaymentResponseHeader({ success: true, network: 'eip155:84532', transaction: `0x${'ab'.repeat(32)}` }) } });
    },
  });
  const result = await f.buyer.payX402(payment);
  assert.equal(result.status, 'pending');
  assert.equal(result.response, undefined);
  confirmed = true;
  const receipt = await f.buyer.getReceipt(result.request_id);
  assert.equal(receipt.outcome, 'paid');
  assert.equal(receipt.error_code, undefined);
  if (delivery === 'http503') {
    assert.equal(receipt.response, 'Service unavailable');
    assert.match(receipt.detail ?? '', /HTTP 503/);
  } else {
    assert.equal(receipt.response, undefined);
    assert.match(receipt.detail ?? '', /resource delivery failed/i);
  }
  assert.equal(new ReceiptStore(f.dir).get(result.request_id)?.detail, receipt.detail);
  assert.equal(purchases, 1);
  assert.equal(f.near.requests.length, 1);
});
