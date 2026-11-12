import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { once } from 'node:events';
import { privateKeyToAccount } from 'viem/accounts';
import { hashMessage } from 'viem';
import { server } from '../../../rails/monerium/src/server.ts';
import { memoryStore } from '../../../rails/monerium/src/store.ts';
import { m1Client, m1Endpoint } from '../src/runtime.ts';
import { mockDerivedKey, CONTRACT, AGENT } from '../../signer/test/fake-near.ts';

const token = 'offline-agent-token-12345678901234567890';
const iban = 'GB33BUKB20201555555555';
const orderId = '00000000-0000-4000-8000-000000000001';

test('authenticated A2 client reaches real M1 verification and submission once', async t => {
  const account = privateKeyToAccount(mockDerivedKey(CONTRACT, AGENT));
  const text = `Send EUR 1.5 to ${iban} at ${new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')}`;
  const signature = await account.signMessage({ message: text });
  const input = { agent: AGENT, request_id: 'a2-service-payout', iban, amount: '1.5', memo: 'Test invoice' };
  const reservation = {
    key: { agent: AGENT, caller: { kind: 'agent' }, request_id: input.request_id },
    shape: 'payout', rail: 'sepa', status: 'signed', valid_before: Math.floor(Date.now() / 1000) + 240,
    payload: { kind: 'message', text }, digest: hashMessage(text),
    signature: { r: signature.slice(0, 66), s: `0x${signature.slice(66, 130)}`, v: Number.parseInt(signature.slice(130), 16) },
  };
  let posts = 0;
  let authentications = 0;
  const service = server({
    near: {
      getAgent: async () => ({ evm_address: account.address, revoked: false }),
      getRequest: async key => { assert.deepEqual(key, reservation.key); return reservation; },
      getPayees: async () => [{ rail: 'sepa', iban }],
    },
    monerium: {
      authenticate: async () => { authentications++; },
      request: async (method, path, body) => {
        posts++; assert.equal(method, 'POST'); assert.equal(path, '/orders');
        assert.equal(body.signature, signature); assert.equal(body.message, text);
        return { ok: true, status: 200, body: { id: orderId, state: 'processed' } };
      },
    },
    store: memoryStore(),
  }, new Map([[AGENT, token]]));
  service.listen(0, '127.0.0.1');
  await once(service, 'listening');
  t.after(async () => {
    service.closeAllConnections();
    await new Promise((resolve, reject) => service.close(error => error ? reject(error) : resolve()));
  });
  const url = `http://127.0.0.1:${service.address().port}/payouts`;
  const submit = m1Client(url, token);
  assert.deepEqual(await submit(input), { status: 'submitted', request_id: input.request_id, monerium_order_id: orderId });
  assert.equal((await submit(input)).error_code, 'M1_DUPLICATE_REQUEST');
  await assert.rejects(m1Client(url, `${token}wrong`)(input), /HTTP 401/);
  assert.equal(posts, 1);
  assert.equal(authentications, 1);
});

test('M1 client forbids remote endpoints and redirects; malformed replies and transit errors surface', async () => {
  for (const raw of ['https://monerium.example/payouts', 'http://localhost:8787/payouts', 'http://127.0.0.1/payouts?token=bad']) {
    assert.throws(() => m1Endpoint(raw), /M1_URL/);
  }
  const input = { agent: AGENT, request_id: 'request-1', iban, amount: '1.5', memo: '' };
  let calls = 0;
  await assert.rejects(m1Client('http://127.0.0.1:8787/payouts', token, async (url, init) => {
    assert.equal(url, 'http://127.0.0.1:8787/payouts'); assert.equal(init?.redirect, 'error');
    calls++; throw new Error('Transit failure');
  })(input), /Transit failure/);
  assert.equal(calls, 1);
  await assert.rejects(m1Client('http://127.0.0.1:8787/payouts', token, async () => new Response('[]'))(input), /Invalid M1/);
});
