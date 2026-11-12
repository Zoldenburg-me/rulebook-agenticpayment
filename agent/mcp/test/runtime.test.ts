import { strict as assert } from 'node:assert';
import { test, type TestContext } from 'node:test';
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createBuyerFromEnv, scamcheckConfig } from '../src/runtime.ts';
import { FakeNear, CONTRACT } from '../../signer/test/fake-near.ts';

async function runtime(t: TestContext, settings: NodeJS.ProcessEnv) {
  const near = new FakeNear();
  const dir = mkdtempSync(join(tmpdir(), 'nearh-a2-runtime-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let baseCalls = 0;
  let revokes = 0;
  t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url !== 'https://rpc.testnet.near.org') { baseCalls++; throw new Error('Base RPC unavailable'); }
    assert.ok(init?.body);
    const message = JSON.parse(String(init.body)) as { method: string; params: Record<string, unknown> };
    let result: unknown;
    if (message.method === 'send_tx') {
      const tx = Buffer.from(String(message.params.signed_tx_base64), 'base64');
      assert.equal(tx.includes(Buffer.from('revoke_self')), true);
      revokes++;
      result = { status: { SuccessValue: Buffer.from(JSON.stringify({ agent: 'agent-1', revoked: true, key_deleted: true })).toString('base64') } };
    } else if (message.method === 'query' && message.params.method_name === 'get_request') {
      result = { result: [...Buffer.from(JSON.stringify({ status: 'signed', rail: 'sepa' }))] };
    } else {
      result = await near.rpc(message.method, message.params);
    }
    return Response.json({ jsonrpc: '2.0', id: 1, result });
  });
  const buyer = await createBuyerFromEnv({ MANDATE_CONTRACT_ID: CONTRACT, AGENT_NEAR_PRIVATE_KEY: near.key.text, MCP_RECEIPT_DIR: dir, BASE_SEPOLIA_RPC: 'https://base.invalid', NEAR_AI_API_KEY: 'offline-test-key', ...settings });
  assert.equal((await buyer.getReceipt('existing-payment')).status, 'signed');
  const result = await buyer.revoke();
  assert.equal(result.revoked, true);
  assert.equal(result.key_deleted, true);
  assert.equal(revokes, 1);
  assert.equal(baseCalls, 0);
}

for (const settings of [
  {},
  { MCP_SELLER_ORIGINS: 'malformed', M1_URL: 'https://remote.invalid/payouts', M1_AGENT_TOKEN: 'bad' },
  { MCP_SELLER_ORIGINS: 'https://seller.example', M1_AGENT_TOKEN: 'offline-agent-token-12345678901234567890' },
]) {
  test(`NEAR receipt and self-revoke work without payment dependencies (${JSON.stringify(Object.keys(settings))})`, t => runtime(t, settings));
}

test('SC1 settings are injected from the env or the NEAR AI key file, never from scamcheck/.env (PayPal audit 1 C1/H1)', t => {
  const dir = mkdtempSync(join(tmpdir(), 'nearh-sc1-config-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'nearai.env');
  writeFileSync(file, 'NEAR_AI_API_KEY="file-key"\n');
  const missing = join(dir, 'absent.env');
  // The environment wins; the other settings pass through, empty ones fall back to SC1's defaults.
  assert.deepEqual(scamcheckConfig({ NEAR_AI_API_KEY: 'env-key', NEAR_AI_BASE_URL: 'https://n.example/v1', NEAR_AI_MODEL: 'm', SCAMCHECK_HELD_DIR: '/q' }, file),
    { apiKey: 'env-key', baseUrl: 'https://n.example/v1', model: 'm', heldDir: '/q' });
  assert.deepEqual(scamcheckConfig({ NEAR_AI_MODEL: '' }, file), { apiKey: 'file-key', baseUrl: undefined, model: undefined, heldDir: undefined });
  assert.equal(scamcheckConfig({ NEAR_AI_ENV_FILE: file }, missing).apiKey, 'file-key');
  // No default file: no key (SC1 skips; pay_paypal then blocks). A named file that is missing is an error.
  assert.equal(scamcheckConfig({}, missing).apiKey, undefined);
  assert.throws(() => scamcheckConfig({ NEAR_AI_ENV_FILE: missing }, file), /NEAR_AI_ENV_FILE/);
  assert.equal(process.env.NEAR_AI_API_KEY === 'file-key', false, 'the key never lands in process.env');
});

test('the NEAR AI key file is explicit opt-in and sets only the key, also through a symlink like the demo\'s scamcheck/.env (PayPal audit 2 L1)', t => {
  const dir = mkdtempSync(join(tmpdir(), 'nearh-sc1-optin-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const target = join(dir, 'nearai.env');
  // A planted file cannot redirect the check: only NEAR_AI_API_KEY is taken from it.
  writeFileSync(target, 'NEAR_AI_API_KEY=linked-key\nNEAR_AI_BASE_URL=https://evil.example/v1\nNEAR_AI_MODEL=evil\nSCAMCHECK_HELD_DIR=/tmp/evil\n');
  const link = join(dir, '.env');
  symlinkSync(target, link);
  const missing = join(dir, 'absent.env');
  assert.deepEqual(scamcheckConfig({ NEAR_AI_ENV_FILE: link }, missing), { apiKey: 'linked-key', baseUrl: undefined, model: undefined, heldDir: undefined });
  assert.equal(process.env.NEAR_AI_BASE_URL === 'https://evil.example/v1', false);
});
