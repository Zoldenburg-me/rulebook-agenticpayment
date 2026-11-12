import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { verifyOwnerDecision } from '../src/runtime.ts';
import { ReceiptStore } from '../src/store.ts';
import { b64url, heldDecideArgs, ownerChallenge } from '../../../dashboard/public/owner.js';

const contractId = 'mandate-owner.testnet';
const sha = value => createHash('sha256').update(value).digest();
async function setup(t) {
  const dir = mkdtempSync(join(tmpdir(), 'nearh-decision-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const store = new ReceiptStore(dir);
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const config = { network: 'testnet', owner: { mode: 'passkey', public_key: publicKey.export({ format: 'der', type: 'spki' }).subarray(-65).toString('base64'), rp_id: 'localhost', origin: 'http://localhost:5173' } };
  const expires = Math.floor(Date.now() / 1000) + 300;
  const item = { id: 'held-original', status: 'approved', agent: 'agent-1', request_id: 'original', decided_nonce: 1, decided_at: new Date().toISOString() };
  const challenge = await ownerChallenge(contractId, 'testnet', 'held_decide', heldDecideArgs(item.id, item.status), 1, expires);
  const client = JSON.stringify({ type: 'webauthn.get', challenge: b64url(challenge), origin: config.owner.origin });
  const auth = Buffer.concat([sha('localhost'), Buffer.from([1, 0, 0, 0, 0])]);
  const signature = sign('sha256', Buffer.concat([auth, sha(client)]), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return { store, config, item: { ...item, assertion: { owner_nonce: 1, expires_at: expires, client_data_json: client, authenticator_data: auth.toString('base64'), signature: signature.toString('base64') } } };
}

test('consumer verifies actual owner proof and rejects file forgery, cross-item replay and stale nonce', async t => {
  const { store, config, item } = await setup(t);
  const query = async method => { assert.equal(method, 'get_config'); return config; };
  await verifyOwnerDecision(query, contractId, store, item);
  await assert.rejects(verifyOwnerDecision(query, contractId, store, { ...item, assertion: undefined }), /assertion/);
  await assert.rejects(verifyOwnerDecision(query, contractId, store, { ...item, decided_nonce: 2 }), /nonce/);
  await assert.rejects(verifyOwnerDecision(query, contractId, store, { ...item, id: 'held-other' }), /different item/);
  await assert.rejects(verifyOwnerDecision(query, contractId, store, { ...item, status: 'rejected' }), /different item/);
  const wrongKey = await setup(t);
  await assert.rejects(verifyOwnerDecision(async () => wrongKey.config, contractId, store, item), /bad signature/);
  store.put({ request_id: 'consumed', agent: 'agent-1', rail: 'sepa', status: 'signed', decision_nonce: 1 });
  await assert.rejects(verifyOwnerDecision(query, contractId, store, item), /stale owner_nonce/);
});
