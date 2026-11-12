import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { encodeAbiParameters, encodeEventTopics, parseAbi, TransactionReceiptNotFoundError, type Hex, type TransactionReceipt } from 'viem';
import { verifyX402Settlement } from '../src/settlement.ts';
import type { Receipt } from '../src/store.ts';

const abi = parseAbi(['event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce)', 'event Transfer(address indexed from, address indexed to, uint256 value)']);
const hash = `0x${'aa'.repeat(32)}` as Hex;
const nonce = `0x${'bb'.repeat(32)}` as Hex;
const agent = `0x${'11'.repeat(20)}` as Hex;
const payee = `0x${'22'.repeat(20)}` as Hex;
const usdc = `0x${'33'.repeat(20)}` as Hex;
const attacker = `0x${'44'.repeat(20)}` as Hex;
const authorization = { address: usdc, topics: encodeEventTopics({ abi, eventName: 'AuthorizationUsed', args: { authorizer: agent, nonce } }), data: '0x' as Hex };
const transfer = { address: usdc, topics: encodeEventTopics({ abi, eventName: 'Transfer', args: { from: agent, to: payee } }), data: encodeAbiParameters([{ type: 'uint256' }], [10000n]) };
const receipt: Receipt = { request_id: 'payment-1', agent: 'agent-1', rail: 'x402', amount: '10000', payee, status: 'signed', reservation: { payload: { kind: 'eip3009', chain_id: 84532, asset: usdc, from: agent, to: payee, value: '10000', nonce } } };
type ChainReceipt = Pick<TransactionReceipt, 'status' | 'transactionHash' | 'logs'>;
const chain = (changes: Partial<ChainReceipt> = {}): ChainReceipt => ({ status: 'success', transactionHash: hash, logs: [authorization, transfer] as TransactionReceipt['logs'], ...changes });

test('confirmed successful USDC authorization and matching transfer establish payment', async () => {
  assert.equal(await verifyX402Settlement({ getTransactionReceipt: async () => chain() }, receipt, hash, agent, usdc), true);
});

for (const kind of ['reverted', 'hash', 'token', 'nonce', 'authorizer', 'payee', 'amount', 'missing-auth', 'missing-transfer'] as const) {
  test(`forged or mismatched ${kind} does not establish payment`, async () => {
    const auth = kind === 'nonce' ? { ...authorization, topics: encodeEventTopics({ abi, eventName: 'AuthorizationUsed', args: { authorizer: agent, nonce: `0x${'cc'.repeat(32)}` } }) } : kind === 'authorizer' ? { ...authorization, topics: encodeEventTopics({ abi, eventName: 'AuthorizationUsed', args: { authorizer: attacker, nonce } }) } : authorization;
    const moved = kind === 'payee' ? { ...transfer, topics: encodeEventTopics({ abi, eventName: 'Transfer', args: { from: agent, to: attacker } }) } : kind === 'amount' ? { ...transfer, data: encodeAbiParameters([{ type: 'uint256' }], [999n]) } : transfer;
    const logs = (kind === 'missing-auth' ? [moved] : kind === 'missing-transfer' ? [auth] : [auth, moved]).map(log => kind === 'token' ? { ...log, address: attacker } : log) as TransactionReceipt['logs'];
    const response = chain({ status: kind === 'reverted' ? 'reverted' : 'success', transactionHash: kind === 'hash' ? nonce : hash, logs });
    assert.equal(await verifyX402Settlement({ getTransactionReceipt: async () => response }, receipt, hash, agent, usdc), false);
  });
}

test('unmined transaction remains unconfirmed and RPC errors propagate', async () => {
  assert.equal(await verifyX402Settlement({ getTransactionReceipt: async () => { throw new TransactionReceiptNotFoundError({ hash }); } }, receipt, hash, agent, usdc), false);
  await assert.rejects(verifyX402Settlement({ getTransactionReceipt: async () => { throw new Error('RPC unavailable'); } }, receipt, hash, agent, usdc), /RPC unavailable/);
});
