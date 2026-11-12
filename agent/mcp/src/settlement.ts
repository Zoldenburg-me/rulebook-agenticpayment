import { parseAbi, parseEventLogs, TransactionReceiptNotFoundError, type Hex, type TransactionReceipt } from 'viem';
import type { Receipt } from './store.ts';

const EVENTS = parseAbi([
  'event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce)',
  'event Transfer(address indexed from, address indexed to, uint256 value)',
]);
export type ReceiptClient = {
  getTransactionReceipt(args: { hash: Hex }): Promise<Pick<TransactionReceipt, 'status' | 'transactionHash' | 'logs'>>;
};
const same = (a: unknown, b: unknown) => typeof a === 'string' && typeof b === 'string' && a.toLowerCase() === b.toLowerCase();

/** A seller's claimed hash is evidence only after matching the signed authorization on USDC. */
export async function verifyX402Settlement(client: ReceiptClient, receipt: Receipt, hash: string, authorizer: string, usdc: string): Promise<boolean> {
  const raw = receipt.reservation?.payload;
  if (!raw || typeof raw !== 'object') return false;
  const payload = raw as Record<string, unknown>;
  if (payload.kind !== 'eip3009' || payload.chain_id !== 84532 || !same(payload.from, authorizer) || !same(payload.asset, usdc) || !same(payload.to, receipt.payee) || payload.value !== receipt.amount) return false;
  if (!/^0x[0-9a-f]{64}$/i.test(hash)) return false;
  let transaction;
  try {
    transaction = await client.getTransactionReceipt({ hash: hash as Hex });
  } catch (error) {
    if (error instanceof TransactionReceiptNotFoundError) return false;
    throw error;
  }
  if (transaction.status !== 'success' || !same(transaction.transactionHash, hash)) return false;
  const events = parseEventLogs({ abi: EVENTS, logs: transaction.logs.filter(log => same(log.address, usdc)), strict: true });
  const authorization = events.some(event => event.eventName === 'AuthorizationUsed' && same(event.args.authorizer, authorizer) && same(event.args.nonce, payload.nonce));
  const transfer = events.some(event => event.eventName === 'Transfer' && same(event.args.from, authorizer) && same(event.args.to, receipt.payee) && event.args.value.toString() === receipt.amount);
  return authorization && transfer;
}
