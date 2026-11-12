import { mkdirSync, readFileSync, readdirSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';

export const REQUEST_ID = /^[A-Za-z0-9._:-]{1,64}$/;
export type ReceiptStatus = 'held' | 'blocked' | 'pending' | 'signed' | 'unknown' | 'spent' | 'released' | 'revoked';
export type PaymentResult = {
  status: 'paid' | 'submitted' | 'held' | 'blocked' | 'pending' | 'failed' | 'uncertain';
  request_id: string;
  amount?: string;
  pay_to?: string;
  tx_hash?: string;
  monerium_order_id?: string;
  payout_batch_id?: string;
  /** PP-V1 checkout: the capture on the owner's PayPal wallet. */
  capture_id?: string;
  error_code?: string;
  detail?: string;
  response?: string;
  scam_check?: string;
};
export type Receipt = {
  request_id: string;
  agent: string;
  rail: 'x402' | 'sepa' | 'paypal';
  status: ReceiptStatus;
  amount?: string;
  payee?: string;
  tx_hash?: string;
  near_tx_hash?: string;
  monerium_order_id?: string;
  /** PayPal: the rail's accepted payout batch, and the supplier invoice it pays. */
  payout_batch_id?: string;
  /** PP-V1 checkout: the capture on the owner's PayPal wallet. */
  capture_id?: string;
  batch_status?: string;
  invoice_id?: string;
  reservation?: Record<string, unknown>;
  outcome?: PaymentResult['status'];
  error_code?: string;
  detail?: string;
  scam_check?: string;
  shape?: Record<string, unknown>;
  created_at?: string;
  completed_at?: string;
  response?: string;
  resource_status?: number;
  resource_error?: string;
  signing_started?: boolean;
  held_id?: string;
  replacement_request_id?: string;
  approved_from_request_id?: string;
  decision_nonce?: number;
  operation?: { tool: 'pay_x402' | 'pay_sepa' | 'pay_paypal'; args: Record<string, unknown> };
};

/** Private files: one MCP process per agent key and receipt directory. */
export class ReceiptStore {
  readonly dir: string;
  constructor(dir: string) {
    this.dir = dir;
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  get(id: string): Receipt | undefined {
    if (!REQUEST_ID.test(id)) throw new Error('Invalid request_id');
    try {
      return JSON.parse(readFileSync(join(this.dir, `${id}.json`), 'utf8')) as Receipt;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw error;
    }
  }
  put(receipt: Receipt): void {
    if (!REQUEST_ID.test(receipt.request_id)) throw new Error('Invalid request_id');
    const path = join(this.dir, `${receipt.request_id}.json`);
    const temp = `${path}.${randomUUID()}.tmp`;
    writeFileSync(temp, JSON.stringify(receipt), { mode: 0o600 });
    renameSync(temp, path);
  }
  all(): Receipt[] {
    return readdirSync(this.dir).filter(name => name.endsWith('.json')).map(name => {
      const receipt = this.get(name.slice(0, -5));
      if (!receipt) throw new Error('Receipt disappeared while reading');
      return receipt;
    });
  }
}
