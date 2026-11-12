// Programmatic and CLI entry to pay_paypal for scripts (the PP5 demo), outside an MCP client.
// Same Buyer, receipts, scam check and held queue as the MCP server; output goes through the
// same redaction (payees masked, configured secrets removed).
//
//   node src/pay-paypal.ts --invoice <file.json | ->  [--reason TEXT]
//   node src/pay-paypal.ts --receipt <request_id>
//   node src/pay-paypal.ts --process-decisions
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { safeDetail, type Buyer } from './buyer.ts';
import { maskEmails } from './policy.ts';
import { createBuyerFromEnv } from './runtime.ts';

/** Pays one supplier invoice (supplier/'s buyer view) and returns the redacted result. */
export async function payPaypalInvoice(invoice: unknown, opts: { reason?: string; buyer?: Buyer } = {}): Promise<Record<string, unknown>> {
  const buyer = opts.buyer ?? await createBuyerFromEnv();
  const result = await buyer.payPaypal({ invoice, ...(opts.reason ? { reason: opts.reason } : {}) });
  return JSON.parse(buyer.redact(JSON.stringify(result), { emails: true })) as Record<string, unknown>;
}

async function main(argv: string[]): Promise<void> {
  const { values } = parseArgs({ args: argv, options: {
    invoice: { type: 'string' }, reason: { type: 'string' }, receipt: { type: 'string' }, 'process-decisions': { type: 'boolean', default: false },
  } });
  const buyer = await createBuyerFromEnv();
  let output: unknown;
  if (values.invoice) {
    const raw = readFileSync(values.invoice === '-' ? 0 : values.invoice, 'utf8');
    output = await payPaypalInvoice(JSON.parse(raw), { reason: values.reason, buyer });
  } else if (values.receipt) {
    output = await buyer.getReceipt(values.receipt);
  } else if (values['process-decisions']) {
    await buyer.processDecisions();
    output = { processed: true };
  } else {
    throw new Error('usage: pay-paypal --invoice <file.json|-> [--reason TEXT] | --receipt <request_id> | --process-decisions');
  }
  process.stdout.write(`${buyer.redact(JSON.stringify(output, null, 2), { emails: true })}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => {
    process.stderr.write(`pay-paypal: ${maskEmails(safeDetail(error))}\n`);
    process.exitCode = 1;
  });
}
