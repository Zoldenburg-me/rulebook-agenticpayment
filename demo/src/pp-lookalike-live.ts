// PP-L1 beats b2 and c2: the lookalike supplier is a real PayPal sandbox account. Against the
// contract from pp-payouts-setup.ts (its payee allowlist unchanged), with the PayPal rail
// (rails/paypal `pnpm start`) running and the PayPal sandbox:
//   1. The demo supplier (supplier/'s issueInvoice, its own PayPal client) issues two sandbox
//      invoices with the display name "acme-suppIies" whose payee is the fake supplier's sandbox
//      Personal account (not on the allowlist).
//   b2. Scam check on: it holds the invoice, no contract call.
//   c2. Scam check stubbed to approve: the contract refuses on chain (ERR_PAYPAL_PAYEE_NOT_ALLOWED),
//      nothing goes to the rail.
//   3. PayPal's view: every payout batch the rail has submitted, read back, has no item to that
//      account; Transaction Search on the sender account since the start of the day has none either.
//
//   node demo/src/pp-lookalike-live.ts --env <agent.env> --agent-key <key.json> --rail-store <dir> --out demo/evidence/pp-payouts-live.jsonl
//
// The fake supplier's email is read from FAKE_SUPPLIER_ENV (default ~/.config/nearh/fake-supplier.env,
// FAKE_SUPPLIER_PAYPAL_EMAIL) inside this process; it is never printed, only masked as the rail
// masks payees. The PayPal credentials file is read as supplier/ and rails/paypal read it.
import { appendFileSync, readdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { parseArgs, parseEnv } from 'node:util';
import { Buyer, type Dependencies } from '../../agent/mcp/src/buyer.ts';
import { createBuyerFromEnv } from '../../agent/mcp/src/runtime.ts';
import { issueInvoice } from '../../supplier/src/invoice.ts';
import { sandboxClient as supplierClient } from '../../supplier/src/paypal.ts';
import { credentialsFile, readCredentials } from '../../rails/paypal/src/config.ts';
import { sandboxClient as railClient } from '../../rails/paypal/src/paypal.ts';

const TX = /\(tx ([1-9A-HJ-NP-Za-km-z]{43,44})\)/;
const NAME = 'acme-suppIies';
const ARCHIVAL_RPC = 'https://archival-rpc.testnet.fastnear.com';

async function main(argv: string[]): Promise<void> {
  const { values } = parseArgs({ args: argv, options: { env: { type: 'string' }, 'agent-key': { type: 'string' }, 'rail-store': { type: 'string' }, out: { type: 'string' }, 'checks-only': { type: 'string' } } });
  if (!values.env || !values['agent-key'] || !values['rail-store'] || !values.out) throw new Error('usage: pp-lookalike-live.ts --env <agent.env> --agent-key <key.json> --rail-store <dir> --out <transcript.jsonl>');
  const fake = parseEnv(readFileSync(process.env.FAKE_SUPPLIER_ENV || join(homedir(), '.config', 'nearh', 'fake-supplier.env'), 'utf8')).FAKE_SUPPLIER_PAYPAL_EMAIL?.trim().toLowerCase();
  if (!fake || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(fake)) throw new Error('FAKE_SUPPLIER_PAYPAL_EMAIL is not set');
  const key = JSON.parse(readFileSync(values['agent-key'], 'utf8')) as { private_key: string };
  const env: NodeJS.ProcessEnv = { ...process.env, ...parseEnv(readFileSync(values.env, 'utf8')), AGENT_NEAR_PRIVATE_KEY: key.private_key };
  const creds = readCredentials(credentialsFile());
  const started = new Date();

  const buyer = await createBuyerFromEnv(env);
  const deps = (buyer as unknown as { deps: Dependencies }).deps;
  const agent = deps.signer.agent;
  let layer = 'scam check on';
  const log = (e: Record<string, unknown>) => {
    const line = buyer.redact(JSON.stringify({ at: new Date().toISOString(), layer, ...e }), { emails: true });
    process.stdout.write(`${line}\n`);
    appendFileSync(values.out!, `${line}\n`);
  };
  const txOf = (detail: unknown) => TX.exec(String(detail ?? ''))?.[1];

  const payees = await deps.view('get_payees', { agent }) as unknown[];
  if (JSON.stringify(payees).toLowerCase().includes(fake)) throw new Error('the fake supplier is on the allowlist; this run needs it off');
  log({ step: 'setup b2/c2', contract: env.MANDATE_CONTRACT_ID, agent, fake_supplier: { paypal_account: fake, sandbox_account: 'Personal, created by the owner', on_allowlist: false }, allowlist_size: payees.length });

  // 1. The supplier issues the invoices through its own PayPal client, display name "acme-suppIies".
  const supplier = supplierClient(creds);
  const due = new Date(Date.now() + 10 * 86_400_000).toISOString().slice(0, 10);
  const issue = async (beat: string) => {
    const inv = await issueInvoice(supplier, { amount: '25.00', description: 'Green coffee beans, 5 kg', dueDate: due, service: 'Green coffee beans', payee: fake, supplierName: NAME, billTo: 'buyer@example.com' }) as Record<string, any>;
    const raw = (await supplier.request('GET', `/v2/invoicing/invoices/${inv.invoice_id}`)).body;
    log({ beat, step: 'invoice', invoice_id: inv.invoice_id, status: inv.status, amount: inv.amount.value, payee: inv.payee, payee_is_fake_supplier: inv.payee === fake, invoicer_business_name: raw?.invoicer?.business_name ?? null, payer_view_url: inv.payer_view_url });
    return inv;
  };
  const pay = async (beat: string, b: Buyer, inv: Record<string, any>) => {
    // The agent's reason names the supplier as the invoice shows it.
    const r = await b.payPaypal({ invoice: inv, reason: `green coffee beans, 5 kg; invoice from ${NAME}` }) as Record<string, any>;
    log({ beat, step: 'result', ...r, near_tx_hash: deps.store.get(r.request_id)?.near_tx_hash ?? txOf(r.detail) ?? null });
    return r;
  };

  // --checks-only <b2 request_id>,<c2 request_id>: a rerun after a failure past c2 does only the checks.
  let b2: Record<string, any>, c2: Record<string, any>;
  if (values['checks-only']) {
    const [b, c] = values['checks-only'].split(',');
    [b2, c2] = [{ request_id: b }, { request_id: c }];
    layer = 'checks';
    log({ step: 'resume', note: 'rerun of the checks only, after the script failed in them; b2 and c2 are the lines above', request_ids: [b, c] });
  } else {
    b2 = await pay('b2', buyer, await issue('b2'));
    const c2inv = await issue('c2');
    layer = 'scam check stubbed to approve (contract alone)';
    const unguarded = new Buyer(Object.assign(Object.create(deps) as Dependencies, { check: async () => ({ status: 'approved', verdict: { result: 'ok', reason: 'demo stub: approves everything' } }) as any }));
    c2 = await pay('c2', unguarded, c2inv);
  }

  // The failed tx as the chain records it.
  layer = 'checks';
  const hash = txOf(c2.detail);
  if (hash && !values['checks-only']) {
    const res = await fetch(ARCHIVAL_RPC, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tx', params: { tx_hash: hash, sender_account_id: env.MANDATE_CONTRACT_ID, wait_until: 'FINAL' } }) });
    const tx = (await res.json() as any).result;
    log({ step: 'chain', rpc: ARCHIVAL_RPC, near_tx_hash: hash, method: tx?.transaction?.actions?.[0]?.FunctionCall?.method_name ?? null, status: tx?.status?.Failure ? 'Failure' : tx?.status ? 'not a failure' : 'not found', failure: JSON.stringify(tx?.status?.Failure ?? null).match(/ERR_[A-Z0-9_]+/)?.[0] ?? null });
  }

  // 3. Nothing at PayPal. (i) The rail's own record of every order it handed to PayPal, each batch read back from PayPal.
  const rail = railClient(creds);
  await rail.authenticate();
  const records = readdirSync(values['rail-store']).filter(f => f.endsWith('.json')).map(f => JSON.parse(readFileSync(join(values['rail-store']!, f), 'utf8')) as Record<string, any>);
  const ours = new Set([b2.request_id, c2.request_id]);
  const batches = [...new Set(records.map(r => r.payout_batch_id).filter(Boolean))] as string[];
  const items: { batch: string; status: string; items: number; to_fake_supplier: number }[] = [];
  for (const id of batches) {
    const body = (await rail.request('GET', `/v1/payments/payouts/${id}`)).body;
    const list = (body?.items ?? []) as any[];
    items.push({ batch: id, status: body?.batch_header?.batch_status ?? 'unknown', items: list.length, to_fake_supplier: list.filter(i => String(i?.payout_item?.receiver ?? '').toLowerCase() === fake).length });
  }
  log({ step: 'paypal check 1', query: 'rail store (PP3_STORE_DIR): every order record; GET /v1/payments/payouts/{batch} for each batch id in it', rail_records: records.length, rail_records_for_b2_c2: records.filter(r => ours.has(r.request_id)).length, batches: items, payout_items_to_fake_supplier: items.reduce((n, b) => n + b.to_fake_supplier, 0) });

  // (ii) Transaction Search on the sender (the rail's business account), the start of the UTC day to now.
  const dayStart = `${started.toISOString().slice(0, 10)}T00:00:00Z`;
  const end = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  const q = `/v1/reporting/transactions?start_date=${dayStart}&end_date=${end}&fields=all&page_size=500`;
  const ts = await rail.request('GET', q);
  const txs = (ts.body?.transaction_details ?? []) as any[];
  log({ step: 'paypal check 2', query: `GET ${q}`, http_status: ts.status, error: ts.ok ? null : ts.body?.name ?? null, transactions: ts.ok ? txs.length : null, last_refreshed_datetime: ts.body?.last_refreshed_datetime ?? null, to_fake_supplier: ts.ok ? txs.filter(t => JSON.stringify(t).toLowerCase().includes(fake)).length : null });
  log({ step: 'after', budget: await deps.view('get_budget', { agent, rail: 'paypal' }) });
}

main(process.argv.slice(2)).catch(error => {
  process.stderr.write(`pp-lookalike-live: ${error instanceof Error ? error.message.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '<email>') : String(error)}\n`);
  process.exitCode = 1;
});
