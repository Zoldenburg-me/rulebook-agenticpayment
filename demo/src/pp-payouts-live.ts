// PP-L1 recorded run: Anya's supplier payouts (shape 4) live, contract-signed, against the fresh
// testnet contract from pp-payouts-setup.ts, the PayPal rail (rails/paypal `pnpm start`, the only
// process with the PayPal credentials) and the PayPal sandbox. The buyer agent is agent/mcp's own
// Buyer (`pay_paypal`), wired as its MCP server wires it.
//   a. A supplier invoice USD 25.00 to an allowed payee: scam check ok, contract signs, rail pays.
//   b. A poisoned invoice, lookalike payee acme-suppIies: the scam check holds it, no contract call.
//   c. The same with the scam check stubbed to approve (as if the AI were fooled): the contract
//      refuses on chain (ERR_PAYPAL_PAYEE_NOT_ALLOWED).
//   d. Over the cap (USD 75.00 > 50.00), scam check stubbed: refused on chain.
//   e. (a)'s request_id again: the contract refuses to sign it twice, and the rail refuses to send
//      (a)'s signed order a second time.
//
//   node demo/src/pp-payouts-live.ts --env <agent.env> --agent-key <key.json> --invoices <dir> --out demo/evidence/pp-payouts-live.jsonl
//
// agent.env (outside the repo): MANDATE_CONTRACT_ID, PP3_URL, PP3_AGENT_TOKEN, NEAR_AI_MODEL,
// SCAMCHECK_HELD_DIR, MCP_RECEIPT_DIR. The agent's NEAR key is read from its key file inside this
// process, never from the command line. invoices/ holds a.json b.json c.json d.json, each the
// supplier CLI's buyer view of a sandbox invoice. Every logged line has payees masked and the
// configured secrets removed.
import { appendFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs, parseEnv } from 'node:util';
// agent/mcp exports only its CLI entry points; the Buyer and its env wiring are imported by path.
import { Buyer, type Dependencies } from '../../agent/mcp/src/buyer.ts';
import { createBuyerFromEnv } from '../../agent/mcp/src/runtime.ts';

const TX = /\(tx ([1-9A-HJ-NP-Za-km-z]{43,44})\)/;

async function main(argv: string[]): Promise<void> {
  const { values } = parseArgs({ args: argv, options: { env: { type: 'string' }, 'agent-key': { type: 'string' }, invoices: { type: 'string' }, out: { type: 'string' }, 'resume-a': { type: 'string' } } });
  if (!values.env || !values['agent-key'] || !values.invoices || !values.out) throw new Error('usage: pp-payouts-live.ts --env <agent.env> --agent-key <key.json> --invoices <dir> --out <transcript.jsonl>');
  const key = JSON.parse(readFileSync(values['agent-key'], 'utf8')) as { private_key: string };
  const env: NodeJS.ProcessEnv = { ...process.env, ...parseEnv(readFileSync(values.env, 'utf8')), AGENT_NEAR_PRIVATE_KEY: key.private_key };
  const invoice = (name: string) => JSON.parse(readFileSync(join(values.invoices!, `${name}.json`), 'utf8')) as Record<string, any>;

  const buyer = await createBuyerFromEnv(env);
  const deps = (buyer as unknown as { deps: Dependencies }).deps;
  const agent = deps.signer.agent;
  const contract = env.MANDATE_CONTRACT_ID!;
  let layer = 'scam check on';
  const log = (e: Record<string, unknown>) => {
    const line = buyer.redact(JSON.stringify({ at: new Date().toISOString(), layer, ...e }), { emails: true });
    process.stdout.write(`${line}\n`);
    appendFileSync(values.out!, `${line}\n`);
  };
  const txOf = (detail: unknown) => TX.exec(String(detail ?? ''))?.[1];
  const pay = async (beat: string, b: Buyer, inv: Record<string, any>, reason: string) => {
    log({ beat, step: 'invoice', invoice_id: inv.invoice_id, amount: inv.amount.value, payee: inv.payee });
    const r = await b.payPaypal({ invoice: inv, reason }) as Record<string, any>;
    const receipt = deps.store.get(r.request_id);
    log({ beat, step: 'result', ...r, near_tx_hash: receipt?.near_tx_hash ?? txOf(r.detail) ?? null, signed_text: (receipt?.reservation as any)?.payload?.text ?? null });
    return r;
  };

  log({ step: 'setup', contract, agent, evm_address: deps.signer.address, mandate: await deps.view('get_mandate', { agent }), payees: await deps.view('get_payees', { agent }) });

  // --resume-a <request_id>: a rerun after a failure past (b) starts at (c); (a) is read back from the receipt store.
  let a: Record<string, any>;
  if (values['resume-a']) {
    a = { request_id: values['resume-a'] };
    log({ step: 'resume', note: 'rerun from beat c after the script failed before it; beats a and b are the lines above', request_id: a.request_id });
  } else {
    a = await pay('a', buyer, invoice('a'), 'green coffee beans, 5 kg');
    await pay('b', buyer, invoice('b'), 'green coffee beans, 5 kg');
  }

  layer = 'scam check stubbed to approve (contract alone)';
    // Inherits the deps (spreading them would read the lazy getters), only the check differs.
  const unguarded = new Buyer(Object.assign(Object.create(deps) as Dependencies, { check: async () => ({ status: 'approved', verdict: { result: 'ok', reason: 'demo stub: approves everything' } }) as any }));
  await pay('c', unguarded, invoice('c'), 'green coffee beans, 5 kg');
  await pay('d', unguarded, invoice('d'), 'green coffee beans, 15 kg');

  layer = 'resubmission of (a)';
  const reqKey = { agent, caller: { kind: 'agent' }, request_id: a.request_id };
  const signedA = await deps.view('get_request', { key: reqKey }) as Record<string, any> | null;
  const shapeA = deps.store.get(a.request_id)?.shape;
  try {
    const again = await deps.call('request_signature', { request_id: a.request_id, shape: shapeA });
    log({ beat: 'e', step: 'contract', request_id: a.request_id, outcome: 'signed again (unexpected)', near_tx_hash: again.hash });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    log({ beat: 'e', step: 'contract', request_id: a.request_id, outcome: 'refused', error_code: /\bERR_[A-Z0-9_]+\b/.exec(detail)?.[0] ?? null, near_tx_hash: txOf(detail) ?? null, detail });
  }
  if (signedA?.signature && shapeA) {
    const rail = await deps.paypalRail!('payout')({ agent, request_id: a.request_id, payee: String(shapeA.payee), amount: String(shapeA.amount), timestamp: Number(shapeA.timestamp), signature: signedA.signature });
    log({ beat: 'e', step: 'rail', ...rail });
  }
  log({ step: 'after', budget: await deps.view('get_budget', { agent, rail: 'paypal' }) });
}

main(process.argv.slice(2)).catch(error => {
  process.stderr.write(`pp-payouts-live: ${error instanceof Error ? error.message.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '<email>') : String(error)}\n`);
  process.exitCode = 1;
});
