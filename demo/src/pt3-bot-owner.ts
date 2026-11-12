// PP-H3, agent-driven Hank run: the owner and attacker steps between the bot's two parts.
// The bot (an LLM session using only the buyer MCP tools) pays the invoices itself; this script runs
// what an honest agent cannot do by design: (1) an attacker hands the rail a contract-signed charge
// with the merchant swapped; (2) the owner revokes the agent on the contract and deletes the vault
// token; (3) the owner tries to re-arm the revoked agent. Testnet and PayPal sandbox only.
//
//   OWNER_ACCOUNT_ID=<owner>.testnet node demo/src/pt3-bot-owner.ts --env <agent.env> --rail-env <rail.env> \
//     --invoices <dir> --out <transcript.jsonl>
// agent.env carries the agent key (AGENT_NEAR_PRIVATE_KEY) like the MCP server's .env; secrets are read
// from files, never from the command line. The owner's NEAR calls are signed by near-cli-rs from the
// legacy keychain.
import { appendFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs, parseEnv } from 'node:util';
import { assertTestnet, NETWORK, nearCli } from '@nearh/owner-near/src/near.ts';
import { type Dependencies } from '../../agent/mcp/src/buyer.ts';
import { createBuyerFromEnv } from '../../agent/mcp/src/runtime.ts';

const SWAPPED = 'sales@cardvau1t.example';

async function main(argv: string[]): Promise<void> {
  const { values } = parseArgs({ args: argv, options: { env: { type: 'string' }, 'rail-env': { type: 'string' }, invoices: { type: 'string' }, out: { type: 'string' } } });
  if (!values.env || !values['rail-env'] || !values.invoices || !values.out) throw new Error('usage: pt3-bot-owner.ts --env <agent.env> --rail-env <rail.env> --invoices <dir> --out <transcript.jsonl>');
  const owner = assertTestnet('OWNER_ACCOUNT_ID', process.env.OWNER_ACCOUNT_ID ?? '');
  const env: NodeJS.ProcessEnv = { ...process.env, ...parseEnv(readFileSync(values.env, 'utf8')) };
  const rail = parseEnv(readFileSync(values['rail-env'], 'utf8'));
  const ownerToken = rail.PP_OWNER_TOKEN ?? '';
  const railUrl = `http://127.0.0.1:${rail.PP3_PORT || 8788}`;
  const buyer = await createBuyerFromEnv(env);
  const deps = (buyer as unknown as { deps: Dependencies }).deps;
  const agent = deps.signer.agent;
  const contract = env.MANDATE_CONTRACT_ID!;
  const redact = (s: string) => buyer.redact(ownerToken ? s.split(ownerToken).join('<owner-token>') : s, { emails: true });
  const log = (e: Record<string, unknown>) => { const line = redact(JSON.stringify({ at: new Date().toISOString(), actor: e.actor ?? 'owner', ...e })); process.stdout.write(`${line}\n`); appendFileSync(values.out!, `${line}\n`); };
  const errorCode = (d: string) => /\bERR_[A-Z0-9_]+\b/.exec(d)?.[0] ?? null;
  const ownerVault = async (method: 'GET' | 'POST', path: string, body?: object) => { const r = await fetch(`${railUrl}${path}`, { method, headers: { authorization: `Bearer ${ownerToken}`, 'content-type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) }); return { http: r.status, ...(await r.json() as Record<string, unknown>) }; };
  const railCheckout = async (order: Record<string, unknown>) => { const r = await fetch(`${railUrl}/checkout`, { method: 'POST', headers: { authorization: `Bearer ${env.PP3_AGENT_TOKEN}`, 'content-type': 'application/json' }, body: JSON.stringify(order) }); return await r.json() as Record<string, unknown>; };
  const ownerCall = (method: string, args: object) => nearCli(['contract', 'call-function', 'as-transaction', contract, method, 'json-args', JSON.stringify(args), 'prepaid-gas', '100 Tgas', 'attached-deposit', '1 yoctoNEAR', 'sign-as', owner, 'network-config', NETWORK, 'sign-with-legacy-keychain', 'send']);

  const mandate = await deps.view('get_mandate', { agent });
  log({ step: 'setup', contract, agent, vault: await ownerVault('GET', `/vault/status?agent=${agent}`), budget: await deps.view('get_budget', { agent, rail: 'paypal' }) });

  // (0) the scam check bypassed: the contract alone on the two invoices the bot's scam check held.
  for (const name of ['fake', 'bait']) {
    const v = JSON.parse(readFileSync(join(values.invoices, `${name}.json`), 'utf8')) as Record<string, any>;
    const id = `chk-${crypto.randomUUID()}`;
    const s = { type: 'paypal_checkout', payee: v.payee, amount: v.amount.value, order_ref: v.invoice_id, timestamp: Math.floor(Date.now() / 1000) };
    try {
      const res = await deps.call('request_signature', { request_id: id, shape: s });
      log({ actor: 'scam check bypassed', step: `contract alone: ${name}`, request_id: id, outcome: (res.value as any)?.status ?? null, near_tx_hash: res.hash });
    } catch (e) {
      const d = String((e as Error)?.message ?? e);
      log({ actor: 'scam check bypassed', step: `contract alone: ${name}`, request_id: id, refused: true, error_code: errorCode(d), near_tx_hash: /\(tx ([1-9A-HJ-NP-Za-km-z]{43,44})\)/.exec(d)?.[1] ?? null });
    }
  }

  // (1) attacker: a charge the contract signs for the agent (binder pages, USD 5.00, the real store), handed to the rail with the merchant swapped.
  const inv = JSON.parse(readFileSync(join(values.invoices, 'pages.json'), 'utf8')) as Record<string, any>;
  const swapId = `chk-${crypto.randomUUID()}`;
  const shape = { type: 'paypal_checkout', payee: inv.payee, amount: inv.amount.value, order_ref: inv.invoice_id, timestamp: Math.floor(Date.now() / 1000) };
  const signed = await deps.call('request_signature', { request_id: swapId, shape });
  const reservation = signed.value as Record<string, any>;
  log({ actor: 'attacker', step: 'contract signs a real order', request_id: swapId, outcome: reservation.status, near_tx_hash: signed.hash, signed_text: reservation.payload?.text ?? null });
  const order = { agent, request_id: swapId, payee: shape.payee, amount: shape.amount, order_ref: shape.order_ref, timestamp: shape.timestamp, signature: reservation.signature };
  log({ actor: 'attacker', step: 'rail, merchant swapped after signing', sent_merchant: SWAPPED, ...(await railCheckout({ ...order, payee: SWAPPED })) });

  // (2) owner: revoke on the contract, then delete the vault token.
  const r = ownerCall('revoke', { agent, assertion: null });
  log({ step: 'contract revoke', ok: r.ok, near_tx_hash: r.txHash ?? null, ...(r.ok ? {} : { detail: r.out.slice(-400) }) });
  log({ step: 'get_agent', revoked: (await deps.view('get_agent', { agent }) as any)?.revoked ?? null });
  log({ step: 'vault revoke', ...(await ownerVault('POST', '/vault/revoke', { agent })) });
  log({ actor: 'attacker', step: 'rail, the signed order replayed unchanged after the revoke', ...(await railCheckout(order)) });

  // (3) owner: try to re-arm the revoked agent.
  const rearm = ownerCall('set_mandate', { agent, mandate, assertion: null });
  log({ step: 'set_mandate after revoke', ok: rearm.ok, error_code: errorCode(rearm.out), near_tx_hash: rearm.txHash ?? null });
  log({ step: 'after', vault: await ownerVault('GET', `/vault/status?agent=${agent}`) });
}

main(process.argv.slice(2)).catch(error => { process.stderr.write(`pt3-bot-owner: ${error instanceof Error ? error.message.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '<email>') : String(error)}\n`); process.exitCode = 1; });
