// PP-H2 recorded run: Hank's trading card (shape 5, the vaulted-wallet charge) live, contract-signed,
// against the fresh testnet contract from pt2-hank-setup.ts, the PayPal rail (rails/paypal
// `pnpm start` with the vault routes on, the only process with the PayPal credentials) and the
// PayPal sandbox. The buyer agent is agent/mcp's own Buyer (`pay_paypal` with mode=checkout), wired
// as its MCP server wires it. Grokbot does not drive it here: this script calls the tool.
//   fake.  The fake listing (lookalike merchant cardvau1t): the scam check, then the check stubbed
//          to approve (the AI fooled): the contract's shape 5 merchant check refuses on chain.
//   bait.  An allowed shop, USD 149.00 at checkout: over the USD 100.00 cap, refused on chain.
//   buy.   The real card, USD 84.00 at the real store: the contract signs, the rail charges the
//          vaulted wallet and pays the store out.
//   swap.  A second signed charge, handed to the rail with the merchant swapped: refused.
//   revoke. Hank revokes: the owner's `revoke` on the contract, the vault token deleted (GET 404);
//          then the agent's next request, the unspent signed charge, and a re-arm of the agent.
//
//   OWNER_ACCOUNT_ID=<owner>.testnet node demo/src/pt2-hank-live.ts --env <agent.env> --rail-env <rail.env> \
//     --agent-key <key.json> --invoices <dir> --out demo/evidence/pt2-hank-live.jsonl
//
// agent.env as pp-payouts-live.ts. rail.env is the rail's env file: only PP_OWNER_TOKEN (the owner's
// vault routes) and PP3_PORT are read from it. The agent's NEAR key is read from its key file inside
// this process, never from the command line. The owner's NEAR calls are signed by near-cli-rs from
// the legacy keychain. invoices/ holds real, fake, fake-again, bait, bait-again, sleeves and pages
// .json, the supplier CLI's buyer view of sandbox invoices from the card shops (a held invoice stays
// open in the receipt store, so the stubbed retries use their own invoice). Every logged line has emails masked and the
// configured secrets removed.
import { appendFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs, parseEnv } from 'node:util';
import { assertTestnet, NETWORK, nearCli } from '@nearh/owner-near/src/near.ts';
// agent/mcp exports only its CLI entry points; the Buyer and its env wiring are imported by path.
import { Buyer, type Dependencies } from '../../agent/mcp/src/buyer.ts';
import { createBuyerFromEnv } from '../../agent/mcp/src/runtime.ts';

const TX = /\(tx ([1-9A-HJ-NP-Za-km-z]{43,44})\)/;
const SWAPPED = 'sales@cardvau1t.example';

async function main(argv: string[]): Promise<void> {
  const { values } = parseArgs({ args: argv, options: { env: { type: 'string' }, 'rail-env': { type: 'string' }, 'agent-key': { type: 'string' }, invoices: { type: 'string' }, out: { type: 'string' } } });
  if (!values.env || !values['rail-env'] || !values['agent-key'] || !values.invoices || !values.out) {
    throw new Error('usage: pt2-hank-live.ts --env <agent.env> --rail-env <rail.env> --agent-key <key.json> --invoices <dir> --out <transcript.jsonl>');
  }
  const owner = assertTestnet('OWNER_ACCOUNT_ID', process.env.OWNER_ACCOUNT_ID ?? '');
  const key = JSON.parse(readFileSync(values['agent-key'], 'utf8')) as { private_key: string };
  const env: NodeJS.ProcessEnv = { ...process.env, ...parseEnv(readFileSync(values.env, 'utf8')), AGENT_NEAR_PRIVATE_KEY: key.private_key };
  const rail = parseEnv(readFileSync(values['rail-env'], 'utf8'));
  const ownerToken = rail.PP_OWNER_TOKEN ?? '';
  const railUrl = `http://127.0.0.1:${rail.PP3_PORT || 8788}`;
  const invoice = (name: string) => JSON.parse(readFileSync(join(values.invoices!, `${name}.json`), 'utf8')) as Record<string, any>;

  const buyer = await createBuyerFromEnv(env);
  const deps = (buyer as unknown as { deps: Dependencies }).deps;
  const agent = deps.signer.agent;
  const contract = env.MANDATE_CONTRACT_ID!;
  let layer = 'scam check on';
  const redact = (s: string) => buyer.redact(ownerToken ? s.split(ownerToken).join('<owner-token>') : s, { emails: true });
  const log = (e: Record<string, unknown>) => {
    const line = redact(JSON.stringify({ at: new Date().toISOString(), layer, ...e }));
    process.stdout.write(`${line}\n`);
    appendFileSync(values.out!, `${line}\n`);
  };
  const txOf = (detail: unknown) => TX.exec(String(detail ?? ''))?.[1];
  const errorCode = (detail: string) => /\bERR_[A-Z0-9_]+\b/.exec(detail)?.[0] ?? null;
  const ownerVault = async (method: 'GET' | 'POST', path: string, body?: object) => {
    const r = await fetch(`${railUrl}${path}`, { method, headers: { authorization: `Bearer ${ownerToken}`, 'content-type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
    return { http: r.status, ...(await r.json() as Record<string, unknown>) };
  };
  const railCheckout = async (order: Record<string, unknown>) => {
    const r = await fetch(`${railUrl}/checkout`, { method: 'POST', headers: { authorization: `Bearer ${env.PP3_AGENT_TOKEN}`, 'content-type': 'application/json' }, body: JSON.stringify(order) });
    return await r.json() as Record<string, unknown>;
  };
  const ownerCall = (method: string, args: object) => nearCli([
    'contract', 'call-function', 'as-transaction', contract, method, 'json-args', JSON.stringify(args),
    'prepaid-gas', '100 Tgas', 'attached-deposit', '1 yoctoNEAR',
    'sign-as', owner, 'network-config', NETWORK, 'sign-with-legacy-keychain', 'send',
  ]);
  const pay = async (beat: string, b: Buyer, inv: Record<string, any>, reason: string) => {
    log({ beat, step: 'listing', invoice_id: inv.invoice_id, amount: inv.amount.value, merchant: inv.payee, description: inv.description });
    const r = await b.payPaypal({ invoice: inv, reason, mode: 'checkout' }) as Record<string, any>;
    const receipt = deps.store.get(r.request_id);
    log({ beat, step: 'result', ...r, error_code: r.error_code ?? errorCode(String(r.detail ?? '')), near_tx_hash: receipt?.near_tx_hash ?? txOf(r.detail) ?? null, signed_text: (receipt?.reservation as any)?.payload?.text ?? null });
    return r;
  };

  // The owner's vault: confirmed once the owner approved PayPal's link (connect was the owner's step before this run).
  let vault = await ownerVault('GET', `/vault/status?agent=${agent}`);
  if (vault.status === 'approval_required') vault = await ownerVault('POST', '/vault/confirm', { agent });
  // Read now: get_mandate answers null once the agent is revoked, and the re-arm below needs it.
  const mandate = await deps.view('get_mandate', { agent });
  log({ step: 'setup', contract, agent, evm_address: deps.signer.address, mandate, merchants: await deps.view('get_payees', { agent }), vault });
  if (vault.status !== 'active') throw new Error(`the vault is not active (${String(vault.status)}); the owner approves the PayPal link first`);

  const unguarded = new Buyer(Object.assign(Object.create(deps) as Dependencies, { check: async () => ({ status: 'approved', verdict: { result: 'ok', reason: 'demo stub: approves everything' } }) as any }));
  const reason = 'Hank: buy me a holo Dragonfire trading card, under USD 100';

  // fake: the lookalike shop, with the real check, then with the check stubbed (the AI fooled).
  await pay('hank-fake', buyer, invoice('fake'), reason);
  layer = 'scam check stubbed to approve (contract alone)';
  await pay('hank-fake', unguarded, invoice('fake-again'), reason);

  // bait: an allowed shop, over the cap. With the real check first; stubbed too if it held.
  layer = 'scam check on';
  const bait = await pay('hank-bait', buyer, invoice('bait'), reason);
  if (bait.status === 'held') {
    layer = 'scam check stubbed to approve (contract alone)';
    await pay('hank-bait', unguarded, invoice('bait-again'), reason);
  }

  // buy: the real card at the real store.
  layer = 'scam check on';
  await pay('hank-buy', buyer, invoice('real'), reason);

  // swap: a second charge the contract signs (sleeves, USD 12.00, the real store), handed to the rail with the merchant swapped.
  layer = 'merchant swapped after signing';
  const sleeves = invoice('sleeves');
  const swapId = `chk-${crypto.randomUUID()}`;
  const shape = { type: 'paypal_checkout', payee: sleeves.payee, amount: sleeves.amount.value, order_ref: sleeves.invoice_id, timestamp: Math.floor(Date.now() / 1000) };
  const signed = await deps.call('request_signature', { request_id: swapId, shape });
  const reservation = signed.value as Record<string, any>;
  log({ beat: 'hank-swap', step: 'contract', request_id: swapId, outcome: reservation.status, near_tx_hash: signed.hash, signed_text: reservation.payload?.text ?? null });
  const order = { agent, request_id: swapId, payee: shape.payee, amount: shape.amount, order_ref: shape.order_ref, timestamp: shape.timestamp, signature: reservation.signature };
  log({ beat: 'hank-swap', step: 'rail', sent_merchant: SWAPPED, ...(await railCheckout({ ...order, payee: SWAPPED })) });

  // revoke: the owner revokes the agent on the contract and deletes the vault token.
  layer = 'after Hank revoked';
  const r = ownerCall('revoke', { agent, assertion: null });
  log({ beat: 'hank-revoke', step: 'contract revoke (owner)', ok: r.ok, near_tx_hash: r.txHash ?? null, ...(r.ok ? {} : { detail: r.out.slice(-400) }) });
  log({ beat: 'hank-revoke', step: 'get_agent', revoked: (await deps.view('get_agent', { agent }) as any)?.revoked ?? null });
  log({ beat: 'hank-revoke', step: 'vault revoke (owner)', ...(await ownerVault('POST', '/vault/revoke', { agent })) });
  // The agent's next request: its function-call key was deleted by the revoke.
  await pay('hank-revoke', buyer, invoice('pages'), reason);
  // The swap beat's signed charge, unspent, handed to the rail unchanged.
  log({ beat: 'hank-revoke', step: 'rail, signed before the revoke', ...(await railCheckout(order)) });
  // Re-arming the revoked agent from the owner side.
  const rearm = ownerCall('set_mandate', { agent, mandate, assertion: null });
  log({ beat: 'hank-revoke', step: 'set_mandate after revoke (owner)', ok: rearm.ok, error_code: errorCode(rearm.out), near_tx_hash: rearm.txHash ?? null });
  log({ step: 'after', budget: await deps.view('get_budget', { agent, rail: 'paypal' }), vault: await ownerVault('GET', `/vault/status?agent=${agent}`) });
}

main(process.argv.slice(2)).catch(error => {
  process.stderr.write(`pt2-hank-live: ${error instanceof Error ? error.message.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '<email>') : String(error)}\n`);
  process.exitCode = 1;
});
