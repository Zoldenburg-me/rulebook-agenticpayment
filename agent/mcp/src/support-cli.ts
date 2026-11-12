// PP-T1: runs support tickets through the SupportAgent against the testnet mandate contract and the
// PayPal rail's refund service (rails/paypal `pnpm refunds`). The agent process holds its NEAR
// function-call key, its rail token and the NEAR AI key; never a PayPal credential.
//
//   node --env-file=.env.support src/support-cli.ts --tickets <file.json> [--out transcript.jsonl]
//
// Env: MANDATE_CONTRACT_ID, AGENT_NEAR_PRIVATE_KEY, AGENT_EVM_ADDRESS (optional check), NEAR_RPC,
// PP_REFUND_URL (default http://127.0.0.1:8790), PP3_AGENT_TOKEN, NEAR_AI_API_KEY or NEAR_AI_ENV_FILE,
// SUPPORT_MODEL (default deepseek-ai/DeepSeek-V4.1-Flash-1017), SCAMCHECK_HELD_DIR.
import { appendFileSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { checkAndHold } from 'scamcheck';
import { NearX402Signer, REQUEST_GAS, DEFAULT_TIMEOUT_MS, assertTestnet, assertTestnetRpc, callAndWait, failureMessage, httpRpc, parseNearKey } from '@nearh/agent-signer';
import { scamcheckConfig } from './runtime.ts';
import { openAiChat, railClient, SupportAgent, type SupportDeps, type Ticket } from './support.ts';

const need = (env: NodeJS.ProcessEnv, name: string, fallback?: string) => {
  const v = env[name] || fallback;
  if (!v) throw new Error(`Set ${name}`);
  return v;
};

/** The agent's wiring from env; the demo replaces single parts (its layer 2 swaps the scam check). */
export async function supportDepsFromEnv(env: NodeJS.ProcessEnv = process.env, log?: (e: Record<string, unknown>) => void): Promise<SupportDeps> {
  const rpcUrl = need(env, 'NEAR_RPC', 'https://rpc.testnet.near.org');
  assertTestnetRpc(rpcUrl);
  const contractId = assertTestnet('MANDATE_CONTRACT_ID', need(env, 'MANDATE_CONTRACT_ID'));
  const near = httpRpc(rpcUrl);
  const key = parseNearKey(contractId, need(env, 'AGENT_NEAR_PRIVATE_KEY'));
  const signer = await NearX402Signer.connect({ near, key, contractId, expectedAddress: env.AGENT_EVM_ADDRESS || undefined });
  const scam = scamcheckConfig(env);
  if (!scam.apiKey) throw new Error('Set NEAR_AI_API_KEY (or NEAR_AI_ENV_FILE): the model and the scam check both need it');
  const token = need(env, 'PP3_AGENT_TOKEN');
  return {
    agent: signer.agent,
    chat: openAiChat({ apiKey: scam.apiKey, baseUrl: env.NEAR_AI_BASE_URL || 'https://cloud-api.near.ai/v1', model: env.SUPPORT_MODEL || 'deepseek-ai/DeepSeek-V4.1-Flash-1017' }),
    rail: railClient(need(env, 'PP_REFUND_URL', 'http://127.0.0.1:8790'), signer.agent, token),
    check: params => checkAndHold(params, scam),
    call: async (method, args) => {
      const outcome = await callAndWait(near, key, contractId, method, args, { gas: REQUEST_GAS, deadlineMs: Date.now() + DEFAULT_TIMEOUT_MS });
      if (outcome.failure !== undefined) throw new Error(`${method}: ${failureMessage(outcome.failure)} (tx ${outcome.hash})`);
      if (outcome.successValue === undefined) throw new Error(`${method}: no final result (tx ${outcome.hash})`);
      return { hash: outcome.hash, value: JSON.parse(Buffer.from(outcome.successValue, 'base64').toString()) as unknown };
    },
    secrets: [env.AGENT_NEAR_PRIVATE_KEY ?? '', token, scam.apiKey],
    log,
  };
}

async function main(argv: string[]): Promise<void> {
  const { values } = parseArgs({ args: argv, options: { tickets: { type: 'string' }, out: { type: 'string' } } });
  if (!values.tickets) throw new Error('usage: support-cli --tickets <file.json> [--out transcript.jsonl]');
  const tickets = JSON.parse(readFileSync(values.tickets, 'utf8')) as Ticket[];
  const out = values.out;
  const log = (e: Record<string, unknown>) => {
    const line = JSON.stringify({ at: new Date().toISOString(), ...e });
    process.stdout.write(`${line}\n`);
    if (out) appendFileSync(out, `${line}\n`);
  };
  const agent = new SupportAgent(await supportDepsFromEnv(process.env, log));
  for (const ticket of tickets) await agent.handle(ticket);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => {
    process.stderr.write(`support: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
