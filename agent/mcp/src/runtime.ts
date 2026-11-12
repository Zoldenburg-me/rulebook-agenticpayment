import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';
import { checkAndHold, readHeldQueue, type ScamcheckConfig } from 'scamcheck';
import { createPublicClient, erc20Abi, getAddress, http } from 'viem';
import { baseSepolia } from 'viem/chains';
import { NearX402Signer, httpRpc, parseNearKey, REQUEST_GAS, DEFAULT_TIMEOUT_MS } from '@nearh/agent-signer';
import { assertTestnet, assertTestnetRpc, callAndWait, failureMessage, view } from '@nearh/agent-signer';
import { Buyer, type HeldDecision, type PaypalOrder } from './buyer.ts';
import { verifyHeldDecision } from '@nearh/dashboard/decisions';
import { verifyX402Settlement } from './settlement.ts';
import { ReceiptStore } from './store.ts';

const pkgDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const envValue = (env: NodeJS.ProcessEnv, name: string, fallback?: string): string => {
  const value = env[name] || fallback;
  if (!value) throw new Error(`Set ${name}`);
  return value;
};

/** An authenticated local rail endpoint, fixed by the operator rather than tool arguments. */
export function m1Endpoint(raw: string): string {
  const url = new URL(raw);
  if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname) || url.username || url.password || url.search || url.hash || url.pathname !== '/payouts') {
    throw new Error('M1_URL must be http://127.0.0.1:<port>/payouts (or [::1])');
  }
  return url.href;
}

/** PP3's local service, fixed by the operator rather than tool arguments. */
export function pp3Endpoint(raw: string, path: '/payouts' | '/checkout' = '/payouts'): string {
  const url = new URL(raw);
  if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname) || url.username || url.password || url.search || url.hash || url.pathname !== path) {
    throw new Error(`PP3_URL must be http://127.0.0.1:<port>${path} (or [::1])`);
  }
  return url.href;
}

/**
 * Calls PP3 once per order; a timeout never triggers another POST. PP3 answers 400/401/403/404/413
 * and 502 `PP3_ERROR` before it claims an order, so those are `failed`; any other non-2xx throws
 * (uncertain).
 */
export function pp3Client(endpoint: string, token: string, fetcher: typeof fetch = fetch, path: '/payouts' | '/checkout' = '/payouts') {
  const url = pp3Endpoint(endpoint, path);
  return async (order: PaypalOrder): Promise<Record<string, unknown>> => {
    const response = await fetcher(url, {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify(order), signal: AbortSignal.timeout(45_000), redirect: 'error',
    });
    if ([400, 401, 403, 404, 413].includes(response.status)) {
      return { status: 'failed', request_id: order.request_id, error_code: `PP3_HTTP_${response.status}`, detail: `PP3 refused the call with HTTP ${response.status} before claiming the order` };
    }
    const result: unknown = await response.json().catch(() => undefined);
    if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error(`PP3 returned HTTP ${response.status} without a result; inspect its order log before anything else`);
    const body = result as Record<string, unknown>;
    if (response.status === 502 && body.error_code === 'PP3_ERROR' && body.status === 'failed') return body;
    if (!response.ok) throw new Error(`PP3 returned HTTP ${response.status}; inspect its order log before anything else`);
    return body;
  };
}

/**
 * SC1's settings, injected rather than left to process.env: NEAR_AI_* and SCAMCHECK_HELD_DIR from
 * `env`; without NEAR_AI_API_KEY there, the key comes from NEAR_AI_ENV_FILE (which must be
 * readable) or else `defaultKeyFile` if present. The key never goes into process.env.
 */
export function scamcheckConfig(env: NodeJS.ProcessEnv = process.env, defaultKeyFile = join(homedir(), '.config', 'nearh', 'nearai.env')): ScamcheckConfig {
  let apiKey = env.NEAR_AI_API_KEY;
  if (!apiKey) {
    const file = env.NEAR_AI_ENV_FILE || defaultKeyFile;
    let raw: string | undefined;
    try {
      raw = readFileSync(file, 'utf8');
    } catch (error) {
      if (env.NEAR_AI_ENV_FILE || (error as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error('cannot read the NEAR AI key file (NEAR_AI_ENV_FILE)');
    }
    if (raw !== undefined) apiKey = parseEnv(raw).NEAR_AI_API_KEY;
  }
  return { apiKey: apiKey || undefined, baseUrl: env.NEAR_AI_BASE_URL || undefined, model: env.NEAR_AI_MODEL || undefined, heldDir: env.SCAMCHECK_HELD_DIR || undefined };
}

export async function createBuyerFromEnv(env: NodeJS.ProcessEnv = process.env): Promise<Buyer> {
  const rpcUrl = envValue(env, 'NEAR_RPC', 'https://rpc.testnet.near.org');
  assertTestnetRpc(rpcUrl);
  const contractId = assertTestnet('MANDATE_CONTRACT_ID', envValue(env, 'MANDATE_CONTRACT_ID'));
  const near = httpRpc(rpcUrl);
  const key = parseNearKey(contractId, envValue(env, 'AGENT_NEAR_PRIVATE_KEY'));
  const scam = scamcheckConfig(env);
  const signer = await NearX402Signer.connect({ near, key, contractId, expectedAddress: env.AGENT_EVM_ADDRESS || undefined });
  let payoutClient: ReturnType<typeof m1Client> | undefined;
  const sepaClient = () => {
    if (!payoutClient) {
      const endpoint = m1Endpoint(envValue(env, 'M1_URL', 'http://127.0.0.1:8787/payouts'));
      const token = envValue(env, 'M1_AGENT_TOKEN');
      if (!/^[A-Za-z0-9._~+\/=-]{32,256}$/.test(token)) throw new Error('M1_AGENT_TOKEN must be a 32-256 character per-agent service token');
      payoutClient = m1Client(endpoint, token);
    }
    return payoutClient;
  };
  const paypalRails = new Map<string, ReturnType<typeof pp3Client>>();
  const paypalClient = (mode: 'payout' | 'checkout' = 'payout') => {
    let rail = paypalRails.get(mode);
    if (!rail) {
      const endpoint = pp3Endpoint(envValue(env, 'PP3_URL', 'http://127.0.0.1:8788/payouts'));
      const token = envValue(env, 'PP3_AGENT_TOKEN');
      if (!/^[A-Za-z0-9._~+\/=-]{32,256}$/.test(token)) throw new Error('PP3_AGENT_TOKEN must be a 32-256 character per-agent service token');
      // Checkout (PP-V1) is the same PP3 service and token, path /checkout.
      rail = mode === 'checkout' ? pp3Client(new URL('/checkout', endpoint).href, token, fetch, '/checkout') : pp3Client(endpoint, token);
      paypalRails.set(mode, rail);
    }
    return rail;
  };
  const query = (method: string, args: object) => view<unknown>(near, contractId, method, args);
  const store = new ReceiptStore(resolve(pkgDir, env.MCP_RECEIPT_DIR || '.receipts', contractId, signer.agent));
  const baseClient = async () => {
    const evm = createPublicClient({ chain: baseSepolia, transport: http(envValue(env, 'BASE_SEPOLIA_RPC', 'https://sepolia.base.org'), { timeout: 15_000, retryCount: 0 }) });
    if (await evm.getChainId() !== baseSepolia.id) throw new Error('Base RPC must be on Base Sepolia');
    return evm;
  };
  return new Buyer({
    signer,
    get allowedOrigins() {
      return envValue(env, 'MCP_SELLER_ORIGINS').split(',').map(origin => new URL(origin.trim()).origin);
    },
    secrets: [env.M1_AGENT_TOKEN ?? '', env.PP3_AGENT_TOKEN ?? '', env.AGENT_NEAR_PRIVATE_KEY ?? '', scam.apiKey ?? ''],
    check: params => checkAndHold(params, scam),
    readHeld: () => readHeldQueue(scam) as Promise<HeldDecision[]>,
    store,
    view: query,
    call: async (method, args) => {
      const outcome = await callAndWait(near, key, contractId, method, args, { gas: REQUEST_GAS, deadlineMs: Date.now() + DEFAULT_TIMEOUT_MS });
      if (outcome.failure !== undefined) throw new Error(`${method}: ${failureMessage(outcome.failure)} (tx ${outcome.hash})`);
      if (outcome.successValue === undefined) throw new Error(`${method}: no final result (tx ${outcome.hash})`);
      return { hash: outcome.hash, value: JSON.parse(Buffer.from(outcome.successValue, 'base64').toString()) as unknown };
    },
    balance: async rail => {
      // Payment dependencies must never block NEAR-only revoke or receipt access.
      if (rail === 'sepa') sepaClient();
      const evm = await baseClient();
      const record = await query('get_agent', { agent: signer.agent }) as { sweep_config: { usdc_address: string; eure_address: string } } | null;
      if (!record) throw new Error('Agent record not found');
      const tokenAddress = rail === 'x402' ? record.sweep_config.usdc_address : record.sweep_config.eure_address;
      return evm.readContract({ address: getAddress(tokenAddress), abi: erc20Abi, functionName: 'balanceOf', args: [signer.address] });
    },
    submit: input => sepaClient()(input),
    paypalRail: paypalClient,
    notifyOwner: message => { process.stderr.write(`${message}\n`); },
    verifyDecision: item => verifyOwnerDecision(query, contractId, store, item),
    verifySettlement: async (receipt, hash) => {
      const evm = await baseClient();
      const record = await query('get_agent', { agent: signer.agent }) as { sweep_config: { usdc_address: string } } | null;
      if (!record) return false;
      return verifyX402Settlement(evm, receipt, hash, signer.address, record.sweep_config.usdc_address);
    },
  });
}

/** Calls the configured service once; a timeout never triggers another POST. */
export function m1Client(endpoint: string, token: string, fetcher: typeof fetch = fetch) {
  const url = m1Endpoint(endpoint);
  return async (input: import('./buyer.ts').PayoutInput): Promise<Record<string, unknown>> => {
    const response = await fetcher(url, {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify(input), signal: AbortSignal.timeout(45_000), redirect: 'error',
    });
    if (!response.ok) throw new Error(`M1 returned HTTP ${response.status}; inspect its private order log before retrying`);
    const result: unknown = await response.json();
    if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('Invalid M1 response');
    return result as Record<string, unknown>;
  };
}

/** Recheck the passkey proof stored by the dashboard; a writable queue is not approval authority. */
export async function verifyOwnerDecision(query: (method: string, args: object) => Promise<unknown>, contractId: string, store: ReceiptStore, item: HeldDecision): Promise<void> {
  if (item.status !== 'approved' && item.status !== 'rejected') throw new Error('Invalid owner decision');
  if (!item.assertion || !Number.isSafeInteger(item.decided_nonce) || item.decided_nonce !== item.assertion.owner_nonce) throw new Error('Missing or inconsistent owner assertion/nonce');
  const timestamp = Date.parse(item.decided_at ?? '');
  if (!Number.isFinite(timestamp) || timestamp > Date.now() + 60_000) throw new Error('Invalid decision timestamp');
  const minNonce = store.all().reduce((max, receipt) => Math.max(max, receipt.decision_nonce ?? 0), 0);
  const config = await query('get_config', {});
  await verifyHeldDecision({ config, contractId, id: item.id, status: item.status, assertion: item.assertion, minNonce, nowSecs: Math.floor(Date.now() / 1000) });
}
