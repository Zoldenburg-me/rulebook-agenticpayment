// Base Sepolia plumbing: one JSON-RPC helper, ERC-20 reads and the calldata the scripts send.

import { createCallData, getFunctionSelector } from "abstractionkit";

export const BASE_SEPOLIA_CHAIN_ID = 84532n;

export type BaseConfig = { rpc: string; bundler: string; paymaster: string };

export function baseConfig(): BaseConfig {
  const bundler = process.env.BUNDLER_URL || `https://api.candide.dev/public/v3/${BASE_SEPOLIA_CHAIN_ID}`;
  return {
    rpc: process.env.BASE_SEPOLIA_RPC_URL || "https://sepolia.base.org",
    bundler,
    paymaster: process.env.PAYMASTER_URL || bundler,
  };
}

export async function ethRpc(url: string, method: string, params: unknown[]): Promise<any> {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const body = (await res.json()) as any;
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

/** Testnet only: the RPC, the bundler and the paymaster must all be Base Sepolia. */
export async function assertBaseSepolia(cfg: BaseConfig): Promise<void> {
  for (const url of new Set([cfg.rpc, cfg.bundler, cfg.paymaster])) {
    const id = BigInt(await ethRpc(url, "eth_chainId", []));
    if (id !== BASE_SEPOLIA_CHAIN_ID) throw new Error(`${new URL(url).host} is chain ${id}, not Base Sepolia (${BASE_SEPOLIA_CHAIN_ID})`);
  }
}

export function assertAddress(field: string, a: string | undefined): string {
  if (!a || !/^0x[0-9a-fA-F]{40}$/.test(a)) throw new Error(`${field} must be a 0x address, got "${a}"`);
  return a.toLowerCase();
}

export async function erc20Balance(rpc: string, token: string, holder: string): Promise<bigint> {
  const data = createCallData(getFunctionSelector("balanceOf(address)"), ["address"], [holder]);
  return BigInt(await ethRpc(rpc, "eth_call", [{ to: token, data }, "latest"]));
}

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

export type Log = { address: string; topics: string[]; data: string };

/** Whether `logs` hold an ERC-20 `Transfer(from, to, amount)` of `token`: proof of the transfer itself, not of a net balance. */
export function hasErc20Transfer(logs: Log[], token: string, from: string, to: string, amount: bigint): boolean {
  const topicOf = (a: string) => "0x" + a.toLowerCase().replace(/^0x/, "").padStart(64, "0");
  return logs.some(
    (l) =>
      l.address.toLowerCase() === token.toLowerCase() &&
      l.topics.length === 3 &&
      l.topics[0].toLowerCase() === TRANSFER_TOPIC &&
      l.topics[1].toLowerCase() === topicOf(from) &&
      l.topics[2].toLowerCase() === topicOf(to) &&
      BigInt(l.data) === amount,
  );
}

/**
 * The Base tx's logs (the bundle may hold other UserOperations; callers look for their own Transfer).
 * The RPC node can lag the bundler, so a missing receipt is retried for about a minute.
 */
export async function txLogs(rpc: string, tx: string, tries = 30): Promise<Log[]> {
  for (let i = 0; i < tries; i++) {
    const r = await ethRpc(rpc, "eth_getTransactionReceipt", [tx]);
    if (r) {
      if (r.status !== "0x1") throw new Error(`tx ${tx} reverted`);
      return r.logs;
    }
    await new Promise((res) => setTimeout(res, 2000));
  }
  throw new Error(`no receipt for tx ${tx} from the RPC yet; check it on sepolia.basescan.org before running again`);
}

export function transferCallData(to: string, amount: bigint): string {
  return createCallData(getFunctionSelector("transfer(address,uint256)"), ["address", "uint256"], [to, amount]);
}

/** The signed reservation payload of a USDC sweep (docs/interfaces.md §4, `kind: "eip3009"`). */
export type Eip3009Payload = {
  kind: "eip3009";
  asset: string;
  chain_id: number;
  from: string;
  to: string;
  value: string;
  valid_after: number;
  valid_before: number;
  nonce: string;
};

export type MpcSignature = { r: string; s: string; v: number };

/** USDC `transferWithAuthorization(from, to, value, validAfter, validBefore, nonce, v, r, s)`. */
export function transferWithAuthorizationCallData(p: Eip3009Payload, sig: MpcSignature): string {
  return createCallData(
    getFunctionSelector("transferWithAuthorization(address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32)"),
    ["address", "address", "uint256", "uint256", "uint256", "bytes32", "uint8", "bytes32", "bytes32"],
    [p.from, p.to, BigInt(p.value), BigInt(p.valid_after), BigInt(p.valid_before), p.nonce, BigInt(sig.v), sig.r, sig.s],
  );
}
