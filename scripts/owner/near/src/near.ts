// NEAR testnet plumbing: config, read-only RPC views, and transactions sent through
// near-cli-rs with the legacy keychain (~/.near-credentials), as spikes/deletekey does.
// Scripts never trust a tx status: after each tx they read the contract state and keys.

import { spawnSync } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";

export const NETWORK = "testnet";

/** Hosts NEAR_RPC may point at; all serve NEAR testnet. */
export const TESTNET_RPC_HOSTS = ["rpc.testnet.near.org", "archival-rpc.testnet.near.org", "test.rpc.fastnear.com"];

/** The contract's agent key method names (contract/src/types.rs AGENT_METHOD_NAMES). */
export const AGENT_METHOD_NAMES = ["request_signature", "sweep", "revoke_self"];

export type Config = {
  rpc: string;
  contractId: string;
  mpcContract: string;
  keyDir: string;
};

/** Testnet only: every account must be a `.testnet` account. */
/** The contract's agent id rule (contract/src/state.rs validate_agent_id). With no `/` or `\\`, `<id>.json` stays in its directory. */
export function assertAgentId(agent: string | undefined): string {
  if (!agent || !/^[A-Za-z0-9._:-]{1,64}$/.test(agent)) {
    throw new Error(`agent must be 1-64 chars of [A-Za-z0-9._:-], got "${agent}"`);
  }
  return agent;
}

export function assertTestnet(field: string, account: string): string {
  if (!/^[a-z0-9._-]+\.testnet$/.test(account)) throw new Error(`${field} must be a .testnet account, got "${account}"`);
  return account;
}

export function env(name: string, fallback?: string): string {
  const v = process.env[name] ?? fallback;
  if (!v) throw new Error(`set ${name}`);
  return v;
}

/** https, no credentials, and a hostname on TESTNET_RPC_HOSTS. */
export function assertTestnetRpc(rpc: string): void {
  let url: URL | undefined;
  try {
    url = new URL(rpc);
  } catch {}
  if (!url || url.protocol !== "https:" || url.username || url.password || !TESTNET_RPC_HOSTS.includes(url.hostname)) {
    throw new Error(`NEAR_RPC must be an https testnet RPC (${TESTNET_RPC_HOSTS.join(", ")}), got ${rpc}`);
  }
}

export function config(): Config {
  const rpc = env("NEAR_RPC", "https://rpc.testnet.near.org");
  assertTestnetRpc(rpc);
  return {
    rpc,
    contractId: assertTestnet("CONTRACT_ID", env("CONTRACT_ID")),
    mpcContract: assertTestnet("MPC_CONTRACT", env("MPC_CONTRACT", "v1.signer-prod.testnet")),
    keyDir: env("OWNER_KEY_DIR", join(homedir(), ".nearh-owner")),
  };
}

async function rpc(cfg: Config, params: Record<string, unknown>): Promise<any> {
  const res = await fetch(cfg.rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "query", params: { finality: "final", ...params } }),
  });
  const body = (await res.json()) as any;
  if (body.error) throw new Error(`rpc ${params.request_type}: ${JSON.stringify(body.error)}`);
  if (body.result?.error) throw new Error(`rpc ${params.request_type}: ${body.result.error}`);
  return body.result;
}

/** A view call; returns the parsed JSON result. */
export async function view<T = any>(cfg: Config, contractId: string, method: string, args: object = {}): Promise<T> {
  const r = await rpc(cfg, {
    request_type: "call_function",
    account_id: contractId,
    method_name: method,
    args_base64: Buffer.from(JSON.stringify(args)).toString("base64"),
  });
  return JSON.parse(Buffer.from(r.result).toString());
}

export type AccessKey = {
  public_key: string;
  access_key: {
    permission: "FullAccess" | { FunctionCall: { allowance: string | null; receiver_id: string; method_names: string[] } };
  };
};

/** `code_hash` of an account with no contract deployed. */
export const EMPTY_CODE_HASH = "11111111111111111111111111111111";

export async function codeHash(cfg: Config, accountId: string): Promise<string> {
  return (await rpc(cfg, { request_type: "view_account", account_id: accountId })).code_hash;
}

export async function accessKeys(cfg: Config, accountId: string): Promise<AccessKey[]> {
  return (await rpc(cfg, { request_type: "view_access_key_list", account_id: accountId })).keys;
}

export const isFullAccess = (k: AccessKey) => k.access_key.permission === "FullAccess";

/** One line per key: public key and permission. No private material exists in this data. */
export function describeKeys(keys: AccessKey[]): string {
  if (keys.length === 0) return "  (no access keys)";
  return keys
    .map((k) => {
      const p = k.access_key.permission;
      if (p === "FullAccess") return `  ${k.public_key}  FULL ACCESS`;
      const fc = p.FunctionCall;
      return `  ${k.public_key}  function-call on ${fc.receiver_id} ${JSON.stringify(fc.method_names)} allowance ${fc.allowance ?? "unlimited"}`;
    })
    .join("\n");
}

/**
 * Hides every NEAR key, public or secret (ed25519: 32-byte public, 64-byte secret; secp256k1:
 * 64-byte public, 32-byte secret; 32 bytes is at least 32 base58 chars), and drops seed/private lines.
 * The curve prefix matches anywhere (no word boundary, so ANSI colour codes or `pk_` in front still
 * redact), in any case, with `:` or URL-encoded `%3A`. Bare base58 keys without a prefix stay
 * unredacted by design: they can't be told apart from tx hashes, which must stay visible.
 */
export function redact(out: string): string {
  return out
    .replace(/(ed25519|secp256k1)(:|%3A)[1-9A-HJ-NP-Za-km-z]{32,}/gi, "$1$2<redacted>")
    .split("\n")
    .filter((l) => !/seed|private/i.test(l))
    .join("\n");
}

/** Runs near-cli-rs; returns its redacted output (stdout + stderr) and the tx hash if printed. */
export function nearCli(args: string[]): { ok: boolean; out: string; txHash?: string } {
  const r = spawnSync("near", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (r.error) throw r.error;
  const out = redact(`${r.stdout}${r.stderr}`);
  const txHash = out.match(/Transaction ID: ([1-9A-HJ-NP-Za-km-z]+)/)?.[1];
  return { ok: r.status === 0, out, txHash };
}

/** A function call on the contract, signed by `signer` from the legacy keychain. */
export function callContract(
  cfg: Config,
  signer: string,
  method: string,
  args: object,
  gas = "100 Tgas",
): { ok: boolean; out: string; txHash?: string } {
  return nearCli([
    "contract", "call-function", "as-transaction", cfg.contractId, method,
    "json-args", JSON.stringify(args),
    "prepaid-gas", gas, "attached-deposit", "0 NEAR",
    "sign-as", assertTestnet("signer", signer),
    "network-config", NETWORK, "sign-with-legacy-keychain", "send",
  ]);
}

/** Polls `check` until it returns a value (state lags the tx by a block or two at `final`). */
export async function waitFor<T>(what: string, check: () => Promise<T | undefined>, tries = 15): Promise<T> {
  for (let i = 0; i < tries; i++) {
    const v = await check();
    if (v !== undefined) return v;
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`state check failed: ${what}`);
}
