// Wiring for the PP3 service: PayPal credentials from a file into a private object (never into
// process.env, so no child process or agent inherits them), NEAR views over testnet RPC (O1's
// plumbing) and the file store.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import { assertTestnet, assertTestnetRpc, callContract, view, type Config } from "@nearh/owner-near/src/near.ts";
import { sandboxClient, type Fetch } from "./paypal.ts";
import type { Deps, Near } from "./payout.ts";
import { parseAgentTokens } from "./server.ts";
import { fileStore } from "./store.ts";
import { fileVaultStore, type VaultDeps } from "./vault.ts";
import { fileSeen, type Report, type WebhookDeps } from "./webhook.ts";

const PACKAGE_DIR = fileURLToPath(new URL("..", import.meta.url));

/** PAYPAL_ENV_FILE, else ~/.config/nearh/paypal-sandbox.env. */
export function credentialsFile(env: NodeJS.ProcessEnv = process.env): string {
  return env.PAYPAL_ENV_FILE || join(homedir(), ".config", "nearh", "paypal-sandbox.env");
}

export function readCredentials(file: string): Record<string, string | undefined> {
  try {
    return { ...parseEnv(readFileSync(file, "utf8")) };
  } catch {
    throw new Error("cannot read the PayPal credentials file (PAYPAL_ENV_FILE)");
  }
}

export function nearViews(cfg: Pick<Config, "rpc" | "contractId">): Near {
  const c = cfg as Config;
  return {
    getAgent: (agent) => view(c, c.contractId, "get_agent", { agent }),
    getRequest: (key) => view(c, c.contractId, "get_request", { key }),
    getPayees: (agent) => view(c, c.contractId, "get_payees", { agent }),
    getSuspendedPayees: (agent) => view(c, c.contractId, "get_suspended_payees", { agent }),
  };
}

/** Per-agent bearer tokens for the service: PP3_AGENT_TOKENS from the environment, else the credentials file. */
export function agentTokens(env: NodeJS.ProcessEnv = process.env): Map<string, string> {
  return parseAgentTokens(env.PP3_AGENT_TOKENS || readCredentials(credentialsFile(env)).PP3_AGENT_TOKENS);
}

export function deps(env: NodeJS.ProcessEnv = process.env, fetcher: Fetch = fetch): Deps {
  const rpc = env.NEAR_RPC || "https://rpc.testnet.near.org";
  assertTestnetRpc(rpc);
  if (!env.CONTRACT_ID) throw new Error("set CONTRACT_ID");
  const contractId = assertTestnet("CONTRACT_ID", env.CONTRACT_ID);
  const creds = readCredentials(credentialsFile(env));
  return {
    near: nearViews({ rpc, contractId }),
    paypal: sandboxClient(creds, fetcher),
    secrets: [creds.PAYPAL_CLIENT_ID, creds.PAYPAL_CLIENT_SECRET].filter((v): v is string => !!v),
    store: fileStore(env.PP3_STORE_DIR || join(PACKAGE_DIR, ".orders")),
    log: (line) => console.log(line),
  };
}

/**
 * PP-V1: the vault routes' wiring, or undefined when PP_OWNER_TOKEN is unset (the routes stay off).
 * The vault store holds the payment token ids; it is a separate directory from the order store.
 */
export function vaultRoutes(base: Deps, env: NodeJS.ProcessEnv = process.env): { deps: VaultDeps; ownerToken: string } | undefined {
  const ownerToken = env.PP_OWNER_TOKEN || readCredentials(credentialsFile(env)).PP_OWNER_TOKEN;
  if (!ownerToken) return undefined;
  return { ownerToken, deps: { ...base, vaults: fileVaultStore(env.PP_VAULT_DIR || join(PACKAGE_DIR, ".vault")) } };
}

/**
 * The PP-W1 receiver's wiring. Reports go to `report_settlement` signed by SETTLEMENT_REPORTER through
 * near-cli-rs (legacy keychain), or, with PP_WEBHOOK_REPORT=log, only to the log (no contract call).
 */
export function webhookDeps(env: NodeJS.ProcessEnv = process.env, fetcher: Fetch = fetch): WebhookDeps {
  const creds = readCredentials(credentialsFile(env));
  const webhookId = env.PAYPAL_WEBHOOK_ID || creds.PAYPAL_WEBHOOK_ID;
  if (!webhookId) throw new Error("set PAYPAL_WEBHOOK_ID (the id of the sandbox webhook subscription)");
  const log = (line: string) => console.log(`${new Date().toISOString()} ${line}`);
  let report: (r: Report) => Promise<void>;
  if (env.PP_WEBHOOK_REPORT === "log") {
    report = async (r) => log(`report (log only, no contract call): ${JSON.stringify(r)}`);
  } else {
    const rpc = env.NEAR_RPC || "https://rpc.testnet.near.org";
    assertTestnetRpc(rpc);
    if (!env.CONTRACT_ID || !env.SETTLEMENT_REPORTER) throw new Error("set CONTRACT_ID and SETTLEMENT_REPORTER, or PP_WEBHOOK_REPORT=log");
    const cfg = { rpc, contractId: assertTestnet("CONTRACT_ID", env.CONTRACT_ID) } as Config;
    const reporter = assertTestnet("SETTLEMENT_REPORTER", env.SETTLEMENT_REPORTER);
    report = async (r) => {
      const out = callContract(cfg, reporter, "report_settlement", r);
      if (!out.ok) throw new Error(`report_settlement failed: ${out.out.slice(-300)}`);
      log(`report_settlement tx ${out.txHash ?? "?"}`);
    };
  }
  return {
    paypal: sandboxClient(creds, fetcher),
    webhookId,
    store: fileStore(env.PP3_STORE_DIR || join(PACKAGE_DIR, ".orders")),
    agents: [...agentTokens(env).keys()],
    seen: fileSeen(env.PP_WEBHOOK_SEEN_DIR || join(PACKAGE_DIR, ".webhook-seen")),
    report,
    log,
    secrets: [creds.PAYPAL_CLIENT_ID, creds.PAYPAL_CLIENT_SECRET].filter((v): v is string => !!v),
  };
}
