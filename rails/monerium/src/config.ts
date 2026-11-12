// Wiring for the M1 service: Monerium credentials from a file into a private object (never into
// process.env, so no child process or agent inherits them), NEAR views over testnet RPC (O1's
// plumbing) and the file store.

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import { assertTestnet, assertTestnetRpc, view, type Config } from "@nearh/owner-near/src/near.ts";
import { sandboxClient, type Fetch } from "@nearh/owner-monerium/src/monerium.ts";
import type { Deps, Near } from "./payout.ts";
import { parseAgentTokens } from "./server.ts";
import { fileStore } from "./store.ts";

const PACKAGE_DIR = fileURLToPath(new URL("..", import.meta.url));

/** MONERIUM_ENV_FILE, else ~/.config/nearh/monerium-sandbox.env, else rails/monerium/.env. */
export function credentialsFile(env: NodeJS.ProcessEnv = process.env): string {
  if (env.MONERIUM_ENV_FILE) return env.MONERIUM_ENV_FILE;
  const home = join(homedir(), ".config", "nearh", "monerium-sandbox.env");
  return existsSync(home) ? home : join(PACKAGE_DIR, ".env");
}

export function readCredentials(file: string): Record<string, string | undefined> {
  try {
    return { ...parseEnv(readFileSync(file, "utf8")) };
  } catch {
    throw new Error("cannot read the Monerium credentials file (MONERIUM_ENV_FILE)");
  }
}

export function nearViews(cfg: Pick<Config, "rpc" | "contractId">): Near {
  const c = cfg as Config;
  return {
    getAgent: (agent) => view(c, c.contractId, "get_agent", { agent }),
    getRequest: (key) => view(c, c.contractId, "get_request", { key }),
    getPayees: (agent) => view(c, c.contractId, "get_payees", { agent }),
  };
}

/** Per-agent bearer tokens for the service: M1_AGENT_TOKENS from the environment, else the credentials file. */
export function agentTokens(env: NodeJS.ProcessEnv = process.env): Map<string, string> {
  return parseAgentTokens(env.M1_AGENT_TOKENS || readCredentials(credentialsFile(env)).M1_AGENT_TOKENS);
}

export function deps(env: NodeJS.ProcessEnv = process.env, fetcher: Fetch = fetch): Deps {
  const rpc = env.NEAR_RPC || "https://rpc.testnet.near.org";
  assertTestnetRpc(rpc);
  if (!env.CONTRACT_ID) throw new Error("set CONTRACT_ID");
  const contractId = assertTestnet("CONTRACT_ID", env.CONTRACT_ID);
  const creds = readCredentials(credentialsFile(env));
  return {
    near: nearViews({ rpc, contractId }),
    monerium: sandboxClient(creds, fetcher),
    secrets: [creds.MONERIUM_CLIENT_ID, creds.MONERIUM_CLIENT_SECRET].filter((v): v is string => !!v),
    store: fileStore(env.M1_STORE_DIR || join(PACKAGE_DIR, ".orders")),
    counterpart: {
      firstName: creds.M1_COUNTERPART_FIRST_NAME || "Test",
      lastName: creds.M1_COUNTERPART_LAST_NAME || "Recipient",
    },
    log: (line) => console.log(line),
  };
}
