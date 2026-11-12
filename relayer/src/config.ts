// Config from the environment (relayer/.env, shape in .env.example). Testnet only.

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { unhex } from "./evm.ts";
import { FileJournal } from "./journal.ts";
import { assertTestnet, assertTestnetRpc, parseNearKey, type NearSigner } from "./near.ts";
import { httpRpc, type Rpc } from "./rpc.ts";

export function env(name: string, fallback?: string): string {
  const v = process.env[name] || fallback;
  if (!v) throw new Error(`set ${name}`);
  return v;
}

export function nearConfig(): { near: Rpc; contractId: string; journal: FileJournal } {
  const rpc = env("NEAR_RPC", "https://rpc.testnet.near.org");
  assertTestnetRpc(rpc);
  return {
    near: httpRpc(rpc),
    contractId: assertTestnet("CONTRACT_ID", env("CONTRACT_ID")),
    journal: new FileJournal(env("RELAYER_JOURNAL", join(homedir(), ".config", "nearh", "relayer-journal"))),
  };
}

export function nearSigner(prefix: "SUBMITTER" | "RELAYER"): NearSigner {
  const account = assertTestnet(`${prefix}_NEAR_ACCOUNT_ID`, env(`${prefix}_NEAR_ACCOUNT_ID`));
  return parseNearKey(account, env(`${prefix}_NEAR_PRIVATE_KEY`));
}

export function baseRpc(): Rpc {
  return httpRpc(env("BASE_SEPOLIA_RPC_URL", "https://sepolia.base.org"));
}

/** The relayer's Base Sepolia key: `RELAYER_EVM_KEY_FILE` (a 0x key on one line), else `RELAYER_EVM_PRIVATE_KEY`. */
export function evmKey(): Uint8Array {
  const file = process.env.RELAYER_EVM_KEY_FILE;
  const k = (file ? readFileSync(file, "utf8") : env("RELAYER_EVM_PRIVATE_KEY")).trim();
  if (!/^0x[0-9a-fA-F]{64}$/.test(k)) throw new Error("the relayer EVM key must be 0x + 64 hex digits");
  return unhex(k);
}
