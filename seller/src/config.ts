// Seller config from env. Throws on a bad value so the server never starts half-configured.
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";

export const NETWORK = "eip155:84532"; // Base Sepolia
export const USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
// Matches the docs/interfaces.md §3 shape 2 example; the contract clamps longer ones anyway.
export const MAX_TIMEOUT_SECONDS = 240;

export interface SellerConfig {
  port: number;
  payTo: `0x${string}`;
  amount: string;
  facilitatorUrl: string;
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const ZERO_ADDRESS = /^0x0{40}$/;
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

// The repo-root .env (the one .env.example documents), then seller/.env as an optional override.
export const ENV_FILES = [
  fileURLToPath(new URL("../../.env", import.meta.url)),
  fileURLToPath(new URL("../.env", import.meta.url)),
];

// Merges the env files that exist, a later file overriding an earlier one; variables already
// in `env` (the shell) win over every file.
export function envWithFiles(files: string[] = ENV_FILES, env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const fromFiles: NodeJS.ProcessEnv = {};
  for (const file of files) {
    if (existsSync(file)) Object.assign(fromFiles, parseEnv(readFileSync(file, "utf8")));
  }
  return { ...fromFiles, ...env };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): SellerConfig {
  const payTo = env.SELLER_PAY_TO?.trim();
  if (!payTo) throw new Error("SELLER_PAY_TO is required (the seller's Base Sepolia address)");
  if (!ADDRESS.test(payTo) || ZERO_ADDRESS.test(payTo)) {
    throw new Error("SELLER_PAY_TO must be a non-zero 0x-prefixed 20-byte hex address");
  }

  const portRaw = env.SELLER_PORT?.trim() || "4021";
  const port = Number(portRaw);
  if (!/^[0-9]+$/.test(portRaw) || port < 1 || port > 65535) {
    throw new Error(`SELLER_PORT must be an integer in 1..65535, got ${portRaw}`);
  }

  const amount = env.SELLER_AMOUNT?.trim() || "10000"; // 0.01 USDC (6 decimals)
  if (!/^[1-9][0-9]*$/.test(amount)) {
    throw new Error("SELLER_AMOUNT must be a positive integer in USDC base units");
  }

  const facilitatorUrl = env.X402_FACILITATOR_URL?.trim() || "https://x402.org/facilitator";
  let url: URL;
  try {
    url = new URL(facilitatorUrl);
  } catch {
    throw new Error(`X402_FACILITATOR_URL is not a valid URL: ${facilitatorUrl}`);
  }
  // Verify and settle carry signed payments, so plain http is only for a facilitator on this machine.
  if (url.protocol !== "https:" && !(url.protocol === "http:" && LOOPBACK.has(url.hostname))) {
    throw new Error("X402_FACILITATOR_URL must be https (http only for localhost, 127.0.0.1 or [::1])");
  }

  return { port, payTo: payTo as `0x${string}`, amount, facilitatorUrl };
}
