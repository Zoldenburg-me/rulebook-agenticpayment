// Key files outside the repo, under $OWNER_KEY_DIR (default ~/.nearh-owner)/<contract>/:
//   owner-p256.json         software P-256 owner key (stands in for the passkey on testnet)
//   agents/<agent>.json     agent ed25519 function-call key, near-cli key-file format
// Directories are 0700 and files 0600. Nothing here is ever printed except public keys.

import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { base58Encode } from "./base58.ts";
import { compressedPublicKey } from "./challenge.ts";
import { assertAgentId, type Config } from "./near.ts";

const contractDir = (cfg: Config) => join(cfg.keyDir, cfg.contractId);

function writeSecret(path: string, data: object): void {
  if (existsSync(path)) throw new Error(`refusing to overwrite ${path}`);
  writeFileSync(path, JSON.stringify(data, null, 2) + "\n", { mode: 0o600, flag: "wx" });
}

export function ownerKeyPath(cfg: Config): string {
  return join(contractDir(cfg), "owner-p256.json");
}

/** Creates the owner key for this contract; fails if one exists. Returns the compressed public key. */
export function createOwnerKey(cfg: Config): Uint8Array {
  mkdirSync(contractDir(cfg), { recursive: true, mode: 0o700 });
  const secret = p256.utils.randomSecretKey();
  const pub = compressedPublicKey(secret);
  writeSecret(ownerKeyPath(cfg), { curve: "p256", secret_key: bytesToHex(secret), public_key: bytesToHex(pub) });
  return pub;
}

export function loadOwnerKey(cfg: Config): { secret: Uint8Array; publicKey: Uint8Array } {
  const path = ownerKeyPath(cfg);
  if (!existsSync(path)) throw new Error(`no owner key at ${path}; run \`pnpm keygen\` first`);
  const secret = hexToBytes(JSON.parse(readFileSync(path, "utf8")).secret_key);
  return { secret, publicKey: compressedPublicKey(secret) };
}

export function agentKeyPath(cfg: Config, agent: string): string {
  return join(contractDir(cfg), "agents", `${assertAgentId(agent)}.json`);
}

/** The agent's generated key, if a file exists (e.g. from an add-agent run that failed). */
export function existingAgentKey(cfg: Config, agent: string): string | undefined {
  const path = agentKeyPath(cfg, agent);
  if (!existsSync(path)) return undefined;
  const k = JSON.parse(readFileSync(path, "utf8"));
  if (k.account_id !== cfg.contractId || !/^ed25519:[1-9A-HJ-NP-Za-km-z]+$/.test(k.public_key)) {
    throw new Error(`${path} is not an agent key for ${cfg.contractId}`);
  }
  return k.public_key;
}

/** New ed25519 agent key in near-cli's key-file format; returns its `ed25519:` public key. */
export function createAgentKey(cfg: Config, agent: string): string {
  mkdirSync(join(contractDir(cfg), "agents"), { recursive: true, mode: 0o700 });
  const secret = ed25519.utils.randomSecretKey();
  const pub = ed25519.getPublicKey(secret);
  const publicKey = `ed25519:${base58Encode(pub)}`;
  const full = new Uint8Array(64);
  full.set(secret);
  full.set(pub, 32);
  writeSecret(agentKeyPath(cfg, agent), {
    account_id: cfg.contractId,
    public_key: publicKey,
    private_key: `ed25519:${base58Encode(full)}`,
  });
  return publicKey;
}
