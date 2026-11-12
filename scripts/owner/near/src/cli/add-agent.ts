// pnpm add-agent <agent> [ed25519:<public key>]: registers the agent. Without a key, a new
// one is generated into the key dir (or the one an earlier failed run generated is reused). evm_address is derived off chain from (contract, agent)
// and cross-checked against the MPC's derived_public_key view. Checks get_agent,
// agent_of_key and the account's access keys afterwards.
import { addAgentArgs, type SweepConfig } from "../borsh.ts";
import { deriveEvmAddress, mpcKeyToPoint, publicKeyToAddress } from "../derive.ts";
import { isDeepStrictEqual } from "node:util";
import { agentKeyPath, createAgentKey, existingAgentKey } from "../keys.ts";
import { AGENT_METHOD_NAMES, accessKeys, assertAgentId, config, describeKeys, env, view, waitFor } from "../near.ts";
import { getConfig, ownerCall } from "../owner.ts";

const cfg = config();
const agent = assertAgentId(process.argv[2]);
let publicKey = process.argv[3];
if (!publicKey) {
  // A key left by an earlier run that failed before add_agent landed is reused, never overwritten.
  publicKey = existingAgentKey(cfg, agent);
  if (publicKey) console.log(`agent key reused: ${publicKey} (key file ${agentKeyPath(cfg, agent)})`);
  else {
    publicKey = createAgentKey(cfg, agent);
    console.log(`agent key generated: ${publicKey} (key file ${agentKeyPath(cfg, agent)})`);
  }
}

const root = await view<string>(cfg, cfg.mpcContract, "public_key");
const evmAddress = deriveEvmAddress(root, cfg.contractId, agent);
const viewKey = await view<string>(cfg, cfg.mpcContract, "derived_public_key", {
  path: agent,
  predecessor: cfg.contractId,
  domain_id: 0,
});
if (publicKeyToAddress(mpcKeyToPoint(viewKey).toBytes(false)) !== evmAddress) {
  throw new Error("local derivation differs from the MPC's derived_public_key view");
}
console.log(`agent EOA derive(${cfg.contractId}, ${agent}) = ${evmAddress} (matches MPC view)`);

const sweepConfig: SweepConfig = {
  safe_address: env("SAFE_ADDRESS").toLowerCase(),
  usdc_address: env("USDC_ADDRESS", "0x036cbd53842c5426634e7929541ec2318f3dcf7e").toLowerCase(),
  eure_address: env("EURE_ADDRESS", "0x29f37f6adca168b79b8d9567eab9be3fbf21db85").toLowerCase(),
  chain_id: 84532,
};
const { nonce } = await ownerCall(
  cfg,
  "add_agent",
  { agent, public_key: publicKey, sweep_config: sweepConfig, evm_address: evmAddress },
  addAgentArgs(agent, publicKey, sweepConfig, evmAddress),
  "100 Tgas",
);
await waitFor("owner_nonce consumed", async () => ((await getConfig(cfg)).owner_nonce >= nonce ? true : undefined));

const record = await waitFor("get_agent shows the agent with its key", async () => {
  const r = await view(cfg, cfg.contractId, "get_agent", { agent });
  return r && r.public_key === publicKey && !r.revoked ? r : undefined;
});
if (record.evm_address !== evmAddress) throw new Error(`stored evm_address ${record.evm_address} != ${evmAddress}`);
if (!isDeepStrictEqual(record.sweep_config, sweepConfig)) throw new Error("stored sweep_config differs");
if ((await view(cfg, cfg.contractId, "agent_of_key", { public_key: publicKey })) !== agent) {
  throw new Error("agent_of_key does not map the key to the agent");
}
const keys = await waitFor("agent key is on the account", async () => {
  const ks = await accessKeys(cfg, cfg.contractId);
  return ks.some((k) => k.public_key === publicKey) ? ks : undefined;
});
const k = keys.find((k) => k.public_key === publicKey)!;
const p = k.access_key.permission;
if (
  p === "FullAccess" ||
  p.FunctionCall.receiver_id !== cfg.contractId ||
  JSON.stringify(p.FunctionCall.method_names) !== JSON.stringify(AGENT_METHOD_NAMES)
) {
  throw new Error(`agent key has the wrong permission: ${JSON.stringify(p)}`);
}
if (keys.some((k) => k.access_key.permission === "FullAccess")) throw new Error("a full-access key is on the contract");
console.log(`get_agent: ${JSON.stringify(record)}`);
console.log(`access keys on ${cfg.contractId}:\n${describeKeys(keys)}`);
console.log(`PASS: ${agent} added, key limited to ${JSON.stringify(AGENT_METHOD_NAMES)}`);
