// pnpm owner:revoke <agent>: revokes the agent. Success is read from state, never from the tx
// status (docs/interfaces.md §1): get_agent shows revoked with no key, the mandate and payees
// are gone, and the key is no longer on the account. On a rerun get_agent has no key any more,
// so the key comes from the local key file; with neither, every unowned agent key fails it.
import { agentArgs } from "../borsh.ts";
import { existingAgentKey } from "../keys.ts";
import { accessKeys, assertAgentId, config, describeKeys, view, waitFor } from "../near.ts";
import { ownerCall } from "../owner.ts";
import { leftoverAgentKeys } from "../revoke-check.ts";

const cfg = config();
const agent = assertAgentId(process.argv[2]);
const before = await view(cfg, cfg.contractId, "get_agent", { agent });
if (!before) throw new Error(`unknown agent ${agent}`);
const knownKey: string | undefined = before.public_key ?? existingAgentKey(cfg, agent);
await ownerCall(cfg, "revoke", { agent }, agentArgs(agent));

const record = await waitFor("get_agent shows revoked", async () => {
  const r = await view(cfg, cfg.contractId, "get_agent", { agent });
  return r?.revoked && r.public_key === null ? r : undefined;
});
if ((await view(cfg, cfg.contractId, "get_mandate", { agent })) !== null) throw new Error("mandate still set");
if ((await view<unknown[]>(cfg, cfg.contractId, "get_payees", { agent })).length !== 0) throw new Error("payees still listed");
const keys = await accessKeys(cfg, cfg.contractId);
const left = await leftoverAgentKeys(keys, cfg.contractId, knownKey, (public_key) =>
  view(cfg, cfg.contractId, "agent_of_key", { public_key }),
);
console.log(`get_agent: ${JSON.stringify(record)}`);
console.log(`access keys on ${cfg.contractId}:\n${describeKeys(keys)}`);
if (left.length > 0) {
  // State is revoked (the agent can no longer sign); the DeleteKey receipt failed. A second
  // revoke retries it (contract revoke_agent).
  if (knownKey) console.log(`WARN: ${agent} is revoked but its key ${knownKey} is still on the account; run owner:revoke again`);
  else {
    // No key file: the contract no longer says which revoked agent owned these keys, so this
    // fails closed without claiming they are this agent's.
    console.log(`WARN: no key known for ${agent}; agent keys no agent owns are still on the account: ${left.join(", ")}`);
    console.log("run owner:revoke for the revoked agent each key belonged to (the contract retries its DeleteKey)");
  }
  process.exitCode = 1;
} else {
  console.log(`PASS: ${agent} revoked, key deleted`);
}
