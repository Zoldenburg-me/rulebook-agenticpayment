// Which agent keys a revoke left on the contract account. Pure apart from the injected
// agent_of_key view, so the rerun branches are unit-tested (test/revoke-check.test.ts).
import { AGENT_METHOD_NAMES, type AccessKey } from "./near.ts";

const isAgentKey = (k: AccessKey, contractId: string) => {
  const p = k.access_key.permission;
  return (
    p !== "FullAccess" &&
    p.FunctionCall.receiver_id === contractId &&
    JSON.stringify(p.FunctionCall.method_names) === JSON.stringify(AGENT_METHOD_NAMES)
  );
};

/**
 * Keys that should be gone after the revoke but are still on the account. With a known key
 * (get_agent before the first revoke, or the local key file on a rerun) that key alone is
 * checked. With none, it fails closed: every agent-shaped function-call key that no agent
 * owns (agent_of_key null) counts as left over.
 */
export async function leftoverAgentKeys(
  keys: AccessKey[],
  contractId: string,
  knownKey: string | null | undefined,
  agentOfKey: (publicKey: string) => Promise<string | null>,
): Promise<string[]> {
  if (knownKey) return keys.some((k) => k.public_key === knownKey) ? [knownKey] : [];
  const left: string[] = [];
  for (const k of keys) {
    if (isAgentKey(k, contractId) && (await agentOfKey(k.public_key)) === null) left.push(k.public_key);
  }
  return left;
}
