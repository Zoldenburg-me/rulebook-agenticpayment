// owner:revoke's key check, including a rerun after the first revoke's DeleteKey failed.
import assert from "node:assert/strict";
import { test } from "node:test";
import { AGENT_METHOD_NAMES, type AccessKey } from "../src/near.ts";
import { leftoverAgentKeys } from "../src/revoke-check.ts";

const C = "c.testnet";
const fc = (public_key: string, method_names = AGENT_METHOD_NAMES, receiver_id = C): AccessKey => ({
  public_key,
  access_key: { permission: { FunctionCall: { allowance: null, receiver_id, method_names } } },
});
const full = (public_key: string): AccessKey => ({ public_key, access_key: { permission: "FullAccess" } });
const owners: Record<string, string> = { "ed25519:Live": "other-agent" };
const agentOfKey = async (k: string) => owners[k] ?? null;

test("first run: the key from get_agent is checked", async () => {
  assert.deepEqual(await leftoverAgentKeys([fc("ed25519:A")], C, "ed25519:A", agentOfKey), ["ed25519:A"]);
  assert.deepEqual(await leftoverAgentKeys([fc("ed25519:Live")], C, "ed25519:A", agentOfKey), []);
});

test("rerun, already revoked, key still present: the key file's key fails the check", async () => {
  // get_agent.public_key is null now; revoke.ts falls back to the local key file.
  assert.deepEqual(await leftoverAgentKeys([fc("ed25519:A"), fc("ed25519:Live")], C, "ed25519:A", agentOfKey), ["ed25519:A"]);
});

test("rerun with no known key fails closed on any agent key no agent owns", async () => {
  const keys = [fc("ed25519:A"), fc("ed25519:Live"), full("ed25519:F"), fc("ed25519:O", ["other"]), fc("ed25519:R", AGENT_METHOD_NAMES, "x.testnet")];
  assert.deepEqual(await leftoverAgentKeys(keys, C, null, agentOfKey), ["ed25519:A"]);
  assert.deepEqual(await leftoverAgentKeys(keys.slice(1), C, undefined, agentOfKey), []);
});
