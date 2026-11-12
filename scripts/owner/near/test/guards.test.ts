// Input guards that run before anything touches disk or chain.
import assert from "node:assert/strict";
import { test } from "node:test";
import { agentKeyPath } from "../src/keys.ts";
import { assertAgentId, config } from "../src/near.ts";

test("agent ids follow the contract's rule, so they cannot leave the key directory", () => {
  for (const ok of ["agent-1", "a.b_c:d", ".", "..", "x".repeat(64)]) assert.equal(assertAgentId(ok), ok);
  for (const bad of [undefined, "", "../evil", "a/b", "a\\b", "x".repeat(65), "agent 1"]) {
    assert.throws(() => assertAgentId(bad), /agent must be/, String(bad));
  }
  const cfg = { rpc: "https://rpc.testnet.near.org", contractId: "c.testnet", mpcContract: "m.testnet", keyDir: "/k" };
  assert.throws(() => agentKeyPath(cfg, "../../owner-p256"), /agent must be/);
  assert.equal(agentKeyPath(cfg, "agent-1"), "/k/c.testnet/agents/agent-1.json");
  assert.equal(agentKeyPath(cfg, ".."), "/k/c.testnet/agents/...json");
});

test("only an https testnet RPC and .testnet accounts are accepted", () => {
  const saved = { ...process.env };
  try {
    process.env.CONTRACT_ID = "c.testnet";
    for (const bad of [
      "http://rpc.testnet.near.org",
      "https://rpc.mainnet.near.org",
      "https://evil.example/testnet",
      "https://rpc.mainnet.near.org?x=testnet",
      "https://testnet@rpc.mainnet.near.org",
      "https://rpc.mainnet.near.org#testnet",
      "https://rpc.testnet.near.org.evil.example",
      "https://user:pw@rpc.testnet.near.org",
      "not a url",
    ]) {
      process.env.NEAR_RPC = bad;
      assert.throws(() => config(), /https testnet RPC/, bad);
    }
    for (const ok of ["https://rpc.testnet.near.org", "https://archival-rpc.testnet.near.org/", "https://test.rpc.fastnear.com"]) {
      process.env.NEAR_RPC = ok;
      assert.equal(config().rpc, ok);
    }
    assert.equal(config().contractId, "c.testnet");
    process.env.CONTRACT_ID = "c.near";
    assert.throws(() => config(), /\.testnet account/);
  } finally {
    process.env = saved;
  }
});
