// pnpm set-mandate <agent> <mandate.json>: sets the agent's mandate; checks get_mandate.
import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { setMandateArgs, type Mandate } from "../borsh.ts";
import { assertAgentId, config, view, waitFor } from "../near.ts";
import { getConfig, ownerCall } from "../owner.ts";

const cfg = config();
const [agent, file] = process.argv.slice(2);
if (!agent || !file) throw new Error("usage: set-mandate <agent> <mandate.json>");
assertAgentId(agent);
const mandate: Mandate = JSON.parse(readFileSync(file, "utf8"));
const { nonce } = await ownerCall(cfg, "set_mandate", { agent, mandate }, setMandateArgs(agent, mandate));
await waitFor("owner_nonce consumed", async () => ((await getConfig(cfg)).owner_nonce >= nonce ? true : undefined));
const stored = await view<Mandate | null>(cfg, cfg.contractId, "get_mandate", { agent });
// The contract stores addresses lowercase; compare values in that form (key order does not matter).
const expected = { ...mandate, usdc_address: mandate.usdc_address.toLowerCase(), eure_address: mandate.eure_address.toLowerCase() };
if (!isDeepStrictEqual(stored, expected)) {
  throw new Error(`get_mandate differs:\n${JSON.stringify(stored)}\n${JSON.stringify(expected)}`);
}
console.log(`PASS: mandate of ${agent} = ${JSON.stringify(stored)}`);
