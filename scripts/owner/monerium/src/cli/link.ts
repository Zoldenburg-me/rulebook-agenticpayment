// pnpm link-agent <agent>: links the agent's MPC-derived EOA to the team's Monerium sandbox profile.
// NEAR settings as in scripts/owner/near (.env.example); Monerium credentials from
// MONERIUM_ENV_FILE (default ~/.config/nearh/monerium-sandbox.env), never printed.
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseEnv } from "node:util";
import { assertAgentId, config } from "@nearh/owner-near/src/near.ts";
import { linkAgentToMonerium, resolveProfile } from "../link.ts";
import { sandboxClient } from "../monerium.ts";
import { nearClient } from "../near.ts";

const agent = assertAgentId(process.argv[2]);
const cfg = config();
const file = process.env.MONERIUM_ENV_FILE || join(homedir(), ".config", "nearh", "monerium-sandbox.env");
let monerium: Record<string, string | undefined>;
try {
  monerium = { ...parseEnv(readFileSync(file, "utf8")) };
} catch {
  throw new Error("cannot read the Monerium credentials file (MONERIUM_ENV_FILE)");
}

const client = sandboxClient(monerium);
await client.authenticate();
const profile = await resolveProfile(client, monerium.MONERIUM_PROFILE_ID);
console.log(`Monerium sandbox: authenticated, profile …${profile.slice(-4)}`);

const result = await linkAgentToMonerium(nearClient(cfg), client, agent, profile, { log: (l) => console.log(l) });
console.log(JSON.stringify(result));
console.log(
  result.result === "pending_verification"
    ? `PENDING: Monerium accepted ${result.address} (HTTP 202) and is verifying it; rerun to confirm it is listed`
    : `PASS: ${result.address} is linked to the Monerium profile on basesepolia`,
);
