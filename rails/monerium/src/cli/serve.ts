// pnpm start: runs the M1 service on 127.0.0.1:$M1_PORT (default 8787).
// Needs CONTRACT_ID and M1_AGENT_TOKENS (and optionally NEAR_RPC, M1_STORE_DIR, MONERIUM_ENV_FILE).
import { agentTokens, deps } from "../config.ts";
import { server } from "../server.ts";

const port = Number(process.env.M1_PORT || 8787);
server(deps(), agentTokens()).listen(port, "127.0.0.1", () => console.log(`M1 listening on 127.0.0.1:${port}`));
