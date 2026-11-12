// pnpm start: runs the PP3 service on 127.0.0.1:$PP3_PORT (default 8788).
// Needs CONTRACT_ID and PP3_AGENT_TOKENS (and optionally NEAR_RPC, PP3_STORE_DIR, PAYPAL_ENV_FILE).
import { agentTokens, deps, vaultRoutes } from "../config.ts";
import { server } from "../server.ts";

const port = Number(process.env.PP3_PORT || 8788);
const d = deps();
const vault = vaultRoutes(d);
server(d, agentTokens(), {}, vault).listen(port, "127.0.0.1", () => console.log(`PP3 listening on 127.0.0.1:${port}${vault ? " (vault routes on)" : ""}`));
