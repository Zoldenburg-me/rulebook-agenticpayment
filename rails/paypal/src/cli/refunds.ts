// pnpm refunds: the PP-T1 refund service on 127.0.0.1:$PP_REFUND_PORT (default 8790).
// Needs CONTRACT_ID and PP3_AGENT_TOKENS (and optionally NEAR_RPC, PP_REFUND_STORE_DIR, PAYPAL_ENV_FILE).
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { agentTokens, credentialsFile, deps, readCredentials } from "../config.ts";
import { refundServer } from "../refund-server.ts";
import { fileStore } from "../store.ts";
import { toolkit } from "../toolkit.ts";

const d = deps();
const store = fileStore(process.env.PP_REFUND_STORE_DIR || join(fileURLToPath(new URL("../..", import.meta.url)), ".refunds"));
const kit = toolkit(readCredentials(credentialsFile()));
const port = Number(process.env.PP_REFUND_PORT || 8790);
refundServer({ ...d, store }, kit, agentTokens()).listen(port, "127.0.0.1", () => console.log(`PP-T1 refunds listening on 127.0.0.1:${port}`));
