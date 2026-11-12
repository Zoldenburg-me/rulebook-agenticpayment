// pnpm webhook: the PP-W1 receiver on 127.0.0.1:$PP_WEBHOOK_PORT (default 8789), for a tunnel to expose.
// Needs PAYPAL_WEBHOOK_ID (credentials file or env), PP3_AGENT_TOKENS (for the agent list) and, unless
// PP_WEBHOOK_REPORT=log, CONTRACT_ID and SETTLEMENT_REPORTER (a .testnet account in ~/.near-credentials).
import { webhookDeps } from "../config.ts";
import { webhookServer } from "../webhook.ts";

const port = Number(process.env.PP_WEBHOOK_PORT || 8789);
webhookServer(webhookDeps()).listen(port, "127.0.0.1", () => console.log(`PP-W1 webhook receiver on 127.0.0.1:${port}/paypal/webhook`));
