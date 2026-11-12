// The flow's NEAR side, wired to the O1 plumbing: views over JSON-RPC, and `link_agent` as an
// owner call (software P-256 assertion, submitted by SUBMITTER_ACCOUNT_ID through near-cli-rs).

import { agentArgs } from "@nearh/owner-near/src/borsh.ts";
import { view, waitFor, type Config } from "@nearh/owner-near/src/near.ts";
import { getConfig, ownerCall } from "@nearh/owner-near/src/owner.ts";
import type { Near } from "./link.ts";

/** `link_agent` signs through the MPC in a cross-contract call; the relayer uses the same gas. */
export const LINK_AGENT_GAS = "300 Tgas";

export function nearClient(cfg: Config, call: typeof ownerCall = ownerCall): Near {
  return {
    getAgent: (agent) => view(cfg, cfg.contractId, "get_agent", { agent }),
    listRequests: (agent, from_index, limit) => view(cfg, cfg.contractId, "list_requests", { agent, from_index, limit }),
    async linkAgent(agent) {
      const { txHash, nonce } = await call(cfg, "link_agent", { agent }, agentArgs(agent), LINK_AGENT_GAS);
      // The contract consumes owner_nonce only when the call succeeds (docs/interfaces.md §2).
      await waitFor("link_agent landed (owner_nonce consumed)", async () =>
        (await getConfig(cfg)).owner_nonce >= nonce ? true : undefined,
      );
      return txHash ? { txHash } : {};
    },
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  };
}
