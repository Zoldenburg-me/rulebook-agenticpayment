// What the scripts read from the mandate contract on NEAR: the agent's EOA, its sweep target
// and its float caps. Reuses the O1 plumbing (../near) for config and views.

import { assertAgentId, view, type Config } from "../../near/src/near.ts";
import type { Mandate, SweepConfig } from "../../near/src/borsh.ts";
import { assertAddress } from "./base.ts";
import type { TokenName } from "./float.ts";
import { loadPasskey } from "./passkey.ts";

export type AgentRecord = {
  agent: string;
  public_key: string | null;
  sweep_config: SweepConfig;
  evm_address: string | null;
  revoked: boolean;
};

/** The agent record, refusing one whose sweep target is not this owner's passkey Safe. */
export async function loadAgent(cfg: Config, agentArg: string | undefined) {
  const agent = assertAgentId(agentArg);
  const record = await view<AgentRecord | null>(cfg, cfg.contractId, "get_agent", { agent });
  if (!record) throw new Error(`no agent ${agent} on ${cfg.contractId}`);
  const eoa = assertAddress("agent evm_address", record.evm_address ?? undefined);
  const safe = loadPasskey().safe_address.toLowerCase();
  if (record.sweep_config.safe_address.toLowerCase() !== safe) {
    throw new Error(`agent ${agent} sweeps to ${record.sweep_config.safe_address}, not this owner's Safe ${safe}`);
  }
  return { agent, record, eoa, safe };
}

/** For a top-up: the token address and `float_cap` from the agent's mandate. No mandate, no top-up. */
export async function agentFloat(cfg: Config, agentArg: string | undefined, token: TokenName) {
  const a = await loadAgent(cfg, agentArg);
  if (a.record.revoked) throw new Error(`agent ${a.agent} is revoked; sweep its float instead`);
  const mandate = await view<Mandate | null>(cfg, cfg.contractId, "get_mandate", { agent: a.agent });
  if (!mandate) throw new Error(`agent ${a.agent} has no mandate, so no float_cap; refusing the top-up`);
  const asset = assertAddress(`mandate ${token}_address`, token === "usdc" ? mandate.usdc_address : mandate.eure_address);
  return { ...a, asset, cap: BigInt(mandate.float_cap[token]) };
}
