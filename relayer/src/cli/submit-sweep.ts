// pnpm submit-sweep <request-key.json>: submits an already signed sweep (requested by the agent,
// the owner or the relayer) on Base Sepolia. The key is { agent, caller, request_id }.

import { readFileSync } from "node:fs";
import { baseRpc, evmKey, nearConfig } from "../config.ts";
import { view } from "../near.ts";
import { submitEureSweep, submitUsdcSweep, type Reservation } from "../sweep.ts";

const file = process.argv[2];
if (!file) throw new Error("usage: pnpm submit-sweep <request-key.json>");
const key = JSON.parse(readFileSync(file, "utf8"));
const d = { ...nearConfig(), base: baseRpc(), evmKey: evmKey() };
const r = await view<Reservation | null>(d.near, d.contractId, "get_request", { key });
if (r?.payload.kind === "eip1559_tx") {
  const out = await submitEureSweep(d, key);
  console.log(`EURe sweep landed: ${out.sweepTx} (gas funded by ${out.fundTx ?? "none needed"})`);
} else console.log(`USDC sweep landed: ${await submitUsdcSweep(d, key)}`);
