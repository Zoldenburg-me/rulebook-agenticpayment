// pnpm sweep <agent> <usdc|eure> <amount in base units> <request_id>: requests a sweep as the
// relayer, waits for the MPC signature, then submits it on Base Sepolia.

import { baseRpc, evmKey, nearConfig, nearSigner } from "../config.ts";
import { requestSweep, submitEureSweep, submitUsdcSweep } from "../sweep.ts";

const [agent, token, amount, requestId] = process.argv.slice(2);
if (!agent || (token !== "usdc" && token !== "eure") || !/^[0-9]+$/.test(amount ?? "") || !requestId) {
  throw new Error("usage: pnpm sweep <agent> <usdc|eure> <amount in base units> <request_id>");
}
const d = { ...nearConfig(), base: baseRpc(), evmKey: evmKey(), relayerNear: nearSigner("RELAYER") };
const key = await requestSweep(d, agent, token, BigInt(amount), requestId);
console.log(`sweep ${requestId}: signed`);
if (token === "usdc") console.log(`USDC sweep landed: ${await submitUsdcSweep(d, key)}`);
else {
  const r = await submitEureSweep(d, key);
  console.log(`EURe sweep landed: ${r.sweepTx} (gas funded by ${r.fundTx ?? "none needed"})`);
}
