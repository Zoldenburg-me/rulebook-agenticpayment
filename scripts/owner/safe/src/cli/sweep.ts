// pnpm sweep <agent> usdc <amount|all> [request_id]: the owner asks the contract for a sweep
// (owner assertion, any submitter), then the Safe submits the MPC-signed EIP-3009 transfer.
// The sweep needs no mandate and works after revoke. EURe sweeps are raw txs from the agent
// EOA that need gas, so the relayer (R1) funds and submits those.
import { config, view, waitFor } from "../../../near/src/near.ts";
import { ownerCall } from "../../../near/src/owner.ts";
import { loadAgent } from "../agent.ts";
import { assertBaseSepolia, baseConfig, erc20Balance, hasErc20Transfer, transferWithAuthorizationCallData, txLogs } from "../base.ts";
import { DECIMALS, formatAmount, parseAmount } from "../float.ts";
import { sendFromSafe } from "../safe.ts";
import { checkSweepReservation, sweepUsdcArgs, type Reservation } from "../sweep.ts";

const [agentArg, tokenArg, amountArg, requestIdArg] = process.argv.slice(2);
if (tokenArg === "eure") throw new Error("EURe sweeps need gas at the agent EOA; the relayer (R1) funds and submits them");
if (tokenArg !== "usdc" || !amountArg) throw new Error("usage: sweep <agent> usdc <amount|all> [request_id]");
const cfg = config();
const base = baseConfig();
await assertBaseSepolia(base);

const { agent, record, eoa, safe } = await loadAgent(cfg, agentArg);
const usdc = record.sweep_config.usdc_address;
const balance = await erc20Balance(base.rpc, usdc, eoa);
const amount = amountArg === "all" ? balance : parseAmount(amountArg, DECIMALS.usdc);
if (amount <= 0n || amount > balance) throw new Error(`sweep amount ${amount} must be in 1..${balance} (the agent EOA's USDC)`);
const requestId = requestIdArg ?? `owner-sweep-${Date.now()}`;

await ownerCall(cfg, "sweep", { agent, token: "usdc", amount: amount.toString(), request_id: requestId, evm_tx: null }, sweepUsdcArgs(agent, amount, requestId), "300 Tgas");
const key = { agent, caller: { kind: "owner" }, request_id: requestId };
const reservation = await waitFor("the sweep is signed", async () => {
  const r = await view<Reservation | null>(cfg, cfg.contractId, "get_request", { key });
  return r && r.status !== "pending" ? r : undefined;
}, 60);
const { payload, signature } = checkSweepReservation(reservation, { eoa, safe, usdc, amount }, Math.floor(Date.now() / 1000));

const usd = (v: bigint) => `${formatAmount(v, DECIMALS.usdc)} USDC`;
const tx = await sendFromSafe(
  base,
  [{ to: usdc, value: 0n, data: transferWithAuthorizationCallData(payload, signature) }],
  `Sweep agent ${agent}: submit the contract-signed transfer of ${usd(amount)} from its EOA ${eoa} back to the Safe ${safe}.`,
);
if (!hasErc20Transfer(await txLogs(base.rpc, tx), usdc, eoa, safe, amount)) {
  throw new Error(`tx ${tx} has no Transfer of ${usd(amount)} from ${eoa} to the Safe`);
}
console.log(`sweep request ${requestId}, tx ${tx}: ${usd(amount)} from agent EOA ${eoa} to the Safe ${safe}\nPASS`);
