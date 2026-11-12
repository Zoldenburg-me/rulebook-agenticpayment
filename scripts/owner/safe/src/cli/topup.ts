// pnpm topup <agent> <usdc|eure> <amount>: sends <amount> (e.g. 5 or 2.5) from the owner's
// passkey Safe to the agent EOA, after checking that the float stays at most float_cap.
import { join } from "node:path";
import { config } from "../../../near/src/near.ts";
import { agentFloat } from "../agent.ts";
import { assertBaseSepolia, baseConfig, erc20Balance, hasErc20Transfer, transferCallData, txLogs } from "../base.ts";
import { assertToken, DECIMALS, formatAmount, guardedTopUp, parseAmount, withLock } from "../float.ts";
import { passkeyPath } from "../passkey.ts";
import { sendFromSafe } from "../safe.ts";

const [agentArg, tokenArg, amountArg] = process.argv.slice(2);
if (!amountArg) throw new Error("usage: topup <agent> <usdc|eure> <amount>");
const token = assertToken(tokenArg);
const amount = parseAmount(amountArg, DECIMALS[token]);
const cfg = config();
const base = baseConfig();
await assertBaseSepolia(base);

const { agent, eoa, safe, asset, cap } = await agentFloat(cfg, agentArg, token);
const fmt = (v: bigint) => `${formatAmount(v, DECIMALS[token])} ${token.toUpperCase()}`;
const safeBalance = await erc20Balance(base.rpc, asset, safe);
if (safeBalance < amount) throw new Error(`the Safe holds ${fmt(safeBalance)}, less than ${fmt(amount)}`);

// The agent id is checked by agentFloat (no path separators), so the lock stays in the key dir.
const lock = join(passkeyPath(), "..", `topup-${agent}-${token}.lock`);
// The Transfer-log check runs inside the lock: if it fails, the lock stays (withLock).
const { before, tx } = await withLock(lock, async (submitted) => {
  const r = await guardedTopUp(() => erc20Balance(base.rpc, asset, eoa), amount, cap, (recheck) =>
    sendFromSafe(
      base,
      [{ to: asset, value: 0n, data: transferCallData(eoa, amount) }],
      `Top up agent ${agent}: send ${fmt(amount)} from the Safe ${safe} to its EOA ${eoa} (float_cap ${fmt(cap)}).`,
      async () => {
        await recheck();
        submitted();
      },
    ),
  );
  if (!hasErc20Transfer(await txLogs(base.rpc, r.tx), asset, safe, eoa, amount)) {
    throw new Error(`tx ${r.tx} has no Transfer of ${fmt(amount)} from the Safe to ${eoa}`);
  }
  return r;
});
console.log(`top-up tx ${tx}: ${fmt(amount)} from the Safe to agent EOA ${eoa} (float before ${fmt(before)}, cap ${fmt(cap)})\nPASS`);
