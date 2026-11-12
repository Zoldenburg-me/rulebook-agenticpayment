// Float rules the owner scripts enforce. The contract cannot see Base balances, so the
// top-up script is the only place `float_cap` is checked (PLAN.md, D8).

import { rmSync, writeFileSync } from "node:fs";

export type TokenName = "usdc" | "eure";

export const DECIMALS: Record<TokenName, number> = { usdc: 6, eure: 18 };

export function assertToken(t: string | undefined): TokenName {
  if (t !== "usdc" && t !== "eure") throw new Error(`token must be usdc or eure, got "${t}"`);
  return t;
}

/** "12.5" USDC → 12500000n. Refuses more fraction digits than the token has, signs and exponents. */
export function parseAmount(s: string | undefined, decimals: number): bigint {
  const m = /^(\d+)(?:\.(\d+))?$/.exec(s ?? "");
  if (!m) throw new Error(`amount must be a plain decimal like 12.5, got "${s}"`);
  const frac = m[2] ?? "";
  if (frac.length > decimals) throw new Error(`amount has more than ${decimals} decimals: ${s}`);
  return BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, "0") || "0");
}

export function formatAmount(v: bigint, decimals: number): string {
  const s = v.toString().padStart(decimals + 1, "0");
  const frac = s.slice(-decimals).replace(/0+$/, "");
  return s.slice(0, -decimals) + (frac ? `.${frac}` : "");
}

/**
 * The cap check, run twice: before the owner's tap and again right before the Safe sends,
 * so a balance that grew while the owner was tapping (another top-up, an inbound transfer)
 * is caught. `send` must call `recheck` after signing and before submitting.
 */
export async function guardedTopUp(
  readBalance: () => Promise<bigint>,
  amount: bigint,
  cap: bigint,
  send: (recheck: () => Promise<void>) => Promise<string>,
): Promise<{ before: bigint; tx: string }> {
  const before = await readBalance();
  checkTopUp(before, amount, cap);
  const tx = await send(async () => checkTopUp(await readBalance(), amount, cap));
  return { before, tx };
}

/**
 * One top-up per agent and token at a time, across processes: an exclusive lock file.
 * `fn` calls `submitted()` right before it hands the transfer to the bundler. From then on
 * the outcome is unknown until `fn` returns, so an error or Ctrl-C keeps the lock: a pending
 * transfer is not yet in the balance the next run would check.
 */
export async function withLock<T>(path: string, fn: (submitted: () => void) => Promise<T>): Promise<T> {
  try {
    writeFileSync(path, `${process.pid}\n`, { flag: "wx", mode: 0o600 });
  } catch (e: any) {
    if (e?.code === "EEXIST") throw new Error(`another top-up holds ${path}; if none is running, delete it`);
    throw e;
  }
  let sent = false;
  const kept = `top-up submitted, outcome unknown: ${path} stays until you have checked the agent EOA on sepolia.basescan.org; delete it then`;
  // Ctrl-C skips `finally`, so handle it here: before submission nothing moved and the lock goes.
  const onSigint = () => {
    if (sent) console.error(kept);
    else rmSync(path, { force: true });
    process.exit(130);
  };
  process.once("SIGINT", onSigint);
  try {
    const out = await fn(() => (sent = true));
    rmSync(path, { force: true });
    return out;
  } catch (e) {
    if (sent) throw new Error(`${(e as Error).message}\n${kept}`);
    rmSync(path, { force: true });
    throw e;
  } finally {
    process.off("SIGINT", onSigint);
  }
}

/** Throws unless `amount > 0` and the float after the top-up stays at most `cap`. */
export function checkTopUp(balance: bigint, amount: bigint, cap: bigint): void {
  if (amount <= 0n) throw new Error("top-up amount must be greater than 0");
  if (balance + amount > cap) {
    throw new Error(`refused: float would be ${balance + amount}, above float_cap ${cap} (balance ${balance} + top-up ${amount})`);
  }
}
