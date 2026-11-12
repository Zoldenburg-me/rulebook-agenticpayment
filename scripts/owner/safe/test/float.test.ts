import assert from "node:assert/strict";
import { test } from "node:test";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkTopUp, formatAmount, guardedTopUp, parseAmount, withLock } from "../src/float.ts";

const CAP = 25_000_000n; // examples/mandate.json: 25 USDC

test("a top-up that keeps the float at or under float_cap passes", () => {
  checkTopUp(0n, CAP, CAP);
  checkTopUp(20_000_000n, 5_000_000n, CAP);
});

test("a top-up above float_cap is refused", () => {
  assert.throws(() => checkTopUp(0n, CAP + 1n, CAP), /refused: .*above float_cap 25000000/);
  // The cap bounds the float, not one transfer: 20 already there + 5.000001 is over.
  assert.throws(() => checkTopUp(20_000_000n, 5_000_001n, CAP), /above float_cap/);
  assert.throws(() => checkTopUp(CAP, 1n, CAP), /above float_cap/);
});

test("a zero top-up is refused", () => {
  assert.throws(() => checkTopUp(0n, 0n, CAP), /greater than 0/);
});

test("amounts parse in token base units and refuse anything but plain decimals", () => {
  assert.equal(parseAmount("25", 6), 25_000_000n);
  assert.equal(parseAmount("2.5", 6), 2_500_000n);
  assert.equal(parseAmount("0.000001", 6), 1n);
  assert.equal(parseAmount("250", 18), 250n * 10n ** 18n);
  for (const bad of ["", "-1", "1e6", "0x10", "1.0000001", " 1", "1,5"]) {
    assert.throws(() => parseAmount(bad, 6), /amount/, bad);
  }
  assert.equal(formatAmount(2_500_000n, 6), "2.5");
  assert.equal(formatAmount(25_000_000n, 6), "25");
  assert.equal(formatAmount(1n, 6), "0.000001");
});

test("the cap is checked again after the tap: a balance that grew meanwhile stops the send", async () => {
  // 0 when the top-up starts, 20 USDC by the time the owner has tapped (say, a parallel top-up landed).
  const balances = [0n, 20_000_000n];
  let sent = false;
  await assert.rejects(
    guardedTopUp(async () => balances.shift()!, 10_000_000n, CAP, async (recheck) => {
      await recheck();
      sent = true;
      return "0xtx";
    }),
    /above float_cap/,
  );
  assert.equal(sent, false);

  const ok = await guardedTopUp(async () => 5_000_000n, 10_000_000n, CAP, async (recheck) => (await recheck(), "0xtx"));
  assert.deepEqual(ok, { before: 5_000_000n, tx: "0xtx" });
});

test("only one top-up per lock file at a time, and the lock is released afterwards", async () => {
  const lock = join(mkdtempSync(join(tmpdir(), "o3-")), "topup-agent-1-usdc.lock");
  await withLock(lock, async () => {
    await assert.rejects(withLock(lock, async () => "second"), /another top-up holds/);
  });
  assert.equal(existsSync(lock), false);
  await assert.rejects(withLock(lock, async () => { throw new Error("boom"); }), /boom/);
  assert.equal(existsSync(lock), false);
});

test("a top-up that failed after submission keeps the lock, so the next run can't double-spend the cap", async () => {
  const lock = join(mkdtempSync(join(tmpdir(), "o3-")), "topup-agent-1-usdc.lock");
  await assert.rejects(
    withLock(lock, async (submitted) => {
      submitted();
      throw new Error("timed out waiting for the UserOperation");
    }),
    /timed out[\s\S]*stays until you have checked/,
  );
  assert.equal(existsSync(lock), true);
  await assert.rejects(withLock(lock, async () => "next"), /another top-up holds/);
});
