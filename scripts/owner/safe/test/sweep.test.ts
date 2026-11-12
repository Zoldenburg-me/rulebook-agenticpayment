import assert from "node:assert/strict";
import { test } from "node:test";
import { hasErc20Transfer, transferWithAuthorizationCallData, type Eip3009Payload } from "../src/base.ts";
import { spkiToPoint } from "../src/passkey.ts";
import { checkSweepReservation, sweepUsdcArgs, type Reservation } from "../src/sweep.ts";

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

test("sweep args are the borsh layout of docs/interfaces.md §2", () => {
  // "a1" | Usdc = 0 | U128 LE 19990000 (0x013105f0) | "r1" | None
  assert.equal(
    hex(sweepUsdcArgs("a1", 19_990_000n, "r1")),
    "02000000" + "6131" + "00" + "f0053101000000000000000000000000" + "02000000" + "7231" + "00",
  );
});

// The S-c settled authorization (spikes/x402/RESULT.md), as a reservation would carry it.
const payload: Eip3009Payload = {
  kind: "eip3009",
  asset: "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
  chain_id: 84532,
  from: "0xbbc0320e02d371a71f18a40b7b15404df218d880",
  to: "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f",
  value: "10000",
  valid_after: 1793555521,
  valid_before: 1793555881,
  nonce: "0x1fc1b8c54141f9488ae59cb01f3500d4b02062c27a2fc5839004370c81a716c7",
};
const signature = {
  r: "0xc36c8c02881c3a55099ebaf50a5aabc502c9195659ec6b69e3376bacaa84d383",
  s: "0x3b537f6c4f6d41969f2585b99c74638ad0d4c24c45fcd2f143a94d9825e20263",
  v: 28,
};

test("transferWithAuthorization calldata", () => {
  const word = (h: string) => h.replace(/^0x/, "").padStart(64, "0");
  assert.equal(
    transferWithAuthorizationCallData(payload, signature),
    "0xe3ee160e" +
      [payload.from, payload.to, (10000).toString(16), (1793555521).toString(16), (1793555881).toString(16), payload.nonce, (28).toString(16), signature.r, signature.s]
        .map(word)
        .join(""),
  );
});

test("only a signed, unexpired USDC transfer from the agent EOA to the Safe is submitted", () => {
  const want = { eoa: payload.from, safe: payload.to, usdc: payload.asset, amount: 10000n };
  const ok: Reservation = { shape: "sweep", status: "signed", payload, signature };
  const now = 1793555600;
  assert.equal(checkSweepReservation(ok, want, now).payload, payload);
  assert.throws(() => checkSweepReservation({ ...ok, payload: { ...payload, to: "0x5afe000000000000000000000000000000000001" } }, want, now), /does not match/);
  assert.throws(() => checkSweepReservation({ ...ok, payload: { ...payload, value: "10001" } }, want, now), /does not match/);
  assert.throws(() => checkSweepReservation({ ...ok, status: "unknown", signature: null }, want, now), /not signed/);
  assert.throws(() => checkSweepReservation({ ...ok, shape: "x402" }, want, now), /not a USDC sweep/);
  assert.throws(() => checkSweepReservation(ok, want, payload.valid_before), /expired/);
});

test("passkey SPKI → (x, y), and anything else is refused", () => {
  const x = "11".repeat(32), y = "22".repeat(32);
  const spki = Buffer.from("3059301306072a8648ce3d020106082a8648ce3d03010703420004" + x + y, "hex");
  assert.deepEqual(spkiToPoint(spki), { x: BigInt("0x" + x), y: BigInt("0x" + y) });
  assert.throws(() => spkiToPoint(spki.subarray(1)), /P-256/);
  const wrong = Buffer.from(spki);
  wrong[26] = 0x02;
  assert.throws(() => spkiToPoint(wrong), /P-256/);
});

test("a transfer is proven by its Transfer log, not by a balance", () => {
  const t = (a: string) => "0x" + a.slice(2).padStart(64, "0");
  const usdc = payload.asset, safe = "0x5afe000000000000000000000000000000000001", eoa = payload.from;
  const log = {
    address: usdc.toUpperCase().replace("0X", "0x"),
    topics: ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", t(safe), t(eoa)],
    data: "0x" + (10000).toString(16).padStart(64, "0"),
  };
  assert.equal(hasErc20Transfer([log], usdc, safe, eoa, 10000n), true);
  assert.equal(hasErc20Transfer([log], usdc, eoa, safe, 10000n), false); // direction
  assert.equal(hasErc20Transfer([log], usdc, safe, eoa, 10001n), false); // amount
  assert.equal(hasErc20Transfer([{ ...log, address: safe }], usdc, safe, eoa, 10000n), false); // token
  assert.equal(hasErc20Transfer([{ ...log, topics: ["0x" + "00".repeat(32), ...log.topics.slice(1)] }], usdc, safe, eoa, 10000n), false);
});
