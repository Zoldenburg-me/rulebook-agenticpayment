import assert from "node:assert/strict";
import { test } from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import {
  addressOfSecret,
  authorizationStateData,
  balanceOfData,
  eip3009Digest,
  erc20TransferData,
  GAS_PRICE_ORACLE,
  getL1FeeData,
  hex,
  keccak,
  MAX_L1_FEE,
  payloadTx,
  recoverAddress,
  signedTx,
  transferWithAuthorizationData,
  txDigest,
  unhex,
  type Eip1559Payload,
  type Eip3009Payload,
  type MpcSignature,
} from "../src/evm.ts";
import { MemoryJournal } from "../src/journal.ts";
import { gasTopUp, requestSweep, submitEureSweep, submitUsdcSweep, type RequestKey } from "../src/sweep.ts";
import { FakeBase, FakeNear, nearSigner, transferLog } from "./fakes.ts";

const CONTRACT = "mandate-demo.testnet";
const SAFE = "0x5afe000000000000000000000000000000000001";
const USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const EURE = "0x29f37f6adca168b79b8d9567eab9be3fbf21db85";
const ATTACKER = "0xa77ac4e7000000000000000000000000000000ff";
const NOW = 1793555600;
const AGENT_SK = new Uint8Array(32).fill(0x44); // stands in for the MPC-derived key
const RELAYER_SK = new Uint8Array(32).fill(0x55);
const EOA = addressOfSecret(AGENT_SK);
const RELAYER_EOA = addressOfSecret(RELAYER_SK);

function mpcSign(digest: Uint8Array, sk = AGENT_SK): MpcSignature {
  const s = secp256k1.sign(digest, sk, { prehash: false, format: "recovered" });
  return { r: hex(s.slice(1, 33)), s: hex(s.slice(33)), v: 27 + s[0] };
}

const KEY: RequestKey = { agent: "agent-1", caller: { kind: "agent" }, request_id: "sweep-1" };

function setup(reservation: any) {
  const near = new FakeNear();
  near.views.get_agent = () => ({ agent: "agent-1", sweep_config: { safe_address: SAFE, usdc_address: USDC, eure_address: EURE, chain_id: 84532 }, evm_address: EOA, revoked: true });
  near.views.get_request = () => reservation;
  const base = new FakeBase();
  const deps = { near: near.rpc, base: base.rpc, contractId: CONTRACT, journal: new MemoryJournal(), evmKey: RELAYER_SK, nowSecs: () => NOW, pollMs: 0 };
  return { near, base, deps };
}

// ---- vectors from docs/interfaces.md §4 (the S-c run and the EURe sweep example) ----

test("digests and recovery match the interfaces.md vectors", () => {
  const p: Eip3009Payload = {
    kind: "eip3009", asset: USDC, chain_id: 84532, from: "0xbbc0320e02d371a71f18a40b7b15404df218d880", to: "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f",
    value: "10000", valid_after: 1793555521, valid_before: 1793555881, nonce: "0x1fc1b8c54141f9488ae59cb01f3500d4b02062c27a2fc5839004370c81a716c7",
  };
  const d = eip3009Digest(p);
  assert.equal(hex(d), "0x720dffe2a39e40e2513eaf70b1d55c4b0b4667c34d2812e2113bebc6834cb5ed");
  const sig = { r: "0xc36c8c02881c3a55099ebaf50a5aabc502c9195659ec6b69e3376bacaa84d383", s: "0x3b537f6c4f6d41969f2585b99c74638ad0d4c24c45fcd2f143a94d9825e20263", v: 28 };
  assert.equal(recoverAddress(d, sig), p.from);
  assert.equal(transferWithAuthorizationData(p, sig).slice(0, 10), "0xe3ee160e");

  const e: Eip1559Payload = {
    kind: "eip1559_tx", chain_id: 84532, nonce: 0, max_priority_fee_per_gas: "1000000", max_fee_per_gas: "2000000000", gas_limit: 80000, to: EURE, value: "0",
    data: "0xa9059cbb0000000000000000000000005afe0000000000000000000000000000000000010000000000000000000000000000000000000000000000008ac7230489e80000",
  };
  assert.equal(hex(txDigest(payloadTx(e))), "0x2d7d3f98d690daa7f5305927d06b2a2b577de2dc0f911e74722703abe95ff378");
  assert.equal(erc20TransferData(SAFE, 10n * 10n ** 18n), e.data);
});

test("a signed tx from signedTx recovers to its signer (the bytes nodes accept)", () => {
  const t = payloadTx({ kind: "eip1559_tx", chain_id: 84532, nonce: 3, max_priority_fee_per_gas: "1", max_fee_per_gas: "2", gas_limit: 60000, to: EURE, value: "0", data: "0x" });
  const sig = mpcSign(txDigest(t));
  const raw = signedTx(t, sig.v - 27, sig.r, sig.s);
  assert.equal(raw[0], 2);
  assert.equal(recoverAddress(txDigest(t), sig), EOA);
});

// ---- USDC: transferWithAuthorization ----

function usdcReservation(over: Partial<Eip3009Payload> = {}, signer = AGENT_SK) {
  const payload: Eip3009Payload = { kind: "eip3009", asset: USDC, chain_id: 84532, from: EOA, to: SAFE, value: "19990000", valid_after: NOW - 60, valid_before: NOW + 240, nonce: hex(keccak(new Uint8Array([1]))), ...over };
  const digest = eip3009Digest(payload);
  return { key: KEY, shape: "sweep", digest: hex(digest), payload, status: "signed", signature: mpcSign(digest, signer) };
}

test("USDC sweep: submitted once, exactly the signed authorization, to the USDC contract", async () => {
  const r = usdcReservation();
  const { base, deps } = setup(r);
  base.logsFor = () => [transferLog(USDC, EOA, SAFE, 19990000n)];
  await submitUsdcSweep(deps, KEY);
  assert.equal(base.sent.length, 1);
  assert.equal(base.sent[0].to, USDC);
  assert.equal(base.sent[0].value, 0n);
  assert.equal(base.sent[0].data, transferWithAuthorizationData(r.payload, r.signature));
  assert.equal(base.calls.length, 1);
  assert.equal(base.calls[0].to.toLowerCase(), USDC.toLowerCase(), "authorizationState read on sc.usdc_address");
  assert.equal(base.calls[0].data, authorizationStateData(EOA, r.payload.nonce));

  await assert.rejects(submitUsdcSweep(deps, KEY), /already relayed/);
  base.authorizationUsed = true;
  await assert.rejects(submitUsdcSweep({ ...deps, journal: new MemoryJournal() }, KEY), /already used on chain/);
  assert.equal(base.sent.length, 1);
});

test("USDC sweep: a tampered or foreign reservation is refused before any send", async () => {
  const cases: [string, any, RegExp][] = [];
  // payload changed after signing: digest no longer matches
  const changed = usdcReservation();
  changed.payload = { ...changed.payload, to: ATTACKER };
  cases.push(["payload to changed", changed, /does not hash to the signed digest/]);
  // digest and payload consistent, but a wrong signer
  cases.push(["signed by another key", usdcReservation({}, new Uint8Array(32).fill(0x66)), /not the agent EOA/]);
  // consistently signed, but not to the agent's Safe
  cases.push(["not to the Safe", usdcReservation({ to: ATTACKER }), /not agent EOA → Safe/]);
  cases.push(["not USDC", usdcReservation({ asset: EURE }), /not agent EOA → Safe/]);
  cases.push(["expired", usdcReservation({ valid_before: NOW }), /expired/]);
  cases.push(["not yet valid", usdcReservation({ valid_after: NOW }), /not valid until after/]);
  cases.push(["pending", { ...usdcReservation(), status: "pending", signature: null }, /not signed/]);
  cases.push(["not a sweep", { ...usdcReservation(), shape: "x402" }, /not a eip3009 sweep/]);
  for (const [name, r, re] of cases) {
    const { base, deps } = setup(r);
    await assert.rejects(submitUsdcSweep(deps, KEY), re, name);
    assert.equal(base.sent.length, 0, name);
  }
  const { base, deps } = setup(usdcReservation());
  base.chainId = 8453; // Base mainnet
  await assert.rejects(submitUsdcSweep(deps, KEY), /not Base Sepolia/);
  assert.equal(base.sent.length, 0);
});

// ---- EURe: the raw-transfer fallback ----

const EURE_AMOUNT = 10n * 10n ** 18n;

function eureReservation(over: Partial<Eip1559Payload> = {}) {
  const payload: Eip1559Payload = {
    kind: "eip1559_tx", chain_id: 84532, nonce: 0, max_priority_fee_per_gas: "1000000", max_fee_per_gas: "2000000000", gas_limit: 80000, to: EURE, value: "0",
    data: erc20TransferData(SAFE, EURE_AMOUNT), ...over,
  };
  const digest = txDigest(payloadTx(payload));
  return { key: KEY, shape: "sweep", digest: hex(digest), payload, status: "signed", signature: mpcSign(digest) };
}

function eureSetup(r: any) {
  const s = setup(r);
  s.base.logsFor = (tx) => (tx.to === EURE ? [transferLog(EURE, EOA, SAFE, EURE_AMOUNT)] : []);
  s.base.setTokenBalance(EURE, EOA, EURE_AMOUNT);
  return s;
}

test("EURe fallback: at zero ETH the EOA gets exactly one tx's gas, then the signed tx goes out once", async () => {
  const r = eureReservation();
  const { base, deps } = eureSetup(r);
  const out = await submitEureSweep(deps, KEY);
  assert.equal(base.sent.length, 2);
  const [fund, sweep] = base.sent;
  assert.equal(fund.to, EOA);
  assert.equal(fund.value, 80000n * 2000000000n + 2n * base.l1Fee, "top-up is gas_limit × max_fee_per_gas + 2 × the L1 data fee");
  // The L1 fee is quoted for the exact signed tx that goes out next.
  const quote = base.calls.find((c) => c.to === GAS_PRICE_ORACLE);
  assert.equal(quote?.data, getL1FeeData(signedTx(payloadTx(r.payload), r.signature.v - 27, r.signature.r, r.signature.s)));
  assert.equal(fund.data, "0x");
  assert.equal(fund.gas, 21000n);
  assert.equal(out.fundTx, hex(keccak(unhex(fund.raw))));
  // The second tx is the contract-built tx with the MPC signature, unchanged.
  const t = payloadTx(r.payload);
  assert.equal(sweep.raw, hex(signedTx(t, r.signature.v - 27, r.signature.r, r.signature.s)));
  assert.equal(sweep.to, EURE);
  assert.equal(sweep.data, r.payload.data);

  // Once the EOA nonce moves past the signed tx, nothing is funded or sent again.
  base.nonces[EOA] = 1n;
  await assert.rejects(submitEureSweep({ ...deps, journal: new MemoryJournal() }, KEY), /nonce 1/);
  assert.equal(base.sent.length, 2);
});

test("EURe fallback: the top-up only fills the gap, and a funded EOA gets nothing", async () => {
  {
    const { base, deps } = eureSetup(eureReservation());
    base.balances[EOA] = 100_000_000_000_000n;
    await submitEureSweep(deps, KEY);
    assert.equal(base.sent[0].value, 80000n * 2000000000n + 2n * base.l1Fee - 100_000_000_000_000n);
  }
  {
    const { base, deps } = eureSetup(eureReservation());
    base.balances[EOA] = 10n ** 18n;
    const out = await submitEureSweep(deps, KEY);
    assert.equal(out.fundTx, null);
    assert.equal(base.sent.length, 1);
    assert.equal(base.sent[0].to, EURE);
  }
});

test("EURe fallback: a second run after funding does not fund again", async () => {
  const { base, deps } = eureSetup(eureReservation());
  const sendRaw = base.rpc;
  let failSweep = true;
  base.rpc = async (m, p: any) => {
    if (m === "eth_sendRawTransaction" && failSweep && base.sent.length === 1) throw new Error("node down");
    return sendRaw(m, p);
  };
  await assert.rejects(submitEureSweep({ ...deps, base: base.rpc }, KEY), (e: Error) => {
    assert.equal(base.sent.length, 1, "funded once, the sweep did not go out");
    const funded = hex(keccak(unhex(base.sent[0].raw)));
    assert.match(e.message, new RegExp(`funded by tx ${funded}, but the sweep failed: node down`));
    return true;
  });
  failSweep = false;
  base.balances[EOA] = base.sent[0].value; // the funding landed
  // Same journal: the sweep id is claimed, so it is not resent blindly; a fresh journal would
  // still not fund twice because the EOA now holds the gas.
  await assert.rejects(submitEureSweep({ ...deps, base: base.rpc }, KEY), /already relayed/);
  const out = await submitEureSweep({ ...deps, base: base.rpc, journal: new MemoryJournal() }, KEY);
  assert.equal(out.fundTx, null);
  assert.equal(base.sent.filter((t) => t.to === EOA).length, 1);
});

test("EURe fallback: gas above the caps, a tampered tx, or a stuck fee funds nothing", async () => {
  assert.throws(() => gasTopUp(150_001n, 1n, 0n, 0n), /over the contract's caps/);
  assert.throws(() => gasTopUp(80000n, 100_000_000_001n, 0n, 0n), /over the contract's caps/);
  assert.equal(gasTopUp(150_000n, 100_000_000_000n, 0n, 0n), 15_000_000_000_000_000n);
  // Base is an OP-stack chain: the node also wants the L1 data fee in the balance (seen live in
  // relayer/LIVE.md leg d). It is added twice, as margin for the L1 fee moving, and capped.
  assert.equal(gasTopUp(80000n, 2_000_000_000n, 0n, 7n), 80000n * 2_000_000_000n + 14n);
  assert.equal(gasTopUp(80000n, 2_000_000_000n, 80000n * 2_000_000_000n, 7n), 14n);
  assert.throws(() => gasTopUp(80000n, 1n, 0n, MAX_L1_FEE + 1n), /L1 data fee/);

  const cases: [string, any, RegExp, (b: FakeBase) => void][] = [
    ["huge gas limit", eureReservation({ gas_limit: 10_000_000 }), /over the contract's caps/, () => {}],
    ["huge fee", eureReservation({ max_fee_per_gas: "1000000000000" }), /over the contract's caps/, () => {}],
    ["to the attacker", eureReservation({ data: erc20TransferData(ATTACKER, EURE_AMOUNT) }), /not EURe transfer\(Safe/, () => {}],
    ["not EURe", eureReservation({ to: USDC }), /not EURe transfer\(Safe/, () => {}],
    ["sends ETH", eureReservation({ value: "1" }), /not EURe transfer\(Safe/, () => {}],
    ["payload changed after signing", { ...eureReservation(), payload: { ...eureReservation().payload, gas_limit: 150000 } }, /does not hash/, () => {}],
    ["base fee above max fee", eureReservation(), /request a new sweep/, (b) => (b.baseFee = 3_000_000_000n)],
    ["EOA holds less EURe than the amount", eureReservation(), /holds 9999999999999999999 EURe, the sweep needs 10000000000000000000/, (b) => b.setTokenBalance(EURE, EOA, EURE_AMOUNT - 1n)],
    ["EOA holds no EURe", eureReservation(), /holds 0 EURe/, (b) => b.setTokenBalance(EURE, EOA, 0n)],
    ["amount 0", eureReservation({ data: erc20TransferData(SAFE, 0n) }), /amount is 0/, () => {}],
    ["v not 27 or 28", { ...eureReservation(), signature: { ...eureReservation().signature, v: 0 } }, /v must be 27 or 28/, () => {}],
  ];
  for (const [name, r, re, tweak] of cases) {
    const { base, deps } = eureSetup(r);
    tweak(base);
    await assert.rejects(submitEureSweep(deps, KEY), re, name);
    assert.equal(base.sent.length, 0, name);
  }
});

test("EURe fallback: USDC in the EOA does not count as EURe; refused before any gas, checked on sc.eure_address", async () => {
  const s = setup(eureReservation());
  s.base.setTokenBalance(USDC, EOA, EURE_AMOUNT);
  await assert.rejects(submitEureSweep(s.deps, KEY), /holds 0 EURe, the sweep needs 10000000000000000000/);
  assert.equal(s.base.sent.length, 0, "no gas top-up and no sweep");
  const balanceCalls = s.base.calls.filter((c) => c.data.startsWith("0x70a08231"));
  assert.equal(balanceCalls.length, 1);
  assert.equal(balanceCalls[0].to.toLowerCase(), EURE.toLowerCase());
  assert.equal(balanceCalls[0].data, balanceOfData(EOA));
});

// ---- requesting a sweep as the relayer ----

test("requestSweep: one relayer sweep call with evm_tx from Base, then waits for the signature", async () => {
  const relayer = nearSigner("relayer-demo.testnet", 0x77);
  const { near, base, deps } = setup(null);
  base.nonces[EOA] = 4n;
  base.setTokenBalance(EURE, EOA, EURE_AMOUNT);
  let stored: any = null;
  near.views.get_request = (a) => (stored && JSON.stringify(a.key) === JSON.stringify(stored.key) ? stored : null);
  near.onSend = (tx) => {
    const a = JSON.parse(tx.args);
    stored = { ...eureReservation(), key: { agent: a.agent, caller: { kind: "relayer", account: relayer.accountId }, request_id: a.request_id } };
    return { SuccessValue: "" };
  };
  const key = await requestSweep({ ...deps, relayerNear: relayer }, "agent-1", "eure", EURE_AMOUNT, "sweep-eure-1");
  assert.deepEqual(key, { agent: "agent-1", caller: { kind: "relayer", account: "relayer-demo.testnet" }, request_id: "sweep-eure-1" });
  assert.equal(near.sent.length, 1);
  assert.equal(near.sent[0].method, "sweep");
  assert.deepEqual(JSON.parse(near.sent[0].args), {
    agent: "agent-1", token: "eure", amount: EURE_AMOUNT.toString(), request_id: "sweep-eure-1",
    evm_tx: { nonce: 4, gas_limit: 100000, max_fee_per_gas: String(2n * 1_000_000n + 1_000_000n), max_priority_fee_per_gas: "1000000" },
    assertion: null,
  });
  assert.equal(base.sent.length, 0);
  assert.notEqual(RELAYER_EOA, EOA);

  // Not enough EURe, or an amount of 0: refused before the NEAR call.
  for (const [amount, re] of [[EURE_AMOUNT + 1n, /holds 10000000000000000000 EURe/], [0n, /amount is 0/]] as const) {
    const s = setup(null);
    s.base.setTokenBalance(EURE, EOA, EURE_AMOUNT);
    await assert.rejects(requestSweep({ ...s.deps, relayerNear: relayer }, "agent-1", "eure", amount, "s-0"), re);
    assert.equal(s.near.sent.length, 0);
  }

  // Fees above the cap: refused before the NEAR call.
  const s2 = setup(null);
  s2.base.setTokenBalance(EURE, EOA, 1n);
  s2.base.baseFee = 60_000_000_000n;
  await assert.rejects(requestSweep({ ...s2.deps, relayerNear: relayer }, "agent-1", "eure", 1n, "s-2"), /over the contract's caps/);
  assert.equal(s2.near.sent.length, 0);
});
