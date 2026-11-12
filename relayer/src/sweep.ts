// Shape 1 sweeps on Base Sepolia. The relayer reads the signed reservation from the contract and
// the destination from the agent's `sweep_config`, recomputes the digest from the payload,
// recovers the MPC signature to the agent EOA, and only then sends. It sends the payload as
// signed; it builds nothing the agent signs.
//
// - USDC: the relayer submits `transferWithAuthorization` and pays the gas.
// - EURe (raw-transfer fallback): the relayer sends the agent EOA the gas for that one tx
//   (`gas_limit × max_fee_per_gas` plus twice its L1 data fee, less what the EOA already holds),
//   then broadcasts it.

import {
  addressOfSecret,
  assertBaseSepolia,
  authorizationStateData,
  balanceOfData,
  BASE_SEPOLIA_CHAIN_ID,
  currentFees,
  eip3009Digest,
  eqAddr,
  erc20TransferData,
  GAS_PRICE_ORACLE,
  getL1FeeData,
  hasTransfer,
  hex,
  MAX_L1_FEE,
  MAX_SWEEP_FEE_PER_GAS,
  MAX_SWEEP_GAS_LIMIT,
  payloadTx,
  recoverAddress,
  sendRaw,
  signedTx,
  signTx,
  transferWithAuthorizationData,
  txDigest,
  waitReceipt,
  type Eip1559Payload,
  type Eip3009Payload,
  type Hex,
  type MpcSignature,
} from "./evm.ts";
import type { Journal } from "./journal.ts";
import { callFunction, view, waitFor, type NearSigner } from "./near.ts";
import type { Rpc } from "./rpc.ts";

export type Caller = { kind: "agent" } | { kind: "owner" } | { kind: "relayer"; account: string };
export type RequestKey = { agent: string; caller: Caller; request_id: string };

export type Reservation = {
  key: RequestKey;
  shape: string;
  digest: Hex;
  payload: Eip3009Payload | Eip1559Payload | { kind: string };
  status: string;
  signature: MpcSignature | null;
};

type AgentRecord = {
  agent: string;
  sweep_config: { safe_address: string; usdc_address: string; eure_address: string; chain_id: number };
  evm_address: string | null;
};

export type SweepDeps = {
  near: Rpc;
  base: Rpc;
  contractId: string;
  journal: Journal;
  /** The relayer's Base Sepolia key: pays for `transferWithAuthorization` and the EURe gas. */
  evmKey: Uint8Array;
  /** The account `set_relayer` named; needed only to request a sweep. */
  relayerNear?: NearSigner;
  nowSecs?: () => number;
  pollMs?: number;
};

const TGAS = 1_000_000_000_000n;
const ETH_TRANSFER_GAS = 21_000n;
/** Gas limit the relayer asks for on a EURe sweep (below MAX_SWEEP_GAS_LIMIT). */
export const EURE_SWEEP_GAS_LIMIT = 100_000n;

/** A signed sweep reservation and its agent; the signature recovers to the agent EOA over `digest`. */
async function loadSweep(d: SweepDeps, key: RequestKey, kind: "eip3009" | "eip1559_tx", digestOf: (p: any) => Uint8Array) {
  const r = await view<Reservation | null>(d.near, d.contractId, "get_request", { key });
  if (!r) throw new Error(`no reservation for ${JSON.stringify(key)}`);
  const agent = await view<AgentRecord | null>(d.near, d.contractId, "get_agent", { agent: key.agent });
  if (!agent?.evm_address) throw new Error(`no agent EOA for ${key.agent}`);
  if (r.shape !== "sweep" || r.payload.kind !== kind) throw new Error(`not a ${kind} sweep: ${r.shape}/${r.payload.kind}`);
  // `revoked` still carries a valid sweep signature (D10); a sweep only ever moves funds to the Safe.
  if ((r.status !== "signed" && r.status !== "revoked") || !r.signature) throw new Error(`sweep is ${r.status}, not signed`);
  if (agent.sweep_config.chain_id !== BASE_SEPOLIA_CHAIN_ID) throw new Error(`sweep_config is chain ${agent.sweep_config.chain_id}`);
  const digest = digestOf(r.payload);
  if (hex(digest) !== r.digest.toLowerCase()) throw new Error(`payload does not hash to the signed digest ${r.digest}`);
  const signer = recoverAddress(digest, r.signature);
  if (!eqAddr(signer, agent.evm_address)) throw new Error(`signature recovers to ${signer}, not the agent EOA ${agent.evm_address}`);
  return { payload: r.payload as any, signature: r.signature, eoa: agent.evm_address.toLowerCase(), sc: agent.sweep_config };
}

/** One EIP-1559 tx from the relayer's own key; returns its hash after a successful receipt. */
async function relayerSend(d: SweepDeps, to: string, value: bigint, data: Hex, gas: bigint): Promise<{ hash: Hex; logs: any[] }> {
  const from = addressOfSecret(d.evmKey);
  const nonce = BigInt(await d.base("eth_getTransactionCount", [from, "pending"]));
  const fees = await currentFees(d.base);
  const raw = signTx(
    { chainId: BASE_SEPOLIA_CHAIN_ID, nonce, maxPriorityFeePerGas: fees.maxPriorityFeePerGas, maxFeePerGas: fees.maxFeePerGas, gasLimit: gas, to, value, data },
    d.evmKey,
  );
  const hash = await sendRaw(d.base, raw);
  return { hash, logs: await waitReceipt(d.base, hash, { pollMs: d.pollMs }) };
}

/** Submits a signed USDC sweep once; returns the Base tx hash with the EOA → Safe Transfer log. */
export async function submitUsdcSweep(d: SweepDeps, key: RequestKey): Promise<Hex> {
  await assertBaseSepolia(d.base);
  const { payload: p, signature, eoa, sc } = await loadSweep(d, key, "eip3009", eip3009Digest);
  const want = p as Eip3009Payload;
  if (!eqAddr(want.from, eoa) || !eqAddr(want.to, sc.safe_address) || !eqAddr(want.asset, sc.usdc_address) || want.chain_id !== BASE_SEPOLIA_CHAIN_ID) {
    throw new Error(`signed sweep is not agent EOA → Safe in USDC on Base Sepolia: ${JSON.stringify(want)}`);
  }
  const now = d.nowSecs?.() ?? Math.floor(Date.now() / 1000);
  if (now >= want.valid_before) throw new Error(`sweep authorization expired at ${want.valid_before}`);
  // EIP-3009 needs block.timestamp > validAfter; sent earlier it would revert after the journal claim.
  if (now <= want.valid_after) throw new Error(`sweep authorization is not valid until after ${want.valid_after}`);
  const used = await d.base("eth_call", [{ to: want.asset, data: authorizationStateData(want.from, want.nonce) }, "latest"]);
  if (BigInt(used) !== 0n) throw new Error(`authorization ${want.nonce} is already used on chain`);

  const data = transferWithAuthorizationData(want, signature);
  const gas = (BigInt(await d.base("eth_estimateGas", [{ from: addressOfSecret(d.evmKey), to: want.asset, data }])) * 5n) / 4n;
  d.journal.claim(`usdc-sweep:${want.from}:${want.nonce}`);
  const { hash, logs } = await relayerSend(d, want.asset, 0n, data, gas);
  if (!hasTransfer(logs, want.asset, eoa, sc.safe_address, BigInt(want.value))) throw new Error(`tx ${hash} has no Transfer of ${want.value} to the Safe`);
  return hash;
}

/**
 * What the relayer sends the agent EOA before its EURe sweep: never more than one tx's gas. On
 * Base (OP stack) the node also requires the tx's L1 data fee in the balance; it is added twice,
 * as margin for the L1 fee moving before the tx lands.
 */
export function gasTopUp(gasLimit: bigint, maxFeePerGas: bigint, eoaBalance: bigint, l1Fee: bigint): bigint {
  if (gasLimit > MAX_SWEEP_GAS_LIMIT || maxFeePerGas > MAX_SWEEP_FEE_PER_GAS) throw new Error("sweep tx gas is over the contract's caps");
  if (l1Fee > MAX_L1_FEE) throw new Error(`L1 data fee ${l1Fee} is over the relayer's cap ${MAX_L1_FEE}`);
  const need = gasLimit * maxFeePerGas + 2n * l1Fee;
  return eoaBalance >= need ? 0n : need - eoaBalance;
}

/** Refuses before any gas is sent if the EOA cannot cover the EURe transfer (a revert would burn the top-up). */
async function assertEureBalance(base: Rpc, eure: string, eoa: string, amount: bigint): Promise<void> {
  if (amount === 0n) throw new Error("EURe sweep amount is 0");
  const balance = BigInt(await base("eth_call", [{ to: eure, data: balanceOfData(eoa) }, "latest"]));
  if (balance < amount) throw new Error(`agent EOA holds ${balance} EURe, the sweep needs ${amount}`);
}

/**
 * The raw-transfer fallback: funds the agent EOA with that tx's gas, then broadcasts the
 * contract-built, MPC-signed EURe `transfer(safe, amount)`. Each step runs once.
 */
export async function submitEureSweep(d: SweepDeps, key: RequestKey): Promise<{ fundTx: Hex | null; sweepTx: Hex }> {
  await assertBaseSepolia(d.base);
  const { payload, signature, eoa, sc } = await loadSweep(d, key, "eip1559_tx", (p) => txDigest(payloadTx(p)));
  const p = payload as Eip1559Payload;
  const amount = p.data.length === 138 ? BigInt("0x" + p.data.slice(74)) : -1n;
  if (
    p.chain_id !== BASE_SEPOLIA_CHAIN_ID ||
    !eqAddr(p.to, sc.eure_address) ||
    BigInt(p.value) !== 0n ||
    amount < 0n ||
    p.data.toLowerCase() !== erc20TransferData(sc.safe_address, amount)
  ) {
    throw new Error(`signed tx is not EURe transfer(Safe, amount) on Base Sepolia: ${JSON.stringify(p)}`);
  }
  const tx = payloadTx(p);
  if (tx.maxPriorityFeePerGas > tx.maxFeePerGas) throw new Error("priority fee above max fee");
  const eoaNonce = BigInt(await d.base("eth_getTransactionCount", [eoa, "pending"]));
  if (eoaNonce !== BigInt(p.nonce)) throw new Error(`agent EOA is at nonce ${eoaNonce}, the signed tx has ${p.nonce}: it was sent or can never land`);
  const { baseFee } = await currentFees(d.base);
  if (baseFee > tx.maxFeePerGas) throw new Error(`base fee ${baseFee} is above the signed max fee ${tx.maxFeePerGas}; request a new sweep`);

  await assertEureBalance(d.base, sc.eure_address, eoa, amount);
  // `v` is 27 or 28: recoverAddress in loadSweep refuses anything else before this point.
  const raw = signedTx(tx, signature.v - 27, signature.r, signature.s);

  const l1Fee = BigInt(await d.base("eth_call", [{ to: GAS_PRICE_ORACLE, data: getL1FeeData(raw) }, "latest"]));
  const balance = BigInt(await d.base("eth_getBalance", [eoa, "latest"]));
  const topUp = gasTopUp(BigInt(p.gas_limit), tx.maxFeePerGas, balance, l1Fee);
  let fundTx: Hex | null = null;
  if (topUp > 0n) {
    d.journal.claim(`eure-gas:${eoa}:${p.nonce}`);
    fundTx = (await relayerSend(d, eoa, topUp, "0x", ETH_TRANSFER_GAS)).hash;
  }

  try {
    d.journal.claim(`eure-sweep:${eoa}:${p.nonce}`);
    const sweepTx = await sendRaw(d.base, raw);
    const logs = await waitReceipt(d.base, sweepTx, { pollMs: d.pollMs });
    if (!hasTransfer(logs, sc.eure_address, eoa, sc.safe_address, amount)) throw new Error(`tx ${sweepTx} has no Transfer of ${amount} EURe to the Safe`);
    return { fundTx, sweepTx };
  } catch (e) {
    if (!fundTx) throw e;
    throw new Error(`agent EOA ${eoa} was funded by tx ${fundTx}, but the sweep failed: ${(e as Error).message}`, { cause: e });
  }
}

/**
 * Requests a sweep as the relayer account (caller `relayer`) and waits for the MPC signature.
 * For EURe it supplies `evm_tx` from Base: the EOA's next nonce, current fees and a gas limit.
 */
export async function requestSweep(d: SweepDeps, agent: string, token: "usdc" | "eure", amount: bigint, requestId: string): Promise<RequestKey> {
  if (!d.relayerNear) throw new Error("requesting a sweep needs the relayer's NEAR account");
  let evmTx: object | null = null;
  if (token === "eure") {
    await assertBaseSepolia(d.base);
    const rec = await view<AgentRecord | null>(d.near, d.contractId, "get_agent", { agent });
    if (!rec?.evm_address) throw new Error(`no agent EOA for ${agent}`);
    await assertEureBalance(d.base, rec.sweep_config.eure_address, rec.evm_address, amount);
    // A fixed limit, not an estimate: the EOA holds no ETH yet, and nodes may refuse to
    // estimate for an account that cannot pay. An ERC-20 transfer needs about 35-55k.
    const gasLimit = EURE_SWEEP_GAS_LIMIT;
    const fees = await currentFees(d.base);
    gasTopUp(gasLimit, fees.maxFeePerGas, 0n, 0n); // refuses gas above the caps
    evmTx = {
      nonce: Number(BigInt(await d.base("eth_getTransactionCount", [rec.evm_address, "pending"]))),
      gas_limit: Number(gasLimit),
      max_fee_per_gas: fees.maxFeePerGas.toString(),
      max_priority_fee_per_gas: fees.maxPriorityFeePerGas.toString(),
    };
  }
  const args = { agent, token, amount: amount.toString(), request_id: requestId, evm_tx: evmTx, assertion: null };
  const r = await callFunction(d.near, d.relayerNear, d.contractId, "sweep", Buffer.from(JSON.stringify(args)), 300n * TGAS);
  if (r.failure) throw new Error(`sweep rejected by the contract (tx ${r.hash}): ${r.failure}`);
  const key: RequestKey = { agent, caller: { kind: "relayer", account: d.relayerNear.accountId }, request_id: requestId };
  await waitFor(
    `reservation ${requestId} signed`,
    async () => {
      const res = await view<Reservation | null>(d.near, d.contractId, "get_request", { key });
      if (res && res.status !== "pending" && !res.signature) throw new Error(`sweep ${requestId} is ${res.status}`);
      return res?.signature ? true : undefined;
    },
    { pollMs: d.pollMs },
  );
  return key;
}
