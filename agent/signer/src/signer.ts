// The agent's x402 signer: its address is the agent EOA the contract stores, and every signature
// comes from the mandate contract's `request_signature` (shape 2), which checks the mandate,
// builds the EIP-3009 authorization itself and has the MPC sign it.

import { randomBytes } from "node:crypto";
import { getAddress, recoverTypedDataAddress, type Hex } from "viem";
import { callAndWait, failureMessage, publicKeyString, view, type NearKey, type Rpc } from "./near.ts";

/** `X402PaymentRequirements` in `contract/src/types.rs` (x402 v2 names). */
export type X402Shape = {
  resourceUrl: string;
  scheme: string;
  network: string;
  asset: string;
  payTo: string;
  amount: string;
  maxTimeoutSeconds: number;
};

/** The parts of `Reservation` (docs/interfaces.md §4) the signer reads. */
export type Reservation = {
  key: { agent: string; caller: { kind: string }; request_id: string };
  shape: string;
  status: "pending" | "signed" | "unknown" | "spent" | "released" | "revoked";
  valid_before: number;
  payload: {
    kind: string;
    asset: string;
    chain_id: number;
    from: string;
    to: string;
    value: string;
    valid_after: number;
    valid_before: number;
    nonce: Hex;
  };
  signature: { r: Hex; s: Hex; v: number } | null;
};

/** An x402 `exact` EIP-3009 payload, as `@x402/evm`'s client builds it. */
export type Eip3009Payload = {
  authorization: { from: Hex; to: Hex; value: string; validAfter: string; validBefore: string; nonce: Hex };
  signature: Hex;
};

/** The EIP-712 types of USDC's `transferWithAuthorization`. */
export const AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

/** The EIP-712 domain the contract signs under (shape 2: `{name: "USDC", version: "2"}`). */
export const USDC_DOMAIN = { name: "USDC", version: "2" } as const;

/** request_signature → MPC sign (50 Tgas) → on_signature (20 Tgas), with room to spare. */
export const REQUEST_GAS = 300_000_000_000_000n;
/** S-c saw 11.8 s for one MPC signature; the contract expires a pending request after 300 s. */
export const DEFAULT_TIMEOUT_MS = 120_000;
/** Time an authorization must still be valid for when it is handed out: x402 verify plus settle. */
export const DEFAULT_SETTLE_MARGIN_SECONDS = 30;
/** Time to budget for one MPC signature before the window starts running out (S-c saw 11.8 s). */
export const DEFAULT_MIN_SIGN_SECONDS = 15;

/**
 * The seller's window cannot cover signing plus settlement. `window-too-short`: refused before
 * `request_signature`, so nothing is reserved. `expires-too-soon`: the contract signed, but too
 * little of the window is left to settle; the reservation stays `signed` and counts toward budget.
 */
export class SettlementWindowError extends Error {
  readonly code: "window-too-short" | "expires-too-soon";
  constructor(code: SettlementWindowError["code"], message: string) {
    super(message);
    this.name = "SettlementWindowError";
    this.code = code;
  }
}

/** A fresh `request_id`: `x402-` + base36 ms + 16 hex, within `[A-Za-z0-9._:-]{1,64}`. */
export const newRequestId = () => `x402-${Date.now().toString(36)}-${randomBytes(8).toString("hex")}`;

export type NearX402SignerOptions = {
  near: Rpc;
  /** The mandate contract; the agent's key is on its account. */
  contractId: string;
  key: NearKey;
  timeoutMs?: number;
  pollMs?: number;
  /** Seconds of validity an authorization must have left when returned. Default `DEFAULT_SETTLE_MARGIN_SECONDS`. */
  settleMarginSeconds?: number;
  /** Seconds budgeted for signing; a seller window under this plus the margin is refused up front. Default `DEFAULT_MIN_SIGN_SECONDS`. */
  minSignSeconds?: number;
  /**
   * Off by default: `connect` refuses an RPC whose `status.chain_id` is not `testnet` and a
   * contract id that does not end in `.testnet`. Set it only for a local sandbox
   * (near-workspaces); never for mainnet.
   */
  allowNonTestnet?: boolean;
  /** Called with each checked signature, e.g. to keep a receipt (A2's `get_receipt`). */
  onSigned?: (signed: SignedX402) => void;
};

export type SignedX402 = { requestId: string; txHash: string; payload: Eip3009Payload; reservation: Reservation };

export class NearX402Signer {
  readonly address: Hex;
  readonly agent: string;
  private readonly opts: NearX402SignerOptions;

  private constructor(opts: NearX402SignerOptions, agent: string, address: Hex) {
    this.opts = opts;
    this.agent = agent;
    this.address = address;
  }

  /**
   * Looks the agent up by its key (`agent_of_key`) and takes the EOA from `get_agent`, the
   * MPC-derived address the owner registered. If `expectedAddress` is given it must match.
   */
  static async connect(opts: NearX402SignerOptions & { expectedAddress?: string }): Promise<NearX402Signer> {
    if (!opts.allowNonTestnet) {
      if (!/^[a-z0-9._-]+\.testnet$/.test(opts.contractId)) throw new Error(`contractId must be a .testnet account, got "${opts.contractId}"`);
      const chainId = (await opts.near("status", []))?.chain_id;
      if (chainId !== "testnet") throw new Error(`the NEAR RPC is on chain ${JSON.stringify(chainId)}, not testnet`);
    }
    if (opts.key.accountId !== opts.contractId) {
      throw new Error(`the agent key belongs to the mandate contract account ${opts.contractId}, not ${opts.key.accountId}`);
    }
    const agent = await view<string | null>(opts.near, opts.contractId, "agent_of_key", { public_key: publicKeyString(opts.key) });
    if (!agent) throw new Error(`${publicKeyString(opts.key)} is not a live agent key on ${opts.contractId}`);
    const record = await view<{ evm_address?: string; revoked: boolean } | null>(opts.near, opts.contractId, "get_agent", { agent });
    if (!record || record.revoked) throw new Error(`agent ${agent} is revoked`);
    if (!record.evm_address) throw new Error(`agent ${agent} has no evm_address`);
    const address = getAddress(record.evm_address);
    if (opts.expectedAddress && getAddress(opts.expectedAddress) !== address) {
      throw new Error(`AGENT_EVM_ADDRESS ${opts.expectedAddress} differs from the contract's ${address} for ${agent}`);
    }
    return new NearX402Signer(opts, agent, address);
  }

  /**
   * Calls `request_signature(request_id, {type: "x402", ...shape})` and waits for the MPC
   * callback. Returns the signed EIP-3009 payload only after checking that it pays exactly what
   * was asked and that the signature recovers to this agent's EOA.
   */
  async signX402(shape: X402Shape, requestId = newRequestId()): Promise<SignedX402> {
    const { near, contractId, key } = this.opts;
    const minWindow = this.minSignSeconds + this.settleMarginSeconds;
    if (!(shape.maxTimeoutSeconds >= minWindow)) {
      throw new SettlementWindowError("window-too-short", `the seller's maxTimeoutSeconds ${shape.maxTimeoutSeconds} is under ${minWindow} s (signing ${this.minSignSeconds} s + settlement ${this.settleMarginSeconds} s); not requesting a signature`);
    }
    const outcome = await callAndWait(near, key, contractId, "request_signature", { request_id: requestId, shape: { type: "x402", ...shape } }, {
      gas: REQUEST_GAS,
      deadlineMs: Date.now() + (this.opts.timeoutMs ?? DEFAULT_TIMEOUT_MS),
      pollMs: this.opts.pollMs,
    });
    if (outcome.failure !== undefined) {
      throw new Error(`request_signature ${requestId} rejected: ${failureMessage(outcome.failure)} (tx ${outcome.hash})`);
    }
    const reservation = JSON.parse(Buffer.from(outcome.successValue ?? "", "base64").toString()) as Reservation;
    if (reservation.status !== "signed" || !reservation.signature) {
      throw new Error(`request_signature ${requestId}: reservation is ${reservation.status}, no signature (tx ${outcome.hash})`);
    }
    const payload = await this.checkedPayload(shape, reservation);
    const signed = { requestId, txHash: outcome.hash, payload, reservation };
    this.opts.onSigned?.(signed);
    return signed;
  }

  /** The x402 payload from a signed reservation, refusing anything that is not exactly `shape`. */
  async checkedPayload(shape: X402Shape, r: Reservation): Promise<Eip3009Payload> {
    const p = r.payload;
    const chainId = chainIdOf(shape.network);
    const lc = (s: string) => s.toLowerCase();
    const mismatch =
      r.shape !== "x402" ? "shape" :
      p.kind !== "eip3009" ? "payload kind" :
      lc(p.from) !== lc(this.address) ? "from" :
      lc(p.to) !== lc(shape.payTo) ? "to" :
      p.value !== shape.amount ? "value" :
      lc(p.asset) !== lc(shape.asset) ? "asset" :
      p.chain_id !== chainId ? "chain_id" :
      !(p.valid_after < p.valid_before) ? "validity window" :
      undefined;
    if (mismatch) throw new Error(`reservation ${r.key.request_id}: signed ${mismatch} does not match the payment requirements`);
    const left = p.valid_before - Math.floor(Date.now() / 1000);
    if (left < this.settleMarginSeconds) {
      throw new SettlementWindowError("expires-too-soon", `reservation ${r.key.request_id}: the authorization expires in ${left} s, under the ${this.settleMarginSeconds} s needed to settle`);
    }
    const sig = r.signature!;
    if (sig.v !== 27 && sig.v !== 28) throw new Error(`reservation ${r.key.request_id}: v must be 27 or 28`);
    const signature = `0x${strip(sig.r).padStart(64, "0")}${strip(sig.s).padStart(64, "0")}${sig.v.toString(16)}` as Hex;
    const authorization = {
      from: getAddress(p.from),
      to: getAddress(p.to),
      value: p.value,
      validAfter: String(p.valid_after),
      validBefore: String(p.valid_before),
      nonce: p.nonce,
    };
    const signer = await recoverTypedDataAddress({
      domain: { ...USDC_DOMAIN, chainId, verifyingContract: getAddress(p.asset) },
      types: AUTHORIZATION_TYPES,
      primaryType: "TransferWithAuthorization",
      message: {
        ...authorization,
        value: BigInt(authorization.value),
        validAfter: BigInt(authorization.validAfter),
        validBefore: BigInt(authorization.validBefore),
      },
      signature,
    });
    if (signer !== this.address) throw new Error(`reservation ${r.key.request_id}: signature recovers to ${signer}, not the agent EOA ${this.address}`);
    return { authorization, signature };
  }

  private get settleMarginSeconds() {
    return this.opts.settleMarginSeconds ?? DEFAULT_SETTLE_MARGIN_SECONDS;
  }
  private get minSignSeconds() {
    return this.opts.minSignSeconds ?? DEFAULT_MIN_SIGN_SECONDS;
  }

  /**
   * `ClientEvmSigner.signTypedData`. Not supported: the contract picks the nonce and validity
   * window itself, so a message built by the caller can never be signed as is. Use
   * `NearExactEvmScheme`, which sends the payment requirements instead.
   */
  async signTypedData(_: { domain: Record<string, unknown>; types: Record<string, unknown>; primaryType: string; message: Record<string, unknown> }): Promise<Hex> {
    throw new Error("NearX402Signer cannot sign caller-built typed data: the mandate contract builds the authorization. Register NearExactEvmScheme instead of ExactEvmScheme.");
  }
}

/** `eip155:<n>` → n. */
export function chainIdOf(network: string): number {
  const m = /^eip155:([0-9]{1,15})$/.exec(network);
  if (!m) throw new Error(`not an EVM network: ${network}`);
  return Number(m[1]);
}

const strip = (h: string) => h.replace(/^0x/, "");
