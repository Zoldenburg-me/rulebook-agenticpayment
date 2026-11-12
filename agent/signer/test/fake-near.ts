// An in-process NEAR RPC with the mandate contract's shape-2 path and T1's mock MPC behind it:
// it checks the agent's signed tx like the chain, applies the C5 checks, builds the EIP-3009
// digest, signs it with the mock MPC key (contract/tests/integration/src/mpc.rs: root 0x42…42,
// epsilon derivation per (predecessor, path)) into the MPC response format, converts it as the
// contract does (v = 27 + recovery_id) and returns the `Reservation`. No network.

import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { base58Encode } from "@nearh/owner-near/src/base58.ts";
import { bytesToHex, hashTypedData, keccak256, toHex, type Hex } from "viem";
import { privateKeyToAddress } from "viem/accounts";
import { RpcError, type NearKey, type Rpc } from "../src/near.ts";
import { AUTHORIZATION_TYPES, USDC_DOMAIN, type Reservation } from "../src/signer.ts";

export const CONTRACT = "mandate-test.testnet";
export const AGENT = "agent-1";
export const USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
export const PAY_TO = "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f";

const MOCK_ROOT_SECRET = 0x42n * (2n ** 256n - 1n) / 255n; // 32 bytes of 0x42
const EPSILON_PREFIX = "near-mpc-recovery v0.1.0 epsilon derivation:";

/** T1's mock MPC key for (predecessor, path): `root + sha3_256(prefix ‖ predecessor ‖ "," ‖ path)`. */
export function mockDerivedKey(predecessor: string, path: string): Hex {
  const n = secp256k1.Point.CURVE().n;
  const eps = BigInt(bytesToHex(sha3_256(new TextEncoder().encode(`${EPSILON_PREFIX}${predecessor},${path}`)))) % n;
  return toHex((MOCK_ROOT_SECRET + eps) % n, { size: 32 });
}

/** The agent's NEAR function-call key (on the contract account), from a fixed seed. */
export function agentKey(seed = 7): { key: NearKey; text: string } {
  const secret = new Uint8Array(32).fill(seed);
  const publicKey = ed25519.getPublicKey(secret);
  const text = `ed25519:${base58Encode(new Uint8Array([...secret, ...publicKey]))}`;
  return { key: { accountId: CONTRACT, secret, publicKey }, text };
}

/**
 * `respond`: final outcome straight from `send_tx`. `slow`: `send_tx` times out and the tx
 * becomes final after a few polls. `hold`: never final (the MPC stays pending). `fail`: the MPC
 * fails, the callback records `unknown`. `tamper` / `wrong-key`: a broken contract or MPC that
 * signs a different `to`, or with another key.
 */
export type Mode = "respond" | "slow" | "hold" | "fail" | "tamper" | "wrong-key";

type Shape = { type: string; resourceUrl: string; scheme: string; network: string; asset: string; payTo: string; amount: string; maxTimeoutSeconds: number };

export class FakeNear {
  mode: Mode = "respond";
  payees = [PAY_TO];
  readonly key = agentKey();
  readonly evmAddress = privateKeyToAddress(mockDerivedKey(CONTRACT, AGENT)).toLowerCase();
  readonly requests: { request_id: string; shape: Shape }[] = [];
  /** `status.chain_id`. */
  chainId = "testnet";
  /** The contract's `max_validity_secs − 60` cap on the window's end. */
  maxValidBeforeSecs = 240;
  /**
   * Holds each access-key answer and each `send_tx` until a second one arrives (or 50 ms), then
   * answers the access keys together and accepts the txs last-first, as a network may reorder them.
   */
  concurrent = false;
  /** Nonces of the txs the fake accepted, in order. */
  readonly nonces: bigint[] = [];
  private readonly held = { query: [] as (() => void)[], send: [] as (() => void)[] };
  private nonce = 100n;
  private readonly seen = new Set<string>();
  private readonly outcomes = new Map<string, { polls: number; status: unknown }>();

  rpc: Rpc = async (method, params: any) => {
    if (method === "status") return { chain_id: this.chainId };
    if (method === "query" && params.request_type === "view_access_key") await this.gate("query");
    if (method === "query") return this.query(params);
    if (method === "send_tx") await this.gate("send");
    if (method === "send_tx") return this.sendTx(params);
    if (method === "tx") return this.txStatus(params);
    throw new Error(`fake near: no ${method}`);
  };

  private async gate(kind: "query" | "send") {
    if (!this.concurrent) return;
    await new Promise<void>((resolve) => {
      const q = this.held[kind];
      q.push(resolve);
      const flush = () => {
        const all = q.splice(0);
        (kind === "send" ? all.reverse() : all).forEach((r) => r());
      };
      if (q.length >= 2) queueMicrotask(flush); // after this await attaches, so the reversal holds
      else setTimeout(flush, 50);
    });
  }

  private query(p: any) {
    if (p.request_type === "view_access_key") {
      if (p.account_id !== CONTRACT || p.public_key !== `ed25519:${base58Encode(this.key.key.publicKey)}`) return { error: "access key does not exist" };
      return { nonce: Number(this.nonce), block_hash: base58Encode(new Uint8Array(32).fill(9)), permission: {} };
    }
    if (p.request_type === "call_function" && p.account_id === CONTRACT) {
      const args = JSON.parse(Buffer.from(p.args_base64, "base64").toString());
      const out = (v: unknown) => ({ result: [...Buffer.from(JSON.stringify(v))] });
      if (p.method_name === "agent_of_key") return out(args.public_key === `ed25519:${base58Encode(this.key.key.publicKey)}` ? AGENT : null);
      if (p.method_name === "get_agent") return out(args.agent === AGENT ? { agent: AGENT, evm_address: this.evmAddress, revoked: false } : null);
    }
    return { error: `fake near: no ${p.request_type} ${p.method_name ?? ""}` };
  }

  private sendTx(p: any) {
    const { hash, method, args } = this.decode(Buffer.from(p.signed_tx_base64, "base64"));
    if (method !== "request_signature") throw new Error(`fake near: unexpected method ${method}`);
    const status = this.requestSignature(args.request_id, args.shape);
    if (this.mode === "respond" || this.mode === "fail" || this.mode === "tamper" || this.mode === "wrong-key" || "Failure" in status) {
      return { status, transaction: { hash } };
    }
    this.outcomes.set(hash, { polls: 0, status });
    throw new RpcError("send_tx", { name: "HANDLER_ERROR", cause: { name: "TIMEOUT_ERROR" } });
  }

  private txStatus(p: any) {
    const o = this.outcomes.get(p.tx_hash);
    if (!o) throw new RpcError("tx", { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_TRANSACTION" } });
    o.polls++;
    if (this.mode === "hold" || o.polls < 3) throw new RpcError("tx", { name: "HANDLER_ERROR", cause: { name: "TIMEOUT_ERROR" } });
    return { status: o.status };
  }

  /** Parses and checks the signed tx like the chain: one zero-deposit FunctionCall by the agent key on the contract. */
  private decode(raw: Uint8Array) {
    let i = 0;
    const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const u32 = () => { const v = view.getUint32(i, true); i += 4; return v; };
    const u64 = () => { const v = view.getBigUint64(i, true); i += 8; return v; };
    const bytes = (n: number) => { const v = raw.slice(i, i + n); i += n; return v; };
    const str = () => Buffer.from(bytes(u32())).toString();
    const signerId = str();
    if (bytes(1)[0] !== 0) throw new Error("fake near: ed25519 only");
    const pk = bytes(32);
    const nonce = u64();
    const receiver = str();
    bytes(32); // block hash
    if (u32() !== 1 || bytes(1)[0] !== 2) throw new Error("fake near: one FunctionCall expected");
    const method = str();
    const args = JSON.parse(Buffer.from(bytes(u32())).toString());
    u64(); // gas
    const deposit = bytes(16);
    const txEnd = i;
    if (bytes(1)[0] !== 0) throw new Error("fake near: ed25519 signature expected");
    const sig = bytes(64);
    const digest = sha256(raw.slice(0, txEnd));
    if (!ed25519.verify(sig, digest, pk)) throw new RpcError("send_tx", { name: "INVALID_TRANSACTION", cause: { name: "INVALID_SIGNATURE" } });
    if (signerId !== CONTRACT || receiver !== CONTRACT) throw new Error(`fake near: ${signerId} → ${receiver}, expected the contract`);
    if (Buffer.compare(Buffer.from(pk), Buffer.from(this.key.key.publicKey)) !== 0) throw new Error("fake near: not the agent key");
    if (deposit.some((b) => b !== 0)) throw new Error("fake near: a function-call key cannot attach a deposit");
    if (nonce <= this.nonce) throw new RpcError("send_tx", { name: "INVALID_TRANSACTION", cause: { name: "INVALID_NONCE" } });
    this.nonce = nonce;
    this.nonces.push(nonce);
    return { hash: base58Encode(digest), method, args };
  }

  private requestSignature(requestId: string, shape: Shape): { Failure: unknown } | { SuccessValue: string } {
    const panic = (code: string, detail = "") => ({ Failure: { ActionError: { index: 0, kind: { FunctionCallError: { ExecutionError: `Smart contract panicked: ${code}: ${detail}` } } } } });
    if (this.seen.has(requestId)) return panic("ERR_DUPLICATE_REQUEST", requestId);
    if (shape.type !== "x402") return panic("ERR_SHAPE_NOT_ALLOWED", shape.type);
    if (shape.scheme !== "exact") return panic("ERR_WRONG_SCHEME");
    if (!this.payees.includes(shape.payTo.toLowerCase())) return panic("ERR_PAYEE_NOT_ALLOWED", shape.payTo);
    if (shape.asset.toLowerCase() !== USDC) return panic("ERR_WRONG_ASSET");
    if (shape.network !== "eip155:84532") return panic("ERR_WRONG_NETWORK");
    if (BigInt(shape.amount) < 1n || BigInt(shape.amount) > 1_000_000n) return panic("ERR_OVER_PER_PAYMENT_CAP");
    if (!(shape.maxTimeoutSeconds >= 1)) return panic("ERR_INVALID_TIMEOUT");
    this.seen.add(requestId);
    this.requests.push({ request_id: requestId, shape });

    const now = Math.floor(Date.now() / 1000);
    const to = this.mode === "tamper" ? "0x000000000000000000000000000000000000dead" : shape.payTo.toLowerCase();
    const auth = {
      from: this.evmAddress, to, value: shape.amount,
      valid_after: now - 60, valid_before: now + Math.min(shape.maxTimeoutSeconds, this.maxValidBeforeSecs),
      nonce: keccak256(new TextEncoder().encode(`${AGENT}|agent|2|${requestId}`)),
    };
    const digest = hashTypedData({
      domain: { ...USDC_DOMAIN, chainId: 84532, verifyingContract: USDC },
      types: AUTHORIZATION_TYPES,
      primaryType: "TransferWithAuthorization",
      message: { from: auth.from as Hex, to: auth.to as Hex, value: BigInt(auth.value), validAfter: BigInt(auth.valid_after), validBefore: BigInt(auth.valid_before), nonce: auth.nonce },
    });
    const reservation: Reservation & Record<string, unknown> = {
      key: { agent: AGENT, caller: { kind: "agent" }, request_id: requestId },
      shape: "x402",
      rail: "x402",
      amount: shape.amount,
      valid_before: auth.valid_before,
      release_after: auth.valid_before + 60,
      digest,
      payload: { kind: "eip3009", asset: USDC, chain_id: 84532, ...auth },
      status: "signed",
      counts_against_budget: true,
      signature: null,
    };
    if (this.mode === "fail") {
      reservation.status = "unknown";
    } else {
      const path = this.mode === "wrong-key" ? "agent-2" : AGENT;
      reservation.signature = fromMpcResponse(mockSignResponse(CONTRACT, path, digest));
    }
    return { SuccessValue: Buffer.from(JSON.stringify(reservation)).toString("base64") };
  }
}

/** `sign`'s response in the real format, as T1's `sign_response` (low-s, RFC 6979). */
function mockSignResponse(predecessor: string, path: string, digest: Hex) {
  const sig = secp256k1.sign(Buffer.from(digest.slice(2), "hex"), Buffer.from(mockDerivedKey(predecessor, path).slice(2), "hex"), { prehash: false, format: "recovered" });
  // noble's recovered format is recovery ‖ r ‖ s.
  const recovery = sig[0];
  return {
    scheme: "Secp256k1",
    big_r: { affine_point: `${recovery ? "03" : "02"}${Buffer.from(sig.slice(1, 33)).toString("hex")}` },
    s: { scalar: Buffer.from(sig.slice(33, 65)).toString("hex") },
    recovery_id: recovery,
  };
}
/** The contract's conversion: `r` = x of `big_r` (prefix dropped), `v = 27 + recovery_id`. */
function fromMpcResponse(res: ReturnType<typeof mockSignResponse>) {
  return { r: `0x${res.big_r.affine_point.slice(2)}` as Hex, s: `0x${res.s.scalar}` as Hex, v: 27 + res.recovery_id };
}
