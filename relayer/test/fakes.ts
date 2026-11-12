// Fake NEAR and Base Sepolia RPCs: they answer the calls the relayer makes and record every send.

import { ed25519 } from "@noble/curves/ed25519.js";
import { base58Encode } from "@nearh/owner-near/src/base58.ts";
import { GAS_PRICE_ORACLE, hex, keccak, unhex } from "../src/evm.ts";
import type { NearSigner } from "../src/near.ts";
import type { Rpc } from "../src/rpc.ts";

export function nearSigner(accountId: string, seedByte: number): NearSigner {
  const secret = new Uint8Array(32).fill(seedByte);
  return { accountId, secret, publicKey: ed25519.getPublicKey(secret) };
}

export type SentNearTx = { signed: Uint8Array; nonce: bigint; method: string; args: string };

/** Parses the one FunctionCall action out of a signed tx (layout of near.ts functionCallTx). */
function parseNearTx(signed: Uint8Array): SentNearTx {
  const b = Buffer.from(signed);
  let i = 0;
  const str = () => {
    const n = b.readUInt32LE(i);
    const s = b.subarray(i + 4, i + 4 + n).toString();
    i += 4 + n;
    return s;
  };
  str(); // signer
  i += 33; // public key
  const nonce = b.readBigUInt64LE(i);
  i += 8;
  str(); // receiver
  i += 32 + 4 + 1; // block hash, action count, action tag
  const method = str();
  const args = str();
  return { signed, nonce, method, args };
}

export class FakeNear {
  views: Record<string, (args: any) => any> = {};
  sent: SentNearTx[] = [];
  /** Called on each send_tx; returns the tx `status`. */
  onSend: (tx: SentNearTx) => any = () => ({ SuccessValue: "" });

  rpc: Rpc = async (method, params: any) => {
    if (method === "query" && params.request_type === "call_function") {
      const f = this.views[params.method_name];
      if (!f) throw new Error(`fake near: no view ${params.method_name}`);
      const args = JSON.parse(Buffer.from(params.args_base64, "base64").toString());
      return { result: [...Buffer.from(JSON.stringify(f(args) ?? null))] };
    }
    if (method === "query" && params.request_type === "view_access_key") {
      return { nonce: 7, block_hash: base58Encode(new Uint8Array(32).fill(9)) };
    }
    if (method === "send_tx") {
      const tx = parseNearTx(Buffer.from(params.signed_tx_base64, "base64"));
      this.sent.push(tx);
      return { status: this.onSend(tx) };
    }
    throw new Error(`fake near: unexpected ${method}`);
  };
}

/** Decodes an RLP item (enough for type-2 txs). */
function rlpDecode(b: Uint8Array, i = 0): [any, number] {
  const p = b[i];
  const read = (off: number, len: number, list: boolean): [any, number] => {
    const body = b.subarray(off, off + len);
    if (!list) return [body, off + len];
    const items = [];
    let j = 0;
    while (j < body.length) {
      const [v, next] = rlpDecode(body, j);
      items.push(v);
      j = next;
    }
    return [items, off + len];
  };
  const lenOf = (n: number, at: number) => Number(BigInt("0x" + Buffer.from(b.subarray(at, at + n)).toString("hex")));
  if (p < 0x80) return [b.subarray(i, i + 1), i + 1];
  if (p <= 0xb7) return read(i + 1, p - 0x80, false);
  if (p < 0xc0) return read(i + 1 + (p - 0xb7), lenOf(p - 0xb7, i + 1), false);
  if (p <= 0xf7) return read(i + 1, p - 0xc0, true);
  return read(i + 1 + (p - 0xf7), lenOf(p - 0xf7, i + 1), true);
}

const int = (x: Uint8Array) => (x.length ? BigInt("0x" + Buffer.from(x).toString("hex")) : 0n);

export type SentEvmTx = { raw: string; nonce: bigint; to: string; value: bigint; data: string; gas: bigint; maxFee: bigint };

export function decodeTx(raw: string): SentEvmTx {
  const b = unhex(raw);
  if (b[0] !== 2) throw new Error("not a type-2 tx");
  const [f] = rlpDecode(b, 1);
  return { raw, nonce: int(f[1]), maxFee: int(f[3]), gas: int(f[4]), to: hex(f[5]), value: int(f[6]), data: hex(f[7]) };
}

const selectorOf = (sig: string) => hex(keccak(new TextEncoder().encode(sig)).slice(0, 4));
const BALANCE_OF = selectorOf("balanceOf(address)");
const AUTHORIZATION_STATE = selectorOf("authorizationState(address,bytes32)");
const GET_L1_FEE = selectorOf("getL1Fee(bytes)");

export class FakeBase {
  chainId = 84532;
  nonces: Record<string, bigint> = {};
  balances: Record<string, bigint> = {};
  baseFee = 1_000_000n;
  authorizationUsed = false;
  /** What the OP-stack GasPriceOracle's `getL1Fee` returns: the L1 data fee a tx pays on top of its L2 gas. */
  l1Fee = 20_000_000_000n;
  /** ERC-20 balances by token, then holder (lowercase addresses), for `balanceOf`. */
  tokenBalances: Record<string, Record<string, bigint>> = {};
  /** Every `eth_call` made, in order. */
  calls: { to: string; data: string }[] = [];
  sent: SentEvmTx[] = [];
  /** Logs of the receipt for a sent tx. */
  logsFor: (tx: SentEvmTx) => any[] = () => [];

  setTokenBalance(token: string, holder: string, amount: bigint) {
    (this.tokenBalances[token.toLowerCase()] ??= {})[holder.toLowerCase()] = amount;
  }

  rpc: Rpc = async (method, params: any) => {
    switch (method) {
      case "eth_chainId":
        return "0x" + this.chainId.toString(16);
      case "eth_getTransactionCount":
        return "0x" + (this.nonces[params[0].toLowerCase()] ?? 0n).toString(16);
      case "eth_getBalance":
        return "0x" + (this.balances[params[0].toLowerCase()] ?? 0n).toString(16);
      case "eth_getBlockByNumber":
        return { baseFeePerGas: "0x" + this.baseFee.toString(16) };
      case "eth_maxPriorityFeePerGas":
        return "0xf4240";
      case "eth_estimateGas":
        return "0xea60"; // 60000
      case "eth_call": {
        const { to, data }: { to: string; data: string } = params[0];
        this.calls.push({ to, data });
        if (data.startsWith(BALANCE_OF)) {
          const held = this.tokenBalances[to.toLowerCase()]?.["0x" + data.slice(-40)] ?? 0n;
          return "0x" + held.toString(16).padStart(64, "0");
        }
        if (to.toLowerCase() === GAS_PRICE_ORACLE.toLowerCase() && data.startsWith(GET_L1_FEE)) {
          return "0x" + this.l1Fee.toString(16).padStart(64, "0");
        }
        if (data.startsWith(AUTHORIZATION_STATE)) {
          return "0x" + (this.authorizationUsed ? "1" : "0").padStart(64, "0");
        }
        throw new Error(`fake base: unexpected eth_call to ${to} with ${data.slice(0, 10)}`);
      }
      case "eth_sendRawTransaction": {
        const tx = decodeTx(params[0]);
        this.sent.push(tx);
        return hex(keccak(unhex(params[0])));
      }
      case "eth_getTransactionReceipt": {
        const tx = this.sent.find((t) => hex(keccak(unhex(t.raw))) === params[0]);
        return tx ? { status: "0x1", logs: this.logsFor(tx) } : null;
      }
    }
    throw new Error(`fake base: unexpected ${method}`);
  };
}

const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const topic = (a: string) => "0x" + a.slice(2).toLowerCase().padStart(64, "0");

export function transferLog(token: string, from: string, to: string, amount: bigint) {
  return { address: token, topics: [TRANSFER_TOPIC, topic(from), topic(to)], data: "0x" + amount.toString(16).padStart(64, "0") };
}
