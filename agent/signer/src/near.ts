// NEAR testnet for the agent: views, and one function-call tx signed with the agent's own
// function-call key. That key lives on the mandate contract's account, so the tx's signer and
// receiver are both the contract (docs/interfaces.md §1).

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Writer } from "@nearh/owner-near/src/borsh.ts";
import { base58Decode, base58Encode } from "@nearh/owner-near/src/base58.ts";

export { assertTestnet, assertTestnetRpc } from "@nearh/owner-near/src/near.ts";

/** One JSON-RPC transport. Returns `result`, throws on a JSON-RPC `error`. Tests pass a fake. */
export type Rpc = (method: string, params: unknown) => Promise<any>;

export function httpRpc(url: string): Rpc {
  return async (method, params) => {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    });
    const body = (await res.json()) as any;
    if (body.error) throw new RpcError(method, body.error);
    return body.result;
  };
}

export class RpcError extends Error {
  readonly data: any;
  constructor(method: string, data: any) {
    super(`${method}: ${JSON.stringify(data)}`);
    this.data = data;
  }
  /** The node gave up waiting for the outcome; the tx may still execute. */
  get isTimeout(): boolean {
    return this.data?.name === "TIMEOUT_ERROR" || this.data?.cause?.name === "TIMEOUT_ERROR";
  }
  /** The node does not know the tx yet (polling too early). */
  get isUnknownTx(): boolean {
    return this.data?.cause?.name === "UNKNOWN_TRANSACTION";
  }
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export type NearKey = { accountId: string; secret: Uint8Array; publicKey: Uint8Array };

/** `ed25519:<base58 of seed ‖ public key>`, the near-cli key file format. */
export function parseNearKey(accountId: string, key: string): NearKey {
  const [curve, data] = key.split(":");
  if (curve !== "ed25519" || !data) throw new Error("AGENT_NEAR_PRIVATE_KEY: only ed25519 private keys");
  const raw = base58Decode(data);
  if (raw.length !== 64) throw new Error("AGENT_NEAR_PRIVATE_KEY: ed25519 private key must be 64 bytes");
  const secret = raw.slice(0, 32);
  const publicKey = ed25519.getPublicKey(secret);
  if (Buffer.compare(Buffer.from(publicKey), Buffer.from(raw.slice(32))) !== 0) {
    throw new Error("AGENT_NEAR_PRIVATE_KEY: private key does not match its public half");
  }
  return { accountId, secret, publicKey };
}

export const publicKeyString = (key: NearKey) => `ed25519:${base58Encode(key.publicKey)}`;

export async function view<T = any>(near: Rpc, contractId: string, method: string, args: object = {}): Promise<T> {
  const r = await near("query", {
    request_type: "call_function",
    finality: "final",
    account_id: contractId,
    method_name: method,
    args_base64: Buffer.from(JSON.stringify(args)).toString("base64"),
  });
  if (r?.error) throw new Error(`view ${method}: ${r.error}`);
  return JSON.parse(Buffer.from(r.result).toString());
}

/** borsh `Transaction` (V0) with one `FunctionCall` action and zero deposit (a function-call key cannot attach one). */
export function functionCallTx(
  key: NearKey,
  nonce: bigint,
  receiverId: string,
  blockHash: Uint8Array,
  method: string,
  args: Uint8Array,
  gas: bigint,
): Uint8Array {
  return new Writer()
    .string(key.accountId)
    .u8(0)
    .bytes(key.publicKey)
    .u64(nonce)
    .string(receiverId)
    .bytes(blockHash)
    .u32(1) // one action
    .u8(2) // Action::FunctionCall
    .string(method)
    .u32(args.length)
    .bytes(args)
    .u64(gas)
    .u128(0)
    .done();
}

/** The tx's final outcome: `successValue` is the base64 return value of the last receipt. */
export type TxOutcome = { hash: string; failure?: unknown; successValue?: string };

/** Last access-key nonce used per (account, public key) in this process. */
const lastNonce = new Map<string, bigint>();
/** Per (account, public key): the tail of its queue of submissions. */
const keyQueue = new Map<string, Promise<unknown>>();

/** Runs `fn` after every earlier `fn` for `id` has settled, so one key's txs are sent one at a time. */
async function serialized<T>(id: string, fn: () => Promise<T>): Promise<T> {
  const run = (keyQueue.get(id) ?? Promise.resolve()).then(fn);
  const tail = run.catch(() => {});
  keyQueue.set(id, tail);
  try {
    return await run;
  } finally {
    if (keyQueue.get(id) === tail) keyQueue.delete(id);
  }
}

/**
 * Signs and sends `method(args)` on `receiverId` and waits for the final outcome, across the
 * MPC's yield/resume. `send_tx` may time out first (the MPC takes 10+ s); then the tx is polled
 * by hash until `deadlineMs`. Throws if no outcome arrived by then: the tx may still land.
 *
 * Nonce allocation and `send_tx` are serialized per (account, key): NEAR only accepts a nonce
 * above the key's current one, so two txs signed together could otherwise both take the same
 * nonce, or land out of order and fail. Time queued behind earlier txs counts toward `deadlineMs`.
 */
export async function callAndWait(
  near: Rpc,
  key: NearKey,
  receiverId: string,
  method: string,
  args: object,
  opts: { gas: bigint; deadlineMs: number; pollMs?: number },
): Promise<TxOutcome> {
  const pk = publicKeyString(key);
  const id = `${key.accountId}|${pk}`;
  let hash = "";
  const outcome = (r: any): TxOutcome | undefined => {
    const status = r?.status;
    if (status?.Failure !== undefined) return { hash, failure: status.Failure };
    if (status?.SuccessValue !== undefined) return { hash, successValue: status.SuccessValue };
    return undefined; // not final yet
  };
  const sent = await serialized(id, async () => {
    if (Date.now() >= opts.deadlineMs) throw new Error(`NEAR tx not sent: the deadline passed while queued behind earlier txs from ${pk}`);
    // Optimistic, and never below the last nonce this process used: a previous tx may not be final yet.
    const ak = await near("query", { request_type: "view_access_key", account_id: key.accountId, public_key: pk, finality: "optimistic" });
    if (ak?.error) throw new Error(`view_access_key: ${ak.error}`);
    const last = lastNonce.get(id) ?? 0n;
    const nonce = (BigInt(ak.nonce) > last ? BigInt(ak.nonce) : last) + 1n;
    lastNonce.set(id, nonce);
    const tx = functionCallTx(key, nonce, receiverId, base58Decode(ak.block_hash), method, Buffer.from(JSON.stringify(args)), opts.gas);
    const digest = sha256(tx);
    const signed = new Writer().bytes(tx).u8(0).bytes(ed25519.sign(digest, key.secret)).done();
    hash = base58Encode(digest);
    const params = { signed_tx_base64: Buffer.from(signed).toString("base64"), wait_until: "EXECUTED_OPTIMISTIC" };
    try {
      return outcome(await near("send_tx", params));
    } catch (e) {
      if (!(e instanceof RpcError && e.isTimeout)) throw e;
      return undefined;
    }
  });
  if (sent) return sent;
  while (Date.now() < opts.deadlineMs) {
    await sleep(opts.pollMs ?? 2000);
    try {
      const done = outcome(await near("tx", { tx_hash: hash, sender_account_id: key.accountId, wait_until: "EXECUTED_OPTIMISTIC" }));
      if (done) return done;
    } catch (e) {
      if (!(e instanceof RpcError && (e.isTimeout || e.isUnknownTx))) throw e;
    }
  }
  throw new Error(`NEAR tx ${hash}: no final outcome before the deadline; it may still execute`);
}

/** The contract's `"{CODE}: {detail}"` panic (docs/interfaces.md §7) from a tx failure, else the raw failure. */
export function failureMessage(failure: unknown): string {
  const text = JSON.stringify(failure);
  const m = /(ERR_[A-Z0-9_]+: [^"\\]*)/.exec(text);
  return m ? m[1] : text;
}
