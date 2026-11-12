// NEAR testnet: views and one function-call tx, signed here with the account's ed25519 key and
// sent over JSON-RPC. The relayer never trusts a tx status as the result; callers read state.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { Writer } from "@nearh/owner-near/src/borsh.ts";
import { base58Decode, base58Encode } from "@nearh/owner-near/src/base58.ts";
import { sleep, type Rpc } from "./rpc.ts";

export { assertTestnet, assertTestnetRpc } from "@nearh/owner-near/src/near.ts";

export type NearSigner = { accountId: string; secret: Uint8Array; publicKey: Uint8Array };

/** `ed25519:<base58 of seed ‖ public key>`, the near-cli key file format. */
export function parseNearKey(accountId: string, key: string): NearSigner {
  const [curve, data] = key.split(":");
  if (curve !== "ed25519" || !data) throw new Error(`${accountId}: only ed25519 private keys`);
  const raw = base58Decode(data);
  if (raw.length !== 64) throw new Error(`${accountId}: ed25519 private key must be 64 bytes`);
  const secret = raw.slice(0, 32);
  const publicKey = ed25519.getPublicKey(secret);
  if (Buffer.compare(Buffer.from(publicKey), Buffer.from(raw.slice(32))) !== 0) throw new Error(`${accountId}: private key does not match its public half`);
  return { accountId, secret, publicKey };
}

async function query(near: Rpc, params: Record<string, unknown>): Promise<any> {
  const r = await near("query", { finality: "final", ...params });
  if (r?.error) throw new Error(`query ${params.request_type}: ${r.error}`);
  return r;
}

export async function view<T = any>(near: Rpc, contractId: string, method: string, args: object = {}): Promise<T> {
  const r = await query(near, {
    request_type: "call_function",
    account_id: contractId,
    method_name: method,
    args_base64: Buffer.from(JSON.stringify(args)).toString("base64"),
  });
  return JSON.parse(Buffer.from(r.result).toString());
}

/** borsh `Transaction` (V0) with one `FunctionCall` action, zero deposit. */
export function functionCallTx(
  signer: NearSigner,
  nonce: bigint,
  receiverId: string,
  blockHash: Uint8Array,
  method: string,
  args: Uint8Array,
  gas: bigint,
): Uint8Array {
  return new Writer()
    .string(signer.accountId)
    .u8(0)
    .bytes(signer.publicKey)
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

/** Last access-key nonce used per public key in this process. */
const lastNonce = new Map<string, bigint>();

export type TxOutcome = { hash: string; failure?: string; successValue?: string };

/** Signs and sends `method(args)` on `receiverId`; `args` is sent byte for byte as given. */
export async function callFunction(
  near: Rpc,
  signer: NearSigner,
  receiverId: string,
  method: string,
  args: Uint8Array,
  gas: bigint,
): Promise<TxOutcome> {
  const pk = `ed25519:${base58Encode(signer.publicKey)}`;
  // Optimistic, and never below the last nonce this process used: a previous tx may not be final yet.
  const ak = await near("query", { request_type: "view_access_key", account_id: signer.accountId, public_key: pk, finality: "optimistic" });
  if (ak?.error) throw new Error(`view_access_key ${signer.accountId}: ${ak.error}`);
  const last = lastNonce.get(pk) ?? 0n;
  const nonce = (BigInt(ak.nonce) > last ? BigInt(ak.nonce) : last) + 1n;
  lastNonce.set(pk, nonce);
  const tx = functionCallTx(signer, nonce, receiverId, base58Decode(ak.block_hash), method, args, gas);
  const digest = sha256(tx);
  const signed = new Writer().bytes(tx).u8(0).bytes(ed25519.sign(digest, signer.secret)).done();
  const hash = base58Encode(digest);
  const r = await near("send_tx", { signed_tx_base64: Buffer.from(signed).toString("base64"), wait_until: "EXECUTED_OPTIMISTIC" });
  const status = r?.status ?? {};
  if (status.Failure) return { hash, failure: JSON.stringify(status.Failure) };
  return { hash, successValue: status.SuccessValue };
}

/** Polls `check` until it returns a value (state lags the tx at `final`). */
export async function waitFor<T>(what: string, check: () => Promise<T | undefined>, opts: { tries?: number; pollMs?: number } = {}): Promise<T> {
  const tries = opts.tries ?? 30;
  for (let i = 0; i < tries; i++) {
    const v = await check();
    if (v !== undefined) return v;
    if (i < tries - 1) await sleep(opts.pollMs ?? 2000);
  }
  throw new Error(`state check failed: ${what}`);
}
