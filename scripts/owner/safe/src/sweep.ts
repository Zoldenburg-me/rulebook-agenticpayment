// The owner's USDC sweep (shape 1): the args the owner assertion signs, and the checks on the
// signed reservation before the Safe submits it.

import { Writer } from "../../near/src/borsh.ts";
import type { Eip3009Payload, MpcSignature } from "./base.ts";

/** borsh `(agent: String, token: Token, amount: U128, request_id: String, evm_tx: Option<EvmTxParams>)`, USDC so `evm_tx` is None. */
export function sweepUsdcArgs(agent: string, amount: bigint, requestId: string): Uint8Array {
  return new Writer().string(agent).u8(0).u128(amount).string(requestId).u8(0).done();
}

export type Reservation = {
  shape: string;
  status: string;
  payload: Eip3009Payload | { kind: string };
  signature: MpcSignature | null;
};

/** The reservation must be a signed USDC transfer from the agent EOA to the Safe, still valid. */
export function checkSweepReservation(
  r: Reservation,
  want: { eoa: string; safe: string; usdc: string; amount: bigint },
  nowSecs: number,
): { payload: Eip3009Payload; signature: MpcSignature } {
  const p = r.payload as Eip3009Payload;
  if (r.shape !== "sweep" || p.kind !== "eip3009") throw new Error(`not a USDC sweep: ${r.shape}/${p.kind}`);
  if (r.status !== "signed" || !r.signature) throw new Error(`sweep is ${r.status}, not signed`);
  const eq = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
  if (!eq(p.from, want.eoa) || !eq(p.to, want.safe) || !eq(p.asset, want.usdc) || BigInt(p.value) !== want.amount) {
    throw new Error(`signed sweep does not match the request: ${JSON.stringify(p)}`);
  }
  if (nowSecs >= p.valid_before) throw new Error(`sweep authorization expired at ${p.valid_before}`);
  return { payload: p, signature: r.signature };
}
