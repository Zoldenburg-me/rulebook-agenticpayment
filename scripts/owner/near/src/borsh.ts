// Borsh encoding of the owner-method argument tuples, as docs/interfaces.md §2 lists them.
// Hand-rolled for exactly the contract's types; test/borsh.test.ts checks it byte for byte
// against `borsh::to_vec` of the contract crate.

import { base58Decode } from "./base58.ts";

export type SweepConfig = {
  safe_address: string;
  usdc_address: string;
  eure_address: string;
  chain_id: number;
};

/** Amounts are decimal strings (the contract's JSON `U128`). */
export type RailMandate = {
  amount_range: { min: string; max: string };
  budget: string;
  period_secs: number;
};

export type Mandate = {
  x402: RailMandate;
  sepa: RailMandate;
  usdc_address: string;
  eure_address: string;
  chain_id: number;
  float_cap: { usdc: string; eure: string };
  max_validity_secs: number;
};

export type Payee = { rail: "x402"; pay_to: string } | { rail: "sepa"; iban: string };

export class Writer {
  private parts: number[] = [];

  u8(n: number): this {
    this.parts.push(n & 0xff);
    return this;
  }

  u32(n: number): this {
    if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) throw new Error(`u32 out of range: ${n}`);
    for (let i = 0; i < 4; i++) this.parts.push((n >>> (8 * i)) & 0xff);
    return this;
  }

  private uint(v: bigint | number | string, bytes: number): this {
    const n = BigInt(v);
    if (n < 0n || n >= 1n << BigInt(8 * bytes)) throw new Error(`u${8 * bytes} out of range: ${v}`);
    for (let i = 0; i < bytes; i++) this.parts.push(Number((n >> BigInt(8 * i)) & 0xffn));
    return this;
  }

  u64(v: bigint | number | string): this {
    return this.uint(v, 8);
  }

  u128(v: bigint | number | string): this {
    return this.uint(v, 16);
  }

  bytes(b: Uint8Array): this {
    for (const x of b) this.parts.push(x);
    return this;
  }

  string(s: string): this {
    const b = new TextEncoder().encode(s);
    return this.u32(b.length).bytes(b);
  }

  option<T>(v: T | null | undefined, f: (w: this, v: T) => void): this {
    if (v === null || v === undefined) return this.u8(0);
    this.u8(1);
    f(this, v);
    return this;
  }

  /** near_sdk `PublicKey`: a `Vec<u8>` of curve byte (0 = ed25519) + 32 key bytes. */
  publicKey(pk: string): this {
    const [curve, data] = pk.split(":");
    if (curve !== "ed25519" || !data) throw new Error(`only ed25519 public keys: ${pk}`);
    const key = base58Decode(data);
    if (key.length !== 32) throw new Error(`ed25519 key must be 32 bytes: ${pk}`);
    return this.u32(33).u8(0).bytes(key);
  }

  done(): Uint8Array {
    return Uint8Array.from(this.parts);
  }
}

function sweepConfig(w: Writer, sc: SweepConfig): void {
  w.string(sc.safe_address).string(sc.usdc_address).string(sc.eure_address).u64(sc.chain_id);
}

function rail(w: Writer, r: RailMandate): void {
  w.u128(r.amount_range.min).u128(r.amount_range.max).u128(r.budget).u64(r.period_secs);
}

function mandate(w: Writer, m: Mandate): void {
  rail(w, m.x402);
  rail(w, m.sepa);
  w.string(m.usdc_address).string(m.eure_address).u64(m.chain_id);
  w.u128(m.float_cap.usdc).u128(m.float_cap.eure).u32(m.max_validity_secs);
}

function payee(w: Writer, p: Payee): void {
  if (p.rail === "x402") w.u8(0).string(p.pay_to);
  else if (p.rail === "sepa") w.u8(1).string(p.iban);
  else throw new Error(`unknown payee rail: ${JSON.stringify(p)}`);
}

export function addAgentArgs(agent: string, publicKey: string, sc: SweepConfig, evmAddress: string): Uint8Array {
  const w = new Writer().string(agent).publicKey(publicKey);
  sweepConfig(w, sc);
  return w.string(evmAddress).done();
}

export function setRelayerArgs(account: string | null): Uint8Array {
  return new Writer().option(account, (w, a) => w.string(a)).done();
}

export function setMandateArgs(agent: string, m: Mandate): Uint8Array {
  const w = new Writer().string(agent);
  mandate(w, m);
  return w.done();
}

export function payeeArgs(agent: string, p: Payee): Uint8Array {
  const w = new Writer().string(agent);
  payee(w, p);
  return w.done();
}

export function agentArgs(agent: string): Uint8Array {
  return new Writer().string(agent).done();
}
