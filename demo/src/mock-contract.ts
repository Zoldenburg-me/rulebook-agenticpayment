// --mock only: an in-memory stand-in for the mandate contract's PayPal paths (shape 4,
// contract/src/shapes/paypal.rs `build_paypal`; shape 5, paypal_checkout.rs; shape 6, refund.rs)
// and for NEAR Chain Signatures. It applies the same
// checks in the same order (PayPal rail present, payee allowlisted, amount within the per-payment
// range, timestamp window, budget, request_id unique) and signs the same text, but with a local
// secp256k1 key instead of the MPC network. The real contract and its tests are in contract/;
// this model exists so the demo runs with no NEAR account. The rail (rails/paypal) verifies the
// signature and reservation exactly as it does against testnet.

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { publicKeyToAddress } from "@nearh/owner-near/src/derive.ts";
import { eip191Digest, paypalMessage, type Near, type Payee, type Reservation, type Signature } from "@nearh/rails-paypal/src/payout.ts";
import { refundMessage } from "@nearh/rails-paypal/src/refund.ts";
import { checkoutMessage } from "@nearh/rails-paypal/src/vault.ts";

/** As the contract's `RailMandate` for the PayPal rail: USD cents as decimal strings (U128 JSON). */
export type PaypalRail = { amount_range: { min: string; max: string }; budget: string; period_secs: number };
export type MockMandate = { paypal: PaypalRail; paypal_refund?: PaypalRail; max_validity_secs: number };
export type PaypalRequest = { payee: string; amount: string; timestamp: number };
export type CheckoutRequest = PaypalRequest & { order_ref: string };
export type RefundRequest = { capture_id: string; amount: string };
export type SignOutcome = { ok: true; signature: Signature; text: string; valid_before: number } | { ok: false; error: string };

/** As the contract: CLOCK_SKEW_SECS. */
const CLOCK_SKEW_SECS = 30;
const AMOUNT = /^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/;

/** As `normalize_receiver`: ASCII trim and ASCII lowercase only. */
export const normalizeReceiver = (p: string) => p.replace(/^[ \t\n\f\r]+|[ \t\n\f\r]+$/g, "").replace(/[A-Z]/g, (c) => c.toLowerCase());
const cents = (usd: string) => BigInt(usd.replace(".", ""));
/** USD cents as `12.34`. */
export const usd = (c: bigint | string) => {
  const n = BigInt(c);
  return `${n / 100n}.${String(n % 100n).padStart(2, "0")}`;
};

export class MockMandateContract {
  readonly agent: string;
  readonly evmAddress: string;
  private readonly key: Uint8Array;
  private mandate: MockMandate | null = null;
  private payees: Payee[] = [];
  private revoked = false;
  /** Reserved USD cents per rail: shapes 4 and 5 share `paypal`, shape 6 has `paypal_refund`. */
  private readonly spent = { paypal: 0n, paypal_refund: 0n };
  private readonly requests = new Map<string, Reservation>();

  constructor(agent: string, now: () => number) {
    this.agent = agent;
    this.now = now;
    this.key = secp256k1.utils.randomSecretKey();
    this.evmAddress = publicKeyToAddress(secp256k1.getPublicKey(this.key, false));
  }
  private readonly now: () => number;

  /** Owner-side (passkey on testnet): `set_mandate` + `add_payee`. Never reachable from the agent tools. */
  ownerSetMandate(mandate: MockMandate, paypalPayees: string[]): void {
    this.mandate = mandate;
    this.payees = paypalPayees.map((p) => ({ rail: "paypal", receiver: normalizeReceiver(p) }));
  }

  ownerRevoke(): void {
    this.revoked = true;
  }

  getMandate(): MockMandate | null {
    return this.mandate;
  }

  getPayees(): Payee[] {
    return this.payees;
  }

  budgetLeft(): string {
    return usd(BigInt(this.mandate?.paypal.budget ?? "0") - this.spent.paypal);
  }

  /** Agent-side `request_signature` with a `paypal_checkout` shape (shape 5): shape 4's checks plus `order_ref`. */
  requestCheckout(request_id: string, req: CheckoutRequest): SignOutcome {
    const early = this.precheck(request_id);
    if (early) return early;
    const m = this.mandate!;
    const payee = normalizeReceiver(req.payee);
    if (!this.payees.some((p) => p.rail === "paypal" && p.receiver === payee)) return { ok: false, error: "ERR_PAYPAL_PAYEE_NOT_ALLOWED" };
    if (!/^[A-Za-z0-9._:-]{1,64}$/.test(req.order_ref)) return { ok: false, error: "ERR_INVALID_ORDER_REF" };
    return this.sign(request_id, "paypal_checkout", "paypal", m.paypal, req.amount, req.timestamp, () =>
      checkoutMessage(req.amount, payee, req.order_ref, req.timestamp, request_id));
  }

  /** Agent-side `request_signature` with a `refund` shape (shape 6): the refund rail's cap and budget, no payee. */
  requestRefund(request_id: string, req: RefundRequest): SignOutcome {
    const early = this.precheck(request_id);
    if (early) return early;
    const rail = this.mandate!.paypal_refund;
    if (!rail) return { ok: false, error: "ERR_SHAPE_NOT_ALLOWED" };
    if (!/^[A-Z0-9]{10,32}$/.test(req.capture_id)) return { ok: false, error: "ERR_INVALID_CAPTURE_ID" };
    // No timestamp in the message: the window starts now, as `build_refund`.
    return this.sign(request_id, "refund", "paypal_refund", rail, req.amount, this.now(), () =>
      refundMessage(req.amount, req.capture_id, request_id));
  }

  private precheck(request_id: string): SignOutcome | null {
    const fail = (error: string): SignOutcome => ({ ok: false, error });
    if (this.revoked) return fail("ERR_AGENT_REVOKED");
    if (!/^[A-Za-z0-9._:-]{1,64}$/.test(request_id)) return fail("ERR_INVALID_REQUEST_ID");
    if (this.requests.has(request_id)) return fail("ERR_DUPLICATE_REQUEST_ID");
    if (!this.mandate) return fail("ERR_NO_MANDATE");
    return null;
  }

  /** Amount, window and budget checks, then the signature and the `signed` reservation. */
  private sign(request_id: string, shape: string, railName: "paypal" | "paypal_refund", rail: PaypalRail, amountUsd: string, timestamp: number, text: () => string): SignOutcome {
    const fail = (error: string): SignOutcome => ({ ok: false, error });
    const m = this.mandate!;
    if (!AMOUNT.test(amountUsd)) return fail("ERR_INVALID_AMOUNT");
    const amount = cents(amountUsd);
    if (amount < BigInt(rail.amount_range.min)) return fail("ERR_BELOW_MINIMUM");
    if (amount > BigInt(rail.amount_range.max)) return fail("ERR_OVER_PER_PAYMENT_CAP");
    const lifetime = m.max_validity_secs - CLOCK_SKEW_SECS;
    const now = this.now();
    if (timestamp < now - lifetime) return fail("ERR_TIMESTAMP_STALE");
    if (timestamp > now + CLOCK_SKEW_SECS) return fail("ERR_TIMESTAMP_FUTURE");
    if (this.spent[railName] + amount > BigInt(rail.budget)) return fail("ERR_OVER_BUDGET");

    const message = text();
    const digest = eip191Digest(message);
    const sig = secp256k1.sign(digest, this.key, { prehash: false, format: "recovered" });
    const signature = { r: `0x${bytesToHex(sig.slice(1, 33))}`, s: `0x${bytesToHex(sig.slice(33))}`, v: 27 + sig[0] };
    const valid_before = timestamp + lifetime;
    this.spent[railName] += amount;
    this.requests.set(request_id, {
      key: { agent: this.agent, caller: { kind: "agent" }, request_id },
      shape,
      rail: railName,
      valid_before,
      digest: `0x${bytesToHex(digest)}`,
      payload: { kind: "message", text: message },
      status: "signed",
      signature,
    });
    return { ok: true, signature, text: message, valid_before };
  }

  /** Agent-side `request_signature` with a `paypal` shape. Errors are the contract's `ERR_*` codes. */
  requestSignature(request_id: string, req: PaypalRequest): SignOutcome {
    const early = this.precheck(request_id);
    if (early) return early;
    const payee = normalizeReceiver(req.payee);
    if (!this.payees.some((p) => p.rail === "paypal" && p.receiver === payee)) return { ok: false, error: "ERR_PAYPAL_PAYEE_NOT_ALLOWED" };
    return this.sign(request_id, "paypal", "paypal", this.mandate!.paypal, req.amount, req.timestamp, () =>
      paypalMessage(req.amount, payee, req.timestamp, request_id));
  }

  /** The contract views rails/paypal reads (`get_agent`, `get_request`, `get_payees`, `get_suspended_payees`). */
  views(): Near {
    return {
      getAgent: async (agent) => (agent === this.agent ? { evm_address: this.evmAddress, revoked: this.revoked } : null),
      getRequest: async (key) => (key.agent === this.agent ? (this.requests.get(key.request_id) ?? null) : null),
      getPayees: async (agent) => (agent === this.agent ? this.payees : []),
      // PP-W1 settlement feedback is not part of the mock demo: nothing is ever suspended.
      getSuspendedPayees: async () => [],
    };
  }
}
