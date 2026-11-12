// M1: the `pay_sepa` backend. It takes a payout the contract signed (shape 3), re-checks it against
// the contract's own record, and POSTs it to the Monerium sandbox as a redeem order, at most once
// per (agent, request_id). It trusts nothing the agent passes beyond the key and what it asked for:
// - the reservation is read from `get_request`, must be a `signed` payout, and must not be past
//   `valid_before` (a `released` reservation is never submitted, docs/interfaces.md §4);
// - the signed text must be exactly `Send EUR {amount} to {iban} at {ts}` for the agent's IBAN and
//   amount, its digest must match, and the signature must recover to the agent EOA;
// - the IBAN must be on the agent's SEPA payees (`get_payees`) at submission time.
// Any failed check returns `blocked` before Monerium is called. IBANs are redacted (last 4 kept) in
// every detail; the Monerium token and secret stay inside O2's sandbox client.

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { publicKeyToAddress } from "@nearh/owner-near/src/derive.ts";
import { CHAIN, refusal, redactIbans, type Client } from "@nearh/owner-monerium/src/monerium.ts";
import type { OrderRecord, Store } from "./store.ts";

export type Signature = { r: string; s: string; v: number };
export type RequestKey = { agent: string; caller: { kind: "agent" }; request_id: string };
export type Reservation = {
  key: RequestKey;
  shape: string;
  rail: string | null;
  valid_before: number;
  digest: string;
  payload: { kind: string; text?: string };
  status: string;
  signature: Signature | null;
};
export type Agent = { evm_address: string | null; revoked: boolean };
export type Payee = { rail: "sepa"; iban: string } | { rail: "x402"; pay_to: string };

/** The contract views M1 reads; the CLI wires them to NEAR RPC. */
export type Near = {
  getAgent(agent: string): Promise<Agent | null>;
  getRequest(key: RequestKey): Promise<Reservation | null>;
  getPayees(agent: string): Promise<Payee[]>;
};

/** What A2 hands over after `request_signature` returned a signed payout. */
export type PayoutInput = { agent: string; request_id: string; iban: string; amount: string; memo: string };

/** `pay_sepa`'s output shape (docs/interfaces.md §8). */
export type PayoutResult =
  | { status: "submitted"; request_id: string; monerium_order_id: string }
  | { status: "blocked" | "failed" | "pending"; request_id: string; error_code: string; detail: string };

export type Deps = {
  near: Near;
  monerium: Client;
  store: Store;
  /** Unix seconds. */
  now?: () => number;
  log?: (line: string) => void;
  /** Credential values to scrub from anything Monerium sends back (client id and secret). */
  secrets?: string[];
  /** Counterpart name on the order. Monerium requires one; the signed text does not contain it. */
  counterpart?: { firstName: string; lastName: string };
};

export const AGENT_ID = /^[A-Za-z0-9._:-]{1,64}$/;
const IBAN = /^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/;
const AMOUNT = /^[0-9]+(\.[0-9]{1,2})?$/;
const SIGNED_TEXT = /^Send EUR ([0-9]+(?:\.[0-9]{1,2})?) to ([A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}) at (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)$/;
const ORDER_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Monerium's refusal of a resubmitted signed order (S-b): HTTP 400 with this message; `code` is just the status. */
export const DUPLICATE_ORDER_MESSAGE = "Duplicate order";
/**
 * Seconds a signed order must still have left when M1 claims it: O2's 30 s POST timeout, so the
 * order cannot land after `valid_before` (which already has CLOCK_SKEW_SECS taken off). An order
 * closer to `valid_before` is refused unclaimed (M1_ORDER_EXPIRED).
 */
export const SUBMIT_MARGIN_SECS = 30;

/** D9 canonical amount, as `contract/src/shapes/payout.rs` `canonical_amount`; undefined if invalid or zero. */
export function canonicalAmount(amount: string): string | undefined {
  if (!AMOUNT.test(amount)) return undefined;
  const [int, frac = ""] = amount.split(".");
  const i = int.replace(/^0+/, "");
  const f = frac.replace(/0+$/, "");
  if (!i && !f) return undefined;
  return f ? `${i || "0"}.${f}` : i || "0";
}

/** EIP-191 personal_sign hash of `text`. */
export function eip191Digest(text: string): Uint8Array {
  const m = utf8ToBytes(text);
  return keccak_256(concatBytes(utf8ToBytes(`\x19Ethereum Signed Message:\n${m.length}`), m));
}

/** `0x r || s || v` if `sig` over `digest` recovers to `address`, else undefined. */
export function orderSignature(sig: Signature, digest: Uint8Array, address: string): string | undefined {
  const word = (hex: unknown) => {
    const h = typeof hex === "string" ? hex.replace(/^0x/, "").toLowerCase() : "";
    return /^[0-9a-f]{1,64}$/.test(h) ? h.padStart(64, "0") : undefined;
  };
  const r = word(sig?.r);
  const s = word(sig?.s);
  if (!r || !s || (sig.v !== 27 && sig.v !== 28)) return undefined;
  try {
    const pub = secp256k1.recoverPublicKey(hexToBytes(`0${sig.v - 27}${r}${s}`), digest, { prehash: false });
    const from = publicKeyToAddress(secp256k1.Point.fromBytes(pub).toBytes(false));
    return from === address.toLowerCase() ? `0x${r}${s}${sig.v.toString(16)}` : undefined;
  } catch {
    return undefined;
  }
}

const last4 = (iban: string) => iban.slice(-4);

/**
 * For text that came from Monerium or a thrown error: IBANs redacted (O2), then the given secret
 * values, then anything token-like (20+ chars of token alphabet holding a letter and a digit), so a
 * refusal that echoes the client secret or the bearer token cannot carry it out. Fails closed.
 */
export function scrub(text: string, secrets: (string | undefined)[] = []): string {
  let out = redactIbans(text);
  for (const s of secrets) if (s && s.length >= 4) out = out.split(s).join("<REDACTED>");
  return out.replace(/[A-Za-z0-9._~+\/=-]{20,}/g, (m) => (/[0-9]/.test(m) && /[A-Za-z]/.test(m) ? "<REDACTED>" : m));
}

export async function submitPayout(deps: Deps, input: PayoutInput): Promise<PayoutResult> {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const log = (line: string) => deps.log?.(redactIbans(line));
  const request_id = typeof input?.request_id === "string" ? input.request_id : "";
  const blocked = (error_code: string, detail: string): PayoutResult => {
    // An invalid request_id is caller text: it never goes into a log line.
    log(`blocked ${AGENT_ID.test(request_id) ? request_id : "<invalid request_id>"}: ${error_code}`);
    return { status: "blocked", request_id, error_code, detail: redactIbans(detail) };
  };

  // 1. Shape of the hand-over.
  const { agent, iban, amount, memo } = input ?? ({} as PayoutInput);
  if (typeof agent !== "string" || !AGENT_ID.test(agent)) return blocked("M1_INVALID_INPUT", "agent must be 1-64 chars of [A-Za-z0-9._:-]");
  if (!AGENT_ID.test(request_id)) return blocked("M1_INVALID_INPUT", "request_id must be 1-64 chars of [A-Za-z0-9._:-]");
  if (typeof iban !== "string" || !IBAN.test(iban)) return blocked("M1_INVALID_INPUT", "iban must be uppercase without spaces");
  const canonical = typeof amount === "string" ? canonicalAmount(amount) : undefined;
  if (!canonical) return blocked("M1_INVALID_INPUT", "amount must be decimal euros with at most 2 decimals, above zero");
  if (typeof memo !== "string" || memo.length > 140) return blocked("M1_INVALID_INPUT", "memo must be a string of at most 140 characters");

  // 2. At most once per request_id: a known request never reaches NEAR or Monerium again.
  const seen = deps.store.get(agent, request_id);
  if (seen) {
    return blocked(
      "M1_DUPLICATE_REQUEST",
      `request ${request_id} was already handed to M1 (${seen.state}${seen.monerium_order_id ? `, order ${seen.monerium_order_id}` : ""}); not submitted again`,
    );
  }

  // 3. The contract's record of the order.
  const record = await deps.near.getAgent(agent);
  if (!record) return blocked("M1_UNKNOWN_AGENT", `no agent ${agent} on the contract`);
  if (record.revoked) return blocked("M1_AGENT_REVOKED", `agent ${agent} is revoked`);
  if (!record.evm_address || !/^0x[0-9a-f]{40}$/i.test(record.evm_address)) return blocked("M1_UNKNOWN_AGENT", `agent ${agent} has no evm_address`);
  const res = await deps.near.getRequest({ agent, caller: { kind: "agent" }, request_id });
  if (!res) return blocked("M1_REQUEST_NOT_FOUND", `no agent request ${request_id} for ${agent}`);
  if (res.shape !== "payout" || res.rail !== "sepa" || res.payload?.kind !== "message" || typeof res.payload.text !== "string") {
    return blocked("M1_NOT_A_PAYOUT", `request ${request_id} is not a payout`);
  }
  if (res.status !== "signed" || !res.signature) return blocked("M1_NOT_SIGNED", `request ${request_id} is ${res.status}, not signed`);
  const m = SIGNED_TEXT.exec(res.payload.text);
  if (!m) return blocked("M1_ORDER_MISMATCH", "the signed text is not a payout order");
  const [, signedAmount, signedIban, signedAt] = m;
  if (signedIban !== iban) return blocked("M1_ORDER_MISMATCH", `IBAN ${iban} is not the IBAN the contract signed`);
  if (signedAmount !== canonical) return blocked("M1_ORDER_MISMATCH", `amount ${canonical} is not the amount the contract signed`);
  const digest = eip191Digest(res.payload.text);
  if (res.digest?.toLowerCase() !== `0x${bytesToHex(digest)}`) return blocked("M1_BAD_SIGNATURE", "the reservation digest is not the hash of its text");
  const signature = orderSignature(res.signature, digest, record.evm_address);
  if (!signature) return blocked("M1_BAD_SIGNATURE", "the signature does not recover to the agent EOA");
  if (now() > res.valid_before) return blocked("M1_ORDER_EXPIRED", `request ${request_id} expired at ${res.valid_before}`);

  // 4. The allowed set as it stands now (a payee removed after signing is refused).
  const payees = await deps.near.getPayees(agent);
  if (!payees.some((p) => p.rail === "sepa" && p.iban === signedIban)) {
    return blocked("M1_IBAN_NOT_ALLOWED", `IBAN ${signedIban} is not on ${agent}'s SEPA payees`);
  }

  // 5. Authenticate first, so an auth failure leaves the request unclaimed and retryable.
  try {
    await deps.monerium.authenticate();
  } catch (e: any) {
    throw new Error(scrub(String(e?.message ?? e), deps.secrets));
  }
  // Re-checked after the network round-trips above: a signature that expired (or will before the
  // POST lands) is refused before the claim, so it does not use up its request_id.
  if (now() + SUBMIT_MARGIN_SECS > res.valid_before) {
    return blocked("M1_ORDER_EXPIRED", `request ${request_id} expires at ${res.valid_before}, too close to submit`);
  }
  const base: OrderRecord = { agent, request_id, state: "submitting", iban_last4: last4(signedIban), amount: signedAmount, at: new Date(now() * 1000).toISOString() };
  if (!deps.store.claim(base)) return blocked("M1_DUPLICATE_REQUEST", `request ${request_id} is already being submitted; not submitted again`);
  // The claim already blocks any resubmission, so a failed update must not turn an accepted order
  // into an error: the result (with the order id) still goes back, and the log names the order id
  // so the record, left as `submitting`, can be fixed by hand (README, "Recovery").
  const finish = (r: Partial<OrderRecord>) => {
    try {
      deps.store.update({ ...base, ...r });
    } catch (e: any) {
      const id = r.monerium_order_id ? `order ${r.monerium_order_id}` : "no order id";
      log(`record-failed ${request_id}: outcome ${r.state}, ${id}; the store update failed (${scrub(String(e?.message ?? e), deps.secrets).slice(0, 200)}), record left as submitting`);
    }
  };

  const { firstName, lastName } = deps.counterpart ?? { firstName: "Test", lastName: "Recipient" };
  const body = {
    address: record.evm_address.toLowerCase(),
    chain: CHAIN,
    kind: "redeem",
    currency: "eur",
    amount: signedAmount,
    counterpart: { identifier: { standard: "iban", iban: signedIban }, details: { firstName, lastName, country: signedIban.slice(0, 2) } },
    message: res.payload.text,
    signature,
    memo,
  };
  log(`submitting ${request_id}: EUR ${signedAmount} to IBAN …${last4(signedIban)} signed at ${signedAt}`);
  let answer;
  try {
    answer = await deps.monerium.request("POST", "/orders", body);
  } catch (e: any) {
    const detail = scrub(String(e?.message ?? e), deps.secrets);
    finish({ state: "unknown", detail });
    return { status: "pending", request_id, error_code: "MONERIUM_OUTCOME_UNKNOWN", detail };
  }

  if (answer.ok) {
    const id = answer.body?.id;
    if (typeof id === "string" && ORDER_ID.test(id) && answer.body.state !== "rejected") {
      finish({ state: "submitted", monerium_order_id: id, monerium_state: String(answer.body.state ?? ""), http_status: answer.status });
      log(`submitted ${request_id}: order ${id}`);
      return { status: "submitted", request_id, monerium_order_id: id };
    }
    const detail = `Monerium answered HTTP ${answer.status} without an accepted order id; check the sandbox orders before anything else`;
    finish({ state: "unknown", http_status: answer.status, detail });
    return { status: "pending", request_id, error_code: "MONERIUM_OUTCOME_UNKNOWN", detail };
  }

  const why = refusal(answer.body);
  if (answer.status === 400 && typeof answer.body?.message === "string" && answer.body.message.trim() === DUPLICATE_ORDER_MESSAGE) {
    const detail = "Monerium refused the order as a duplicate (HTTP 400, Duplicate order): this signed order was submitted before";
    finish({ state: "duplicate_order", http_status: 400, detail });
    return { status: "failed", request_id, error_code: "MONERIUM_DUPLICATE_ORDER", detail };
  }
  const detail = scrub(`Monerium refused the order (HTTP ${answer.status}${why.message ? `, ${why.message}` : ""})`, deps.secrets);
  if (answer.status >= 500) {
    finish({ state: "unknown", http_status: answer.status, detail });
    return { status: "pending", request_id, error_code: "MONERIUM_OUTCOME_UNKNOWN", detail };
  }
  finish({ state: "refused", http_status: answer.status, detail });
  return { status: "failed", request_id, error_code: "MONERIUM_REFUSED", detail };
}
