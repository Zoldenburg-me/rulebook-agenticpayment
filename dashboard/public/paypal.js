// Shape 4 (PayPal payout) helpers for the USD view; used by the page and by serve.mjs.

/**
 * An email as rails/paypal's maskEmail (src/payout.ts) masks it: `su…@example.com`, at most 2
 * characters of the local part. A Venmo handle keeps its first 2 characters: `@de…`.
 */
export function maskPayee(email) {
  const s = String(email ?? "");
  const at = s.lastIndexOf("@");
  if (at < 0) return "…";
  if (at === 0) return `@${s.slice(1, 3)}…`;
  return `${s.slice(0, Math.min(2, at))}…${s.slice(at)}`;
}

/** USD cents (the contract's paypal base units) as `12.50 USD`. */
export function formatUsd(cents) {
  const v = BigInt(cents);
  return `${v / 100n}.${(v % 100n).toString().padStart(2, "0")} USD`;
}

const MESSAGE = /^Send USD (\S+) to (\S+) at (\S+) ref (.+)$/;

/** The fields of shape 4's signed text, `Send USD {amount} to {payee} at {RFC3339} ref {request_id}`; null if it is not one. */
export function parsePaypalText(text) {
  const m = MESSAGE.exec(text ?? "");
  return m ? { amount: m[1], payee: m[2], at: m[3], request_id: m[4] } : null;
}
