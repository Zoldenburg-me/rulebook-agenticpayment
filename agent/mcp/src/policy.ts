import { z } from 'zod';

export const x402Input = z.object({
  url: z.string().url(), method: z.enum(['GET', 'POST']).default('GET'),
  body: z.string().max(64_000).optional(), reason: z.string().min(1).max(16_000),
}).strict();
export const sepaInput = z.object({
  iban: z.string().regex(/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/),
  amount: z.string().max(40).regex(/^[0-9]+(\.[0-9]{1,2})?$/),
  memo: z.string().max(140), invoice: z.string().max(16_000).optional(),
  reason: z.string().min(1).max(16_000),
}).strict();
/** A supplier invoice in supplier/'s buyer view (`BuyerInvoice`). Untrusted: the scam check and the contract decide. */
export const paypalInvoice = z.object({
  invoice_id: z.string().regex(/^INV2(-[A-Z0-9]{4}){4}$/),
  invoice_number: z.string().max(127),
  status: z.enum(['SENT', 'UNPAID']),
  amount: z.object({
    currency: z.literal('USD'),
    // As the contract's amount_to_cents and PP3: canonical, never rewritten.
    value: z.string().regex(/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/).refine(value => value !== '0.00', 'Amount must be greater than zero'),
  }),
  payee: z.string().min(3).max(254),
  due_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  description: z.string().max(4000),
  payer_view_url: z.string().max(2048).nullable().optional(),
});
/**
 * `payout` (default): shape 4, the rail pays the supplier from its PayPal balance.
 * `checkout` (PP-V1): shape 5, the rail charges the owner's vaulted PayPal wallet, then pays the supplier.
 */
export const paypalMode = z.enum(['payout', 'checkout']);
export const paypalInput = z.object({ invoice: paypalInvoice, reason: z.string().max(16_000).optional(), mode: paypalMode.optional() }).strict();
export const receiptInput = z.object({ request_id: z.string().regex(/^[A-Za-z0-9._:-]{1,64}$/) }).strict();
export const revokeInput = z.object({}).strict();

export function canonicalAmount(amount: string): string {
  const [whole, fraction = ''] = amount.split('.');
  const integer = whole.replace(/^0+/, '') || '0';
  const decimal = fraction.replace(/0+$/, '');
  const result = decimal ? `${integer}.${decimal}` : integer;
  if (result === '0') throw new Error('Amount must be greater than zero');
  return result;
}
export function euroUnits(amount: string): bigint {
  const [whole, fraction = ''] = amount.split('.');
  return BigInt(whole) * 10n ** 18n + BigInt(fraction.padEnd(18, '0'));
}

/** Only operator-configured origins; redirects must not move a paid request elsewhere. */
export function sellerUrl(raw: string, origins: string[]): string {
  const url = new URL(raw);
  if (url.username || url.password || url.hash || !origins.includes(url.origin)) throw new Error('Seller origin is not allowed');
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname))) {
    throw new Error('Seller requires HTTPS or loopback HTTP');
  }
  return url.href;
}

/** As the contract's normalize_receiver: ASCII whitespace trimmed, ASCII letters lowercased, nothing else folded. */
export function paypalPayee(raw: string): string {
  return raw.replace(/^[ \t\n\f\r]+|[ \t\n\f\r]+$/g, '').replace(/[A-Z]/g, c => c.toLowerCase());
}
/** `su…@example.com`: as PP3's maskEmail. */
export function maskEmail(email: string): string {
  const at = email.lastIndexOf('@');
  if (at < 0) return '…';
  return at === 0 ? `@${email.slice(1, 3)}…` : `${email.slice(0, Math.min(2, at))}…${email.slice(at)}`;
}
export const maskEmails = (text: string) => text.replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, maskEmail);
