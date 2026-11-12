import { randomUUID } from 'node:crypto';
import { nearX402Fetch, SettlementWindowError, type NearX402Signer, type X402Shape } from '@nearh/agent-signer';
import { decodePaymentResponseHeader } from '@x402/fetch';
import { readLimitedText } from '@x402/core/http';
import { checkAndHold, readHeldQueue, type CheckParams, type CheckResult, type HeldItem } from 'scamcheck';
import { canonicalAmount, euroUnits, sellerUrl, x402Input, sepaInput, receiptInput, paypalInput, paypalPayee, maskEmail, maskEmails } from './policy.ts';
import { ReceiptStore, type PaymentResult, type Receipt } from './store.ts';

export type PayoutInput = { agent: string; request_id: string; iban: string; amount: string; memo: string };
/** PP3's PaypalOrder (rails/paypal/src/payout.ts): shape 4's fields plus the contract's MPC signature. */
export type PaypalOrder = { agent: string; request_id: string; payee: string; amount: string; timestamp: number; order_ref?: string; signature: { r: string; s: string; v: number } };
type PaypalShape = { type: 'paypal' | 'paypal_checkout'; payee: string; amount: string; timestamp: number; order_ref?: string };
export type HeldDecision = Omit<HeldItem, 'status' | 'decided_at'> & { status: 'held' | 'approved' | 'rejected'; decided_at: string | null; decided_nonce?: number; assertion?: { owner_nonce: number; expires_at: number; authenticator_data: string; client_data_json: string; signature: string } };
export type Dependencies = {
  signer: NearX402Signer;
  store: ReceiptStore;
  allowedOrigins: string[];
  view(method: string, args: object): Promise<unknown>;
  call(method: 'request_signature' | 'revoke_self', args: object): Promise<{ hash: string; value: unknown }>;
  submit(input: PayoutInput): Promise<Record<string, unknown>>;
  /**
   * PP3's `POST /payouts` client; resolving it checks the rail configuration before anything is
   * signed. Called at most once per request; the PayPal credentials stay in PP3.
   */
  paypalRail?: (mode?: 'payout' | 'checkout') => (order: PaypalOrder) => Promise<Record<string, unknown>>;
  balance(rail: 'x402' | 'sepa'): Promise<bigint>;
  fetch?: typeof fetch;
  check?: (params: CheckParams) => Promise<CheckResult>;
  readHeld?: () => Promise<HeldDecision[]>;
  secrets?: string[];
  verifySettlement(receipt: Receipt, hash: string): Promise<boolean>;
  verifyDecision(item: HeldDecision): Promise<void>;
  notifyOwner?: (message: string) => void;
};
class HeldPayment extends Error {}
class LowFloat extends Error {}
const equalShape = (a: Record<string, unknown>, b: Record<string, unknown>) =>
  Object.keys(a).length === Object.keys(b).length && Object.entries(a).every(([key, value]) => b[key] === value);
const requestId = () => `pay-${randomUUID()}`;
const PAYOUT_BATCH_ID = /^[A-Z0-9]{8,30}$/;
const rfc3339 = (secs: number) => new Date(secs * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
/** The shape 4 text, as `paypal_message` in contract/src/shapes/paypal.rs. */
export const paypalMessage = (amount: string, payee: string, timestamp: number, id: string) => `Send USD ${amount} to ${payee} at ${rfc3339(timestamp)} ref ${id}`;
/** The shape 5 text, as `checkout_message` in contract/src/shapes/paypal_checkout.rs. */
export const checkoutMessage = (amount: string, payee: string, orderRef: string, timestamp: number, id: string) =>
  `Charge USD ${amount} to merchant ${payee} for order ${orderRef} at ${rfc3339(timestamp)} ref ${id}`;
const shapeMessage = (shape: PaypalShape, id: string) => shape.type === 'paypal_checkout'
  ? checkoutMessage(shape.amount, shape.payee, String(shape.order_ref), shape.timestamp, id)
  : paypalMessage(shape.amount, shape.payee, shape.timestamp, id);
/** PP3 answers meaning this order (or request_id) was submitted before, so a payout may exist. */
const PAYOUT_MAY_EXIST = new Set(['PAYPAL_DUPLICATE_BATCH', 'PP3_DUPLICATE_REQUEST']);
const TOOL = { x402: 'pay_x402', sepa: 'pay_sepa', paypal: 'pay_paypal' } as const;
const object = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid service response');
  return value as Record<string, unknown>;
};

export function safeDetail(error: unknown, secrets: string[] = []): string {
  let text = error instanceof Error ? error.message : String(error);
  for (const secret of secrets) if (secret) text = text.split(secret).join('<REDACTED>');
  return text.replace(/[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}/g, iban => `IBAN …${iban.slice(-4)}`).slice(0, 1000);
}

export class Buyer {
  private readonly deps: Dependencies;
  private revoked = false;
  private readonly running = new Set<string>();
  constructor(deps: Dependencies) { this.deps = deps; }

  /** Removes secrets and IBANs; `emails` also masks email addresses (PayPal outputs only, where the payee is one). */
  redact(text: string, { emails = false }: { emails?: boolean } = {}): string {
    let result = text;
    for (const secret of this.deps.secrets ?? []) if (secret) result = result.split(secret).join('<REDACTED>');
    result = result.replace(/[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}/g, iban => `IBAN …${iban.slice(-4)}`);
    return emails ? maskEmails(result) : result;
  }

  private save(id: string, fields: Partial<Receipt>): Receipt {
    const previous = this.deps.store.get(id);
    if (!previous) throw new Error('Receipt not found');
    const receipt = { ...previous, ...fields };
    this.deps.store.put(receipt);
    return receipt;
  }
  private begin(rail: 'x402' | 'sepa' | 'paypal', args: Record<string, unknown>): string {
    if (this.revoked) throw new Error('ERR_AGENT_REVOKED: this agent revoked itself');
    const id = requestId();
    this.deps.store.put({ request_id: id, agent: this.deps.signer.agent, rail, status: 'pending', created_at: new Date().toISOString(), signing_started: false, operation: { tool: TOOL[rail], args } });
    return id;
  }
  private fail(id: string, error: unknown): PaymentResult {
    const receipt = this.deps.store.get(id);
    const detail = safeDetail(error, this.deps.secrets);
    if (receipt?.outcome === 'paid') {
      const delivery = `Payment settled; resource delivery failed: ${detail}`;
      this.save(id, { detail: delivery });
      return { status: 'paid', request_id: id, amount: receipt.amount, pay_to: receipt.payee, tx_hash: receipt.tx_hash, scam_check: receipt.scam_check, detail: delivery };
    }
    const code = /\bERR_[A-Z0-9_]+\b/.exec(detail)?.[0];
    const held = error instanceof HeldPayment || receipt?.status === 'held';
    const lowFloat = error instanceof LowFloat || receipt?.error_code === 'LOW_FLOAT';
    const uncertain = !held && !code && !lowFloat && receipt?.signing_started === true;
    const status = held ? 'held' : code || lowFloat ? 'blocked' : uncertain ? 'pending' : 'failed';
    const error_code = held ? undefined : code ?? (lowFloat ? 'LOW_FLOAT' : 'PAYMENT_ERROR');
    this.save(id, { status: held ? 'held' : status === 'blocked' ? 'blocked' : receipt?.status === 'signed' ? 'signed' : uncertain ? 'unknown' : 'blocked', outcome: status, error_code, detail });
    return { status, request_id: id, tx_hash: receipt?.tx_hash, error_code, detail, scam_check: receipt?.scam_check };
  }

  private async guard(id: string, shape: Record<string, unknown>, invoice: string, source: string, approved = false, memo?: string): Promise<void> {
    const receipt = this.deps.store.get(id);
    if (!receipt) throw new Error('Receipt not found');
    const payee = String(shape.payTo ?? shape.iban ?? shape.payee);
    if (approved) {
      if (!receipt.shape || !equalShape(shape, receipt.shape)) throw new Error('Approved payment requirements changed; request a new payment');
    } else {
      this.save(id, { shape, payee, amount: String(shape.amount) });
      const payees = await this.deps.view('get_payees', { agent: this.deps.signer.agent });
      if (!Array.isArray(payees)) throw new Error('Invalid contract payee response');
      const known = payees.some(value => {
        const p = object(value);
        if (receipt.rail === 'paypal') return p.rail === 'paypal' && p.receiver === payee;
        return receipt.rail === 'x402' ? p.rail === 'x402' && String(p.pay_to).toLowerCase() === payee.toLowerCase() : p.rail === 'sepa' && p.iban === payee;
      });
      const history = this.deps.store.all().filter(r => r.agent === receipt.agent && r.rail === receipt.rail && r.payee && r.amount && ['paid', 'submitted'].includes(r.outcome ?? '') && (r.completed_at || r.created_at));
      const result = await (this.deps.check ?? checkAndHold)({
        agent: receipt.agent, request_id: id, rail: receipt.rail, shape, memo,
        invoice: { text: invoice, source }, payee_known: known,
        payee_history: history.map(r => ({ payee: r.payee!, amounts: [r.amount!], last_seen: (r.completed_at ?? r.created_at)! })),
      });
      this.save(id, { scam_check: result.verdict.result });
      if (result.status === 'held') {
        this.save(id, { status: 'held', held_id: result.item?.id });
        throw new HeldPayment(result.verdict.reason ?? 'Scam check timed out; held for owner');
      }
      if (result.status !== 'approved' && result.status !== 'skipped') throw new Error('Invalid scam check response');
      // Without a NEAR AI key SC1 skips even its deterministic rules; a PayPal payout never goes unchecked.
      if (receipt.rail === 'paypal' && result.status !== 'approved') throw new Error('ERR_SCAM_CHECK_UNAVAILABLE: the scam check did not run (set NEAR_AI_API_KEY); nothing was signed');
    }
    if (receipt.rail === 'paypal') {
      // The PayPal float is the rail's PayPal balance, not an agent EOA token; PP3 and PayPal refuse an overdraft.
      this.save(id, { status: 'pending' });
      return;
    }
    const balance = await this.deps.balance(receipt.rail);
    const amount = receipt.rail === 'sepa' ? euroUnits(String(shape.amount)) : BigInt(String(shape.amount));
    if (balance < amount) {
      this.save(id, { status: 'blocked', error_code: 'LOW_FLOAT' });
      this.deps.notifyOwner?.(`Owner notice: LOW_FLOAT for agent ${receipt.agent} on ${receipt.rail}; owner Safe top-up required`);
      throw new LowFloat('Low float: owner must top up from the Safe; the agent cannot top up');
    }
    // Persist before signing: an interrupted call must never become an automatic retry.
    this.save(id, { status: 'pending' });
  }

  async payX402(input: unknown): Promise<PaymentResult> {
    const args = x402Input.parse(input);
    sellerUrl(args.url, this.deps.allowedOrigins);
    const id = this.begin('x402', args);
    return this.executeX402(id, args);
  }
  private async executeX402(id: string, args: ReturnType<typeof x402Input.parse>, approved = false): Promise<PaymentResult> {
    let signed = false;
    const signer = this.deps.signer;
    // The SDK's scheme keeps its domain and payload checks; the guard sits immediately before A1 signs.
    const guarded = new Proxy(signer, { get: (target, property, receiver) => property === 'signX402' ? async (shape: X402Shape) => {
      if (signed) throw new Error('One signature per payment operation');
      if (new URL(shape.resourceUrl).href !== new URL(args.url).href) throw new Error('Seller resource URL differs from the requested URL');
      await this.guard(id, { type: 'x402', ...shape }, args.reason, args.url, approved);
      signed = true;
      this.save(id, { signing_started: true });
      let result;
      try {
        result = await target.signX402(shape, id);
      } catch (error) {
        if (error instanceof SettlementWindowError && error.code === 'window-too-short') this.save(id, { signing_started: false });
        throw error;
      }
      this.save(id, { status: 'signed', reservation: result.reservation as unknown as Record<string, unknown>, near_tx_hash: result.txHash });
      return result;
    } : Reflect.get(target, property, receiver) });
    try {
      const response = await nearX402Fetch(guarded, this.deps.fetch)(sellerUrl(args.url, this.deps.allowedOrigins), {
        method: args.method, body: args.method === 'POST' ? args.body : undefined,
        redirect: 'error', signal: AbortSignal.timeout(180_000),
      });
      const header = response.headers.get('payment-response');
      if (!signed || !header) throw new Error('No verified payment settlement response; inspect the receipt before retrying');
      const settlement = decodePaymentResponseHeader(header);
      if (!settlement.success || settlement.network !== 'eip155:84532' || !/^0x[0-9a-f]{64}$/i.test(settlement.transaction)) {
        throw new Error('Facilitator did not report a successful Base Sepolia settlement');
      }
      const claimed = this.save(id, { outcome: 'pending', tx_hash: settlement.transaction });
      let confirmed = false;
      let detail = 'Claimed settlement is not confirmed by matching USDC logs on Base Sepolia';
      try { confirmed = await this.deps.verifySettlement(claimed, settlement.transaction); }
      catch (error) { detail = `Settlement confirmation unavailable: ${safeDetail(error, this.deps.secrets)}`; }
      if (!confirmed) {
        // Keep the bounded resource privately so a delayed chain receipt does not require repurchase.
        this.save(id, { resource_status: response.status });
        let body;
        try { body = await readLimitedText(response, 64_000); }
        catch (error) {
          this.save(id, { resource_error: safeDetail(error, this.deps.secrets) });
          throw error;
        }
        this.save(id, { response: body, detail });
        return { status: 'pending', request_id: id, tx_hash: settlement.transaction, detail: `${detail}; inspect get_receipt for confirmation and the saved resource` };
      }
      const receipt = this.save(id, { outcome: 'paid', completed_at: new Date().toISOString() });
      const body = await readLimitedText(response, 64_000);
      return { status: 'paid', request_id: id, amount: receipt.amount, pay_to: receipt.payee, tx_hash: settlement.transaction, response: body, scam_check: receipt.scam_check, ...(response.ok ? {} : { detail: `Payment settled, resource returned HTTP ${response.status}` }) };
    } catch (error) { return this.fail(id, error); }
  }

  async paySepa(input: unknown): Promise<PaymentResult> {
    const raw = sepaInput.parse(input);
    const args = { ...raw, amount: canonicalAmount(raw.amount) };
    const id = this.begin('sepa', args);
    const shape = { type: 'payout', iban: args.iban, amount: args.amount, timestamp: Math.floor(Date.now() / 1000) };
    this.save(id, { shape, payee: args.iban, amount: args.amount });
    return this.executeSepa(id, args, shape);
  }
  private async executeSepa(id: string, args: ReturnType<typeof sepaInput.parse>, shape: Record<string, unknown>, approved = false): Promise<PaymentResult> {
    try {
      await this.guard(id, shape, [args.invoice, args.reason].filter(Boolean).join('\n'), 'agent invoice', approved, args.memo);
      this.save(id, { signing_started: true });
      const signed = await this.deps.call('request_signature', { request_id: id, shape });
      const reservation = object(signed.value);
      this.save(id, { near_tx_hash: signed.hash, reservation });
      if (reservation.shape !== 'payout' || reservation.status !== 'signed' || !reservation.signature) throw new Error('Payout is not signed; M1 was not called');
      this.save(id, { status: 'signed' });
      // M1 reads and verifies the signature from get_request; no Monerium credentials cross this boundary.
      const result = await this.deps.submit({ agent: this.deps.signer.agent, request_id: id, iban: args.iban, amount: args.amount, memo: args.memo });
      if (result.request_id !== id || !['submitted', 'blocked', 'failed', 'pending'].includes(String(result.status))) throw new Error('Invalid M1 payout response');
      if (result.status === 'submitted' && typeof result.monerium_order_id !== 'string') throw new Error('M1 omitted the accepted order id');
      const answer = result as PaymentResult;
      this.save(id, { outcome: answer.status, ...(answer.status === 'submitted' ? { completed_at: new Date().toISOString() } : {}), monerium_order_id: answer.monerium_order_id, error_code: answer.error_code, detail: answer.detail });
      return { ...answer, scam_check: this.deps.store.get(id)?.scam_check };
    } catch (error) { return this.fail(id, error); }
  }

  /**
   * Pays a supplier's PayPal invoice only via shape 4: SC1 first, then the contract builds and
   * MPC-signs the payout order, then PP3 verifies it and submits it once. `paid` only on PP3's
   * accepted batch for this request_id.
   */
  async payPaypal(input: unknown): Promise<PaymentResult> {
    const args = paypalInput.parse(input);
    if (!this.deps.paypalRail) throw new Error('PayPal rail (PP3) is not configured');
    const invoice = args.invoice.invoice_id;
    // One live payment per invoice: a held, signed, uncertain or paid one is never paid again here.
    const open = this.deps.store.all().find(r => r.agent === this.deps.signer.agent && r.rail === 'paypal' && r.invoice_id === invoice && r.status !== 'blocked' && !['blocked', 'failed'].includes(r.outcome ?? ''));
    if (open) {
      return { status: 'blocked', request_id: open.request_id, error_code: 'DUPLICATE_INVOICE', detail: `Invoice ${invoice} already has payment ${open.request_id} (${open.outcome ?? open.status}); inspect get_receipt, nothing was submitted` };
    }
    const id = this.begin('paypal', args);
    const payee = paypalPayee(args.invoice.payee);
    const timestamp = Math.floor(Date.now() / 1000);
    // Checkout: the invoice id is the merchant order reference the contract signs (it fits [A-Za-z0-9._:-]{1,64}).
    const shape: PaypalShape = args.mode === 'checkout'
      ? { type: 'paypal_checkout', payee, amount: args.invoice.amount.value, order_ref: invoice, timestamp }
      : { type: 'paypal', payee, amount: args.invoice.amount.value, timestamp };
    this.save(id, { shape, payee, amount: shape.amount, invoice_id: invoice });
    return this.executePaypal(id, args, shape);
  }
  private async executePaypal(id: string, args: ReturnType<typeof paypalInput.parse>, shape: PaypalShape, approved = false): Promise<PaymentResult> {
    const inv = args.invoice;
    const base = { request_id: id, amount: shape.amount, pay_to: maskEmail(shape.payee) };
    try {
      const submit = this.deps.paypalRail!(shape.type === 'paypal_checkout' ? 'checkout' : 'payout');
      const text = [inv.description, `Pay to: ${inv.payee}`, `Amount: USD ${inv.amount.value}`, `Due: ${inv.due_date}`, args.reason].filter(Boolean).join('\n');
      await this.guard(id, shape, text, `paypal-invoice:${inv.invoice_id}`, approved, `PayPal invoice ${inv.invoice_number}`);
      this.save(id, { signing_started: true });
      const signed = await this.deps.call('request_signature', { request_id: id, shape });
      const reservation = object(signed.value);
      this.save(id, { near_tx_hash: signed.hash, reservation });
      const signature = reservation.signature as PaypalOrder['signature'] | null | undefined;
      const payload = reservation.payload as { text?: unknown } | undefined;
      if (reservation.shape !== shape.type || reservation.status !== 'signed' || !signature || typeof signature.r !== 'string' || typeof signature.s !== 'string' || typeof signature.v !== 'number'
        || payload?.text !== shapeMessage(shape, id)) {
        throw new Error('PayPal order is not signed as requested; PP3 was not called');
      }
      this.save(id, { status: 'signed' });
      const result = await submit({ agent: this.deps.signer.agent, request_id: id, payee: shape.payee, amount: shape.amount, timestamp: shape.timestamp, ...(shape.order_ref ? { order_ref: shape.order_ref } : {}), signature: { r: signature.r, s: signature.s, v: signature.v } });
      if (result.request_id !== id || !['submitted', 'blocked', 'failed', 'pending'].includes(String(result.status))) throw new Error('Invalid PP3 payout response');
      const code = typeof result.error_code === 'string' ? result.error_code : undefined;
      const detail = typeof result.detail === 'string' ? maskEmails(result.detail).slice(0, 1000) : undefined;
      const batch = typeof result.payout_batch_id === 'string' && PAYOUT_BATCH_ID.test(result.payout_batch_id) ? result.payout_batch_id : undefined;
      const batch_status = typeof result.batch_status === 'string' ? result.batch_status.slice(0, 40) : undefined;
      // Paid only on the rail's own record: an accepted batch id for this request_id, not DENIED.
      // A duplicate answer or any batch id means a payout for this order may already exist: uncertain, the invoice stays open.
      // Checkout: a capture id means the owner's wallet was charged, whatever happened to the payout.
      const capture = typeof result.capture_id === 'string' && /^[A-Za-z0-9-]{6,64}$/.test(result.capture_id) ? result.capture_id : undefined;
      const maybePaid = (code !== undefined && PAYOUT_MAY_EXIST.has(code)) || result.payout_batch_id !== undefined || capture !== undefined;
      const status: PaymentResult['status'] = result.status === 'submitted'
        ? (batch && batch_status !== 'DENIED' ? 'paid' : 'uncertain')
        : result.status === 'pending' || maybePaid ? 'uncertain' : result.status as 'blocked' | 'failed';
      const why = status === 'uncertain' && result.status === 'submitted' ? 'PP3 reported submitted without an accepted payout batch id; inspect its order log'
        : status === 'uncertain' && maybePaid ? `PP3 answered ${result.status}${code ? ` ${code}` : ''} but a payout for this order may already exist; inspect its order log${detail ? `: ${detail}` : ''}` : detail;
      this.save(id, { outcome: status, payout_batch_id: batch, batch_status, error_code: code, detail: why, ...(capture ? { capture_id: capture } : {}), ...(status === 'paid' ? { completed_at: new Date().toISOString() } : {}) });
      return { status, ...base, ...(batch ? { payout_batch_id: batch } : {}), ...(capture ? { capture_id: capture } : {}), ...(code ? { error_code: code } : {}), ...(why ? { detail: why } : {}), scam_check: this.deps.store.get(id)?.scam_check };
    } catch (error) {
      const failed = this.fail(id, error);
      if (failed.status !== 'pending') return { ...failed, ...base };
      // Signing or the PP3 hand-off started and its outcome is unknown: never retried automatically.
      this.save(id, { outcome: 'uncertain' });
      return { ...failed, ...base, status: 'uncertain' };
    }
  }

  async revoke(): Promise<{ revoked: boolean; key_deleted?: boolean; tx_hash: string }> {
    const outcome = await this.deps.call('revoke_self', {});
    const value = object(outcome.value);
    if (value.agent !== this.deps.signer.agent || typeof value.revoked !== 'boolean' || typeof value.key_deleted !== 'boolean') throw new Error('Invalid RevokeResult; check get_agent state');
    this.revoked = value.revoked;
    return { revoked: value.revoked, key_deleted: value.key_deleted, tx_hash: outcome.hash };
  }

  async getReceipt(id: string): Promise<Receipt> {
    receiptInput.parse({ request_id: id });
    const local = this.deps.store.get(id);
    if (local && local.agent !== this.deps.signer.agent) throw new Error('Receipt belongs to another agent');
    if (local?.status === 'held' || local?.status === 'blocked') return this.publicReceipt(local);
    const reservation = await this.deps.view('get_request', { key: { agent: this.deps.signer.agent, caller: { kind: 'agent' }, request_id: id } });
    if (reservation) {
      const r = object(reservation);
      const statuses = ['pending', 'signed', 'unknown', 'spent', 'released', 'revoked'];
      if (!statuses.includes(String(r.status))) throw new Error('Invalid reservation status');
      const latest = this.deps.store.get(id);
      // A concurrent payment completion wins over the view started before it.
      if (latest && latest.status !== local?.status) return this.publicReceipt(latest);
      const rail = r.shape === 'paypal' || r.shape === 'paypal_checkout' || r.rail === 'paypal' ? 'paypal' as const : r.shape === 'payout' || r.rail === 'sepa' ? 'sepa' as const : 'x402' as const;
      const receipt = { ...(latest ?? { request_id: id, agent: this.deps.signer.agent, rail }), status: r.status as Receipt['status'], reservation: r };
      this.deps.store.put(receipt);
      return this.publicReceipt(await this.refreshSettlement(receipt));
    }
    if (!local) throw new Error('Receipt not found');
    return this.publicReceipt(await this.refreshSettlement(local));
  }
  private async refreshSettlement(receipt: Receipt): Promise<Receipt> {
    if (receipt.rail !== 'x402' || receipt.outcome !== 'pending' || !receipt.tx_hash) return receipt;
    try {
      if (await this.deps.verifySettlement(receipt, receipt.tx_hash)) {
        const latest = this.deps.store.get(receipt.request_id) ?? receipt;
        const detail = latest.resource_error ? `Payment settled; resource delivery failed: ${latest.resource_error}`
          : latest.resource_status !== undefined && (latest.resource_status < 200 || latest.resource_status >= 300)
            ? `Payment settled, resource returned HTTP ${latest.resource_status}` : undefined;
        return this.save(receipt.request_id, { outcome: 'paid', completed_at: new Date().toISOString(), error_code: undefined, detail });
      }
      return receipt;
    } catch (error) {
      return this.save(receipt.request_id, { detail: `Settlement confirmation unavailable: ${safeDetail(error, this.deps.secrets)}` });
    }
  }
  private publicReceipt(receipt: Receipt): Receipt {
    const { operation, shape, response, ...result } = receipt;
    if (operation && !['pay_x402', 'pay_sepa', 'pay_paypal'].includes(operation.tool)) throw new Error('Invalid stored operation');
    if (shape && !['x402', 'payout', 'paypal', 'paypal_checkout'].includes(String(shape.type))) throw new Error('Invalid stored shape');
    if (result.rail === 'paypal' && result.payee) result.payee = maskEmail(result.payee);
    return result.outcome === 'paid' && response !== undefined ? { ...result, response } : result;
  }

  /** Only resume known locally held requests after verifying the owner's decision. */
  async processDecisions(): Promise<void> {
    const decisions = await (this.deps.readHeld ?? readHeldQueue)() as HeldDecision[];
    const nonce = (id: string) => decisions.find(item => item.request_id === id)?.decided_nonce ?? 0;
    const receipts = this.deps.store.all().filter(r => r.agent === this.deps.signer.agent && r.status === 'held').sort((a, b) => nonce(a.request_id) - nonce(b.request_id));
    for (const receipt of receipts) {
      if (this.running.has(receipt.request_id)) continue;
      const item = decisions.find(d => d.agent === receipt.agent && d.request_id === receipt.request_id);
      if (!item || item.status === 'held') continue;
      this.running.add(receipt.request_id);
      try {
        if (!receipt.held_id || item.id !== receipt.held_id || !item.decided_at || !receipt.shape || !equalShape(item.shape, receipt.shape)) throw new Error('Held decision does not match the saved payment');
        await this.deps.verifyDecision(item);
        if (item.status === 'rejected') {
          this.save(receipt.request_id, { status: 'blocked', outcome: 'blocked', decision_nonce: item.decided_nonce, detail: 'Owner rejected held request' });
          continue;
        }
        if (item.status !== 'approved') throw new Error('Invalid held decision');
        this.save(receipt.request_id, { status: 'pending', outcome: 'pending', decision_nonce: item.decided_nonce });
        const op = receipt.operation;
        let executionId = receipt.request_id;
        let result: PaymentResult;
        if (op?.tool === 'pay_x402') result = await this.executeX402(executionId, x402Input.parse(op.args), true);
        else if (op?.tool === 'pay_sepa') {
          // Lead decision (task 23): approval creates a fresh reservation; never replay the held ID.
          const args = sepaInput.parse(op.args);
          executionId = this.begin('sepa', args);
          const shape = { ...receipt.shape, timestamp: Math.floor(Date.now() / 1000) };
          this.save(executionId, { shape, payee: receipt.payee, amount: receipt.amount, scam_check: receipt.scam_check, held_id: receipt.held_id, decision_nonce: item.decided_nonce, approved_from_request_id: receipt.request_id });
          // Consume and link the original before requesting any signature, including on interruption.
          this.save(receipt.request_id, { status: 'blocked', outcome: 'blocked', replacement_request_id: executionId, detail: 'Owner approval created a fresh payout reservation; inspect replacement_request_id' });
          result = await this.executeSepa(executionId, args, shape, true);
        } else if (op?.tool === 'pay_paypal') {
          // As SEPA: a fresh request id and timestamp, same payee and amount; the held id is never replayed.
          const args = paypalInput.parse(op.args);
          executionId = this.begin('paypal', args);
          const checkout = receipt.shape.type === 'paypal_checkout';
          const shape: PaypalShape = {
            type: checkout ? 'paypal_checkout' : 'paypal', payee: String(receipt.shape.payee), amount: String(receipt.shape.amount),
            ...(checkout ? { order_ref: String(receipt.shape.order_ref) } : {}), timestamp: Math.floor(Date.now() / 1000),
          };
          this.save(executionId, { shape, payee: receipt.payee, amount: receipt.amount, invoice_id: receipt.invoice_id, scam_check: receipt.scam_check, held_id: receipt.held_id, decision_nonce: item.decided_nonce, approved_from_request_id: receipt.request_id });
          this.save(receipt.request_id, { status: 'blocked', outcome: 'blocked', replacement_request_id: executionId, detail: 'Owner approval created a fresh PayPal payout reservation; inspect replacement_request_id' });
          result = await this.executePaypal(executionId, args, shape, true);
        } else throw new Error('Held request has no saved payment operation');
        if (result.request_id !== executionId) throw new Error('Held payment returned a different request id');
      } catch (error) {
        const detail = safeDetail(error, this.deps.secrets);
        this.save(receipt.request_id, { status: 'blocked', outcome: 'blocked', error_code: 'OWNER_APPROVAL_INVALID', detail });
        this.deps.notifyOwner?.(`Held request ${receipt.request_id} blocked: ${detail}`);
      } finally { this.running.delete(receipt.request_id); }
    }
  }
}
