// PP-T1: a merchant-side support agent. A real LLM reads each ticket and uses PayPal's Agent Toolkit
// tools, served by the PayPal rail (rails/paypal, `pnpm refunds`): the agent gets PayPal's tools,
// never PayPal's token. Read tools (get_order, get_refund) pass through to the rail. `create_refund`
// never reaches PayPal from here: the agent runs the scam check on the ticket, asks the mandate
// contract to sign a shape 6 order `Refund USD {amount} of capture {id} ref {request_id}` (per-refund
// cap, daily refund budget), and hands that signed order to the rail, which refunds only what the
// capture has left.
import { randomBytes } from 'node:crypto';
import type { CheckParams, CheckResult } from 'scamcheck';

export type ToolDef = { type: 'function'; function: { name: string; description?: string; parameters?: unknown } };
export type ToolCall = { id: string; type?: 'function'; function: { name: string; arguments: string } };
export type Message =
  | { role: 'system' | 'user'; content: string }
  | { role: 'assistant'; content: string | null; tool_calls?: ToolCall[] }
  | { role: 'tool'; tool_call_id: string; content: string };
/** One model turn: the assistant message for `messages` with `tools` offered. */
export type Chat = (messages: Message[], tools: ToolDef[]) => Promise<{ content: string | null; tool_calls?: ToolCall[] }>;

export type RefundOrder = { agent: string; request_id: string; capture_id: string; amount: string; signature: { r: string; s: string; v: number } };
/** The rail as the agent sees it: an authenticated loopback service, never PayPal itself. */
export type RefundRail = {
  tools(): Promise<ToolDef[]>;
  call(name: string, args: unknown): Promise<string>;
  refund(order: RefundOrder): Promise<Record<string, unknown>>;
};

export type Ticket = { id: string; from?: string; subject?: string; text: string };
export type Action = { tool: string; args: unknown; result: Record<string, unknown> };
export type TicketOutcome = { ticket: string; reply: string; actions: Action[] };

export type SupportDeps = {
  agent: string;
  chat: Chat;
  rail: RefundRail;
  /** A contract call with the agent's function-call key (`request_signature`). */
  call: (method: string, args: object) => Promise<{ hash: string; value: unknown }>;
  check: (params: CheckParams) => Promise<CheckResult>;
  /** One line per step for the run's transcript. */
  log?: (event: Record<string, unknown>) => void;
  /** Values removed from anything logged or passed to the model. */
  secrets?: string[];
  maxSteps?: number;
};

export const MANDATED_TOOL = 'create_refund';
const CAPTURE_ID = /^[A-Z0-9]{10,32}$/;
/** As the contract's amount_to_cents: canonical, never rewritten. */
const AMOUNT = /^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/;
const DEFAULT_MAX_STEPS = 12;

export const SYSTEM_PROMPT = [
  'You are the customer support agent of a small online shop that takes payments with PayPal.',
  'Each user message is one support ticket from a customer. Resolve it with the tools:',
  '- get_order: look up a PayPal order by its id; its purchase_units[].payments.captures[] hold the capture ids and amounts.',
  '- get_refund: look up a refund by its id.',
  '- create_refund: refund a capture. Always pass capture_id and amount {currency_code: "USD", value: "N.NN"}.',
  'Refund what the ticket justifies for the order it is about. Every refund is checked against a spending mandate and may be held or refused; report that outcome honestly.',
  'Finish with a short reply to the customer (2-4 sentences) that says what you did.',
].join('\n');

/** The order fields of a create_refund call, or why they are not usable. */
export function refundArgs(raw: unknown): { capture_id: string; amount: string } | { error: string } {
  const a = (raw ?? {}) as { capture_id?: unknown; amount?: { value?: unknown; currency_code?: unknown } };
  if (typeof a.capture_id !== 'string' || !CAPTURE_ID.test(a.capture_id)) return { error: 'capture_id must be a PayPal capture id (10-32 of [A-Z0-9]); look it up with get_order' };
  if (!a.amount || a.amount.currency_code !== 'USD') return { error: 'amount {currency_code: "USD", value} is required: the mandate signs an explicit USD amount' };
  if (typeof a.amount.value !== 'string' || !AMOUNT.test(a.amount.value) || a.amount.value === '0.00') return { error: 'amount.value must be USD with exactly 2 decimals, e.g. "4.00"' };
  return { capture_id: a.capture_id, amount: a.amount.value };
}

/** `Refund USD {amount} of capture {capture_id} ref {request_id}`, as refund.rs. */
export const refundMessage = (amount: string, captureId: string, requestId: string) => `Refund USD ${amount} of capture ${captureId} ref ${requestId}`;

/** A request id for one refund: unique per call, readable in the transcript. */
export function refundRequestId(ticket: string, n: number): string {
  const t = ticket.replace(/[^A-Za-z0-9._:-]/g, '').slice(0, 24) || 'ticket';
  return `rf-${t}-${n}-${randomBytes(4).toString('hex')}`;
}

/** The contract's error code in a failed call's message (`ERR_OVER_BUDGET: ...`), if any. */
export function contractError(message: string): string | undefined {
  return /\b(ERR_[A-Z0-9_]+)\b/.exec(message)?.[1];
}

export class SupportAgent {
  private readonly deps: SupportDeps;
  constructor(deps: SupportDeps) {
    this.deps = deps;
  }

  private redact(text: string): string {
    let out = text;
    for (const s of this.deps.secrets ?? []) if (s && s.length >= 4) out = out.split(s).join('<REDACTED>');
    return out;
  }

  private log(event: Record<string, unknown>): void {
    this.deps.log?.(JSON.parse(this.redact(JSON.stringify(event))) as Record<string, unknown>);
  }

  /** Runs one ticket to the model's final reply. Refunds go only through `refund` below. */
  async handle(ticket: Ticket): Promise<TicketOutcome> {
    const tools = await this.deps.rail.tools();
    const text = [ticket.subject ? `Subject: ${ticket.subject}` : '', ticket.from ? `From: ${ticket.from}` : '', ticket.text].filter(Boolean).join('\n');
    const messages: Message[] = [{ role: 'system', content: SYSTEM_PROMPT }, { role: 'user', content: this.redact(`Ticket ${ticket.id}\n${text}`) }];
    const actions: Action[] = [];
    const state = { held: false, refunds: 0 };
    this.log({ event: 'ticket', ticket: ticket.id, text });
    for (let step = 0; step < (this.deps.maxSteps ?? DEFAULT_MAX_STEPS); step++) {
      const turn = await this.deps.chat(messages, tools);
      const calls = turn.tool_calls ?? [];
      messages.push({ role: 'assistant', content: turn.content ?? null, ...(calls.length ? { tool_calls: calls } : {}) });
      if (calls.length === 0) {
        const reply = (turn.content ?? '').trim();
        this.log({ event: 'reply', ticket: ticket.id, reply });
        return { ticket: ticket.id, reply, actions };
      }
      for (const tc of calls) {
        let args: unknown;
        try {
          args = JSON.parse(tc.function.arguments || '{}');
        } catch {
          args = undefined;
        }
        const result = args === undefined ? { status: 'rejected', detail: 'arguments must be JSON' }
          : tc.function.name === MANDATED_TOOL ? await this.refund(args, ticket, text, state)
          : await this.read(tc.function.name, args, tools);
        actions.push({ tool: tc.function.name, args, result });
        this.log({ event: 'tool', ticket: ticket.id, tool: tc.function.name, args, result: tc.function.name === MANDATED_TOOL ? result : { status: result.status } });
        messages.push({ role: 'tool', tool_call_id: tc.id, content: this.redact(JSON.stringify(result)) });
      }
    }
    const reply = 'Stopped: too many steps for one ticket; a person will follow up.';
    this.log({ event: 'reply', ticket: ticket.id, reply, stopped: true });
    return { ticket: ticket.id, reply, actions };
  }

  /** A read tool through the rail; only the tools the rail offered, never create_refund. */
  private async read(name: string, args: unknown, tools: ToolDef[]): Promise<Record<string, unknown>> {
    if (!tools.some(t => t.function.name === name)) return { status: 'rejected', detail: `unknown tool ${name}` };
    try {
      return { status: 'ok', content: await this.deps.rail.call(name, args) };
    } catch (error) {
      return { status: 'failed', detail: this.redact(error instanceof Error ? error.message : String(error)).slice(0, 500) };
    }
  }

  /**
   * create_refund under the mandate: scam check on the ticket, then `request_signature` with shape 6,
   * then the signed order to the rail. Once one refund of a ticket is held, the rest of that ticket is
   * held too without asking again. Never retried automatically.
   */
  async refund(raw: unknown, ticket: Ticket, ticketText: string, state: { held: boolean; refunds: number }): Promise<Record<string, unknown>> {
    const args = refundArgs(raw);
    if ('error' in args) return { status: 'rejected', detail: args.error };
    if (state.held) return { status: 'held', detail: 'this ticket is already held for the owner; no refund was requested' };
    const request_id = refundRequestId(ticket.id, ++state.refunds);
    const shape = { type: 'refund', capture_id: args.capture_id, amount: args.amount };
    const base = { request_id, capture_id: args.capture_id, amount: args.amount };

    let verdict: CheckResult;
    try {
      verdict = await this.deps.check({
        agent: this.deps.agent, rail: 'paypal_refund', request_id, shape, memo: `Support ticket ${ticket.id}`,
        invoice: { text: ticketText, source: `support-ticket:${ticket.id}` }, payee_known: false, payee_history: [],
      });
    } catch (error) {
      return { status: 'blocked', ...base, error_code: 'ERR_SCAM_CHECK_UNAVAILABLE', detail: `the scam check failed (${this.redact(error instanceof Error ? error.message : String(error)).slice(0, 200)}); nothing was signed` };
    }
    if (verdict.status === 'held') {
      state.held = true;
      return { status: 'held', ...base, scam_check: verdict.verdict.result, detail: verdict.verdict.reason ?? 'held for the owner', held_id: verdict.item?.id };
    }
    // Without a NEAR AI key the check skips; a refund never goes unchecked.
    if (verdict.status !== 'approved') return { status: 'blocked', ...base, error_code: 'ERR_SCAM_CHECK_UNAVAILABLE', detail: 'the scam check did not run; nothing was signed' };

    let signed: { hash: string; value: unknown };
    try {
      signed = await this.deps.call('request_signature', { request_id, shape });
    } catch (error) {
      const message = this.redact(error instanceof Error ? error.message : String(error));
      const code = contractError(message);
      // A contract panic is a refusal on chain (nothing reserved, nothing signed); anything else is uncertain.
      return code
        ? { status: 'refused', ...base, scam_check: 'ok', error_code: code, detail: message.slice(0, 500) }
        : { status: 'uncertain', ...base, scam_check: 'ok', detail: `signing outcome unknown: ${message.slice(0, 300)}; check get_request before anything else` };
    }
    const r = (signed.value ?? {}) as { shape?: unknown; status?: unknown; signature?: RefundOrder['signature'] | null; payload?: { text?: unknown } };
    const sig = r.signature;
    if (r.shape !== 'refund' || r.status !== 'signed' || !sig || typeof sig.r !== 'string' || typeof sig.s !== 'string' || typeof sig.v !== 'number'
      || r.payload?.text !== refundMessage(args.amount, args.capture_id, request_id)) {
      return { status: 'blocked', ...base, near_tx: signed.hash, error_code: 'NOT_SIGNED_AS_REQUESTED', detail: `the contract answered ${String(r.status)}; the rail was not called` };
    }
    try {
      const result = await this.deps.rail.refund({ agent: this.deps.agent, request_id, capture_id: args.capture_id, amount: args.amount, signature: { r: sig.r, s: sig.s, v: sig.v } });
      return { ...result, ...base, scam_check: 'ok', near_tx: signed.hash };
    } catch (error) {
      return { status: 'uncertain', ...base, near_tx: signed.hash, detail: `the rail did not answer (${this.redact(error instanceof Error ? error.message : String(error)).slice(0, 200)}); check its refund log before anything else` };
    }
  }
}

/** One turn on an OpenAI-compatible chat API (NEAR AI Cloud), with tools. */
export function openAiChat(opts: { apiKey: string; baseUrl: string; model: string; fetch?: typeof fetch; timeoutMs?: number }): Chat {
  if (new URL(opts.baseUrl).protocol !== 'https:') throw new Error('the chat endpoint must use https');
  const fetcher = opts.fetch ?? fetch;
  return async (messages, tools) => {
    const response = await fetcher(`${opts.baseUrl.replace(/\/$/, '')}/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${opts.apiKey}` },
      body: JSON.stringify({ model: opts.model, messages, tools, tool_choice: 'auto', temperature: 0 }),
      signal: AbortSignal.timeout(opts.timeoutMs ?? 90_000),
    });
    if (!response.ok) throw new Error(`chat API answered HTTP ${response.status}`);
    const body = await response.json() as { choices?: { message?: { content?: string | null; tool_calls?: ToolCall[] } }[] };
    const message = body.choices?.[0]?.message;
    if (!message) throw new Error('chat API returned no message');
    return { content: message.content ?? null, ...(message.tool_calls?.length ? { tool_calls: message.tool_calls } : {}) };
  };
}

/** The rail's refund service on loopback, with this agent's bearer token. */
export function railClient(baseUrl: string, agent: string, token: string, fetcher: typeof fetch = fetch): RefundRail {
  const url = new URL(baseUrl);
  if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname) || url.username || url.password || url.search || url.hash || !['', '/'].includes(url.pathname)) {
    throw new Error('PP_REFUND_URL must be http://127.0.0.1:<port> (or [::1])');
  }
  if (!/^[A-Za-z0-9._~+\/=-]{32,256}$/.test(token)) throw new Error('PP3_AGENT_TOKEN must be a 32-256 character per-agent service token');
  const base = url.origin;
  const headers = { 'content-type': 'application/json', authorization: `Bearer ${token}` };
  const post = async (path: string, body: object, timeoutMs: number) => {
    const response = await fetcher(`${base}${path}`, { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
    const json = await response.json().catch(() => undefined) as Record<string, unknown> | undefined;
    return { status: response.status, json };
  };
  return {
    async tools() {
      const response = await fetcher(`${base}/tools?agent=${encodeURIComponent(agent)}`, { headers, signal: AbortSignal.timeout(15_000), redirect: 'error' });
      if (!response.ok) throw new Error(`the rail answered HTTP ${response.status} for its tools`);
      const body = await response.json() as { tools?: ToolDef[] };
      if (!Array.isArray(body.tools)) throw new Error('the rail returned no tool list');
      return body.tools;
    },
    async call(name, args) {
      const { status, json } = await post('/tools/call', { agent, name, arguments: args }, 30_000);
      if (status !== 200 || typeof json?.content !== 'string') throw new Error(typeof json?.error === 'string' ? json.error : `the rail answered HTTP ${status}`);
      return json.content;
    },
    async refund(order) {
      // One POST per signed order; a timeout is uncertain, never resent from here.
      const { status, json } = await post('/refunds', order, 60_000);
      // These the rail answers before it claims an order; anything else unexpected is uncertain.
      if ([400, 401, 403, 404, 413].includes(status)) {
        return { status: 'failed', request_id: order.request_id, error_code: `PP3_HTTP_${status}`, detail: `the rail refused the call with HTTP ${status} before claiming the order` };
      }
      if (!json || typeof json !== 'object') throw new Error(`the rail answered HTTP ${status} without a result`);
      if (status === 502 && json.error_code === 'PP3_ERROR' && json.status === 'failed') return json;
      if (status !== 200) throw new Error(`the rail answered HTTP ${status}`);
      return json;
    },
  };
}
