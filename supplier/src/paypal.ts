// Minimal PayPal sandbox client for the demo supplier: OAuth client credentials, then JSON calls.
// The supplier is a separate party from our PayPal rail (rails/paypal), so it has its own client.
// The base URL is fixed to the sandbox. The client id, secret and bearer token are never returned,
// logged or put in an error message: errors carry only the HTTP status, PayPal's error name and
// debug id, and pass through `scrub` as well.

export const SANDBOX_BASE = "https://api-m.sandbox.paypal.com";
export const TIMEOUT_MS = 30_000;

export type Fetch = typeof fetch;
export type Credentials = Record<string, string | undefined>;
export type Answer = { ok: boolean; status: number; debugId: string | null; body: any };
export type Client = {
  request(method: string, path: string, body?: unknown, headers?: Record<string, string>): Promise<Answer>;
  /** Removes the credentials and the token from a string. */
  scrub(text: string): string;
};

export class PaypalError extends Error {
  readonly status: number;
  readonly debugId: string | null;
  constructor(message: string, status: number, debugId: string | null) {
    super(message);
    this.name = "PaypalError";
    this.status = status;
    this.debugId = debugId;
  }
}

/** Throws unless the credentials are for the sandbox and complete. */
export function assertSandbox(creds: Credentials): { id: string; secret: string } {
  if (creds.PAYPAL_ENV !== "sandbox") throw new Error("PAYPAL_ENV must be 'sandbox' in the PayPal credentials file");
  const id = creds.PAYPAL_CLIENT_ID;
  const secret = creds.PAYPAL_CLIENT_SECRET;
  if (!id || !secret) throw new Error("PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET must be set in the PayPal credentials file");
  return { id, secret };
}

/** A secret-free error for a non-2xx answer: status, PayPal's error `name`, issue codes, debug id. */
export function answerError(what: string, a: Answer, scrub: (s: string) => string): PaypalError {
  // Only code-shaped values: REST's upper-case `name`, OAuth's lower-case `error` (`invalid_client`).
  // Free text (`message`, `description`) may echo input.
  const rawName = a.body?.name ?? a.body?.error;
  const name = typeof rawName === "string" && /^([A-Z0-9_]{1,64}|[a-z0-9_]{1,64})$/.test(rawName) ? `, ${rawName}` : "";
  const issues = Array.isArray(a.body?.details)
    ? a.body.details.map((d: any) => d?.issue).filter((i: unknown): i is string => typeof i === "string" && /^[A-Z0-9_]{1,64}$/.test(i))
    : [];
  const issue = issues.length ? ` [${issues.join(", ")}]` : "";
  const debug = a.debugId ? `, debug id ${a.debugId}` : "";
  return new PaypalError(scrub(`${what} failed (HTTP ${a.status}${name}${issue}${debug})`), a.status, a.debugId);
}

const TOKEN_MARGIN_SECS = 300;

export function sandboxClient(creds: Credentials, fetcher: Fetch = fetch): Client {
  const { id, secret } = assertSandbox(creds);
  // Refreshed TOKEN_MARGIN_SECS before PayPal's expires_in, as PP3's client (PayPal audit 1 M2).
  let token: { value: string; expiresAt: number } | undefined;
  const issued: string[] = [];

  const scrub = (text: string) => {
    let out = text;
    for (const s of [id, secret, ...issued]) if (s) out = out.split(s).join("<REDACTED>");
    return out.replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/g, "$1 <REDACTED>");
  };

  async function call(method: string, path: string, headers: Record<string, string>, body?: string): Promise<Answer> {
    let res: Response;
    try {
      res = await fetcher(SANDBOX_BASE + path, {
        method,
        headers: { Accept: "application/json", ...headers },
        body,
        redirect: "error",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch {
      // The underlying error may echo headers; never pass it on.
      throw new PaypalError(`PayPal ${method} ${path.split("?")[0]}: no answer from the sandbox`, 0, null);
    }
    let text: string;
    try {
      text = await res.text();
    } catch {
      // A timeout or reset while reading the body; same treatment as a failed request.
      throw new PaypalError(`PayPal ${method} ${path.split("?")[0]}: answer cut off (HTTP ${res.status})`, res.status, res.headers.get("paypal-debug-id"));
    }
    let json: any;
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      json = { raw: scrub(text.slice(0, 500)) };
    }
    return { ok: res.ok, status: res.status, debugId: res.headers.get("paypal-debug-id"), body: json };
  }

  async function authenticate(): Promise<string> {
    if (token && Date.now() < token.expiresAt) return token.value;
    const a = await call(
      "POST",
      "/v1/oauth2/token",
      {
        Authorization: "Basic " + Buffer.from(`${id}:${secret}`).toString("base64"),
        "Content-Type": "application/x-www-form-urlencoded",
      },
      "grant_type=client_credentials",
    );
    const value = a.body?.access_token;
    if (a.status !== 200 || typeof value !== "string" || !value) throw answerError("PayPal authentication", a, scrub);
    issued.push(value);
    const ttl = Number(a.body.expires_in) || 0;
    token = { value, expiresAt: Date.now() + Math.max(0, ttl - TOKEN_MARGIN_SECS) * 1000 };
    return value;
  }

  return {
    scrub,
    async request(method, path, body, headers = {}) {
      const bearer = await authenticate();
      return call(
        method,
        path,
        { Authorization: `Bearer ${bearer}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
        body === undefined ? undefined : JSON.stringify(body),
      );
    },
  };
}
