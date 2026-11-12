// PayPal sandbox client for PP3: OAuth client credentials and JSON calls to the Payouts API
// (calls as in spikes/paypal/payouts.mjs). The base URL is fixed to the sandbox, so the
// credentials and the bearer token only ever go to api-m.sandbox.paypal.com. Neither is ever
// returned, logged or put in an error message.

export const SANDBOX_BASE = "https://api-m.sandbox.paypal.com";
/** Per-call timeout; a POST that times out is an unknown outcome, never retried. */
export const TIMEOUT_MS = 30_000;
/** Renew the token this long before PayPal's `expires_in`. */
const TOKEN_MARGIN_SECS = 300;

export type Fetch = typeof fetch;
export type Answer = { ok: boolean; status: number; debugId: string | null; body: any };
export type Client = {
  /** Gets (or reuses) a bearer token. Throws a secret-free error if PayPal refuses. */
  authenticate(): Promise<void>;
  /** One JSON call with the bearer token; a string body is sent as is (already JSON). Throws only if the call never got an answer. */
  request(method: string, path: string, body?: unknown, headers?: Record<string, string>): Promise<Answer>;
};

export type Credentials = Record<string, string | undefined>;

/** Throws unless the credentials are for the sandbox and complete. */
export function assertSandbox(creds: Credentials): { id: string; secret: string } {
  if (creds.PAYPAL_ENV !== "sandbox") throw new Error("PAYPAL_ENV must be 'sandbox' in the PayPal credentials file");
  const id = creds.PAYPAL_CLIENT_ID;
  const secret = creds.PAYPAL_CLIENT_SECRET;
  if (!id || !secret) throw new Error("PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET must be set in the PayPal credentials file");
  return { id, secret };
}

export function sandboxClient(creds: Credentials, fetcher: Fetch = fetch, nowMs: () => number = Date.now): Client {
  const { id, secret } = assertSandbox(creds);
  let token: { value: string; expiresAt: number } | undefined;

  async function call(method: string, path: string, headers: Record<string, string>, body?: string): Promise<Answer> {
    const res = await fetcher(SANDBOX_BASE + path, {
      method,
      headers: { Accept: "application/json", ...headers },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const text = await res.text();
    let json: any;
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      json = { raw: text.slice(0, 500) };
    }
    return { ok: res.ok, status: res.status, debugId: res.headers.get("paypal-debug-id"), body: json };
  }

  return {
    async authenticate() {
      if (token && nowMs() < token.expiresAt) return;
      let a: Answer;
      try {
        a = await call(
          "POST",
          "/v1/oauth2/token",
          {
            Authorization: "Basic " + Buffer.from(`${id}:${secret}`).toString("base64"),
            "Content-Type": "application/x-www-form-urlencoded",
          },
          "grant_type=client_credentials",
        );
      } catch {
        throw new Error("PayPal authentication failed: no answer from the sandbox");
      }
      const value = a.body?.access_token;
      if (a.status !== 200 || typeof value !== "string" || !value) {
        throw new Error(`PayPal authentication failed (HTTP ${a.status}${typeof a.body?.error === "string" ? `, ${a.body.error}` : ""})`);
      }
      const ttl = Number(a.body.expires_in) || 0;
      token = { value, expiresAt: nowMs() + Math.max(0, ttl - TOKEN_MARGIN_SECS) * 1000 };
    },
    async request(method, path, body, headers = {}) {
      if (!token) throw new Error("PayPal client: authenticate() first");
      return call(
        method,
        path,
        { Authorization: `Bearer ${token.value}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }), ...headers },
        body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
      );
    },
  };
}
