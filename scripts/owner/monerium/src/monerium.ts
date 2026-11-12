// Monerium sandbox client for the owner's link step (client credentials, API v2), ported from
// spikes/monerium. Sandbox only: the base URL, environment and chain are fixed, the token never
// leaves api.monerium.dev, and errors carry Monerium's status and code but never the response
// body, the token or the client secret.

export const API = "https://api.monerium.dev";
export const CHAIN = "basesepolia";
export const LINK_MESSAGE = "I hereby declare that I am the address owner.";

export type Fetch = typeof fetch;
export type Env = Record<string, string | undefined>;
export type Response = { ok: boolean; status: number; body: any };

/** A refused Monerium request: HTTP status plus Monerium's own `code`/`message`, redacted. */
export class MoneriumError extends Error {
  readonly operation: string;
  readonly status: number;
  readonly refusal: { code?: string | number; message?: string };

  constructor(operation: string, status: number, refusal: { code?: string | number; message?: string }) {
    const detail = [refusal.code, refusal.message].filter((v) => v !== undefined).join(": ");
    super(`${operation} refused by Monerium (HTTP ${status}${detail ? `, ${detail}` : ""})`);
    this.operation = operation;
    this.status = status;
    this.refusal = refusal;
  }
}

// IBAN length per country code, from the ISO 13616 registry (SWIFT), plus the partner countries that publish IBANs.
const IBAN_LENGTHS: Record<string, number> = Object.fromEntries(
  (
    "AD24 AE23 AL28 AO25 AT20 AZ28 BA20 BE16 BF28 BG22 BH22 BI27 BJ28 BL27 BR29 BY28 CF27 CG27 CH21 CI28 CM27 CR22 " +
    "CV25 CY28 CZ24 DE22 DJ27 DK18 DO28 DZ26 EE20 EG29 ES24 FI18 FK18 FO18 FR27 GA27 GB22 GE22 GF27 GI23 GL18 GP27 " +
    "GQ27 GR27 GT28 GW25 HN28 HR21 HU28 IE22 IL23 IQ23 IR26 IS26 IT27 JO30 KM27 KW30 KZ20 LB28 LC32 LI21 LT20 LU20 " +
    "LV21 LY25 MA28 MC27 MD24 ME22 MF27 MG27 MK19 ML28 MN20 MQ27 MR27 MT31 MU30 MZ25 NC27 NE28 NI28 NL18 NO15 OM23 " +
    "PF27 PK24 PL28 PM27 PS29 QA29 RE27 RO24 RS22 RU33 SA24 SC31 SD18 SE24 SI19 SK24 SM27 SN28 SO23 ST25 SV28 TD27 " +
    "TF27 TG28 TL23 TN24 TR26 UA29 VA22 VG24 WF27 XK20 YE30 YT27"
  )
    .split(" ")
    .map((e) => [e.slice(0, 2), Number(e.slice(2))]),
);

// Where an IBAN may start: a country code and two check digits, even glued to a word (`IBANDE89…`).
const IBAN_START = /([a-z]{2})[0-9]{2}/gi;
// One group of an IBAN and the separators before it: any whitespace (NBSP too), `-`, `.` or `/`.
const IBAN_GROUP = /[\s\-./]*([a-z0-9]+)/giy;

/** ISO 7064 mod 97-10 check of an IBAN without separators. */
function ibanChecks(iban: string): boolean {
  let rest = 0;
  for (const c of (iban.slice(4) + iban.slice(0, 4)).toUpperCase()) {
    rest = Number(`${rest}${parseInt(c, 36)}`) % 97;
  }
  return rest === 1;
}

/**
 * The IBAN at `start`: exactly as many alphanumerics as its country's IBAN has, in groups split
 * by whitespace, `-`, `.` or `/`. It counts when the check digits hold or the last group ends right there, so
 * a number after it (a status, an amount) stays outside and a mistyped IBAN is still hidden.
 * Otherwise (wrong check digits and a number glued on, or the wrong length) it fails closed: the
 * whole groups up to the country's length are returned without the IBAN, if they hold a digit
 * past the check digits, so the account number is hidden even when the exact span is unknown.
 */
function ibanAt(s: string, start: number, length: number): { iban?: string; end: number } | undefined {
  const group = new RegExp(IBAN_GROUP);
  group.lastIndex = start;
  let iban = "";
  let span = "";
  let spanEnd = start;
  for (let g; iban.length < length && (g = group.exec(s)); ) {
    const take = Math.min(g[1].length, length - iban.length);
    iban += g[1].slice(0, take);
    const end = g.index + g[0].length - g[1].length + take;
    if (iban.length === length && (ibanChecks(iban) || take === g[1].length)) return { iban, end };
    span += g[1];
    spanEnd = group.lastIndex;
  }
  return /[0-9]/.test(span.slice(4)) ? { end: spanEnd } : undefined;
}

/**
 * An IBAN-like span at `start` whose country code is unknown (or mistyped): groups that hold a
 * digit or are 1 to 4 letters, up to the last group with a digit. It fails closed: 15 or more
 * alphanumerics in all (the shortest IBAN, Norway's) are hidden, so `DX89 3704 …` and
 * `QQ82 WES …` go, `DX89 1234` and `ab12 is` stay.
 */
function unknownIbanAt(s: string, start: number): { end: number } | undefined {
  const group = new RegExp(IBAN_GROUP);
  group.lastIndex = start;
  let span = "";
  let kept = 0;
  let end = start;
  for (let g; (g = group.exec(s)) && (/[0-9]/.test(g[1]) || g[1].length <= 4); ) {
    span += g[1];
    if (/[0-9]/.test(g[1])) [kept, end] = [span.length, group.lastIndex];
  }
  return kept >= 15 ? { end } : undefined;
}

/**
 * Replaces IBANs in any case, spacing or grouping with `<IBAN …last4>`, or `<IBAN>` when one
 * fails its check and length or has an unknown country code, so its exact end is unknown; the
 * text around them stays.
 */
export function redactIbans(s: string): string {
  let out = "";
  let from = 0;
  for (const m of s.matchAll(IBAN_START)) {
    const length = IBAN_LENGTHS[m[1].toUpperCase()];
    const found = m.index < from ? undefined : length !== undefined ? ibanAt(s, m.index, length) : unknownIbanAt(s, m.index);
    if (!found) continue;
    out += s.slice(from, m.index) + (found.iban ? `<IBAN …${found.iban.slice(-4)}>` : "<IBAN>");
    from = found.end;
  }
  return out + s.slice(from);
}

const redact = (v: unknown) =>
  typeof v === "number"
    ? v
    : typeof v === "string"
      ? // Hex and UUIDs first, so the IBAN scan (no word boundary) does not take them apart.
        redactIbans(
          v
            .replace(/0x[0-9a-f]+/gi, "<HEX>")
            .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<UUID>"),
        ).slice(0, 200)
      : undefined;

/** Monerium's refusal fields only (`code`, then `message` or OAuth `error`), with IBANs (last 4 kept), hex and UUIDs redacted. */
export function refusal(body: any): { code?: string | number; message?: string } {
  const out: { code?: string | number; message?: string } = {};
  const code = redact(body?.code ?? body?.error);
  const message = redact(body?.message ?? body?.error_description);
  if (code !== undefined) out.code = code;
  if (typeof message === "string") out.message = message;
  return out;
}

/** Throws a MoneriumError unless the response is 2xx; returns the body. */
export function must(res: Response, operation: string): any {
  if (!res.ok) throw new MoneriumError(operation, res.status, refusal(res.body));
  return res.body;
}

export function sandboxClient(env: Env, fetcher: Fetch = fetch) {
  if (env.MONERIUM_ENVIRONMENT !== "sandbox") throw new Error("MONERIUM_ENVIRONMENT must be sandbox");
  if (!env.MONERIUM_CLIENT_ID || !env.MONERIUM_CLIENT_SECRET) throw new Error("set MONERIUM_CLIENT_ID and MONERIUM_CLIENT_SECRET");
  if (env.MONERIUM_BASE_URL && env.MONERIUM_BASE_URL !== API) throw new Error("only the Monerium sandbox API is allowed");
  if (env.MONERIUM_CHAIN && env.MONERIUM_CHAIN !== CHAIN) throw new Error("only Base Sepolia is allowed");
  let token: string | undefined;

  async function send(method: string, path: string, body?: unknown): Promise<Response> {
    if (!/^\/[a-z0-9/?=&%-]+$/i.test(path) || path.startsWith("//")) throw new Error("invalid Monerium API path");
    const auth = path === "/auth/token";
    if (!auth && !token) throw new Error("authenticate before calling Monerium");
    let res: globalThis.Response;
    try {
      res = await fetcher(`${API}${path}`, {
        method,
        redirect: "error",
        signal: AbortSignal.timeout(30_000),
        headers: {
          accept: "application/vnd.monerium.api-v2+json",
          ...(auth ? {} : { authorization: `Bearer ${token}` }),
          ...(body ? { "content-type": auth ? "application/x-www-form-urlencoded" : "application/json" } : {}),
        },
        body: body ? (auth ? String(body) : JSON.stringify(body)) : undefined,
      });
    } catch {
      throw new Error(`Monerium ${method} ${path} failed in transit; outcome unknown, check the sandbox before retrying`);
    }
    const text = await res.text();
    let data: any;
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      throw new Error(`Monerium ${method} ${path} returned non-JSON (HTTP ${res.status}); body withheld`);
    }
    return { ok: res.ok, status: res.status, body: data };
  }

  return {
    async authenticate(): Promise<void> {
      const res = await send(
        "POST",
        "/auth/token",
        new URLSearchParams({
          grant_type: "client_credentials",
          client_id: env.MONERIUM_CLIENT_ID!,
          client_secret: env.MONERIUM_CLIENT_SECRET!,
        }),
      );
      const body = must(res, "Sandbox authentication");
      if (typeof body.access_token !== "string" || !body.access_token) throw new Error("Monerium returned no access token");
      token = body.access_token;
    },
    request: send,
  };
}

export type Client = ReturnType<typeof sandboxClient>;
