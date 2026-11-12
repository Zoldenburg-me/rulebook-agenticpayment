// The PP3 service: `POST /payouts` with a PaypalOrder, answered with a PayoutResult. It listens on
// 127.0.0.1 only and refuses non-loopback peers; the agent's `pay_paypal` tool calls it, so the
// PayPal credentials stay in this process. Every call carries `Authorization: Bearer <token>` for
// the order's agent (`PP3_AGENT_TOKENS`), so one local caller cannot spend another agent's order.

import { createHash, timingSafeEqual } from "node:crypto";
import type { Server } from "node:http";
import { boundedServer, closeAfter, readBody, type Limits } from "./http.ts";
import { AGENT_ID, scrub, submitPaypalPayout, type Deps } from "./payout.ts";
import { chargeCheckout, confirmVault, connectVault, revokeVault, vaultStatus, type VaultDeps } from "./vault.ts";

const MAX_BODY = 4096;
const LOOPBACK = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);
const TOKEN = /^[A-Za-z0-9._~+\/=-]{32,256}$/;

/** Per-agent bearer tokens, `agent=token` pairs separated by commas. Throws on a malformed entry. */
export function parseAgentTokens(spec: string | undefined): Map<string, string> {
  const tokens = new Map<string, string>();
  for (const entry of (spec ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const i = entry.indexOf("=");
    const [agent, token] = [entry.slice(0, i), entry.slice(i + 1)];
    if (i < 1 || !AGENT_ID.test(agent)) throw new Error("PP3_AGENT_TOKENS: each entry is agent=token with a valid agent id");
    if (!TOKEN.test(token)) throw new Error(`PP3_AGENT_TOKENS: the token for ${agent} must be 32-256 chars of [A-Za-z0-9._~+/=-]`);
    if (tokens.has(agent)) throw new Error(`PP3_AGENT_TOKENS: ${agent} is listed twice`);
    tokens.set(agent, token);
  }
  return tokens;
}

const sha = (s: string) => createHash("sha256").update(s).digest();

/** Constant-time: the bearer token equals `expected`. */
function bearerIs(expected: string | undefined, header: string | undefined): boolean {
  const given = /^Bearer (\S+)$/.exec(header ?? "")?.[1] ?? "";
  const ok = timingSafeEqual(sha(given), sha(expected ?? "\0no-token"));
  return ok && expected !== undefined;
}

/** Constant-time: the bearer token equals the one configured for `agent`. */
function authorised(tokens: Map<string, string>, agent: string, header: string | undefined): boolean {
  return bearerIs(tokens.get(agent), header);
}

/** PP-V1 routes, on when `vault` is given: `POST /checkout` (agent token) and the owner's `/vault/*` (owner token). */
export type VaultRoutes = { deps: VaultDeps; ownerToken: string };

export function server(d: Deps, agentTokens: Map<string, string>, limits: Partial<Limits> = {}, vault?: VaultRoutes): Server {
  const l: Limits = { ...limits, maxBody: MAX_BODY };
  if (agentTokens.size === 0) throw new Error("set PP3_AGENT_TOKENS: the service refuses to run without per-agent tokens");
  if (vault && !TOKEN.test(vault.ownerToken)) throw new Error("PP_OWNER_TOKEN must be 32-256 chars of [A-Za-z0-9._~+/=-]");
  return boundedServer(l, (req, res) => {
    res.on("error", () => {});
    const reply = (status: number, body: unknown) => {
      if (res.headersSent || res.writableEnded || res.destroyed) return;
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    const handle = async () => {
      if (!LOOPBACK.has(req.socket.remoteAddress ?? "")) return reply(403, { error: "loopback only" });
      const url = new URL(req.url ?? "/", "http://localhost");
      if (vault && req.method === "GET" && url.pathname === "/vault/status") {
        if (!bearerIs(vault.ownerToken, req.headers.authorization)) return reply(401, { error: "missing or wrong owner token" });
        const agent = url.searchParams.get("agent") ?? "";
        if (!AGENT_ID.test(agent)) return reply(400, { error: "agent must be 1-64 chars of [A-Za-z0-9._:-]" });
        return reply(200, vaultStatus(vault.deps, agent));
      }
      const route = req.method === "POST" ? url.pathname : "";
      const isVault = !!vault && ["/vault/connect", "/vault/confirm", "/vault/revoke"].includes(route);
      const isCheckout = !!vault && route === "/checkout";
      if (route !== "/payouts" && !isVault && !isCheckout) return reply(404, { error: vault ? "POST /payouts, /checkout, /vault/{connect,confirm,revoke} or GET /vault/status" : "POST /payouts only" });
      const raw = await readBody(req, l);
      if (raw === undefined) return; // client disconnected; nothing was submitted
      if (raw === "too_large" || raw === "timeout") closeAfter(req, res);
      if (raw === "too_large") return reply(413, { error: "body too large" });
      if (raw === "timeout") return reply(408, { error: "body not received in time" });
      let input;
      try {
        input = JSON.parse(raw);
      } catch {
        return reply(400, { error: "body must be JSON" });
      }
      if (isVault) {
        if (!bearerIs(vault!.ownerToken, req.headers.authorization)) return reply(401, { error: "missing or wrong owner token" });
        const agent = input?.agent;
        if (typeof agent !== "string" || !AGENT_ID.test(agent)) return reply(400, { error: "agent must be 1-64 chars of [A-Za-z0-9._:-]" });
        const op = route === "/vault/connect" ? connectVault : route === "/vault/confirm" ? confirmVault : revokeVault;
        try {
          const out = await op(vault!.deps, agent);
          return reply(out.ok ? 200 : 409, out);
        } catch (e: any) {
          const detail = scrub(String(e?.message ?? e), d.secrets).slice(0, 300);
          d.log?.(`vault error ${agent}: ${detail}`);
          return reply(502, { ok: false, agent, error_code: "PP3_ERROR", detail });
        }
      }
      // Validated before anything is logged or echoed: only these two values ever reach a log line.
      const { agent, request_id } = input ?? {};
      if (typeof agent !== "string" || !AGENT_ID.test(agent) || typeof request_id !== "string" || !AGENT_ID.test(request_id)) {
        return reply(400, { error: "agent and request_id must be 1-64 chars of [A-Za-z0-9._:-]" });
      }
      if (!authorised(agentTokens, agent, req.headers.authorization)) {
        d.log?.(`unauthorised ${agent}/${request_id}`);
        return reply(401, { error: "missing or wrong bearer token for this agent" });
      }
      try {
        reply(200, isCheckout ? await chargeCheckout(vault!.deps, input) : await submitPaypalPayout(d, input));
      } catch (e: any) {
        // NEAR RPC or the store failed before any order was claimed; safe to retry.
        const detail = scrub(String(e?.message ?? e), d.secrets).slice(0, 300);
        d.log?.(`error ${request_id}: ${detail}`);
        reply(502, { status: "failed", request_id, error_code: "PP3_ERROR", detail });
      }
    };
    handle().catch(() => reply(500, { error: "internal error" }));
  });
}
