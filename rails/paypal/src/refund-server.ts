// PP-T1: the refund service for the support agent, separate from PP3's payout service so either
// can run alone. 127.0.0.1 only; every call carries `Authorization: Bearer <token>` for the
// named agent (`PP3_AGENT_TOKENS`, the same per-agent tokens as PP3).
//   GET  /tools?agent=<id>                    the toolkit's definitions (read tools + create_refund)
//   POST /tools/call {agent, name, arguments} runs one read tool; create_refund is refused here
//   POST /refunds    RefundOrder              a contract-signed shape 6 order, at most once

import { createHash, timingSafeEqual } from "node:crypto";
import type { Server } from "node:http";
import { boundedServer, closeAfter, readBody, type Limits } from "./http.ts";
import { AGENT_ID, scrub } from "./payout.ts";
import { submitRefund, type RefundDeps } from "./refund.ts";
import { MANDATED_TOOL, type Toolkit } from "./toolkit.ts";

const MAX_BODY = 4096;
const LOOPBACK = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);

const sha = (s: string) => createHash("sha256").update(s).digest();

/** Constant-time: the bearer token equals the one configured for `agent`. */
function authorised(tokens: Map<string, string>, agent: string, header: string | undefined): boolean {
  const given = /^Bearer (\S+)$/.exec(header ?? "")?.[1] ?? "";
  const expected = tokens.get(agent);
  return timingSafeEqual(sha(given), sha(expected ?? "\0no-token")) && expected !== undefined;
}

export function refundServer(d: RefundDeps, kit: Toolkit, agentTokens: Map<string, string>, limits: Partial<Limits> = {}): Server {
  const l: Limits = { ...limits, maxBody: MAX_BODY };
  if (agentTokens.size === 0) throw new Error("set PP3_AGENT_TOKENS: the service refuses to run without per-agent tokens");
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
      if (req.method === "GET" && url.pathname === "/tools") {
        const agent = url.searchParams.get("agent") ?? "";
        if (!AGENT_ID.test(agent)) return reply(400, { error: "agent must be 1-64 chars of [A-Za-z0-9._:-]" });
        if (!authorised(agentTokens, agent, req.headers.authorization)) return reply(401, { error: "missing or wrong bearer token for this agent" });
        return reply(200, { tools: kit.tools() });
      }
      const route = req.method === "POST" ? url.pathname : "";
      if (route !== "/tools/call" && route !== "/refunds") return reply(404, { error: "GET /tools, POST /tools/call or POST /refunds" });
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
      const agent = input?.agent;
      if (typeof agent !== "string" || !AGENT_ID.test(agent)) return reply(400, { error: "agent must be 1-64 chars of [A-Za-z0-9._:-]" });
      if (!authorised(agentTokens, agent, req.headers.authorization)) {
        d.log?.(`unauthorised ${agent} ${route}`);
        return reply(401, { error: "missing or wrong bearer token for this agent" });
      }
      if (route === "/tools/call") {
        const name = input?.name;
        if (name === MANDATED_TOOL) return reply(403, { error: "create_refund runs only as a contract-signed refund order: POST /refunds" });
        if (typeof name !== "string" || !kit.tools().some((t) => t.function.name === name)) return reply(404, { error: "unknown tool" });
        try {
          return reply(200, { name, content: await kit.call(name, input?.arguments) });
        } catch (e: any) {
          return reply(502, { name, error: scrub(String(e?.message ?? e), d.secrets).slice(0, 300) });
        }
      }
      const request_id = input?.request_id;
      if (typeof request_id !== "string" || !AGENT_ID.test(request_id)) return reply(400, { error: "request_id must be 1-64 chars of [A-Za-z0-9._:-]" });
      try {
        reply(200, await submitRefund(d, input));
      } catch (e: any) {
        // NEAR RPC or the store failed before any refund was claimed; safe to retry.
        const detail = scrub(String(e?.message ?? e), d.secrets).slice(0, 300);
        d.log?.(`refund error ${request_id}: ${detail}`);
        reply(502, { status: "failed", request_id, error_code: "PP3_ERROR", detail });
      }
    };
    handle().catch(() => reply(500, { error: "internal error" }));
  });
}
