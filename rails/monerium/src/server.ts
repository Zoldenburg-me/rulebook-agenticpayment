// The M1 service: `POST /payouts` with a PayoutInput, answered with a PayoutResult. It listens on
// 127.0.0.1 only and refuses non-loopback peers; A2 calls it, so the Monerium credentials stay in
// this process. Every call carries `Authorization: Bearer <token>` for the payout's agent
// (`M1_AGENT_TOKENS`), so one local caller cannot spend another agent's signed payout.

import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { AGENT_ID, scrub, submitPayout, type Deps } from "./payout.ts";

const MAX_BODY = 4096;
const LOOPBACK = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);
const TOKEN = /^[A-Za-z0-9._~+\/=-]{32,256}$/;

/** Per-agent bearer tokens, `agent=token` pairs separated by commas. Throws on a malformed entry. */
export function parseAgentTokens(spec: string | undefined): Map<string, string> {
  const tokens = new Map<string, string>();
  for (const entry of (spec ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
    const i = entry.indexOf("=");
    const [agent, token] = [entry.slice(0, i), entry.slice(i + 1)];
    if (i < 1 || !AGENT_ID.test(agent)) throw new Error("M1_AGENT_TOKENS: each entry is agent=token with a valid agent id");
    if (!TOKEN.test(token)) throw new Error(`M1_AGENT_TOKENS: the token for ${agent} must be 32-256 chars of [A-Za-z0-9._~+/=-]`);
    if (tokens.has(agent)) throw new Error(`M1_AGENT_TOKENS: ${agent} is listed twice`);
    tokens.set(agent, token);
  }
  return tokens;
}

const sha = (s: string) => createHash("sha256").update(s).digest();

/** Constant-time: the bearer token equals the one configured for `agent`. */
function authorised(tokens: Map<string, string>, agent: string, header: string | undefined): boolean {
  const given = /^Bearer (\S+)$/.exec(header ?? "")?.[1] ?? "";
  const expected = tokens.get(agent);
  const ok = timingSafeEqual(sha(given), sha(expected ?? "\0no-token"));
  return ok && expected !== undefined;
}

/** The body as text, or undefined if the client went away or it is over MAX_BODY. Never throws. */
async function readBody(req: IncomingMessage): Promise<string | "too_large" | undefined> {
  let raw = "";
  try {
    for await (const chunk of req) {
      raw += chunk;
      if (raw.length > MAX_BODY) return "too_large";
    }
  } catch {
    return undefined;
  }
  return req.complete ? raw : undefined;
}

export function server(d: Deps, agentTokens: Map<string, string>): Server {
  if (agentTokens.size === 0) throw new Error("set M1_AGENT_TOKENS: the service refuses to run without per-agent tokens");
  const s = createServer((req, res) => {
    res.on("error", () => {});
    const reply = (status: number, body: unknown) => {
      if (res.headersSent || res.writableEnded || res.destroyed) return;
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    const handle = async () => {
      if (!LOOPBACK.has(req.socket.remoteAddress ?? "")) return reply(403, { error: "loopback only" });
      if (req.method !== "POST" || req.url !== "/payouts") return reply(404, { error: "POST /payouts only" });
      const raw = await readBody(req);
      if (raw === undefined) return; // client disconnected; nothing was submitted
      if (raw === "too_large") return reply(413, { error: "body too large" });
      let input;
      try {
        input = JSON.parse(raw);
      } catch {
        return reply(400, { error: "body must be JSON" });
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
        reply(200, await submitPayout(d, input));
      } catch (e: any) {
        // NEAR RPC, the store or Monerium auth failed before any order was claimed; safe to retry.
        const detail = scrub(String(e?.message ?? e), d.secrets).slice(0, 300);
        d.log?.(`error ${request_id}: ${detail}`);
        reply(502, { status: "failed", request_id, error_code: "M1_ERROR", detail });
      }
    };
    handle().catch(() => reply(500, { error: "internal error" }));
  });
  s.on("clientError", (_e, socket) => socket.destroy());
  return s;
}
