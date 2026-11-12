// The judge page server: `pnpm --filter @nearh/demo judge`. Read-only, and it holds no credential:
// it serves demo/judge/ (the page), a fixed list of evidence and source files from the repo, and
// GET /api/replay/{anya,hank}, which runs judge-replay.ts in-process (mock contract, mock PayPal,
// no network). Listens on HOST:PORT (default 127.0.0.1:8080; a hosted deploy sets HOST=0.0.0.0).

import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { replay, type StoryId } from "./judge-replay.ts";

const root = fileURLToPath(new URL("../../", import.meta.url));
const pageDir = fileURLToPath(new URL("../judge/", import.meta.url));

/** The page's own files. */
const PAGE: Record<string, string> = { "/": "index.html", "/app.js": "app.js", "/stories.js": "stories.js", "/style.css": "style.css" };
/** Repo files the page links as proof, served as plain text. Payees in them are masked; none holds a key or token. */
export const EVIDENCE = [
  "demo/evidence/pt1-refunds.md",
  "demo/evidence/pt1-refunds.jsonl",
  "demo/evidence/pp-payouts-live.md",
  "demo/evidence/pp-payouts-live.jsonl",
  "demo/evidence/pt2-hank-live.md",
  "demo/evidence/pt2-hank-live.jsonl",
  "demo/evidence/pt3-bot-run.md",
  "demo/evidence/pt3-bot-run.jsonl",
  "rails/paypal/RESULT.md",
  "rails/paypal/RESULT-webhooks.md",
  "rails/paypal/evidence-vault.json",
  "contract/src/errors.rs",
  "contract/src/shapes/paypal.rs",
  "contract/src/shapes/paypal_checkout.rs",
  "contract/src/shapes/refund.rs",
  "contract/tests/pt1_refund.rs",
  "rails/paypal/src/payout.ts",
  "rails/paypal/src/vault.ts",
  "rails/paypal/src/refund.ts",
  "demo/src/judge-replay.ts",
  "demo/src/mock-contract.ts",
  "demo/src/mock-paypal.ts",
];
const TYPES: Record<string, string> = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };
const HEADERS = {
  "content-security-policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
};
/** Replays running at once; more get 503, so the page can't be used to load the host. */
const MAX_REPLAYS = 4;

export function judgeServer(): Server {
  let running = 0;
  return createServer(async (req, res) => {
    const send = (status: number, type: string, body: string | Buffer) => {
      res.writeHead(status, { ...HEADERS, "content-type": type });
      res.end(body);
    };
    const url = new URL(req.url ?? "/", "http://localhost");
    if (req.method !== "GET" && req.method !== "HEAD") return send(405, "text/plain", "read-only");
    if (url.pathname === "/healthz") return send(200, "text/plain", "ok");
    const page = PAGE[url.pathname];
    if (page) return send(200, TYPES[extname(page)], readFileSync(join(pageDir, page)));
    if (url.pathname.startsWith("/evidence/")) {
      const path = url.pathname.slice("/evidence/".length);
      if (!EVIDENCE.includes(path)) return send(404, "text/plain", "not an evidence file");
      return send(200, "text/plain; charset=utf-8", readFileSync(resolve(root, path)));
    }
    const story = /^\/api\/replay\/(anya|hank)$/.exec(url.pathname)?.[1] as StoryId | undefined;
    if (story) {
      if (running >= MAX_REPLAYS) return send(503, "application/json", JSON.stringify({ error: "busy, try again" }));
      running++;
      try {
        return send(200, "application/json", JSON.stringify(await replay(story)));
      } catch (e: any) {
        console.error(`replay ${story} failed: ${String(e?.message ?? e).slice(0, 200)}`);
        return send(500, "application/json", JSON.stringify({ error: "replay failed" }));
      } finally {
        running--;
      }
    }
    send(404, "text/plain", "not found");
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const host = process.env.HOST || "127.0.0.1";
  const port = Number(process.env.PORT || 8080);
  judgeServer().listen(port, host, () => console.log(`Rulebook judge page on http://${host}:${port}`));
}
