// Shared by the PP3 service and the PP-W1 webhook receiver: a bounded body read and server timeouts,
// so a client that trickles headers or body (slow loris) cannot hold a connection open (PayPal audit 2 M1/M2).

import { createServer, type IncomingMessage, type RequestListener, type Server, type ServerResponse } from "node:http";

export type Limits = {
  /** Body cap in bytes; a larger Content-Length is refused before anything is read. */
  maxBody: number;
  /** The whole body must arrive within this many ms of the handler starting to read it. */
  bodyTimeoutMs?: number;
  /** No more than this many ms between two body chunks. */
  idleTimeoutMs?: number;
  /** Node's own limits on the whole request and on its headers. */
  requestTimeoutMs?: number;
  headersTimeoutMs?: number;
};

export const BODY_TIMEOUT_MS = 10_000;
export const IDLE_TIMEOUT_MS = 5_000;
export const REQUEST_TIMEOUT_MS = 15_000;
export const HEADERS_TIMEOUT_MS = 10_000;

/**
 * The body as text; `too_large` over `maxBody` bytes; `timeout` if it does not arrive in time;
 * undefined if the client went away. Never throws.
 */
export function readBody(req: IncomingMessage, l: Limits): Promise<string | "too_large" | "timeout" | undefined> {
  const declared = Number(req.headers["content-length"]);
  if (Number.isFinite(declared) && declared > l.maxBody) return Promise.resolve("too_large");
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let bytes = 0;
    let idle: NodeJS.Timeout | undefined;
    const finish = (out: string | "too_large" | "timeout" | undefined) => {
      clearTimeout(deadline);
      clearTimeout(idle);
      req.off("data", onData).off("end", onEnd).off("error", onGone).off("close", onGone);
      if (out === "too_large" || out === "timeout") req.pause();
      resolve(out);
    };
    const armIdle = () => {
      clearTimeout(idle);
      idle = setTimeout(() => finish("timeout"), l.idleTimeoutMs ?? IDLE_TIMEOUT_MS);
    };
    const onData = (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > l.maxBody) return finish("too_large");
      chunks.push(chunk);
      armIdle();
    };
    const onEnd = () => finish(req.complete ? Buffer.concat(chunks).toString("utf8") : undefined);
    const onGone = () => finish(undefined);
    const deadline = setTimeout(() => finish("timeout"), l.bodyTimeoutMs ?? BODY_TIMEOUT_MS);
    armIdle();
    req.on("data", onData).on("end", onEnd).on("error", onGone).on("close", onGone);
  });
}

/** An HTTP server with Node's request and header timeouts set, checked every second. */
export function boundedServer(l: Limits, handler: RequestListener): Server {
  const requestTimeout = l.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
  const s = createServer(
    { requestTimeout, headersTimeout: Math.min(l.headersTimeoutMs ?? HEADERS_TIMEOUT_MS, requestTimeout), connectionsCheckingInterval: 1_000 },
    handler,
  );
  s.on("clientError", (_e, socket) => socket.destroy());
  return s;
}

/** Ends an answered request whose body was not read to the end: the connection is not reused. */
export function closeAfter(req: IncomingMessage, res: ServerResponse): void {
  res.setHeader("connection", "close");
  res.once("finish", () => req.socket.destroy());
}
