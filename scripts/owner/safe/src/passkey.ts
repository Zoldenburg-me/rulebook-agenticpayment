// The owner's passkey taps. A one-shot page on http://localhost runs WebAuthn in the owner's
// browser and posts the result back; no private key ever reaches this process.

import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { homedir } from "node:os";
import { join } from "node:path";
import { pubkeyCoordinatesFromJson, type WebauthnPublicKey } from "abstractionkit";

/** The passkey's site. A passkey made here works only on http://localhost:<port>. */
export const RP_ID = "localhost";

/** Public material only: the credential id, the P-256 point and the Safe it controls. */
export type PasskeyFile = { credential_id: string; x: string; y: string; safe_address: string };

export function passkeyPath(): string {
  return join(process.env.OWNER_KEY_DIR ?? join(homedir(), ".nearh-owner"), "safe-passkey.json");
}

export function loadPasskey(): PasskeyFile & { publicKey: WebauthnPublicKey } {
  const p = passkeyPath();
  if (!existsSync(p)) throw new Error(`no passkey at ${p}; run pnpm passkey first`);
  const f = JSON.parse(readFileSync(p, "utf8")) as PasskeyFile;
  return { ...f, publicKey: pubkeyCoordinatesFromJson({ x: f.x, y: f.y }) };
}

export function savePasskey(f: PasskeyFile): string {
  const p = passkeyPath();
  // Before the Safe is deployed this file is the only record of its address: never overwrite it.
  if (existsSync(p)) throw new Error(`${p} exists; refusing to overwrite`);
  mkdirSync(join(p, ".."), { recursive: true, mode: 0o700 });
  writeFileSync(p, JSON.stringify(f, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  chmodSync(p, 0o600);
  return p;
}

/** P-256 SubjectPublicKeyInfo (91 bytes, from `getPublicKey()`) → (x, y). */
export function spkiToPoint(spki: Uint8Array): WebauthnPublicKey {
  const prefix = "3059301306072a8648ce3d020106082a8648ce3d03010703420004";
  if (spki.length !== 91 || Buffer.from(spki.subarray(0, 27)).toString("hex") !== prefix) {
    throw new Error("passkey public key is not an uncompressed P-256 SPKI");
  }
  const hex = (b: Uint8Array) => BigInt("0x" + Buffer.from(b).toString("hex"));
  return { x: hex(spki.subarray(27, 59)), y: hex(spki.subarray(59, 91)) };
}

export type TapRequest =
  | { mode: "create"; summary: string }
  | { mode: "get"; summary: string; challenge: Uint8Array; credentialId: string };

export type CreateResult = { id: string; publicKey: string };
export type GetResult = { authenticatorData: string; clientDataJSON: string; signature: string };

const PAGE = (req: object, token: string) => `<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>nearH owner passkey</title>
<body style="font:16px system-ui;max-width:36rem;margin:3rem auto;padding:0 1rem">
<h1>nearH owner passkey</h1><p id="s"></p><button id="b" style="font:inherit;padding:.6rem 1.2rem">Use passkey</button><p id="o"></p>
<script>
const req = ${JSON.stringify(req)};
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
document.getElementById("s").textContent = req.summary;
document.getElementById("b").onclick = async () => {
  const out = document.getElementById("o");
  try {
    let body;
    if (req.mode === "create") {
      const c = await navigator.credentials.create({ publicKey: {
        rp: { id: "${RP_ID}", name: "nearH owner" },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "nearh-owner", displayName: "nearH owner" },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
      } });
      body = { id: c.id, publicKey: b64u(c.response.getPublicKey()) };
    } else {
      const a = await navigator.credentials.get({ publicKey: {
        rpId: "${RP_ID}", challenge: unb64u(req.challenge), userVerification: "required",
        allowCredentials: [{ type: "public-key", id: unb64u(req.credentialId) }],
      } });
      body = { authenticatorData: b64u(a.response.authenticatorData), clientDataJSON: b64u(a.response.clientDataJSON), signature: b64u(a.response.signature) };
    }
    const r = await fetch("/result?t=${token}", { method: "POST", body: JSON.stringify(body) });
    out.textContent = r.ok ? "Done. You can close this tab." : "Error: " + await r.text();
  } catch (e) { out.textContent = "Error: " + e; }
};
</script>`;

/** Serves one page, waits for the owner's tap, returns what the browser posted. */
export function tap(req: { mode: "create"; summary: string }): Promise<CreateResult>;
export function tap(req: { mode: "get"; summary: string; challenge: Uint8Array; credentialId: string }): Promise<GetResult>;
export function tap(req: TapRequest): Promise<CreateResult | GetResult> {
  const port = Number(process.env.PASSKEY_PORT ?? 5174);
  const token = randomBytes(16).toString("hex");
  const pageReq = req.mode === "get" ? { ...req, challenge: Buffer.from(req.challenge).toString("base64url") } : req;
  return new Promise((resolve, reject) => {
    const server = createServer((r, w) => {
      const url = new URL(r.url ?? "/", "http://localhost");
      if (r.method === "GET" && url.pathname === "/" && url.searchParams.get("t") === token) {
        w.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(PAGE(pageReq, token));
      } else if (r.method === "POST" && url.pathname === "/result" && url.searchParams.get("t") === token) {
        let body = "";
        r.on("data", (c) => (body += c));
        r.on("end", () => {
          try {
            const parsed = JSON.parse(body);
            w.writeHead(200).end("ok");
            server.close();
            resolve(parsed);
          } catch (e) {
            w.writeHead(400).end("bad body");
          }
        });
      } else {
        w.writeHead(404).end();
      }
    });
    server.on("error", reject);
    server.listen(port, "localhost", () => {
      console.log(`\nPasskey tap needed: ${req.summary}\nOpen http://localhost:${port}/?t=${token} and press "Use passkey".\n`);
    });
  });
}
