// Serves index.html and writes POST /save to ../fixtures/assertion.json.
// Binds to 127.0.0.1 only; expose it with `tailscale serve` (tailnet only, never funnel).
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const port = Number(process.env.PORT || 8787);
const out = join(here, '..', 'fixtures', 'assertion.json');
const FIELDS = ['rpId', 'origin', 'credentialId', 'publicKeySpki', 'authenticatorData', 'clientDataJSON', 'signature'];
const MAX_BODY = 16 * 1024;
// The one origin that serves the page (to check POST /save against).
// Set PASSKEY_ORIGIN when exposing through tailscale serve (WebAuthn needs HTTPS).
const ALLOWED_ORIGIN = process.env.PASSKEY_ORIGIN || `http://127.0.0.1:${port}`;

createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      return res.end(await readFile(join(here, 'index.html')));
    }
    if (req.method === 'POST' && req.url === '/save') {
      // SEC-3: reject cross-origin and non-JSON requests
      const origin = req.headers.origin || '';
      const ctype = req.headers['content-type'] || '';
      if (origin !== ALLOWED_ORIGIN) { res.writeHead(403); return res.end('origin rejected'); }
      if (ctype !== 'application/json' && ctype !== 'application/json; charset=utf-8') { res.writeHead(415); return res.end('content-type not supported'); }
      let body = '';
      for await (const chunk of req) {
        body += chunk;
        if (body.length > MAX_BODY) { res.writeHead(413); return res.end('too large'); }
      }
      const blob = JSON.parse(body);
      for (const f of FIELDS) {
        if (typeof blob[f] !== 'string' || !blob[f]) { res.writeHead(400); return res.end(`missing ${f}`); }
      }
      await mkdir(dirname(out), { recursive: true });
      await writeFile(out, JSON.stringify(blob, null, 2) + '\n');
      console.log(`saved ${out} (rpId=${blob.rpId}, origin=${blob.origin})`);
      res.writeHead(200, { 'content-type': 'text/plain' });
      return res.end('saved');
    }
    res.writeHead(404);
    res.end('not found');
  } catch (e) {
    res.writeHead(400);
    res.end(String(e.message || e));
  }
}).listen(port, '127.0.0.1', () => console.log(`passkey page on http://127.0.0.1:${port}`));
