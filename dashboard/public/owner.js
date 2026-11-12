// Owner calls signed in the browser with the passkey (docs/interfaces.md §2). Runs in the
// page and in Node (the unit tests import it), so it uses only Web Crypto and TextEncoder.

const utf8 = new TextEncoder();
const OWNER_CHALLENGE_DOMAIN = "zold-mandate-v1";
/** Validity of a signed owner call; the contract caps it at MAX_ASSERTION_TTL_SECS (600). */
export const ASSERTION_TTL_SECS = 300;

/** Borsh writer for the argument tuples of the owner methods the dashboard calls. */
export class Writer {
  #out = [];
  u8(n) {
    this.#out.push(n & 0xff);
    return this;
  }
  u32(n) {
    for (let i = 0; i < 4; i++) this.#out.push((n >>> (8 * i)) & 0xff);
    return this;
  }
  u64(n) {
    let v = BigInt(n);
    if (v < 0n || v >= 1n << 64n) throw new Error(`u64 out of range: ${n}`);
    for (let i = 0; i < 8; i++, v >>= 8n) this.#out.push(Number(v & 0xffn));
    return this;
  }
  bytes(b) {
    for (const x of b) this.#out.push(x);
    return this;
  }
  string(s) {
    const b = utf8.encode(s);
    return this.u32(b.length).bytes(b);
  }
  done() {
    return Uint8Array.from(this.#out);
  }
}

const CALLERS = ["agent", "owner", "relayer"];
const OUTCOMES = ["spent", "released"];

/** borsh((agent: String,)) for `revoke`. */
export function revokeArgs(agent) {
  return new Writer().string(agent).done();
}

/** borsh((key: RequestKey, outcome: ResolveOutcome)) for `resolve_reservation`. */
export function resolveArgs(key, outcome) {
  const c = CALLERS.indexOf(key?.caller?.kind);
  if (c < 0) throw new Error(`unknown caller: ${JSON.stringify(key?.caller)}`);
  const o = OUTCOMES.indexOf(outcome);
  if (o < 0) throw new Error(`unknown outcome: ${outcome}`);
  const w = new Writer().string(key.agent).u8(c);
  if (key.caller.kind === "relayer") w.string(key.caller.account);
  return w.string(key.request_id).u8(o).done();
}

/**
 * Held-queue decisions are not contract calls, but they are signed with the same §2 challenge
 * under this method name, which no contract method has (so neither signature works for the other).
 */
export const HELD_DECIDE_METHOD = "held_decide";
const DECISIONS = ["approved", "rejected"];

/** borsh((id: String, status: u8)) for a held-queue decision; approved=0, rejected=1. */
export function heldDecideArgs(id, status) {
  const d = DECISIONS.indexOf(status);
  if (d < 0) throw new Error(`status must be approved or rejected, got ${JSON.stringify(status)}`);
  return new Writer().string(id).u8(d).done();
}

async function sha256(bytes) {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
}

/** sha256("zold-mandate-v1" || contract_id || network || method || args || owner_nonce || expires_at). */
export async function ownerChallenge(contractId, network, method, args, ownerNonce, expiresAt) {
  const tail = new Writer().u64(ownerNonce).u64(expiresAt).done();
  const parts = [utf8.encode(OWNER_CHALLENGE_DOMAIN + contractId + network + method), args, tail];
  const pre = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    pre.set(p, at);
    at += p.length;
  }
  return sha256(pre);
}

export function b64(bytes) {
  let s = "";
  for (const x of bytes) s += String.fromCharCode(x);
  return btoa(s);
}

export function b64url(bytes) {
  return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The browser's DER ECDSA signature as the raw 64-byte `r || s` the contract takes. */
export function derToRaw(der) {
  const d = der instanceof Uint8Array ? der : new Uint8Array(der);
  const fail = () => {
    throw new Error("malformed DER signature");
  };
  if (d.length < 8 || d[0] !== 0x30 || d[1] !== d.length - 2) fail();
  const out = new Uint8Array(64);
  let at = 2;
  for (const slot of [0, 32]) {
    if (d[at] !== 0x02) fail();
    const len = d[at + 1];
    let int = d.subarray(at + 2, at + 2 + len);
    if (len === 0 || int.length !== len) fail();
    while (int.length > 1 && int[0] === 0) int = int.subarray(1);
    if (int.length > 32) fail();
    out.set(int, slot + 32 - int.length);
    at += 2 + len;
  }
  if (at !== d.length) fail();
  return out;
}

/**
 * Signs one owner call with the passkey and returns `{ method, args, assertion }` for the
 * relayer. `config` is the contract's `get_config()`; the nonce comes from it, so read it
 * fresh before every call. A held decision passes the held queue's own `ownerNonce`.
 */
export async function signOwnerCall({ config, contractId, method, args, borshArgs, credentials, origin, nowMs, ownerNonce }) {
  if (config?.owner?.mode !== "passkey") throw new Error("the contract has a wallet owner; the dashboard signs passkey owner calls only");
  if (origin !== config.owner.origin) {
    throw new Error(`refusing to sign: this page is ${origin}, but the contract's owner origin is ${config.owner.origin}`);
  }
  const owner_nonce = ownerNonce ?? config.owner_nonce + 1;
  const expires_at = Math.floor(nowMs / 1000) + ASSERTION_TTL_SECS;
  const challenge = await ownerChallenge(contractId, config.network, method, borshArgs, owner_nonce, expires_at);
  const cred = await credentials.get({
    publicKey: { challenge, rpId: config.owner.rp_id, userVerification: "required", timeout: 120_000 },
  });
  if (!cred) throw new Error("no passkey assertion");
  const client_data_json = new TextDecoder().decode(cred.response.clientDataJSON);
  const client = JSON.parse(client_data_json);
  if (client.type !== "webauthn.get" || client.challenge !== b64url(challenge)) {
    throw new Error("the authenticator signed a different challenge");
  }
  return {
    method,
    args,
    assertion: {
      authenticator_data: b64(new Uint8Array(cred.response.authenticatorData)),
      client_data_json,
      signature: b64(derToRaw(cred.response.signature)),
      owner_nonce,
      expires_at,
    },
  };
}
