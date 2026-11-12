// O2 with NEAR testnet RPC and the Monerium sandbox both mocked: the views go through the O1
// JSON-RPC code against a stubbed global fetch, the owner call is stubbed, and Monerium gets its
// own fetch. The link signature is a real secp256k1 signature over the EIP-191 link digest.
import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { publicKeyToAddress } from "@nearh/owner-near/src/derive.ts";
import type { Config } from "@nearh/owner-near/src/near.ts";
import { linkAgentToMonerium, linkDigest, linkSignature, resolveProfile, type Reservation } from "../src/link.ts";
import { API, LINK_MESSAGE, MoneriumError, refusal, sandboxClient } from "../src/monerium.ts";
import { LINK_AGENT_GAS, nearClient } from "../src/near.ts";

const CFG: Config = { rpc: "https://rpc.testnet.near.org", contractId: "mandate.testnet", mpcContract: "v1.signer-prod.testnet", keyDir: "/k" };
const PROFILE = "11111111-2222-3333-4444-55555555ab78";
const AGENT = "agent-1";
const KEY = secp256k1.utils.randomSecretKey();
const ADDRESS = publicKeyToAddress(secp256k1.getPublicKey(KEY, false));
const OTHER = publicKeyToAddress(secp256k1.getPublicKey(secp256k1.utils.randomSecretKey(), false));
const DIGEST = `0x${bytesToHex(linkDigest())}`;

function signLink(key = KEY) {
  const sig = secp256k1.sign(linkDigest(), key, { prehash: false, format: "recovered" });
  return { r: `0x${bytesToHex(sig.slice(1, 33))}`, s: `0x${bytesToHex(sig.slice(33))}`, v: 27 + sig[0] };
}

const reservation = (over: Partial<Reservation> = {}): Reservation => ({
  key: { agent: AGENT, caller: { kind: "owner" }, request_id: "link-1000" },
  shape: "link",
  created_at_ms: 1000,
  digest: DIGEST,
  status: "signed",
  signature: signLink(),
  ...over,
});

/** Contract state the mocked RPC serves; `link_agent` mutates it like the contract does. */
type Chain = { agent: any; requests: Reservation[]; ownerNonce: number; calls: string[]; ownerCalls: any[] };
let chain: Chain;
const realFetch = globalThis.fetch;

beforeEach(() => {
  chain = {
    agent: { agent: AGENT, evm_address: ADDRESS, linked: false, revoked: false },
    requests: [],
    ownerNonce: 4,
    calls: [],
    ownerCalls: [],
  };
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    assert.equal(url, CFG.rpc);
    const { params } = JSON.parse(String(init.body));
    assert.equal(params.request_type, "call_function");
    const args = JSON.parse(Buffer.from(params.args_base64, "base64").toString());
    chain.calls.push(params.method_name);
    const out =
      params.method_name === "get_agent"
        ? (assert.equal(args.agent, AGENT), chain.agent)
        : params.method_name === "list_requests"
          ? chain.requests.slice(args.from_index, args.from_index + args.limit)
          : params.method_name === "get_config"
            ? { owner_nonce: chain.ownerNonce }
            : assert.fail(`unexpected view ${params.method_name}`);
    const result = [...Buffer.from(JSON.stringify(out))];
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { result } }));
  }) as typeof fetch;
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

/** Stands in for O1's ownerCall: records the call; `land` applies link_agent to the chain. */
function ownerCall(land: (c: Chain) => void = linkLands) {
  return async (_cfg: Config, method: string, json: Record<string, unknown>, borsh: Uint8Array, gas?: string) => {
    chain.ownerCalls.push({ method, json, borsh: bytesToHex(borsh), gas });
    const nonce = chain.ownerNonce + 1;
    land(chain);
    return { txHash: "LinkTx111", nonce };
  };
}
function linkLands(c: Chain) {
  c.ownerNonce += 1;
  c.agent.linked = true;
  c.requests.push(reservation({ created_at_ms: 2000, key: { agent: AGENT, caller: { kind: "owner" }, request_id: "link-2000" } }));
}

type Reply = { status: number; body?: unknown };
/** Monerium sandbox mock: `addresses` is what GET /addresses lists; `post` answers POST /addresses. */
function monerium(opts: { addresses?: () => unknown[]; post?: Reply; token?: Reply } = {}) {
  const seen: { method: string; path: string; body?: any; auth?: string }[] = [];
  const reply = (r: Reply) => new Response(r.body === undefined ? "" : JSON.stringify(r.body), { status: r.status });
  const fetcher = (async (url: string, init: RequestInit) => {
    assert.ok(url.startsWith(`${API}/`), url);
    const path = url.slice(API.length);
    const headers = init.headers as Record<string, string>;
    const body = path === "/auth/token" ? String(init.body) : init.body ? JSON.parse(String(init.body)) : undefined;
    seen.push({ method: String(init.method), path, body, auth: headers.authorization });
    if (path === "/auth/token") return reply(opts.token ?? { status: 200, body: { access_token: "mock-access" } });
    assert.equal(headers.authorization, "Bearer mock-access");
    if (path === "/auth/context") return reply({ status: 200, body: { defaultProfile: PROFILE, profiles: [{ id: PROFILE }] } });
    if (path === "/addresses" && init.method === "GET") return reply({ status: 200, body: { addresses: opts.addresses?.() ?? [] } });
    if (path === "/addresses" && init.method === "POST") return reply(opts.post ?? { status: 201, body: { address: ADDRESS } });
    return assert.fail(`unexpected Monerium call ${init.method} ${path}`);
  }) as typeof fetch;
  const client = sandboxClient(
    { MONERIUM_ENVIRONMENT: "sandbox", MONERIUM_CLIENT_ID: "id", MONERIUM_CLIENT_SECRET: "fake" },
    fetcher,
  );
  return { client, seen, posts: () => seen.filter((s) => s.method === "POST" && s.path === "/addresses") };
}

const listed = (address = ADDRESS) => ({ profile: PROFILE, address, chains: ["basesepolia"] });
const opts = { pollMs: 0, maxPolls: 3 };

async function run(m: ReturnType<typeof monerium>, call = ownerCall()) {
  await m.client.authenticate();
  return linkAgentToMonerium(nearClient(CFG, call as any), m.client, AGENT, PROFILE, opts);
}

test("fresh agent: owner calls link_agent, the signed link is posted, 201 is linked", async () => {
  const m = monerium();
  const r = await run(m);
  assert.deepEqual(r, { result: "linked", address: ADDRESS, status: 201, requestId: "link-2000", txHash: "LinkTx111" });
  assert.equal(chain.ownerCalls.length, 1);
  const c = chain.ownerCalls[0];
  assert.equal(c.method, "link_agent");
  assert.deepEqual(c.json, { agent: AGENT });
  assert.equal(c.borsh, "070000006167656e742d31"); // borsh (String,) of "agent-1"
  assert.equal(c.gas, LINK_AGENT_GAS);
  const [post] = m.posts();
  assert.deepEqual(Object.keys(post.body).sort(), ["address", "chain", "message", "profile", "signature"]);
  assert.equal(post.body.profile, PROFILE);
  assert.equal(post.body.address, ADDRESS);
  assert.equal(post.body.chain, "basesepolia");
  assert.equal(post.body.message, LINK_MESSAGE);
  assert.match(post.body.signature, /^0x[0-9a-f]{128}(1b|1c)$/);
  // The posted signature recovers to the agent EOA.
  assert.equal(linkSignature(chain.requests[0].signature!, ADDRESS), post.body.signature);
});

test("202 from Monerium is reported as pending verification", async () => {
  const m = monerium({ post: { status: 202, body: {} } });
  const r = await run(m);
  assert.equal(r.result, "pending_verification");
  assert.equal((r as any).status, 202);
});

test("a 4xx is surfaced with Monerium's code and message, redacted, and never the token or secret", async () => {
  const m = monerium({ post: { status: 400, body: { code: 400, status: "Bad Request", message: `Signature 0xdeadbeef invalid for ${ADDRESS}` } } });
  const err = await run(m).then(() => assert.fail("expected a refusal"), (e) => e);
  assert.ok(err instanceof MoneriumError);
  assert.equal(err.status, 400);
  assert.deepEqual(err.refusal, { code: 400, message: "Signature <HEX> invalid for <HEX>" });
  assert.equal(err.message, "Link address refused by Monerium (HTTP 400, 400: Signature <HEX> invalid for <HEX>)");
  assert.doesNotMatch(err.message, /mock-access|fake/);
});

test("other 2xx statuses are not taken as linked", async () => {
  const m = monerium({ post: { status: 200, body: {} } });
  await assert.rejects(run(m), /HTTP 200, expected 201 or 202/);
});

test("already linked on Monerium: nothing is called on NEAR and nothing is posted", async () => {
  const m = monerium({ addresses: () => [listed(ADDRESS.toUpperCase().replace("0X", "0x"))] });
  const r = await run(m);
  assert.deepEqual(r, { result: "already_linked", address: ADDRESS });
  assert.equal(chain.ownerCalls.length, 0);
  assert.equal(m.posts().length, 0);
});

test("an address on another profile or chain does not count as linked", async () => {
  const m = monerium({
    addresses: () => [
      { ...listed(), profile: "99999999-2222-3333-4444-555555555555" },
      { ...listed(), chains: ["ethereum"] },
    ],
  });
  assert.equal((await run(m)).result, "linked");
});

test("linked on the contract already (ERR_ALREADY_LINKED): the signed link is reused, link_agent is not called", async () => {
  chain.agent.linked = true;
  chain.requests = [reservation()];
  const m = monerium();
  const r = await run(m);
  assert.equal(r.result, "linked");
  assert.equal((r as any).requestId, "link-1000");
  assert.equal("txHash" in r, false);
  assert.equal(chain.ownerCalls.length, 0);
  assert.equal(m.posts().length, 1);
});

test("Monerium refuses with 4xx because the address got listed meanwhile: reported as already linked", async () => {
  let posted = false;
  const m = monerium({ addresses: () => (posted ? [listed()] : []), post: { status: 409, body: { code: 409, message: "Address already linked" } } });
  const real = m.client.request;
  m.client.request = async (method, path, body) => {
    const res = await real(method, path, body);
    if (method === "POST" && path === "/addresses") posted = true;
    return res;
  };
  assert.deepEqual(await run(m), { result: "already_linked", address: ADDRESS });
});

test("a link signature that does not recover to the agent EOA is never posted", async () => {
  chain.agent.evm_address = OTHER;
  const m = monerium();
  await assert.rejects(run(m), /recovers to 0x[0-9a-f]{40}, not the agent EOA/);
  assert.equal(m.posts().length, 0);
});

test("a reservation whose digest is not the link message is never posted", async () => {
  chain.agent.linked = true;
  chain.requests = [reservation({ digest: `0x${"00".repeat(32)}` })];
  const m = monerium();
  await assert.rejects(run(m), /digest is not the link message/);
  assert.equal(m.posts().length, 0);
});

test("only owner link reservations count: an agent-caller or non-link signed request is ignored", async () => {
  chain.requests = [
    reservation({ key: { agent: AGENT, caller: { kind: "agent" }, request_id: "x-1" } }),
    reservation({ shape: "x402" }),
  ];
  const m = monerium();
  const r = await run(m);
  assert.equal(chain.ownerCalls.length, 1);
  assert.equal((r as any).requestId, "link-2000");
});

test("the MPC callback failed (unknown, linked reset): it says to run link again and posts nothing", async () => {
  const m = monerium();
  const call = ownerCall((c) => {
    c.ownerNonce += 1;
    c.requests.push(reservation({ created_at_ms: 2000, status: "unknown", signature: null }));
  });
  await assert.rejects(run(m, call), /ended unknown; the contract reset linked, run link again/);
  assert.equal(m.posts().length, 0);
});

test("a link still pending after the polls stops without posting", async () => {
  const m = monerium();
  const call = ownerCall((c) => {
    c.ownerNonce += 1;
    c.agent.linked = true;
    c.requests.push(reservation({ created_at_ms: 2000, status: "pending", signature: null }));
  });
  await assert.rejects(run(m, call), /still pending; rerun later/);
  assert.equal(m.posts().length, 0);
});

test("linked on the contract with the MPC still pending: waits for that request, does not call link_agent", async () => {
  chain.agent.linked = true;
  chain.requests = [reservation({ status: "pending", signature: null })];
  let polls = 0;
  const m = monerium();
  await m.client.authenticate();
  const near = nearClient(CFG, ownerCall() as any);
  near.sleep = async () => {
    if (++polls === 1) chain.requests[0] = reservation();
  };
  const r = await linkAgentToMonerium(near, m.client, AGENT, PROFILE, opts);
  assert.equal(r.result, "linked");
  assert.equal(chain.ownerCalls.length, 0);
});

test("revoked, unknown or EOA-less agents are refused before anything is sent", async () => {
  for (const [agent, re] of [
    [{ ...chain.agent, revoked: true }, /is revoked/],
    [null, /no agent agent-1/],
    [{ ...chain.agent, evm_address: null }, /has no evm_address/],
  ] as const) {
    chain.agent = agent;
    const m = monerium();
    await assert.rejects(run(m), re);
    assert.equal(m.seen.filter((s) => s.path !== "/auth/token").length, 0);
    assert.equal(chain.ownerCalls.length, 0);
  }
});

test("link_agent that never lands (owner_nonce not consumed) fails instead of waiting for a reservation", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const m = monerium();
  await m.client.authenticate();
  const near = nearClient(CFG, ownerCall(() => {}) as any);
  const p = assert.rejects(linkAgentToMonerium(near, m.client, AGENT, PROFILE, opts), /link_agent landed/);
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setImmediate(r));
    t.mock.timers.tick(2000);
  }
  await p;
  assert.equal(m.posts().length, 0);
});

test("profile: MONERIUM_PROFILE_ID or the default, and it must be accessible", async () => {
  const m = monerium();
  await m.client.authenticate();
  assert.equal(await resolveProfile(m.client), PROFILE);
  assert.equal(await resolveProfile(m.client, PROFILE), PROFILE);
  await assert.rejects(resolveProfile(m.client, "99999999-2222-3333-4444-555555555555"), /not a profile this sandbox app can access/);
});

test("a refused authentication is surfaced with the OAuth error, without the secret", async () => {
  const m = monerium({ token: { status: 401, body: { error: "invalid_client", error_description: "Client authentication failed" } } });
  const err = await m.client.authenticate().then(() => assert.fail("expected a refusal"), (e) => e);
  assert.ok(err instanceof MoneriumError);
  assert.equal(err.message, "Sandbox authentication refused by Monerium (HTTP 401, invalid_client: Client authentication failed)");
  assert.doesNotMatch(err.message, /fake/);
});

test("the client is sandbox and Base Sepolia only, and needs credentials", () => {
  const ok = { MONERIUM_ENVIRONMENT: "sandbox", MONERIUM_CLIENT_ID: "id", MONERIUM_CLIENT_SECRET: "s" };
  assert.throws(() => sandboxClient({ ...ok, MONERIUM_ENVIRONMENT: "production" }), /must be sandbox/);
  assert.throws(() => sandboxClient({ ...ok, MONERIUM_BASE_URL: "https://api.monerium.app" }), /only the Monerium sandbox API/);
  assert.throws(() => sandboxClient({ ...ok, MONERIUM_CHAIN: "ethereum" }), /only Base Sepolia/);
  assert.throws(() => sandboxClient({ ...ok, MONERIUM_CLIENT_SECRET: "" }), /set MONERIUM_CLIENT_ID/);
});

test("refusal keeps only code and message, with IBANs, hex and UUIDs redacted", () => {
  assert.deepEqual(refusal({ code: 400, message: "IBAN DE89 3704 0044 0532 0130 00 for 0xabc in 6668ee04-d891-11f1-a9cb-fa98e9983566", token: "t" }), {
    code: 400,
    message: "IBAN <IBAN …3000> for <HEX> in <UUID>",
  });
  assert.deepEqual(refusal("<html>"), {});
});

test("IBANs are redacted to the last 4 whatever their spacing, grouping or case", () => {
  const cases: [string, string][] = [
    ["IBAN DE89 3704 0044 0532 0130 00 rejected", "IBAN <IBAN …3000> rejected"],
    ["IBAN DE89370400440532013000 rejected", "IBAN <IBAN …3000> rejected"],
    ["IBAN de89 3704 0044 0532 0130 00 rejected", "IBAN <IBAN …3000> rejected"],
    ["iban de89370400440532013000.", "iban <IBAN …3000>."],
    ["IBAN DE89  3704\t0044 \u00a00532   0130 00 rejected", "IBAN <IBAN …3000> rejected"],
    ["IBAN DE89 37040044 053201 3000 rejected", "IBAN <IBAN …3000> rejected"],
    ["IBAN GB29 NWBK 6016 1331 9268 19 is closed", "IBAN <IBAN …6819> is closed"],
    ["from DE89 3704 0044 0532 0130 00 to FR14 2004 1010 0505 0001 3M02 606", "from <IBAN …3000> to <IBAN …2606>"],
    // Letter-heavy IBANs: few digits, letters in the bank code and the account.
    ["IBAN MT84 MALT 0110 0001 2345 MTLC AST0 01S rejected", "IBAN <IBAN …001S> rejected"],
    ["IBAN MT84MALT011000012345MTLCAST001S rejected", "IBAN <IBAN …001S> rejected"],
    ["IBAN LC55 HEMM 0001 0001 0012 0012 0002 3015 rejected", "IBAN <IBAN …3015> rejected"],
    ["IBAN gb82 west 1234 5698 7654 32 rejected", "IBAN <IBAN …5432> rejected"],
    ["IBAN GB33 BUKB 2020 1555 5555 55 rejected", "IBAN <IBAN …5555> rejected"],
    // A number right after the IBAN stays outside it, spaced or not.
    ["IBAN DE89 3704 0044 0532 0130 00 400", "IBAN <IBAN …3000> 400"],
    ["IBAN DE89 3704 0044 0532 0130 00\t400 rejected", "IBAN <IBAN …3000>\t400 rejected"],
    ["IBAN DE89 3704 0044 0532 0130 00400", "IBAN <IBAN …3000>400"],
    ["IBAN DE89370400440532013000 400", "IBAN <IBAN …3000> 400"],
    ["IBAN GB82 WEST 1234 5698 7654 32 404 not found", "IBAN <IBAN …5432> 404 not found"],
    ["IBAN nl91\u00a0abna\u00a00417\u00a01643\u00a000 409", "IBAN <IBAN …4300> 409"],
    // A mistyped IBAN of the right length is still hidden.
    ["IBAN DE00 3704 0044 0532 0130 00 rejected", "IBAN <IBAN …3000> rejected"],
    // A mistyped IBAN that fails its check and length is still hidden, without a last 4.
    ["IBAN DE00 3704 0044 0532 0130 00404", "IBAN <IBAN>"],
    ["IBAN DE00 3704 0044 0532 0130 00404 rejected", "IBAN <IBAN> rejected"],
    ["IBAN DE00370400440532013000404", "IBAN <IBAN>"],
    ["IBAN DE89 3704 0044 0532 0130 0 404", "IBAN <IBAN>"],
    ["IBAN DE89 3704 0044 0532 0130, rejected", "IBAN <IBAN>, rejected"],
    ["IBAN DE89 3704 0044 0532 0130", "IBAN <IBAN>"],
    ["IBAN DE89 3704 0044 0532 0130 0 rejected", "IBAN <IBAN>"],
    ["IBAN GB00 WEST 1234 5698 7654 32404", "IBAN <IBAN>"],
  ];
  for (const [input, message] of cases) assert.deepEqual(refusal({ message: input }), { message }, input);
  assert.deepEqual(refusal({ message: "HTTP 400: ab12 is not valid, retry in 30 s" }), { message: "HTTP 400: ab12 is not valid, retry in 30 s" });
  assert.deepEqual(refusal({ message: "DE12 is not allowed for this account" }), { message: "DE12 is not allowed for this account" });
});

test("a refused request never puts a spaced IBAN in the error message", () => {
  const err = new MoneriumError("Link address", 400, refusal({ code: "iban", message: "IBAN DE89 3704 0044 0532 0130 00 is blocked" }));
  assert.equal(err.message, "Link address refused by Monerium (HTTP 400, iban: IBAN <IBAN …3000> is blocked)");
  assert.doesNotMatch(err.message.replace(/\s+/g, ""), /370400440532/);
});

test("a refused request never puts a mistyped IBAN with a status code glued on in the error message", () => {
  const err = new MoneriumError("Link address", 400, refusal({ code: "iban", message: "IBAN DE00 3704 0044 0532 0130 00404 is blocked" }));
  assert.equal(err.message, "Link address refused by Monerium (HTTP 400, iban: IBAN <IBAN> is blocked)");
  assert.doesNotMatch(err.message.replace(/\s+/g, ""), /3704|0532|0130/);
});

test("IBANs grouped with -, ., / or NBSP are redacted, valid or mistyped", () => {
  const cases: [string, string][] = [];
  for (const sep of ["-", ".", "/", "\u00a0", " - "]) {
    const g = (iban: string) => iban.split(" ").join(sep);
    cases.push(
      [`IBAN ${g("DE89 3704 0044 0532 0130 00")} rejected`, "IBAN <IBAN …3000> rejected"],
      [`IBAN ${g("DE00 3704 0044 0532 0130 00")} rejected`, "IBAN <IBAN …3000> rejected"],
      [`IBAN ${g("DE00 3704 0044 0532 0130 00404")} rejected`, "IBAN <IBAN> rejected"],
      [`IBAN ${g("DE89 3704 0044 0532 0130")}, rejected`, "IBAN <IBAN>, rejected"],
    );
  }
  for (const [input, message] of cases) assert.deepEqual(refusal({ message: input }), { message }, input);
});

test("IBANs glued to a word are redacted", () => {
  const cases = [
    ["iban_DE89370400440532013000 rejected", "iban_<IBAN …3000> rejected"],
    ["IBANDE89370400440532013000 rejected", "IBAN<IBAN …3000> rejected"],
    ["ibande89 3704 0044 0532 0130 00 rejected", "iban<IBAN …3000> rejected"],
    ["IBANDE00370400440532013000404", "IBAN<IBAN>"],
  ];
  for (const [input, message] of cases) assert.deepEqual(refusal({ message: input }), { message }, input);
  assert.deepEqual(refusal({ message: "0xde89370400440532013000 rejected" }), { message: "<HEX> rejected" });
});

test("IBANs with an unknown or mistyped country code fail closed", () => {
  const cases = [
    ["IBAN DX89 3704 0044 0532 0130 00 rejected", "IBAN <IBAN> rejected"],
    ["IBAN DX89370400440532013000 rejected", "IBAN <IBAN> rejected"],
    // A number right after it is hidden too (the exact end is unknown).
    ["IBAN dx89-3704-0044-0532-0130-00 400", "IBAN <IBAN>"],
    ["IBAN QQ82 WEST 1234 5698 7654 32 is closed", "IBAN <IBAN> is closed"],
    // As short as Norway's (15 characters), grouped or not, and with a 3-letter group.
    ["IBAN XX93 8601 1117 947 rejected", "IBAN <IBAN> rejected"],
    ["IBAN XX9386011117947 rejected", "IBAN <IBAN> rejected"],
    ["IBAN QQ82 WES 1234 5698 7 rejected", "IBAN <IBAN> rejected"],
    ["IBAN QQ82WES123456987 rejected", "IBAN <IBAN> rejected"],
    ["IBAN qq82-wes-1234-5698-7 rejected", "IBAN <IBAN> rejected"],
    // Too short to be an IBAN: stays.
    ["code DX89 1234 rejected", "code DX89 1234 rejected"],
    ["HTTP 400: ab12 is not valid, retry in 30 s", "HTTP 400: ab12 is not valid, retry in 30 s"],
  ];
  for (const [input, message] of cases) assert.deepEqual(refusal({ message: input }), { message }, input);
});

test("linkSignature rejects malformed v, r and s", () => {
  const sig = signLink();
  assert.throws(() => linkSignature({ ...sig, v: 0 }, ADDRESS), /v must be 27 or 28/);
  assert.throws(() => linkSignature({ ...sig, r: "0xzz" }, ADDRESS), /r is not a 32-byte hex/);
  assert.throws(() => linkSignature({ ...sig, s: `0x${"1".repeat(65)}` }, ADDRESS), /s is not a 32-byte hex/);
});
