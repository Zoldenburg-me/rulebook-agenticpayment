import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { setRelayerArgs } from "@nearh/owner-near/src/borsh.ts";
import { buildAssertion, compressedPublicKey, softwareSigner } from "@nearh/owner-near/src/challenge.ts";
import { FileJournal, MemoryJournal } from "../src/journal.ts";
import { relayOwnerCall, type SignedOwnerCall } from "../src/owner-call.ts";
import { FakeNear, nearSigner } from "./fakes.ts";

const CONTRACT = "mandate-demo.testnet";
const OWNER_SECRET = new Uint8Array(32).fill(0x11); // the contract tests' key (c2_owner.rs)
const NOW = 1793600000;

function setup(ownerNonce = 4) {
  const near = new FakeNear();
  const state = { ownerNonce, mode: "passkey" };
  near.views.get_config = () =>
    state.mode === "passkey"
      ? { owner: { mode: "passkey", public_key: Buffer.from(compressedPublicKey(OWNER_SECRET)).toString("base64"), rp_id: "localhost", origin: "http://localhost:5173" }, owner_nonce: state.ownerNonce, network: "testnet" }
      : { owner: { mode: "wallet", account: "sme-owner.testnet" }, owner_nonce: state.ownerNonce, network: "testnet" };
  // The contract consumes the nonce only when the call succeeds.
  near.onSend = (tx) => {
    const a = JSON.parse(tx.args).assertion;
    state.ownerNonce = a.owner_nonce;
    return { SuccessValue: "" };
  };
  const submitter = nearSigner("submitter-demo.testnet", 0x22);
  const deps = { near: near.rpc, contractId: CONTRACT, submitter, journal: new MemoryJournal(), nowSecs: () => NOW, pollMs: 0 };
  return { near, state, deps, submitter };
}

function signedSetRelayer(account: string | null, ownerNonce = 5, secret = OWNER_SECRET): SignedOwnerCall {
  const assertion = buildAssertion(
    { contractId: CONTRACT, network: "testnet", method: "set_relayer", args: setRelayerArgs(account), ownerNonce, expiresAt: NOW + 300, rpId: "localhost", origin: "http://localhost:5173" },
    softwareSigner(secret),
  );
  return { method: "set_relayer", args: { account }, assertion };
}

test("a signed owner call is submitted once, byte for byte, by the submitter", async () => {
  const { near, deps, submitter } = setup();
  const call = signedSetRelayer("relayer-demo.testnet");
  const r = await relayOwnerCall(deps, call);
  assert.equal(r.ownerNonce, 5);
  assert.equal(near.sent.length, 1);
  const tx = near.sent[0];
  assert.equal(tx.method, "set_relayer");
  assert.equal(tx.args, JSON.stringify({ account: "relayer-demo.testnet", assertion: call.assertion }));
  // The tx is signed by the submitter's key over sha256(tx bytes).
  const body = tx.signed.subarray(0, tx.signed.length - 65);
  assert.equal(tx.signed[tx.signed.length - 65], 0);
  assert.ok(ed25519.verify(tx.signed.subarray(tx.signed.length - 64), sha256(body), submitter.publicKey));

  await assert.rejects(relayOwnerCall(deps, call), /already used|already relayed/);
  assert.equal(near.sent.length, 1, "a second relay of the same call sends nothing");
});

test("the journal stops a resend after a restart, even before the contract's nonce moves", async () => {
  const dir = mkdtempSync(join(tmpdir(), "relayer-"));
  const path = join(dir, "journal");
  const call = signedSetRelayer("relayer-demo.testnet");
  {
    const { near, deps } = setup();
    near.onSend = () => ({ SuccessValue: "" }); // nonce never moves: the view still says 4
    await assert.rejects(relayOwnerCall({ ...deps, journal: new FileJournal(path) }, call), /state check failed/);
    assert.equal(near.sent.length, 1);
  }
  const { near, deps } = setup();
  await assert.rejects(relayOwnerCall({ ...deps, journal: new FileJournal(path) }, call), /already relayed/);
  assert.equal(near.sent.length, 0);
  assert.equal(statSync(path).mode & 0o777, 0o700);
  const files = readdirSync(path);
  assert.equal(files.length, 1);
  assert.equal(statSync(join(path, files[0])).mode & 0o777, 0o600);
});

test("two journals on one directory cannot both claim an id (exclusive create)", () => {
  const dir = join(mkdtempSync(join(tmpdir(), "relayer-")), "journal");
  const a = new FileJournal(dir);
  const b = new FileJournal(dir);
  a.claim("eure-gas:0xabc:0");
  assert.throws(() => b.claim("eure-gas:0xabc:0"), /already relayed/);
  b.claim("eure-gas:0xabc:1");
});

test("back-to-back calls use increasing NEAR nonces even if the node still shows the old one", async () => {
  const { near, deps } = setup();
  await relayOwnerCall(deps, signedSetRelayer("relayer-demo.testnet", 5));
  await relayOwnerCall(deps, signedSetRelayer("relayer-demo.testnet", 6));
  // The fake node always reports access-key nonce 7.
  const nonces = near.sent.map((t) => t.nonce);
  assert.equal(nonces.length, 2);
  assert.ok(nonces[0] >= 8n && nonces[1] === nonces[0] + 1n, `nonces ${nonces}`);
});

test("a tampered call is refused before anything is sent", async () => {
  const cases: [string, (c: SignedOwnerCall) => void][] = [
    ["changed arg", (c) => (c.args.account = "attacker.testnet")],
    ["changed method", (c) => (c.method = "revoke")],
    ["extra arg", (c) => (c.args.extra = 1)],
    ["changed nonce", (c) => (c.assertion.owner_nonce = 6)],
    ["changed expiry", (c) => (c.assertion.expires_at += 1)],
    ["flipped signature byte", (c) => {
      const s = Buffer.from(c.assertion.signature, "base64");
      s[10] ^= 1;
      c.assertion.signature = s.toString("base64");
    }],
    ["changed authenticator data", (c) => {
      const s = Buffer.from(c.assertion.authenticator_data, "base64");
      s[32] = 0x04;
      c.assertion.authenticator_data = s.toString("base64");
    }],
    ["not a JSON client data", (c) => (c.assertion.client_data_json = "x")],
  ];
  for (const [name, tamper] of cases) {
    const { near, deps } = setup();
    const call = signedSetRelayer("relayer-demo.testnet");
    tamper(call);
    await assert.rejects(relayOwnerCall(deps, call), Error, name);
    assert.equal(near.sent.length, 0, name);
  }
});

test("a call signed by another key, stale, expired, or for a wallet owner is refused", async () => {
  {
    const { near, deps } = setup();
    await assert.rejects(relayOwnerCall(deps, signedSetRelayer("r.testnet", 5, new Uint8Array(32).fill(0x33))), /not signed by the contract's owner/);
    assert.equal(near.sent.length, 0);
  }
  {
    const { near, deps } = setup(5);
    await assert.rejects(relayOwnerCall(deps, signedSetRelayer("r.testnet", 5)), /already used/);
    assert.equal(near.sent.length, 0);
  }
  {
    const { near, deps } = setup();
    await assert.rejects(relayOwnerCall({ ...deps, nowSecs: () => NOW + 301 }, signedSetRelayer("r.testnet")), /expired/);
    assert.equal(near.sent.length, 0);
  }
  {
    const { near, deps, state } = setup();
    state.mode = "wallet";
    await assert.rejects(relayOwnerCall(deps, signedSetRelayer("r.testnet")), /wallet owner/);
    assert.equal(near.sent.length, 0);
  }
  {
    const { near, deps } = setup();
    const call = signedSetRelayer("r.testnet");
    await assert.rejects(relayOwnerCall(deps, { ...call, method: "request_signature" }), /not a relayable owner method/);
    await assert.rejects(relayOwnerCall(deps, { ...call, method: "__proto__" }), /not a relayable owner method/);
    assert.equal(near.sent.length, 0);
  }
});

test("a call the contract rejects is reported as rejected, and not retried", async () => {
  const { near, deps } = setup();
  near.onSend = () => ({ Failure: { ActionError: { kind: { FunctionCallError: { ExecutionError: "Smart contract panicked: ERR_ASSERTION_EXPIRED" } } } } });
  const call = signedSetRelayer("relayer-demo.testnet");
  await assert.rejects(relayOwnerCall(deps, call), /rejected by the contract.*ERR_ASSERTION_EXPIRED/);
  await assert.rejects(relayOwnerCall(deps, call), /already relayed/);
  assert.equal(near.sent.length, 1);
});

test("a call the contract rejected does not block the owner's next call at the same nonce", async () => {
  const { near, state, deps } = setup();
  let reject = true;
  near.onSend = (tx) => {
    if (reject) return { Failure: { ActionError: { kind: { FunctionCallError: { ExecutionError: "Smart contract panicked: ERR_ASSERTION_BAD_ORIGIN" } } } } };
    state.ownerNonce = JSON.parse(tx.args).assertion.owner_nonce;
    return { SuccessValue: "" };
  };
  await assert.rejects(relayOwnerCall(deps, signedSetRelayer("relayer-demo.testnet")), /rejected by the contract/);
  reject = false;
  // The contract's nonce did not move, so the owner signs the next call with the same nonce.
  const r = await relayOwnerCall(deps, signedSetRelayer("other-relayer.testnet"));
  assert.equal(r.ownerNonce, 5);
  assert.equal(near.sent.length, 2);
});

test("the same signed call with a malleated (high-s) signature is still refused by the journal", async () => {
  const { near, deps } = setup();
  near.onSend = () => ({ Failure: { ActionError: { kind: { FunctionCallError: { ExecutionError: "Smart contract panicked: ERR_ASSERTION_EXPIRED" } } } } });
  const call = signedSetRelayer("relayer-demo.testnet");
  await assert.rejects(relayOwnerCall(deps, call), /rejected by the contract/);
  const sig = Buffer.from(call.assertion.signature, "base64");
  const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n; // P-256 order
  const s = BigInt("0x" + sig.subarray(32).toString("hex"));
  const flipped = Buffer.concat([sig.subarray(0, 32), Buffer.from((n - s).toString(16).padStart(64, "0"), "hex")]);
  const malleated = { ...call, assertion: { ...call.assertion, signature: flipped.toString("base64") } };
  await assert.rejects(relayOwnerCall(deps, malleated), /already relayed/);
  assert.equal(near.sent.length, 1);
});

test("the borsh args of sweep and resolve_reservation match the contract's layout", async () => {
  // A sweep call signed over this layout passes; the same call with a different evm_tx does not.
  const { Writer } = await import("@nearh/owner-near/src/borsh.ts");
  const args = { agent: "agent-1", token: "eure", amount: "10", request_id: "s-1", evm_tx: { nonce: 0, gas_limit: 80000, max_fee_per_gas: "2000000000", max_priority_fee_per_gas: "1000000" } };
  const borsh = new Writer().string("agent-1").u8(1).u128(10).string("s-1").u8(1).u64(0).u64(80000).u128(2000000000).u128(1000000).done();
  const assertion = buildAssertion(
    { contractId: CONTRACT, network: "testnet", method: "sweep", args: borsh, ownerNonce: 5, expiresAt: NOW + 300, rpId: "localhost", origin: "http://localhost:5173" },
    softwareSigner(OWNER_SECRET),
  );
  const { near, deps } = setup();
  await relayOwnerCall(deps, { method: "sweep", args, assertion });
  assert.equal(near.sent.length, 1);
  const { deps: deps2, near: near2 } = setup();
  await assert.rejects(relayOwnerCall(deps2, { method: "sweep", args: { ...args, evm_tx: { ...args.evm_tx, gas_limit: 150000 } }, assertion }), /does not sign/);
  assert.equal(near2.sent.length, 0);

  const key = { agent: "agent-1", caller: { kind: "relayer", account: "relayer-demo.testnet" }, request_id: "s-1" };
  const rb = new Writer().string("agent-1").u8(2).string("relayer-demo.testnet").string("s-1").u8(1).done();
  const ra = buildAssertion(
    { contractId: CONTRACT, network: "testnet", method: "resolve_reservation", args: rb, ownerNonce: 5, expiresAt: NOW + 300, rpId: "localhost", origin: "http://localhost:5173" },
    softwareSigner(OWNER_SECRET),
  );
  const { deps: deps3, near: near3 } = setup();
  await relayOwnerCall(deps3, { method: "resolve_reservation", args: { key, outcome: "released" }, assertion: ra });
  assert.equal(near3.sent.length, 1);
});
