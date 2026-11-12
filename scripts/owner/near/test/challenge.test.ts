// The assertion builder must produce the exact bytes the contract checks. The vectors come
// from the contract crate itself: the worked vector in docs/interfaces.md §2 (which
// contract/tests/c2_owner.rs asserts), and the assertion that c2_owner.rs's `Signing::sign`
// builds for `valid_assertion_is_accepted_from_any_submitter_and_consumes_the_nonce`
// (key 0x11 * 32, set_relayer("relayer-demo.testnet"), owner_nonce 1, expires_at 1793600000),
// printed with the contract's own `owner_challenge` and the `p256` crate.
import assert from "node:assert/strict";
import { test } from "node:test";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { setRelayerArgs } from "../src/borsh.ts";
import { buildAssertion, challengePreimage, compressedPublicKey, ownerChallenge, softwareSigner } from "../src/challenge.ts";

const relayerArgs = setRelayerArgs("relayer-demo.testnet");
const VECTOR = ["mandate-demo.testnet", "testnet", "set_relayer", relayerArgs, 1, 1_793_600_000] as const;
const OWNER_SECRET = new Uint8Array(32).fill(0x11);
const INPUT = {
  contractId: "mandate-demo.testnet",
  network: "testnet",
  method: "set_relayer",
  args: relayerArgs,
  ownerNonce: 1,
  expiresAt: 1_793_600_000,
  rpId: "localhost",
  origin: "http://localhost:5173",
};

test("preimage and challenge match the worked vector in interfaces.md", () => {
  assert.equal(
    bytesToHex(challengePreimage(...VECTOR)),
    "7a6f6c642d6d616e646174652d76316d616e646174652d64656d6f2e746573746e6574746573746e65747365745f72656c61796572011400000072656c617965722d64656d6f2e746573746e65740100000000000000002ae86a00000000",
  );
  const c = ownerChallenge(...VECTOR);
  assert.equal(bytesToHex(c), "ec27a25ee1455067baa5daecd431d5c72f6b40842bf3c0df9a8c284b17bd72c5");
  assert.equal(Buffer.from(c).toString("base64url"), "7CeiXuFFUGe6pdrs1DHVxy9rQIQr88DfmowoSxe9csU");
});

test("assertion is byte-equal to the one the contract tests accept", () => {
  assert.equal(bytesToHex(compressedPublicKey(OWNER_SECRET)), "020217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed");
  const a = buildAssertion(INPUT, softwareSigner(OWNER_SECRET));
  assert.deepEqual(a, {
    authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2MFAAAAAA==",
    client_data_json:
      '{"type":"webauthn.get","challenge":"7CeiXuFFUGe6pdrs1DHVxy9rQIQr88DfmowoSxe9csU","origin":"http://localhost:5173","crossOrigin":false}',
    // RFC 6979 deterministic, so equal to the p256 crate's signature, S not normalised.
    signature: "Tk11ePmLZyLmSi6GOdt4Je1/MJO2SaCtq48QR+d6upIfnG2C8IXKAD2PTrqSx2BJ0fyQt4IFUUX542nMTQU92A==",
    owner_nonce: 1,
    expires_at: 1_793_600_000,
  });
});

test("signature verifies as the contract checks it: p256(sha256(authData || sha256(clientDataJSON)))", () => {
  const a = buildAssertion(INPUT, softwareSigner(OWNER_SECRET));
  const authData = Buffer.from(a.authenticator_data, "base64");
  assert.equal(authData.length, 37);
  assert.deepEqual(authData.subarray(0, 32), Buffer.from(sha256(new TextEncoder().encode("localhost"))));
  assert.equal(authData[32]! & 0x01, 1, "user present");
  const prehash = sha256(Buffer.concat([authData, sha256(new TextEncoder().encode(a.client_data_json))]));
  const sig = Buffer.from(a.signature, "base64");
  assert.equal(sig.length, 64);
  assert.ok(p256.verify(sig, prehash, compressedPublicKey(OWNER_SECRET), { prehash: false, lowS: false }));
});

test("every bound field changes the challenge", () => {
  const base = bytesToHex(ownerChallenge(...VECTOR));
  const variants: Parameters<typeof ownerChallenge>[] = [
    ["mandate-demo2.testnet", "testnet", "set_relayer", relayerArgs, 1, 1_793_600_000],
    ["mandate-demo.testnet", "mainnet", "set_relayer", relayerArgs, 1, 1_793_600_000],
    ["mandate-demo.testnet", "testnet", "revoke", relayerArgs, 1, 1_793_600_000],
    ["mandate-demo.testnet", "testnet", "set_relayer", setRelayerArgs("evil.testnet"), 1, 1_793_600_000],
    ["mandate-demo.testnet", "testnet", "set_relayer", relayerArgs, 2, 1_793_600_000],
    ["mandate-demo.testnet", "testnet", "set_relayer", relayerArgs, 1, 1_793_600_001],
  ];
  for (const v of variants) assert.notEqual(bytesToHex(ownerChallenge(...v)), base, JSON.stringify(v.slice(0, 3)));
});

test("a signer that does not return raw r || s is refused", () => {
  assert.throws(() => buildAssertion(INPUT, () => new Uint8Array(70)), /64-byte/);
});
