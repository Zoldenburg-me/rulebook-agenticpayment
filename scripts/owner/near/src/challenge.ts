// Owner-call challenge and WebAuthn assertion (docs/interfaces.md §2, contract/src/owner.rs).
// The scripts sign with a software P-256 key that stands in for the passkey; the bytes it
// signs are the ones a WebAuthn authenticator signs, so the contract cannot tell them apart.

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";

export const OWNER_CHALLENGE_DOMAIN = "zold-mandate-v1";
/** contract/src/types.rs MAX_ASSERTION_TTL_SECS. */
export const MAX_ASSERTION_TTL_SECS = 600;
/** User present (bit 0) | user verified (bit 2), as a passkey tap sets them. */
const FLAGS_UP_UV = 0x05;

export type OwnerAssertion = {
  authenticator_data: string; // base64
  client_data_json: string;
  signature: string; // base64 of raw r || s
  owner_nonce: number;
  expires_at: number;
};

const utf8 = (s: string) => new TextEncoder().encode(s);

function u64le(v: number | bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(v), true);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) {
    out.set(p, i);
    i += p.length;
  }
  return out;
}

/** The preimage of the challenge; exposed so the test can compare it with interfaces.md. */
export function challengePreimage(
  contractId: string,
  network: string,
  method: string,
  args: Uint8Array,
  ownerNonce: number | bigint,
  expiresAt: number | bigint,
): Uint8Array {
  return concat(
    utf8(OWNER_CHALLENGE_DOMAIN),
    utf8(contractId),
    utf8(network),
    utf8(method),
    args,
    u64le(ownerNonce),
    u64le(expiresAt),
  );
}

/** `sha256("zold-mandate-v1" || contract_id || network || method || borsh(args) || owner_nonce || expires_at)`. */
export function ownerChallenge(...a: Parameters<typeof challengePreimage>): Uint8Array {
  return sha256(challengePreimage(...a));
}

/** A P-256 signer over `message` (ES256: SHA-256 inside), returning raw 64-byte r || s. */
export type P256Signer = (message: Uint8Array) => Uint8Array;

/** Software owner key. No low-S normalisation, like an authenticator (the contract takes both). */
export function softwareSigner(secretKey: Uint8Array): P256Signer {
  return (message) => p256.sign(message, secretKey, { prehash: true, lowS: false });
}

/** 33-byte compressed SEC1 public key, the form `OwnerMode::Passkey.public_key` stores. */
export function compressedPublicKey(secretKey: Uint8Array): Uint8Array {
  return p256.getPublicKey(secretKey, true);
}

export type AssertionInput = {
  contractId: string;
  network: string;
  method: string;
  args: Uint8Array;
  ownerNonce: number;
  expiresAt: number;
  rpId: string;
  origin: string;
};

/** Builds the assertion the contract's `assert_owner` checks, signed by `sign`. */
export function buildAssertion(input: AssertionInput, sign: P256Signer): OwnerAssertion {
  const challenge = ownerChallenge(
    input.contractId,
    input.network,
    input.method,
    input.args,
    input.ownerNonce,
    input.expiresAt,
  );
  // rpIdHash || flags || signCount (0, as synced passkeys report).
  const authData = concat(sha256(utf8(input.rpId)), Uint8Array.of(FLAGS_UP_UV), new Uint8Array(4));
  const clientDataJson = JSON.stringify({
    type: "webauthn.get",
    challenge: Buffer.from(challenge).toString("base64url"),
    origin: input.origin,
    crossOrigin: false,
  });
  const signature = sign(concat(authData, sha256(utf8(clientDataJson))));
  if (signature.length !== 64) throw new Error("signer must return raw 64-byte r || s");
  return {
    authenticator_data: Buffer.from(authData).toString("base64"),
    client_data_json: clientDataJson,
    signature: Buffer.from(signature).toString("base64"),
    owner_nonce: input.ownerNonce,
    expires_at: input.expiresAt,
  };
}
