// Agent EOA off chain, as spike S-a derives it: the MPC key for (predecessor, path) is
// `root + epsilon·G` with `epsilon = sha3_256("near-mpc-recovery v0.1.0 epsilon derivation:"
// + predecessor + "," + path)`. For the mandate contract the predecessor is the contract and
// the path is the agent id, so the EOA is derive(contract_id, agent).

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256, sha3_256 } from "@noble/hashes/sha3.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { base58Decode } from "./base58.ts";

const EPSILON_PREFIX = "near-mpc-recovery v0.1.0 epsilon derivation:";

/** `secp256k1:<base58 of 64-byte x || y>` (the MPC's `public_key` view) → uncompressed point. */
export function mpcKeyToPoint(key: string) {
  const [curve, data] = key.split(":");
  if (curve !== "secp256k1" || !data) throw new Error(`not a secp256k1 key: ${key}`);
  const xy = base58Decode(data);
  if (xy.length !== 64) throw new Error(`secp256k1 key must be 64 bytes x || y: ${key}`);
  const raw = new Uint8Array(65);
  raw[0] = 4;
  raw.set(xy, 1);
  return secp256k1.Point.fromBytes(raw);
}

/** Lowercase `0x` address of the MPC key derived for (predecessor, path) from `rootKey`. */
export function deriveEvmAddress(rootKey: string, predecessor: string, path: string): string {
  const eps = BigInt(
    "0x" + bytesToHex(sha3_256(new TextEncoder().encode(`${EPSILON_PREFIX}${predecessor},${path}`))),
  );
  const derived = mpcKeyToPoint(rootKey).add(secp256k1.Point.BASE.multiply(eps));
  return publicKeyToAddress(derived.toBytes(false));
}

/** Last 20 bytes of keccak256(x || y), lowercase (the form the contract stores). */
export function publicKeyToAddress(uncompressed: Uint8Array): string {
  if (uncompressed.length !== 65 || uncompressed[0] !== 4) throw new Error("need an uncompressed point");
  return "0x" + bytesToHex(keccak_256(uncompressed.slice(1)).slice(12));
}
