// pnpm keygen: creates the software P-256 owner key for $CONTRACT_ID outside the repo.
import { bytesToHex } from "@noble/hashes/utils.js";
import { createOwnerKey, ownerKeyPath } from "../keys.ts";
import { config } from "../near.ts";

const cfg = config();
const pub = createOwnerKey(cfg);
console.log(`owner key written to ${ownerKeyPath(cfg)}`);
console.log(`owner public key (compressed SEC1): ${bytesToHex(pub)}`);
