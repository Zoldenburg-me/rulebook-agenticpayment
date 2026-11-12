// pnpm passkey: creates the owner's passkey (one tap) and prints the Safe address it controls.
// The Safe deploys with its first UserOperation (the first top-up).
import { existsSync } from "node:fs";
import { passkeyPath, savePasskey, spkiToPoint, tap } from "../passkey.ts";
import { safeAddressFor } from "../safe.ts";

if (existsSync(passkeyPath())) throw new Error(`${passkeyPath()} exists; refusing to overwrite`);
const c = await tap({ mode: "create", summary: "Create the nearH owner passkey for the Safe on Base Sepolia." });
const pk = spkiToPoint(new Uint8Array(Buffer.from(c.publicKey, "base64url")));
const safe = safeAddressFor(pk);
const path = savePasskey({ credential_id: c.id, x: "0x" + pk.x.toString(16), y: "0x" + pk.y.toString(16), safe_address: safe });
console.log(`passkey saved to ${path}\nSafe (Base Sepolia, deploys on first use): ${safe}\nUse it as SAFE_ADDRESS for add-agent.`);
