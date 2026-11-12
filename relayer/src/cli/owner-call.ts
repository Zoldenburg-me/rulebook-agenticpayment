// pnpm owner-call <signed-call.json>: relays one owner-signed call ({ method, args, assertion }).

import { readFileSync } from "node:fs";
import { nearConfig, nearSigner } from "../config.ts";
import { relayOwnerCall } from "../owner-call.ts";

const file = process.argv[2];
if (!file) throw new Error("usage: pnpm owner-call <signed-call.json>");
const call = JSON.parse(readFileSync(file, "utf8"));
const r = await relayOwnerCall({ ...nearConfig(), submitter: nearSigner("SUBMITTER") }, call);
console.log(`${call.method}: landed, owner_nonce ${r.ownerNonce}, tx ${r.txHash}`);
