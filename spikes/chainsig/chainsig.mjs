// S-a spike: derive the EOA for (predecessor, path) on v1.signer-prod.testnet,
// request one secp256k1 signature, recover the address from it.
// Throwaway code, never imported. Usage: see RESULT.md.
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Account, JsonRpcProvider, KeyPairSigner } from "near-api-js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { hashMessage, recoverAddress, serializeSignature } from "viem";
import { publicKeyToAddress } from "viem/accounts";

const MPC = process.env.MPC_CONTRACT ?? "v1.signer-prod.testnet";
if (!MPC.endsWith(".testnet")) throw new Error(`MPC_CONTRACT must be a testnet account, got ${MPC}`);
const RPC = process.env.NEAR_RPC ?? "https://rpc.testnet.near.org";
const ACCOUNT = process.env.NEAR_ACCOUNT_ID;
const PATH = process.env.CHAINSIG_PATH ?? "nearh-sa-test";
if (!ACCOUNT) throw new Error("set NEAR_ACCOUNT_ID (a testnet account with a key in ~/.near-credentials/testnet)");

const provider = new JsonRpcProvider({ url: RPC });
const view = (method, args) => provider.callFunction({ contractId: MPC, method, args });

// "secp256k1:<base58 of 64-byte x||y>" -> uncompressed "04..." hex
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58decode(s) {
  let n = 0n;
  for (const c of s) n = n * 58n + BigInt(BASE58.indexOf(c));
  const hex = n.toString(16).padStart(128, "0");
  return hexToBytes(hex);
}
const nearKeyToHex = (k) => "04" + bytesToHex(b58decode(k.split(":")[1]));

// 1. Derived key, two ways: the MPC contract's view, and local KDF
//    (epsilon = sha3_256("near-mpc-recovery v0.1.0 epsilon derivation:" + predecessor + "," + path),
//     derived = root + epsilon*G). They must agree.
const rootPk = nearKeyToHex(await view("public_key", {}));
const viewPk = nearKeyToHex(await view("derived_public_key", { path: PATH, predecessor: ACCOUNT, domain_id: 0 }));
const eps = BigInt("0x" + bytesToHex(sha3_256(new TextEncoder().encode(
  `near-mpc-recovery v0.1.0 epsilon derivation:${ACCOUNT},${PATH}`))));
const localPk = "04" + bytesToHex(
  secp256k1.Point.fromHex(rootPk)
    .add(secp256k1.Point.BASE.multiply(eps)).toBytes(false)).slice(2);
const address = publicKeyToAddress(`0x${viewPk}`);
console.log("mpc contract      :", MPC);
console.log("predecessor, path :", ACCOUNT, ",", PATH);
console.log("derived address   :", address);
console.log("local KDF matches :", localPk === viewPk);
if (localPk !== viewPk) process.exitCode = 1;

// 2. Ask the MPC network to sign an EIP-191 message hash.
const message = `nearH S-a chainsig spike ${new Date().toISOString()}`;
const hash = hashMessage(message);
const cred = JSON.parse(readFileSync(join(homedir(), ".near-credentials/testnet", `${ACCOUNT}.json`), "utf8"));
const account = new Account(ACCOUNT, provider, KeyPairSigner.fromSecretKey(cred.private_key));
const t0 = Date.now();
const res = await account.callFunctionRaw({
  contractId: MPC,
  methodName: "sign",
  args: { request: { payload_v2: { Ecdsa: hash.slice(2) }, path: PATH, domain_id: 0 } },
  gas: 300_000_000_000_000n,
  deposit: 1n,
});
const secs = ((Date.now() - t0) / 1000).toFixed(1);
const ok = res.status?.SuccessValue;
if (ok === undefined) throw new Error("sign failed: " + JSON.stringify(res.status));
const sig = JSON.parse(Buffer.from(ok, "base64").toString());
console.log("near tx           :", res.transaction.hash, `(${secs}s)`);
console.log("raw mpc response  :", JSON.stringify(sig));

// 3. Recover. Response: { scheme, big_r: { affine_point: "02|03..x" }, s: { scalar }, recovery_id }
const r = `0x${sig.big_r.affine_point.slice(2)}`;
const s = `0x${sig.s.scalar}`;
const signature = serializeSignature({ r, s, yParity: sig.recovery_id });
const recovered = await recoverAddress({ hash, signature });
console.log("message           :", message);
console.log("eip-191 hash      :", hash);
console.log("signature (65B)   :", signature);
console.log("recovered address :", recovered);
console.log(recovered === address ? "PASS" : "FAIL");
if (recovered !== address) process.exitCode = 1;
