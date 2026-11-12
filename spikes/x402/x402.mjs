// S-c spike: an EIP-3009 transferWithAuthorization (USDC, Base Sepolia) for the
// S-a derived EOA, signed by v1.signer-prod.testnet, settled by the x402.org
// facilitator (x402 v2, scheme "exact"). Throwaway code, never imported.
// Usage: see RESULT.md. DRY_RUN=1 signs and calls /verify only (no settle).
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Account, JsonRpcProvider, KeyPairSigner } from "near-api-js";
import {
  createPublicClient, domainSeparator, erc20Abi, hashStruct, hashTypedData, http,
  recoverAddress, serializeSignature, toHex,
} from "viem";
import { publicKeyToAddress } from "viem/accounts";
import { baseSepolia } from "viem/chains";

// MPC_CONTRACT guard copied from spikes/chainsig/chainsig.mjs (S-a exports nothing).
const MPC = process.env.MPC_CONTRACT ?? "v1.signer-prod.testnet";
if (!MPC.endsWith(".testnet")) throw new Error(`MPC_CONTRACT must be a testnet account, got ${MPC}`);
const NEAR_RPC = process.env.NEAR_RPC ?? "https://rpc.testnet.near.org";
const ACCOUNT = process.env.NEAR_ACCOUNT_ID;
const PATH = process.env.CHAINSIG_PATH ?? "nearh-sa-test"; // same EOA as S-a
const PAYEE_PATH = process.env.PAYEE_PATH ?? "nearh-sc-payee";
const FACILITATOR = process.env.FACILITATOR_URL ?? "https://x402.org/facilitator";
const AMOUNT = BigInt(process.env.AMOUNT ?? "10000"); // 0.01 USDC
// Window validBefore - validAfter must stay within PLAN.md max_validity_secs (<= 300 s).
const SKEW_SECS = 30n;
const VALIDITY_SECS = 240n;
const DRY_RUN = process.env.DRY_RUN === "1";
if (!ACCOUNT) throw new Error("set NEAR_ACCOUNT_ID (a testnet account with a key in ~/.near-credentials/testnet)");

const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"; // Base Sepolia
const NETWORK = "eip155:84532";
const domain = { name: "USDC", version: "2", chainId: 84532, verifyingContract: USDC };
const types = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
};

const near = new JsonRpcProvider({ url: NEAR_RPC });
const evm = createPublicClient({ chain: baseSepolia, transport: http(process.env.BASE_SEPOLIA_RPC) });

// Derived EOA, from the MPC contract's view (S-a showed it equals the local KDF).
const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58hex = (s) => { let n = 0n; for (const c of s) n = n * 58n + BigInt(BASE58.indexOf(c)); return n.toString(16).padStart(128, "0"); };
const derive = async (path) => publicKeyToAddress(`0x04${b58hex((await near.callFunction({
  contractId: MPC, method: "derived_public_key", args: { path, predecessor: ACCOUNT, domain_id: 0 },
})).split(":")[1])}`);

const from = await derive(PATH);
const payTo = await derive(PAYEE_PATH);
const balance = await evm.readContract({ address: USDC, abi: erc20Abi, functionName: "balanceOf", args: [from] });
console.log("mpc contract      :", MPC);
console.log("from (agent EOA)  :", from, `(${PATH})`);
console.log("payTo             :", payTo, `(${PAYEE_PATH})`);
console.log("usdc balance      :", balance.toString());
if (balance < AMOUNT && !DRY_RUN) {
  console.log(`\nNEEDS FUNDING: send >= ${AMOUNT} base units of Base Sepolia USDC to ${from}`);
  console.log("  e.g. https://faucet.circle.com (Base Sepolia, USDC). Then rerun. Or DRY_RUN=1 to sign + /verify only.");
  process.exit(2);
}

// 1. Build the EIP-3009 authorization and its EIP-712 digest.
const now = BigInt(Math.floor(Date.now() / 1000));
const message = {
  from, to: payTo, value: AMOUNT,
  validAfter: now - SKEW_SECS, validBefore: now + VALIDITY_SECS, // 270 s window
  nonce: toHex(randomBytes(32)),
};
const digest = hashTypedData({ domain, types, primaryType: "TransferWithAuthorization", message });
const onchainSep = await evm.readContract({ address: USDC, abi: [{ type: "function", name: "DOMAIN_SEPARATOR", inputs: [], outputs: [{ type: "bytes32" }], stateMutability: "view" }], functionName: "DOMAIN_SEPARATOR" });
console.log("authorization     :", JSON.stringify(message, (_, v) => typeof v === "bigint" ? v.toString() : v));
console.log("domain separator  :", domainSeparator({ domain }), onchainSep === domainSeparator({ domain }) ? "(= on-chain DOMAIN_SEPARATOR)" : `(MISMATCH, on-chain ${onchainSep})`);
console.log("struct hash       :", hashStruct({ data: message, types, primaryType: "TransferWithAuthorization" }));
console.log("eip-712 digest    :", digest);

// 2. MPC signs the digest as-is. Call shape and the r/s/v conversion are copied from
// spikes/chainsig/chainsig.mjs: v comes from recovery_id, never from the big_r prefix.
const cred = JSON.parse(readFileSync(join(homedir(), ".near-credentials/testnet", `${ACCOUNT}.json`), "utf8"));
const account = new Account(ACCOUNT, near, KeyPairSigner.fromSecretKey(cred.private_key));
const t0 = Date.now();
const res = await account.callFunctionRaw({
  contractId: MPC, methodName: "sign",
  args: { request: { payload_v2: { Ecdsa: digest.slice(2) }, path: PATH, domain_id: 0 } },
  gas: 300_000_000_000_000n, deposit: 1n,
});
const ok = res.status?.SuccessValue;
if (ok === undefined) throw new Error("sign failed: " + JSON.stringify(res.status));
const sig = JSON.parse(Buffer.from(ok, "base64").toString());
const signature = serializeSignature({ r: `0x${sig.big_r.affine_point.slice(2)}`, s: `0x${sig.s.scalar}`, yParity: sig.recovery_id });
const recovered = await recoverAddress({ hash: digest, signature });
console.log("near tx           :", res.transaction.hash, `(${((Date.now() - t0) / 1000).toFixed(1)}s)`);
console.log("signature (65B)   :", signature);
console.log("recovered = from  :", recovered === from);
if (recovered !== from) { process.exitCode = 1; throw new Error("signature does not recover to the agent EOA"); }

// 3. x402 v2 facilitator: /verify, then /settle.
const paymentRequirements = {
  scheme: "exact", network: NETWORK, amount: AMOUNT.toString(), asset: USDC, payTo,
  maxTimeoutSeconds: Number(SKEW_SECS + VALIDITY_SECS), extra: { name: "USDC", version: "2" },
};
const body = {
  x402Version: 2,
  paymentPayload: {
    x402Version: 2,
    resource: { url: "https://nearh.invalid/spike-x402", description: "nearH S-c spike", mimeType: "application/json" },
    accepted: paymentRequirements,
    payload: {
      signature,
      authorization: Object.fromEntries(Object.entries(message).map(([k, v]) => [k, v.toString()])),
    },
  },
  paymentRequirements,
};
const post = async (ep) => {
  const r = await fetch(`${FACILITATOR}/${ep}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const text = await r.text();
  console.log(`facilitator /${ep.padEnd(6)}:`, r.status, text);
  try { return JSON.parse(text); } catch { return {}; }
};
const v = await post("verify");
if (DRY_RUN) { console.log(v.isValid ? "DRY RUN: verify OK" : "DRY RUN: verify rejected (see reason)"); process.exit(0); }
if (!v.isValid) { process.exitCode = 1; throw new Error("facilitator /verify rejected the payment"); }
const s = await post("settle");
if (!s.success || !s.transaction) { process.exitCode = 1; throw new Error("facilitator /settle failed"); }
const receipt = await evm.waitForTransactionReceipt({ hash: s.transaction });
console.log("base sepolia tx   :", s.transaction, `status=${receipt.status} block=${receipt.blockNumber}`);
console.log("payTo balance     :", (await evm.readContract({ address: USDC, abi: erc20Abi, functionName: "balanceOf", args: [payTo] })).toString());
console.log(receipt.status === "success" ? "PASS" : "FAIL");
if (receipt.status !== "success") process.exitCode = 1;
