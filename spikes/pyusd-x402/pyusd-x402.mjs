// PP-S2 spike: an EIP-3009 transferWithAuthorization for PYUSD on Ethereum Sepolia,
// from the S-a derived EOA, signed by v1.signer-prod.testnet, settled by our own
// submitter (the team testnet funder pays gas), then a second payment through the
// @x402/evm 2.30.0 facilitator verify/settle. Based on spikes/x402/x402.mjs (S-c).
// Throwaway code, never imported. Usage: see RESULT.md.
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { Account, JsonRpcProvider, KeyPairSigner } from "near-api-js";
import {
  BaseError, ContractFunctionRevertedError, createPublicClient, createWalletClient, domainSeparator,
  erc20Abi, hashStruct, hashTypedData, http, keccak256, parseSignature, publicActions, recoverAddress,
  serializeSignature, toHex,
} from "viem";
import { privateKeyToAccount, publicKeyToAddress } from "viem/accounts";
import { sepolia } from "viem/chains";
import { toFacilitatorEvmSigner } from "@x402/evm";
import { ExactEvmScheme } from "@x402/evm/exact/facilitator";

// MPC_CONTRACT guard copied from spikes/chainsig/chainsig.mjs (S-a exports nothing).
const MPC = process.env.MPC_CONTRACT ?? "v1.signer-prod.testnet";
if (!MPC.endsWith(".testnet")) throw new Error(`MPC_CONTRACT must be a testnet account, got ${MPC}`);
const NEAR_RPC = process.env.NEAR_RPC ?? "https://rpc.testnet.near.org";
const SEPOLIA_RPC = process.env.SEPOLIA_RPC ?? "https://ethereum-sepolia-rpc.publicnode.com";
const ACCOUNT = process.env.NEAR_ACCOUNT_ID;
const PATH = process.env.CHAINSIG_PATH ?? "nearh-sa-test"; // same EOA as S-a / S-c
const PAYEE_PATH = process.env.PAYEE_PATH ?? "nearh-sc-payee";
const FUNDER_KEY_FILE = process.env.FUNDER_KEY_FILE ?? join(homedir(), ".config/nearh/testnet-funder.key");
const AMOUNT = BigInt(process.env.AMOUNT ?? "10000"); // 0.01 PYUSD
const FUND_AMOUNT = 20_000_000n; // 20 PYUSD, sent only if the agent EOA holds less than 2 * AMOUNT
const SKIP_X402 = process.env.SKIP_X402 === "1";
// Window validBefore - validAfter must stay within PLAN.md max_validity_secs (<= 300 s).
const SKEW_SECS = 30n;
const VALIDITY_SECS = 240n;
if (!ACCOUNT) throw new Error("set NEAR_ACCOUNT_ID (a testnet account with a key in ~/.near-credentials/testnet)");

const PYUSD = "0xCaC524BcA292aaade2DF8A05cC58F0a65B1B3bB9"; // Ethereum Sepolia
const CHAIN_ID = 11155111;
const NETWORK = `eip155:${CHAIN_ID}`;
const domain = { name: "PayPal USD", version: "1", chainId: CHAIN_ID, verifyingContract: PYUSD };
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
const authArgs = [
  { name: "from", type: "address" }, { name: "to", type: "address" }, { name: "value", type: "uint256" },
  { name: "validAfter", type: "uint256" }, { name: "validBefore", type: "uint256" }, { name: "nonce", type: "bytes32" },
];
// PYUSD (Paxos impl behind a zos proxy) has both overloads; we submit the (v,r,s) one,
// which is also what @x402/evm uses for a 65-byte ECDSA signature.
const pyusdAbi = [
  { type: "function", name: "transferWithAuthorization", stateMutability: "nonpayable", outputs: [],
    inputs: [...authArgs, { name: "v", type: "uint8" }, { name: "r", type: "bytes32" }, { name: "s", type: "bytes32" }] },
  { type: "function", name: "transferWithAuthorization", stateMutability: "nonpayable", outputs: [],
    inputs: [...authArgs, { name: "signature", type: "bytes" }] },
  { type: "function", name: "authorizationState", stateMutability: "view", outputs: [{ type: "bool" }],
    inputs: [{ name: "authorizer", type: "address" }, { name: "nonce", type: "bytes32" }] },
  { type: "function", name: "DOMAIN_SEPARATOR", stateMutability: "view", outputs: [{ type: "bytes32" }], inputs: [] },
  ...erc20Abi,
];

const near = new JsonRpcProvider({ url: NEAR_RPC });
const evm = createPublicClient({ chain: sepolia, transport: http(SEPOLIA_RPC) });
// The funder key is read from its 0600 file at runtime and never printed.
const funder = privateKeyToAccount(readFileSync(FUNDER_KEY_FILE, "utf8").trim());
const wallet = createWalletClient({ account: funder, chain: sepolia, transport: http(SEPOLIA_RPC) }).extend(publicActions);

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const b58hex = (s) => { let n = 0n; for (const c of s) n = n * 58n + BigInt(BASE58.indexOf(c)); return n.toString(16).padStart(128, "0"); };
const derive = async (path) => publicKeyToAddress(`0x04${b58hex((await near.callFunction({
  contractId: MPC, method: "derived_public_key", args: { path, predecessor: ACCOUNT, domain_id: 0 },
})).split(":")[1])}`);
// Reads take an optional blockNumber: publicnode load-balances, so "latest" right after a
// receipt can come from a node that has not seen the block yet.
const bal = (a, blockNumber) => evm.readContract({ address: PYUSD, abi: pyusdAbi, functionName: "balanceOf", args: [a], blockNumber });
const TOPIC = {
  Transfer: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
  AuthorizationUsed: keccak256(toHex("AuthorizationUsed(address,bytes32)")),
  AuthorizationAlreadyUsed: keccak256(toHex("AuthorizationAlreadyUsed(address,bytes32)")),
};
const events = (logs) => logs.filter((l) => l.address.toLowerCase() === PYUSD.toLowerCase())
  .map((l) => Object.keys(TOPIC).find((k) => TOPIC[k] === l.topics[0]) ?? l.topics[0]);
const authState = (a, n) => evm.readContract({ address: PYUSD, abi: pyusdAbi, functionName: "authorizationState", args: [a, n] });
const tx = (h) => `${h} https://sepolia.etherscan.io/tx/${h}`;
const revertReason = (e) => {
  const inner = e instanceof BaseError ? e.walk((x) => x instanceof ContractFunctionRevertedError) : null;
  return inner?.reason ?? inner?.shortMessage ?? e.shortMessage ?? String(e);
};
const json = (o) => JSON.stringify(o, (_, v) => typeof v === "bigint" ? v.toString() : v);

const from = await derive(PATH);
const payTo = await derive(PAYEE_PATH);
console.log("mpc contract      :", MPC);
console.log("from (agent EOA)  :", from, `(${PATH})`);
console.log("payTo             :", payTo, `(${PAYEE_PATH})`);
console.log("submitter (funder):", funder.address);

// Domain check before anything is spent.
const onchainSep = await evm.readContract({ address: PYUSD, abi: pyusdAbi, functionName: "DOMAIN_SEPARATOR" });
const localSep = domainSeparator({ domain });
console.log("domain separator  :", localSep, onchainSep === localSep ? "(= on-chain DOMAIN_SEPARATOR)" : `(MISMATCH, on-chain ${onchainSep})`);
if (onchainSep !== localSep) { process.exitCode = 1; throw new Error("domain separator mismatch"); }

// Step 1: fund the agent EOA with PYUSD (plain ERC-20 transfer from the funder).
if (await bal(from) < 2n * AMOUNT) {
  const h = await wallet.writeContract({ address: PYUSD, abi: pyusdAbi, functionName: "transfer", args: [from, FUND_AMOUNT] });
  const r = await evm.waitForTransactionReceipt({ hash: h });
  console.log("fund tx           :", tx(h), `status=${r.status}`);
  if (r.status !== "success") { process.exitCode = 1; throw new Error("funding failed"); }
  await evm.waitForTransactionReceipt({ hash: h, confirmations: 2 });
}
console.log("agent pyusd / eth :", (await bal(from)).toString(), "/", (await evm.getBalance({ address: from })).toString());

// Step 2: authorization + digest, MPC signs it (call shape and r/s/v from S-a / S-c).
const cred = JSON.parse(readFileSync(join(homedir(), ".near-credentials/testnet", `${ACCOUNT}.json`), "utf8"));
const account = new Account(ACCOUNT, near, KeyPairSigner.fromSecretKey(cred.private_key));
async function authorize(label) {
  const now = BigInt(Math.floor(Date.now() / 1000));
  const message = {
    from, to: payTo, value: AMOUNT,
    validAfter: now - SKEW_SECS, validBefore: now + VALIDITY_SECS, // 270 s window
    nonce: toHex(randomBytes(32)),
  };
  const digest = hashTypedData({ domain, types, primaryType: "TransferWithAuthorization", message });
  console.log(`\n[${label}] authorization :`, json(message));
  console.log(`[${label}] struct hash   :`, hashStruct({ data: message, types, primaryType: "TransferWithAuthorization" }));
  console.log(`[${label}] eip-712 digest:`, digest);
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
  console.log(`[${label}] near tx       :`, res.transaction.hash, `(${((Date.now() - t0) / 1000).toFixed(1)}s)`);
  console.log(`[${label}] signature 65B :`, signature, `(recovery_id ${sig.recovery_id})`);
  console.log(`[${label}] recovered=from:`, recovered === from);
  if (recovered !== from) { process.exitCode = 1; throw new Error("signature does not recover to the agent EOA"); }
  return { message, signature };
}

const a1 = await authorize("own");
const { v, r, s } = parseSignature(a1.signature);
const base = [a1.message.from, a1.message.to, a1.message.value, a1.message.validAfter, a1.message.validBefore, a1.message.nonce];
const vrsArgs = [...base, Number(v), r, s];
const bytesArgs = [...base, a1.signature];
const call = (args) => ({ address: PYUSD, abi: pyusdAbi, functionName: "transferWithAuthorization", args, account: funder });

// Dry eth_call of both overloads before submitting.
for (const [name, args] of [["(v,r,s)", vrsArgs], ["(bytes)", bytesArgs]]) {
  try { await evm.simulateContract(call(args)); console.log(`[own] simulate ${name}  : ok`); }
  catch (e) { console.log(`[own] simulate ${name}  : REVERT ${revertReason(e)}`); }
}

// Step 3: our own submitter (funder pays gas; the agent EOA holds no ETH).
const h1 = await wallet.writeContract(call(vrsArgs));
const r1 = await evm.waitForTransactionReceipt({ hash: h1 });
const payBefore = await bal(payTo, r1.blockNumber - 1n);
const payAfter = await bal(payTo, r1.blockNumber);
const used = await authState(from, a1.message.nonce);
console.log("[own] settle tx       :", tx(h1), `status=${r1.status} block=${r1.blockNumber} gasUsed=${r1.gasUsed} events=${events(r1.logs)}`);
console.log("[own] payTo delta     :", (payAfter - payBefore).toString());
console.log("[own] authorizationState(from, nonce):", used);

// Step 4: replay the same authorization. PYUSD does NOT revert on a used nonce: it emits
// AuthorizationAlreadyUsed and returns, moving nothing. eth_call both overloads, then
// broadcast one replay (fixed gas, funder pays) to record it on chain.
for (const [name, args] of [["(v,r,s)", vrsArgs], ["(bytes)", bytesArgs]]) {
  try { await evm.simulateContract(call(args)); console.log(`[own] replay eth_call ${name}: no revert`); }
  catch (e) { console.log(`[own] replay eth_call ${name}: reverts "${revertReason(e)}"`); }
}
const h1b = await wallet.writeContract({ ...call(vrsArgs), gas: 100_000n });
const r1b = await evm.waitForTransactionReceipt({ hash: h1b });
const payReplay = await bal(payTo, r1b.blockNumber);
const replayNoop = r1b.status === "success" && payReplay === payAfter && !events(r1b.logs).includes("Transfer")
  && events(r1b.logs).includes("AuthorizationAlreadyUsed");
console.log("[own] replay tx       :", tx(h1b), `status=${r1b.status} gasUsed=${r1b.gasUsed} events=${events(r1b.logs)}`);
console.log("[own] replay payTo delta:", (payReplay - payAfter).toString(), replayNoop ? "(no-op, as expected for PYUSD)" : "(UNEXPECTED)");
const ownPass = r1.status === "success" && payAfter - payBefore === AMOUNT && used === true
  && events(r1.logs).includes("Transfer") && replayNoop;
console.log("[own]", ownPass ? "PASS" : "FAIL");
if (!ownPass) process.exitCode = 1;

// Optional: a second payment through the @x402/evm 2.30.0 facilitator, funder as signer.
if (!SKIP_X402) {
  const facilitator = new ExactEvmScheme(toFacilitatorEvmSigner({ ...wallet, address: funder.address }));
  const a2 = await authorize("x402");
  const requirements = {
    scheme: "exact", network: NETWORK, amount: AMOUNT.toString(), asset: PYUSD, payTo,
    maxTimeoutSeconds: Number(SKEW_SECS + VALIDITY_SECS), extra: { name: "PayPal USD", version: "1" },
  };
  const payload = {
    x402Version: 2,
    resource: { url: "https://nearh.invalid/spike-pyusd-x402", description: "nearH PP-S2 spike", mimeType: "application/json" },
    accepted: requirements,
    payload: { signature: a2.signature, authorization: Object.fromEntries(Object.entries(a2.message).map(([k, x]) => [k, x.toString()])) },
  };
  const vr = await facilitator.verify(payload, requirements);
  console.log("[x402] verify         :", json(vr));
  if (!vr.isValid) { process.exitCode = 1; throw new Error("facilitator verify rejected"); }
  const sr = await facilitator.settle(payload, requirements);
  console.log("[x402] settle         :", json(sr));
  if (!sr.success) { process.exitCode = 1; throw new Error("facilitator settle failed"); }
  const r2 = await evm.waitForTransactionReceipt({ hash: sr.transaction });
  const after = await bal(payTo, r2.blockNumber);
  const delta = after - await bal(payTo, r2.blockNumber - 1n);
  console.log("[x402] settle tx      :", tx(sr.transaction), `status=${r2.status} block=${r2.blockNumber} events=${events(r2.logs)}`);
  console.log("[x402] payTo delta    :", delta.toString());
  console.log("[x402] authorizationState(from, nonce):", await authState(from, a2.message.nonce));
  // Replay through the facilitator: a fresh scheme instance, so its in-memory pending
  // store cannot short-circuit the retry (as a second facilitator replica would see it).
  const facilitator2 = new ExactEvmScheme(toFacilitatorEvmSigner({ ...wallet, address: funder.address }));
  console.log("[x402] replay verify  :", json(await facilitator2.verify(payload, requirements)));
  const sr2 = await facilitator2.settle(payload, requirements);
  console.log("[x402] replay settle  :", json(sr2));
  if (sr2.transaction) {
    const r3 = await evm.waitForTransactionReceipt({ hash: sr2.transaction });
    const d3 = (await bal(payTo, r3.blockNumber)) - after;
    console.log("[x402] replay tx      :", tx(sr2.transaction), `status=${r3.status} events=${events(r3.logs)} payTo delta=${d3}`);
  }
  const x402Pass = r2.status === "success" && delta === AMOUNT;
  console.log("[x402]", x402Pass ? "PASS" : "FAIL");
  if (!x402Pass) process.exitCode = 1;
}
console.log("\nagent pyusd after :", (await bal(from)).toString(), " payTo pyusd after:", (await bal(payTo)).toString());
