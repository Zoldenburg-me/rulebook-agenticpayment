// `pnpm --filter @nearh/agent-signer pay <url>`: GET a URL, paying an x402 402 through the
// mandate contract. Testnet only. Never prints a key.
import { decodePaymentResponseHeader } from "@x402/fetch";
import { assertTestnet, assertTestnetRpc } from "../near.ts";
import { httpRpc, NearX402Signer, nearX402Fetch, parseNearKey } from "../index.ts";

const env = (name: string, fallback?: string) => {
  const v = process.env[name] || fallback;
  if (!v) throw new Error(`set ${name}`);
  return v;
};

const url = process.argv[2];
if (!url) throw new Error("usage: pay <url>");
const rpc = env("NEAR_RPC", "https://rpc.testnet.near.org");
assertTestnetRpc(rpc);
const contractId = assertTestnet("MANDATE_CONTRACT_ID", env("MANDATE_CONTRACT_ID"));
const signer = await NearX402Signer.connect({
  near: httpRpc(rpc),
  contractId,
  key: parseNearKey(contractId, env("AGENT_NEAR_PRIVATE_KEY")),
  expectedAddress: process.env.AGENT_EVM_ADDRESS || undefined,
  onSigned: (s) => console.log("signed    :", s.requestId, `NEAR tx ${s.txHash}`, `window ${s.reservation.payload.valid_after}..${s.reservation.payload.valid_before}`),
});
console.log("agent     :", signer.agent);
console.log("agent EOA :", signer.address);
const t0 = Date.now();
const res = await nearX402Fetch(signer)(url);
console.log("status    :", res.status, `(${((Date.now() - t0) / 1000).toFixed(1)}s)`);
const header = res.headers.get("payment-response");
if (header) console.log("settlement:", JSON.stringify(decodePaymentResponseHeader(header)));
console.log("body      :", await res.text());
if (!res.ok) process.exitCode = 1;
