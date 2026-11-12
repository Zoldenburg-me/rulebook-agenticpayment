// PP-H2 setup: a fresh testnet mandate contract for Hank's agent with the PayPal rail that shape 5
// (paypal_checkout, the vaulted-wallet charge) uses, as pp-payouts-setup.ts set up Anya's. The owner
// is a NEAR wallet account (wallet mode): the owner scripts and the dashboard do not encode `paypal`
// yet, so this signs the owner calls as that account through near-cli-rs (legacy keychain), with
// `assertion: null`.
//
//   CONTRACT_ID=<fresh>.testnet OWNER_ACCOUNT_ID=<fresh-owner>.testnet node demo/src/pt2-hank-setup.ts <wasm> <merchants.json>
//
// Both accounts must exist with their full-access keys in ~/.near-credentials; the contract has no
// code yet. merchants.json is a JSON array of 3 PayPal emails, the card shops (kept outside the
// repo; the first is the real store). The agent key goes to $OWNER_KEY_DIR/<contract>/agents/<agent>.json
// (default ~/.nearh-owner), never printed. Merchants are masked in every line this prints.
import { readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { deriveEvmAddress, mpcKeyToPoint, publicKeyToAddress } from "@nearh/owner-near/src/derive.ts";
import { createAgentKey, existingAgentKey } from "@nearh/owner-near/src/keys.ts";
import {
  AGENT_METHOD_NAMES, accessKeys, assertTestnet, codeHash, config, describeKeys, EMPTY_CODE_HASH, isFullAccess, NETWORK, nearCli, view, waitFor,
} from "@nearh/owner-near/src/near.ts";
import { maskEmail } from "@nearh/rails-paypal/src/payout.ts";

/** AGENT_ID adds a second agent with the same rulebook to the same contract (a rerun skips what is on chain). */
export const AGENT = process.env.AGENT_ID || "grokbot-hank";
const USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
const EURE = "0x29f37f6adca168b79b8d9567eab9be3fbf21db85";
/** Hank's rulebook: USD 0.01-100.00 per payment, USD 150.00 per week, orders valid 5 minutes. x402 and sepa are the mandate's required rails, unused here. */
export const MANDATE = {
  x402: { amount_range: { min: "1", max: "1000000" }, budget: "20000000", period_secs: 604800 },
  sepa: { amount_range: { min: "1", max: "50000000000000000000" }, budget: "200000000000000000000", period_secs: 604800 },
  usdc_address: USDC,
  eure_address: EURE,
  chain_id: 84532,
  float_cap: { usdc: "25000000", eure: "250000000000000000000" },
  max_validity_secs: 300,
  paypal: { amount_range: { min: "1", max: "10000" }, budget: "15000", period_secs: 604800 },
  usdc_eip712_name: "USDC",
  usdc_eip712_version: "2",
};

/** A wallet-mode owner call: signed by the owner account with exactly 1 yoctoNEAR, as the contract requires. */
const ownerCall = (method: string, args: object) => nearCli([
  "contract", "call-function", "as-transaction", cfg.contractId, method,
  "json-args", JSON.stringify(args),
  "prepaid-gas", "100 Tgas", "attached-deposit", "1 yoctoNEAR",
  "sign-as", owner, "network-config", NETWORK, "sign-with-legacy-keychain", "send",
]);

const step = (name: string, r: { ok: boolean; out: string; txHash?: string }) => {
  console.log(`${name}: tx ${r.txHash ?? "(none printed)"}`);
  if (!r.ok || !r.txHash) {
    console.log(r.out);
    throw new Error(`${name} did not go through`);
  }
  return r.txHash;
};

const cfg = config();
const owner = assertTestnet("OWNER_ACCOUNT_ID", process.env.OWNER_ACCOUNT_ID ?? "");
const [wasm, merchantsFile] = process.argv.slice(2);
if (!wasm || !merchantsFile) throw new Error("usage: pt2-hank-setup.ts <wasm> <merchants.json>");
const merchants = (JSON.parse(readFileSync(merchantsFile, "utf8")) as string[]).map((p) => p.trim().toLowerCase());
if (merchants.length !== 3) throw new Error("merchants.json must list 3 PayPal emails");
// 1. Deploy + new, wallet-mode owner. A rerun after a failed step skips the steps already on chain.
const init = { owner: { mode: "wallet", account: owner }, network: NETWORK, mpc_contract: cfg.mpcContract };
if ((await codeHash(cfg, cfg.contractId)) === EMPTY_CODE_HASH) step("deploy + new", nearCli([
  "contract", "deploy", cfg.contractId, "use-file", wasm,
  "with-init-call", "new", "json-args", JSON.stringify(init),
  "prepaid-gas", "100 Tgas", "attached-deposit", "0 NEAR",
  "network-config", NETWORK, "sign-with-legacy-keychain", "send",
]));
else console.log("deploy + new: already deployed, checking get_config");
const c = await waitFor("get_config after new", async () => view(cfg, cfg.contractId, "get_config").catch(() => undefined));
if (!isDeepStrictEqual(c, { ...init, owner_nonce: 0, relayer: null, settlement_reporter: null })) throw new Error(`get_config is not what new was called with: ${JSON.stringify(c)}`);

// 2. add_agent with a function-call-only key; evm_address cross-checked against the MPC view.
const publicKey = existingAgentKey(cfg, AGENT) ?? createAgentKey(cfg, AGENT);
const root = await view<string>(cfg, cfg.mpcContract, "public_key");
const evmAddress = deriveEvmAddress(root, cfg.contractId, AGENT);
const viewKey = await view<string>(cfg, cfg.mpcContract, "derived_public_key", { path: AGENT, predecessor: cfg.contractId, domain_id: 0 });
if (publicKeyToAddress(mpcKeyToPoint(viewKey).toBytes(false)) !== evmAddress) throw new Error("local derivation differs from the MPC view");
console.log(`agent ${AGENT}: EOA ${evmAddress} (derive(contract, agent), equal to the MPC's derived_public_key view)`);
const sweep_config = { safe_address: "0x5afe000000000000000000000000000000000001", usdc_address: USDC, eure_address: EURE, chain_id: 84532, usdc_eip712_name: "USDC", usdc_eip712_version: "2" };
if (!(await view(cfg, cfg.contractId, "get_agent", { agent: AGENT }))) step("add_agent", ownerCall("add_agent", { agent: AGENT, public_key: publicKey, sweep_config, evm_address: evmAddress, assertion: null }));
await waitFor("get_agent", async () => {
  const r = await view(cfg, cfg.contractId, "get_agent", { agent: AGENT });
  return r?.public_key === publicKey && r.evm_address === evmAddress ? r : undefined;
});

// 3. set_mandate with the paypal rail, then the 3 card shops (shape 5's merchant allowlist is the paypal payees).
const m0 = await view(cfg, cfg.contractId, "get_mandate", { agent: AGENT });
if (!isDeepStrictEqual(m0?.paypal, MANDATE.paypal)) step("set_mandate", ownerCall("set_mandate", { agent: AGENT, mandate: MANDATE, assertion: null }));
const m = await waitFor("get_mandate", async () => {
  const got = await view(cfg, cfg.contractId, "get_mandate", { agent: AGENT });
  return got?.paypal ? got : undefined;
});
if (!isDeepStrictEqual(m.paypal, MANDATE.paypal) || m.max_validity_secs !== 300) throw new Error(`get_mandate differs: ${JSON.stringify(m)}`);
const before: any[] = await view(cfg, cfg.contractId, "get_payees", { agent: AGENT });
for (const receiver of merchants.filter((r) => !before.some((p) => p.rail === "paypal" && p.receiver === r))) {
  step(`add_payee paypal ${maskEmail(receiver)}`, ownerCall("add_payee", { agent: AGENT, payee: { rail: "paypal", receiver }, assertion: null }));
}
const listed = await waitFor("get_payees", async () => {
  const ps: any[] = await view(cfg, cfg.contractId, "get_payees", { agent: AGENT });
  return merchants.every((r) => ps.some((p) => p.rail === "paypal" && p.receiver === r)) ? ps : undefined;
});
console.log(`get_mandate.paypal: ${JSON.stringify(m.paypal)}, max_validity_secs ${m.max_validity_secs}; merchants: ${listed.map((p) => maskEmail(p.receiver)).join(", ")}`);

// 4. Delete the contract account's full-access key; only agents' function-call keys stay.
const full = (await accessKeys(cfg, cfg.contractId)).filter(isFullAccess).map((k) => k.public_key);
if (full.length) step("delete full-access key", nearCli(["account", "delete-keys", cfg.contractId, "public-keys", full.join(","), "network-config", NETWORK, "sign-with-legacy-keychain", "send"]));
const keys = await waitFor("no full-access key left", async () => {
  const ks = await accessKeys(cfg, cfg.contractId);
  return !ks.some(isFullAccess) && ks.some((k) => k.public_key === publicKey) ? ks : undefined;
});
const p = keys.find((k) => k.public_key === publicKey)!.access_key.permission;
if (p === "FullAccess" || p.FunctionCall.receiver_id !== cfg.contractId || JSON.stringify(p.FunctionCall.method_names) !== JSON.stringify(AGENT_METHOD_NAMES)) {
  throw new Error(`agent key has the wrong permission: ${JSON.stringify(p)}`);
}
console.log(`access keys on ${cfg.contractId}:\n${describeKeys(keys)}`);
console.log("PASS: fresh contract with Hank's paypal rail and 3 card shops; no full-access key left");
