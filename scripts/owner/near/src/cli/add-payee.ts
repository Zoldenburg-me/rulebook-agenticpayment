// pnpm add-payee <agent> x402 <0x address> | sepa <IBAN>: allowlists a payee; checks get_payees.
import { isDeepStrictEqual } from "node:util";
import { payeeArgs, type Payee } from "../borsh.ts";
import { assertAgentId, config, view, waitFor } from "../near.ts";
import { getConfig, ownerCall } from "../owner.ts";

const cfg = config();
const [agent, rail, value] = process.argv.slice(2);
if (!agent || !value || (rail !== "x402" && rail !== "sepa")) {
  throw new Error("usage: add-payee <agent> x402 <0x address> | sepa <IBAN>");
}
assertAgentId(agent);
const payee: Payee = rail === "x402" ? { rail, pay_to: value } : { rail, iban: value };
const { nonce } = await ownerCall(cfg, "add_payee", { agent, payee }, payeeArgs(agent, payee));
await waitFor("owner_nonce consumed", async () => ((await getConfig(cfg)).owner_nonce >= nonce ? true : undefined));
const want = rail === "x402" ? { rail, pay_to: value.toLowerCase() } : payee;
const payees = await view<Payee[]>(cfg, cfg.contractId, "get_payees", { agent });
if (!payees.some((p) => isDeepStrictEqual(p, want))) {
  throw new Error(`get_payees does not list ${JSON.stringify(want)}: ${JSON.stringify(payees)}`);
}
console.log(`PASS: payees of ${agent} = ${JSON.stringify(payees)}`);
