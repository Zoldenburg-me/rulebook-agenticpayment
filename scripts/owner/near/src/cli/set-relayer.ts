// pnpm set-relayer <account.testnet | none>: names the relayer; checks get_config.relayer.
import { setRelayerArgs } from "../borsh.ts";
import { assertTestnet, config, waitFor } from "../near.ts";
import { getConfig, ownerCall } from "../owner.ts";

const cfg = config();
const arg = process.argv[2];
if (!arg) throw new Error("usage: set-relayer <account.testnet | none>");
const account = arg === "none" ? null : assertTestnet("relayer", arg);
const { nonce } = await ownerCall(cfg, "set_relayer", { account }, setRelayerArgs(account));
const c = await waitFor("get_config shows the relayer", async () => {
  const c = await getConfig(cfg);
  return c.owner_nonce >= nonce ? c : undefined;
});
if (c.relayer !== account) throw new Error(`relayer is ${c.relayer}, expected ${account}`);
console.log(`PASS: relayer = ${c.relayer}`);
