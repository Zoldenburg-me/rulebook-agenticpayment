// pnpm deploy-contract [wasm]: deploys the mandate contract to $CONTRACT_ID with `new` (passkey owner =
// the software owner key), then deletes every full-access key on the account and checks that
// none remain. $CONTRACT_ID must exist with its full-access key in ~/.near-credentials and no
// code yet: deploying over existing state is refused, so old state can never pass for `new`.
import { isDeepStrictEqual } from "node:util";
import { accessKeys, codeHash, config, describeKeys, env, EMPTY_CODE_HASH, isFullAccess, NETWORK, nearCli, waitFor } from "../near.ts";
import { loadOwnerKey } from "../keys.ts";
import { getConfig } from "../owner.ts";

const cfg = config();
const wasm = process.argv[2] ?? "../../../target/near/mandate/mandate.wasm";
const rpId = env("OWNER_RP_ID", "localhost");
const origin = env("OWNER_ORIGIN", "http://localhost:5173");
const owner = loadOwnerKey(cfg);

const init = {
  owner: { mode: "passkey", public_key: Buffer.from(owner.publicKey).toString("base64"), rp_id: rpId, origin },
  network: NETWORK,
  mpc_contract: cfg.mpcContract,
};
if ((await codeHash(cfg, cfg.contractId)) !== EMPTY_CODE_HASH) {
  throw new Error(`${cfg.contractId} already has code; deploy-contract only deploys to a fresh account`);
}
const d = nearCli([
  "contract", "deploy", cfg.contractId, "use-file", wasm,
  "with-init-call", "new", "json-args", JSON.stringify(init),
  "prepaid-gas", "100 Tgas", "attached-deposit", "0 NEAR",
  "network-config", NETWORK, "sign-with-legacy-keychain", "send",
]);
console.log(`deploy + new: tx ${d.txHash ?? "(none printed)"}`);
if (!d.ok || !d.txHash) {
  console.log(d.out);
  throw new Error("deploy + new did not go through; not deleting keys");
}

// Never delete the keys of an account whose state is not ours: check `new` ran with our args.
const c = await waitFor("get_config after new", async () => {
  try {
    return await getConfig(cfg);
  } catch {
    return undefined;
  }
});
const expected = { ...init, owner_nonce: 0, relayer: null };
if (!isDeepStrictEqual(c, expected)) {
  throw new Error(`get_config is not what new was called with; not deleting keys: ${JSON.stringify(c)}`);
}
if (c.owner.mode !== "passkey") throw new Error("unreachable");
console.log(`get_config: passkey owner ${c.owner.rp_id} ${c.owner.origin}, network ${c.network}, mpc ${c.mpc_contract}`);

const full = (await accessKeys(cfg, cfg.contractId)).filter(isFullAccess).map((k) => k.public_key);
if (full.length > 0) {
  const del = nearCli([
    "account", "delete-keys", cfg.contractId, "public-keys", full.join(","),
    "network-config", NETWORK, "sign-with-legacy-keychain", "send",
  ]);
  console.log(`delete full-access keys ${full.join(", ")}: tx ${del.txHash ?? "(none printed)"}`);
  if (!del.ok) console.log(del.out);
}
const keys = await waitFor("no full-access key remains", async () => {
  const ks = await accessKeys(cfg, cfg.contractId);
  return ks.some(isFullAccess) ? undefined : ks;
});
console.log(`access keys on ${cfg.contractId}:\n${describeKeys(keys)}`);
console.log("PASS: deployed, initialized, no full-access key");
