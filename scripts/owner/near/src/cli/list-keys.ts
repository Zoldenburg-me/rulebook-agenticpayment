// pnpm list-keys: the contract account's access keys (public keys and permissions only).
import { accessKeys, config, describeKeys } from "../near.ts";

const cfg = config();
console.log(`access keys on ${cfg.contractId}:\n${describeKeys(await accessKeys(cfg, cfg.contractId))}`);
