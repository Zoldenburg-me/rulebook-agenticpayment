// One owner call: read owner_nonce from the contract, sign the challenge with the owner key,
// submit through any NEAR account. The caller then checks the state it expected.

import { bytesToHex } from "@noble/hashes/utils.js";
import { buildAssertion, softwareSigner, type OwnerAssertion } from "./challenge.ts";
import { loadOwnerKey } from "./keys.ts";
import { callContract, env, NETWORK, view, type Config } from "./near.ts";

/** Seconds until the assertion expires; the contract allows at most 600 past block time. */
const ASSERTION_TTL_SECS = 300;

export type ConfigView = {
  owner: { mode: "passkey"; public_key: string; rp_id: string; origin: string } | { mode: "wallet"; account: string };
  owner_nonce: number;
  network: string;
  mpc_contract: string;
  relayer: string | null;
};

export const getConfig = (cfg: Config) => view<ConfigView>(cfg, cfg.contractId, "get_config");

/**
 * Signs and submits `method(args..., assertion)`. `borshArgs` must encode exactly `jsonArgs`
 * (the contract hashes the arguments as received). Returns the tx hash, if any, for the log.
 */
export async function ownerCall(
  cfg: Config,
  method: string,
  jsonArgs: Record<string, unknown>,
  borshArgs: Uint8Array,
  gas?: string,
): Promise<{ txHash?: string; nonce: number }> {
  const c = await getConfig(cfg);
  if (c.owner.mode !== "passkey") throw new Error("these scripts sign for a passkey owner; the contract is in wallet mode");
  if (c.network !== NETWORK) throw new Error(`contract network is ${c.network}, expected ${NETWORK}`);
  const key = loadOwnerKey(cfg);
  if (Buffer.from(c.owner.public_key, "base64").toString("hex") !== bytesToHex(key.publicKey)) {
    throw new Error("the local owner key is not this contract's owner");
  }
  const nonce = c.owner_nonce + 1;
  const assertion: OwnerAssertion = buildAssertion(
    {
      contractId: cfg.contractId,
      network: c.network,
      method,
      args: borshArgs,
      ownerNonce: nonce,
      expiresAt: Math.floor(Date.now() / 1000) + ASSERTION_TTL_SECS,
      rpId: c.owner.rp_id,
      origin: c.owner.origin,
    },
    softwareSigner(key.secret),
  );
  const submitter = env("SUBMITTER_ACCOUNT_ID");
  const r = callContract(cfg, submitter, method, { ...jsonArgs, assertion }, gas);
  console.log(`${method}: submitted by ${submitter}, owner_nonce ${nonce}, tx ${r.txHash ?? "(none printed)"}`);
  if (!r.ok || !r.txHash) console.log(r.out);
  return { txHash: r.txHash, nonce };
}
