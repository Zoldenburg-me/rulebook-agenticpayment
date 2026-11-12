import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { Account, JsonRpcProvider, KeyPairSigner } from "near-api-js";
import { hashMessage, recoverAddress, serializeSignature } from "viem";
import { publicKeyToAddress } from "viem/accounts";

// near-cli-rs key files carry no account_id; legacy near-cli files must name this account.
export function credentialFor(credential, accountId) {
  return typeof credential?.private_key === "string" &&
    (credential.account_id === undefined || credential.account_id === accountId);
}

export async function mpcSigner(env, record) {
  const accountId = env.NEAR_ACCOUNT_ID;
  if (!/^[a-z0-9][a-z0-9._-]*\.testnet$/.test(accountId ?? "") || accountId.length > 64) {
    throw new Error("Set NEAR_ACCOUNT_ID to your own funded testnet account");
  }
  const contractId = "v1.signer-prod.testnet";
  const path = env.CHAINSIG_PATH || "nearh-sb-monerium";
  const provider = new JsonRpcProvider({ url: "https://rpc.testnet.near.org" });
  let credential;
  try { credential = JSON.parse(await readFile(join(homedir(), ".near-credentials/testnet", `${accountId}.json`), "utf8")); }
  catch { throw new Error("Missing or invalid testnet keychain file for NEAR_ACCOUNT_ID; key withheld"); }
  if (!credentialFor(credential, accountId)) throw new Error("Testnet credential does not match NEAR_ACCOUNT_ID");
  let account;
  try { account = new Account(accountId, provider, KeyPairSigner.fromSecretKey(credential.private_key)); }
  catch { throw new Error("Invalid testnet signing key; key withheld"); }
  const nearKey = await provider.callFunction({ contractId, method: "derived_public_key", args: { path, predecessor: accountId, domain_id: 0 } });
  if (typeof nearKey !== "string" || !nearKey.startsWith("secp256k1:")) throw new Error("Unexpected MPC derived public key scheme");
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let n = 0n;
  for (const c of nearKey.slice(10)) {
    const digit = alphabet.indexOf(c);
    if (digit < 0) throw new Error("Invalid MPC public key encoding");
    n = n * 58n + BigInt(digit);
  }
  const keyHex = n.toString(16).padStart(128, "0");
  if (keyHex.length !== 128) throw new Error("Invalid MPC public key length");
  const address = publicKeyToAddress(`0x04${keyHex}`);
  record({ step: "derived_address", address, accountId, path });
  return {
    address,
    async sign(message) {
      const hash = hashMessage(message);
      let result;
      try {
        result = await account.callFunctionRaw({ contractId, methodName: "sign",
          args: { request: { payload_v2: { Ecdsa: hash.slice(2) }, path, domain_id: 0 } },
          gas: 300_000_000_000_000n, deposit: 1n,
        });
      } catch { throw new Error("NEAR testnet sign failed or timed out; inspect the account before retrying"); }
      const value = result.status?.SuccessValue;
      if (typeof value !== "string") throw new Error("MPC sign did not return SuccessValue");
      const sig = JSON.parse(Buffer.from(value, "base64").toString());
      if (sig.scheme !== "Secp256k1" || !/^0[23][0-9a-f]{64}$/i.test(sig.big_r?.affine_point ?? "") ||
          !/^[0-9a-f]{64}$/i.test(sig.s?.scalar ?? "") || ![0, 1].includes(sig.recovery_id)) throw new Error("Invalid MPC signature response");
      const signature = serializeSignature({ r: `0x${sig.big_r.affine_point.slice(2)}`, s: `0x${sig.s.scalar}`, yParity: sig.recovery_id });
      const recovered = await recoverAddress({ hash, signature });
      if (recovered.toLowerCase() !== address.toLowerCase()) throw new Error("MPC signature recovers to another address");
      record({ step: "mpc_sign", nearTx: result.transaction.hash, recoveredAddressMatches: true });
      return signature;
    },
  };
}
