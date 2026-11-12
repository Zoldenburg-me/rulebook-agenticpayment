// The owner's passkey Safe on Base Sepolia (Candide abstractionkit, ERC-4337). Every Safe tx
// is one sponsored UserOperation signed with one passkey tap; the first one also deploys it.

import {
  Erc7677Paymaster,
  SafeMultiChainSigAccountV1 as SafeAccount,
  fromSafeWebauthn,
  webauthnSignatureFromAssertion,
  type MetaTransaction,
  type WebauthnPublicKey,
} from "abstractionkit";
import { BASE_SEPOLIA_CHAIN_ID, ethRpc, type BaseConfig } from "./base.ts";
import { loadPasskey, tap } from "./passkey.ts";

/** The Safe address a passkey controls (counterfactual until the first UserOperation). */
export const safeAddressFor = (pk: WebauthnPublicKey): string => SafeAccount.initializeNewAccount([pk]).accountAddress;

/** Sends `calls` from the owner's Safe after one tap; `beforeSend` runs after the tap and may refuse. Returns the Base tx hash; throws on revert. */
export async function sendFromSafe(
  cfg: BaseConfig,
  calls: MetaTransaction[],
  summary: string,
  beforeSend: () => Promise<void> = async () => {},
): Promise<string> {
  const pk = loadPasskey();
  if (safeAddressFor(pk.publicKey).toLowerCase() !== pk.safe_address.toLowerCase()) {
    throw new Error("passkey file: safe_address does not match the passkey");
  }
  const deployed = (await ethRpc(cfg.rpc, "eth_getCode", [pk.safe_address, "latest"])) !== "0x";
  const account = deployed ? new SafeAccount(pk.safe_address) : SafeAccount.initializeNewAccount([pk.publicKey]);

  let op = await account.createUserOperation(calls, cfg.rpc, cfg.bundler, { expectedSigners: [pk.publicKey] });
  op = (await new Erc7677Paymaster(cfg.paymaster).createPaymasterUserOperation(account, op, cfg.bundler)).userOperation;

  const signer = fromSafeWebauthn({
    publicKey: pk.publicKey,
    isInit: op.nonce === 0n,
    accountClass: SafeAccount,
    getAssertion: async (challenge: Uint8Array) => {
      const a = await tap({ mode: "get", summary, challenge, credentialId: pk.credential_id });
      const b = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));
      return webauthnSignatureFromAssertion({
        authenticatorData: b(a.authenticatorData),
        clientDataJSON: b(a.clientDataJSON),
        signature: b(a.signature),
      });
    },
  });
  op.signature = await account.signUserOperationWithSigners(op, [signer], BASE_SEPOLIA_CHAIN_ID);
  await beforeSend();

  const sent = await account.sendUserOperation(op, cfg.bundler);
  console.log(`userOp ${sent.userOperationHash}${deployed ? "" : " (also deploys the Safe)"}`);
  const receipt = await sent.included();
  if (!receipt) throw new Error("timed out waiting for the UserOperation");
  const tx = receipt.receipt.transactionHash;
  if (!receipt.success) throw new Error(`UserOperation reverted in tx ${tx}`);
  return tx;
}
