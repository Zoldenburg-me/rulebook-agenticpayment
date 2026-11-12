// x402 buying on the NEAR signer: `@x402/fetch` with the `exact` EVM scheme registered for
// Base Sepolia only, so every payment is signed through the mandate contract.

import { wrapFetchWithPayment, x402Client } from "@x402/fetch";
import { NearExactEvmScheme } from "./scheme.ts";
import type { NearX402Signer } from "./signer.ts";

export { NearExactEvmScheme } from "./scheme.ts";
export * from "./signer.ts";
export { httpRpc, parseNearKey, type NearKey, type Rpc } from "./near.ts";

/** The one network the contract signs for (`BASE_SEPOLIA_CHAIN_ID`). */
export const BASE_SEPOLIA = "eip155:84532";

export function nearX402Client(signer: NearX402Signer): x402Client {
  return new x402Client().register(BASE_SEPOLIA, new NearExactEvmScheme(signer));
}

/** `fetch` that answers an x402 `402` with a contract-signed payment and retries once. */
export function nearX402Fetch(signer: NearX402Signer, fetchFn: typeof fetch = fetch) {
  return wrapFetchWithPayment(fetchFn, nearX402Client(signer));
}

export { assertTestnet, assertTestnetRpc, callAndWait, failureMessage, view } from "./near.ts";
