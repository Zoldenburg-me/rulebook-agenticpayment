// The x402 `exact` client scheme for EVM, on the NEAR signer. It takes the place of
// `@x402/evm`'s `ExactEvmScheme`: that one builds the authorization (nonce, validity) locally
// and asks the signer to sign it, but here the mandate contract builds it, so this scheme sends
// the payment requirements to `request_signature` and returns the contract-built authorization.

import type { PaymentPayloadResult, PaymentRequirements, SchemeNetworkClient } from "@x402/core/types";
import type { PaymentCreationContext } from "@x402/core/client";
import { findDefaultAsset } from "@x402/evm";
import { NearX402Signer, USDC_DOMAIN } from "./signer.ts";

export class NearExactEvmScheme implements SchemeNetworkClient {
  readonly scheme = "exact";
  /** Lets `x402Client`'s default spend controls recognise USDC, as with `ExactEvmScheme`. */
  readonly findDefaultAsset = findDefaultAsset;
  private readonly signer: NearX402Signer;
  /** Resource URL per selected requirements object, from the 402 response (the shape needs it). */
  private readonly resources = new WeakMap<object, string>();
  readonly schemeHooks;

  constructor(signer: NearX402Signer) {
    this.signer = signer;
    this.schemeHooks = {
      onBeforePaymentCreation: async (ctx: PaymentCreationContext) => {
        this.resources.set(ctx.selectedRequirements, ctx.paymentRequired.resource?.url ?? "");
      },
    };
  }

  async createPaymentPayload(x402Version: number, requirements: PaymentRequirements): Promise<PaymentPayloadResult> {
    if (x402Version !== 2) throw new Error(`x402 v${x402Version} is not supported (v2 only)`);
    const method = requirements.extra?.assetTransferMethod ?? "eip3009";
    if (method !== "eip3009") throw new Error(`asset transfer method ${String(method)} is not supported (EIP-3009 only)`);
    // The facilitator verifies against the seller's domain; the contract always signs USDC's.
    if (requirements.extra?.name !== USDC_DOMAIN.name || requirements.extra?.version !== USDC_DOMAIN.version) {
      throw new Error(`EIP-712 domain ${JSON.stringify([requirements.extra?.name, requirements.extra?.version])} is not USDC v2`);
    }
    const resourceUrl = this.resources.get(requirements);
    if (resourceUrl === undefined) throw new Error("no resource for these payment requirements (use the x402Client this scheme is registered on)");
    const { payload } = await this.signer.signX402({
      resourceUrl,
      scheme: requirements.scheme,
      network: requirements.network,
      asset: requirements.asset,
      payTo: requirements.payTo,
      amount: requirements.amount,
      maxTimeoutSeconds: requirements.maxTimeoutSeconds,
    });
    return { x402Version, payload };
  }
}
