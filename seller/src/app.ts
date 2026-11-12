// The demo seller: one x402-paid route, GET /weather, priced in USDC on Base Sepolia.
import express, { type Express } from "express";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import type { FacilitatorClient } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { MAX_TIMEOUT_SECONDS, NETWORK, USDC_BASE_SEPOLIA, type SellerConfig } from "./config.ts";

export const WEATHER = {
  location: "Berlin",
  forecast: "light rain",
  temperatureC: 11,
  windKph: 14,
  source: "nearH demo fixture",
} as const;

export function createApp(config: SellerConfig, facilitator: FacilitatorClient): Express {
  const resourceServer = new x402ResourceServer(facilitator).register(NETWORK, new ExactEvmScheme());

  const app = express();
  app.disable("x-powered-by");
  app.use(
    paymentMiddleware(
      {
        "GET /weather": {
          accepts: {
            scheme: "exact",
            network: NETWORK,
            payTo: config.payTo,
            // An explicit asset amount, so no USD-to-token conversion happens. The EIP-712
            // domain in `extra` is what the x402 client signs over (docs/interfaces.md §3).
            price: { asset: USDC_BASE_SEPOLIA, amount: config.amount, extra: { name: "USDC", version: "2" } },
            maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
          },
          description: "Demo weather report",
          mimeType: "application/json",
        },
      },
      resourceServer,
    ),
  );
  app.get("/weather", (_req, res) => {
    res.json(WEATHER);
  });
  return app;
}
