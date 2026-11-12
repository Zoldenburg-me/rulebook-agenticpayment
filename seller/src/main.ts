// `pnpm --filter seller start`: reads env (root .env, then seller/.env; see .env.example) and serves on SELLER_PORT.
import type { AddressInfo } from "node:net";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { createApp } from "./app.ts";
import { envWithFiles, loadConfig } from "./config.ts";

// Loopback only: the demo buyer runs on the same machine.
const HOST = "127.0.0.1";

let config;
try {
  config = loadConfig(envWithFiles());
} catch (error) {
  console.error(`seller: ${(error as Error).message}`);
  process.exit(1);
}
const app = createApp(config, new HTTPFacilitatorClient({ url: config.facilitatorUrl }));
const server = app.listen(config.port, HOST, () => {
  const { address, port } = server.address() as AddressInfo;
  console.log(`seller: GET http://${address}:${port}/weather (payTo ${config.payTo}, facilitator ${config.facilitatorUrl})`);
});
