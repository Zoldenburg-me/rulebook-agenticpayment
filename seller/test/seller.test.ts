// Offline: the facilitator is an in-process stub, the seller listens on 127.0.0.1.
import { strict as assert } from "node:assert";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { once } from "node:events";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import type { FacilitatorClient } from "@x402/core/server";
import {
  decodePaymentRequiredHeader,
  decodePaymentResponseHeader,
  encodePaymentSignatureHeader,
} from "@x402/core/http";
import type {
  PaymentPayload,
  PaymentRequired,
  PaymentRequirements,
  SettleResponse,
  SupportedResponse,
  VerifyResponse,
} from "@x402/core/types";
import { createApp, WEATHER } from "../src/app.ts";
import { envWithFiles, loadConfig, type SellerConfig } from "../src/config.ts";

const PAY_TO = "0xeEa5E3BcC1E058AEf9586a1C5c4CaDC9cFdbC74F";
const PAYER = "0x1111111111111111111111111111111111111111";
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const TX = `0x${"ab".repeat(32)}`;

class StubFacilitator implements FacilitatorClient {
  verifyResult: VerifyResponse = { isValid: true, payer: PAYER };
  settleResult: SettleResponse = { success: true, payer: PAYER, transaction: TX, network: "eip155:84532" };
  verified: PaymentRequirements[] = [];
  settled: PaymentRequirements[] = [];

  async getSupported(): Promise<SupportedResponse> {
    return { kinds: [{ x402Version: 2, scheme: "exact", network: "eip155:84532" }], extensions: [], signers: {} };
  }
  async verify(_p: PaymentPayload, req: PaymentRequirements): Promise<VerifyResponse> {
    this.verified.push(req);
    return this.verifyResult;
  }
  async settle(_p: PaymentPayload, req: PaymentRequirements): Promise<SettleResponse> {
    this.settled.push(req);
    return this.settleResult;
  }
}

const config: SellerConfig = loadConfig({ SELLER_PAY_TO: PAY_TO });

async function start(facilitator: FacilitatorClient): Promise<{ server: Server; url: string }> {
  const server = createApp(config, facilitator).listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/weather` };
}

async function requirementsFrom(url: string): Promise<PaymentRequired> {
  const res = await fetch(url);
  assert.equal(res.status, 402);
  const header = res.headers.get("payment-required");
  assert.ok(header, "402 carries a PAYMENT-REQUIRED header");
  return decodePaymentRequiredHeader(header);
}

// A payment the stub can verify: the shape an x402 exact/EVM client sends. The signature is
// a placeholder; signature checks are the facilitator's job, and the stub decides the result.
function paymentFor(required: PaymentRequired, accepted = required.accepts[0]): string {
  const now = Math.floor(Date.now() / 1000);
  return encodePaymentSignatureHeader({
    x402Version: 2,
    resource: required.resource,
    accepted,
    payload: {
      signature: `0x${"11".repeat(65)}`,
      authorization: {
        from: PAYER,
        to: accepted.payTo,
        value: accepted.amount,
        validAfter: String(now - 60),
        validBefore: String(now + 240),
        nonce: `0x${"22".repeat(32)}`,
      },
    },
  });
}

describe("seller GET /weather", () => {
  let facilitator: StubFacilitator;
  let server: Server;
  let url: string;

  before(async () => {
    facilitator = new StubFacilitator();
    ({ server, url } = await start(facilitator));
  });
  after(() => new Promise<void>((resolve) => server.close(() => resolve())));

  it("without a payment returns 402 with the configured requirements", async () => {
    const required = await requirementsFrom(url);
    assert.equal(required.x402Version, 2);
    assert.equal(required.resource.url, url);
    assert.equal(required.accepts.length, 1);
    assert.deepEqual(required.accepts[0], {
      scheme: "exact",
      network: "eip155:84532",
      asset: USDC,
      amount: "10000",
      payTo: PAY_TO,
      maxTimeoutSeconds: 240,
      extra: { name: "USDC", version: "2" },
    });
    assert.equal(facilitator.verified.length, 0);
  });

  it("serves the resource once the facilitator verifies and settles the payment", async () => {
    facilitator.verifyResult = { isValid: true, payer: PAYER };
    facilitator.settleResult = { success: true, payer: PAYER, transaction: TX, network: "eip155:84532" };
    const required = await requirementsFrom(url);
    const res = await fetch(url, { headers: { "PAYMENT-SIGNATURE": paymentFor(required) } });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), WEATHER);
    const receipt = res.headers.get("payment-response");
    assert.ok(receipt, "200 carries a PAYMENT-RESPONSE header");
    assert.equal(decodePaymentResponseHeader(receipt).transaction, TX);
    assert.equal(facilitator.verified.at(-1)?.payTo, PAY_TO);
    assert.equal(facilitator.settled.at(-1)?.payTo, PAY_TO);
  });

  it("withholds the resource when the facilitator rejects the payment", async () => {
    facilitator.verifyResult = { isValid: false, invalidReason: "invalid_exact_evm_payload_signature", payer: PAYER };
    const settledBefore = facilitator.settled.length;
    const required = await requirementsFrom(url);
    const res = await fetch(url, { headers: { "PAYMENT-SIGNATURE": paymentFor(required) } });
    assert.equal(res.status, 402);
    assert.notDeepEqual(await res.json().catch(() => null), WEATHER);
    assert.equal(facilitator.settled.length, settledBefore, "a rejected payment is never settled");
  });

  it("withholds the resource when settlement fails", async () => {
    facilitator.verifyResult = { isValid: true, payer: PAYER };
    facilitator.settleResult = { success: false, errorReason: "insufficient_funds", transaction: "", network: "eip155:84532" };
    const required = await requirementsFrom(url);
    const res = await fetch(url, { headers: { "PAYMENT-SIGNATURE": paymentFor(required) } });
    assert.equal(res.status, 402);
    assert.notDeepEqual(await res.json().catch(() => null), WEATHER);
  });

  it("rejects a payment made to a different payTo without asking the facilitator", async () => {
    facilitator.verifyResult = { isValid: true, payer: PAYER };
    facilitator.settleResult = { success: true, payer: PAYER, transaction: TX, network: "eip155:84532" };
    const verifiedBefore = facilitator.verified.length;
    const required = await requirementsFrom(url);
    const swapped = { ...required.accepts[0], payTo: "0x2222222222222222222222222222222222222222" };
    const res = await fetch(url, { headers: { "PAYMENT-SIGNATURE": paymentFor(required, swapped) } });
    assert.equal(res.status, 402);
    assert.notDeepEqual(await res.json().catch(() => null), WEATHER);
    assert.equal(facilitator.verified.length, verifiedBefore);
  });
});

describe("seller config", () => {
  it("accepts a valid SELLER_PAY_TO and applies the defaults", () => {
    assert.deepEqual(loadConfig({ SELLER_PAY_TO: PAY_TO }), {
      port: 4021,
      payTo: PAY_TO,
      amount: "10000",
      facilitatorUrl: "https://x402.org/facilitator",
    });
  });

  for (const [name, value] of [
    ["missing", undefined],
    ["empty", ""],
    ["not hex", "0xzz5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f0"],
    ["too short", "0xeea5e3bcc1e058aef9586a1c5c4cadc9cfdbc7"],
    ["no 0x prefix", "eea5e3bcc1e058aef9586a1c5c4cadc9cfdbc74f"],
    ["zero address", "0x0000000000000000000000000000000000000000"],
  ] as const) {
    it(`rejects SELLER_PAY_TO ${name}`, () => {
      assert.throws(() => loadConfig(value === undefined ? {} : { SELLER_PAY_TO: value }), /SELLER_PAY_TO/);
    });
  }

  it("rejects a bad port, amount or facilitator URL", () => {
    assert.throws(() => loadConfig({ SELLER_PAY_TO: PAY_TO, SELLER_PORT: "70000" }), /SELLER_PORT/);
    assert.throws(() => loadConfig({ SELLER_PAY_TO: PAY_TO, SELLER_AMOUNT: "0" }), /SELLER_AMOUNT/);
    assert.throws(() => loadConfig({ SELLER_PAY_TO: PAY_TO, SELLER_AMOUNT: "0.01" }), /SELLER_AMOUNT/);
    assert.throws(() => loadConfig({ SELLER_PAY_TO: PAY_TO, X402_FACILITATOR_URL: "not a url" }), /X402_FACILITATOR_URL/);
  });

  it("requires an https facilitator unless it is on loopback", () => {
    for (const bad of ["http://x402.org/facilitator", "http://192.168.1.5:8080", "http://localhost.evil.example", "ftp://localhost"]) {
      assert.throws(() => loadConfig({ SELLER_PAY_TO: PAY_TO, X402_FACILITATOR_URL: bad }), /X402_FACILITATOR_URL must be https/, bad);
    }
    for (const good of ["https://facilitator.example/x402", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"]) {
      assert.equal(loadConfig({ SELLER_PAY_TO: PAY_TO, X402_FACILITATOR_URL: good }).facilitatorUrl, good);
    }
  });

  it("reads the root .env, lets seller/.env override it, and lets the shell win over both", () => {
    const dir = mkdtempSync(join(tmpdir(), "seller-env-"));
    try {
      const root = join(dir, "root.env");
      const seller = join(dir, "seller.env");
      writeFileSync(root, `SELLER_PAY_TO=${PAY_TO}\nSELLER_AMOUNT=500\nSELLER_PORT=4100\n`);
      assert.equal(loadConfig(envWithFiles([root, join(dir, "missing.env")], {})).payTo, PAY_TO);

      writeFileSync(seller, "SELLER_AMOUNT=700\n");
      const merged = loadConfig(envWithFiles([root, seller], { SELLER_PORT: "4200" }));
      assert.deepEqual([merged.payTo, merged.amount, merged.port], [PAY_TO, "700", 4200]);

      assert.deepEqual(envWithFiles([join(dir, "none-a.env"), join(dir, "none-b.env")], { A: "1" }), { A: "1" });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("the server process refuses to start without a valid SELLER_PAY_TO", () => {
    const main = fileURLToPath(new URL("../src/main.ts", import.meta.url));
    for (const payTo of [undefined, "0x1234"]) {
      // An empty SELLER_PAY_TO beats any value in a local .env file.
      const env: NodeJS.ProcessEnv = { PATH: process.env.PATH, SELLER_PORT: "0", SELLER_PAY_TO: payTo ?? "" };
      const run = spawnSync(process.execPath, [main], { env, encoding: "utf8", timeout: 10_000 });
      assert.equal(run.status, 1, `exit code for SELLER_PAY_TO=${payTo}`);
      assert.match(run.stderr, /SELLER_PAY_TO/);
    }
  });

  it("the server process listens on 127.0.0.1 only", async () => {
    const main = fileURLToPath(new URL("../src/main.ts", import.meta.url));
    const probe = createServer().listen(0, "127.0.0.1");
    await once(probe, "listening");
    const port = (probe.address() as AddressInfo).port;
    await new Promise((resolve) => probe.close(resolve));
    // A dead loopback facilitator keeps this offline: startup only logs that it is unreachable.
    const env: NodeJS.ProcessEnv = {
      PATH: process.env.PATH,
      SELLER_PORT: String(port),
      SELLER_PAY_TO: PAY_TO,
      X402_FACILITATOR_URL: "http://127.0.0.1:9",
    };
    const child = spawn(process.execPath, [main], { env, stdio: ["ignore", "pipe", "pipe"] });
    try {
      const line = await new Promise<string>((resolve, reject) => {
        let out = "";
        child.stdout.on("data", (chunk) => {
          out += chunk;
          if (out.includes("\n")) resolve(out);
        });
        child.once("exit", (code) => reject(new Error(`seller exited ${code} before listening`)));
      });
      assert.match(line, new RegExp(`^seller: GET http://127\\.0\\.0\\.1:${port}/weather `));
    } finally {
      child.kill();
    }
  });
});
