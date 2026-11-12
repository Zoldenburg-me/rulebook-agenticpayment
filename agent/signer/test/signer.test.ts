// Offline: @x402/fetch pays the SE1 seller (in process, on 127.0.0.1) through the NEAR signer,
// with a fake NEAR RPC running the contract's shape-2 path on T1's mock MPC key, and a
// facilitator stub that verifies the EIP-3009 signature itself. Nothing touches the network.
import { strict as assert } from "node:assert";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, beforeEach, describe, it } from "node:test";
import type { FacilitatorClient } from "@x402/core/server";
import { decodePaymentResponseHeader } from "@x402/core/http";
import type { PaymentPayload, PaymentRequired, PaymentRequirements, SettleResponse, SupportedResponse, VerifyResponse } from "@x402/core/types";
import { getAddress, recoverTypedDataAddress, type Hex } from "viem";
import { createApp, WEATHER } from "seller/src/app.ts";
import { loadConfig } from "seller/src/config.ts";
import { AUTHORIZATION_TYPES, BASE_SEPOLIA, NearX402Signer, nearX402Client, nearX402Fetch, newRequestId, parseNearKey, SettlementWindowError, type X402Shape } from "../src/index.ts";
import { agentKey, CONTRACT, FakeNear, mockDerivedKey, PAY_TO, USDC } from "./fake-near.ts";
import { privateKeyToAddress } from "viem/accounts";

/** A facilitator that checks what the x402.org one checks offline: signature, payee, amount, window. */
class VerifyingFacilitator implements FacilitatorClient {
  verified: PaymentPayload[] = [];
  settled: PaymentPayload[] = [];

  async getSupported(): Promise<SupportedResponse> {
    return { kinds: [{ x402Version: 2, scheme: "exact", network: BASE_SEPOLIA }], extensions: [], signers: {} };
  }
  async verify(p: PaymentPayload, req: PaymentRequirements): Promise<VerifyResponse> {
    const reason = await this.check(p, req);
    if (reason) return { isValid: false, invalidReason: reason };
    this.verified.push(p);
    return { isValid: true, payer: (p.payload as any).authorization.from };
  }
  async settle(p: PaymentPayload, req: PaymentRequirements): Promise<SettleResponse> {
    const reason = await this.check(p, req);
    if (reason) return { success: false, errorReason: reason, transaction: "", network: req.network };
    this.settled.push(p);
    return { success: true, payer: (p.payload as any).authorization.from, transaction: `0x${"ab".repeat(32)}`, network: req.network };
  }
  private async check(p: PaymentPayload, req: PaymentRequirements): Promise<string | undefined> {
    const { authorization: a, signature } = p.payload as any;
    const now = Math.floor(Date.now() / 1000);
    if (getAddress(a.to) !== getAddress(req.payTo)) return "wrong_to";
    if (a.value !== req.amount) return "wrong_value";
    if (!(Number(a.validAfter) <= now && now < Number(a.validBefore))) return "outside_window";
    const signer = await recoverTypedDataAddress({
      domain: { name: req.extra.name as string, version: req.extra.version as string, chainId: 84532, verifyingContract: getAddress(req.asset) },
      types: AUTHORIZATION_TYPES,
      primaryType: "TransferWithAuthorization",
      message: { from: a.from, to: a.to, value: BigInt(a.value), validAfter: BigInt(a.validAfter), validBefore: BigInt(a.validBefore), nonce: a.nonce },
      signature: signature as Hex,
    });
    return signer === getAddress(a.from) ? undefined : "invalid_signature";
  }
}

let near: FakeNear;
let facilitator: VerifyingFacilitator;
let server: Server;
let url: string;

async function startSeller(payTo = PAY_TO) {
  server?.close();
  const app = createApp(loadConfig({ SELLER_PAY_TO: payTo }), facilitator);
  server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/weather`;
}

const connect = (opts: { expectedAddress?: string; allowNonTestnet?: boolean; settleMarginSeconds?: number } = {}) =>
  NearX402Signer.connect({ near: near.rpc, contractId: CONTRACT, key: near.key.key, timeoutMs: 2000, pollMs: 5, ...opts });

beforeEach(async () => {
  near = new FakeNear();
  facilitator = new VerifyingFacilitator();
  await startSeller();
});
after(() => server?.close());

describe("NearX402Signer.connect", () => {
  it("takes the agent EOA from the contract: T1's mock-MPC derived address for (contract, agent)", async () => {
    const signer = await connect();
    assert.equal(signer.agent, "agent-1");
    assert.equal(signer.address, privateKeyToAddress(mockDerivedKey(CONTRACT, "agent-1")));
    assert.equal(signer.address, getAddress(near.evmAddress));
  });

  it("refuses an AGENT_EVM_ADDRESS that differs from the contract's", async () => {
    await assert.rejects(connect({ expectedAddress: PAY_TO }), /differs from the contract's/);
  });

  it("refuses a key that is not a live agent key", async () => {
    const other = agentKey(8).key;
    await assert.rejects(NearX402Signer.connect({ near: near.rpc, contractId: CONTRACT, key: other }), /not a live agent key/);
  });

  it("refuses a key for another account (agent keys live on the contract account)", async () => {
    await assert.rejects(NearX402Signer.connect({ near: near.rpc, contractId: CONTRACT, key: { ...near.key.key, accountId: "someone.testnet" } }), /belongs to the mandate contract account/);
  });

  it("refuses an RPC that is not on testnet", async () => {
    near.chainId = "mainnet";
    await assert.rejects(connect(), /on chain "mainnet", not testnet/);
    near.chainId = "localnet";
    await assert.rejects(connect(), /not testnet/);
  });

  it("refuses a contract id that is not a .testnet account", async () => {
    for (const contractId of ["mandate.near", "mandate.test.near", "testnet"]) {
      await assert.rejects(
        NearX402Signer.connect({ near: near.rpc, contractId, key: { ...near.key.key, accountId: contractId } }),
        /contractId must be a \.testnet account/,
      );
    }
  });

  it("allowNonTestnet skips both checks (local sandbox only)", async () => {
    near.chainId = "localnet";
    const signer = await connect({ allowNonTestnet: true });
    assert.equal(signer.agent, "agent-1");
  });

  it("parses the near-cli key format", () => {
    const k = parseNearKey(CONTRACT, near.key.text);
    assert.deepEqual(k.publicKey, near.key.key.publicKey);
    assert.throws(() => parseNearKey(CONTRACT, "secp256k1:abc"), /only ed25519/);
  });
});

describe("@x402/fetch paying SE1 through request_signature", () => {
  it("pays and gets the resource; the facilitator sees a valid signature from the agent EOA", async () => {
    const seen: string[] = [];
    const signer = await NearX402Signer.connect({ near: near.rpc, contractId: CONTRACT, key: near.key.key, onSigned: (s) => seen.push(s.requestId) });
    const res = await nearX402Fetch(signer)(url);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), WEATHER);
    const settlement = decodePaymentResponseHeader(res.headers.get("payment-response")!);
    assert.equal(settlement.success, true);
    assert.equal(settlement.payer, signer.address);

    // One request_signature, carrying exactly the seller's requirements.
    assert.equal(near.requests.length, 1);
    const { shape, request_id } = near.requests[0];
    assert.match(request_id, /^x402-[a-z0-9]+-[0-9a-f]{16}$/);
    assert.deepEqual(seen, [request_id]);
    assert.deepEqual(shape, {
      type: "x402", resourceUrl: url, scheme: "exact", network: BASE_SEPOLIA,
      asset: getAddress(USDC), payTo: PAY_TO, amount: "10000", maxTimeoutSeconds: 240,
    });
    // The payment carries the contract-built authorization (its nonce and window), not a local one.
    assert.equal(facilitator.settled.length, 1);
    const auth = (facilitator.settled[0].payload as any).authorization;
    assert.equal(auth.from, signer.address);
    assert.equal(Number(auth.validBefore) - Number(auth.validAfter), 300);
  });

  it("waits across a send_tx timeout for the MPC callback", async () => {
    near.mode = "slow";
    const res = await nearX402Fetch(await connect())(url);
    assert.equal(res.status, 200);
    assert.equal(facilitator.settled.length, 1);
  });

  it("gives up at the deadline when the MPC never answers, and sends no payment", async () => {
    near.mode = "hold";
    const signer = await NearX402Signer.connect({ near: near.rpc, contractId: CONTRACT, key: near.key.key, timeoutMs: 100, pollMs: 5 });
    await assert.rejects(nearX402Fetch(signer)(url), /no final outcome before the deadline/);
    assert.equal(facilitator.verified.length + facilitator.settled.length, 0);
  });

  it("a failed MPC call (reservation unknown) sends no payment", async () => {
    near.mode = "fail";
    await assert.rejects(nearX402Fetch(await connect())(url), /reservation is unknown, no signature/);
    assert.equal(facilitator.verified.length, 0);
  });

  it("a seller whose payTo is not allowlisted is rejected by the contract; no payment is sent", async () => {
    await startSeller("0x000000000000000000000000000000000000bEEF");
    await assert.rejects(nearX402Fetch(await connect())(url), /ERR_PAYEE_NOT_ALLOWED/);
    assert.equal(near.requests.length, 0);
    assert.equal(facilitator.verified.length, 0);
  });

  it("refuses a signed authorization whose `to` is not the seller's payTo", async () => {
    near.mode = "tamper";
    await assert.rejects(nearX402Fetch(await connect())(url), /signed to does not match/);
    assert.equal(facilitator.verified.length, 0);
  });

  it("refuses a signature that does not recover to the agent EOA", async () => {
    near.mode = "wrong-key";
    await assert.rejects(nearX402Fetch(await connect())(url), /not the agent EOA/);
    assert.equal(facilitator.verified.length, 0);
  });
});

describe("signX402", () => {
  const shape = (maxTimeoutSeconds = 240): X402Shape => ({
    resourceUrl: "http://127.0.0.1/x", scheme: "exact", network: BASE_SEPOLIA, asset: getAddress(USDC), payTo: PAY_TO, amount: "10000", maxTimeoutSeconds,
  });

  it("two concurrent payments get distinct nonces and both succeed, even if the network reorders their txs", async () => {
    near.concurrent = true;
    const signer = await connect();
    const [a, b] = await Promise.all([signer.signX402(shape()), signer.signX402(shape())]);
    assert.notEqual(a.requestId, b.requestId);
    assert.equal(near.requests.length, 2);
    assert.equal(near.nonces.length, 2);
    assert.ok(near.nonces[0] < near.nonces[1]);
  });

  it("refuses a seller window too short to sign and settle before any NEAR call; nothing is reserved", async () => {
    const signer = await connect();
    const err = await signer.signX402(shape(44)).catch((e) => e);
    assert.ok(err instanceof SettlementWindowError);
    assert.equal(err.code, "window-too-short");
    assert.equal(near.requests.length, 0);
    assert.equal(near.nonces.length, 0);
    await signer.signX402(shape(45)); // 15 s signing + 30 s settlement
  });

  it("refuses an authorization that expires before it can settle", async () => {
    near.maxValidBeforeSecs = 20; // the contract signed, but only 20 s of the window are left
    const signer = await connect();
    const err = await signer.signX402(shape()).catch((e) => e);
    assert.ok(err instanceof SettlementWindowError);
    assert.equal(err.code, "expires-too-soon");
    assert.equal(near.requests.length, 1);
  });

  it("the settlement margin is configurable", async () => {
    near.maxValidBeforeSecs = 20;
    const signed = await (await connect({ settleMarginSeconds: 10 })).signX402(shape());
    assert.ok(Number(signed.payload.authorization.validBefore) - Date.now() / 1000 >= 10);
  });
});

describe("NearExactEvmScheme", () => {
  const required = (extra: Record<string, unknown>): PaymentRequired => ({
    x402Version: 2,
    resource: { url: "http://127.0.0.1/x", description: "", mimeType: "application/json" },
    accepts: [{ scheme: "exact", network: BASE_SEPOLIA, asset: getAddress(USDC), amount: "10000", payTo: PAY_TO, maxTimeoutSeconds: 60, extra }],
  });

  it("refuses an EIP-712 domain other than USDC v2 before any NEAR call", async () => {
    const client = nearX402Client(await connect());
    await assert.rejects(client.createPaymentPayload(required({ name: "USD Coin", version: "2" })), /is not USDC v2/);
    assert.equal(near.requests.length, 0);
  });

  it("refuses Permit2 requirements", async () => {
    const client = nearX402Client(await connect());
    await assert.rejects(client.createPaymentPayload(required({ name: "USDC", version: "2", assetTransferMethod: "permit2" })), /EIP-3009 only/);
  });

  it("registers Base Sepolia only", async () => {
    const client = nearX402Client(await connect());
    const req = required({ name: "USDC", version: "2" });
    req.accepts[0].network = "eip155:8453";
    await assert.rejects(client.createPaymentPayload(req));
    assert.equal(near.requests.length, 0);
  });

  it("signTypedData refuses caller-built messages", async () => {
    const signer = await connect();
    await assert.rejects(signer.signTypedData({ domain: {}, types: {}, primaryType: "X", message: {} }), /mandate contract builds the authorization/);
  });

  it("request ids are fresh and fit the contract's format", () => {
    const ids = new Set(Array.from({ length: 100 }, newRequestId));
    assert.equal(ids.size, 100);
    for (const id of ids) assert.match(id, /^[A-Za-z0-9._:-]{1,64}$/);
  });
});
