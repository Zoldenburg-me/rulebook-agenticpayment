// Relays an owner call the owner already signed (docs/interfaces.md §2). Before sending, the
// relayer recomputes the challenge from the exact args it will send and checks the owner's
// P-256 signature over it, so it refuses to forward anything the owner did not sign. The
// contract runs the full `assert_owner` again; the relayer only pays the gas.

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import {
  addAgentArgs,
  agentArgs,
  payeeArgs,
  setMandateArgs,
  setRelayerArgs,
  Writer,
} from "@nearh/owner-near/src/borsh.ts";
import { ownerChallenge, type OwnerAssertion } from "@nearh/owner-near/src/challenge.ts";
import type { Journal } from "./journal.ts";
import { callFunction, view, waitFor, type NearSigner } from "./near.ts";
import type { Rpc } from "./rpc.ts";

const TGAS = 1_000_000_000_000n;

export type SignedOwnerCall = { method: string; args: Record<string, any>; assertion: OwnerAssertion };

const CALLERS = ["agent", "owner", "relayer"];
const TOKENS = ["usdc", "eure"];

function requestKey(w: Writer, k: any): void {
  const i = CALLERS.indexOf(k?.caller?.kind);
  if (i < 0) throw new Error(`unknown caller: ${JSON.stringify(k?.caller)}`);
  w.string(k.agent).u8(i);
  if (k.caller.kind === "relayer") w.string(k.caller.account);
  w.string(k.request_id);
}

/** For each owner method: its JSON arg names (without `assertion`), borsh(args), and gas. */
const METHODS: Record<string, { keys: string[]; borsh: (a: any) => Uint8Array; tgas: bigint }> = {
  add_agent: { keys: ["agent", "public_key", "sweep_config", "evm_address"], borsh: (a) => addAgentArgs(a.agent, a.public_key, a.sweep_config, a.evm_address), tgas: 100n },
  set_relayer: { keys: ["account"], borsh: (a) => setRelayerArgs(a.account), tgas: 30n },
  set_mandate: { keys: ["agent", "mandate"], borsh: (a) => setMandateArgs(a.agent, a.mandate), tgas: 30n },
  add_payee: { keys: ["agent", "payee"], borsh: (a) => payeeArgs(a.agent, a.payee), tgas: 30n },
  remove_payee: { keys: ["agent", "payee"], borsh: (a) => payeeArgs(a.agent, a.payee), tgas: 30n },
  link_agent: { keys: ["agent"], borsh: (a) => agentArgs(a.agent), tgas: 300n },
  revoke: { keys: ["agent"], borsh: (a) => agentArgs(a.agent), tgas: 100n },
  resolve_reservation: {
    keys: ["key", "outcome"],
    borsh: (a) => {
      const w = new Writer();
      requestKey(w, a.key);
      const o = ["spent", "released"].indexOf(a.outcome);
      if (o < 0) throw new Error(`unknown outcome: ${a.outcome}`);
      return w.u8(o).done();
    },
    tgas: 30n,
  },
  sweep: {
    keys: ["agent", "token", "amount", "request_id", "evm_tx"],
    borsh: (a) => {
      const t = TOKENS.indexOf(a.token);
      if (t < 0) throw new Error(`unknown token: ${a.token}`);
      return new Writer()
        .string(a.agent)
        .u8(t)
        .u128(a.amount)
        .string(a.request_id)
        .option(a.evm_tx, (w, e: any) => w.u64(e.nonce).u64(e.gas_limit).u128(e.max_fee_per_gas).u128(e.max_priority_fee_per_gas))
        .done();
    },
    tgas: 300n,
  },
};

type ConfigView = {
  owner: { mode: "passkey"; public_key: string } | { mode: "wallet"; account: string };
  owner_nonce: number;
  network: string;
};

export type OwnerCallDeps = { near: Rpc; contractId: string; submitter: NearSigner; journal: Journal; nowSecs?: () => number; pollMs?: number };

/**
 * Checks that `call` is signed by the contract's passkey owner over exactly these args, then
 * submits it once. Returns the tx hash once `owner_nonce` shows the contract accepted it.
 */
export async function relayOwnerCall(d: OwnerCallDeps, call: SignedOwnerCall): Promise<{ txHash: string; ownerNonce: number }> {
  const spec = Object.hasOwn(METHODS, call.method) ? METHODS[call.method] : undefined;
  if (!spec) throw new Error(`not a relayable owner method: ${call.method}`);
  const got = Object.keys(call.args ?? {}).sort();
  if (JSON.stringify(got) !== JSON.stringify([...spec.keys].sort())) {
    throw new Error(`${call.method} takes exactly ${spec.keys.join(", ")}; got ${got.join(", ")}`);
  }
  const a = call.assertion;
  if (!a || !Number.isSafeInteger(a.owner_nonce) || !Number.isSafeInteger(a.expires_at)) throw new Error("missing or malformed assertion");

  const cfg = await view<ConfigView>(d.near, d.contractId, "get_config");
  if (cfg.owner.mode !== "passkey") throw new Error("the contract has a wallet owner; its calls cannot be relayed");

  // The signed challenge must be the one these args produce.
  const challenge = ownerChallenge(d.contractId, cfg.network, call.method, spec.borsh(call.args), a.owner_nonce, a.expires_at);
  let client: any;
  try {
    client = JSON.parse(a.client_data_json);
  } catch {
    throw new Error("client_data_json is not JSON");
  }
  if (client.type !== "webauthn.get" || client.challenge !== Buffer.from(challenge).toString("base64url")) {
    throw new Error(`the assertion does not sign these ${call.method} args`);
  }
  const authData = Buffer.from(a.authenticator_data, "base64");
  // ES256 over authData ‖ sha256(clientDataJSON); `prehash` applies the outer sha256.
  const signed = concatBytes(authData, sha256(utf8ToBytes(a.client_data_json)));
  const ownerKey = Buffer.from(cfg.owner.public_key, "base64");
  let ok = false;
  try {
    ok = p256.verify(Buffer.from(a.signature, "base64"), signed, ownerKey, { prehash: true, lowS: false });
  } catch {}
  if (!ok) throw new Error("the assertion is not signed by the contract's owner key");

  if (a.owner_nonce <= cfg.owner_nonce) throw new Error(`owner_nonce ${a.owner_nonce} is already used (contract is at ${cfg.owner_nonce})`);
  const now = d.nowSecs?.() ?? Math.floor(Date.now() / 1000);
  if (a.expires_at <= now) throw new Error(`assertion expired at ${a.expires_at}`);

  // Keyed by what the owner signed, not by the nonce alone: a call the contract rejects leaves
  // the nonce unused, and the owner's next call must be able to reuse it. The signature is left
  // out so a malleated (high-s) copy of the same call maps to the same id.
  d.journal.claim(`owner:${d.contractId}:${a.owner_nonce}:${bytesToHex(sha256(signed))}`);
  const body = utf8ToBytes(JSON.stringify({ ...call.args, assertion: a }));
  const r = await callFunction(d.near, d.submitter, d.contractId, call.method, body, spec.tgas * TGAS);
  if (r.failure) throw new Error(`${call.method} rejected by the contract (tx ${r.hash}): ${r.failure}`);
  await waitFor(
    `owner_nonce reaches ${a.owner_nonce} after tx ${r.hash}`,
    async () => ((await view<ConfigView>(d.near, d.contractId, "get_config")).owner_nonce >= a.owner_nonce ? true : undefined),
    { pollMs: d.pollMs },
  );
  return { txHash: r.hash, ownerNonce: a.owner_nonce };
}
