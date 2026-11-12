// O2: link an agent's MPC-derived EOA to the team's Monerium sandbox profile.
// 1. The owner calls `link_agent` on the mandate contract (owner-signed assertion, submitted by
//    any NEAR account; O1 plumbing). The contract asks the MPC to sign the fixed link message
//    with EIP-191 for derive(contract, agent), once per agent.
// 2. The script reads the signed link reservation, checks the digest and that the signature
//    recovers to the agent's `evm_address`.
// 3. It POSTs { profile, address, chain, message, signature } to the sandbox /addresses.
// Reruns are safe: a link already on Monerium is reported and nothing is sent; a link already
// signed on the contract is reused instead of calling `link_agent` again (ERR_ALREADY_LINKED).

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { publicKeyToAddress } from "@nearh/owner-near/src/derive.ts";
import { CHAIN, LINK_MESSAGE, MoneriumError, must, refusal, type Client } from "./monerium.ts";

export type Signature = { r: string; s: string; v: number };
export type Reservation = {
  key: { agent: string; caller: { kind: string }; request_id: string };
  shape: string;
  created_at_ms: number;
  digest: string;
  status: "pending" | "signed" | "unknown" | "spent" | "released";
  signature: Signature | null;
};
export type Agent = { evm_address: string | null; revoked: boolean; linked: boolean };

/** What the flow needs from NEAR; the CLI wires these to RPC views and near-cli-rs. */
export type Near = {
  getAgent(agent: string): Promise<Agent | null>;
  listRequests(agent: string, from: number, limit: number): Promise<Reservation[]>;
  /** Signs and submits `link_agent(agent)` as the owner; returns the tx hash if printed. */
  linkAgent(agent: string): Promise<{ txHash?: string }>;
  sleep(ms: number): Promise<void>;
};

export type Result =
  | { result: "already_linked"; address: string }
  | { result: "linked" | "pending_verification"; address: string; status: number; requestId: string; txHash?: string };

/** EIP-191 personal_sign hash of the link message (the digest `link_agent` asks the MPC to sign). */
export function linkDigest(message = LINK_MESSAGE): Uint8Array {
  const m = utf8ToBytes(message);
  return keccak_256(concatBytes(utf8ToBytes(`\x19Ethereum Signed Message:\n${m.length}`), m));
}

const word = (hex: string, what: string) => {
  const h = hex.replace(/^0x/, "").toLowerCase();
  if (!/^[0-9a-f]{1,64}$/.test(h)) throw new Error(`link signature ${what} is not a 32-byte hex value`);
  return h.padStart(64, "0");
};

/** `0x r || s || v` (65 bytes), as Monerium expects, after checking it recovers to `address`. */
export function linkSignature(sig: Signature, address: string): string {
  if (sig.v !== 27 && sig.v !== 28) throw new Error(`link signature v must be 27 or 28, got ${sig.v}`);
  const r = word(sig.r, "r");
  const s = word(sig.s, "s");
  const recovered = secp256k1.recoverPublicKey(hexToBytes(`${(sig.v - 27).toString(16).padStart(2, "0")}${r}${s}`), linkDigest(), {
    prehash: false,
  });
  const from = publicKeyToAddress(secp256k1.Point.fromBytes(recovered).toBytes(false));
  if (from !== address.toLowerCase()) throw new Error(`link signature recovers to ${from}, not the agent EOA ${address.toLowerCase()}`);
  return `0x${r}${s}${sig.v.toString(16)}`;
}

const isLink = (r: Reservation) => r.shape === "link" && r.key.caller.kind === "owner";

async function linkReservations(near: Near, agent: string): Promise<Reservation[]> {
  const out: Reservation[] = [];
  for (let from = 0; ; from += 50) {
    const page = await near.listRequests(agent, from, 50);
    out.push(...page.filter(isLink));
    if (page.length < 50) return out;
  }
}

/** True if Monerium lists `address` on `chain` under `profile`. */
export async function isLinked(client: Client, profile: string, address: string): Promise<boolean> {
  const body = must(await client.request("GET", "/addresses"), "List addresses");
  const list = Array.isArray(body) ? body : body?.addresses;
  if (!Array.isArray(list)) throw new Error("unexpected /addresses response");
  return list.some(
    (a: any) =>
      a?.profile === profile && typeof a.address === "string" && a.address.toLowerCase() === address.toLowerCase() &&
      Array.isArray(a.chains) && a.chains.includes(CHAIN),
  );
}

/** The profile to link to: MONERIUM_PROFILE_ID, else the app's default; must be accessible. */
export async function resolveProfile(client: Client, wanted?: string): Promise<string> {
  const ctx = must(await client.request("GET", "/auth/context"), "Auth context");
  const profile = wanted || ctx?.defaultProfile;
  if (!/^[a-f0-9-]{36}$/i.test(profile ?? "") || !ctx?.profiles?.some((p: any) => p?.id === profile)) {
    throw new Error("MONERIUM_PROFILE_ID is not a profile this sandbox app can access");
  }
  return profile;
}

export type Options = { pollMs?: number; maxPolls?: number; log?: (line: string) => void };

/** Waits for the newest owner link reservation created after `after` (ms) to leave `pending`. */
async function waitForLink(near: Near, agent: string, after: number, o: Required<Options>): Promise<Reservation> {
  for (let i = 0; i < o.maxPolls; i++) {
    const links = (await linkReservations(near, agent)).filter((r) => r.created_at_ms > after);
    const newest = links.sort((a, b) => b.created_at_ms - a.created_at_ms)[0];
    if (newest && newest.status !== "pending") return newest;
    await near.sleep(o.pollMs);
  }
  throw new Error("the link reservation is still pending; rerun later (it reuses the signature once recorded)");
}

export async function linkAgentToMonerium(
  near: Near,
  client: Client,
  agent: string,
  profile: string,
  opts: Options = {},
): Promise<Result> {
  const o: Required<Options> = { pollMs: 3000, maxPolls: 40, log: () => {}, ...opts };
  const record = await near.getAgent(agent);
  if (!record) throw new Error(`no agent ${agent} on the contract`);
  if (record.revoked) throw new Error(`agent ${agent} is revoked`);
  if (!record.evm_address || !/^0x[0-9a-f]{40}$/i.test(record.evm_address)) throw new Error(`agent ${agent} has no evm_address`);
  const address = record.evm_address.toLowerCase();

  if (await isLinked(client, profile, address)) {
    o.log(`${address} is already linked to the Monerium profile on ${CHAIN}; nothing sent`);
    return { result: "already_linked", address };
  }

  // Reuse a link the contract already signed; otherwise ask the owner to link now.
  const links = await linkReservations(near, agent);
  let link = links.filter((r) => r.status === "signed").sort((a, b) => b.created_at_ms - a.created_at_ms)[0];
  let txHash: string | undefined;
  if (!link) {
    if (record.linked) {
      const after = Math.max(0, ...links.map((r) => r.created_at_ms)) - 1;
      o.log(`a link_agent request for ${agent} is in flight; waiting for the MPC signature`);
      link = await waitForLink(near, agent, after, o);
    } else {
      const after = Math.max(0, ...links.map((r) => r.created_at_ms));
      txHash = (await near.linkAgent(agent)).txHash;
      link = await waitForLink(near, agent, after, o);
    }
  } else {
    o.log(`reusing the signed link ${link.key.request_id}`);
  }
  if (link.status !== "signed" || !link.signature) {
    throw new Error(`link reservation ${link.key.request_id} ended ${link.status}; the contract reset linked, run link again`);
  }
  if (link.digest.toLowerCase() !== `0x${bytesToHex(linkDigest())}`) throw new Error("link reservation digest is not the link message");
  const signature = linkSignature(link.signature, address);

  const res = await client.request("POST", "/addresses", { profile, address, chain: CHAIN, message: LINK_MESSAGE, signature });
  if (!res.ok) {
    // Monerium may refuse an address that is already on the profile (e.g. linked by a parallel run).
    if (res.status >= 400 && res.status < 500 && (await isLinked(client, profile, address))) {
      o.log(`Monerium refused with HTTP ${res.status} but already lists ${address}; treating as linked`);
      return { result: "already_linked", address };
    }
    throw new MoneriumError("Link address", res.status, refusal(res.body));
  }
  if (res.status !== 201 && res.status !== 202) throw new Error(`Link address returned HTTP ${res.status}, expected 201 or 202`);
  return {
    result: res.status === 201 ? "linked" : "pending_verification",
    address,
    status: res.status,
    requestId: link.key.request_id,
    ...(txHash ? { txHash } : {}),
  };
}
