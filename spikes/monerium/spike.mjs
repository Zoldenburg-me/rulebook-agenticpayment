import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { loadEnvFile } from "node:process";
import { fileURLToPath } from "node:url";
import { sandboxClient, CHAIN, LINK_MESSAGE, RUN_JOURNAL, PAYOUT_LOCK, takePayoutLock, canonicalAmount, eurCents, ibanFor, refusalCode, payoutMessage, replayResult, assertNoPayoutAttempt, journalEvents } from "./monerium.mjs";
import { mpcSigner } from "./mpc.mjs";

const command = process.argv[2] || "check";
if (!["check", "link", "iban", "payout"].includes(command)) throw new Error("Usage: node spike.mjs check|link|iban|payout");
const journalPath = new URL(`./${RUN_JOURNAL}`, import.meta.url);
const record = (event) => {
  const line = JSON.stringify({ at: new Date().toISOString(), ...event });
  appendFileSync(journalPath, `${line}\n`, { mode: 0o600 });
  process.stdout.write(`${line}\n`);
};
const must = (res, operation) => {
  if (!res.ok) throw new Error(`${operation} failed (HTTP ${res.status}); response details withheld`);
  return res.body;
};

async function main() {
  loadEnvFile(process.env.MONERIUM_ENV_FILE || fileURLToPath(new URL("../../rails/monerium/.env", import.meta.url)));
  const env = process.env;
  const client = sandboxClient(env, fetch, record);
  await client.authenticate();
  const context = must(await client.request("GET", "/auth/context"), "Auth context");
  const profile = env.MONERIUM_PROFILE_ID || context.defaultProfile;
  if (!/^[a-f0-9-]{36}$/i.test(profile ?? "") || !context.profiles?.some(p => p.id === profile)) throw new Error("Select an accessible MONERIUM_PROFILE_ID");
  const signer = await mpcSigner(env, record);
  const addresses = must(await client.request("GET", "/addresses"), "List addresses");
  const list = Array.isArray(addresses) ? addresses : addresses.addresses;
  if (!Array.isArray(list)) throw new Error("Unexpected addresses response");
  const linked = list.some(a => a.profile === profile && a.address?.toLowerCase() === signer.address.toLowerCase() && a.chains?.includes(CHAIN));
  record({ step: "preflight", linked, profileAddressCount: list.filter(a => a.profile === profile).length });
  if (command === "check") return;
  if (command === "link") {
    if (linked) { record({ step: "link", result: "already_linked" }); return; }
    const signature = await signer.sign(LINK_MESSAGE);
    const res = await client.request("POST", "/addresses", { profile, address: signer.address, chain: CHAIN, message: LINK_MESSAGE, signature });
    must(res, "Link address");
    if (![201, 202].includes(res.status)) throw new Error("Link did not return the required 201/202; inspect sandbox");
    record({ step: "link", result: res.status === 201 ? "linked" : "pending_verification" });
    return;
  }
  if (!linked) throw new Error("Run link first, and wait for the sandbox to verify it");
  if (command === "iban") {
    const listIbans = async () => {
      const res = must(await client.request("GET", "/ibans"), "List IBANs");
      const items = Array.isArray(res) ? res : res.ibans;
      if (!Array.isArray(items)) throw new Error("Unexpected IBANs response");
      return items;
    };
    if (ibanFor(await listIbans(), signer.address, profile)) { record({ step: "iban", result: "already_issued" }); return; }
    // One IBAN per profile: 304 means the profile's IBAN pays another address. Not moved here.
    const res = await client.request("POST", "/ibans", { address: signer.address, chain: CHAIN });
    if (res.status === 304) { record({ step: "iban", result: "profile_has_iban_elsewhere" }); return; }
    must(res, "Request IBAN");
    const issued = ibanFor(await listIbans(), signer.address, profile);
    record({ step: "iban", result: issued ? "issued" : "requested_not_yet_listed", requestStatus: res.status,
      ...(issued ? { ibanLast4: issued.iban.replace(/\s/g, "").slice(-4) } : {}) });
    return;
  }
  if (existsSync(journalPath)) assertNoPayoutAttempt(journalEvents(readFileSync(journalPath, "utf8")));
  const amount = canonicalAmount(env.MONERIUM_AMOUNT || "0.01");
  const iban = (env.MONERIUM_SANDBOX_IBAN || "").replace(/\s/g, "").toUpperCase();
  const timestamp = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const message = payoutMessage(amount, iban, timestamp);
  const balance = must(await client.request("GET", `/balances/${CHAIN}/${signer.address}`), "Read EURe balance");
  const eur = balance.balances?.find(b => b.currency === "eur");
  const balanceCents = eurCents(eur?.amount);
  if (balanceCents === null || balanceCents < eurCents(amount)) {
    throw new Error("Mint sandbox EURe to the derived address on Base Sepolia at sandbox.monerium.dev/receive, then rerun");
  }
  record({ step: "funding", sufficientSandboxEure: true });
  const signature = await signer.sign(message);
  const body = { address: signer.address, chain: CHAIN, kind: "redeem", currency: "eur", amount,
    counterpart: { identifier: { standard: "iban", iban }, details: { firstName: "Test", lastName: "Recipient", country: iban.slice(0, 2) } },
    message, signature, memo: "nearH sandbox spike" };
  record({ step: "payout_message", amount, timestamp, message: message.replace(iban, "<SANDBOX_IBAN>") });
  takePayoutLock(fileURLToPath(new URL(`./${PAYOUT_LOCK}`, import.meta.url)));
  record({ step: "payout_attempt" });
  const first = await client.request("POST", "/orders", body);
  must(first, "First payout");
  if (![200, 201, 202].includes(first.status) || !/^[0-9a-f-]{36}$/i.test(first.body.id ?? "") || first.body.state === "rejected") throw new Error("First payout was not accepted with an order id");
  record({ step: "payout", orderId: first.body.id, state: ["placed", "pending", "processed"].includes(first.body.state) ? first.body.state : "unclassified" });
  // Send the identical payload once: no new timestamp, signature or order UUID.
  const replay = await client.request("POST", "/orders", body);
  const result = replayResult(first, replay);
  record({ step: "replay", result, status: replay.status, sameOrderId: replay.body?.id === first.body.id,
    ...(replay.ok ? {} : { refusal: refusalCode(replay.body) }) });
  if (result !== "rejected_duplicate") throw new Error("Duplicate refusal is not proven; inspect orders before any rerun and record the replay gap");
  record({ step: "result", result: "accepted_payout_and_duplicate_rejected", settlementVerified: false });
}

try { await main(); }
catch (error) {
  record({ step: "run", result: "incomplete" });
  // Only messages produced here are safe; partner errors and credentials stay private.
  if (error instanceof Error && !error.cause && !error.stack?.includes("node_modules")) process.stderr.write(`${error.message}\n`);
  else process.stderr.write("Spike failed; partner response and credential details withheld\n");
  process.exitCode = 1;
}
