// DB1 dashboard page. Every value from the chain or the held queue goes into the DOM through
// textContent (el() below), never innerHTML: invoice text comes straight from inbound email.

import { b64, HELD_DECIDE_METHOD, heldDecideArgs, resolveArgs, revokeArgs, signOwnerCall } from "./owner.js";
import { formatUsd, maskPayee, parsePaypalText } from "./paypal.js";

const $ = (id) => document.getElementById(id);
const utf8 = new TextEncoder();
const DECIMALS = { x402: 6, sepa: 18 };
const TOKEN = { x402: "USDC", sepa: "EURe" };
/** `paypal` (shape 4) is optional in a mandate; get_budget returns null without it. */
const RAILS = ["x402", "sepa", "paypal"];
/** Contract status → the label DB1 shows. `signed` is a request the mandate allowed. */
const STATUS_LABEL = { signed: "allowed", pending: "pending", unknown: "unknown", revoked: "revoked", spent: "spent", released: "released" };
const COUNTED = ["allowed", "held", "blocked", "pending", "unknown", "revoked", "spent", "released"];

let local; // /config.json: { contract_id, near_rpc, network }
let state = { agents: [], held: [], paypal: [], vault: new Map() };
let busy = false;

function el(tag, props = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "text") e.textContent = v;
    else if (k === "onclick") e.addEventListener("click", v);
    else if (k === "disabled") e.disabled = Boolean(v);
    else e.setAttribute(k, v);
  }
  for (const c of children) e.append(c ?? "");
  return e;
}

const badge = (label) => el("span", { class: `badge status-${label}`, "data-testid": "status", text: label });

function showError(msg) {
  $("errors").append(el("li", { text: msg }));
}

async function getJson(path) {
  const res = await fetch(path);
  const body = await res.json();
  if (!res.ok) throw new Error(`${path}: ${body.error ?? res.status}`);
  return body;
}

async function postJson(path, payload) {
  const res = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
  const body = await res.json();
  if (!res.ok) throw new Error(body.error ?? `${path}: HTTP ${res.status}`);
  return body;
}

async function rpc(method, params) {
  const res = await fetch(local.near_rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "dashboard", method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

async function view(method, args) {
  const r = await rpc("query", {
    request_type: "call_function",
    finality: "final",
    account_id: local.contract_id,
    method_name: method,
    args_base64: b64(utf8.encode(JSON.stringify(args))),
  });
  if (r.error) throw new Error(`${method}: ${r.error}`);
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(r.result)));
}

function formatUnits(amount, rail) {
  if (rail === "paypal") return formatUsd(amount);
  const d = DECIMALS[rail];
  if (d === undefined) return String(amount);
  const v = BigInt(amount);
  const whole = v / 10n ** BigInt(d);
  const frac = (v % 10n ** BigInt(d)).toString().padStart(d, "0").replace(/0+$/, "");
  return `${whole}${frac ? "." + frac : ""} ${TOKEN[rail]}`;
}

async function load() {
  $("errors").replaceChildren();
  local = await getJson("/config.json");
  if (local.network !== "testnet") throw new Error(`network must be testnet, got ${local.network}`);
  const status = await rpc("status", []);
  if (status?.chain_id !== local.network) throw new Error(`the NEAR RPC ${local.near_rpc} is on ${status?.chain_id}, not ${local.network}`);
  const config = await view("get_config", {});
  if (config.network !== local.network) throw new Error(`the contract is on ${config.network}, not ${local.network}`);
  $("contract").textContent = `${local.contract_id} · owner ${config.owner.mode} · owner_nonce ${config.owner_nonce}`;

  const agents = [];
  for (const record of await view("list_agents", { from_index: 0, limit: 100 })) {
    const a = { record, mandate: null, budgets: {}, requests: [], suspended: [], settlements: new Map() };
    agents.push(a);
    const step = async (what, fn) => {
      try {
        await fn();
      } catch (e) {
        showError(`${record.agent}: ${what}: ${e.message}`);
      }
    };
    await step("get_mandate", async () => (a.mandate = await view("get_mandate", { agent: record.agent })));
    for (const rail of RAILS) {
      await step(`get_budget ${rail}`, async () => (a.budgets[rail] = await view("get_budget", { agent: record.agent, rail })));
    }
    await step("list_requests", async () => (a.requests = await view("list_requests", { agent: record.agent, from_index: 0, limit: 100 })));
    // PP-W1: what verified PayPal webhooks reported (tighten-only settlement feedback).
    await step("get_suspended_payees", async () => (a.suspended = await view("get_suspended_payees", { agent: record.agent })));
    for (const r of a.requests.filter((r) => r.shape === "paypal" && r.status === "signed")) {
      await step(`get_settlement ${r.key.request_id}`, async () => {
        const s = await view("get_settlement", { key: r.key });
        if (s) a.settlements.set(r.key.request_id, s);
      });
    }
  }
  let held = [];
  try {
    const h = await getJson("/api/held");
    held = h.items;
    $("held-file").textContent = `reading ${h.file}`;
    h.errors.forEach(showError);
  } catch (e) {
    showError(`held queue: ${e.message}`);
  }
  let paypal = [];
  try {
    const p = await getJson("/api/paypal");
    paypal = p.records;
    $("paypal-dir").textContent = `PayPal rail records from ${p.dir}`;
    p.errors.forEach(showError);
  } catch (e) {
    showError(`PayPal rail records: ${e.message}`);
  }
  // PP-V1: the PayPal rail's vault status per agent (never the token itself).
  const vault = new Map();
  for (const { record } of agents) {
    try {
      vault.set(record.agent, (await getJson(`/api/vault?agent=${encodeURIComponent(record.agent)}`)).status);
    } catch (e) {
      vault.set(record.agent, `unavailable (${e.message})`);
    }
  }
  state = { config, agents, held, paypal, vault };
  render();
}

function render() {
  renderAgents();
  renderMandates();
  renderRequests();
  renderUnknown();
  renderHeld();
  renderPaypal();
  renderVault();
}

const VAULT_LABEL = { none: "not connected", approval_required: "awaiting approval on PayPal", active: "connected", revoked: "revoked" };

function renderVault() {
  const rows = state.agents.map(({ record }) => {
    const status = state.vault.get(record.agent) ?? "none";
    const act = (op, text) => el("button", { type: "button", text, onclick: (e) => vaultOp(op, record.agent, e.target) });
    const actions = status === "active" ? [act("revoke", "Revoke PayPal")]
      : status === "approval_required" ? [act("confirm", "I approved"), act("revoke", "Cancel")]
      : status === "none" || status === "revoked" ? [act("connect", "Connect PayPal")] : [];
    return el("tr", { "data-vault": record.agent }, el("td", { text: record.agent }), el("td", { "data-testid": "vault-status", text: VAULT_LABEL[status] ?? status }), el("td", {}, ...actions));
  });
  $("vault").replaceChildren(el("tr", {}, ...["Agent", "PayPal wallet", ""].map((t) => el("th", { text: t }))), ...rows);
}

async function vaultOp(op, agent, button) {
  button.disabled = true;
  try {
    const out = await postJson(`/api/vault/${op}`, { agent });
    // PayPal's own page; the owner approves there, then clicks "I approved".
    if (op === "connect" && typeof out.approve_url === "string" && out.approve_url.startsWith("https://www.sandbox.paypal.com/")) {
      window.open(out.approve_url, "_blank", "noopener");
    }
    await load();
  } catch (e) {
    showError(`PayPal ${op}: ${e.message}`);
    button.disabled = false;
  }
}

function renderAgents() {
  const rows = state.agents.map(({ record }) =>
    el(
      "tr",
      { "data-agent": record.agent },
      el("td", { text: record.agent }),
      el("td", {}, badge(record.revoked ? "revoked" : "active")),
      el("td", { text: record.evm_address ?? "" }),
      el("td", { text: record.linked ? "linked" : "not linked" }),
      // A revoked agent's DeleteKey may have failed (D1); revoking again retries it, or does
      // nothing if the key is already gone.
      el("td", {}, el("button", { type: "button", text: record.revoked ? "Retry key deletion" : "Revoke", onclick: (e) => revoke(record.agent, e.target) })),
    ),
  );
  $("agents").replaceChildren(el("tr", {}, ...["Agent", "Status", "EOA", "Link", ""].map((t) => el("th", { text: t }))), ...rows);
}

function renderMandates() {
  const blocks = state.agents.map(({ record, mandate, budgets }) => {
    if (!mandate) return el("p", { text: `${record.agent}: no mandate` });
    const rows = RAILS.filter((rail) => mandate[rail]).map((rail) => {
      const m = mandate[rail];
      const b = budgets[rail];
      return el(
        "tr",
        { "data-rail": rail },
        el("td", { text: rail }),
        el("td", { text: `${formatUnits(m.amount_range.min, rail)} – ${formatUnits(m.amount_range.max, rail)}` }),
        el("td", { "data-testid": "budget", text: b ? `${formatUnits(b.reserved, rail)} of ${formatUnits(b.budget, rail)}` : "?" }),
        // The current window's length; a changed period_secs applies from the next window (D7).
        el("td", { text: `${(b?.period_secs ?? m.period_secs) / 86400} days` }),
      );
    });
    return el(
      "div",
      { "data-mandate": record.agent },
      el("h3", { text: record.agent }),
      el("table", {}, el("tr", {}, ...["Rail", "Per payment", "Used this period", "Period"].map((t) => el("th", { text: t }))), ...rows),
    );
  });
  $("mandates").replaceChildren(...blocks);
}

function renderRequests() {
  const counts = Object.fromEntries(COUNTED.map((s) => [s, 0]));
  const rows = [];
  for (const { requests } of state.agents) {
    for (const r of requests) {
      const label = STATUS_LABEL[r.status] ?? r.status;
      counts[label] = (counts[label] ?? 0) + 1;
      rows.push(
        el(
          "tr",
          { "data-request": r.key.request_id },
          el("td", { text: r.key.agent }),
          el("td", { text: r.key.request_id }),
          el("td", { text: r.shape }),
          el("td", { text: r.rail ? formatUnits(r.amount, r.rail) : "—" }),
          el("td", {}, badge(label)),
        ),
      );
    }
  }
  for (const h of state.held) {
    if (h.status === "held") counts.held++;
    if (h.status === "rejected") counts.blocked++;
  }
  $("counts").replaceChildren(...Object.entries(counts).map(([s, n]) => el("li", { "data-count": s }, badge(s), ` ${n}`)));
  $("requests").replaceChildren(el("tr", {}, ...["Agent", "Request", "Shape", "Amount", "Status"].map((t) => el("th", { text: t }))), ...rows);
}

function renderUnknown() {
  const nowSecs = Date.now() / 1000;
  const rows = [];
  for (const { requests } of state.agents) {
    for (const r of requests.filter((r) => r.status === "unknown")) {
      const early = nowSecs < r.release_after;
      rows.push(
        el(
          "tr",
          { "data-unknown": r.key.request_id },
          el("td", { text: `${r.key.agent} / ${r.key.request_id}` }),
          el("td", { text: r.rail ? formatUnits(r.amount, r.rail) : "—" }),
          el("td", {}, el("button", { type: "button", text: "Spent", onclick: (e) => resolve(r.key, "spent", e.target) })),
          el(
            "td",
            {},
            el("button", {
              type: "button",
              text: "Released",
              disabled: early,
              title: early ? `available after ${new Date(r.release_after * 1000).toISOString()}` : "",
              onclick: (e) => resolve(r.key, "released", e.target, r.release_after),
            }),
          ),
        ),
      );
    }
  }
  $("unknown").replaceChildren(...(rows.length ? rows : [el("tr", {}, el("td", { text: "No unknown reservations." }))]));
}

function renderHeld() {
  const items = state.held.map((h) => {
    const s = h.shape ?? {};
    // A PayPal payee is masked as rails/paypal masks it.
    const payee = s.type === "paypal" ? maskPayee(s.payee) : (s.iban ?? s.pay_to ?? s.payTo ?? s.requirements?.payTo ?? "");
    const buttons =
      h.status === "held"
        ? [
            el("button", { type: "button", text: "Approve", onclick: (e) => decide(h.id, "approved", e.target) }),
            el("button", { type: "button", text: "Reject", onclick: (e) => decide(h.id, "rejected", e.target) }),
          ]
        : [];
    return el(
      "div",
      { class: "held-item", "data-held-id": h.id },
      el("div", {}, badge(h.status), ` ${h.id} · ${h.agent} · ${h.rail} · ${h.request_id}`),
      el("div", { text: `${s.type ?? "?"} ${s.amount ?? ""} to ${payee}` }),
      el("div", { text: `memo: ${h.memo ?? ""}` }),
      el("pre", { "data-testid": "invoice", text: h.invoice?.text ?? "" }),
      el("div", { text: `verdict: ${h.verdict?.result ?? "?"}${h.verdict?.reason ? " — " + h.verdict.reason : ""}` }),
      el("div", {}, ...buttons),
    );
  });
  $("held").replaceChildren(...(items.length ? items : [el("p", { text: "The held queue is empty." })]));
}

/**
 * USD view: shape 4 PayPal payouts, the contract's reservations plus held-queue items the contract
 * has not seen yet, each with the PayPal rail's (PP3) record once it has one.
 */
function renderPaypal() {
  const rail = new Map(state.paypal.map((r) => [`${r.agent}\n${r.request_id}`, r]));
  const rows = [];
  const seen = new Set();
  const suspended = new Map(state.agents.map((a) => [a.record.agent, new Set(a.suspended.filter((p) => p.rail === "paypal").map((p) => p.receiver))]));
  const settlements = new Map(state.agents.map((a) => [a.record.agent, a.settlements]));
  const row = (agent, requestId, payee, amount, label, fullPayee) => {
    const rec = rail.get(`${agent}\n${requestId}`);
    const isSuspended = suspended.get(agent)?.has(fullPayee) ?? false;
    const s = settlements.get(agent)?.get(requestId);
    return el(
      "tr",
      { "data-paypal": requestId },
      el("td", { text: agent }),
      el("td", { text: requestId }),
      el("td", { "data-testid": "payee", class: isSuspended ? "suspended" : "", title: isSuspended ? "suspended after an adverse PayPal settlement" : "", text: isSuspended ? `${payee} (suspended)` : payee }),
      el("td", { "data-testid": "amount", text: amount }),
      el("td", {}, badge(label)),
      el("td", { "data-testid": "batch", text: rec?.payout_batch_id ?? "—" }),
      el("td", { "data-testid": "rail-status", text: rec ? [rec.state, rec.batch_status].filter(Boolean).join(" · ") : "not submitted" }),
      el("td", { "data-testid": "settlement", class: s && s.status !== "completed" && s.status !== "unclaimed" ? "suspended" : "" , text: s ? (s.status === "completed" ? "PayPal-confirmed" : `PayPal: ${s.status}`) : "—" }),
    );
  };
  for (const { requests } of state.agents) {
    for (const r of requests.filter((r) => r.shape === "paypal")) {
      seen.add(`${r.key.agent}\n${r.key.request_id}`);
      const fields = parsePaypalText(r.payload?.text);
      rows.push(row(r.key.agent, r.key.request_id, fields ? maskPayee(fields.payee) : "?", formatUsd(r.amount), STATUS_LABEL[r.status] ?? r.status, fields?.payee));
    }
  }
  for (const h of state.held.filter((h) => h.shape?.type === "paypal" && !seen.has(`${h.agent}\n${h.request_id}`))) {
    const label = h.status === "rejected" ? "blocked" : h.status;
    rows.push(row(h.agent, h.request_id, maskPayee(h.shape.payee), `${h.shape.amount} USD`, label, h.shape.payee));
  }
  $("paypal").replaceChildren(
    el("tr", {}, ...["Agent", "Request", "Payee", "Amount", "Status", "PayPal batch", "Rail status", "Settlement"].map((t) => el("th", { text: t }))),
    ...(rows.length ? rows : [el("tr", {}, el("td", { text: "No PayPal payouts." }))]),
  );
}

/** A held decision, signed with the passkey for this id and status and the queue's next nonce. */
async function decide(id, status, button) {
  if (busy) return;
  busy = true;
  button.disabled = true;
  try {
    const config = await view("get_config", {});
    const { held_nonce } = await getJson("/api/held");
    const { assertion } = await signOwnerCall({
      config,
      contractId: local.contract_id,
      method: HELD_DECIDE_METHOD,
      args: { id, status },
      borshArgs: heldDecideArgs(id, status),
      credentials: navigator.credentials,
      origin: location.origin,
      nowMs: Date.now(),
      ownerNonce: held_nonce + 1,
    });
    await postJson("/api/held/decide", { id, status, assertion });
    await load();
  } catch (e) {
    showError(`${id}: ${e.message}`);
    button.disabled = false;
  } finally {
    busy = false;
  }
}

/** One signed owner call: reads owner_nonce fresh, signs with the passkey, relays, reloads. */
async function ownerCall(method, args, borshArgs, button) {
  if (busy) return;
  busy = true;
  button.disabled = true;
  try {
    const config = await view("get_config", {});
    const call = await signOwnerCall({
      config,
      contractId: local.contract_id,
      method,
      args,
      borshArgs,
      credentials: navigator.credentials,
      origin: location.origin,
      nowMs: Date.now(),
    });
    await postJson("/api/owner-call", call);
    await load();
    return true;
  } catch (e) {
    showError(`${method}: ${e.message}`);
    button.disabled = false;
  } finally {
    busy = false;
  }
}

async function revoke(agent, button) {
  const ok = await ownerCall("revoke", { agent }, revokeArgs(agent), button);
  // Two kill switches: the contract revoke, then the PayPal wallet token at the rail.
  if (ok && ["active", "approval_required"].includes(state.vault.get(agent))) {
    try {
      await postJson("/api/vault/revoke", { agent });
    } catch (e) {
      showError(`PayPal revoke: ${e.message}`);
    }
    await load();
  }
}

function resolve(key, outcome, button, releaseAfter = 0) {
  if (outcome === "released" && Date.now() / 1000 < releaseAfter) {
    showError(`${key.request_id}: Released is refused until ${new Date(releaseAfter * 1000).toISOString()}`);
    return;
  }
  return ownerCall("resolve_reservation", { key, outcome }, resolveArgs(key, outcome), button);
}

$("refresh").addEventListener("click", () => load().catch((e) => showError(e.message)));
load().catch((e) => showError(e.message));
// Enables Released once release_after passes without waiting for a refresh.
setInterval(() => state.agents.length && renderUnknown(), 15_000);
