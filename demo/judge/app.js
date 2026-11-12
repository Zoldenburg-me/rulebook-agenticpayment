// The judge page: renders a story from stories.js, and "Run it" fetches the same-origin replay
// (GET /api/replay/{story}), which runs on the server's mock contract and mock PayPal.
import { ONCHAIN_REFUSAL, PAYOUT_CONTRACT, REFUND_CONTRACT, STORIES } from "./stories.js";

const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  for (const k of kids) n.append(k);
  return n;
};
const label = (l) => el("span", { class: `label ${l === "live run" ? "live" : "replay"}` }, l);

function render(id) {
  const s = STORIES[id];
  const root = document.getElementById("story");
  root.replaceChildren();
  root.setAttribute("aria-labelledby", `tab-${id}`);
  root.append(el("p", { class: "kind" }, s.kind), el("p", { class: "intro" }, s.intro));

  const card = el("div", { class: "rulebook", "data-testid": "rulebook" }, el("h3", {}, "Rulebook (on the contract)"));
  const dl = el("dl");
  for (const [k, v] of s.rulebook) dl.append(el("dt", {}, k), el("dd", {}, v));
  card.append(dl);
  root.append(card);
  if (s.note) root.append(el("p", { class: "note" }, s.note));

  const list = el("ol", { class: "beats" });
  for (const b of s.beats) {
    const li = el("li", { class: "beat", id: b.id, "data-testid": "beat" }, el("h3", {}, b.title), el("p", {}, b.text));
    if (b.code) li.append(el("p", {}, el("code", { class: "code" }, b.code)));
    const proof = el("ul", { class: "proof" });
    for (const p of b.proof) {
      const item = el("li", {}, label(p.label), " ", p.text);
      for (const [text, href] of p.links ?? []) item.append(" ", el("a", { href, rel: "noopener" }, text));
      proof.append(item);
    }
    li.append(proof);
    if (!b.live) li.append(el("div", { class: "replay-out", "data-beat": b.id }));
    list.append(li);
  }

  const btn = el("button", { class: "run", type: "button" }, "Run it (replay)");
  const status = el("p", { class: "status", role: "status" });
  btn.addEventListener("click", () => run(id, btn, status));
  // A story whose every beat ran live has nothing to replay.
  if (s.beats.some((b) => !b.live)) root.append(el("div", { class: "runbar" }, btn, el("span", { class: "hint" }, "Mock contract + mock PayPal, no network call"), status));
  root.append(list);
}

async function run(id, btn, status) {
  btn.disabled = true;
  status.textContent = "Replaying…";
  for (const n of document.querySelectorAll(".replay-out")) n.replaceChildren();
  try {
    const r = await fetch(`/api/replay/${id}`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const out = await r.json();
    let shown = 0;
    for (const step of out.steps) {
      const box = document.querySelector(`.replay-out[data-beat="${step.beat}"]`);
      if (!box) continue;
      const line = el("p", { class: `step ${step.outcome}`, "data-testid": "step" }, label("replay"), " ", el("strong", {}, step.outcome), " ", step.text);
      if (step.code) line.append(" ", el("code", { class: "code" }, step.code));
      box.append(line);
      shown++;
    }
    status.textContent = `Replay done: ${shown} steps.`;
  } catch (e) {
    status.textContent = `Replay failed (${e.message}).`;
  } finally {
    btn.disabled = false;
  }
}

function select(id) {
  for (const t of document.querySelectorAll("[role=tab]")) t.setAttribute("aria-selected", String(t.dataset.story === id));
  render(id);
}

for (const t of document.querySelectorAll("[role=tab]")) t.addEventListener("click", () => select(t.dataset.story));

document.getElementById("contract-id").textContent = REFUND_CONTRACT;
document.getElementById("payout-contract-id").textContent = PAYOUT_CONTRACT;
document.getElementById("view-cli").textContent =
  `near contract call-function as-read-only ${REFUND_CONTRACT} get_mandate \\\n  json-args '{"agent":"support-1"}' network-config testnet now`;
const args = btoa(JSON.stringify({ agent: "support-1" }));
document.getElementById("view-rpc").textContent =
  `curl -s https://rpc.testnet.near.org -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"query","params":{"request_type":"call_function","finality":"final","account_id":"${REFUND_CONTRACT}","method_name":"get_mandate","args_base64":"${args}"}}'`;
const link = document.getElementById("refusal-link");
link.href = `https://testnet.nearblocks.io/txns/${ONCHAIN_REFUSAL}`;
link.textContent = `testnet tx ${ONCHAIN_REFUSAL.slice(0, 8)}…${ONCHAIN_REFUSAL.slice(-4)}`;

select("anya");
