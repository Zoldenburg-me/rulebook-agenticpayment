// The judge page in a browser, at desktop and phone width: both stories, labels, proof links,
// "Run it" (same-origin only), "Verify it yourself", and no horizontal scroll.
import { expect, test } from "@playwright/test";

/** Every request the page makes; navigation to proof links is not followed. */
function watch(page) {
  const urls = [];
  page.on("request", (r) => urls.push(r.url()));
  return urls;
}

test("hero, Anya's rulebook and beats with labels and proof links", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("We built a verifiable rulebook for agentic payments.");
  await expect(page.getByTestId("rulebook")).toContainText("max USD 50.00 per payment, USD 100.00 per week");
  await expect(page.getByTestId("rulebook")).toContainText("max USD 30.00 each, USD 60.00 per day");
  const beats = page.getByTestId("beat");
  await expect(beats).toHaveCount(5);
  for (const b of await beats.all()) await expect(b.locator(".label").first()).toHaveText(/^(live run|replay)$/);
  const onchain = page.locator("#anya-onchain");
  await expect(onchain).toContainText("ERR_OVER_PER_PAYMENT_CAP");
  await expect(onchain.locator(".label.live")).toHaveCount(1);
  await expect(onchain.getByRole("link", { name: /nearblocks tx 48cPQwuF/ })).toHaveAttribute("href", "https://testnet.nearblocks.io/txns/48cPQwuFsUYb1MtPB4oUShVKD979xTF6vGJE2CHhxdRi");
  await expect(page.locator("#anya-poisoned .label.live")).toHaveCount(1);
  await expect(page.locator("#anya-poisoned").getByRole("link", { name: /nearblocks tx FkGbQ2UP/ })).toHaveAttribute("href", "https://testnet.nearblocks.io/txns/FkGbQ2UP7bmaSoNastDgkx8ueCMAUMBMbQ4GtsG6pjzM");
  await expect(page.locator("#anya-pay")).toContainText("payout batch 4UT7JP3CLY46U SUCCESS");
});

test("Anya: every beat ran live, so there is nothing to replay and no request leaves the page", async ({ page, baseURL }) => {
  const urls = watch(page);
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Run it (replay)" })).toHaveCount(0);
  for (const id of ["anya-pay", "anya-poisoned", "anya-refund", "anya-injected", "anya-onchain"]) {
    await expect(page.locator(`#${id} .label.live`), id).toHaveCount(1);
    await expect(page.locator(`#${id} .label.replay`), id).toHaveCount(0);
    await expect(page.locator(`#${id} .replay-out`), id).toHaveCount(0);
  }
  await expect(page.locator("#anya-pay")).toContainText("PP3_DUPLICATE_REQUEST");
  await expect(page.locator("#anya-poisoned")).toContainText("held");
  for (const u of urls) expect(new URL(u).origin).toBe(new URL(baseURL).origin);
  await expect(page.locator("body")).not.toContainText(/billing@|sales@|orders@/);
});

test("Hank: replay labels, every refusal code, and the revoke", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("tab", { name: "Hank's trading card" }).click();
  await expect(page.getByRole("tab", { name: "Hank's trading card" })).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("rulebook")).toContainText("max USD 100.00 per payment, USD 150.00 per week");
  await expect(page.locator(".note")).toContainText("Grokbot did not run against our MCP server");
  await expect(page.getByTestId("beat")).toHaveCount(6);
  await page.getByRole("button", { name: "Run it (replay)" }).click();
  await expect(page.getByRole("status")).toHaveText("Replay done: 8 steps.");
  await expect(page.getByTestId("step")).toHaveCount(8);
  await expect(page.locator("#hank-fake .replay-out")).toContainText("held");
  await expect(page.locator("#hank-fake .replay-out")).toContainText("ERR_PAYPAL_PAYEE_NOT_ALLOWED");
  await expect(page.locator("#hank-bait .replay-out")).toContainText("ERR_OVER_PER_PAYMENT_CAP");
  await expect(page.locator("#hank-buy .replay-out")).toContainText("USD 84.00");
  await expect(page.locator("#hank-swap .replay-out")).toContainText("PP3_BAD_SIGNATURE");
  await expect(page.locator("#hank-revoke .replay-out")).toContainText("404");
  await expect(page.locator("#hank-revoke .replay-out")).toContainText("ERR_AGENT_REVOKED");
  for (const s of await page.getByTestId("step").all()) await expect(s.locator(".label")).toHaveText("replay");
});

test("Verify it yourself: contract, view call and the on-chain refusal", async ({ page }) => {
  await page.goto("/");
  const v = page.locator("#verify");
  await expect(v).toContainText("nearh-pt1-1794232398.testnet");
  await expect(v.locator("#view-cli")).toContainText("get_mandate");
  await expect(v.locator("#view-rpc")).toContainText('"args_base64":"eyJhZ2VudCI6InN1cHBvcnQtMSJ9"');
  await expect(v.locator("#refusal-link")).toHaveAttribute("href", /48cPQwuFsUYb1MtPB4oUShVKD979xTF6vGJE2CHhxdRi$/);
  await expect(v.locator("#payout-contract-id")).toHaveText("nearh-pl1-1794480855.testnet");
});

test("proof links to repo files are served, other paths are not", async ({ page, request }) => {
  await page.goto("/");
  for (const tab of ["Anya's Coffeehouse", "Hank's trading card"]) {
    await page.getByRole("tab", { name: tab }).click();
    for (const href of await page.locator(".proof a").evaluateAll((as) => as.map((a) => a.getAttribute("href")))) {
      if (href.startsWith("/evidence/")) expect((await request.get(href)).status(), href).toBe(200);
      else expect(href).toMatch(/^https:\/\/testnet\.nearblocks\.io\/txns\/[1-9A-HJ-NP-Za-km-z]{43,44}$/);
    }
  }
  expect((await request.get("/evidence/package.json")).status()).toBe(404);
  expect((await request.post("/api/replay/anya")).status()).toBe(405);
});

test("no horizontal scroll at this width", async ({ page }) => {
  await page.goto("/");
  for (const tab of ["Anya's Coffeehouse", "Hank's trading card"]) {
    await page.getByRole("tab", { name: tab }).click();
    if (tab === "Hank's trading card") {
      await page.getByRole("button", { name: "Run it (replay)" }).click();
      await expect(page.getByRole("status")).toHaveText(/Replay done/);
    }
    const [scroll, client] = await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
    expect(scroll, tab).toBeLessThanOrEqual(client);
  }
});
