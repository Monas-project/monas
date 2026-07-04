// E2E verification of Monas Drive UI against the REAL stack
// (vite :5174 → gateway :3000 → AWS state nodes node1-4.monas-demo.net).
// Run: node e2e-verify.mjs
import { chromium } from "playwright";

const URL = process.env.E2E_URL || "http://127.0.0.1:5174";
const SHOTS = process.env.E2E_SHOTS || "/tmp/e2e-shots";
import { mkdirSync } from "node:fs";
mkdirSync(SHOTS, { recursive: true });

const results = [];
function report(step, ok, detail = "") {
  results.push({ step, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"} | ${step}${detail ? " | " + detail : ""}`);
}

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
const page = await ctx.newPage();

// Record every toast (they auto-dismiss in ~3s, so observe mutations).
await page.addInitScript(() => {
  window.__toasts = [];
  const obs = new MutationObserver(() => {
    document.querySelectorAll(".toast").forEach((t) => {
      const text = t.textContent || "";
      const kind = t.className.replace("toast", "").trim();
      if (!window.__toasts.some((x) => x.text === text && x.t > Date.now() - 2000)) {
        window.__toasts.push({ kind, text, t: Date.now() });
      }
    });
  });
  addEventListener("DOMContentLoaded", () =>
    obs.observe(document.body, { childList: true, subtree: true }),
  );
});
const pageErrors = [];
page.on("pageerror", (e) => pageErrors.push(String(e)));

async function waitToast(substr, timeout = 120_000) {
  await page.waitForFunction(
    (s) => (window.__toasts || []).some((t) => t.text.includes(s)),
    substr,
    { timeout },
  );
}
async function shot(name) {
  await page.screenshot({ path: `${SHOTS}/${name}.png` });
}
async function openRowMenu(rowName, item) {
  const row = page.locator(".row", { hasText: rowName }).first();
  await row.locator(".row-menu-wrap .icon-btn").click();
  await page.locator(".menu button", { hasText: item }).click();
}

try {
  // 1. load + gateway up ---------------------------------------------------
  await page.goto(URL, { waitUntil: "domcontentloaded" });
  await page.waitForSelector(".topbar", { timeout: 15_000 });
  report("App loads", true);
  await page.waitForSelector(".conn .dot.up", { timeout: 15_000 });
  report("Gateway health indicator up", true);

  // 2. create signing account + recipient identity -------------------------
  await page.locator(".account-chip").click();
  await page.waitForSelector(".modal");
  await page.getByPlaceholder("e.g. me, alice, bob").fill("e2e-main");
  await page.locator(".btn.primary", { hasText: "Create account" }).click();
  await waitToast("created", 60_000);
  report("Signing account created", true);

  // keypair-only identity for sharing
  await page.getByPlaceholder("e.g. me, alice, bob").fill("bob");
  await page.locator('input[type="checkbox"]').first().uncheck();
  await page.locator(".btn.primary", { hasText: "Create identity" }).click();
  await waitToast("Identity “bob” created", 60_000);
  report("Recipient identity (bob) created", true);
  await shot("1-identities");
  await page.keyboard.press("Escape");

  // 3. new folder -----------------------------------------------------------
  await page.locator(".btn", { hasText: "New folder" }).click();
  await page.locator(".modal .input").fill("docs");
  await page.locator(".modal .btn.primary", { hasText: "Create" }).click();
  await page.waitForSelector(".row .fname >> text=docs", { timeout: 10_000 });
  report("Folder created", true);

  // 4. enter folder, create file (the old 408-repro path) -------------------
  await page.locator(".row", { hasText: "docs" }).first().dblclick();
  await page.waitForSelector(".crumb.last >> text=docs", { timeout: 5_000 });
  const t0 = Date.now();
  await page.locator(".btn.primary", { hasText: "New file" }).click();
  await page.waitForSelector(".modal");
  await page.locator(".modal .input").first().fill("hello.txt");
  await page.locator(".modal textarea").fill("Hello from the E2E run after the state-node redeploy.");
  await page.locator(".modal .btn.primary", { hasText: "Encrypt & create" }).click();
  await waitToast("encrypted & created", 150_000);
  const createMs = Date.now() - t0;
  await page.waitForSelector(".row", { timeout: 10_000 });
  const synced = await page
    .locator(".row", { hasText: "hello.txt" })
    .locator(".badge.synced")
    .count();
  report("File created inside folder", true, `${createMs}ms, synced badge: ${synced > 0}`);
  await shot("2-file-created");

  // 5. preview: state-node history + integrity ------------------------------
  await page.locator(".row", { hasText: "hello.txt" }).first().dblclick();
  await page.waitForSelector(".modal.wide", { timeout: 60_000 });
  await page.waitForSelector(".state-history .ver", { timeout: 60_000 });
  const vers1 = await page.locator(".state-history .ver").count();
  report("Version history loads", vers1 >= 1, `${vers1} version(s)`);
  await page.locator(".btn.sm", { hasText: "Verify integrity" }).click();
  await page.waitForSelector(".badge.synced >> text=valid", { timeout: 60_000 });
  report("Integrity verify → valid", true);
  await shot("3-preview-state");
  await page.keyboard.press("Escape");

  // 6. edit / re-encrypt -----------------------------------------------------
  await openRowMenu("hello.txt", "Edit contents");
  await page.waitForSelector(".modal textarea", { timeout: 30_000 });
  const loaded = await page.locator(".modal textarea").inputValue();
  report("Edit loads decrypted content", loaded.includes("Hello from the E2E run"));
  await page.locator(".modal textarea").fill("Edited content v2 — update path via relay routing fix.");
  await page.locator(".modal .btn.primary", { hasText: "Re-encrypt & save" }).click();
  await waitToast("updated", 150_000);
  report("File updated", true);

  // history should now show 2 versions
  await page.locator(".row", { hasText: "hello.txt" }).first().dblclick();
  await page.waitForSelector(".state-history .ver", { timeout: 60_000 });
  const vers2 = await page.locator(".state-history .ver").count();
  report("History shows new version", vers2 >= 2, `${vers2} version(s)`);
  const previewText = await page.locator(".preview-box").textContent();
  report("Preview shows updated plaintext", (previewText || "").includes("Edited content v2"));
  await shot("4-after-edit");
  await page.keyboard.press("Escape");

  // 7. share + prove round-trip + revoke ------------------------------------
  await openRowMenu("hello.txt", "Share");
  await page.waitForSelector(".modal.wide", { timeout: 10_000 });
  await page.locator(".modal .btn.primary", { hasText: "Wrap CEK & share" }).click();
  await waitToast("Shared with bob", 120_000);
  report("Share (HPKE wrap + decrypt proof)", true);
  await page.waitForSelector(".recipient-row .btn.danger >> text=Revoke", { timeout: 10_000 });
  await page.locator(".recipient-row .btn.danger", { hasText: "Revoke" }).click();
  await waitToast("Access revoked", 120_000);
  report("Revoke + re-encrypt", true);
  await shot("5-share-revoke");
  await page.keyboard.press("Escape");

  // 8. delete file + folder ---------------------------------------------------
  await openRowMenu("hello.txt", "Delete");
  await page.locator(".modal .btn.danger", { hasText: "Delete" }).click();
  await waitToast("deleted", 120_000);
  report("File deleted", true);
  await page.locator(".nav-item", { hasText: "My Drive" }).click();
  await openRowMenu("docs", "Delete");
  await page.locator(".modal .btn.danger", { hasText: "Delete" }).click();
  await waitToast("Folder “docs” deleted", 120_000);
  report("Folder deleted", true);
  await shot("6-final");
} catch (e) {
  report("UNCAUGHT", false, String(e).slice(0, 500));
  await shot("error");
}

// summary -------------------------------------------------------------------
const toasts = await page.evaluate(() => window.__toasts || []);
const errToasts = toasts.filter((t) => t.kind.includes("error"));
console.log("\n--- error toasts ---");
errToasts.forEach((t) => console.log(`  [error] ${t.text}`));
console.log("--- page errors ---");
pageErrors.forEach((e) => console.log(`  ${e}`));
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} steps passed, ${errToasts.length} error toast(s), ${pageErrors.length} page error(s)`);
await browser.close();
process.exit(failed || errToasts.length ? 1 : 0);
