import { test, expect } from "@playwright/test";

/**
 * Seed test — bootstraps the app into a state an agent (or a human) can
 * actually explore from.
 *
 * Two things make a bare `page.goto()` insufficient here:
 *
 * 1. The Drive keeps its registry in localStorage, so state leaks between
 *    runs unless it is cleared first.
 * 2. Content operations are gated behind a **signing account** — without one,
 *    "New file" refuses to do anything and most of the UI is unreachable.
 *    Creating that account registers a P-256 key with monas-account, which
 *    the SDK then uses to sign state-node requests.
 *
 * Requires the full stack (vite → gateway → 4-node cluster). See README.
 */
test("seed", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => localStorage.clear());
  await page.reload();

  await expect(page.locator(".topbar")).toBeVisible();

  // The gateway must actually be reachable, otherwise every later step fails
  // with a confusing network error instead of a clear setup failure.
  // The health dot only gains `.up` once a /health probe succeeds.
  await expect(page.locator(".conn-item .dot.up")).toBeVisible({
    timeout: 30_000,
  });

  // Create the signing account that unlocks content operations.
  await page.locator(".account-chip").click();
  await page.getByPlaceholder("e.g. me, alice, bob").fill("agent-main");
  await page.locator(".btn.primary", { hasText: "Create account" }).click();
  await expect(page.locator(".modal")).toContainText("agent-main");

  await page.keyboard.press("Escape");
});
