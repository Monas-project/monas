import { test, expect } from "@playwright/test";
import { freshApp } from "./helpers";

/**
 * Group B — PipelinePanel (B-08).
 *
 * No mutations: collapse/expand is pure component state.
 */

test.beforeEach(async ({ page }) => {
  await freshApp(page);
});

test("B-08: Collapse hides the panel body and swaps the control", async ({ page }) => {
  const panel = page.locator("aside.pipeline");

  // Expanded by default: a header, the title, and a Collapse control.
  await expect(panel).toBeVisible();
  await expect(panel).not.toHaveClass(/collapsed/);
  await expect(panel.locator(".pipe-head")).toBeVisible();
  await expect(panel).toContainText("Protocol activity");

  // `Collapse` has no text — the accessible name comes from `title`.
  await page.getByRole("button", { name: "Collapse" }).click();

  await expect(panel).toHaveClass(/collapsed/);
  await expect(panel.locator(".pipe-head")).toHaveCount(0);

  // Collapsed state renders exactly one control, named only via `title`
  // (A11Y-3: no text, no aria-label).
  await expect(panel.locator("button")).toHaveCount(1);
  const showBtn = page.getByRole("button", { name: "Show protocol activity" });
  await expect(showBtn).toBeVisible();

  // With no runs there is no Clear button either.
  await expect(page.getByRole("button", { name: "Clear" })).toHaveCount(0);

  // Toggling back restores the full panel.
  await showBtn.click();
  await expect(panel).not.toHaveClass(/collapsed/);
  await expect(panel.locator(".pipe-head")).toBeVisible();
  await expect(page.getByRole("button", { name: "Collapse" })).toBeVisible();
});
