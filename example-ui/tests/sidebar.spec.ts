import { test, expect } from "@playwright/test";
import { freshApp } from "./helpers";

/**
 * Group C — Sidebar (C-13, C-18).
 *
 * No content mutations. The nav rows are `div.nav-item` with `role="button"`,
 * so `getByRole("button", ...)` reaches them; the active one carries
 * `.nav-item.active`.
 */

test.beforeEach(async ({ page }) => {
  await freshApp(page);
});

/** The nav row (not the inner span) whose accessible name starts with `name`. */
function navItem(page: import("@playwright/test").Page, name: string) {
  return page.locator(".nav-item", { hasText: name }).first();
}

test("C-13: filter views switch the active nav item and retitle the breadcrumb", async ({
  page,
}) => {
  const myDrive = navItem(page, "My Drive");
  const crumbLast = page.locator(".crumb.last");

  // Baseline: folder browsing.
  await expect(myDrive).toHaveClass(/active/);
  await expect(crumbLast).toHaveText("My Drive");

  for (const [label, crumb] of [
    ["Encrypted files", "Encrypted files"],
    ["On state-node", "On state-node"],
    ["Shared", "Shared"],
  ] as const) {
    await page.getByRole("button", { name: new RegExp(`^${label}`) }).click();

    await expect(navItem(page, label)).toHaveClass(/active/);
    await expect(myDrive).not.toHaveClass(/active/);
    await expect(crumbLast).toHaveText(crumb);

    // A filter view is drive-wide, so the breadcrumb collapses to a single
    // title crumb rather than a path.
    await expect(page.locator(".crumb")).toHaveCount(1);
  }

  // Back to folder browsing: `.active` returns and the crumb shows the path.
  await page.getByRole("button", { name: "My Drive" }).click();
  await expect(myDrive).toHaveClass(/active/);
  await expect(navItem(page, "Shared")).not.toHaveClass(/active/);
  await expect(crumbLast).toHaveText("My Drive");
});

test("C-18: sidebar New folder opens the modal and Upload opens the file chooser", async ({
  page,
}) => {
  // --- New folder: a real modal ---
  await page.getByRole("button", { name: "New folder" }).click();

  const modal = page.locator(".modal");
  await expect(modal.getByRole("heading", { name: "New folder" })).toBeVisible();
  await expect(modal).toMatchAriaSnapshot(`
    - img
    - heading "New folder" [level=2]
    - button:
      - img
    - text: Folder name
    - textbox
    - button "Cancel"
    - button "Create" [disabled]
  `);

  await page.keyboard.press("Escape");
  await expect(page.locator(".overlay")).toHaveCount(0);

  // --- Upload: triggers the hidden input[type=file] ---
  // The input is `display:none`, so it is never "visible" — the only
  // observable effect is the file chooser event.
  const chooserPromise = page.waitForEvent("filechooser");
  await page.getByRole("button", { name: "Upload" }).click();
  const chooser = await chooserPromise;
  expect(chooser.isMultiple()).toBe(false);

  // Nothing was selected, so no modal and no registry change.
  await expect(page.locator(".overlay")).toHaveCount(0);
  await expect(page.locator(".row")).toHaveCount(0);
});
