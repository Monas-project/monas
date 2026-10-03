import { test, expect } from "@playwright/test";
import { freshApp, REGISTRY_KEY } from "./helpers";

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

  // Baseline: the full file list.
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

    await expect(page.locator(".crumb")).toHaveCount(1);
  }

  // Back to the full list.
  await page.getByRole("button", { name: "My Drive" }).click();
  await expect(myDrive).toHaveClass(/active/);
  await expect(navItem(page, "Shared")).not.toHaveClass(/active/);
  await expect(crumbLast).toHaveText("My Drive");
});

test("C-18: sidebar Upload opens the file chooser, and there is no New folder", async ({
  page,
}) => {
  // Monas has no folder concept, so the UI must not offer one.
  await expect(page.getByRole("button", { name: "New folder" })).toHaveCount(0);

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

test("C-19: a registry saved with folders shows its files flat and drops the folder rows", async ({
  page,
}) => {
  // What a browser that used the old folder UI has in localStorage: a folder
  // row and a file whose parentPath points into it.
  await page.evaluate((key) => {
    const now = Date.now();
    localStorage.setItem(
      key,
      JSON.stringify([
        {
          id: "old-folder", kind: "folder", name: "docs", parentPath: "/",
          sizeBytes: 0, createdAt: now, updatedAt: now,
          syncedToStateNode: false, versionCount: 0, shares: [],
        },
        {
          id: "old-file", kind: "file", name: "inside.txt", parentPath: "/docs",
          sizeBytes: 5, mimeType: "text/plain", createdAt: now, updatedAt: now,
          localContentId: "cid-local", syncedToStateNode: false, versionCount: 1, shares: [],
        },
      ]),
    );
  }, REGISTRY_KEY);
  await page.reload();

  await expect(page.locator(".row")).toHaveCount(1);
  await expect(page.locator(".row .fname")).toHaveText("inside.txt");
  const stored = await page.evaluate((key) => JSON.parse(localStorage.getItem(key)!), REGISTRY_KEY);
  expect(stored.map((e: { id: string }) => e.id)).toEqual(["old-file"]);
});
