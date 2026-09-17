import { test, expect } from "@playwright/test";
import { freshApp, waitForGateway, seedFileEntry, rowMenuButton } from "./helpers";

/**
 * Group I — guards (I-45, I-46).
 *
 * Both scenarios test the NO-account / NO-identity case, so this file must
 * never create one. `freshApp` clears localStorage and reloads; nothing here
 * depends on seed.spec.ts (which would break the precondition if it did).
 */

test.beforeEach(async ({ page }) => {
  await freshApp(page);
  await waitForGateway(page);
  // Precondition: genuinely no identity.
  await expect(page.locator(".account-chip")).toContainText("No identity");
});

test("I-45: content ops without a signing account are refused", async ({ page }) => {
  // --- New file ---
  await page.getByRole("button", { name: "New file" }).click();
  const modal = page.locator(".modal");
  await modal.locator("input.input").fill("blocked.txt");
  await page.getByRole("button", { name: "Encrypt & create" }).click();

  // `requireSigningAccount()` toasts and forces the identity modal open.
  await expect(
    page.locator(".toast.error", { hasText: "Create a signing account first" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Identities & keys" }),
  ).toBeVisible();

  // Nothing was created and no pipeline run was started.
  await expect(page.locator(".row")).toHaveCount(0);
  await expect(page.locator(".run")).toHaveCount(0);
  await expect(page.locator(".pipe-empty")).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(page.locator(".overlay")).toHaveCount(0);

  // The registry is still empty on disk, not just visually.
  expect(
    await page.evaluate(() => localStorage.getItem("monas.registry.v3")),
  ).toBeNull();

  // Wait out the error toast (5.2s) so the next assertion starts clean.
  await expect(page.locator(".toast")).toHaveCount(0, { timeout: 10_000 });

  // --- Upload shares the same guard (handleUpload → requireSigningAccount) ---
  const chooserPromise = page.waitForEvent("filechooser");
  await page.getByRole("button", { name: "Upload" }).click();
  const chooser = await chooserPromise;
  await chooser.setFiles({
    name: "blocked-upload.txt",
    mimeType: "text/plain",
    buffer: Buffer.from("should never be encrypted"),
  });

  await expect(
    page.locator(".toast.error", { hasText: "Create a signing account first" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Identities & keys" }),
  ).toBeVisible();

  await expect(page.locator(".row")).toHaveCount(0);
  await expect(page.locator(".run")).toHaveCount(0);
});

test("I-46: share without an identity is refused", async ({ page }) => {
  // An entry can exist without an identity (e.g. a registry restored into a
  // fresh browser), so seed one directly and try to share it.
  await seedFileEntry(page);
  await expect(page.locator(".row")).toHaveCount(1);
  await expect(page.locator(".account-chip")).toContainText("No identity");

  await rowMenuButton(page).click();
  await page.locator(".menu button", { hasText: "Share" }).click();

  // `onAction("share")` guards on `active` before opening the modal.
  await expect(
    page.locator(".toast.error", { hasText: "Create an identity first" }),
  ).toBeVisible();

  // The Identity modal opens — NOT the Share modal.
  await expect(
    page.getByRole("heading", { name: "Identities & keys" }),
  ).toBeVisible();
  await expect(page.getByRole("heading", { name: /^Share/ })).toHaveCount(0);
  await expect(page.locator(".modal")).toHaveCount(1);

  // No share was recorded and no run started.
  await expect(page.locator(".run")).toHaveCount(0);
  await expect(page.locator(".badge.shared")).toHaveCount(0);
});
