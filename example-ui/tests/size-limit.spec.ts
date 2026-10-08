import { test, expect, type Page } from "@playwright/test";
import { freshApp, waitForGateway, createSigningAccount, rowMenuButton } from "./helpers";

/**
 * Group I — file size limit (I-50).
 *
 * Bodies over MAX_FILE_BYTES (64 KB) do not replicate between state nodes, so
 * every path that sends a body — New file, Upload, Edit — must refuse them
 * before encrypting. A refused action starts no pipeline run, i.e. no gateway
 * call. The limit itself is pinned at 64 KB: 64 KB passes, one byte more fails.
 */

const LIMIT = 64 * 1024;
const refusal = (page: Page) => page.locator(".toast.error", { hasText: "can't be stored in this demo" });

test.beforeEach(async ({ page }) => {
  await freshApp(page);
  await waitForGateway(page);
  await createSigningAccount(page);
});

test("I-50a: Upload over the limit is refused before any gateway call", async ({ page }) => {
  const chooser = page.waitForEvent("filechooser");
  await page.getByRole("button", { name: "Upload" }).click();
  await (await chooser).setFiles({
    name: "too-big.bin",
    mimeType: "application/octet-stream",
    buffer: Buffer.alloc(LIMIT + 1, 7),
  });

  await expect(refusal(page)).toContainText("too-big.bin");
  await expect(refusal(page)).toContainText("64.0 KB");
  await expect(page.locator(".row")).toHaveCount(0);
  await expect(page.locator(".run")).toHaveCount(0);
});

test("I-50b: New file over the limit is refused and the editor stays open", async ({ page }) => {
  await page.getByRole("button", { name: "New file" }).click();
  const modal = page.locator(".modal");
  await modal.locator("input.input").fill("big.txt");
  // fill() sets the value in one go; typing 64 KB would take minutes.
  await modal.locator("textarea").fill("x".repeat(LIMIT + 1));
  await page.getByRole("button", { name: "Encrypt & create" }).click();

  await expect(refusal(page)).toContainText("big.txt");
  // The user keeps what they typed and can trim it.
  await expect(modal).toBeVisible();
  await expect(page.locator(".run")).toHaveCount(0);
});

test("I-50c: Edit that grows a file over the limit is refused", async ({ page }) => {
  // A real (small) file: the editor pulls the head from the state node first,
  // so a seeded registry row with a fake CID would never open it.
  await page.getByRole("button", { name: "New file" }).click();
  const modal = page.locator(".modal");
  await modal.locator("input.input").fill("grow.txt");
  await modal.locator("textarea").fill("small");
  await page.getByRole("button", { name: "Encrypt & create" }).click();
  await expect(page.locator(".toast.success", { hasText: "encrypted & created" })).toBeVisible();

  await rowMenuButton(page).click();
  await page.locator(".menu button", { hasText: "Edit contents" }).click();
  await expect(modal.locator("textarea")).toHaveValue("small");
  await modal.locator("textarea").fill("y".repeat(LIMIT + 1));
  const runsBefore = await page.locator(".run").count();
  await page.getByRole("button", { name: "Re-encrypt & save" }).click();

  await expect(refusal(page)).toContainText("grow.txt");
  await expect(modal).toBeVisible();
  await expect(page.locator(".run")).toHaveCount(runsBefore);
});

test("I-50d: exactly 64 KB is accepted (a run starts)", async ({ page }) => {
  await page.getByRole("button", { name: "New file" }).click();
  const modal = page.locator(".modal");
  await modal.locator("input.input").fill("at-limit.txt");
  await modal.locator("textarea").fill("z".repeat(LIMIT));
  await page.getByRole("button", { name: "Encrypt & create" }).click();

  await expect(page.locator(".run").first()).toBeVisible();
  await expect(refusal(page)).toHaveCount(0);
});
