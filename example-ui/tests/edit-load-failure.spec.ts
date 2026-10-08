import { test, expect, type Page } from "@playwright/test";
import { freshApp, seedFileEntry, rowMenuButton } from "./helpers";

/**
 * The owner's editor starts from the Content Network head (it pulls first, so
 * a recipient's write is not overwritten). When that load fails the editor
 * must not open: an empty editor saves as "replace the file with what I typed
 * over nothing", and with the pull skipped it also discards the recipient's
 * version.
 *
 * No stack needed: the gateway calls are mocked, so these run against the
 * Vite dev server alone.
 */

const envelope = (data: unknown) => ({ success: true, data, trace_id: "t" });

async function mockPull(page: Page, respond: "fail" | "ok") {
  await page.route("**/state/pull", (route) =>
    respond === "fail"
      ? route.fulfill({
          status: 500,
          contentType: "application/json",
          body: JSON.stringify({
            success: false,
            error: { type: "Internal", message: "state node unreachable" },
            trace_id: "t",
          }),
        })
      : route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(
            envelope({
              content_id: "seeded-remote-cid",
              local_content_id: "seeded-local-cid",
              version: "v1",
              adopted: false,
              content: "c21hbGw", // "small"
            }),
          ),
        }),
  );
}

test.beforeEach(async ({ page }) => {
  await freshApp(page);
});

test("a failed pull does not open the owner's editor empty", async ({ page }) => {
  await mockPull(page, "fail");
  await seedFileEntry(page);

  await rowMenuButton(page).click();
  await page.locator(".menu button", { hasText: "Edit contents" }).click();

  await expect(
    page.locator(".toast.error", { hasText: "Could not load contents" }),
  ).toBeVisible();
  // No editor to save over the file with.
  await expect(page.locator(".modal textarea")).toHaveCount(0);
  await expect(page.locator(".overlay")).toHaveCount(0);
});

test("control: a successful pull still opens the editor with the head's text", async ({ page }) => {
  await mockPull(page, "ok");
  await seedFileEntry(page);

  await rowMenuButton(page).click();
  await page.locator(".menu button", { hasText: "Edit contents" }).click();

  await expect(page.locator(".modal textarea")).toHaveValue("small");
});
