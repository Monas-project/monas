import { test, expect } from "@playwright/test";
import { freshApp, createSigningAccount, seedFileEntry, rowMenuButton } from "./helpers";

/**
 * Group G — ShareModal (G-34).
 *
 * The entry is seeded directly into the registry: reaching the Share modal
 * only requires a row plus an active identity, not a real encrypted file, and
 * the assertion here is that NOTHING happens — so no real content is at risk.
 */

test.beforeEach(async ({ page }) => {
  await freshApp(page);
  // `onAction("share")` guards on an active identity, so one must exist for
  // the Share modal to open at all (see I-46 for the negative case).
  await createSigningAccount(page, "agent-main");
  await seedFileEntry(page);
});

/** Open the Share modal from the first row's menu. */
async function openShare(page: import("@playwright/test").Page) {
  await rowMenuButton(page).click();
  await page.locator(".menu button", { hasText: "Share" }).click();
  await expect(page.getByRole("heading", { name: /^Share/ })).toBeVisible();
}

/**
 * KNOWN BUG — ShareModal.tsx:53.
 *
 * In "Paste public key" mode `submit()` does `if (!pubKey.trim()) return;`
 * while the button stays ENABLED. Clicking it with an empty textarea produces
 * nothing at all: no toast, no pipeline run, no validation message, and the
 * modal stays open. This is the "control silently does nothing" failure mode.
 *
 * The test asserts the CURRENT (buggy) behaviour so the suite stays green
 * while documenting the defect. WHEN THE BUG IS FIXED THIS TEST WILL FAIL —
 * that is intended. The correct behaviour is either:
 *   a) `disabled={busy || (mode === "key" && !pubKey.trim())}`, or
 *   b) an error toast on submit with an empty key.
 * When fixing, flip the assertions below to expect the disabled button (or
 * the error toast) and delete this note.
 */
test("G-34: empty public key makes 'Wrap CEK & share' a dead click [KNOWN BUG]", async ({
  page,
}) => {
  await openShare(page);

  const modal = page.locator(".modal.wide");

  // Only the signing account exists, so there is no *other* identity to pick:
  // "Pick identity (none)" is disabled and the modal opens in key mode.
  await modal.getByRole("button", { name: /^Paste public key/ }).click();

  const textarea = modal.getByPlaceholder(
    "P-256 public key, base64url (from the gateway /keypair)",
  );
  await expect(textarea).toBeVisible();
  await expect(textarea).toHaveValue("");

  await expect(modal).toMatchAriaSnapshot(`
    - img
    - heading /Share/ [level=2]
    - button:
      - img
    - text: Add recipient
    - button /Pick identity/ [disabled]
    - button "Paste public key"
    - text: Recipient public key (base64url)
    - textbox
    - text: Label (optional)
    - textbox
    - text: Permission
    - button "read"
    - button "read + write"
    - button "Close"
    - button "Wrap CEK & share"
  `);

  const shareBtn = modal.getByRole("button", { name: "Wrap CEK & share" });

  // INTENDED: the button is disabled with an empty key.
  // ACTUAL: it is enabled but inert.
  await expect(shareBtn).toBeEnabled();

  await shareBtn.click();

  // Nothing happens. Give the app a moment to prove the absence of an effect
  // (a real share would push a run within a few hundred ms).
  await page.waitForTimeout(1500);

  // INTENDED: an error toast explaining the empty key.
  // ACTUAL: no toast at all.
  await expect(page.locator(".toast")).toHaveCount(0);

  // INTENDED: nothing (the submit was rejected) — this part is already right,
  // but it confirms no partial share was attempted.
  await expect(page.locator(".run")).toHaveCount(0);
  await expect(page.locator(".pipe-empty")).toBeVisible();

  // The modal stays open with no feedback, so the user has no idea why.
  await expect(page.getByRole("heading", { name: /^Share/ })).toBeVisible();
  await expect(textarea).toHaveValue("");

  // And no share was recorded on the entry.
  await expect(page.locator(".recipient-row")).toHaveCount(0);
  await expect(page.locator(".badge.shared")).toHaveCount(0);

  // Whitespace-only is the same dead click (`.trim()` is what rejects it).
  await textarea.fill("   ");
  await shareBtn.click();
  await page.waitForTimeout(1000);
  await expect(page.locator(".toast")).toHaveCount(0);
  await expect(page.locator(".run")).toHaveCount(0);
  await expect(page.getByRole("heading", { name: /^Share/ })).toBeVisible();
});
