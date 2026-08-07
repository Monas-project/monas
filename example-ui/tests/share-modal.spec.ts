import { test, expect } from "@playwright/test";
import { freshApp, createSigningAccount, seedFileEntry, rowMenuButton } from "./helpers";

/**
 * Group G — ShareModal (G-34).
 *
 * The entry is seeded directly into the registry: reaching the Share modal
 * only requires a row plus an active identity, not a real encrypted file, and
 * nothing here is ever submitted — so no content round trip is needed.
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
 * "Wrap CEK & share" must not be clickable when there is no recipient to
 * share with.
 *
 * Both branches of `submit()` bail out early on missing input, so while the
 * button stayed enabled, clicking it with an empty key was a silent no-op —
 * no toast, no run, no validation, modal still open. The button is now gated
 * on `recipientReady`, and the empty key field explains why.
 */
test("G-34: 'Wrap CEK & share' is disabled until a recipient is supplied", async ({
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
    - text: Paste a recipient public key to enable sharing. Label (optional)
    - textbox
    - text: Permission
    - button "read"
    - button "read + write"
    - button "Close"
    - button "Wrap CEK & share" [disabled]
  `);

  const shareBtn = modal.getByRole("button", { name: "Wrap CEK & share" });
  await expect(shareBtn).toBeDisabled();

  // Whitespace-only is still no recipient — `.trim()` is what rejects it.
  await textarea.fill("   ");
  await expect(shareBtn).toBeDisabled();

  // A non-empty key enables it, and the hint goes away.
  await textarea.fill("BHT7z8bTbRATF3GC4IzZ8BFp_8YM6rW9krTje7azSgt0");
  await expect(shareBtn).toBeEnabled();
  await expect(modal.getByText("Paste a recipient public key")).toHaveCount(0);

  // Clearing it disables the button again.
  await textarea.fill("");
  await expect(shareBtn).toBeDisabled();

  // Nothing was ever submitted along the way.
  await expect(page.locator(".run")).toHaveCount(0);
  await expect(page.locator(".recipient-row")).toHaveCount(0);
});
