import { test, expect, type Page } from "@playwright/test";
import { freshApp, seedFileEntry, rowMenuButton } from "./helpers";

/**
 * Group F — ActionModals (F-29, F-30, F-31).
 *
 * All assertions land *before* anything is committed, so no scenario here
 * costs a crypto round trip. F-31 seeds a registry entry directly rather than
 * creating a real file — it only needs a row to open Rename/Delete from.
 */

test.beforeEach(async ({ page }) => {
  await freshApp(page);
});

const overlay = (page: Page) => page.locator(".overlay");

test("F-29: New file — empty or whitespace-only name disables submit", async ({
  page,
}) => {
  await page.getByRole("button", { name: "New file" }).click();

  const modal = page.locator(".modal");
  await expect(modal.getByRole("heading", { name: "New file" })).toBeVisible();

  // Labels are siblings with no `for` (A11Y-5) — address the inputs
  // positionally: the name input, then the contents textarea.
  const nameInput = modal.locator("input.input");
  const submit = page.getByRole("button", { name: "Encrypt & create" });

  await expect(modal).toMatchAriaSnapshot(`
    - img
    - heading "New file" [level=2]
    - button:
      - img
    - text: File name
    - textbox: untitled.txt
    - text: Contents
    - textbox
    - text: /0 bytes/
    - button "Cancel"
    - button "Encrypt & create"
  `);

  // Pre-filled and enabled.
  await expect(nameInput).toHaveValue("untitled.txt");
  await expect(submit).toBeEnabled();

  // `valid = name.trim().length > 0`
  await nameInput.fill("");
  await expect(submit).toBeDisabled();

  await nameInput.fill("   ");
  await expect(submit).toBeDisabled();

  await nameInput.fill("notes.txt");
  await expect(submit).toBeEnabled();

  // Leave without committing anything.
  await page.keyboard.press("Escape");
  await expect(overlay(page)).toHaveCount(0);
  await expect(page.locator(".row")).toHaveCount(0);
});

test("F-30: New folder — submit disabled until a real name is typed", async ({
  page,
}) => {
  await page.getByRole("button", { name: "New folder" }).click();

  const modal = page.locator(".modal");
  const input = modal.locator("input.input");
  // Scoped to the modal: a bare name="Create" also matches the account chip
  // ("click to create") in strict mode.
  const create = modal.getByRole("button", { name: "Create", exact: true });

  await expect(input).toHaveValue("");
  await expect(input).toHaveAttribute("placeholder", "Untitled folder");
  await expect(create).toBeDisabled();

  await page.keyboard.type("   ");
  await expect(create).toBeDisabled();

  await input.fill("docs");
  await expect(create).toBeEnabled();

  await page.keyboard.press("Escape");
  await expect(overlay(page)).toHaveCount(0);
  await expect(page.locator(".row")).toHaveCount(0);
});

test("F-31: Cancel, X, Escape and backdrop all dismiss without side effects", async ({
  page,
}) => {
  // A seeded row gives us Rename and Delete without a crypto round trip.
  await seedFileEntry(page);
  await expect(page.locator(".row")).toHaveCount(1);

  /** Open one of the four modals under test. */
  const openers: Record<string, () => Promise<void>> = {
    "New file": async () => {
      await page.getByRole("button", { name: "New file" }).click();
    },
    "New folder": async () => {
      await page.getByRole("button", { name: "New folder" }).click();
    },
    Rename: async () => {
      await rowMenuButton(page).click();
      await page.locator(".menu button", { hasText: "Rename" }).click();
    },
    Delete: async () => {
      await rowMenuButton(page).click();
      await page.locator(".menu button.danger", { hasText: "Delete" }).click();
    },
  };

  /** Dismiss the open modal one of four ways. */
  const dismissers: Record<string, () => Promise<void>> = {
    cancel: async () => {
      await page.getByRole("button", { name: "Cancel" }).click();
    },
    // A11Y-2: the close X has no accessible name — only `.modal-head .icon-btn`.
    x: async () => {
      await page.locator(".modal-head .icon-btn").click();
    },
    escape: async () => {
      await page.keyboard.press("Escape");
    },
    // Modal binds onMouseDown on `.overlay`; the inner `.modal` stops
    // propagation, so a backdrop click must close and an inner click must not.
    backdrop: async () => {
      await page.locator(".overlay").click({ position: { x: 5, y: 5 } });
    },
  };

  for (const [modalName, open] of Object.entries(openers)) {
    for (const [how, dismiss] of Object.entries(dismissers)) {
      await open();
      await expect(overlay(page), `${modalName} should open`).toHaveCount(1);

      // Fill a value where the modal has an editable field, so we are
      // dismissing a *dirty* modal rather than an untouched one.
      const input = page.locator(".modal input.input");
      if (await input.count()) await input.first().fill("throwaway-name");

      // Clicking *inside* the modal must NOT close it.
      await page.locator(".modal-body").click({ position: { x: 5, y: 5 } });
      await expect(
        overlay(page),
        `${modalName}: inner click must not close (${how})`,
      ).toHaveCount(1);

      await dismiss();

      await expect(
        overlay(page),
        `${modalName} should close via ${how}`,
      ).toHaveCount(0);

      // No toast — a dismissal is not an action.
      await expect(page.locator(".toast")).toHaveCount(0);

      // Registry unchanged: still exactly the one seeded row.
      await expect(page.locator(".row")).toHaveCount(1);
      await expect(page.locator(".row .fname")).toHaveText("probe.txt");
    }
  }
});
