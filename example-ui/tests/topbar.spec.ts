import { test, expect } from "@playwright/test";
import { freshApp, waitForGateway, createSigningAccount } from "./helpers";

/**
 * Group D — TopBar (D-19, D-21).
 */

test.beforeEach(async ({ page }) => {
  await freshApp(page);
});

test("D-19: the gateway health indicator turns up", async ({ page }) => {
  const wrapper = page.locator(".conn");

  // The wrapper carries the only human-readable description of this control.
  await expect(wrapper).toHaveAttribute(
    "title",
    "Gateway health (monas-gateway → SDK)",
  );
  await expect(wrapper.locator(".conn-item")).toContainText("gateway");

  // A11Y-1: the health state exists ONLY as a CSS class. There is no text
  // change, no aria-live and no title change, so this is the only way to
  // assert it — and a screen-reader user cannot perceive it at all.
  // The probe runs on mount and then every 6s.
  await expect(page.locator(".conn .dot")).toHaveClass(/\bup\b/, {
    timeout: 30_000,
  });
  await expect(page.locator(".conn .dot")).not.toHaveClass(/\bdown\b/);
});

test("D-21: the account chip reflects identity state and opens the identity modal", async ({
  page,
}) => {
  await waitForGateway(page);

  const chip = page.locator(".account-chip");

  // --- With no identity ---
  // A11Y-4: the chip has no accessible name of its own; only its children
  // carry text, so it is addressed by class.
  await expect(chip).toContainText("No identity");
  await expect(chip).toContainText("click to create");
  await expect(chip.locator(".avatar")).toHaveText("+");

  await chip.click();
  await expect(
    page.getByRole("heading", { name: "Identities & keys" }),
  ).toBeVisible();
  await expect(page.locator(".modal")).toContainText("None yet");
  await page.keyboard.press("Escape");
  await expect(page.locator(".overlay")).toHaveCount(0);

  // --- After creating the signing account ---
  await createSigningAccount(page, "agent-main");

  await expect(chip).toContainText("agent-main");
  // initials() = first two chars, uppercased.
  await expect(chip.locator(".avatar")).toHaveText("AG");

  // Sub-line renders `<keyType> · <first 10 chars of the public key>`.
  const sub = chip.locator(".meta span").last();
  await expect(sub).toHaveText(/^secp256r1 · .{10}$/);

  // The label must agree with what the store actually holds.
  const identity = await page.evaluate(() => {
    const raw = localStorage.getItem("monas.identities.v2");
    return raw ? JSON.parse(raw) : null;
  });
  expect(identity.activeLabel).toBe("agent-main");
  const active = identity.identities.find(
    (i: { label: string }) => i.label === "agent-main",
  );
  expect(active.isSigningAccount).toBe(true);
  await expect(sub).toHaveText(
    `secp256r1 · ${active.publicKeyB64Url.slice(0, 10)}`,
  );
});
