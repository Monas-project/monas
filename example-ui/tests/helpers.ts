import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";

/**
 * Shared setup helpers.
 *
 * Every spec starts from a known state rather than inheriting whatever the
 * previous file left in localStorage. The registry, the identity list and the
 * endpoint config all live there, so a stale key from an earlier spec can
 * silently change what a later assertion sees.
 */

export const REGISTRY_KEY = "monas.registry.v3";
export const IDENTITY_KEY = "monas.identities.v2";
export const ENDPOINT_KEY = "monas.endpoints.v2";

/** Load the app with a completely empty localStorage. */
export async function freshApp(page: Page) {
  await page.goto("/");
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await expect(page.locator(".topbar")).toBeVisible();
}

/**
 * Wait for the gateway health probe to succeed. The state is CSS-only
 * (`.dot.up`), see A11Y-1 in specs/ui-coverage.md — there is no text or
 * aria-live to assert on.
 */
export async function waitForGateway(page: Page) {
  await expect(page.locator(".conn-item .dot.up")).toBeVisible({
    timeout: 30_000,
  });
}

/**
 * Create the P-256 signing account that unlocks every content operation.
 * Specs that need one call this inline instead of depending on seed.spec.ts
 * having run first (test files must be independently runnable).
 */
export async function createSigningAccount(page: Page, label = "agent-main") {
  await waitForGateway(page);
  await page.locator(".account-chip").click();
  await page.getByPlaceholder("e.g. me, alice, bob").fill(label);
  await page.locator(".btn.primary", { hasText: "Create account" }).click();
  await expect(page.locator(".modal")).toContainText(label);
  await page.keyboard.press("Escape");
  await expect(page.locator(".overlay")).toHaveCount(0);
}

/**
 * Write a file entry straight into the registry.
 *
 * A real create costs a full encrypt → CID → 4-node state-node round trip
 * (seconds). Scenarios that only need *a row to exist* — to open its menu, or
 * to reach the Share modal — get the same UI state for free by seeding the
 * store the app reads on boot. The caller must reload afterwards; the store
 * snapshots localStorage at module load.
 */
export async function seedFileEntry(
  page: Page,
  overrides: Record<string, unknown> = {},
) {
  await page.evaluate(
    ([key, extra]) => {
      const raw = localStorage.getItem(key as string);
      const list = raw ? JSON.parse(raw) : [];
      list.push({
        id: "seeded-file-1",
        kind: "file",
        name: "probe.txt",
        parentPath: "/",
        sizeBytes: 16,
        mimeType: "text/plain",
        createdAt: Date.now(),
        updatedAt: Date.now(),
        localContentId: "seeded-local-cid",
        remoteContentId: "seeded-remote-cid",
        syncedToStateNode: true,
        versionCount: 1,
        shares: [],
        ...(extra as Record<string, unknown>),
      });
      localStorage.setItem(key as string, JSON.stringify(list));
    },
    [REGISTRY_KEY, overrides] as const,
  );
  await page.reload();
  await expect(page.locator(".topbar")).toBeVisible();
}

/** Read a JSON localStorage key, or null when absent. */
export async function readStorage(page: Page, key: string) {
  return page.evaluate((k) => {
    const raw = localStorage.getItem(k);
    return raw === null ? null : JSON.parse(raw);
  }, key);
}

/** Open the row menu (the `⋯` icon-btn) for the Nth row. A11Y-3: no name. */
export function rowMenuButton(page: Page, nth = 0) {
  return page.locator(".row .row-menu-wrap .icon-btn").nth(nth);
}
