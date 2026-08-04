import { test, expect } from "@playwright/test";
import { freshApp, readStorage, ENDPOINT_KEY } from "./helpers";

/**
 * Group A — SettingsModal (S-02, S-04, S-05, S-06, S-07).
 *
 * No content mutations: every assertion here is pure UI + localStorage.
 * Labels in this modal are *siblings* of their inputs with no `for`/`id`
 * (A11Y-5), so `getByLabel()` does not work — the two textboxes are addressed
 * positionally: index 0 = gateway, index 1 = account service.
 */

const PRESET_PROXY = "Local (Vite proxy → Docker)";
const PRESET_DIRECT = "Local (direct :3000)";

test.beforeEach(async ({ page }) => {
  await freshApp(page);
});

/** Open Settings and return the two endpoint inputs. */
async function openSettings(page: import("@playwright/test").Page) {
  await page.getByRole("button", { name: "Settings · endpoint" }).click();
  await expect(page.getByRole("heading", { name: "Endpoint" })).toBeVisible();
  const inputs = page.locator(".modal.wide .field input.input");
  return { gateway: inputs.nth(0), account: inputs.nth(1) };
}

test("S-02: preset buttons rewrite the gateway field and move the `on` class", async ({
  page,
}) => {
  const { gateway } = await openSettings(page);

  // Baseline: PROXY_DEFAULTS, with the proxy preset highlighted.
  await expect(gateway).toHaveValue("/api");
  await expect(page.getByRole("button", { name: PRESET_PROXY })).toHaveClass(/on/);

  await page.getByRole("button", { name: PRESET_DIRECT }).click();
  await expect(gateway).toHaveValue("http://127.0.0.1:3000");

  // The highlight is derived from `cfg.gateway === p.value`, so it must move.
  await expect(page.getByRole("button", { name: PRESET_DIRECT })).toHaveClass(/on/);
  await expect(page.getByRole("button", { name: PRESET_PROXY })).not.toHaveClass(/on/);

  await page.getByRole("button", { name: PRESET_PROXY }).click();
  await expect(gateway).toHaveValue("/api");
  await expect(page.getByRole("button", { name: PRESET_PROXY })).toHaveClass(/on/);
  await expect(page.getByRole("button", { name: PRESET_DIRECT })).not.toHaveClass(/on/);
});

test("S-02b: the modal exposes the documented control set (ARIA snapshot)", async ({
  page,
}) => {
  await openSettings(page);

  // Snapshotting the whole modal asserts the full control set in one go and
  // survives CSS churn — a renamed/removed button fails here immediately.
  // The leading `- img` is the modal's icon and the bare `- button` is the
  // close X, which has no accessible name at all (A11Y-2).
  await expect(page.locator(".modal.wide")).toMatchAriaSnapshot(`
    - img
    - heading "Endpoint" [level=2]
    - button:
      - img
    - text: /monas-gateway base URL/
    - textbox: /api
    - button "Local (Vite proxy → Docker)"
    - button "Local (direct :3000)"
    - text: /monas-account base URL/
    - textbox: /account-api
    - button "Reset to proxy"
    - button "Test connection"
    - button "Save":
      - img
      - text: Save
  `);
});

test("S-04: Save persists to localStorage and closes the modal", async ({ page }) => {
  const { gateway } = await openSettings(page);
  await page.getByRole("button", { name: PRESET_DIRECT }).click();
  await expect(gateway).toHaveValue("http://127.0.0.1:3000");

  await page.getByRole("button", { name: "Save" }).click();

  await expect(page.locator(".toast.success", { hasText: "Endpoint saved" })).toBeVisible();
  await expect(page.locator(".overlay")).toHaveCount(0);

  expect(await readStorage(page, ENDPOINT_KEY)).toEqual({
    gateway: "http://127.0.0.1:3000",
    accountService: "/account-api",
  });

  // Cleanup: leave the endpoint back on the proxy so nothing later in the run
  // (or a re-run of this file) inherits a direct-:3000 gateway.
  const reopened = await openSettings(page);
  await page.getByRole("button", { name: "Reset to proxy" }).click();
  await expect(reopened.gateway).toHaveValue("/api");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.locator(".overlay")).toHaveCount(0);
  expect(await readStorage(page, ENDPOINT_KEY)).toEqual({
    gateway: "/api",
    accountService: "/account-api",
  });
});

test("S-05: preset clicks alone are not persisted until Save", async ({ page }) => {
  // Fresh registry: the key does not exist at all before the first Save.
  expect(await readStorage(page, ENDPOINT_KEY)).toBeNull();

  const { gateway } = await openSettings(page);
  await page.getByRole("button", { name: PRESET_DIRECT }).click();
  await expect(gateway).toHaveValue("http://127.0.0.1:3000");

  // Dismiss without saving.
  await page.keyboard.press("Escape");
  await expect(page.locator(".overlay")).toHaveCount(0);

  // Selecting a preset is component state only — nothing reached storage.
  expect(await readStorage(page, ENDPOINT_KEY)).toBeNull();
});

test("S-06: Test connection probes the gateway and reports reachable", async ({ page }) => {
  await openSettings(page);

  const testBtn = page.getByRole("button", { name: "Test connection" });
  await testBtn.click();

  // With the stack up this must be the success variant.
  await expect(page.locator(".toast", { hasText: /gateway (✓ reachable|✗ unreachable)/ })).toBeVisible();
  await expect(page.locator(".toast.success", { hasText: "gateway ✓ reachable" })).toBeVisible();

  // The spinner clears and the button re-enables afterwards.
  await expect(testBtn).toBeEnabled();
  await expect(testBtn.locator(".spinner")).toHaveCount(0);
});

test("S-06b: Test connection reports unreachable for a dead endpoint", async ({ page }) => {
  const { gateway } = await openSettings(page);
  await gateway.fill("http://127.0.0.1:9");

  await page.getByRole("button", { name: "Test connection" }).click();
  await expect(page.locator(".toast.error", { hasText: "gateway ✗ unreachable" })).toBeVisible();

  // Mandatory cleanup — `test()` already wrote :9 to storage (see S-07), so
  // Reset alone is not enough; Save is what actually clears it.
  await page.getByRole("button", { name: "Reset to proxy" }).click();
  await expect(gateway).toHaveValue("/api");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.locator(".overlay")).toHaveCount(0);
  expect(await readStorage(page, ENDPOINT_KEY)).toEqual({
    gateway: "/api",
    accountService: "/account-api",
  });
});

/**
 * KNOWN BUG — SettingsModal.tsx:27.
 *
 * `test()` calls `saveEndpoints(cfg)` before probing ("probe reads from
 * storage"), so clicking "Test connection" writes the *unsaved* edit to
 * localStorage. Escaping the modal without pressing Save therefore still
 * leaves the tested endpoint persisted, and it survives a reload.
 *
 * This test asserts the CURRENT (buggy) behaviour so the suite stays green
 * while documenting the defect. WHEN THE BUG IS FIXED THIS TEST WILL FAIL —
 * that is intended: flip the assertion to `toBeNull()` (a cancelled test must
 * not touch storage) and delete this note.
 */
test("S-07: Test connection silently persists an unsaved endpoint [KNOWN BUG]", async ({
  page,
}) => {
  expect(await readStorage(page, ENDPOINT_KEY)).toBeNull();

  const { gateway } = await openSettings(page);
  await page.getByRole("button", { name: PRESET_DIRECT }).click();
  await expect(gateway).toHaveValue("http://127.0.0.1:3000");

  await page.getByRole("button", { name: "Test connection" }).click();
  await expect(page.locator(".toast", { hasText: /gateway/ })).toBeVisible();

  // Cancel — explicitly NOT pressing Save.
  await page.keyboard.press("Escape");
  await expect(page.locator(".overlay")).toHaveCount(0);

  // INTENDED: null (a cancelled edit must not be persisted).
  // ACTUAL: the tested endpoint was written to storage by the probe.
  expect(await readStorage(page, ENDPOINT_KEY)).toEqual({
    gateway: "http://127.0.0.1:3000",
    accountService: "/account-api",
  });

  // ...and it survives a reload, so the next session talks to :3000.
  await page.reload();
  expect(await readStorage(page, ENDPOINT_KEY)).toEqual({
    gateway: "http://127.0.0.1:3000",
    accountService: "/account-api",
  });

  /**
   * KNOWN BUG (2) — SettingsModal.tsx:41. `Reset to proxy` only sets component
   * state; it never writes storage. So after the above, a user who resets and
   * closes still leaves :3000 persisted.
   */
  const reopened = await openSettings(page);
  await page.getByRole("button", { name: "Reset to proxy" }).click();
  await expect(reopened.gateway).toHaveValue("/api");
  await page.keyboard.press("Escape");
  await expect(page.locator(".overlay")).toHaveCount(0);

  // INTENDED: `/api`. ACTUAL: Reset did not persist, so :3000 remains.
  expect(await readStorage(page, ENDPOINT_KEY)).toEqual({
    gateway: "http://127.0.0.1:3000",
    accountService: "/account-api",
  });
});
