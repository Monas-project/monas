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

  // No cleanup needed: probing no longer writes to storage, so a failed test
  // leaves the app on the endpoint it was already using.
  expect(await readStorage(page, ENDPOINT_KEY)).toBeNull();
  await page.keyboard.press("Escape");
  await expect(page.locator(".conn-item .dot.up")).toBeVisible();
});

/**
 * "Test connection" must probe the endpoint in the form WITHOUT committing it.
 *
 * It used to call `saveEndpoints(cfg)` first, because the probe could only read
 * the endpoint back out of storage — so merely testing an endpoint persisted
 * it, and a cancelled edit silently took effect. `probeGateway` now accepts the
 * candidate URL directly, so the probe no longer has a side effect.
 */
test("S-07: Test connection probes without persisting an unsaved endpoint", async ({
  page,
}) => {
  expect(await readStorage(page, ENDPOINT_KEY)).toBeNull();

  const { gateway } = await openSettings(page);
  await page.getByRole("button", { name: PRESET_DIRECT }).click();
  await expect(gateway).toHaveValue("http://127.0.0.1:3000");

  await page.getByRole("button", { name: "Test connection" }).click();
  await expect(page.locator(".toast", { hasText: /gateway/ })).toBeVisible();

  // Probing alone must not write anything.
  expect(await readStorage(page, ENDPOINT_KEY)).toBeNull();

  // Cancel — explicitly NOT pressing Save.
  await page.keyboard.press("Escape");
  await expect(page.locator(".overlay")).toHaveCount(0);

  expect(await readStorage(page, ENDPOINT_KEY)).toBeNull();

  // The app is still talking to the proxy, and that survives a reload.
  await page.reload();
  expect(await readStorage(page, ENDPOINT_KEY)).toBeNull();

  // Since a cancelled test leaves nothing behind, "Reset to proxy" has nothing
  // to undo — it only needs to restore the form, which Save then commits.
  const reopened = await openSettings(page);
  await page.getByRole("button", { name: PRESET_DIRECT }).click();
  await page.getByRole("button", { name: "Reset to proxy" }).click();
  await expect(reopened.gateway).toHaveValue("/api");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.locator(".overlay")).toHaveCount(0);

  expect(await readStorage(page, ENDPOINT_KEY)).toEqual({
    gateway: "/api",
    accountService: "/account-api",
  });
});

/**
 * The probe result must describe the endpoint being tested — including when
 * that endpoint is unusable from the browser.
 *
 * The "Local (direct :3000)" preset bypasses the Vite proxy, and monas-gateway
 * sends no CORS headers, so the browser blocks it. Testing it must therefore
 * report ✗ unreachable: a ✓ here would mean the probe is measuring something
 * other than the endpoint in the form (which is exactly what the old
 * save-then-probe implementation did).
 *
 * This is the regression guard for having decoupled probing from saving.
 */
test("S-07b: probing reports the tested endpoint, not the one in use", async ({ page }) => {
  // The proxy endpoint currently in effect is reachable...
  await expect(page.locator(".conn-item .dot.up")).toBeVisible();

  const { gateway } = await openSettings(page);
  await page.getByRole("button", { name: PRESET_DIRECT }).click();
  await expect(gateway).toHaveValue("http://127.0.0.1:3000");

  // ...but the direct endpoint is CORS-blocked from the browser, and the probe
  // must say so rather than reporting on the still-active proxy.
  await page.getByRole("button", { name: "Test connection" }).click();
  await expect(page.locator(".toast.error", { hasText: "gateway ✗ unreachable" })).toBeVisible();

  // The failed test left the app untouched: still unsaved, still on the proxy.
  expect(await readStorage(page, ENDPOINT_KEY)).toBeNull();
  await page.keyboard.press("Escape");
  await expect(page.locator(".conn-item .dot.up")).toBeVisible();
});
