import { test, expect, type Browser, type BrowserContext, type Locator, type Page } from "@playwright/test";
import {
  ENDPOINT_KEY,
  REGISTRY_KEY,
  createSigningAccount,
  freshApp,
  waitForGateway,
} from "../tests/helpers";

/**
 * Journey 4 — two devices share a file through the state node.
 *
 * "Device" here is a browser context bound to its own gateway + monas-account
 * pair: separate localStorage, separate CEK store, separate signing key. Alice
 * (device A, the default :3000/:4002 pair) creates and shares; Bob (device B,
 * the :3001/:4003 pair behind vite's /api2 proxy — see scripts/second-device.sh)
 * receives. Nothing crosses between them except what a person would paste into
 * a chat: Bob's public key one way, Alice's share package the other.
 *
 * Requirements: the usual stack (vite :5174, gateway :3000, account :4002)
 * plus `MONAS_STATE_NODE_URL=… ./scripts/second-device.sh`.
 */

const BASE = process.env.E2E_URL || "http://localhost:5174";
const nonce = `${Date.now().toString(36)}`;

async function expectToast(page: Page, text: string | RegExp, timeout = 120_000) {
  const toast = page.locator(".toast", { hasText: text }).first();
  await expect(toast).toBeVisible({ timeout });
  await expect(page.locator(".toast")).toHaveCount(0, { timeout: 15_000 });
}

function row(page: Page, name: string) {
  return page.locator(".row", { hasText: name }).first();
}

async function rowAction(page: Page, name: string, item: string) {
  await row(page, name).locator(".row-menu-wrap .icon-btn").click();
  await page.locator(".menu button", { hasText: item }).click();
}

/** The recipient-key textarea in the Share dialog. Not `textarea.input`: once a
 *  grant exists the dialog also shows the share package in a textarea. */
function pubKeyBox(modal: Locator) {
  return modal.locator(".field", { hasText: "Recipient public key" }).locator("textarea");
}

async function closeModal(page: Page) {
  await page.keyboard.press("Escape");
  await expect(page.locator(".overlay")).toHaveCount(0);
}

/** Point a browser context at the second gateway/account pair. Endpoints are
 *  read from localStorage at load, so set them and reload. */
async function useSecondDevice(page: Page) {
  await page.evaluate(
    ([key]) =>
      localStorage.setItem(key, JSON.stringify({ gateway: "/api2", accountService: "/account-api2" })),
    [ENDPOINT_KEY] as const,
  );
  await page.reload();
  await expect(page.locator(".topbar")).toBeVisible();
}

async function newDevice(browser: Browser): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ baseURL: BASE });
  // The journey exercises the real Copy buttons, so the clipboard must work.
  await context.grantPermissions(["clipboard-read", "clipboard-write"], { origin: BASE });
  const page = await context.newPage();
  await freshApp(page);
  return { context, page };
}

const readClipboard = (page: Page) => page.evaluate(() => navigator.clipboard.readText());

test("J-4: a file shared from one device opens on another via a pasted share package", async ({
  browser,
}) => {
  const name = `j4-${nonce}.txt`;
  const secret = `journey-4 secret ${nonce}`;

  const alice = await newDevice(browser);
  const bob = await newDevice(browser);
  await useSecondDevice(bob.page);

  await test.step("both devices have a signing account; they are different keys", async () => {
    await waitForGateway(alice.page);
    await createSigningAccount(alice.page, "alice-device");
    await waitForGateway(bob.page);
    await createSigningAccount(bob.page, "bob-device");
  });

  let bobPublicKey = "";
  await test.step("Bob copies his public key to send to Alice", async () => {
    await bob.page.locator(".account-chip").click();
    const modal = bob.page.locator(".modal");
    await modal
      .locator(".recipient-row", { hasText: "bob-device" })
      .getByRole("button", { name: "Copy public key" })
      .click();
    await expectToast(bob.page, "Public key of “bob-device” copied");
    bobPublicKey = await readClipboard(bob.page);
    expect(bobPublicKey.length).toBeGreaterThan(40);
    await closeModal(bob.page);
  });

  await test.step("Alice creates the file on the state node", async () => {
    await alice.page.getByRole("button", { name: "New file" }).click();
    const modal = alice.page.locator(".modal");
    await modal.locator("input.input").fill(name);
    await modal.locator("textarea.input").fill(secret);
    await alice.page.getByRole("button", { name: "Encrypt & create" }).click();
    await expectToast(alice.page, `“${name}” encrypted & created`);
    await expect(row(alice.page, name).locator(".badge.synced")).toBeVisible();
  });

  let sharePackage = "";
  await test.step("Alice shares to Bob's pasted key and copies the share package", async () => {
    await rowAction(alice.page, name, "Share");
    const modal = alice.page.locator(".modal");
    await modal.locator(".seg button", { hasText: "Paste public key" }).click();
    await pubKeyBox(modal).fill(bobPublicKey);
    await modal.locator(".field", { hasText: "Label (optional)" }).locator("input.input").fill("bob");
    await modal.getByRole("button", { name: "Wrap CEK & share" }).click();
    await expectToast(alice.page, "Shared with bob");

    // The package for the grant just added opens by itself…
    const pkgBox = modal.locator(".share-package textarea");
    await expect(pkgBox).toBeVisible();
    const shown = await pkgBox.inputValue();
    const parsed = JSON.parse(shown);
    expect(parsed.kind).toBe("monas-share");
    expect(parsed.name).toBe(name);
    expect(parsed.recipient_public_key).toBe(bobPublicKey);
    expect(parsed.remote_content_id).toBeTruthy();
    expect(parsed.key_envelope.ciphertext).toBeTruthy();
    // …and "Copy package" puts exactly that text on the clipboard.
    await modal
      .locator(".recipient-row", { hasText: "bob" })
      .getByRole("button", { name: "Copy package" })
      .click();
    await expectToast(alice.page, "Share package for bob copied");
    sharePackage = await readClipboard(alice.page);
    expect(sharePackage).toBe(shown);
    await closeModal(alice.page);
  });

  await test.step("Bob pastes the package, unwraps it, and reads the plaintext", async () => {
    await bob.page.getByRole("button", { name: "Import shared" }).click();
    const modal = bob.page.locator(".modal");
    const unwrap = modal.getByRole("button", { name: "Unwrap & add to my Drive" });
    await expect(unwrap).toBeDisabled();

    // Garbage is named for what it is, not swallowed.
    await modal.locator("textarea.input").fill("hello");
    await expect(modal.locator(".hint.error-text")).toContainText("not a share package");
    await expect(unwrap).toBeDisabled();

    await modal.locator("textarea.input").fill(sharePackage);
    await expect(modal.locator(".package-summary")).toContainText(name);
    await expect(modal.locator(".package-summary")).toContainText("Addressed to your identity bob-device");
    await unwrap.click();
    await expectToast(bob.page, `“${name}” unwrapped and added to your Drive`);

    // The import opens the preview straight away, with the decrypted text.
    const preview = bob.page.locator(".modal");
    await expect(preview.locator(".preview-box").first()).toHaveText(secret);
    await expect(preview).toContainText("Shared with you by");
    await closeModal(bob.page);

    const r = row(bob.page, name);
    await expect(r.locator(".badge.received")).toBeVisible();
    // Bob holds an envelope, not the file: no Edit, no Share, no network delete.
    await r.locator(".row-menu-wrap .icon-btn").click();
    const menu = bob.page.locator(".menu");
    await expect(menu.locator("button", { hasText: "Open / preview" })).toBeVisible();
    await expect(menu.locator("button", { hasText: "Remove from my Drive" })).toBeVisible();
    await expect(menu.locator("button", { hasText: "Edit contents" })).toHaveCount(0);
    await expect(menu.locator("button", { hasText: "Share" })).toHaveCount(0);
    await bob.page.keyboard.press("Escape");
  });

  await test.step("Bob can reopen it later from the kept envelope, across a reload", async () => {
    await bob.page.reload();
    await expect(bob.page.locator(".topbar")).toBeVisible();
    await rowAction(bob.page, name, "Open / preview");
    await expect(bob.page.locator(".modal .preview-box").first()).toHaveText(secret);
    await closeModal(bob.page);
  });

  let rewrapped = "";
  await test.step("Alice revokes a third party; Bob's envelope is re-wrapped and re-sent", async () => {
    // A throwaway P-256 key stands in for a third recipient.
    const carolKey = await alice.page.evaluate(async () => {
      const res = await fetch("/api/keypair", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ key_type: "secp256r1" }),
      });
      const body = (await res.json()) as { data?: { public_key?: string } };
      if (!body.data?.public_key) throw new Error("keypair failed");
      return body.data.public_key;
    });
    await rowAction(alice.page, name, "Share");
    const modal = alice.page.locator(".modal");
    await modal.locator(".seg button", { hasText: "Paste public key" }).click();
    await pubKeyBox(modal).fill(carolKey);
    await modal.locator(".field", { hasText: "Label (optional)" }).locator("input.input").fill("carol");
    await modal.getByRole("button", { name: "Wrap CEK & share" }).click();
    await expectToast(alice.page, "Shared with carol");

    await modal.locator(".recipient-row", { hasText: "carol" }).getByRole("button", { name: "Revoke" }).click();
    await expectToast(alice.page, "Access revoked & content re-encrypted");
    const bobRow = modal.locator(".recipient-row", { hasText: "bob" });
    await expect(bobRow).toContainText("re-wrapped after a revoke");

    // The re-wrapped package is what the dialog now shows for bob.
    const pkgBox = modal.locator(".share-package textarea");
    await expect(modal.locator(".share-package label")).toContainText("re-wrapped");
    rewrapped = await pkgBox.inputValue();
    const before = JSON.parse(sharePackage);
    const after = JSON.parse(rewrapped);
    expect(after.key_envelope.key_epoch).toBeGreaterThan(before.key_envelope.key_epoch);
    await closeModal(alice.page);
  });

  await test.step("Bob imports the re-wrapped package: same entry, still readable", async () => {
    await bob.page.getByRole("button", { name: "Import shared" }).click();
    const modal = bob.page.locator(".modal");
    await modal.locator("textarea.input").fill(rewrapped);
    await modal.getByRole("button", { name: "Unwrap & add to my Drive" }).click();
    await expectToast(bob.page, `“${name}” unwrapped and added to your Drive`);
    await expect(bob.page.locator(".modal .preview-box").first()).toHaveText(secret);
    await closeModal(bob.page);
    await expect(bob.page.locator(".row", { hasText: name })).toHaveCount(1);
  });

  await test.step("the pre-rotation package is refused as stale", async () => {
    await bob.page.getByRole("button", { name: "Import shared" }).click();
    const modal = bob.page.locator(".modal");
    await modal.locator("textarea.input").fill(sharePackage);
    await modal.getByRole("button", { name: "Unwrap & add to my Drive" }).click();
    await expectToast(bob.page, `Could not import “${name}”`);
    // The pipeline names the reason: an older key_epoch than the one pinned.
    await expect(bob.page.locator(".run").first()).toContainText(/stale key envelope|key_epoch/i, {
      timeout: 30_000,
    });
    await closeModal(bob.page);
  });

  await test.step("cleanup: Alice deletes the file, Bob removes his copy", async () => {
    await rowAction(alice.page, name, "Delete");
    await alice.page.locator(".modal .btn.danger", { hasText: "Delete" }).click();
    await expectToast(alice.page, `“${name}” deleted`);

    await rowAction(bob.page, name, "Remove from my Drive");
    await expect(bob.page.locator(".modal")).toContainText("the owner's file and its Content Network are untouched");
    await bob.page.locator(".modal .btn.danger", { hasText: "Remove" }).click();
    await expectToast(bob.page, /removed from your Drive/);
    await expect(bob.page.locator(".row", { hasText: name })).toHaveCount(0);
    const registry = (await bob.page.evaluate((k) => JSON.parse(localStorage.getItem(k) || "[]"), REGISTRY_KEY)) as unknown[];
    expect(registry).toHaveLength(0);
  });

  await alice.context.close();
  await bob.context.close();
});
