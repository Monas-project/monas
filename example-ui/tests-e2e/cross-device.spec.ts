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
 * The two gateways should point at *different* state nodes (node1 / node2) so
 * that Bob's reads prove replication as well as delegation: Bob reads the
 * version Alice shared, then the version she wrote afterwards, from his own
 * node with the delegated token in the package. A revoke voids that token;
 * the re-wrapped package carries a fresh one.
 *
 * Requirements: the usual stack (vite :5174, gateway :3000, account :4002)
 * plus `MONAS_STATE_NODE_URL=https://node2.… ./scripts/second-device.sh`.
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

test("J-4: a file shared from one device opens, reads and is edited on another via a pasted share package", async ({
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
  await test.step("Alice shares (read + write) to Bob's pasted key and copies the share package", async () => {
    await rowAction(alice.page, name, "Share");
    const modal = alice.page.locator(".modal");
    await modal.locator(".seg button", { hasText: "Paste public key" }).click();
    await pubKeyBox(modal).fill(bobPublicKey);
    await modal.locator(".field", { hasText: "Label (optional)" }).locator("input.input").fill("bob");
    await modal.locator(".field", { hasText: "Permission" }).locator(".seg button", { hasText: "read + write" }).click();
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
    expect(parsed.permissions).toEqual(["read", "write"]);
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
    // Bob holds an envelope plus a write token, not the file: he can edit
    // (straight to Alice's Content Network) but not re-share or delete it.
    await r.locator(".row-menu-wrap .icon-btn").click();
    const menu = bob.page.locator(".menu");
    await expect(menu.locator("button", { hasText: "Open / preview" })).toBeVisible();
    await expect(menu.locator("button", { hasText: "Edit contents" })).toBeVisible();
    await expect(menu.locator("button", { hasText: "Remove from my Drive" })).toBeVisible();
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

  /** Open Bob's copy and read it back from HIS state node with the delegated
   *  token; returns the plaintext the verified read produced. */
  async function bobReadsFromStateNode(): Promise<string> {
    await rowAction(bob.page, name, "Open / preview");
    const modal = bob.page.locator(".modal");
    await expect(modal).toContainText("Reading as a recipient with the delegated token");
    // latest + history load with the token too
    await expect(modal.locator(".kv", { hasText: "latest version" }).locator("b.mono")).toBeVisible({
      timeout: 60_000,
    });
    await modal.getByRole("button", { name: "Read from state-node" }).click();
    await expect(modal.locator(".badge.synced", { hasText: "verified" })).toBeVisible({
      timeout: 120_000,
    });
    const text = await modal.locator(".preview-box").nth(1).innerText();
    await closeModal(bob.page);
    return text;
  }

  await test.step("Bob reads the shared version back from his own state node", async () => {
    expect(await bobReadsFromStateNode()).toBe(secret);
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
    // The revoke voided every earlier token, Bob's included; the re-wrapped
    // package must carry a fresh one, issued after the invalidation boundary.
    expect(after.delegated_access.jti).not.toBe(before.delegated_access.jti);
    expect(after.delegated_access.issued_at).toBeGreaterThan(before.delegated_access.issued_at);
    await closeModal(alice.page);
  });

  await test.step("with the old token Bob's state-node read is refused", async () => {
    await rowAction(bob.page, name, "Open / preview");
    const modal = bob.page.locator(".modal");
    await modal.getByRole("button", { name: "Read from state-node" }).click();
    await expect(modal.locator(".inline-err").first()).toBeVisible({ timeout: 120_000 });
    await expect(modal.locator(".badge.synced", { hasText: "verified" })).toHaveCount(0);
    await closeModal(bob.page);
  });

  await test.step("Bob imports the re-wrapped package: same entry, readable again from the state node", async () => {
    await bob.page.getByRole("button", { name: "Import shared" }).click();
    const modal = bob.page.locator(".modal");
    await modal.locator("textarea.input").fill(rewrapped);
    await modal.getByRole("button", { name: "Unwrap & add to my Drive" }).click();
    await expectToast(bob.page, `“${name}” unwrapped and added to your Drive`);
    // The re-wrapped envelope carries the re-encrypted current version.
    await expect(bob.page.locator(".modal .preview-box").first()).toHaveText(secret);
    await closeModal(bob.page);
    await expect(bob.page.locator(".row", { hasText: name })).toHaveCount(1);
    // …and the fresh token reads from the state node again.
    expect(await bobReadsFromStateNode()).toBe(secret);
  });

  const secret2 = `journey-4 second draft ${nonce}`;
  await test.step("Alice edits; Bob reads the newer version with the same token and CEK", async () => {
    await rowAction(alice.page, name, "Edit contents");
    const editor = alice.page.locator(".modal");
    await expect(editor.locator("textarea.input")).toHaveValue(secret, { timeout: 60_000 });
    await editor.locator("textarea.input").fill(secret2);
    await alice.page.getByRole("button", { name: "Re-encrypt & save" }).click();
    await expectToast(alice.page, `“${name}” updated`);

    // Bob's envelope still opens the version he was given…
    await rowAction(bob.page, name, "Open / preview");
    const preview = bob.page.locator(".modal");
    await expect(preview.locator(".preview-box").first()).toHaveText(secret);
    // …and the state node hands him the new one, flagged as newer than shared.
    await preview.getByRole("button", { name: "Read from state-node" }).click();
    await expect(preview.locator(".badge.synced", { hasText: "verified" })).toBeVisible({
      timeout: 120_000,
    });
    await expect(preview.locator(".preview-box").nth(1)).toHaveText(secret2);
    await expect(preview.locator(".kv", { hasText: "newer than shared" })).toBeVisible();
    await closeModal(bob.page);
  });

  const secret3 = `journey-4 bob's draft ${nonce}`;
  await test.step("Bob edits with the delegated token; Alice's verified read sees his version", async () => {
    // The editor loads the owner's newest version, not the one the envelope
    // carried.
    await rowAction(bob.page, name, "Edit contents");
    const editor = bob.page.locator(".modal");
    await expect(editor.locator("textarea.input")).toHaveValue(secret2, { timeout: 120_000 });
    await editor.locator("textarea.input").fill(secret3);
    await bob.page.getByRole("button", { name: "Re-encrypt & save" }).click();
    await expectToast(bob.page, `“${name}” updated on the owner's Content Network`);
    await expect(bob.page.locator(".run").first()).toContainText("grants write");

    // Bob's own state node now serves the version he wrote…
    await rowAction(bob.page, name, "Open / preview");
    const preview = bob.page.locator(".modal");
    await expect(preview).toContainText("You have since written a newer version");
    await preview.getByRole("button", { name: "Read from state-node" }).click();
    await expect(preview.locator(".badge.synced", { hasText: "verified" })).toBeVisible({
      timeout: 120_000,
    });
    await expect(preview.locator(".preview-box").nth(1)).toHaveText(secret3);
    await expect(preview.locator(".kv", { hasText: "your edit" })).toBeVisible();
    await closeModal(bob.page);

    // …and so does Alice's, flagged against her local copy, which still holds
    // her own last save.
    await rowAction(alice.page, name, "Open / preview");
    const aliceView = alice.page.locator(".modal");
    await expect(aliceView.locator(".preview-box").first()).toHaveText(secret2);
    await aliceView.getByRole("button", { name: "Read from state-node" }).click();
    await expect(aliceView.locator(".badge.synced", { hasText: "verified" })).toBeVisible({
      timeout: 120_000,
    });
    await expect(aliceView.locator(".preview-box").nth(1)).toHaveText(secret3);
    await expect(aliceView.locator(".kv", { hasText: "newer than your copy" })).toBeVisible();
    await closeModal(alice.page);

    // Opening the editor pulls Bob's version into her local record first, so
    // her next save (or a revoke's re-encryption) builds on it, not over it.
    await rowAction(alice.page, name, "Edit contents");
    await expectToast(alice.page, /Pulled a newer version/);
    await expect(alice.page.locator(".modal textarea.input")).toHaveValue(secret3, {
      timeout: 120_000,
    });
    await closeModal(alice.page);
    await rowAction(alice.page, name, "Open / preview");
    await expect(alice.page.locator(".modal .preview-box").first()).toHaveText(secret3);
    await closeModal(alice.page);
  });

  // The epoch record lives in the SDK's sender pin, keyed by the Content
  // Network — not by the owner's content id, which the edit above has just
  // changed. A pre-rotation package naming the OLD id must still be refused.
  await test.step("the pre-rotation package is refused as stale, even after the edit", async () => {
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

  await test.step("Alice revokes Bob; his write is refused and Alice's copy is unchanged", async () => {
    await rowAction(alice.page, name, "Share");
    const modal = alice.page.locator(".modal");
    await modal.locator(".recipient-row", { hasText: "bob" }).getByRole("button", { name: "Revoke" }).click();
    await expectToast(alice.page, "Access revoked & content re-encrypted");
    await closeModal(alice.page);

    // The voided token cannot even load the current version for editing; the
    // editor opens empty and the save is refused by the state node.
    await rowAction(bob.page, name, "Edit contents");
    await expectToast(bob.page, /Could not load contents/);
    const editor = bob.page.locator(".modal");
    await editor.locator("textarea.input").fill("this must not land");
    await bob.page.getByRole("button", { name: "Re-encrypt & save" }).click();
    await expectToast(bob.page, "Update failed");
    await expect(bob.page.locator(".run").first()).toContainText(/HTTP 40[13]/);

    // Alice's node still serves Bob's earlier (authorised) version.
    await rowAction(alice.page, name, "Open / preview");
    const view = alice.page.locator(".modal");
    await view.getByRole("button", { name: "Read from state-node" }).click();
    await expect(view.locator(".badge.synced", { hasText: "verified" })).toBeVisible({
      timeout: 120_000,
    });
    await expect(view.locator(".preview-box").nth(1)).toHaveText(secret3);
    await closeModal(alice.page);
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
