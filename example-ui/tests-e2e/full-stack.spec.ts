import { test, expect, type Page } from "@playwright/test";
import { freshApp, waitForGateway, createSigningAccount } from "../tests/helpers";

/**
 * Real-stack user journeys: vite → monas-gateway → monas-account → the live
 * state-node network. Unlike `tests/` (which seeds localStorage and never
 * mutates content), every step here pays the real cost — encrypt → CID →
 * state-node round trip — so this is the suite that proves a fresh user can
 * actually manage content on the public nodes.
 *
 * The three journeys are independent (each starts from a cleared browser and
 * its own signing account) but internally sequential, expressed as
 * `test.step`s. Content names carry a per-run nonce so reruns never collide
 * with what earlier runs left on the network.
 *
 * Requirements: the stack from example-ui/README.md — vite :5174, gateway
 * :3000 (pointed at a reachable state node), monas-account :4002.
 */

const nonce = `${Date.now().toString(36)}`;

/** Toasts auto-dismiss after ~3s, but protocol ops can take a while to emit
 *  one; wait generously for the toast to APPEAR, then for it to go away so it
 *  cannot bleed into the next step's assertions. */
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

/** Create a text file through the New file dialog and wait for the full
 *  create pipeline (encrypt → CID → state-node registration) to finish. */
async function createTextFile(page: Page, name: string, text: string) {
  await page.getByRole("button", { name: "New file" }).click();
  const modal = page.locator(".modal");
  await modal.locator("input.input").fill(name);
  await modal.locator("textarea.input").fill(text);
  await page.getByRole("button", { name: "Encrypt & create" }).click();
  await expectToast(page, `“${name}” encrypted & created`);
  // Synced badge = the state node accepted the content network.
  await expect(row(page, name).locator(".badge.synced")).toBeVisible();
}

/** The last pipeline run must have completed — no silently-failed steps. */
async function expectLastRunComplete(page: Page) {
  await expect(
    page.locator(".run").first().locator(".run-status"),
  ).toHaveText("complete", { timeout: 120_000 });
}

test.beforeEach(async ({ page }) => {
  await freshApp(page);
  await waitForGateway(page);
});

// ---------------------------------------------------------------------------
// Journey 1 — content lifecycle: create → read (4 ways) → edit → history →
// old-version read → persistence across reload → delete.
// ---------------------------------------------------------------------------
test("J-1: a fresh user can create, read, verify, edit and delete content on the state node", async ({
  page,
}) => {
  const name = `j1-${nonce}.txt`;
  const v1 = `journey-1 first version ${nonce}`;
  const v2 = `journey-1 second version ${nonce}`;

  await test.step("create signing account", async () => {
    await createSigningAccount(page, "j1-main");
  });

  await test.step("create an encrypted file on the state node", async () => {
    await createTextFile(page, name, v1);
    await expectLastRunComplete(page);
  });

  await test.step("preview decrypts the plaintext and loads state-node facts", async () => {
    await rowAction(page, name, "Open / preview");
    const modal = page.locator(".modal");
    await expect(modal.locator(".preview-box").first()).toHaveText(v1);
    // Auto-loaded from the state node on open. A create writes two versions,
    // not one: the content itself, then the owner's access policy. The suite
    // used to expect one because versions written in the same second collapsed
    // onto a single CID — the sync bug fixed in #70.
    await expect(modal).toContainText("latest version");
    await expect(modal.locator(".state-history .ver")).toHaveCount(2, {
      timeout: 60_000,
    });
    await expect(modal.locator(".state-history .ver.current")).toHaveCount(1);
  });

  await test.step("integrity of the local plaintext verifies against the network", async () => {
    const modal = page.locator(".modal");
    await modal.getByRole("button", { name: "Verify integrity" }).click();
    await expect(modal.locator(".badge.synced", { hasText: "valid" })).toBeVisible({
      timeout: 60_000,
    });
    await expect(modal.locator(".badge.invalid")).toHaveCount(0);
  });

  await test.step("verified read pulls the ciphertext off the state node and re-derives the plaintext", async () => {
    const modal = page.locator(".modal");
    await modal.getByRole("button", { name: "Read from state-node" }).click();
    await expect(modal.locator(".badge.synced", { hasText: "verified" })).toBeVisible({
      timeout: 120_000,
    });
    await expect(modal.locator(".preview-box").nth(1)).toHaveText(v1);
    await page.keyboard.press("Escape");
    await expect(page.locator(".overlay")).toHaveCount(0);
  });

  await test.step("edit re-encrypts, bumps the version and can rename via the editor", async () => {
    await rowAction(page, name, "Edit contents");
    const editor = page.locator(".modal");
    await expect(editor.locator("textarea.input")).toHaveValue(v1, {
      timeout: 60_000,
    });
    await editor.locator("textarea.input").fill(v2);
    await page.getByRole("button", { name: "Re-encrypt & save" }).click();
    await expectToast(page, `“${name}” updated`);
    await expectLastRunComplete(page);
  });

  await test.step("the edit adds a version, and the head still verifies", async () => {
    await rowAction(page, name, "Open / preview");
    const modal = page.locator(".modal");
    await expect(modal.locator(".preview-box").first()).toHaveText(v2);
    // Two from the create, plus this edit.
    await expect(modal.locator(".state-history .ver")).toHaveCount(3, {
      timeout: 60_000,
    });
    await expect(modal.locator(".state-history .ver.current")).toHaveCount(1);

    // The verified read covers the newest version only: the check re-derives
    // the plaintext and compares it against the local content id, and the
    // registry holds only the current one. Reading an older version here would
    // fail the very comparison the control exists to demonstrate.
    await modal.getByRole("button", { name: "Read from state-node" }).click();
    await expect(modal.locator(".badge.synced", { hasText: "verified" })).toBeVisible({
      timeout: 120_000,
    });
    await expect(modal.locator(".preview-box").nth(1)).toHaveText(v2);
    await page.keyboard.press("Escape");
    await expect(page.locator(".overlay")).toHaveCount(0);
  });

  await test.step("a reload keeps the registry and the content stays readable", async () => {
    await page.reload();
    await waitForGateway(page);
    await expect(row(page, name)).toBeVisible();
    await rowAction(page, name, "Open / preview");
    await expect(page.locator(".modal .preview-box").first()).toHaveText(v2, {
      timeout: 120_000,
    });
    await page.keyboard.press("Escape");
    await expect(page.locator(".overlay")).toHaveCount(0);
  });

  await test.step("delete tombstones the content network and clears the row", async () => {
    await rowAction(page, name, "Delete");
    await page.locator(".modal .btn.danger", { hasText: "Delete" }).click();
    await expectToast(page, `“${name}” deleted`);
    await expect(page.locator(".row", { hasText: name })).toHaveCount(0);
  });
});

// ---------------------------------------------------------------------------
// Journey 2 — sharing lifecycle: share to a local identity (with the HPKE
// round-trip proof), share to a pasted external key, revoke one recipient and
// confirm the survivor's envelope is reissued under the new epoch.
// ---------------------------------------------------------------------------
test("J-2: sharing, external-key sharing, and revoke with envelope reissue", async ({
  page,
}) => {
  const name = `j2-${nonce}.txt`;

  await test.step("create signing account and a recipient identity", async () => {
    await createSigningAccount(page, "j2-main");
    await page.locator(".account-chip").click();
    await page.getByPlaceholder("e.g. me, alice, bob").fill("bob");
    await page.locator('input[type="checkbox"]').first().uncheck();
    await page.locator(".btn.primary", { hasText: "Create identity" }).click();
    await expect(page.locator(".modal")).toContainText("bob");
    // The signing account must stay active — creating bob must not switch.
    await page.keyboard.press("Escape");
    await expect(page.locator(".overlay")).toHaveCount(0);
    await expect(page.locator(".account-chip")).toContainText("j2-main");
  });

  await test.step("create the file to share", async () => {
    await createTextFile(page, name, `journey-2 secret ${nonce}`);
  });

  await test.step("share with bob, proving the HPKE round trip as the recipient", async () => {
    await rowAction(page, name, "Share");
    const modal = page.locator(".modal");
    await modal.locator("select.select").selectOption({ label: "bob · secp256r1" });
    // "Prove access" is off by default, and this journey leaves it off: it
    // decrypts as the recipient, which replaces the stored CEK for this content
    // with the recipient's copy. The revoke later in this journey rotates the
    // CEK, and the owner would then be holding a stale one. The HPKE round trip
    // itself is covered by the pasted-key step below.
    await expect(modal.locator('input[type="checkbox"]')).not.toBeChecked();
    await modal.getByRole("button", { name: "Wrap CEK & share" }).click();
    await expectToast(page, "Shared with bob");
    await expectLastRunComplete(page);

    await expect(modal.locator(".recipient-row", { hasText: "bob" })).toContainText(
      /KeyId .+ · epoch \d+/,
    );
    await expect(row(page, name).locator(".badge.shared")).toContainText("1");
  });

  await test.step("share to a pasted public key (external recipient)", async () => {
    // A P-256 keypair obtained the way an external user would hand one over —
    // minted by the gateway, only its PUBLIC half is pasted into the form.
    const pubKey = await page.evaluate(async () => {
      const res = await fetch("/api/keypair", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ key_type: "secp256r1" }),
      });
      if (!res.ok) throw new Error(`keypair failed: ${res.status}`);
      // The gateway wraps every reply in the SDK envelope
      // ({ success, data, trace_id }); the key lives under `data`.
      const body = (await res.json()) as { data?: { public_key?: string } };
      const key = body.data?.public_key;
      if (!key) throw new Error(`keypair reply had no public_key: ${JSON.stringify(body)}`);
      return key;
    });

    const modal = page.locator(".modal");
    await modal.locator(".seg button", { hasText: "Paste public key" }).click();
    await modal.locator("textarea.input").fill(pubKey);
    await modal.locator(".field", { hasText: "Label (optional)" }).locator("input.input").fill("carol-ext");
    await modal.getByRole("button", { name: "Wrap CEK & share" }).click();
    await expectToast(page, "Shared with carol-ext");
    await expect(modal.locator(".recipient-row")).toHaveCount(2);
    await expect(row(page, name).locator(".badge.shared")).toContainText("2");
  });

  await test.step("revoking carol rotates the CEK and reissues bob's envelope", async () => {
    const modal = page.locator(".modal");
    const bobEpoch = await modal
      .locator(".recipient-row", { hasText: "bob" })
      .locator(".mono")
      .innerText();

    await modal
      .locator(".recipient-row", { hasText: "carol-ext" })
      .getByRole("button", { name: "Revoke" })
      .click();
    await expectToast(page, "Access revoked & content re-encrypted");
    await expectLastRunComplete(page);

    await expect(modal.locator(".recipient-row")).toHaveCount(1);
    const bobRow = modal.locator(".recipient-row", { hasText: "bob" });
    // The survivor's envelope was swapped for one under the new epoch.
    await expect(bobRow).toContainText("re-wrapped after a revoke");
    const bobEpochAfter = await bobRow.locator(".mono").innerText();
    expect(bobEpochAfter).not.toBe(bobEpoch);

    await page.keyboard.press("Escape");
    await expect(page.locator(".overlay")).toHaveCount(0);
    await expect(row(page, name).locator(".badge.shared")).toContainText("1");
  });

  await test.step("the owner can still read after the rotation", async () => {
    await rowAction(page, name, "Open / preview");
    const modal = page.locator(".modal");
    await expect(modal.locator(".preview-box").first()).toHaveText(
      `journey-2 secret ${nonce}`,
    );
    await modal.getByRole("button", { name: "Read from state-node" }).click();
    await expect(modal.locator(".badge.synced", { hasText: "verified" })).toBeVisible({
      timeout: 120_000,
    });
    await page.keyboard.press("Escape");
    await expect(page.locator(".overlay")).toHaveCount(0);
  });

  await test.step("cleanup: delete the shared file", async () => {
    await rowAction(page, name, "Delete");
    await page.locator(".modal .btn.danger", { hasText: "Delete" }).click();
    await expectToast(page, `“${name}” deleted`);
    await expect(page.locator(".row", { hasText: name })).toHaveCount(0);
  });
});

// ---------------------------------------------------------------------------
// Journey 3 — folders, binary upload, sidebar filters, and cascade delete.
// ---------------------------------------------------------------------------
test("J-3: folders, image upload, filter views and cascading folder delete", async ({
  page,
}) => {
  const folder = `j3-docs-${nonce}`;
  const image = `j3-pixel-${nonce}.png`;
  // Smallest valid PNG (1×1, red). Kept tiny so the crypto round trip is fast.
  const PNG_B64 =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/q842iQAAAABJRU5ErkJggg==";

  await test.step("create signing account", async () => {
    await createSigningAccount(page, "j3-main");
  });

  await test.step("create a folder and navigate into it", async () => {
    await page.getByRole("button", { name: "New folder" }).click();
    await page.locator(".modal input.input").fill(folder);
    await page.getByRole("button", { name: "Create" }).click();
    await expectToast(page, `Folder “${folder}” created`, 15_000);
    await row(page, folder).dblclick();
    await expect(page.locator(".crumb.last")).toHaveText(folder);
  });

  await test.step("upload an image into the folder", async () => {
    const chooserPromise = page.waitForEvent("filechooser");
    await page.getByRole("button", { name: "Upload" }).click();
    const chooser = await chooserPromise;
    await chooser.setFiles({
      name: image,
      mimeType: "image/png",
      buffer: Buffer.from(PNG_B64, "base64"),
    });
    await expectToast(page, `“${image}” encrypted & created`);
    await expect(row(page, image).locator(".badge.synced")).toBeVisible();
  });

  await test.step("the image previews as an image, decrypted", async () => {
    await rowAction(page, image, "Open / preview");
    const img = page.locator(".modal .preview-img");
    await expect(img).toBeVisible();
    // The data: URI must decode to a real image, not garbage.
    const size = await img.evaluate(
      (el: HTMLImageElement) => `${el.naturalWidth}x${el.naturalHeight}`,
    );
    expect(size).toBe("1x1");
    await page.keyboard.press("Escape");
    await expect(page.locator(".overlay")).toHaveCount(0);
  });

  await test.step("sidebar filter counts reflect reality", async () => {
    // 1 file total, synced, unshared.
    await expect(
      page.locator(".nav-item", { hasText: "Encrypted files" }).locator(".mono"),
    ).toHaveText("1");
    await expect(
      page.locator(".nav-item", { hasText: "On state-node" }).locator(".mono"),
    ).toHaveText("1");
    await expect(
      page.locator(".nav-item", { hasText: "Shared" }).locator(".mono"),
    ).toHaveText("0");

    // The synced view lists the image even though we're outside its folder.
    await page.locator(".nav-item", { hasText: "On state-node" }).click();
    await expect(page.locator(".crumb.last")).toHaveText("On state-node");
    await expect(row(page, image)).toBeVisible();
    await page.locator(".nav-item", { hasText: "My Drive" }).click();
  });

  await test.step("renaming the folder keeps its contents reachable", async () => {
    const renamed = `${folder}-renamed`;
    await rowAction(page, folder, "Rename");
    await page.locator(".modal input.input").fill(renamed);
    await page.getByRole("button", { name: "Rename" }).click();
    await expectToast(page, "Folder renamed", 15_000);
    await row(page, renamed).dblclick();
    await expect(page.locator(".crumb.last")).toHaveText(renamed);
    await expect(row(page, image)).toBeVisible();
    await page.locator(".nav-item", { hasText: "My Drive" }).click();
  });

  await test.step("deleting the folder deletes its encrypted contents too", async () => {
    await rowAction(page, `${folder}-renamed`, "Delete");
    await page.locator(".modal .btn.danger", { hasText: "Delete" }).click();
    await expectToast(page, `Folder “${folder}-renamed” deleted`);
    await expect(page.locator(".row")).toHaveCount(0);
    await expect(
      page.locator(".nav-item", { hasText: "Encrypted files" }).locator(".mono"),
    ).toHaveText("0");
  });
});
