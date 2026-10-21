import { test, expect, type Page } from "@playwright/test";
import type { Entry, Identity, ShareGrant } from "../src/types";

// Share-dialog regressions reported from a group session:
//  1. the package of an earlier share reopened by itself every time the
//     dialog opened, and read like a field asking for input;
//  2. pasting a key that already has a share only offered "Wrap CEK & share"
//     (which the SDK refuses with AlreadyShared) — no revoke / change there;
//  3. read ⇄ write needed a revoke followed by a fresh share.
// Only HTTP is simulated; App, ShareModal, flows and API adapters run as-is.

const owner: Identity = { label: "owner", keyType: "secp256r1", publicKeyB64Url: "public-owner", privateKeyB64Url: "fake-private-owner", isSigningAccount: true };
const envelope = { enc: "fixture", wrapped_cek: "fixture", ciphertext: "fixture-v1", key_epoch: 0 };
const token = (jti: string) => ({ delegated_token: `token-${jti}`, issued_at: 10, expires_at: 4102444800, jti });
const grant = (who: string, permissions: ("read" | "write")[]): ShareGrant => ({
  recipientPublicKeyB64Url: `public-${who}`, recipientLabel: who, permissions, senderKeyId: "owner-kid",
  recipientKeyId: `kid-${who}`, senderPublicKeyB64Url: "public-owner", envelope, delegatedAccess: token(`${who}-1`), grantedAt: 1,
});
const fileEntry = (shares: ShareGrant[]): Entry => ({
  id: "owner-file", kind: "file", name: "owner.txt", parentPath: "/", sizeBytes: 2, mimeType: "text/plain",
  createdAt: 1, updatedAt: 1, localContentId: "plain-v1", remoteContentId: "network", syncedToStateNode: true,
  versionCount: 1, shares,
} as Entry);

async function boot(page: Page, entries: Entry[]) {
  const requests: { path: string; body: any }[] = [];
  const unexpected: string[] = [];
  await page.addInitScript(({ entries, owner }) => {
    if (sessionStorage.getItem("seeded")) return;
    sessionStorage.setItem("seeded", "yes");
    localStorage.setItem("monas.identities.v2", JSON.stringify({ identities: [owner], activeLabel: "owner" }));
    localStorage.setItem("monas.registry.v3", JSON.stringify(entries));
    localStorage.setItem("monas.endpoints.v2", JSON.stringify({ gateway: "/api" }));
  }, { entries, owner });
  await page.route("**/*", async route => {
    const req = route.request();
    const url = new URL(req.url());
    if (url.origin !== "http://127.0.0.1:5198") { unexpected.push(req.url()); return route.abort(); }
    if (!url.pathname.startsWith("/api")) return route.continue();
    const path = url.pathname;
    const body = req.postDataJSON();
    requests.push({ path, body });
    let data: unknown;
    if (path === "/api/health") return route.fulfill({ status: 200, body: "" });
    if (path === "/api/state/read") data = { content_id: "network", local_content_id: "plain-v1", version: "v1", content: "VjE" };
    else if (path === "/api/share") {
      const who = String(body.recipient_public_key).replace("public-", "");
      data = { content_id: "plain-v1", recipient_public_key: body.recipient_public_key, sender_public_key: "public-owner", sender_key_id: "owner-kid", recipient_key_id: `kid-${who}`, key_envelope: envelope, delegated_access: token(`${who}-1`) };
    } else if (path === "/api/share/permission") {
      const who = String(body.recipient_public_key).replace("public-", "");
      const downgrade = !body.permissions.includes("write");
      data = {
        content_id: "plain-v1", recipient_public_key: body.recipient_public_key, recipient_key_id: `kid-${who}`,
        permissions: downgrade ? ["read"] : ["write"], delegated_access: token(`${who}-2`),
        ...(downgrade ? { token_invalidated_at: 50, reissued_tokens: [{ recipient_key_id: "kid-carol", delegated_access: token("carol-2") }] } : {}),
      };
    } else { unexpected.push(`${req.method()} ${path}`); return route.fulfill({ status: 500, body: "Unexpected test request" }); }
    return route.fulfill({ json: { success: true, data, trace_id: "test" } });
  });
  await page.goto("/");
  return { requests, unexpected };
}

async function openShare(page: Page) {
  await page.locator(".row-menu-wrap > button").click();
  await page.locator(".menu").getByRole("button", { name: "Share", exact: true }).click();
  await expect(page.getByRole("heading", { name: /^Share/ })).toBeVisible();
}
const stored = (page: Page) => page.evaluate(() => JSON.parse(localStorage.getItem("monas.registry.v3")!)[0].shares as ShareGrant[]);

test("the package shows after sharing, and does not come back when the dialog is reopened", async ({ page }) => {
  const gateway = await boot(page, [fileEntry([])]);
  await openShare(page);
  await page.getByPlaceholder("P-256 public key, base64url (from the gateway /keypair)").fill("public-bob");
  await page.getByRole("button", { name: "Wrap CEK & share" }).click();
  await expect(page.locator(".share-package textarea")).toBeVisible();
  // the form is cleared so the next paste starts fresh
  await expect(page.getByPlaceholder("P-256 public key, base64url (from the gateway /keypair)")).toHaveValue("");

  await page.getByRole("button", { name: "Close", exact: true }).click();
  await openShare(page);
  await expect(page.locator(".recipient-row")).toHaveCount(1);
  await expect(page.locator(".share-package")).toHaveCount(0);
  expect(gateway.unexpected).toEqual([]);
});

test("pasting a key that already has a share offers revoke and permission change, not a new share", async ({ page }) => {
  const gateway = await boot(page, [fileEntry([grant("bob", ["read"])])]);
  await openShare(page);
  await page.getByPlaceholder("P-256 public key, base64url (from the gateway /keypair)").fill("public-bob");
  const modal = page.locator(".modal");
  await expect(modal.locator(".existing-recipient")).toContainText("Already shared with bob");
  await expect(modal.getByRole("button", { name: "Wrap CEK & share" })).toHaveCount(0);
  const update = modal.getByRole("button", { name: "Update permission" });
  await expect(update).toBeDisabled(); // read is selected and bob already has read
  await modal.locator(".field .seg").getByRole("button", { name: "read + write" }).click();
  await update.click();
  await expect(page.locator(".run-status").first()).toHaveText("complete");
  await expect(page.locator(".share-package textarea")).toBeVisible();
  const calls = gateway.requests.filter(r => r.path.startsWith("/api/share"));
  expect(calls.map(r => r.path)).toEqual(["/api/share/permission"]);
  expect(calls[0].body).toMatchObject({ content_id: "plain-v1", remote_content_id: "network", recipient_public_key: "public-bob", permissions: ["read", "write"] });
  const shares = await stored(page);
  expect(shares[0].permissions).toEqual(["write"]);
  expect(shares[0].delegatedAccess?.jti).toBe("bob-2");
  expect(gateway.unexpected).toEqual([]);
});

test("downgrading from a row needs no revoke; other recipients' replaced tokens are stored", async ({ page }) => {
  const gateway = await boot(page, [fileEntry([grant("bob", ["read", "write"]), grant("carol", ["read"])])]);
  await openShare(page);
  await expect(page.locator(".share-package")).toHaveCount(0);
  const bob = page.locator(".recipient-row").filter({ hasText: "bob" });
  await bob.locator(".seg").getByRole("button", { name: "read", exact: true }).click();
  await expect(page.locator(".run-status").first()).toHaveText("complete");
  await expect(bob.locator(".seg button.on")).toHaveText("read");
  await expect(page.locator(".share-package label")).toContainText("Share package for bob");
  expect(gateway.requests.filter(r => r.path.startsWith("/api/share")).map(r => r.path)).toEqual(["/api/share/permission"]);
  const shares = await stored(page);
  const byLabel = Object.fromEntries(shares.map(s => [s.recipientLabel, s]));
  expect(byLabel.bob.permissions).toEqual(["read"]);
  expect(byLabel.bob.delegatedAccess?.jti).toBe("bob-2");
  expect(byLabel.carol.permissions).toEqual(["read"]);
  expect(byLabel.carol.delegatedAccess?.jti).toBe("carol-2");
  expect(byLabel.carol.tokenReissuedAt).toBeTruthy();
  expect(gateway.unexpected).toEqual([]);
});
