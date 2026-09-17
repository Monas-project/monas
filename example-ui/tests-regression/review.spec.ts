import { test, expect, type Page } from "@playwright/test";
import type { Entry, Identity, SharePackage } from "../src/types";

const identity = (label: string, signing = true): Identity => ({ label, keyType: "secp256r1", publicKeyB64Url: `public-${label}`, privateKeyB64Url: `fake-private-${label}`, isSigningAccount: signing });
const envelope = { enc: "fixture", wrapped_cek: "fixture", ciphertext: "fixture-v1", key_epoch: 1 };
const pkg: SharePackage = {
  kind: "monas-share", v: 1, name: "shared.txt", mimeType: "text/plain", sizeBytes: 2,
  content_id: "plain-v1", remote_content_id: "network", sender_public_key: "public-owner",
  recipient_public_key: "public-B", recipient_key_id: "recipient-B", permissions: ["read", "write"],
  key_envelope: envelope, shared_at: 1,
  delegated_access: { delegated_token: "fixture-token", issued_at: 1, expires_at: 4102444800, jti: "fixture" },
};
const ownerEntry = (): Entry => ({ id: "owner-file", kind: "file", name: "owner.txt", parentPath: "/", sizeBytes: 2, mimeType: "text/plain", createdAt: 1, updatedAt: 1, localContentId: "plain-v1", remoteContentId: "network", syncedToStateNode: true, versionCount: 1, shares: [] });
const b64 = (text: string) => Buffer.from(text).toString("base64url");

// Exercise App, stores, flow runner and API adapters unchanged. Only HTTP is
// simulated: every gateway call is intercepted, unknown calls fail closed.
async function boot(page: Page, entries: Entry[] = [], identities = [identity("B")], activeLabel = "B") {
  let head = "v1";
  const requests: { path: string; body: any; method: string }[] = [];
  const unexpected: string[] = [];
  await page.addInitScript(({ entries, identities, activeLabel }) => {
    if (sessionStorage.getItem("regression-seeded")) return;
    sessionStorage.setItem("regression-seeded", "yes");
    localStorage.setItem("monas.identities.v2", JSON.stringify({ identities, activeLabel }));
    localStorage.setItem("monas.registry.v3", JSON.stringify(entries));
    localStorage.setItem("monas.endpoints.v2", JSON.stringify({ gateway: "/api", accountService: "/account-api" }));
  }, { entries, identities, activeLabel });
  await page.route("**/*", async route => {
    const req = route.request();
    const url = new URL(req.url());
    const path = url.pathname;
    if (url.origin !== "http://127.0.0.1:5198") {
      unexpected.push(req.url());
      return route.abort();
    }
    if (!path.startsWith("/api") && !path.startsWith("/account-api")) return route.continue();
    const body = req.postDataJSON();
    requests.push({ path, body, method: req.method() });
    let data: unknown;
    if (path === "/api/health") return route.fulfill({ status: 200, body: "" });
    if (path === "/api/share/decrypt") data = { content_id: "plain-v1", content: b64("V1"), version: "v1" };
    else if (path === "/api/state/read") data = { content_id: "network", local_content_id: `plain-${head}`, version: head, content: b64(head.toUpperCase()) };
    else if (path === "/api/state/latest-version") data = { content_id: "network", latest_version: head };
    else if (path === "/api/state/history") data = { content_id: "network", versions: [head] };
    else if (path === "/api/share/content/network" && req.method() === "PUT") {
      expect(body.content).toBe(b64("V2"));
      expect(req.headers().authorization).toBe("Bearer fixture-token");
      head = "v2";
      data = { remote_content_id: "network", version_id: "plain-v2" };
    } else if (path === "/api/content/plain-v1") data = { content_id: "plain-v1", content: b64("V1") };
    else {
      unexpected.push(`${req.method()} ${path}`);
      return route.fulfill({ status: 500, body: "Unexpected test request" });
    }
    return route.fulfill({ json: { success: true, data, trace_id: "test" } });
  });
  await page.goto("/");
  return { requests, unexpected, setHead: (value: string) => { head = value; } };
}
async function action(page: Page, name: string) {
  await page.locator(".row-menu-wrap > button").click();
  await page.locator(".menu").getByRole("button", { name, exact: true }).click();
}

test("recipient import → edit → reopen compares the displayed envelope, not the recorded write", async ({ page }) => {
  const gateway = await boot(page);
  await page.getByRole("button", { name: "Import shared", exact: true }).click();
  await page.locator(".modal textarea").fill(JSON.stringify(pkg));
  await page.getByRole("button", { name: "Unwrap & add to my Drive" }).click();
  await expect(page.locator(".preview-box").first()).toHaveText("V1");
  await expect(page.locator(".sync-status")).toHaveAttribute("data-sync", "current");
  await page.keyboard.press("Escape");
  await action(page, "Edit contents");
  await expect(page.locator(".modal textarea")).toHaveValue("V1");
  await page.locator(".modal textarea").fill("V2");
  await page.getByRole("button", { name: "Re-encrypt & save" }).click();
  await expect.poll(() => page.evaluate(() => JSON.parse(localStorage.getItem("monas.registry.v3")!)[0].receivedShare.writtenVersionId)).toBe("plain-v2");
  await expect(page.locator(".row .sync")).toHaveAttribute("data-sync", "current");
  await action(page, "Open / preview");
  await expect(page.locator(".preview-box").first()).toHaveText("V1");
  await expect(page.locator(".sync-status")).toHaveAttribute("data-sync", "behind");
  await expect(page.locator(".sync-status")).not.toContainText("the owner has edited");
  await page.getByRole("button", { name: "Read from state-node", exact: true }).click();
  await expect(page.locator(".preview-box").last()).toHaveText("V2");
  await expect(page.locator(".modal")).toContainText("your edit");
  await expect(page.locator(".sync-status")).toHaveAttribute("data-sync", "behind");
  await expect(page.locator(".row .sync")).toHaveAttribute("data-sync", "current");
  expect(gateway.requests.filter(r => r.path === "/api/share/decrypt")).toHaveLength(2);
  expect(gateway.unexpected).toEqual([]);
});

test("owner preview compares its local body with the network head", async ({ page }) => {
  const gateway = await boot(page, [ownerEntry()]);
  await action(page, "Open / preview");
  await expect(page.locator(".preview-box").first()).toHaveText("V1");
  await expect(page.locator(".sync-status")).toHaveAttribute("data-sync", "current");
  gateway.setHead("v2");
  await page.getByRole("button", { name: "Check now" }).click();
  await expect(page.locator(".sync-status")).toHaveAttribute("data-sync", "behind");
  await expect(page.locator(".row .sync")).toHaveAttribute("data-sync", "behind");
  await expect(page.locator(".preview-box").first()).toHaveText("V1");
  await expect(page.locator(".preview-box").last()).toHaveText("V2");
  expect(gateway.unexpected).toEqual([]);
});

const reachCases = [
  { name: "legacy", output: { token_invalidated_at: 42 }, detail: /propagation.*unknown/i, toast: /propagation.*unknown/i },
  { name: "local", output: {}, detail: /No state node involved/, toast: null },
  { name: "relayed", output: { token_invalidated_at: 42, token_invalidation_reach: { notified_members: [], unreached_members: [], relayed: true } }, detail: /relayed.*not known/, toast: /relayed to a member/ },
  { name: "all", output: { token_invalidated_at: 42, token_invalidation_reach: { notified_members: ["node-2"], unreached_members: [], relayed: false } }, detail: /All 1 other member/, toast: null },
  { name: "unreached", output: { token_invalidated_at: 42, token_invalidation_reach: { notified_members: [], unreached_members: [{ node_id: "node-2", error: "offline" }], relayed: false } }, detail: /1 member\(s\) did not get/, toast: /did not reach 1 member/ },
];
for (const scenario of reachCases) {
  test(`revoke ${scenario.name}: flow and toast report propagation honestly`, async ({ page }) => {
    const entry = ownerEntry();
    if (scenario.name === "local") { entry.syncedToStateNode = false; delete entry.remoteContentId; }
    entry.shares = [{ recipientPublicKeyB64Url: "public-recipient", recipientLabel: "recipient", permissions: ["read", "write"], senderKeyId: "B", recipientKeyId: "recipient", senderPublicKeyB64Url: "public-B", envelope, grantedAt: 1 }];
    const gateway = await boot(page, [entry]);
    await page.route("**/api/share/revoke", async route => {
      expect(route.request().postDataJSON().sender_public_key).toBe("public-B");
      await route.fulfill({ json: { success: true, data: { content_id: "plain-v1", recipient_public_key: "public-recipient", revoked: true, reissued_envelopes: [], ...scenario.output } } });
    });
    await action(page, "Share");
    await page.getByRole("button", { name: "Revoke", exact: true }).click();
    await expect(page.locator(".run-status")).toHaveText("complete");
    // Soft assertions catch flow and App toast independently in a RED run.
    await expect.soft(page.locator(".step").filter({ hasText: "Cutoff propagation" })).toContainText(scenario.detail);
    if (scenario.toast) await expect.soft(page.locator(".toast.error")).toContainText(scenario.toast);
    else await expect(page.locator(".toast.error")).toHaveCount(0);
    await expect(page.locator(".modal").getByRole("button", { name: "Revoke", exact: true })).toHaveCount(0);
    expect(gateway.unexpected).toEqual([]);
  });
}

for (const activeLabel of ["B", "A", "legacy"]) {
  test(`identity migration retains latest signing key B when old activeLabel is ${activeLabel}`, async ({ page }) => {
    const ids = [identity("A"), identity("B"), identity("legacy", false)];
    const gateway = await boot(page, [], ids, activeLabel);
    await expect.soft(page.locator(".account-chip .meta b")).toHaveText("B");
    await page.locator(".account-chip").click();
    const signing = page.locator(".recipient-row").filter({ has: page.locator(".badge.enc") });
    await expect.soft(signing).toContainText("B");
    await expect.soft(page.locator(".recipient-row")).toHaveCount(3);
    await expect.soft(page.locator(".recipient-row").filter({ hasText: "public-A" })).toContainText("keypair only");
    await expect.soft(page.locator(".recipient-row").filter({ hasText: "public-legacy" })).toContainText("keypair only");
    const migrated = await page.evaluate(() => JSON.parse(localStorage.getItem("monas.identities.v2")!).identities);
    expect(migrated).toEqual([{ ...ids[0], isSigningAccount: false }, ids[1], ids[2]]);
    await page.reload();
    await expect(page.locator(".account-chip .meta b")).toHaveText("B");
    await page.locator(".account-chip").click();
    // Migration preserves all material, but never revives A as signing when B is removed.
    await signing.getByTitle("Remove from this browser").click();
    await expect(page.getByRole("button", { name: "Create account", exact: true })).toBeVisible();
    await expect(page.locator(".recipient-row .badge.enc")).toHaveCount(0);
    const stored = await page.evaluate(() => JSON.parse(localStorage.getItem("monas.identities.v2")!));
    expect(stored.identities.every((i: Identity) => !i.isSigningAccount)).toBe(true);
    expect(stored.identities.find((i: Identity) => i.label === "legacy")).toEqual(ids[2]);
    expect(gateway.unexpected).toEqual([]);
  });
}

test("identity with one signing key preserves it over an active legacy keypair", async ({ page }) => {
  await boot(page, [], [identity("old", false), identity("B"), identity("legacy", false)], "legacy");
  await expect(page.locator(".account-chip .meta b")).toHaveText("B");
  await page.locator(".account-chip").click();
  await expect(page.locator(".recipient-row")).toHaveCount(3);
  await expect(page.locator(".recipient-row").filter({ has: page.locator(".badge.enc") })).toContainText("B");
});

test("identity keypair-only fallback preserves active legacy identity and all envelope keys", async ({ page }) => {
  const ids = [identity("A", false), identity("B", false)];
  await boot(page, [], ids, "B");
  await expect(page.locator(".account-chip .meta b")).toHaveText("B");
  await page.locator(".account-chip").click();
  await expect(page.locator(".recipient-row")).toHaveCount(2);
  await expect(page.locator(".recipient-row .badge.enc")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Create account", exact: true })).toBeVisible();
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("monas.identities.v2")!).identities)).toEqual(ids);
});
