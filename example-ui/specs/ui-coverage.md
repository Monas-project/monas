# Monas Drive example UI — coverage test plan

Playwright scenarios for the interactive surface that the real-stack journeys
(`tests-e2e/full-stack.spec.ts`) do **not** need to touch. The journeys walk
the protocol paths (create account → folder → file → preview → verify → edit →
share → revoke → delete) against real nodes; the scenarios below cover the
rest of the interactive surface cheaply, without content mutations.

## Preconditions & house rules

- The stack must be running: vite `:5174`, gateway `127.0.0.1:3000`,
  monas-account `127.0.0.1:4002`; for `tests-e2e/` the gateway's
  `MONAS_STATE_NODE_URL` must point at a live state node.
- `tests/seed.spec.ts` runs first. It clears `localStorage`, waits for the
  gateway health dot, and creates the **signing account** `agent-main`.
  Without a signing account every content operation is refused (see S-14).
- The Drive registry lives in `localStorage`; assume a blank registry unless a
  scenario seeds one.
- **Content mutations are expensive** (~1.5–3s, sometimes far longer: real
  crypto + a 4-node state-node round trip). Scenarios are ordered so that the
  cheap, pure-UI ones run first and the few that need a real file **share one
  fixture file** rather than each creating their own. Use
  `timeout: 180_000` / `expect.timeout: 30_000` from `playwright.config.ts`.
- Prefer asserting on **observable UI state** (`.on`, `.active`, `.badge`,
  toast text, `localStorage`) over screenshots.

### Shared fixture

Scenarios marked **[fixture]** reuse one file created once per file:

```
name:     probe.txt
contents: "probe content v1"
created:  at "/" with a signing account present
```

Create it once in a `test.beforeAll` / serial-mode first test and let the later
scenarios in that file operate on it. Do **not** create a file per scenario.

---

## Accessible names observed in the running app

Recorded from the live accessibility tree — use these for ARIA/role assertions.
Several controls are **icon-only with no accessible name**; those are flagged
and must be located by `title`, CSS class, or fixed with an `aria-label`
(see "Accessibility defects" at the end).

**TopBar**
| Control | Role / name |
|---|---|
| Settings | `button "Settings · endpoint"` (name comes from `title`) |
| Account chip | `button` — **no accessible name**; children render `"No identity"` / `"click to create"`, or the identity label |
| Gateway health | `generic "Gateway health (monas-gateway → SDK)"` wrapping `generic "gateway"`; **state lives only in the CSS class** `.dot.up` / `.dot.down` / `.dot` |

**Sidebar** — all `role="button"`, `tabIndex=0` `div.nav-item`
`button "New file"`, `button "Upload"`, `button "New folder"`,
`button "My Drive"`, `button "Encrypted files"`, `button "On state-node"`,
`button "Shared"`. Active view = `.nav-item.active`. Counts render inside a
`span.mono` (text reads e.g. `"Encrypted files0"`).

**PipelinePanel**
Expanded: `generic "Protocol activity"`, `button "Collapse"` (name from `title`),
`button "Clear"` (only when `runs.length > 0`).
Collapsed: `aside.pipeline.collapsed` with a single
`button "Show protocol activity"` (name from `title`, **no text/aria-label**).

**SettingsModal** (`Endpoint`)
`heading "Endpoint"`, `textbox` (value `/api`) labelled
`"monas-gateway base URL"`, `textbox` (value `/account-api`) labelled
`"monas-account base URL (for “create account”)"`,
`button "Local (Vite proxy → Docker)"`, `button "Local (direct :3000)"`,
`button "Reset to proxy"`, `button "Test connection"`, `button "Save"`.
Labels are **siblings, not `for`-associated** — `getByLabel` will not work.

**ShareModal**
`heading "Share “<name>”"`, seg 1 = `button "Pick identity"` /
`button "Paste public key"`, seg 2 (permission) = `button "read"` /
`button "read + write"`, `select` of `"<label> · <keyType>"`,
`checkbox` labelled `"Prove access: unwrap CEK & decrypt as the recipient"`
(default **checked**), `textarea` placeholder
`"P-256 public key, base64url (from the gateway /keypair)"`,
footer `button "Close"` / `button "Wrap CEK & share"`.
Recipient rows: `.recipient-row` with `button "Revoke"`.

**PreviewModal**
`heading "<file name>"`, `button "Reload"` (`title="Reload from state-node"`),
`button "Verify integrity"`, `button "Read from state-node"`,
`select` whose first option is `"latest version"` followed by one shortened CID
per version, `.state-history .ver` (current one also carries `.current` and the
text ` · latest`), `.preview-box`, `.kv` rows keyed
`local content_id` / `Content Network` / `seriesId` / `versions` / `latest version`.

**FileBrowser row menu** — `Open / preview`, `Edit contents`,
`Share`, `Delete` (`.danger`). Folder rows show `Open folder` instead of
`Open / preview` and have no `Edit contents` / `Share`.
Badges: `.badge.enc` "enc", `.badge.synced` "synced", `.badge.local` "local",
`.badge.shared`. Header: `Name`, `Location`, `Size`, `Modified`, ``.

**ActionModals** — footers are `Cancel` + one of
`Encrypt & create` / `Re-encrypt & save` / `Create` / `Rename` / `Delete`.
Every modal's close **X** is an `.icon-btn` with **no accessible name**.

---

# Scenarios

Priority: **P0** = a control that may silently do nothing (the failure mode we
most want to catch) or a data-integrity risk. **P1** = state/rendering
correctness. **P2** = polish and a11y.

## A. SettingsModal — completely untested (7 scenarios)

### S-01 · Settings opens and shows current endpoints — P1
No mutation.
1. Click `button "Settings · endpoint"`.
2. Expect `heading "Endpoint"` visible and `.modal.wide` present.
3. Expect gateway input value `/api` and account input value `/account-api`
   (the `PROXY_DEFAULTS`).
4. Expect exactly two preset buttons, with
   `"Local (Vite proxy → Docker)"` carrying class `on`.

### S-02 · Preset buttons rewrite the gateway field — P0
Verified manually: works.
1. Open Settings, click `"Local (direct :3000)"`.
2. Expect gateway input value becomes `http://127.0.0.1:3000`.
3. Expect the `on` class moves to that button and leaves the proxy preset.
4. Click `"Local (Vite proxy → Docker)"` and expect the value returns to `/api`.

### S-03 · Editing a preset field deselects the preset highlight — P1
1. Open Settings, type a custom URL (e.g. `http://localhost:9999`) into the
   gateway field.
2. Expect **neither** preset button has class `on` (highlight is derived from
   `cfg.gateway === p.value`).

### S-04 · Save persists to localStorage and closes — P0
1. Open Settings, pick `"Local (direct :3000)"`, click `Save`.
2. Expect toast `"Endpoint saved"`.
3. Expect the modal closes.
4. Expect `localStorage["monas.endpoints.v2"]` parses to
   `{gateway:"http://127.0.0.1:3000", accountService:"/account-api"}`.
5. **Cleanup**: reopen, `Reset to proxy`, `Save` — otherwise later scenarios
   run against a different endpoint.

### S-05 · Changes are NOT persisted until Save — P0
1. Open Settings, pick `"Local (direct :3000)"`.
2. Without saving, press `Escape`.
3. Expect `localStorage["monas.endpoints.v2"]` is unchanged (still `/api`).
   *Verified manually with a fresh registry: before any Save the key is
   `null`, and preset clicks alone do not create it.*

### S-06 · "Test connection" probes the gateway and reports — P0
1. Open Settings, click `Test connection`.
2. Expect a toast matching `/gateway (✓ reachable|✗ unreachable)/`.
   With the stack up this must be `✓ reachable`.
3. Expect the button re-enables (spinner clears) afterwards.
4. Negative variant: set the gateway to `http://127.0.0.1:9` first, then
   `Test connection`, and expect `✗ unreachable`. **Must** finish with
   `Reset to proxy` + `Save`.

### S-07 · ⚠ "Test connection" silently persists the endpoint — P0 (**suspected bug**)
`SettingsModal.test()` calls `saveEndpoints(cfg)` before probing "because the
probe reads from storage", so the *unsaved* value is written to
`localStorage` as a side effect. **Reproduced manually.**
1. Start with a saved `/api` config.
2. Open Settings, pick `"Local (direct :3000)"`, click `Test connection`.
3. Press `Escape` **without** clicking Save.
4. **Observed**: `monas.endpoints.v2` now holds
   `{"gateway":"http://127.0.0.1:3000",...}`, i.e. a cancelled edit took effect
   and survives reload.
   Compounding this, `Reset to proxy` only resets local component state — it
   does **not** write storage — so a user who tests, resets, then closes still
   leaves the tested endpoint persisted.
   Assert the intended behaviour (storage unchanged after a cancelled test) so
   the test fails until the side effect is fixed, or file it and assert the
   current behaviour with an explicit `// known bug` note.

---

## B. PipelinePanel — completely untested (5 scenarios)

### B-08 · Collapse hides the panel body and swaps the control — P0
No mutation. Verified manually: works.
1. Expect `aside.pipeline` **without** `.collapsed` and a `.pipe-head`.
2. Click `button "Collapse"`.
3. Expect `aside.pipeline.collapsed`, `.pipe-head` gone, and exactly one
   button — `"Show protocol activity"`.
4. Click it; expect the panel expands and `.pipe-head` returns.

### B-09 · Empty state copy renders before any run — P1
1. With `runs === []`, expect `.pipe-empty` containing
   `"Every action (create, update, share, revoke, delete) runs through Monas"`
   and the bolded `"CEK → AES-256-GCM → SHA-256 CID → storage → state-node"`.
2. Expect **no** `Clear` button (it renders only when `runs.length > 0`).

### B-10 · A run renders its full step list — P1 **[fixture]**
Reuses the fixture creation; asserts on the panel afterwards rather than
triggering a new mutation. Verified manually against a real Create.
1. After the fixture file is created, expect one `.run`.
2. Expect `.op` = `"Create"`, `.tgt` = `probe.txt`,
   `.run-status.done` with text `"complete"`.
3. Expect **6** `.step` rows, all `.step.done`, with titles in order:
   `Generate content key (CEK)`, `Encrypt content · gateway call`,
   `Compute content address (CID)`, `Store encrypted blob`,
   `Register on state-node`, `Select members & init CRDT`
   and hints `AES-256`, `monas-sdk · AES-256-GCM`, `SHA-256`,
   `monas-filesync`, `Content Network · signed`, `Kademlia XOR · DAG-CRDT`.

### B-11 · Clear empties the run list — P0 **[fixture]**
1. With ≥1 run present, expect `button "Clear"` visible.
2. Click it.
3. Expect zero `.run`, the `.pipe-empty` copy returns, and the `Clear` button
   disappears.

### B-12 · Running an action auto-expands a collapsed panel — P1 **[fixture]**
`App.run()` does `if (collapsed) setCollapsed(false)`.
1. Collapse the panel.
2. Trigger any pipeline action (cheapest: `Open / preview` on the fixture,
   which runs the Open flow and no write).
3. Expect the panel is expanded again and shows the new run.

---

## C. Sidebar filter views — completely untested (6 scenarios)

Verified manually: the three filter views switch `.active`, retitle the
breadcrumb, and swap the empty-state copy correctly.

### C-13 · Filter views switch the active nav item and breadcrumb — P0
No mutation.
1. Click `"Encrypted files"`; expect that `.nav-item` gains `.active`,
   `My Drive` loses it, and `.crumb.last` reads `"Encrypted files"`.
2. Repeat for `"On state-node"` → crumb `"On state-node"`, and
   `"Shared"` → crumb `"Shared"`.
3. Click `"My Drive"`; expect `.active` returns to it and the crumb shows the
   path (`My Drive`).

### C-14 · Empty filter view shows the "no matching files" copy — P1
1. With a blank registry, click `"Shared"`.
2. Expect `.empty h3` = `"No matching files"` (not `"This folder is empty"`)
   and the body copy beginning `"Nothing matches this view yet."`.
3. Click `"My Drive"` and expect `.empty h3` = `"This folder is empty"`.

### C-15 · Counts reflect the registry — P1 **[fixture]**
1. With the fixture file present (synced, unshared), expect the
   `Encrypted files` row's `span.mono` = `1`, `On state-node` = `1`,
   `Shared` = `0`.
2. Assert counts are read from the sidebar, not the file list.

### C-16 · Filter views are flat and drive-wide — P1 **[fixture]**
This is the behaviour most likely to regress: `entriesIn(path)` vs. the flat
filter list.
1. Seed a folder `docs` and move/create the fixture inside it (one extra
   mutation — or seed `localStorage` directly to avoid the round trip).
2. From `My Drive` (root) the file is **not** listed.
3. Click `"Encrypted files"`; expect the file **is** listed even though it
   lives in `/docs`.

### C-17 · Navigating a folder drops the filter view — P1 **[fixture]**
`navigateTo()` resets `view` to `{kind:"folder"}`.
1. Select `"Encrypted files"`.
2. Click `"My Drive"`.
3. Expect `.crumb.last` is the path crumb and the `Encrypted files` nav item is
   no longer `.active`.

### C-18 · Sidebar "New folder" / "Upload" open the right affordance — P0
1. Click `"New folder"`; expect a modal titled `"New folder"` with label
   `"Folder name"` and a `Create` button. `Escape`.
2. Click `"Upload"`; expect it triggers the hidden `input[type=file]`
   (assert via `page.waitForEvent("filechooser")` — the input is
   `display:none`, so a normal click assertion will not see it).

---

## D. TopBar — completely untested (3 scenarios)

### D-19 · Gateway health indicator turns up — P0
1. Load the app.
2. Expect `.conn .dot` gains class `up` within 30s (poll runs every 6s).
3. Expect the wrapper's `title` is `"Gateway health (monas-gateway → SDK)"`.
   *Note: state is CSS-only; there is no `aria-live` or text change, so a
   screen-reader user cannot perceive it (see A11Y-1).*

### D-20 · Health indicator goes down for a bad endpoint — P1
1. Settings → set the gateway to `http://127.0.0.1:9` → `Save`.
2. Expect `.conn .dot` gains class `down` within ~12s (two poll cycles;
   `onSaved` also re-probes immediately).
3. **Cleanup**: `Reset to proxy` → `Save`; expect `.dot.up` returns.

### D-21 · Account chip reflects identity state and opens the modal — P0
1. With no identity, expect the chip shows `"No identity"` / `"click to create"`
   and the avatar reads `+`.
2. Click it; expect the `"Identities & keys"` modal.
3. After seeding `agent-main`, expect the chip shows `agent-main`, the avatar
   shows `AG` (first two chars, uppercased), and the sub-line shows
   `secp256r1 · <first 10 chars of the public key>`.

---

## E. FileBrowser rows, menus, navigation (7 scenarios)

### E-22 · Row menu opens, closes, and offers the right items — P0 **[fixture]**
Verified manually. No mutation.
1. Click the row's `.row-menu-wrap .icon-btn`.
2. Expect a `.menu` with exactly: `Open / preview`, `Edit contents`,
   `Share`, `Delete` (last has class `danger`). There is **no** `Rename` on a
   file row — a file's name only reaches the SDK through an update, so the
   rename path is the name field in `Edit contents`.
3. Click elsewhere in `.scroll`; expect the menu closes.
4. Expect opening a second row's menu closes the first (single `openMenu` id).

### E-23 · Folder rows expose a different menu — P1
Cheap: folders are localStorage-only, no crypto.
1. Create folder `docs`.
2. Open its row menu.
3. Expect `Open folder`, `Rename`, `Delete` and **no** `Edit contents` /
   `Open / preview` / `Share`.

### E-24 · Folder navigation and breadcrumbs — P0
Cheap (folders only).
1. Create nested folders `docs` then `docs/reports`.
2. Double-click into each; expect `.crumb.last` tracks the folder name.
3. Expect the breadcrumb renders ancestors separated by `›`.
4. Click an **ancestor** crumb; expect navigation back to it.
5. Click the **last** crumb; expect **nothing happens** — the handler is
   `i < crumbs.length - 1 && onNavigate(...)`. This is an intentional dead
   click; assert the path does not change.

### E-25 · Rename a folder rewrites descendant paths — P0
Cheap and high-risk (`renameFolder` rewrites `parentPath` by string prefix).
1. Create `docs`, and a subfolder `docs/reports`.
2. Rename `docs` → `documents`.
3. Expect toast `"Folder renamed"`.
4. Navigate into `documents`; expect `reports` is still there (i.e. the
   descendant's `parentPath` was rewritten, not orphaned).
5. Edge case worth asserting: rename `docs` → `docs2` when a sibling folder
   `docs2` already exists, and check the two trees do not merge.

### E-26 · Duplicate names are allowed and stay distinguishable — P1
`addEntry` does not dedupe.
1. Create folder `dup`, then create folder `dup` again.
2. Expect **two** rows named `dup`.
3. Note for the implementer: `page.locator(".row", {hasText:"dup"})` matches
   both — tests must use `.first()`/`.nth()` or an id-based selector.
   Flag as a UX defect if duplicates should be rejected.

### E-27 · Files have no Rename action — P1 **[fixture]**
A local-only rename used to exist and never reached the protocol; it was
removed. Renaming a file is done through `Edit contents`, whose name field is
carried to the SDK by the update flow.
1. Open a file row's menu; expect **no** `Rename` item.
2. Open a folder row's menu; expect `Rename` **is** offered (folders are local
   organization only).

### E-28 · Double-click opens the right action per row kind — P1 **[fixture]**
1. Double-click a **file** row; expect the preview modal (an `Open` run
   appears).
2. Double-click a **folder** row; expect navigation, not a modal.

---

## F. ActionModals — validation and cancels (5 scenarios)

All cheap: they assert *before* any mutation is committed.

### F-29 · New file: empty / whitespace name disables submit — P0
Verified manually: works (`valid = name.trim().length > 0`).
1. Sidebar → `New file`.
2. Expect the name pre-filled `"untitled.txt"` and `Encrypt & create` enabled.
3. Clear the name; expect `Encrypt & create` **disabled**.
4. Type `"   "` (spaces only); expect it stays **disabled**.
5. Type a valid name; expect it re-enables.

### F-30 · New folder: submit disabled until a name is typed — P0
1. Sidebar → `New folder`.
2. Expect the input empty and `Create` **disabled**.
3. Type spaces only; expect still **disabled**.
4. Type `docs`; expect enabled.

### F-31 · Cancel and X and Escape all dismiss without side effects — P0
For each of `New file`, `New folder`, `Rename` (folder row), `Delete`:
1. Open the modal, fill a value.
2. Dismiss three ways in separate runs: `Cancel` button, the header `.icon-btn`
   X, and `Escape`.
3. Expect the modal closes, **no toast**, and the registry is unchanged
   (row count identical).
4. Also assert clicking the `.overlay` backdrop closes it (Modal binds
   `onMouseDown` on the overlay) **and** that clicking *inside* `.modal` does
   **not** (the inner `onMouseDown` stops propagation).

### F-32 · Delete confirm shows kind-specific copy — P1 **[fixture]**
1. File row menu → `Delete`; expect the message contains
   `"removes the encrypted blob and tombstones its Content Network"`.
2. Folder row menu → `Delete`; expect
   `"and everything inside it"`.
3. Press `Cancel` in both cases and expect the entry still exists.

### F-33 · Byte counter tracks the textarea — P2
1. Open `New file`; expect the hint reads `0 bytes`.
2. Type `hello`; expect `5 bytes`.
3. Type a multi-byte character (e.g. `あ`); expect the count grows by 3
   (`new Blob([text]).size` is UTF-8 bytes, not `length`).

---

## G. ShareModal — under-covered (6 scenarios)

The existing e2e only clicks `Wrap CEK & share` once in the default
`Pick identity` mode and then `Revoke`.

### G-34 · ⚠ Empty public key makes the share button a dead click — P0 (**confirmed bug**)
**Reproduced manually.** In `Paste public key` mode `submit()` does
`if (!pubKey.trim()) return;` while the button stays **enabled**.
1. Open Share on the fixture, click `Paste public key`.
2. Leave the textarea empty and click `Wrap CEK & share`.
3. **Observed**: nothing at all — no toast, no new `.run`, no error, modal
   stays open. The control is enabled but inert.
4. Assert the intended behaviour (either the button is `disabled`, or an error
   toast appears) so the test fails until fixed.

### G-35 · Mode toggle swaps the recipient inputs — P0
Verified manually: works.
1. Open Share; expect `Pick identity` has class `on` (an identity other than
   the active one exists) and a `select` is shown together with the
   `"Prove access…"` checkbox.
2. Click `Paste public key`; expect the `select` **and** the checkbox
   disappear and a `textarea` with placeholder
   `"P-256 public key, base64url (from the gateway /keypair)"` plus a
   `Label (optional)` input appear.
3. Click back; expect the select returns.

### G-36 · With no other identity, "Pick identity" is disabled — P1
1. Seed **only** the signing account (delete `bob` in the Identity modal, or
   start from seed alone).
2. Open Share.
3. Expect `button "Pick identity (none)"` is **disabled** and the modal opens
   already in `Paste public key` mode (`useState` default).

### G-37 · Permission toggle switches read vs read+write and survives a mode change — P0
Verified manually: works.
1. Open Share; expect `read` has class `on` (default `canWrite=false`).
2. Click `read + write`; expect the `on` class moves.
3. Switch to `Paste public key` and back; expect `read + write` is **still**
   selected (permission state is independent of mode).
4. Optional (one real share): share with `read + write` and expect the
   recipient row renders **two** `.badge` chips, `read` and `write`.

### G-38 · "Prove access" checkbox controls the decrypt round-trip — P1
The checkbox is checked by default; unchecking omits
`recipientPrivateKeyB64Url`, which drops the prove step from the flow.
1. Open Share in `Pick identity` mode; expect the checkbox **checked**.
2. Uncheck it and share.
3. Expect the share still succeeds (`Shared with bob`) but the pipeline run has
   **fewer** steps than a proven share — assert the absence of the
   unwrap/decrypt-as-recipient step by title.
4. Compare against a proven share (checkbox left checked) in the same file.

### G-39 · Revoking one of several recipients keeps the others — P0
The highest-value untested path: `handleRevoke` re-wraps surviving recipients
under the new `key_epoch`, and the app deliberately raises an **error** toast
if any survivor got no reissued envelope.
1. Seed a third identity `carol` (keypair-only).
2. Share the fixture with `bob`, then with `carol`. Expect two
   `.recipient-row`s and a `.badge.shared` count of `2` on the row.
3. Revoke **bob** only.
4. Expect toast `"Access revoked & content re-encrypted"` with class
   `toast success` — **not** `toast error`. An error toast here means a
   surviving recipient lost access (the `stale > 0` branch) and is a real
   protocol regression.
5. Expect exactly one `.recipient-row` remains (`carol`), and its mono line now
   contains `"· re-wrapped after a revoke"` and a **bumped** `epoch`.
6. Expect the row badge count drops to `1`.

---

## H. PreviewModal — under-covered (5 scenarios)

The existing e2e clicks `Verify integrity` and `Read from state-node` once each,
always at the default (latest) version.

### H-40 · Version dropdown lists every recorded version — P1 **[fixture, 1 edit]**
Verified manually after one edit: the select held `latest version` plus 2 CIDs
while `.state-history` showed 2 `.ver` rows.
1. Edit the fixture once so it has two versions.
2. Open the preview.
3. Expect `select option` count = `versions + 1`; the first option's label is
   `"latest version"` and its `value` is `""`.
4. Expect one `.state-history .ver` per version, exactly one carrying `.current`
   and the suffix `" · latest"`.

### H-41 · Verified read of an OLDER version returns the old plaintext — P0 **[fixture, 1 edit]**
This is the whole point of the dropdown and is entirely untested.
1. With two versions, select the **non-latest** option.
2. Click `Read from state-node`.
3. Expect `.badge.synced` "verified" appears.
4. Expect the second `.preview-box` shows the **v1** text, while the top
   preview (from the gateway store) still shows the **v2** text.
5. Expect the `version read` `.kv` matches the selected option, not the latest.

### H-42 · Reload re-queries latest + history — P1 **[fixture]**
1. Open the preview and let it settle.
2. Click `Reload` (`title="Reload from state-node"`).
3. Expect the `latest version` `.kv` shows a spinner and then a value again,
   and the history list re-renders with the same count.
4. Assert `Reload` is only rendered for **synced** files.

### H-43 · Local-only file shows the warning instead of state-node controls — P0
Reachable without any state-node write by seeding `localStorage` with an entry
whose `syncedToStateNode` is `false` — **much cheaper than a real mutation.**
1. Seed such an entry and open its preview.
2. Expect `.callout.warn` containing `"This file is local-only"`.
3. Expect **no** `Reload`, **no** `Verify integrity`, **no**
   `Read from state-node`, and no version dropdown.

### H-44 · ⚠ Local `versions` count drifts from the state-node history — P1 (**suspected bug**)
**Observed manually**: right after a single create, the modal's `versions` `.kv`
read `1` while the state-node `version history` listed **2** entries and the
dropdown offered both. `entry.versionCount` is a local counter incremented only
by the edit flow, so it does not track what the Content Network actually holds.
1. Create a file, open the preview immediately.
2. Compare the `versions` `.kv` against `.state-history .ver` count.
3. Assert they agree (test fails until reconciled), or assert the current
   values with an explicit `// known drift` note.

---

## I. Guards, identity, and binary content (5 scenarios)

### I-45 · Content ops without a signing account are refused — P0
**Verified manually — works correctly.** Must run with a cleared
`localStorage` and **without** the seed's account (own file / `test.describe`).
1. Clear `localStorage`, reload.
2. Sidebar → `New file`, give it a name, click `Encrypt & create`.
3. Expect toast `"Create a signing account first"` with class `toast error`.
4. Expect the `"Identities & keys"` modal auto-opens.
5. Expect **no** row is added and **no** `.run` is created.
6. Same for `Upload` (`handleUpload` shares the guard).

### I-46 · Share without an identity is refused — P0
`onAction("share")` guards on `active`.
1. With no identity but an existing entry (seed the registry directly), open a
   row menu → `Share`.
2. Expect toast `"Create an identity first"` and the Identity modal, **not**
   the Share modal.

### I-47 · Identity modal: signing checkbox drives the button label — P1
All keys are P-256 (signing requires it, and the HPKE share envelopes are
DHKEM(P-256)); there is no key-type selector.
1. Open the identity modal with no signing account; expect the checkbox
   **checked** and the primary button reading `Create account`.
2. Uncheck it; expect the button relabels to `Create identity`.

### I-48 · Switching the active identity — P1
1. With two identities, click `Use` on the non-active one.
2. Expect the `active` badge moves and the TopBar chip label follows.
3. Expect the previously active row now shows a `Use` button and the new active
   one does not.

### I-49 · Image upload previews as an image — P1
One upload; use a tiny (<1KB) PNG so the crypto cost stays small.
1. Upload a small PNG via the hidden `input[type=file]`.
2. Expect the row's icon is the image variant and the mime shows `image/png`.
3. Open the preview; expect an `img.preview-img` (**not** a `.preview-box`) with
   a `data:image/png;base64,` src.
4. Run `Read from state-node`; expect the verified-read box shows
   `"(image decrypted and verified — rendered above)"` rather than mojibake.

---

# Findings from live exploration

Controls found **broken or inert** while clicking through the running app:

1. **`Wrap CEK & share` is a dead click with an empty public key** (G-34) —
   *confirmed*. In `Paste public key` mode the button is enabled, but
   `submit()` returns early on an empty key: no toast, no pipeline run, no
   validation message, modal stays open. This is exactly the "silently does
   nothing" failure mode. `ShareModal.tsx:53`.

2. **`Test connection` persists unsaved endpoint changes** (S-07) —
   *confirmed*. `SettingsModal.test()` calls `saveEndpoints(cfg)` before
   probing, so a cancelled edit is written to `localStorage` anyway and
   survives reload. `SettingsModal.tsx:27`.

3. **`Reset to proxy` does not reset persisted config** (S-07) — *confirmed*.
   It only sets component state, so after (2) the tested endpoint stays in
   storage unless the user also presses `Save`. `SettingsModal.tsx:41`.

4. **`versions` count disagrees with state-node history** (H-44) — *observed*.
   Immediately after a create, the preview showed `versions 1` against 2
   entries in the state-node history and 2 CIDs in the dropdown.
   `entry.versionCount` is a purely local counter. `App.tsx:166`.

5. **Last breadcrumb is intentionally inert** (E-24) — by design
   (`i < crumbs.length - 1`), documented here so it is not mistaken for a bug.

6. **Duplicate folder/file names are accepted silently** (E-26) — `addEntry`
   never dedupes, producing indistinguishable sibling rows.

### Accessibility defects (P2, worth `aria-label` fixes)

- **A11Y-1** — the gateway health state exists **only** as a CSS class
  (`.dot.up` / `.dot.down`). No text, `aria-live`, or `title` change, so the
  status is invisible to assistive tech and can only be asserted via CSS.
- **A11Y-2** — every modal close **X** (`.icon-btn` with a bare SVG) has **no
  accessible name**.
- **A11Y-3** — the collapsed pipeline toggle and the row `More` (`⋯`) button
  have no accessible name; only `title` (or nothing) is available.
- **A11Y-4** — the TopBar account chip has no accessible name of its own.
- **A11Y-5** — Settings/Share/Editor `<label>`s are **siblings** of their
  inputs with no `for`/`id`, so `getByLabel()` does not work; tests must fall
  back to placeholders, CSS, or positional selectors.

# Suggested file layout

| File | Scenarios | Needs mutations |
|---|---|---|
| `tests/settings.spec.ts` | S-01…S-07 | none |
| `tests/pipeline.spec.ts` | B-08…B-12 | 1 shared fixture |
| `tests/sidebar.spec.ts` | C-13…C-18 | folders + 1 fixture |
| `tests/topbar.spec.ts` | D-19…D-21 | none |
| `tests/browser-rows.spec.ts` | E-22…E-28 | folders + 1 fixture |
| `tests/action-modals.spec.ts` | F-29…F-33 | none (all pre-commit) |
| `tests/share.spec.ts` | G-34…G-39 | 1 fixture + shares |
| `tests/preview.spec.ts` | H-40…H-44 | 1 fixture + 1 edit |
| `tests/guards.spec.ts` | I-45…I-49 | cleared storage; 1 small PNG |

Run serially (`workers: 1`, already configured) — all specs share one gateway
and one `localStorage` registry.

**Total: 49 scenarios.**
