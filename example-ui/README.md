# Monas Drive — example UI

A minimal, Google-Drive-like web UI for the Monas protocol, built on the
**monas-sdk** via the **monas-gateway** HTTP API. It lets you **create, open,
edit, rename, share, revoke and delete** files and folders, and surfaces the
encryption + state-node work behind every action in a live **Protocol activity**
panel (CEK → AES-256-GCM → SHA-256 CID → storage → state-node → HPKE).

The UI talks to a **single backend — the gateway** — which embeds the SDK and
orchestrates everything server-side:

```
┌──────────────┐    /api/*  (Vite proxy)   ┌───────────────┐  embeds monas-sdk
│   this UI    │ ────────────────────────▶ │ monas-gateway │ ─┬─▶ encrypt + store (monas-content)
│ (React+Vite) │      single endpoint      │     :3000     │  ├─▶ state-node  (:8080)
└──────────────┘                           └───────────────┘  └─▶ sign        (monas-account :4002)
```

## Run

```bash
cd example-ui
npm install
npm run dev          # http://localhost:5173
```

You also need the gateway (and the services it calls) running, e.g. via your
local Docker. The gateway defaults to `:3000` and reads:

```
MONAS_API_PORT=3000
MONAS_STATE_NODE_URL=http://127.0.0.1:8080
MONAS_ACCOUNT_URL=http://127.0.0.1:4002
MONAS_PERSISTENCE_DIR=...   # recommended; otherwise CEK/shares are in-memory
```

### Endpoint & CORS

The browser calls same-origin `/api/*`, and the **Vite dev server proxies it**
to the gateway — so you never hit CORS locally. The target is configurable in
`.env` (copy `.env.example`):

```
VITE_GATEWAY_TARGET=http://127.0.0.1:3000
```

You can also repoint the gateway at runtime from the **Settings** dialog (gear
icon) — there are presets for *local (proxied)* and a *public API*. ⚠️ Pointing
at a cross-origin URL directly (not through the proxy) requires that server to
send permissive CORS headers.

## Tests

```bash
npm test                 # Playwright suite (tests/) — ~22s
npm run test:ui          # same, in the Playwright UI runner
npm run test:e2e-stack   # the full protocol happy path (e2e-verify.mjs)
```

Both need a running stack. `npm test` only needs vite + gateway + account;
`test:e2e-stack` additionally exercises the state-node round trip, so it wants
the 4-node cluster (`monas-state-node/scripts/start-local-nodes.sh` — 4 nodes,
because `create_content` excludes the creator from the member set).

Two suites, deliberately split by what they cost and what they prove:

| | `tests/` (`npm test`) | `e2e-verify.mjs` |
| --- | --- | --- |
| Proves | the **UI** behaves — every control does what it claims | the **protocol** works end to end |
| Content mutations | none (seeds `localStorage` directly) | many, against 4 real nodes |
| Runtime | ~22s | minutes |

`tests/` avoids content mutations on purpose: a create is a real crypto +
4-node round trip, so a suite that made one per scenario would take minutes and
mostly re-test the protocol that `e2e-verify.mjs` already covers. Where a
scenario needs a file to exist, it writes a registry entry into `localStorage`
and reloads.

Modal structure is asserted with **ARIA snapshots** (`toMatchAriaSnapshot`)
rather than CSS selectors, so the whole control set of a dialog is checked in
one assertion and the tests survive styling changes.

### Bugs this suite found (and now guards)

Writing the suite surfaced two defects, both since fixed. The tests are the
regression guards — reverting either fix makes them fail, which was verified
rather than assumed:

- **G-34** — with *Paste public key* selected and the field empty, *Wrap CEK &
  share* stayed enabled and did nothing: both branches of `submit()` return
  early on missing input, with no toast and no validation. The button is now
  gated on a `recipientReady` check and the empty field explains why.
- **S-07** — *Test connection* called `saveEndpoints(cfg)` before probing,
  because the probe could only read the endpoint back out of storage. Testing
  an endpoint therefore committed it, and *Reset to proxy* only resets
  component state, so a cancelled edit could not be undone from the dialog.
  `probeGateway(base?)` now takes the candidate URL, so probing has no side
  effect.

The plan the suite was generated from lives in `specs/ui-coverage.md`
(49 scenarios); the tests here cover the P0 subset that needs no fixtures.

### Extending the suite

The plan and the tests were produced with [Playwright
Agents](https://playwright.dev/docs/test-agents) — a *planner* explores the
running app and writes the plan, a *generator* turns plan entries into specs
while verifying selectors against the live UI, and a *healer* repairs tests
whose locators have drifted. The agent definitions are gitignored (they are
per-developer and must be regenerated when Playwright is updated):

```bash
npx playwright init-agents --loop=claude   # or codex | vscode | opencode
```

`tests/seed.spec.ts` is the bootstrap the planner starts from: it clears
`localStorage` and creates the signing account, without which content
operations are refused and most of the UI is unreachable.

Note that the agents are used at **authoring** time only. What runs in CI is
ordinary, deterministic Playwright code — no model is in the execution loop,
so the suite cannot go non-deterministic on a model update.

## Gateway / SDK endpoints used

| Action            | Gateway call                          | SDK model                         |
| ----------------- | ------------------------------------- | --------------------------------- |
| Create identity   | `POST /keypair`                       | `GenerateKeypair{Input,Output}`   |
| New file / Upload  | `POST /content`                       | `CreateContent{Input,Output}`     |
| Open / preview    | `GET /content/{id}`                   | `GetContent{Input,Output}`        |
| Edit contents     | `PUT /content/{id}`                   | `UpdateContent{Input,Output}`     |
| Delete            | `DELETE /content/{id}`                | `DeleteContent{Input,Output}`     |
| Share             | `POST /share`                         | `ShareContent{Input,Output}`      |
| Prove access      | `POST /share/decrypt`                 | `DecryptSharedContent{Input,Out}` |
| Revoke            | `POST /share/revoke`                  | `RevokeShare{Input,Output}`       |
| Verified read     | `POST /state/read`                    | `ReadContentFromStateNode{In,Out}`|
| (history/version) | `POST /state/history`, `/state/...`   | `state` models                    |

Notes on the contract:

- All content/keys are exchanged as **base64url (no padding)** — matching the
  SDK models.
- Responses are wrapped in the SDK `ApiResponse<T>` envelope
  (`{ success, data, error: { type, message }, trace_id }`); the client unwraps
  `data` or throws the typed error.
- `POST /content`, `PUT/DELETE /content/{id}`, `POST /share/revoke` and the
  `/state/*` calls require an **`X-Request-Timestamp`** header (the gateway
  returns 401 without it). The UI sends the current Unix time; the SDK then
  signs the state-node request via the account service.
- **Two read paths, and they prove different things.** `GET /content/{id}`
  reads the gateway's own local store — convenient, but it never touches the
  network, so it proves nothing about what the state node holds.
  `POST /state/read` fetches the version from the state node (relayed to a
  member when the contacted node isn't one) and verifies it: the Node CID is
  recomputed, the CEK decrypts it (AES-256-GCM) and the plaintext is
  re-addressed to the local id. The preview modal exposes both.
  What the verified read does *not* prove is that the version is the newest or
  that a legitimate writer produced it — version metadata has no trust anchor
  yet (issue #59).
- **Sharing is HPKE Auth mode.** `/share` and `/share/revoke` take the sender's
  *private* key (the SDK never stores it) because the wrap mixes it in;
  `/share/decrypt` correspondingly takes the sender's **public key**, not a
  self-asserted `sender_key_id`. The recipient TOFU-pins that key on the first
  envelope for a content and rejects any later envelope that doesn't match.
- **`key_epoch` must be carried through untouched.** Every revoke rotates the
  CEK and bumps the epoch, and recipients reject envelopes older than the epoch
  they've recorded (rollback replay defence). A revoke therefore also returns
  `reissued_envelopes` for the *surviving* recipients — the UI swaps those into
  its registry, because a recipient left holding the pre-rotation envelope can
  no longer decrypt.

## Accounts & the signing key

Create your account from the UI: open the identity chip (top-right) → **Create
account**. With *Register as signing account* checked, the UI sends
`POST /accounts` to **monas-account** (via the `/account-api` proxy), which
registers a **P-256** key. The SDK uses that key to sign state-node requests for
**create / edit / delete**.

This is needed because the gateway's `/keypair` is stateless — it returns a
fresh keypair (handy for share recipients) but does **not** register a signing
key. So:

- **Create account** (signing) → `POST /account-api/accounts` → monas-account.
- **Add identity** (keypair-only, e.g. a share recipient) → `POST /api/keypair`
  → gateway.

Sharing (`/share`, `/share/decrypt`, `/share/revoke`) only uses the keypairs the
UI holds, so a recipient identity doesn't need to be a signing account.

## What's real vs. illustrative

A single gateway call does the whole orchestration server-side, so the Protocol
activity panel pairs **one real call** per action with **illustrative phases**
that narrate the protocol and read ids out of the response:

- **Real:** the labelled "· gateway call" step in each run (and the share
  unwrap+decrypt proof). Errors are shown verbatim with their SDK type.
- **Illustrative:** CEK generation, CID addressing, member selection, token
  issuance, etc. — these happen *inside* the SDK call; the panel narrates them
  with a short minimum duration for readability.

## Notes

- **Folders are logical** (path prefixes). The gateway has no folder/listing
  concept, so the UI keeps its own file registry in `localStorage`
  (`monas.registry.v2`). Identities and the endpoint live there too. Clearing
  site data resets the demo.
- **Rename** of a file is local-only here (the SDK applies a new name on the
  next content edit); folder rename re-paths its descendants locally.
- Private keys for demo identities are stored in `localStorage` so the HPKE
  round-trip proof can run — fine for a local demo, not for production.

## Project layout

```
src/
  api/          gateway client (account=keypair, content, share, stateNode=state) + base64url helpers
  pipeline/     per-action flow definitions + sequential runner → drives the activity panel
  store/        localStorage-backed registry + identities (React via useSyncExternalStore)
  components/   TopBar, Sidebar, FileBrowser, PipelinePanel, modals, icons, toasts
  config.ts     single gateway endpoint (proxy default + presets)
  App.tsx       wiring: actions → pipeline → registry updates
```
