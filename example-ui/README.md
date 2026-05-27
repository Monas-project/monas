# Monas Drive — example UI

A minimal, Google-Drive-like web UI for the Monas protocol, built on the
**monas-sdk** via the **monas-gateway** HTTP API. It lets you **create, open,
edit, rename, share, revoke and delete** files and folders, and surfaces the
encryption + state-node work behind every action in a live **Protocol activity**
panel (CEK → AES-256-CTR → SHA-256 CID → storage → state-node → HPKE).

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
| (history/version) | `POST /state/history`, `/state/...`   | `state` models                    |

Notes on the contract:

- All content/keys are exchanged as **base64url (no padding)** — matching the
  SDK models.
- Responses are wrapped in the SDK `ApiResponse<T>` envelope
  (`{ success, data, error: { type, message }, trace_id }`); the client unwraps
  `data` or throws the typed error.
- `POST /content`, `PUT/DELETE /content/{id}`, `POST /share/revoke` and the
  `/state/*` calls require an **`X-Request-Timestamp`** header. The UI sends the
  current Unix time; the SDK then signs the state-node request via the account
  service.

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
