import { useCallback, useEffect, useRef, useState } from "react";
import { TopBar } from "./components/TopBar";
import { Sidebar } from "./components/Sidebar";
import { FileBrowser } from "./components/FileBrowser";
import { PipelinePanel } from "./components/PipelinePanel";
import { Toasts, pushToast } from "./components/Toast";
import { Modal } from "./components/Modal";
import { TextPromptModal, FileEditorModal, ConfirmModal } from "./components/ActionModals";
import { IdentityModal } from "./components/IdentityModal";
import { SettingsModal } from "./components/SettingsModal";
import { ShareModal, type ShareInput } from "./components/ShareModal";
import { PreviewModal } from "./components/PreviewModal";

import {
  useEntries,
  entriesIn,
  addEntry,
  updateEntry,
  removeEntry,
  allEntries,
  descendantsOf,
  folderPath,
} from "./store/registry";
import { useIdentities, getActive } from "./store/identity";
import { probeGateway } from "./api/http";
import {
  uuid,
  utf8ToBase64Url,
  fileToBase64Url,
  base64UrlToUtf8,
} from "./api/crypto";
import { runPipeline } from "./pipeline/runner";
import type { RunView, StepSpec } from "./pipeline/types";
import * as flows from "./pipeline/flows";
import * as contentApi from "./api/content";
import * as shareApi from "./api/share";
import type { Entry } from "./types";

type Modal =
  | { type: "none" }
  | { type: "newFile" }
  | { type: "newFolder" }
  | { type: "rename"; entry: Entry }
  | { type: "edit"; entry: Entry; text: string }
  | { type: "delete"; entry: Entry }
  | { type: "share"; entryId: string }
  | { type: "preview"; entry: Entry; contentB64Url: string }
  | { type: "identity" }
  | { type: "settings" }
  | { type: "loadingEdit" };

function mimeFromName(name: string): string {
  const ext = name.split(".").pop()?.toLowerCase();
  const map: Record<string, string> = {
    txt: "text/plain",
    md: "text/markdown",
    json: "application/json",
    csv: "text/csv",
    html: "text/html",
    js: "text/javascript",
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    gif: "image/gif",
    svg: "image/svg+xml",
    webp: "image/webp",
  };
  return (ext && map[ext]) || "text/plain";
}

export default function App() {
  const entries = useEntries();
  const { identities, activeLabel } = useIdentities();
  const active = getActive();

  const [path, setPath] = useState("/");
  const [modal, setModal] = useState<Modal>({ type: "none" });
  const [runs, setRuns] = useState<RunView[]>([]);
  const [collapsed, setCollapsed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [gatewayUp, setGatewayUp] = useState<boolean | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  // ---- health polling -------------------------------------------------
  const poll = useCallback(async () => {
    setGatewayUp(await probeGateway());
  }, []);

  useEffect(() => {
    poll();
    const t = setInterval(poll, 6000);
    return () => clearInterval(t);
  }, [poll]);

  // ---- pipeline plumbing ----------------------------------------------
  const upsertRun = useCallback((run: RunView) => {
    setRuns((prev) => {
      const i = prev.findIndex((r) => r.id === run.id);
      if (i >= 0) {
        const copy = [...prev];
        copy[i] = run;
        return copy;
      }
      return [run, ...prev].slice(0, 15);
    });
  }, []);

  const run = useCallback(
    (op: string, target: string, specs: StepSpec[]) => {
      if (collapsed) setCollapsed(false);
      return runPipeline(op, target, specs, upsertRun);
    },
    [collapsed, upsertRun],
  );

  const current = entriesIn(path);
  const liveEntry = (id: string) => allEntries().find((e) => e.id === id);

  // ---- actions --------------------------------------------------------
  const createFromBytes = async (
    name: string,
    contentBase64Url: string,
    sizeBytes: number,
    mimeType: string,
  ) => {
    const specs = flows.createFileFlow({ name, contentBase64Url, sizeBytes, contentType: mimeType });
    const { ok, ctx } = await run("Create", name, specs);
    if (ok && ctx.create) {
      const created = ctx.create as contentApi.CreateContentOutput;
      addEntry({
        id: uuid(),
        kind: "file",
        name,
        parentPath: path,
        sizeBytes,
        mimeType,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        localContentId: created.content_id,
        remoteContentId: created.remote_content_id || undefined,
        syncedToStateNode: !!created.remote_content_id,
        versionCount: 1,
        shares: [],
      });
      pushToast(`“${name}” encrypted & created`, "success");
    } else {
      pushToast(`Failed to create “${name}”`, "error");
    }
  };

  // Creating content registers a signed request on the state-node, so a signing
  // account must exist first. Guard up front (like share does) instead of letting
  // the gateway call fail with a generic error.
  const requireSigningAccount = (): boolean => {
    if (identities.some((i) => i.isSigningAccount)) return true;
    pushToast("Create a signing account first", "error");
    setModal({ type: "identity" });
    return false;
  };

  const handleNewFile = async (v: { name: string; text: string }) => {
    if (!requireSigningAccount()) return;
    setModal({ type: "none" });
    await createFromBytes(v.name, utf8ToBase64Url(v.text), new Blob([v.text]).size, mimeFromName(v.name));
  };

  const handleUpload = async (file: File) => {
    if (!requireSigningAccount()) return;
    const b64 = await fileToBase64Url(file);
    await createFromBytes(file.name, b64, file.size, file.type || mimeFromName(file.name));
  };

  const handleNewFolder = (name: string) => {
    setModal({ type: "none" });
    addEntry({
      id: uuid(),
      kind: "folder",
      name,
      parentPath: path,
      sizeBytes: 0,
      createdAt: Date.now(),
      updatedAt: Date.now(),
      syncedToStateNode: false,
      versionCount: 0,
      shares: [],
    });
    pushToast(`Folder “${name}” created`, "success");
  };

  const handleEditOpen = async (entry: Entry) => {
    setModal({ type: "loadingEdit" });
    try {
      const res = await contentApi.getContent(entry.localContentId!);
      setModal({ type: "edit", entry, text: base64UrlToUtf8(res.content) });
    } catch (e) {
      pushToast(`Could not load contents: ${(e as Error).message}`, "error");
      setModal({ type: "edit", entry, text: "" });
    }
  };

  const handleEditSave = async (entry: Entry, v: { name: string; text: string }) => {
    setModal({ type: "none" });
    const sizeBytes = new Blob([v.text]).size;
    const renamed = v.name && v.name !== entry.name ? v.name : undefined;
    const specs = flows.updateFileFlow({
      entry,
      contentBase64Url: utf8ToBase64Url(v.text),
      sizeBytes,
      name: renamed,
    });
    const { ok, ctx } = await run("Update", renamed || entry.name, specs);
    if (ok && ctx.update) {
      const upd = ctx.update as contentApi.UpdateContentOutput;
      updateEntry(entry.id, {
        localContentId: upd.version_id,
        seriesId: upd.series_id,
        sizeBytes,
        versionCount: entry.versionCount + 1,
        ...(renamed ? { name: renamed } : {}),
      });
      pushToast(`“${renamed || entry.name}” updated`, "success");
    } else {
      pushToast("Update failed", "error");
    }
  };

  const handleDelete = async (entry: Entry) => {
    setModal({ type: "none" });
    if (entry.kind === "folder") {
      await deleteFolder(entry);
      return;
    }
    const specs = flows.deleteFileFlow({ entry });
    const { ok } = await run("Delete", entry.name, specs);
    if (ok) {
      removeEntry(entry.id);
      pushToast(`“${entry.name}” deleted`, "success");
    } else {
      pushToast("Delete failed", "error");
    }
  };

  const handleOpen = async (entry: Entry) => {
    const specs = flows.openFileFlow({ entry });
    const { ok, ctx } = await run("Open", entry.name, specs);
    if (ok && ctx.get) {
      const g = ctx.get as contentApi.GetContentOutput;
      setModal({ type: "preview", entry, contentB64Url: g.content });
    } else {
      pushToast("Could not open file", "error");
    }
  };

  const handleShare = async (entry: Entry, input: ShareInput) => {
    if (!active) {
      pushToast("Create an identity first", "error");
      setModal({ type: "identity" });
      return;
    }
    setBusy(true);
    const specs = flows.shareFlow({
      entry,
      identity: active,
      recipientPublicKeyB64Url: input.recipientPublicKeyB64Url,
      recipientLabel: input.recipientLabel,
      permissions: input.permissions,
      recipientPrivateKeyB64Url: input.recipientPrivateKeyB64Url,
    });
    const { ok, ctx } = await run("Share", entry.name, specs);
    if (ok && ctx.share) {
      const g = ctx.share as shareApi.ShareContentOutput;
      const existing = entry.shares.filter((s) => s.recipientKeyId !== g.recipient_key_id);
      updateEntry(entry.id, {
        shares: [
          ...existing,
          {
            recipientPublicKeyB64Url: input.recipientPublicKeyB64Url,
            recipientLabel: input.recipientLabel,
            permissions: input.permissions,
            senderKeyId: g.sender_key_id,
            recipientKeyId: g.recipient_key_id,
            envelope: g.key_envelope,
            grantedAt: Date.now(),
          },
        ],
      });
      pushToast(`Shared with ${input.recipientLabel || "recipient"}`, "success");
    } else {
      pushToast("Share failed", "error");
    }
    setBusy(false);
  };

  const handleRevoke = async (entry: Entry, recipientPublicKeyB64Url: string) => {
    if (!active) return;
    setBusy(true);
    const specs = flows.revokeFlow({ entry, identity: active, recipientPublicKeyB64Url });
    const { ok } = await run("Revoke", entry.name, specs);
    if (ok) {
      updateEntry(entry.id, {
        shares: entry.shares.filter((s) => s.recipientPublicKeyB64Url !== recipientPublicKeyB64Url),
      });
      pushToast("Access revoked & content re-encrypted", "success");
    } else {
      pushToast("Revoke failed", "error");
    }
    setBusy(false);
  };

  // ---- folder helpers -------------------------------------------------
  function renameFolder(entry: Entry, newName: string) {
    const oldPath = folderPath(entry.parentPath, entry.name);
    const newPath = folderPath(entry.parentPath, newName);
    updateEntry(entry.id, { name: newName });
    for (const e of allEntries()) {
      if (e.parentPath === oldPath || e.parentPath.startsWith(oldPath + "/")) {
        updateEntry(e.id, { parentPath: newPath + e.parentPath.slice(oldPath.length) });
      }
    }
  }

  async function deleteFolder(entry: Entry) {
    const here = folderPath(entry.parentPath, entry.name);
    const desc = descendantsOf(here);
    const files = desc.filter((e) => e.kind === "file");
    const specs: StepSpec[] = [
      {
        title: `Delete ${files.length} encrypted file(s)`,
        hint: "monas-sdk",
        kind: "cleanup",
        minMs: 200,
        exec: async () => {
          for (const f of files) {
            try {
              await contentApi.deleteContent({
                localContentId: f.localContentId!,
                remoteContentId: f.remoteContentId || f.localContentId!,
              });
            } catch {
              /* best effort */
            }
          }
          return `Removed ${files.length} content network(s)`;
        },
      },
      {
        title: "Remove folder & contents",
        hint: "registry",
        kind: "cleanup",
        minMs: 140,
        exec: async () => "Folder tree cleared",
      },
    ];
    const { ok } = await run("Delete folder", entry.name, specs);
    if (ok) {
      for (const e of desc) removeEntry(e.id);
      removeEntry(entry.id);
      pushToast(`Folder “${entry.name}” deleted`, "success");
    }
  }

  const handleRename = async (entry: Entry, newName: string) => {
    setModal({ type: "none" });
    if (entry.kind === "folder") {
      renameFolder(entry, newName);
      pushToast("Folder renamed", "success");
      return;
    }
    // A content rename is a metadata update; reuse the update flow with the
    // current content unchanged is not possible without bytes, so we just
    // rename locally and let the next edit carry the new name to the SDK.
    updateEntry(entry.id, { name: newName });
    pushToast("Renamed", "success");
  };

  // ---- dispatch from row menu ----------------------------------------
  const onAction = (action: string, entry: Entry) => {
    switch (action) {
      case "openFolder":
        return setPath(folderPath(entry.parentPath, entry.name));
      case "open":
        return handleOpen(entry);
      case "update":
        return handleEditOpen(entry);
      case "rename":
        return setModal({ type: "rename", entry });
      case "share":
        if (!active) {
          pushToast("Create an identity first", "error");
          return setModal({ type: "identity" });
        }
        return setModal({ type: "share", entryId: entry.id });
      case "delete":
        return setModal({ type: "delete", entry });
    }
  };

  const shareEntry = modal.type === "share" ? liveEntry(modal.entryId) : null;

  return (
    <div className="app">
      <TopBar
        gatewayUp={gatewayUp}
        identity={active}
        onOpenIdentity={() => setModal({ type: "identity" })}
        onOpenSettings={() => setModal({ type: "settings" })}
      />
      <div className="body">
        <Sidebar
          entries={entries}
          onNewFile={() => setModal({ type: "newFile" })}
          onNewFolder={() => setModal({ type: "newFolder" })}
          onUpload={() => fileInput.current?.click()}
        />
        <main className="main">
          <FileBrowser path={path} entries={current} onNavigate={setPath} onAction={onAction} />
        </main>
        <PipelinePanel
          runs={runs}
          collapsed={collapsed}
          onToggle={() => setCollapsed((c) => !c)}
          onClear={() => setRuns([])}
        />
      </div>

      <input
        ref={fileInput}
        type="file"
        style={{ display: "none" }}
        onChange={(e) => {
          const f = e.target.files?.[0];
          e.target.value = "";
          if (f) handleUpload(f);
        }}
      />

      {/* modals */}
      {modal.type === "newFile" && (
        <FileEditorModal mode="create" onSubmit={handleNewFile} onClose={() => setModal({ type: "none" })} />
      )}
      {modal.type === "newFolder" && (
        <TextPromptModal
          title="New folder"
          label="Folder name"
          confirmLabel="Create"
          kind="folder"
          onConfirm={handleNewFolder}
          onClose={() => setModal({ type: "none" })}
        />
      )}
      {modal.type === "rename" && (
        <TextPromptModal
          title={`Rename ${modal.entry.kind}`}
          label="New name"
          initial={modal.entry.name}
          confirmLabel="Rename"
          kind="rename"
          onConfirm={(v) => handleRename(modal.entry, v)}
          onClose={() => setModal({ type: "none" })}
        />
      )}
      {modal.type === "loadingEdit" && (
        <Modal title="Loading…" onClose={() => setModal({ type: "none" })}>
          <div className="center-load">
            <span className="spinner" /> Fetching & decrypting current contents…
          </div>
        </Modal>
      )}
      {modal.type === "edit" && (
        <FileEditorModal
          mode="edit"
          initialName={modal.entry.name}
          initialText={modal.text}
          onSubmit={(v) => handleEditSave(modal.entry, v)}
          onClose={() => setModal({ type: "none" })}
        />
      )}
      {modal.type === "delete" && (
        <ConfirmModal
          title={`Delete ${modal.entry.kind}`}
          message={
            modal.entry.kind === "folder"
              ? `Delete “${modal.entry.name}” and everything inside it? Encrypted blobs are removed and the Content Networks are tombstoned.`
              : `Delete “${modal.entry.name}”? This removes the encrypted blob and tombstones its Content Network on the state-node.`
          }
          confirmLabel="Delete"
          onConfirm={() => handleDelete(modal.entry)}
          onClose={() => setModal({ type: "none" })}
        />
      )}
      {modal.type === "share" && shareEntry && (
        <ShareModal
          entry={shareEntry}
          identities={identities}
          activeLabel={activeLabel}
          busy={busy}
          onShare={handleShare}
          onRevoke={handleRevoke}
          onClose={() => setModal({ type: "none" })}
        />
      )}
      {modal.type === "preview" && (
        <PreviewModal
          entry={modal.entry}
          contentB64Url={modal.contentB64Url}
          onClose={() => setModal({ type: "none" })}
        />
      )}
      {modal.type === "identity" && <IdentityModal onClose={() => setModal({ type: "none" })} />}
      {modal.type === "settings" && (
        <SettingsModal onClose={() => setModal({ type: "none" })} onSaved={poll} />
      )}

      <Toasts />
    </div>
  );
}
