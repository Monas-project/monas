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
import { ImportShareModal } from "./components/ImportShareModal";
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
import { checkNetworkHead, checkAllNetworkHeads } from "./store/sync";
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
import * as stateApi from "./api/stateNode";
import type { Entry, Identity, SharePackage, View } from "./types";

type Modal =
  | { type: "none" }
  | { type: "newFile" }
  | { type: "newFolder" }
  | { type: "rename"; entry: Entry }
  | { type: "edit"; entry: Entry; text: string }
  | { type: "delete"; entry: Entry }
  | { type: "share"; entryId: string }
  | { type: "importShare" }
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
  const { identities } = useIdentities();
  const active = getActive();

  const [path, setPath] = useState("/");
  const [view, setView] = useState<View>({ kind: "folder" });
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

  // Sync-status sweep: a verified read of every synced file's head, shortly
  // after load and then every 30 s while the gateway is up. Sequential and
  // slow on purpose — the state node rate-limits — but it is what lets the
  // list say "newer on network" without anyone pressing a button. The first
  // run is deferred a few seconds so it never races the initial render (and
  // the tests' localStorage seeding, which reloads right after writing).
  useEffect(() => {
    if (!gatewayUp) return;
    let stopped = false;
    const sweep = async () => {
      if (!stopped) await checkAllNetworkHeads();
    };
    const first = setTimeout(sweep, 5_000);
    const t = setInterval(sweep, 30_000);
    return () => {
      stopped = true;
      clearTimeout(first);
      clearInterval(t);
    };
  }, [gatewayUp]);

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

  // Changing the folder path always implies normal folder browsing, so this
  // wrapper also drops any active filter view.
  const navigateTo = useCallback((p: string) => {
    setPath(p);
    setView({ kind: "folder" });
  }, []);

  // What the browser shows: folder view = direct children of `path`; the filter
  // views are flat, drive-wide file listings. Derived from the reactive
  // `entries` so it updates live on create/share/sync/delete.
  const current =
    view.kind === "folder"
      ? entriesIn(path)
      : entries
          .filter((e) => e.kind === "file")
          .filter((e) =>
            view.kind === "all"
              ? true
              : view.kind === "synced"
                ? e.syncedToStateNode
                : e.shares.length > 0 || !!e.receivedShare,
          )
          .sort((a, b) => a.name.localeCompare(b.name));

  const liveEntry = (id: string) => allEntries().find((e) => e.id === id);

  // Right after this device wrote a version, it *is* the head — record that
  // so the row reads "up to date" without a round trip. The Node CID is not
  // known here (writes return plain ids); the next check fills it in.
  const ownHead = (localId: string) => ({
    networkHead: { localId, checkedAt: Date.now() },
    networkCheckError: undefined,
  });

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
        ...(created.remote_content_id ? ownHead(created.content_id) : {}),
      });
      // Drop back to folder browsing so the new file is visible at `path`
      // (it wouldn't match an active filter view yet).
      setView({ kind: "folder" });
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
    setView({ kind: "folder" });
    pushToast(`Folder “${name}” created`, "success");
  };

  const handleEditOpen = async (entry: Entry) => {
    setModal({ type: "loadingEdit" });
    try {
      let text: string;
      if (entry.receivedShare) {
        // A received share is edited from the owner's *newest* version, not
        // from the one the envelope carried: the gateway has no local copy of
        // it anyway, and the state node is where the recipient's write lands.
        text = (
          await stateApi.readFromStateNode({
            contentId: entry.remoteContentId!,
            localContentId: entry.localContentId!,
            acceptAnyVersion: true,
            auth: { delegatedToken: entry.receivedShare.delegatedAccess!.delegated_token },
          })
        ).content;
      } else if (entry.syncedToStateNode && entry.remoteContentId) {
        // The owner's local copy may be behind the Content Network: a
        // recipient with write access can have edited since. Pull the head
        // into the local record first, so the edit starts from — and the
        // update is applied over — their version instead of silently
        // overwriting it.
        const pulled = await stateApi.pullFromStateNode({
          contentId: entry.remoteContentId,
          localContentId: entry.localContentId!,
        });
        if (pulled.adopted) {
          updateEntry(entry.id, {
            localContentId: pulled.local_content_id,
            versionCount: entry.versionCount + 1,
            ...ownHead(pulled.local_content_id),
          });
          entry = { ...entry, localContentId: pulled.local_content_id };
          pushToast("Pulled a newer version written by a recipient into your copy", "info");
        } else {
          updateEntry(entry.id, ownHead(pulled.local_content_id));
        }
        text = pulled.content;
      } else {
        text = (await contentApi.getContent(entry.localContentId!)).content;
      }
      setModal({ type: "edit", entry, text: base64UrlToUtf8(text) });
    } catch (e) {
      pushToast(`Could not load contents: ${(e as Error).message}`, "error");
      setModal({ type: "edit", entry, text: "" });
    }
  };

  // Recipient side of a write share: the new plaintext goes straight to the
  // owner's Content Network under the delegated token. The name field of the
  // editor is local here — a recipient cannot rename the owner's file.
  const handleReceivedEditSave = async (entry: Entry, v: { name: string; text: string }) => {
    setModal({ type: "none" });
    const sizeBytes = new Blob([v.text]).size;
    const specs = flows.updateReceivedFlow({
      entry,
      contentBase64Url: utf8ToBase64Url(v.text),
      sizeBytes,
    });
    const { ok, ctx } = await run("Update (as recipient)", entry.name, specs);
    if (ok && ctx.update) {
      const upd = ctx.update as shareApi.UpdateSharedContentOutput;
      updateEntry(entry.id, {
        sizeBytes,
        versionCount: entry.versionCount + 1,
        receivedShare: { ...entry.receivedShare!, writtenVersionId: upd.version_id },
        ...ownHead(upd.version_id),
      });
      pushToast(`“${entry.name}” updated on the owner's Content Network`, "success");
    } else {
      pushToast("Update failed", "error");
    }
  };

  const handleEditSave = async (entry: Entry, v: { name: string; text: string }) => {
    if (entry.receivedShare) return handleReceivedEditSave(entry, v);
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
        ...(entry.syncedToStateNode ? ownHead(upd.version_id) : {}),
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
    // A received share is the owner's content; "delete" here only forgets it
    // locally. The gateway keeps the pinned sender key + CEK, which is fine:
    // re-importing the same package simply works again.
    if (entry.receivedShare) {
      removeEntry(entry.id);
      pushToast(`“${entry.name}” removed from your Drive (the owner's copy is untouched)`, "success");
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
    let specs: StepSpec[];
    if (entry.receivedShare) {
      const recipient = identities.find(
        (i) => i.publicKeyB64Url === entry.receivedShare!.recipientPublicKeyB64Url,
      );
      if (!recipient) {
        pushToast(
          `The identity “${entry.receivedShare.recipientLabel}” this share was addressed to is no longer in this browser`,
          "error",
        );
        return;
      }
      specs = flows.openReceivedFlow({ entry, recipient });
    } else {
      specs = flows.openFileFlow({ entry });
    }
    const { ok, ctx } = await run("Open", entry.name, specs);
    if (ok && ctx.get) {
      const g = ctx.get as { content: string };
      setModal({ type: "preview", entry, contentB64Url: g.content });
      void checkNetworkHead(entry);
    } else {
      pushToast("Could not open file", "error");
    }
  };

  // Recipient side of a cross-device share: the package came in over chat or
  // mail, the identity it names is one of ours, and the gateway unwraps it.
  const handleImportShare = async (pkg: SharePackage, recipient: Identity) => {
    setBusy(true);
    const specs = flows.importShareFlow({ pkg, recipient });
    const { ok, ctx } = await run("Import share", pkg.name, specs);
    setBusy(false);
    if (!ok || !ctx.imported) {
      pushToast(`Could not import “${pkg.name}”`, "error");
      return;
    }
    const res = ctx.imported as shareApi.DecryptSharedContentOutput;
    // Re-importing (a re-wrapped envelope after a revoke, or a fresh package
    // after the owner edited) replaces the earlier entry for the same content
    // rather than adding a twin. The owner's content id changes with every
    // edit, so match on the Content Network (series) when the package names
    // one, and fall back to the content id for local-only content.
    const existing = allEntries().find(
      (e) =>
        e.receivedShare &&
        (pkg.remote_content_id
          ? e.remoteContentId === pkg.remote_content_id
          : e.localContentId === pkg.content_id),
    );
    const receivedShare = {
      senderPublicKeyB64Url: pkg.sender_public_key,
      recipientPublicKeyB64Url: recipient.publicKeyB64Url,
      recipientLabel: recipient.label,
      recipientKeyId: pkg.recipient_key_id,
      permissions: pkg.permissions,
      envelope: pkg.key_envelope,
      delegatedAccess: pkg.delegated_access,
      receivedAt: Date.now(),
    };
    let entry: Entry;
    if (existing) {
      // The SDK filed the CEK under the package's content id (the owner's
      // current version), so that is the id later reads must select by.
      const patch = {
        receivedShare,
        name: pkg.name,
        sizeBytes: pkg.sizeBytes,
        localContentId: pkg.content_id,
        versionCount: existing.versionCount + (existing.localContentId !== pkg.content_id ? 1 : 0),
      };
      updateEntry(existing.id, patch);
      entry = { ...existing, ...patch };
    } else {
      entry = {
        id: uuid(),
        kind: "file",
        name: pkg.name,
        parentPath: "/",
        sizeBytes: pkg.sizeBytes,
        mimeType: pkg.mimeType || res.metadata?.content_type || mimeFromName(pkg.name),
        createdAt: Date.now(),
        updatedAt: Date.now(),
        localContentId: pkg.content_id,
        remoteContentId: pkg.remote_content_id,
        syncedToStateNode: !!pkg.remote_content_id,
        versionCount: 1,
        shares: [],
        receivedShare,
      };
      addEntry(entry);
    }
    setView({ kind: "folder" });
    setPath("/");
    pushToast(`“${pkg.name}” unwrapped and added to your Drive`, "success");
    setModal({ type: "preview", entry, contentB64Url: res.content });
    // The envelope carries the version the owner shared; whether that is
    // still the head only the network knows.
    void checkNetworkHead(entry);
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
            senderPublicKeyB64Url: g.sender_public_key,
            envelope: g.key_envelope,
            delegatedAccess: g.delegated_access,
            grantedAt: Date.now(),
          },
        ],
      });
      pushToast(`Shared with ${input.recipientLabel || "recipient"} — copy the package to send it`, "success");
    } else {
      pushToast("Share failed", "error");
    }
    setBusy(false);
  };

  const handleRevoke = async (entry: Entry, recipientPublicKeyB64Url: string) => {
    if (!active) return;
    setBusy(true);
    const specs = flows.revokeFlow({ entry, identity: active, recipientPublicKeyB64Url });
    const { ok, ctx } = await run("Revoke", entry.name, specs);
    if (ok) {
      const r = ctx.revoke as shareApi.RevokeShareOutput | undefined;
      // Revoking rotates the CEK, so every *surviving* recipient's envelope is
      // reissued under the new key_epoch. Keeping the old envelope would leave
      // them unable to decrypt, and re-presenting it is rejected as a
      // rollback replay — so swap in the reissued one, keyed by recipientKeyId.
      const reissued = new Map((r?.reissued_envelopes ?? []).map((e) => [e.recipient_key_id, e]));
      const shares = entry.shares
        .filter((s) => s.recipientPublicKeyB64Url !== recipientPublicKeyB64Url)
        .map((s) => {
          const fresh = reissued.get(s.recipientKeyId);
          // The survivor's token was voided along with the revoked one's, so
          // the fresh package must carry the reissued token, not the old one.
          return fresh
            ? {
                ...s,
                envelope: fresh.key_envelope,
                delegatedAccess: fresh.delegated_access ?? undefined,
                reissuedAt: Date.now(),
              }
            : s;
        });
      // The SDK pulls the Content Network head before rotating, so if a
      // write-share recipient had edited since our last save, the local
      // record — and its id — moved to their version.
      const moved = r && r.content_id !== entry.localContentId;
      updateEntry(entry.id, {
        shares,
        ...(moved ? { localContentId: r.content_id, versionCount: entry.versionCount + 1 } : {}),
        // The SDK just re-encrypted under the new CEK and wrote that as the
        // head, so whatever id the local record now has is the network head.
        ...(r && entry.syncedToStateNode ? ownHead(r.content_id) : {}),
      });

      if (r?.head_pull_error) {
        pushToast(
          `Revoked from the local copy: the Content Network head could not be pulled first (${r.head_pull_error}). A recipient's newer version may have been overwritten.`,
          "error",
        );
      }

      const stale = shares.filter((s) => !reissued.has(s.recipientKeyId)).length;
      const cutoff = r?.token_invalidated_at
        ? ` · tokens issued before ${new Date(r.token_invalidated_at * 1000).toLocaleTimeString()} are void`
        : "";
      pushToast(
        `Access revoked & content re-encrypted${cutoff}`,
        // A surviving recipient with no reissued envelope can no longer read;
        // that is a real problem for the demo, so don't report it as success.
        stale > 0 ? "error" : "success",
      );
      // The cutoff is enforced per member, on each member's own copy of the
      // policy; a member it did not reach still accepts writes under the
      // voided tokens until its next sync. Say so — "revoked" alone would
      // overstate what just happened.
      const reach = r?.token_invalidation_reach;
      if (reach?.relayed) {
        pushToast(
          "The revoke was relayed to a member node; which members enforce the cutoff yet is not known from here. Writes under the old token may land on members that have not synced.",
          "error",
        );
      } else if (reach && reach.unreached_members.length > 0) {
        pushToast(
          `Cutoff did not reach ${reach.unreached_members.length} member node(s). Until they sync (~30 s), a write under the revoked token can still land there.`,
          "error",
        );
      }
      if (stale > 0) {
        pushToast(
          `${stale} other recipient(s) got no reissued envelope and can no longer decrypt`,
          "error",
        );
      }
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

  // Folders are purely local organization, so renaming one never touches the
  // protocol. Files deliberately have no Rename action: a file's name reaches
  // the SDK only through an update, so the honest rename path is the name
  // field in "Edit contents".
  const handleRename = async (entry: Entry, newName: string) => {
    setModal({ type: "none" });
    renameFolder(entry, newName);
    pushToast("Folder renamed", "success");
  };

  // ---- dispatch from row menu ----------------------------------------
  const onAction = (action: string, entry: Entry) => {
    switch (action) {
      case "openFolder":
        return navigateTo(folderPath(entry.parentPath, entry.name));
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
          view={view}
          onSelectView={setView}
          onMyDrive={() => navigateTo("/")}
          onNewFile={() => setModal({ type: "newFile" })}
          onNewFolder={() => setModal({ type: "newFolder" })}
          onUpload={() => fileInput.current?.click()}
          onImportShare={() => setModal({ type: "importShare" })}
        />
        <main className="main">
          <FileBrowser path={path} view={view} entries={current} onNavigate={navigateTo} onAction={onAction} />
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
          title="Rename folder"
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
          title={modal.entry.receivedShare ? "Remove from my Drive" : `Delete ${modal.entry.kind}`}
          message={
            modal.entry.receivedShare
              ? `Remove “${modal.entry.name}” from your Drive? It was shared with you; the owner's file and its Content Network are untouched, and you can import the package again later.`
              : modal.entry.kind === "folder"
                ? `Delete “${modal.entry.name}” and everything inside it? Encrypted blobs are removed and the Content Networks are tombstoned.`
                : `Delete “${modal.entry.name}”? This removes the encrypted blob and tombstones its Content Network on the state-node.`
          }
          confirmLabel={modal.entry.receivedShare ? "Remove" : "Delete"}
          onConfirm={() => handleDelete(modal.entry)}
          onClose={() => setModal({ type: "none" })}
        />
      )}
      {modal.type === "share" && shareEntry && (
        <ShareModal
          entry={shareEntry}
          busy={busy}
          onShare={handleShare}
          onRevoke={handleRevoke}
          onClose={() => setModal({ type: "none" })}
        />
      )}
      {modal.type === "importShare" && (
        <ImportShareModal
          identities={identities}
          busy={busy}
          onImport={handleImportShare}
          onClose={() => setModal({ type: "none" })}
        />
      )}
      {modal.type === "preview" && (
        <PreviewModal
          entry={liveEntry(modal.entry.id) ?? modal.entry}
          contentB64Url={modal.contentB64Url}
          onCheckHead={checkNetworkHead}
          onEdit={(e) => handleEditOpen(e)}
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
