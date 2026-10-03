import { useState } from "react";
import type { Entry, View } from "../types";
import { fmtBytes, fmtTime } from "../utils";
import {
  FileText,
  ImageIcon,
  FileIcon,
  More,
  Eye,
  Share,
  Pencil,
  Trash,
  Lock,
  Network,
  Cloud,
  Inbox,
} from "./icons";
import { syncStatusOf, describeSync } from "../store/sync";

// Where this copy stands against the Content Network head. One badge, four
// states, so a glance at the list says whether "Open" would show the newest
// version or whether someone (the owner, or a writer we shared with) has
// moved the file on since. The check itself runs on open and on a timer in
// App; this only renders what the entry records.
export function SyncBadge({ entry }: { entry: Entry }) {
  const s = syncStatusOf(entry);
  const d = describeSync(s);
  const cls =
    s.kind === "current"
      ? "synced"
      : s.kind === "behind"
        ? "behind"
        : s.kind === "unreachable"
          ? "invalid"
          : "";
  return (
    <span className={`badge sync ${cls}`} data-sync={s.kind} title={d.title}>
      {s.kind === "checking" ? <span className="spinner xs" /> : <Network size={11} />} {d.label}
    </span>
  );
}

function FileTypeIcon({ entry }: { entry: Entry }) {
  const mime = entry.mimeType || "";
  const Ic = mime.startsWith("image/") ? ImageIcon : mime.startsWith("text/") ? FileText : FileIcon;
  return (
    <span className="file-ic file">
      <Ic size={17} />
    </span>
  );
}

function Row({
  entry,
  open,
  onToggleMenu,
  onAction,
}: {
  entry: Entry;
  open: boolean;
  onToggleMenu: (id: string | null) => void;
  onAction: (a: string, e: Entry) => void;
}) {
  // A file shared to us: we hold an envelope, not the content, so the owner's
  // actions (edit, share on, delete on the network) are not ours to offer.
  const received = !!entry.receivedShare;
  // A write share can be edited from here: the new version goes to the
  // owner's Content Network with the delegated token, so both are needed.
  const canWrite =
    received &&
    entry.receivedShare!.permissions.includes("write") &&
    !!entry.receivedShare!.delegatedAccess;
  return (
    <div className="row" onDoubleClick={() => onAction("open", entry)}>
      <div className="name">
        <FileTypeIcon entry={entry} />
        <span className="fname">{entry.name}</span>
        <div className="badges">
          <span className="badge enc" title="Encrypted with AES-256-GCM">
            <Lock size={11} /> enc
          </span>
          {received && (
            <span
              className="badge received"
              title={`Shared with you (${entry.receivedShare!.permissions.join(", ")}) — the owner holds the file`}
            >
              <Inbox size={11} /> shared with me
            </span>
          )}
          {!received && !entry.syncedToStateNode && (
              <span className="badge local" title="Stored & encrypted, not on the state-node">
                <Cloud size={11} /> local
              </span>
            )}
          {entry.syncedToStateNode && <SyncBadge entry={entry} />}
          {entry.shares.length > 0 && (
            <span className="badge shared">
              <Share size={11} /> {entry.shares.length}
            </span>
          )}
        </div>
      </div>
      <div className="muted">{entry.mimeType || "file"}</div>
      <div className="muted">{fmtBytes(entry.sizeBytes)}</div>
      <div className="muted">{fmtTime(entry.updatedAt)}</div>
      <div className="row-menu-wrap">
        <button
          className="icon-btn"
          onClick={(e) => {
            e.stopPropagation();
            onToggleMenu(open ? null : entry.id);
          }}
        >
          <More />
        </button>
        {open && (
          <div className="menu" onClick={(e) => e.stopPropagation()}>
            <button onClick={() => onAction("open", entry)}>
              <Eye size={15} /> Open / preview
            </button>
            {(!received || canWrite) && (
              <button onClick={() => onAction("update", entry)}>
                <Pencil size={15} /> Edit contents
              </button>
            )}
            {!received && (
              <button onClick={() => onAction("share", entry)}>
                <Share size={15} /> Share
              </button>
            )}
            <div className="menu-sep" />
            {received ? (
              <button className="danger" onClick={() => onAction("delete", entry)}>
                <Trash size={15} /> Remove from my Drive
              </button>
            ) : (
              <button className="danger" onClick={() => onAction("delete", entry)}>
                <Trash size={15} /> Delete
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

const VIEW_TITLES: Record<View["kind"], string> = {
  drive: "My Drive",
  all: "Encrypted files",
  synced: "On state-node",
  shared: "Shared",
};

export function FileBrowser({
  view,
  entries,
  onAction,
}: {
  view: View;
  entries: Entry[];
  onAction: (action: string, entry: Entry) => void;
}) {
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const filtered = view.kind !== "drive";

  return (
    <>
      <div className="toolbar">
        <div className="crumbs">
          <span className="crumb last">{VIEW_TITLES[view.kind]}</span>
        </div>
      </div>

      {entries.length === 0 ? (
        <div className="empty">
          <span className="big">
            <FileIcon size={30} />
          </span>
          <h3>{filtered ? "No matching files" : "No files yet"}</h3>
          <p className="muted">
            {filtered
              ? "Nothing matches this view yet. Files appear here once they're encrypted, synced to a state-node, or shared."
              : "Create a file or upload one — it gets encrypted and addressed by CID before anything leaves the client."}
          </p>
        </div>
      ) : (
        <div className="scroll" onClick={() => setOpenMenu(null)}>
          <div className="list-head">
            <div>Name</div>
            <div>Type</div>
            <div>Size</div>
            <div>Modified</div>
            <div />
          </div>
          {entries.map((e) => (
            <Row
              key={e.id}
              entry={e}
              open={openMenu === e.id}
              onToggleMenu={setOpenMenu}
              onAction={(a, en) => {
                setOpenMenu(null);
                onAction(a, en);
              }}
            />
          ))}
        </div>
      )}
    </>
  );
}
