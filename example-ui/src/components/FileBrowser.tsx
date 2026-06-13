import { useState } from "react";
import type { Entry } from "../types";
import { fmtBytes, fmtTime, crumbsFor } from "../utils";
import {
  Folder,
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
} from "./icons";

function FileTypeIcon({ entry }: { entry: Entry }) {
  if (entry.kind === "folder")
    return (
      <span className="file-ic folder">
        <Folder size={17} />
      </span>
    );
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
  const isFile = entry.kind === "file";
  return (
    <div
      className="row"
      onDoubleClick={() => onAction(isFile ? "open" : "openFolder", entry)}
    >
      <div className="name">
        <FileTypeIcon entry={entry} />
        <span className="fname">{entry.name}</span>
        <div className="badges">
          {isFile && (
            <span className="badge enc" title="Encrypted with AES-256-CTR">
              <Lock size={11} /> enc
            </span>
          )}
          {isFile &&
            (entry.syncedToStateNode ? (
              <span className="badge synced" title="Synced to a Content Network">
                <Network size={11} /> synced
              </span>
            ) : (
              <span className="badge local" title="Stored & encrypted, not on the state-node">
                <Cloud size={11} /> local
              </span>
            ))}
          {isFile && entry.shares.length > 0 && (
            <span className="badge shared">
              <Share size={11} /> {entry.shares.length}
            </span>
          )}
        </div>
      </div>
      <div className="muted">
        {entry.kind === "folder" ? "Folder" : entry.mimeType || "file"}
      </div>
      <div className="muted">{isFile ? fmtBytes(entry.sizeBytes) : "—"}</div>
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
            {isFile && (
              <button onClick={() => onAction("open", entry)}>
                <Eye size={15} /> Open / preview
              </button>
            )}
            {!isFile && (
              <button onClick={() => onAction("openFolder", entry)}>
                <Folder size={15} /> Open folder
              </button>
            )}
            {isFile && (
              <button onClick={() => onAction("update", entry)}>
                <Pencil size={15} /> Edit contents
              </button>
            )}
            <button onClick={() => onAction("rename", entry)}>
              <Pencil size={15} /> Rename
            </button>
            {isFile && (
              <button onClick={() => onAction("share", entry)}>
                <Share size={15} /> Share
              </button>
            )}
            <div className="menu-sep" />
            <button className="danger" onClick={() => onAction("delete", entry)}>
              <Trash size={15} /> Delete
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

export function FileBrowser({
  path,
  entries,
  onNavigate,
  onAction,
}: {
  path: string;
  entries: Entry[];
  onNavigate: (path: string) => void;
  onAction: (action: string, entry: Entry) => void;
}) {
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const crumbs = crumbsFor(path);

  return (
    <>
      <div className="toolbar">
        <div className="crumbs">
          {crumbs.map((c, i) => (
            <span key={c.path} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
              {i > 0 && <span className="sep">›</span>}
              <span
                className={`crumb ${i === crumbs.length - 1 ? "last" : ""}`}
                onClick={() => i < crumbs.length - 1 && onNavigate(c.path)}
              >
                {c.name}
              </span>
            </span>
          ))}
        </div>
      </div>

      {entries.length === 0 ? (
        <div className="empty">
          <span className="big">
            <Folder size={30} />
          </span>
          <h3>This folder is empty</h3>
          <p className="muted">
            Create a file or upload one — it gets encrypted and addressed by CID
            before anything leaves the client.
          </p>
        </div>
      ) : (
        <div className="scroll" onClick={() => setOpenMenu(null)}>
          <div className="list-head">
            <div>Name</div>
            <div>Location</div>
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
