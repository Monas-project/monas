import type { Entry } from "../types";
import { Folder, Plus, Upload, FileText, Network, Lock } from "./icons";

export function Sidebar({
  entries,
  onNewFolder,
  onNewFile,
  onUpload,
}: {
  entries: Entry[];
  onNewFolder: () => void;
  onNewFile: () => void;
  onUpload: () => void;
}) {
  const files = entries.filter((e) => e.kind === "file");
  const synced = files.filter((e) => e.syncedToStateNode).length;
  const shared = files.filter((e) => e.shares.length > 0).length;

  return (
    <nav className="sidebar">
      <div className="side-new" style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <button className="btn primary" onClick={onNewFile}>
          <Plus size={15} /> New file
        </button>
        <button className="btn" onClick={onUpload}>
          <Upload size={15} /> Upload
        </button>
        <button className="btn" onClick={onNewFolder}>
          <Folder size={15} /> New folder
        </button>
      </div>

      <div className="side-label">Library</div>
      <div className="nav-item active">
        <Folder size={17} /> My Drive
      </div>

      <div className="side-label">At a glance</div>
      <div className="nav-item">
        <Lock size={16} /> Encrypted files
        <span style={{ marginLeft: "auto" }} className="mono">
          {files.length}
        </span>
      </div>
      <div className="nav-item">
        <Network size={16} /> On state-node
        <span style={{ marginLeft: "auto" }} className="mono">
          {synced}
        </span>
      </div>
      <div className="nav-item">
        <FileText size={16} /> Shared
        <span style={{ marginLeft: "auto" }} className="mono">
          {shared}
        </span>
      </div>

      <div className="side-meta">
        Files are encrypted client-side (AES-256-CTR), addressed by SHA-256 CID,
        and synced to the Monas <code>state-node</code> network.
      </div>
    </nav>
  );
}
