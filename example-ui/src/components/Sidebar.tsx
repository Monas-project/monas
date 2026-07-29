import type { ReactNode } from "react";
import type { Entry, View } from "../types";
import { Folder, Plus, Upload, FileText, Network, Lock } from "./icons";

// A keyboard-accessible, clickable nav row. Reuses the .nav-item styling
// (which assumes a flex div), so we keep a <div> and add button semantics.
function NavItem({
  active,
  onSelect,
  children,
}: {
  active: boolean;
  onSelect: () => void;
  children: ReactNode;
}) {
  return (
    <div
      className={`nav-item ${active ? "active" : ""}`}
      role="button"
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect();
        }
      }}
    >
      {children}
    </div>
  );
}

export function Sidebar({
  entries,
  view,
  onSelectView,
  onMyDrive,
  onNewFolder,
  onNewFile,
  onUpload,
}: {
  entries: Entry[];
  view: View;
  onSelectView: (view: View) => void;
  onMyDrive: () => void;
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
      <NavItem active={view.kind === "folder"} onSelect={onMyDrive}>
        <Folder size={17} /> My Drive
      </NavItem>

      <div className="side-label">At a glance</div>
      <NavItem active={view.kind === "all"} onSelect={() => onSelectView({ kind: "all" })}>
        <Lock size={16} /> Encrypted files
        <span style={{ marginLeft: "auto" }} className="mono">
          {files.length}
        </span>
      </NavItem>
      <NavItem active={view.kind === "synced"} onSelect={() => onSelectView({ kind: "synced" })}>
        <Network size={16} /> On state-node
        <span style={{ marginLeft: "auto" }} className="mono">
          {synced}
        </span>
      </NavItem>
      <NavItem active={view.kind === "shared"} onSelect={() => onSelectView({ kind: "shared" })}>
        <FileText size={16} /> Shared
        <span style={{ marginLeft: "auto" }} className="mono">
          {shared}
        </span>
      </NavItem>

      <div className="side-meta">
        Files are encrypted client-side (AES-256-GCM), addressed by SHA-256 CID,
        and synced to the Monas <code>state-node</code> network.
      </div>
    </nav>
  );
}
