import { useState } from "react";
import { Modal } from "./Modal";
import { Folder, Pencil, FileText, Trash, Lock } from "./icons";

export function TextPromptModal({
  title,
  label,
  initial,
  confirmLabel,
  kind,
  busy,
  onConfirm,
  onClose,
}: {
  title: string;
  label: string;
  initial?: string;
  confirmLabel: string;
  kind: "folder" | "rename";
  busy?: boolean;
  onConfirm: (value: string) => void;
  onClose: () => void;
}) {
  const [value, setValue] = useState(initial || "");
  const submit = () => value.trim() && onConfirm(value.trim());
  return (
    <Modal
      title={title}
      icon={kind === "folder" ? <Folder /> : <Pencil />}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={!value.trim() || busy} onClick={submit}>
            {busy ? <span className="spinner" /> : null}
            {confirmLabel}
          </button>
        </>
      }
    >
      <div className="field">
        <label>{label}</label>
        <input
          className="input"
          autoFocus
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && submit()}
          placeholder={kind === "folder" ? "Untitled folder" : "name"}
        />
      </div>
    </Modal>
  );
}

export function FileEditorModal({
  mode,
  initialName,
  initialText,
  busy,
  onSubmit,
  onClose,
}: {
  mode: "create" | "edit";
  initialName?: string;
  initialText?: string;
  busy?: boolean;
  onSubmit: (v: { name: string; text: string }) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(initialName || "untitled.txt");
  const [text, setText] = useState(initialText ?? "");

  const valid = name.trim().length > 0;
  return (
    <Modal
      title={mode === "create" ? "New file" : `Edit “${initialName}”`}
      icon={<FileText />}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn primary"
            disabled={!valid || busy}
            onClick={() => onSubmit({ name: name.trim(), text })}
          >
            {busy ? <span className="spinner" /> : <Lock size={14} />}
            {mode === "create" ? "Encrypt & create" : "Re-encrypt & save"}
          </button>
        </>
      }
    >
      <div className="field">
        <label>File name</label>
        <input
          className="input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoFocus={mode === "create"}
        />
      </div>
      <div className="field">
        <label>Contents</label>
        <textarea
          className="input"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Type the file contents… (the SDK AES-256-CTR-encrypts this before storage)"
        />
        <div className="hint">{new Blob([text]).size} bytes · plaintext stays client-side until the gateway encrypts it</div>
      </div>
    </Modal>
  );
}

export function ConfirmModal({
  title,
  message,
  confirmLabel,
  busy,
  onConfirm,
  onClose,
}: {
  title: string;
  message: string;
  confirmLabel: string;
  busy?: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <Modal
      title={title}
      icon={<Trash />}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn danger" disabled={busy} onClick={onConfirm}>
            {busy ? <span className="spinner" /> : <Trash size={14} />}
            {confirmLabel}
          </button>
        </>
      }
    >
      <p className="muted" style={{ lineHeight: 1.55 }}>
        {message}
      </p>
    </Modal>
  );
}
