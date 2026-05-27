import { useState } from "react";
import { Modal } from "./Modal";
import { Share, Lock } from "./icons";
import type { Entry, Identity, Permission } from "../types";

export interface ShareInput {
  recipientPublicKeyB64Url: string;
  recipientLabel?: string;
  permissions: Permission[];
  recipientPrivateKeyB64Url?: string;
}

export function ShareModal({
  entry,
  identities,
  activeLabel,
  busy,
  onShare,
  onRevoke,
  onClose,
}: {
  entry: Entry;
  identities: Identity[];
  activeLabel: string | null;
  busy: boolean;
  onShare: (entry: Entry, input: ShareInput) => void;
  onRevoke: (entry: Entry, recipientPublicKeyB64Url: string) => void;
  onClose: () => void;
}) {
  const others = identities.filter((i) => i.label !== activeLabel);
  const [mode, setMode] = useState<"identity" | "key">(
    others.length > 0 ? "identity" : "key",
  );
  const [pickLabel, setPickLabel] = useState(others[0]?.label || "");
  const [pubKey, setPubKey] = useState("");
  const [label, setLabel] = useState("");
  const [canWrite, setCanWrite] = useState(false);
  const [verify, setVerify] = useState(true);

  const permissions: Permission[] = canWrite ? ["read", "write"] : ["read"];

  const submit = () => {
    if (mode === "identity") {
      const who = others.find((i) => i.label === pickLabel);
      if (!who) return;
      onShare(entry, {
        recipientPublicKeyB64Url: who.publicKeyB64Url,
        recipientLabel: who.label,
        permissions,
        recipientPrivateKeyB64Url: verify ? who.privateKeyB64Url : undefined,
      });
    } else {
      if (!pubKey.trim()) return;
      onShare(entry, {
        recipientPublicKeyB64Url: pubKey.trim(),
        recipientLabel: label.trim() || undefined,
        permissions,
      });
    }
  };

  return (
    <Modal
      title={`Share “${entry.name}”`}
      icon={<Share />}
      onClose={onClose}
      wide
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Close
          </button>
          <button className="btn primary" disabled={busy} onClick={submit}>
            {busy ? <span className="spinner" /> : <Lock size={14} />} Wrap CEK & share
          </button>
        </>
      }
    >
      {entry.shares.length > 0 && (
        <>
          <div style={{ fontWeight: 650, fontSize: 13, marginBottom: 4 }}>
            Shared with
          </div>
          {entry.shares.map((s) => (
            <div className="recipient-row" key={s.recipientKeyId}>
              <span className="avatar">
                {(s.recipientLabel || "??").slice(0, 2).toUpperCase()}
              </span>
              <div className="grow">
                <div style={{ fontWeight: 600 }}>
                  {s.recipientLabel || "external recipient"}{" "}
                  {s.permissions.map((p) => (
                    <span className="badge" key={p}>
                      {p}
                    </span>
                  ))}
                </div>
                <div className="mono" style={{ fontSize: 10.5 }}>
                  KeyId {s.recipientKeyId}
                </div>
              </div>
              <button
                className="btn sm danger"
                disabled={busy}
                onClick={() => onRevoke(entry, s.recipientPublicKeyB64Url)}
              >
                Revoke
              </button>
            </div>
          ))}
          <div style={{ height: 14 }} />
        </>
      )}

      <div style={{ fontWeight: 650, fontSize: 13, marginBottom: 8 }}>
        Add recipient
      </div>

      <div className="seg" style={{ marginBottom: 14 }}>
        <button
          className={mode === "identity" ? "on" : ""}
          onClick={() => setMode("identity")}
          disabled={others.length === 0}
        >
          Pick identity {others.length === 0 ? "(none)" : ""}
        </button>
        <button className={mode === "key" ? "on" : ""} onClick={() => setMode("key")}>
          Paste public key
        </button>
      </div>

      {mode === "identity" ? (
        <div className="field">
          <label>Recipient identity</label>
          <select
            className="select"
            value={pickLabel}
            onChange={(e) => setPickLabel(e.target.value)}
          >
            {others.map((i) => (
              <option key={i.label} value={i.label}>
                {i.label} · {i.keyType}
              </option>
            ))}
          </select>
          <label
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginTop: 10,
              fontWeight: 500,
              textTransform: "none",
              color: "var(--text)",
            }}
          >
            <input type="checkbox" checked={verify} onChange={(e) => setVerify(e.target.checked)} />
            Prove access: unwrap CEK & decrypt as the recipient
          </label>
        </div>
      ) : (
        <>
          <div className="field">
            <label>Recipient public key (base64url)</label>
            <textarea
              className="input"
              value={pubKey}
              onChange={(e) => setPubKey(e.target.value)}
              placeholder="P-256 public key, base64url (from the gateway /keypair)"
            />
          </div>
          <div className="field">
            <label>Label (optional)</label>
            <input className="input" value={label} onChange={(e) => setLabel(e.target.value)} />
          </div>
        </>
      )}

      <div className="field">
        <label>Permission</label>
        <div className="seg">
          <button className={!canWrite ? "on" : ""} onClick={() => setCanWrite(false)}>
            read
          </button>
          <button className={canWrite ? "on" : ""} onClick={() => setCanWrite(true)}>
            read + write
          </button>
        </div>
      </div>
    </Modal>
  );
}
