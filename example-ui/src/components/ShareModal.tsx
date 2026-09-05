import { useEffect, useState } from "react";
import { Modal } from "./Modal";
import { Share, Lock, Copy } from "./icons";
import { pushToast } from "./Toast";
import { buildSharePackage, copyText, serializeSharePackage } from "../sharePackage";
import type { Entry, Identity, Permission, ShareGrant } from "../types";

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
  // Off by default: proving access decrypts as the recipient, and the SDK
  // stores the CEK it recovers under this content id — the same slot the owner
  // reads from. After a revoke rotates the CEK, the owner is then left holding
  // the recipient's stale copy and can no longer read their own file. Useful to
  // demonstrate the HPKE round trip, but it is not free.
  const [verify, setVerify] = useState(false);

  const permissions: Permission[] = canWrite ? ["read", "write"] : ["read"];

  // The share package for one recipient, shown as text so it can always be
  // selected and copied by hand — the clipboard API is not available in every
  // browser context, and the whole point is to paste this into a chat.
  // Opens by itself for whichever grant was added or re-wrapped last, since
  // that is the one the owner now has to deliver.
  const [packageFor, setPackageFor] = useState<string | null>(null);
  const newest = entry.shares.reduce<ShareGrant | null>(
    (best, s) =>
      !best || (s.reissuedAt ?? s.grantedAt) > (best.reissuedAt ?? best.grantedAt) ? s : best,
    null,
  );
  const newestStamp = newest ? `${newest.recipientKeyId}:${newest.reissuedAt ?? newest.grantedAt}` : null;
  // Keyed on the stamp, not the grant object: re-open when a grant is added
  // or reissued, not on every render.
  useEffect(() => {
    if (newestStamp) setPackageFor(newestStamp.split(":")[0]);
  }, [newestStamp]);

  const copyPackage = async (grant: ShareGrant) => {
    const text = serializeSharePackage(buildSharePackage(entry, grant));
    if (await copyText(text)) {
      pushToast(`Share package for ${grant.recipientLabel || "recipient"} copied`, "success");
    } else {
      setPackageFor(grant.recipientKeyId);
      pushToast("Clipboard unavailable — select the package text below to copy it", "error");
    }
  };

  // Whether submitting can actually do anything. Both branches of submit()
  // bail out early when their input is missing, so without this the button
  // stayed enabled and clicking it was a silent no-op.
  const recipientReady =
    mode === "identity"
      ? others.some((i) => i.label === pickLabel)
      : pubKey.trim().length > 0;

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
          <button
            className="btn primary"
            disabled={busy || !recipientReady}
            title={recipientReady ? undefined : "Choose a recipient identity or paste a public key"}
            onClick={submit}
          >
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
                  KeyId {s.recipientKeyId} · epoch {s.envelope.key_epoch}
                  {s.reissuedAt ? " · re-wrapped after a revoke" : ""}
                </div>
              </div>
              <button
                className="btn sm"
                title="Copy the share package to send to this recipient"
                onClick={() => copyPackage(s)}
              >
                <Copy size={13} /> Copy package
              </button>
              <button
                className="btn sm danger"
                disabled={busy}
                onClick={() => onRevoke(entry, s.recipientPublicKeyB64Url)}
              >
                Revoke
              </button>
            </div>
          ))}
          {packageFor &&
            (() => {
              const grant = entry.shares.find((s) => s.recipientKeyId === packageFor);
              if (!grant) return null;
              return (
                <div className="field share-package" style={{ marginTop: 10 }}>
                  <label>
                    Share package for {grant.recipientLabel || "recipient"} — send this to them
                    {grant.reissuedAt ? " (re-wrapped: the old one no longer opens)" : ""}
                  </label>
                  <textarea
                    className="input mono"
                    readOnly
                    rows={5}
                    value={serializeSharePackage(buildSharePackage(entry, grant))}
                    onFocus={(e) => e.currentTarget.select()}
                    style={{ fontSize: 10.5 }}
                  />
                  <div className="hint">
                    Any channel works (chat, mail). The recipient pastes it into{" "}
                    <b>Import shared</b> on their own device. It carries the content key
                    wrapped to their key only, so it is useless to anyone else — but treat
                    it like a link to the file.
                  </div>
                </div>
              );
            })()}
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
          <div className="hint">
            Decrypts as the recipient to show the HPKE round trip really works.
            It also replaces the locally stored CEK for this content with the
            recipient's copy, so a later revoke — which rotates the CEK — leaves
            you unable to read your own file until you share it again.
          </div>
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
            {!pubKey.trim() && (
              <div className="hint">
                Paste a recipient public key to enable sharing.
              </div>
            )}
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
