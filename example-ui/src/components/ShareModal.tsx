import { useEffect, useState } from "react";
import { Modal } from "./Modal";
import { Share, Lock, Copy } from "./icons";
import { pushToast } from "./Toast";
import { buildSharePackage, copyText, serializeSharePackage } from "../sharePackage";
import type { Entry, Permission, ShareGrant } from "../types";

export interface ShareInput {
  recipientPublicKeyB64Url: string;
  recipientLabel?: string;
  permissions: Permission[];
}

// Sharing is always to a pasted public key. A device has exactly one account
// (see IdentityModal), so there is no second local identity to pick, and the
// recipient's private key is never on this device — the HPKE round trip is
// proven on *their* device when they import the package.
export function ShareModal({
  entry,
  busy,
  onShare,
  onRevoke,
  onClose,
}: {
  entry: Entry;
  busy: boolean;
  onShare: (entry: Entry, input: ShareInput) => void;
  onRevoke: (entry: Entry, recipientPublicKeyB64Url: string) => void;
  onClose: () => void;
}) {
  const [pubKey, setPubKey] = useState("");
  const [label, setLabel] = useState("");
  const [canWrite, setCanWrite] = useState(false);

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

  // Whether submitting can actually do anything; without this the button
  // stayed enabled and clicking it with an empty key was a silent no-op.
  const recipientReady = pubKey.trim().length > 0;

  const submit = () => {
    if (!pubKey.trim()) return;
    onShare(entry, {
      recipientPublicKeyB64Url: pubKey.trim(),
      recipientLabel: label.trim() || undefined,
      permissions,
    });
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
            title={recipientReady ? undefined : "Paste the recipient's public key"}
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
      <div className="hint" style={{ marginBottom: 10 }}>
        Ask them for the public key of their account (identity chip → <b>Copy public
        key</b> on their device) and paste it here.
      </div>

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
