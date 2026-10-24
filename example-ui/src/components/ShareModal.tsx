import { useState } from "react";
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

const READ: Permission[] = ["read"];
const READ_WRITE: Permission[] = ["read", "write"];
const hasWrite = (p: Permission[]) => p.includes("write");

// Sharing is always to a pasted public key. A device has exactly one account
// (see IdentityModal), so there is no second local identity to pick, and the
// recipient's private key is never on this device — the HPKE round trip is
// proven on *their* device when they import the package.
//
// A pasted key that already has a share is not a new share: the SDK refuses
// a second grant to the same key. The form then turns into "change this
// recipient's permission / revoke them", the same actions each row offers.
export function ShareModal({
  entry,
  busy,
  onShare,
  onRevoke,
  onChangePermission,
  onClose,
}: {
  entry: Entry;
  busy: boolean;
  onShare: (entry: Entry, input: ShareInput) => Promise<boolean>;
  onRevoke: (entry: Entry, recipientPublicKeyB64Url: string) => Promise<boolean>;
  onChangePermission: (
    entry: Entry,
    recipientPublicKeyB64Url: string,
    permissions: Permission[],
  ) => Promise<boolean>;
  onClose: () => void;
}) {
  const [pubKey, setPubKey] = useState("");
  const [label, setLabel] = useState("");
  const [canWrite, setCanWrite] = useState(false);

  const permissions: Permission[] = canWrite ? READ_WRITE : READ;
  const trimmedKey = pubKey.trim();
  const existing = trimmedKey
    ? entry.shares.find((s) => s.recipientPublicKeyB64Url === trimmedKey)
    : undefined;

  // The package text for one recipient. Shown only for the recipient this
  // dialog just shared to or changed — the one the owner now has to deliver —
  // or on request ("Show package"). It is keyed by public key, which the grant
  // keeps across permission changes, and is never restored on reopening: a
  // package the owner already sent is not something the dialog should push
  // back at them every time.
  const [packageFor, setPackageFor] = useState<string | null>(null);

  const copyPackage = async (grant: ShareGrant) => {
    const text = serializeSharePackage(buildSharePackage(entry, grant));
    if (await copyText(text)) {
      pushToast(`Share package for ${grant.recipientLabel || "recipient"} copied`, "success");
    } else {
      setPackageFor(grant.recipientPublicKeyB64Url);
      pushToast("Clipboard unavailable — select the package text below to copy it", "error");
    }
  };

  const share = async () => {
    if (!trimmedKey || existing) return;
    const ok = await onShare(entry, {
      recipientPublicKeyB64Url: trimmedKey,
      recipientLabel: label.trim() || undefined,
      permissions,
    });
    if (ok) {
      setPackageFor(trimmedKey);
      setPubKey("");
      setLabel("");
    }
  };

  const changePermission = async (grant: ShareGrant, next: Permission[]) => {
    if (hasWrite(grant.permissions) === hasWrite(next)) return;
    const ok = await onChangePermission(entry, grant.recipientPublicKeyB64Url, next);
    if (ok) setPackageFor(grant.recipientPublicKeyB64Url);
  };

  const revoke = async (grant: ShareGrant) => {
    const ok = await onRevoke(entry, grant.recipientPublicKeyB64Url);
    if (!ok) return;
    if (packageFor === grant.recipientPublicKeyB64Url) setPackageFor(null);
    if (pubKey.trim() === grant.recipientPublicKeyB64Url) setPubKey("");
  };

  const shownGrant = packageFor
    ? entry.shares.find((s) => s.recipientPublicKeyB64Url === packageFor)
    : undefined;
  // Revoking rotates the key; every surviving recipient's old package stops
  // opening, so say how many need a new one instead of opening one of them.
  const rewrapped = entry.shares.filter((s) => s.reissuedAt).length;

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
          {existing ? (
            <>
              <button
                className="btn danger"
                disabled={busy}
                onClick={() => revoke(existing)}
              >
                Revoke
              </button>
              <button
                className="btn primary"
                disabled={busy || hasWrite(existing.permissions) === canWrite}
                title={
                  hasWrite(existing.permissions) === canWrite
                    ? "This recipient already has that permission"
                    : undefined
                }
                onClick={() => changePermission(existing, permissions)}
              >
                {busy ? <span className="spinner" /> : <Lock size={14} />} Update permission
              </button>
            </>
          ) : (
            <button
              className="btn primary"
              disabled={busy || !trimmedKey}
              title={trimmedKey ? undefined : "Paste the recipient's public key"}
              onClick={share}
            >
              {busy ? <span className="spinner" /> : <Lock size={14} />} Wrap CEK & share
            </button>
          )}
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
                  {s.recipientLabel || "external recipient"}
                </div>
                <div className="mono" style={{ fontSize: 10.5 }}>
                  KeyId {s.recipientKeyId} · epoch {s.envelope.key_epoch}
                  {s.reissuedAt
                    ? " · re-wrapped after a revoke"
                    : s.tokenReissuedAt
                      ? " · new token issued"
                      : ""}
                </div>
              </div>
              <div className="seg sm" title="Change this recipient's permission">
                <button
                  className={!hasWrite(s.permissions) ? "on" : ""}
                  disabled={busy}
                  onClick={() => changePermission(s, READ)}
                >
                  read
                </button>
                <button
                  className={hasWrite(s.permissions) ? "on" : ""}
                  disabled={busy}
                  onClick={() => changePermission(s, READ_WRITE)}
                >
                  read + write
                </button>
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
                onClick={() => revoke(s)}
              >
                Revoke
              </button>
            </div>
          ))}
          {rewrapped > 0 && !shownGrant && (
            <div className="hint" style={{ marginTop: 6 }}>
              {rewrapped} recipient(s) were re-wrapped after a revoke — their old
              package no longer opens. Copy and send each one the new package.
            </div>
          )}
          {shownGrant && (
            <div className="field share-package" style={{ marginTop: 10 }}>
              <label>
                Share package for {shownGrant.recipientLabel || "recipient"} — send this to them
                {shownGrant.reissuedAt
                  ? " (re-wrapped: the old one no longer opens)"
                  : shownGrant.tokenReissuedAt
                    ? " (new token: the old package can no longer reach the state node)"
                    : ""}
              </label>
              <textarea
                className="input mono"
                readOnly
                rows={5}
                value={serializeSharePackage(buildSharePackage(entry, shownGrant))}
                onFocus={(e) => e.currentTarget.select()}
                style={{ fontSize: 10.5 }}
              />
              <div className="hint">
                Any channel works (chat, mail). The recipient pastes it into{" "}
                <b>Import shared</b> on their own device. It carries the content key
                wrapped to their key only, so it is useless to anyone else — but treat
                it like a link to the file.{" "}
                <button className="link-btn" onClick={() => setPackageFor(null)}>
                  Hide
                </button>
              </div>
            </div>
          )}
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
        {!trimmedKey && (
          <div className="hint">
            Paste a recipient public key to enable sharing.
          </div>
        )}
        {existing && (
          <div className="hint existing-recipient">
            Already shared with <b>{existing.recipientLabel || "this recipient"}</b> (
            {existing.permissions.join(" + ")}). Pick a permission below to change it, or
            revoke their access.
          </div>
        )}
      </div>
      {!existing && (
        <div className="field">
          <label>Label (optional)</label>
          <input className="input" value={label} onChange={(e) => setLabel(e.target.value)} />
        </div>
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
