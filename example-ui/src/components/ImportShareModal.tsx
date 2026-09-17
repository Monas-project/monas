import { useMemo, useState } from "react";
import { Modal } from "./Modal";
import { Inbox, Lock } from "./icons";
import { parseSharePackage, SharePackageError } from "../sharePackage";
import { short } from "../api/crypto";
import { fmtBytes } from "../utils";
import type { Identity, SharePackage } from "../types";

/**
 * The recipient's side of a cross-device share: paste the package the owner
 * sent, see what it is and who it is for, unwrap it.
 *
 * The recipient identity is picked for the user: the package names the public
 * key it was wrapped to, and exactly one local identity can match. Offering a
 * dropdown here would only let people choose wrong.
 */
export function ImportShareModal({
  identities,
  busy,
  onImport,
  onClose,
}: {
  identities: Identity[];
  busy: boolean;
  onImport: (pkg: SharePackage, recipient: Identity) => void;
  onClose: () => void;
}) {
  const [text, setText] = useState("");

  const parsed = useMemo<
    { ok: true; pkg: SharePackage } | { ok: false; error: string } | null
  >(() => {
    if (!text.trim()) return null;
    try {
      return { ok: true, pkg: parseSharePackage(text) };
    } catch (e) {
      return {
        ok: false,
        error: e instanceof SharePackageError ? e.message : (e as Error).message,
      };
    }
  }, [text]);

  const pkg = parsed?.ok ? parsed.pkg : null;
  const recipient = pkg
    ? identities.find((i) => i.publicKeyB64Url === pkg.recipient_public_key) ?? null
    : null;

  return (
    <Modal
      title="Import shared file"
      icon={<Inbox />}
      onClose={onClose}
      wide
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn primary"
            disabled={busy || !pkg || !recipient}
            title={
              !pkg
                ? "Paste a share package first"
                : !recipient
                  ? "None of your identities holds the key this package is for"
                  : undefined
            }
            onClick={() => pkg && recipient && onImport(pkg, recipient)}
          >
            {busy ? <span className="spinner" /> : <Lock size={14} />} Unwrap & add to my Drive
          </button>
        </>
      }
    >
      <div className="callout">
        Someone shared a file with you? Paste the <b>share package</b> they sent
        you. It was wrapped to your public key, so only the identity holding that
        key can open it — nothing here talks to the sender's device.
      </div>

      <div className="field" style={{ marginTop: 14 }}>
        <label>Share package (JSON)</label>
        <textarea
          className="input mono"
          rows={7}
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder='{ "kind": "monas-share", "v": 1, … }'
          style={{ fontSize: 10.5 }}
        />
        {parsed && !parsed.ok && <div className="hint error-text">{parsed.error}</div>}
      </div>

      {pkg && (
        <div className="package-summary">
          <div className="recipient-row">
            <span className="avatar">{pkg.name.slice(0, 2).toUpperCase()}</span>
            <div className="grow">
              <div style={{ fontWeight: 600 }}>
                {pkg.name}{" "}
                {pkg.permissions.map((p) => (
                  <span className="badge" key={p}>
                    {p}
                  </span>
                ))}
              </div>
              <div className="mono" style={{ fontSize: 10.5 }}>
                {pkg.mimeType || "file"} · {fmtBytes(pkg.sizeBytes)} · epoch {pkg.key_envelope.key_epoch}
                {pkg.remote_content_id ? ` · network ${short(pkg.remote_content_id, 8, 6)}` : ""}
              </div>
              <div className="mono" style={{ fontSize: 10.5 }}>
                from {short(pkg.sender_public_key, 12, 6)} · to {short(pkg.recipient_public_key, 12, 6)}
              </div>
            </div>
          </div>
          {recipient ? (
            <>
              <div className="hint">
                Addressed to your identity <b>{recipient.label}</b>. Unwrapping pins the
                sender's key for this file (trust on first use); a later package from a
                different sender for the same file will be refused.
              </div>
              {!recipient.isSigningAccount && (
                <div className="hint">
                  <b>{recipient.label}</b> is not this device's signing account, so the
                  envelope will open but the state node cannot be read as this identity
                  (it verifies the delegated token against the key that signs requests).
                  To follow the owner's edits, ask them to share to your signing account's
                  public key instead.
                </div>
              )}
            </>
          ) : (
            <div className="hint error-text">
              None of your identities holds the key this package is for. Send the
              owner the public key of the identity you want to use (Identities →
              Copy public key) and ask them to share again.
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}
