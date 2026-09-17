import { useState } from "react";
import { Modal } from "./Modal";
import { Key, Plus, Trash, Copy } from "./icons";
import { createSigningAccount } from "../api/account";
import { useIdentities, addIdentity, removeIdentity } from "../store/identity";
import { pushToast } from "./Toast";
import { copyText } from "../sharePackage";

// One device, one account. monas-account holds exactly one signing key: it is
// what the SDK signs every state-node request with, and the audience of every
// delegated token a share package brings to this device. So there is nothing
// to "switch" between — a second Create would overwrite the key in
// monas-account and silently orphan the first — and a keypair-only identity
// (the gateway's stateless /keypair) can open an envelope but can never read
// or write the state node. The dialog therefore offers exactly one thing:
// this device's account, and a way to replace it.
export function IdentityModal({ onClose }: { onClose: () => void }) {
  const { identities } = useIdentities();
  const account = identities.find((i) => i.isSigningAccount) ?? null;
  // Identities minted before the dialog was reduced to one account. They
  // still open envelopes addressed to them, so they stay removable, not hidden.
  const legacy = identities.filter((i) => !i.isSigningAccount);

  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);

  const create = async () => {
    const name = label.trim() || "me";
    setBusy(true);
    try {
      // Always P-256: signing requires it, and the HPKE share envelopes are
      // DHKEM(P-256) — any other curve would mint a key that cannot receive
      // a share, a dead end this dialog should not offer.
      const res = await createSigningAccount("secp256r1");
      // monas-account now signs with the new key, so a previous account entry
      // would only claim an authority it no longer has. Drop it.
      for (const old of identities) if (old.isSigningAccount) removeIdentity(old.label);
      addIdentity(
        {
          label: name,
          keyType: res.key_type,
          publicKeyB64Url: res.public_key,
          privateKeyB64Url: res.private_key,
          isSigningAccount: true,
        },
        true,
      );
      setLabel("");
      pushToast(`Account “${name}” created`, "success");
    } catch (e) {
      pushToast((e as Error).message, "error");
    } finally {
      setBusy(false);
    }
  };

  // The public key is what another person needs to share a file with you. It
  // is shown truncated in the list, so offer the full value on demand: to the
  // clipboard when the browser allows, otherwise expanded inline to select.
  const [revealed, setRevealed] = useState<string | null>(null);
  const copyPublicKey = async (label: string, key: string) => {
    if (await copyText(key)) {
      pushToast(`Public key of “${label}” copied`, "success");
    } else {
      setRevealed(label);
      pushToast("Clipboard unavailable — select the key below to copy it", "error");
    }
  };

  const renderRow = (id: { label: string; keyType: string; publicKeyB64Url: string }, signing: boolean) => (
    <div className="recipient-row" key={id.label}>
      <span className="avatar">{id.label.slice(0, 2).toUpperCase()}</span>
      <div className="grow">
        <div style={{ fontWeight: 600 }}>
          {id.label}{" "}
          {signing ? (
            <span className="badge enc" style={{ marginLeft: 4 }}>
              signing
            </span>
          ) : (
            <span className="badge local" style={{ marginLeft: 4 }} title="Not the current monas-account key — cannot sign or read the state node">
              keypair only
            </span>
          )}
        </div>
        <div className="mono" style={{ fontSize: 10.5 }}>
          {id.keyType} · pub {id.publicKeyB64Url.slice(0, 22)}…
        </div>
        {revealed === id.label && (
          <textarea
            className="input mono public-key"
            readOnly
            rows={2}
            value={id.publicKeyB64Url}
            onFocus={(e) => e.currentTarget.select()}
            style={{ fontSize: 10.5, marginTop: 6 }}
          />
        )}
      </div>
      <button
        className="btn sm"
        title="Copy this identity's public key (base64url)"
        onClick={() => copyPublicKey(id.label, id.publicKeyB64Url)}
      >
        <Copy size={13} /> Copy public key
      </button>
      <button
        className="icon-btn"
        title="Remove from this browser"
        onClick={() => removeIdentity(id.label)}
      >
        <Trash size={15} />
      </button>
    </div>
  );

  return (
    <Modal title="Identities & keys" icon={<Key />} onClose={onClose} wide>
      <div className="callout">
        This device has one <b>account</b>: a P-256 key registered with{" "}
        <b>monas-account</b>. The SDK signs every state-node request with it, and
        a share package sent to you is bound to it too — so it is both your
        signing key and the key others share to. To receive a file from someone
        on another device, send them your <b>public key</b> (Copy below).
      </div>

      <div style={{ margin: "16px 0 6px", fontWeight: 650, fontSize: 13 }}>
        Your account
      </div>
      {account ? (
        renderRow(account, true)
      ) : (
        <p className="muted" style={{ fontSize: 12.5 }}>
          None yet — create it below. Nothing can be created, shared or received
          without it.
        </p>
      )}

      {legacy.length > 0 && (
        <>
          <div style={{ margin: "16px 0 6px", fontWeight: 650, fontSize: 13 }}>
            Other identities
          </div>
          <div className="hint" style={{ marginBottom: 6 }}>
            Older identities (including replaced signing accounts). They can
            still open envelopes addressed to them, but cannot sign or read the
            state node. Have files shared to your account instead.
          </div>
          {legacy.map((id) => renderRow(id, false))}
        </>
      )}

      {!account && (
        <>
          <div style={{ margin: "18px 0 8px", fontWeight: 650, fontSize: 13 }}>
            Create account
          </div>
          <div className="field">
            <label>Label</label>
            <input
              className="input"
              value={label}
              placeholder="e.g. me, alice, bob"
              onChange={(e) => setLabel(e.target.value)}
            />
            <div className="hint">
              Sends <code>POST /accounts</code> to monas-account, which generates and
              keeps the P-256 key; the SDK signs state-node requests with it.
            </div>
          </div>
          <div style={{ display: "flex", justifyContent: "flex-end", paddingBottom: 6 }}>
            <button className="btn primary" disabled={busy} onClick={create}>
              {busy ? <span className="spinner" /> : <Plus size={14} />} Create account
            </button>
          </div>
        </>
      )}
      {account && (
        <div className="hint" style={{ marginTop: 14, paddingBottom: 6 }}>
          To start over with a fresh key, remove the account above and create a
          new one. monas-account keeps only one key, so files created under the
          old key can no longer be updated or deleted from this device.
        </div>
      )}
    </Modal>
  );
}
