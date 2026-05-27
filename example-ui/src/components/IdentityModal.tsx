import { useState } from "react";
import { Modal } from "./Modal";
import { Key, Plus, Check, Trash } from "./icons";
import { generateKeypair, createSigningAccount } from "../api/account";
import {
  useIdentities,
  addIdentity,
  setActive,
  removeIdentity,
} from "../store/identity";
import { pushToast } from "./Toast";
import type { KeyType } from "../types";

export function IdentityModal({ onClose }: { onClose: () => void }) {
  const { identities, activeLabel } = useIdentities();
  const hasSigningAccount = identities.some((i) => i.isSigningAccount);

  const [label, setLabel] = useState("");
  const [keyType, setKeyType] = useState<KeyType>("secp256r1");
  const [asSigning, setAsSigning] = useState(!hasSigningAccount);
  const [busy, setBusy] = useState(false);

  const create = async () => {
    const name = label.trim() || `account-${identities.length + 1}`;
    setBusy(true);
    try {
      const res = asSigning
        ? await createSigningAccount(keyType)
        : await generateKeypair(keyType);
      addIdentity(
        {
          label: name,
          keyType: res.key_type,
          publicKeyB64Url: res.public_key,
          privateKeyB64Url: res.private_key,
          isSigningAccount: asSigning,
        },
        identities.length === 0 || asSigning,
      );
      setLabel("");
      pushToast(
        asSigning ? `Signing account “${name}” created` : `Identity “${name}” created`,
        "success",
      );
    } catch (e) {
      pushToast((e as Error).message, "error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="Identities & keys" icon={<Key />} onClose={onClose} wide>
      <div className="callout">
        Create your <b>account</b> here — the signing account registers a P-256
        key with <b>monas-account</b>, which the SDK uses to sign state-node
        requests for create / edit / delete. Add extra keypair-only identities to
        demo sharing (the UI then holds the recipient's private key and proves
        the HPKE round-trip).
      </div>

      <div style={{ margin: "16px 0 6px", fontWeight: 650, fontSize: 13 }}>
        Your identities
      </div>
      {identities.length === 0 && (
        <p className="muted" style={{ fontSize: 12.5 }}>
          None yet — create your account below.
        </p>
      )}
      {identities.map((id) => (
        <div className="recipient-row" key={id.label}>
          <span className="avatar">{id.label.slice(0, 2).toUpperCase()}</span>
          <div className="grow">
            <div style={{ fontWeight: 600 }}>
              {id.label}{" "}
              {id.label === activeLabel && (
                <span className="badge synced" style={{ marginLeft: 4 }}>
                  active
                </span>
              )}
              {id.isSigningAccount && (
                <span className="badge enc" style={{ marginLeft: 4 }}>
                  signing
                </span>
              )}
            </div>
            <div className="mono" style={{ fontSize: 10.5 }}>
              {id.keyType} · pub {id.publicKeyB64Url.slice(0, 22)}…
            </div>
          </div>
          {id.label !== activeLabel && (
            <button className="btn sm" onClick={() => setActive(id.label)}>
              <Check size={13} /> Use
            </button>
          )}
          <button
            className="icon-btn"
            title="Remove from this browser"
            onClick={() => removeIdentity(id.label)}
          >
            <Trash size={15} />
          </button>
        </div>
      ))}

      <div style={{ margin: "18px 0 8px", fontWeight: 650, fontSize: 13 }}>
        Create {asSigning ? "account" : "identity"}
      </div>
      <div className="field">
        <label>Label</label>
        <input
          className="input"
          value={label}
          placeholder="e.g. me, alice, bob"
          onChange={(e) => setLabel(e.target.value)}
        />
      </div>
      <div className="field">
        <label>Key type</label>
        <div className="seg">
          <button
            className={keyType === "secp256r1" ? "on" : ""}
            onClick={() => setKeyType("secp256r1")}
          >
            secp256r1 / P-256 (recommended)
          </button>
          <button
            className={keyType === "secp256k1" ? "on" : ""}
            onClick={() => setKeyType("secp256k1")}
            disabled={asSigning}
            title={asSigning ? "Signing account must be P-256" : undefined}
          >
            secp256k1
          </button>
        </div>
      </div>
      <div className="field">
        <label
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            fontWeight: 500,
            textTransform: "none",
            color: "var(--text)",
          }}
        >
          <input
            type="checkbox"
            checked={asSigning}
            onChange={(e) => {
              setAsSigning(e.target.checked);
              if (e.target.checked) setKeyType("secp256r1");
            }}
          />
          Register as signing account (P-256) — enables create / edit / delete
        </label>
        <div className="hint">
          Sends <code>POST /accounts</code> to monas-account so the SDK can sign
          state-node requests. Uncheck to create a keypair-only identity (e.g. a
          share recipient) via the gateway.
        </div>
      </div>
      <div style={{ display: "flex", justifyContent: "flex-end", paddingBottom: 6 }}>
        <button className="btn primary" disabled={busy} onClick={create}>
          {busy ? <span className="spinner" /> : <Plus size={14} />}{" "}
          {asSigning ? "Create account" : "Create identity"}
        </button>
      </div>
    </Modal>
  );
}
