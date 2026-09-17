import type { Identity } from "../types";
import { Settings } from "./icons";

function initials(label: string) {
  return label.slice(0, 2).toUpperCase();
}

export function TopBar({
  gatewayUp,
  identity,
  onOpenIdentity,
  onOpenSettings,
}: {
  gatewayUp: boolean | null;
  identity: Identity | null;
  onOpenIdentity: () => void;
  onOpenSettings: () => void;
}) {
  return (
    <header className="topbar">
      <div className="brand">
        <span className="logo">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
            <path d="M5 18V8l7 6 7-6v10" />
          </svg>
        </span>
        Monas Drive
        <small>example</small>
      </div>

      <span className="spacer" />

      <div className="conn" title="Gateway health (monas-gateway → SDK)">
        <span className="conn-item">
          <span
            className={`dot ${gatewayUp === true ? "up" : gatewayUp === false ? "down" : ""}`}
          />
          gateway
        </span>
      </div>

      <button className="icon-btn" title="Settings · endpoint" onClick={onOpenSettings}>
        <Settings />
      </button>

      <button className="account-chip" onClick={onOpenIdentity}>
        <span className="avatar">{identity ? initials(identity.label) : "+"}</span>
        <span className="meta">
          <b>{identity ? identity.label : "No identity"}</b>
          <br />
          <span>
            {identity ? `${identity.keyType} · ${identity.publicKeyB64Url.slice(0, 10)}` : "click to create"}
          </span>
        </span>
      </button>
    </header>
  );
}
