import { useState } from "react";
import { Modal } from "./Modal";
import { Settings, Check } from "./icons";
import {
  loadEndpoints,
  saveEndpoints,
  PROXY_DEFAULTS,
  GATEWAY_PRESETS,
  type EndpointConfig,
} from "../config";
import { probeGateway } from "../api/http";
import { pushToast } from "./Toast";

export function SettingsModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [cfg, setCfg] = useState<EndpointConfig>(loadEndpoints());
  const [testing, setTesting] = useState(false);

  const save = () => {
    saveEndpoints(cfg);
    pushToast("Endpoint saved", "success");
    onSaved();
    onClose();
  };

  const test = async () => {
    setTesting(true);
    saveEndpoints(cfg); // probe reads from storage
    const ok = await probeGateway();
    setTesting(false);
    pushToast(`gateway ${ok ? "✓ reachable" : "✗ unreachable"}`, ok ? "success" : "error");
  };

  return (
    <Modal
      title="Endpoint"
      icon={<Settings />}
      onClose={onClose}
      wide
      footer={
        <>
          <button className="btn" onClick={() => setCfg({ ...PROXY_DEFAULTS })}>
            Reset to proxy
          </button>
          <span style={{ flex: 1 }} />
          <button className="btn" disabled={testing} onClick={test}>
            {testing ? <span className="spinner" /> : null} Test connection
          </button>
          <button className="btn primary" onClick={save}>
            <Check size={14} /> Save
          </button>
        </>
      }
    >
      <div className="callout">
        The UI talks to a single backend: <b>monas-gateway</b>, which runs the
        SDK and orchestrates encryption, storage, the state-node and signing. By
        default it's reached through the Vite dev proxy (<code>/api</code> → your
        local gateway), which avoids CORS. Point it at a hosted gateway below —
        a cross-origin URL must send CORS headers.
      </div>

      <div className="field" style={{ marginTop: 16 }}>
        <label>monas-gateway base URL</label>
        <input
          className="input"
          value={cfg.gateway}
          onChange={(e) => setCfg({ ...cfg, gateway: e.target.value })}
        />
        <div className="seg" style={{ marginTop: 8 }}>
          {GATEWAY_PRESETS.map((p) => (
            <button
              key={p.value}
              className={cfg.gateway === p.value ? "on" : ""}
              onClick={() => setCfg({ ...cfg, gateway: p.value })}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      <div className="field">
        <label>monas-account base URL (for “create account”)</label>
        <input
          className="input"
          value={cfg.accountService}
          onChange={(e) => setCfg({ ...cfg, accountService: e.target.value })}
        />
        <div className="hint">
          The UI seeds the P-256 signing key here. Defaults to the{" "}
          <code>/account-api</code> proxy → monas-account on :4002.
        </div>
      </div>
    </Modal>
  );
}
