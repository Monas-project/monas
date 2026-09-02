import { useEffect, useState } from "react";
import { Modal } from "./Modal";
import { Eye, Network, Refresh, Check, X } from "./icons";
import type { Entry } from "../types";
import { base64UrlToUtf8, base64UrlToStandard, short } from "../api/crypto";
import { ApiError } from "../api/http";
import {
  getHistory,
  getLatestVersion,
  readFromStateNode,
  verifyIntegrity,
  type GetHistoryOutput,
  type GetLatestVersionOutput,
  type ReadFromStateNodeOutput,
  type VerifyIntegrityOutput,
} from "../api/stateNode";

// One async slice (latest / history / verify). Mirrors the small idle→loading→
// ok|error state machine the rest of the app uses, kept local to this modal.
type AsyncState<T> =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ok"; data: T }
  | { status: "error"; message: string };

// Same error formatting as the pipeline runner (runner.ts) so messages read
// consistently across the app.
function errMsg(e: unknown): string {
  return e instanceof ApiError
    ? `${e.message}${e.status ? ` (HTTP ${e.status})` : ""}`
    : (e as Error).message;
}

export function PreviewModal({
  entry,
  contentB64Url,
  onClose,
}: {
  entry: Entry;
  contentB64Url: string;
  onClose: () => void;
}) {
  const isImage = (entry.mimeType || "").startsWith("image/");
  let text = "";
  if (!isImage) {
    try {
      text = base64UrlToUtf8(contentB64Url);
    } catch {
      text = "(binary content — cannot render as text)";
    }
  }

  // The state-node calls address the Content Network. For a synced file that's
  // remoteContentId; fall back to the local id like the update/delete flows do.
  const synced = entry.syncedToStateNode;
  const cid = entry.remoteContentId || entry.localContentId;

  const [latest, setLatest] = useState<AsyncState<GetLatestVersionOutput>>({ status: "idle" });
  const [history, setHistory] = useState<AsyncState<GetHistoryOutput>>({ status: "idle" });
  const [verify, setVerify] = useState<AsyncState<VerifyIntegrityOutput>>({ status: "idle" });
  const [read, setRead] = useState<AsyncState<ReadFromStateNodeOutput>>({ status: "idle" });

  // Auto-load latest + history on open, but only for synced files (local-only
  // files have no Content Network and the calls would just fail).
  useEffect(() => {
    if (!synced || !cid) return;
    let cancelled = false;
    setLatest({ status: "loading" });
    setHistory({ status: "loading" });
    setVerify({ status: "idle" });
    setRead({ status: "idle" });
    getLatestVersion(cid)
      .then((d) => !cancelled && setLatest({ status: "ok", data: d }))
      .catch((e) => !cancelled && setLatest({ status: "error", message: errMsg(e) }));
    getHistory(cid)
      .then((d) => !cancelled && setHistory({ status: "ok", data: d }))
      .catch((e) => !cancelled && setHistory({ status: "error", message: errMsg(e) }));
    return () => {
      cancelled = true;
    };
    // re-run if we navigate to a different content (e.g. after an edit reopens)
  }, [cid, synced]);

  const reload = () => {
    if (!synced || !cid) return;
    setLatest({ status: "loading" });
    setHistory({ status: "loading" });
    getLatestVersion(cid)
      .then((d) => setLatest({ status: "ok", data: d }))
      .catch((e) => setLatest({ status: "error", message: errMsg(e) }));
    getHistory(cid)
      .then((d) => setHistory({ status: "ok", data: d }))
      .catch((e) => setHistory({ status: "error", message: errMsg(e) }));
  };

  const runVerify = () => {
    if (!cid) return;
    setVerify({ status: "loading" });
    const expectedVersion = latest.status === "ok" ? latest.data.latest_version : undefined;
    verifyIntegrity({
      contentId: cid,
      contentBase64Url: contentB64Url,
      expectedVersion,
      localContentId: entry.localContentId,
    })
      .then((d) => setVerify({ status: "ok", data: d }))
      .catch((e) => setVerify({ status: "error", message: errMsg(e) }));
  };

  // Verified read: unlike the preview above (which comes from the gateway's own
  // store), this pulls the version off the state node — relayed to a member if
  // the contacted node isn't one — and only yields plaintext once the CID has
  // been recomputed and the AES-GCM decryption re-addresses to the local id.
  // Only the newest version can be verified here. The check re-derives the
  // plaintext and compares it against `local_content_id`, and each version has
  // its own — the registry keeps just the current one, so asking for an older
  // version would always fail the comparison it is meant to prove. Offering
  // that choice made the control look broken rather than honest.
  const runRead = () => {
    if (!cid || !entry.localContentId) return;
    setRead({ status: "loading" });
    readFromStateNode({
      contentId: cid,
      localContentId: entry.localContentId,
    })
      .then((d) => setRead({ status: "ok", data: d }))
      .catch((e) => setRead({ status: "error", message: errMsg(e) }));
  };

  return (
    <Modal title={entry.name} icon={<Eye />} onClose={onClose} wide>
      <div className="callout" style={{ marginBottom: 12 }}>
        Fetched through the gateway and decrypted by the SDK with the CEK. The
        plaintext below never left the backend unencrypted.
      </div>

      {isImage ? (
        <img
          className="preview-img"
          src={`data:${entry.mimeType};base64,${base64UrlToStandard(contentB64Url)}`}
          alt={entry.name}
        />
      ) : (
        <div className="preview-box">{text || "(empty)"}</div>
      )}

      <div style={{ marginTop: 14 }}>
        <div className="kv">
          <span>local content_id</span>
          <b>{entry.localContentId}</b>
        </div>
        {entry.remoteContentId && (
          <div className="kv">
            <span>Content Network</span>
            <b>{entry.remoteContentId}</b>
          </div>
        )}
        {entry.seriesId && (
          <div className="kv">
            <span>seriesId</span>
            <b>{entry.seriesId}</b>
          </div>
        )}
        <div className="kv">
          <span>versions</span>
          <b>{entry.versionCount}</b>
        </div>
      </div>

      {/* ---- state-node: version history + integrity verification ---- */}
      <div className="state-head">
        <Network size={15} />
        <span style={{ fontWeight: 650, fontSize: 13 }}>State-node</span>
        <span style={{ flex: 1 }} />
        {synced && cid && (
          <button className="btn ghost sm" onClick={reload} title="Reload from state-node">
            <Refresh size={13} /> Reload
          </button>
        )}
      </div>

      {!synced || !cid ? (
        <div className="callout warn">
          This file is local-only — it has not been registered on a state-node,
          so there is no Content Network version history or integrity check to
          query. Sync it (create or edit against a state-node) to enable these.
        </div>
      ) : (
        <>
          <div className="kv">
            <span>latest version</span>
            {latest.status === "loading" ? (
              <b>
                <span className="spinner" />
              </b>
            ) : latest.status === "ok" ? (
              <b className="mono">{short(latest.data.latest_version)}</b>
            ) : latest.status === "error" ? (
              <b className="inline-err">{latest.message}</b>
            ) : (
              <b>—</b>
            )}
          </div>

          <div className="field" style={{ marginTop: 10 }}>
            <label>version history</label>
            {history.status === "loading" ? (
              <div className="muted" style={{ fontSize: 12 }}>
                <span className="spinner" /> Loading history…
              </div>
            ) : history.status === "error" ? (
              <div className="inline-err">{history.message}</div>
            ) : history.status === "ok" ? (
              history.data.versions.length === 0 ? (
                <div className="muted" style={{ fontSize: 12 }}>
                  No versions recorded yet.
                </div>
              ) : (
                <div className="state-history">
                  {history.data.versions.map((v, i) => {
                    const isCurrent =
                      latest.status === "ok" && v === latest.data.latest_version;
                    return (
                      <div className={`ver ${isCurrent ? "current" : ""}`} key={`${v}-${i}`}>
                        {v}
                        {isCurrent ? " · latest" : ""}
                      </div>
                    );
                  })}
                </div>
              )
            ) : null}
          </div>

          <div className="field" style={{ marginTop: 10 }}>
            <label>integrity</label>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <button
                className="btn sm"
                disabled={verify.status === "loading"}
                onClick={runVerify}
              >
                {verify.status === "loading" ? <span className="spinner" /> : <Check size={13} />}{" "}
                Verify integrity
              </button>
              {verify.status === "ok" &&
                (verify.data.valid ? (
                  <span className="badge synced">
                    <Check size={11} /> valid
                  </span>
                ) : (
                  <span className="badge invalid">
                    <X size={11} /> invalid
                  </span>
                ))}
            </div>
            {verify.status === "ok" && (
              <>
                <div className="kv" style={{ marginTop: 8 }}>
                  <span>computed_hash</span>
                  <b className="mono">{short(verify.data.computed_hash)}</b>
                </div>
                {verify.data.reason && (
                  <div className="kv">
                    <span>reason</span>
                    <b>{verify.data.reason}</b>
                  </div>
                )}
              </>
            )}
            {verify.status === "error" && (
              <div className="inline-err" style={{ marginTop: 6 }}>
                {verify.message}
              </div>
            )}
          </div>

          {/* ---- verified read straight off the state node ---- */}
          <div className="field" style={{ marginTop: 10 }}>
            <label>verified read</label>
            <div className="muted" style={{ fontSize: 11.5, marginBottom: 8 }}>
              The preview above came from the gateway's own store. This reads the
              newest version back from the state node — relayed to a member node
              if the one we contacted isn't one — and only shows plaintext after
              the Node CID is recomputed, the CEK decrypts it (AES-GCM), and the
              plaintext re-addresses to the local id. A relay cannot forge this.
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <button className="btn sm" disabled={read.status === "loading"} onClick={runRead}>
                {read.status === "loading" ? <span className="spinner" /> : <Network size={13} />}{" "}
                Read from state-node
              </button>
              {read.status === "ok" && (
                <span className="badge synced">
                  <Check size={11} /> verified
                </span>
              )}
            </div>

            {read.status === "ok" && (
              <>
                <div className="kv" style={{ marginTop: 8 }}>
                  <span>version read</span>
                  <b className="mono">{short(read.data.version)}</b>
                </div>
                <div className="preview-box" style={{ marginTop: 8 }}>
                  {(() => {
                    if ((entry.mimeType || "").startsWith("image/"))
                      return "(image decrypted and verified — rendered above)";
                    try {
                      return base64UrlToUtf8(read.data.content) || "(empty)";
                    } catch {
                      return "(binary content — cannot render as text)";
                    }
                  })()}
                </div>
                <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>
                  Payload authenticity is proven. Whether this is the newest
                  version, or was written by a legitimate writer, is not —
                  version metadata has no trust anchor yet (issue #59).
                </div>
              </>
            )}
            {read.status === "error" && (
              <div className="inline-err" style={{ marginTop: 6 }}>
                {read.message}
              </div>
            )}
          </div>
        </>
      )}
    </Modal>
  );
}
