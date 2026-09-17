import { useEffect, useState } from "react";
import { Modal } from "./Modal";
import { Eye, Network, Refresh, Check, X, Pencil } from "./icons";
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
import { syncStatusOf, describeSync, heldVersionId } from "../store/sync";

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

// The SDK's verify-integrity reasons this UI knows how to explain. Matching on
// the message is brittle but the response has no code field; the strings are
// in monas-sdk/src/controller/state.rs.
function classifyVerify(v: VerifyIntegrityOutput): "valid" | "behind" | "no-local" | "mismatch" {
  if (v.valid) return "valid";
  if (v.reason?.includes("differs from local ciphertext")) return "behind";
  if (v.reason?.includes("failed to load local ciphertext")) return "no-local";
  return "mismatch";
}

export function PreviewModal({
  entry,
  contentB64Url,
  displayedVersionId,
  onCheckHead,
  onEdit,
  onClose,
}: {
  entry: Entry;
  contentB64Url: string;
  /** Identity of the rendered body, fixed when opened (not the last write). */
  displayedVersionId: string | undefined;
  /** Verified read of the head that also records it on the entry — the
   *  list's sync badge and the status line here read from that record. */
  onCheckHead: (entry: Entry) => Promise<ReadFromStateNodeOutput | null>;
  /** "Edit contents"; for the owner this pulls the head first. */
  onEdit: (entry: Entry) => void;
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
  //
  // A received share reads with the delegated token from its package: the
  // gateway still signs with this device's account key (the token's audience)
  // and presents the token, and the state node grants the recipient what the
  // owner delegated. The token lives an hour and is voided by any revoke on
  // the file, after which the owner has to send a fresh package.
  const received = !!entry.receivedShare;
  const token = entry.receivedShare?.delegatedAccess;
  const tokenExpired = !!token && token.expires_at * 1000 < Date.now();
  const auth = token ? { delegatedToken: token.delegated_token } : undefined;
  const synced = entry.syncedToStateNode && (!received || !!token);
  const cid = entry.remoteContentId || entry.localContentId;
  const canWrite = !received || !!entry.receivedShare?.permissions.includes("write");

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
    getLatestVersion(cid, auth)
      .then((d) => !cancelled && setLatest({ status: "ok", data: d }))
      .catch((e) => !cancelled && setLatest({ status: "error", message: errMsg(e) }));
    getHistory(cid, 100, auth)
      .then((d) => !cancelled && setHistory({ status: "ok", data: d }))
      .catch((e) => !cancelled && setHistory({ status: "error", message: errMsg(e) }));
    return () => {
      cancelled = true;
    };
    // re-run if we navigate to a different content (e.g. after an edit reopens)
    // or the received share was re-imported with a fresh token
  }, [cid, synced, token?.delegated_token]);

  const reload = () => {
    if (!synced || !cid) return;
    setLatest({ status: "loading" });
    setHistory({ status: "loading" });
    getLatestVersion(cid, auth)
      .then((d) => setLatest({ status: "ok", data: d }))
      .catch((e) => setLatest({ status: "error", message: errMsg(e) }));
    getHistory(cid, 100, auth)
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
  //
  // Neither side can assume the newest version is its own: the owner may
  // have edited since sharing, and a write-share recipient may have written
  // since. So the read only uses the local id to pick the CEK, and reports
  // the id the plaintext actually addresses to; the rows below say whose
  // version that is. For a synced file it goes through the entry-recording
  // check, so the sync badge in the list and the status line here agree with
  // what was just read.
  const runRead = () => {
    if (!cid || !entry.localContentId) return;
    setRead({ status: "loading" });
    const p = synced
      ? onCheckHead(entry).then((d) => {
          if (!d) throw new Error(entry.networkCheckError || "could not read the Content Network head");
          return d;
        })
      : readFromStateNode({ contentId: cid, localContentId: entry.localContentId, acceptAnyVersion: true, auth });
    p.then((d) => setRead({ status: "ok", data: d })).catch((e) =>
      setRead({ status: "error", message: errMsg(e) }),
    );
  };

  // The one-line answer to "am I looking at the newest version?". Derived
  // from what the entry recorded at the last head check (open, sweep, or the
  // verified read below), so it stays right even while this dialog is idle.
  const sync = syncStatusOf(entry, displayedVersionId);
  const syncText = describeSync(sync);
  const held = heldVersionId(entry);
  const syncBadgeClass =
    sync.kind === "current" ? "synced" : sync.kind === "behind" ? "behind" : sync.kind === "unreachable" ? "invalid" : "";

  return (
    <Modal title={entry.name} icon={<Eye />} onClose={onClose} wide>
      {received ? (
        <div className="callout" style={{ marginBottom: 12 }}>
          Shared with you by <b className="mono">{short(entry.receivedShare!.senderPublicKeyB64Url, 12, 6)}</b>{" "}
          ({entry.receivedShare!.permissions.join(", ")}). The SDK unwrapped the
          content key from their envelope with your identity{" "}
          <b>{entry.receivedShare!.recipientLabel}</b> and decrypted the ciphertext
          it carries — this is the version the owner shared.
          {entry.receivedShare!.writtenVersionId && (
            <>
              {" "}
              You have since written a newer version with the delegated token;
              “Read from state-node” below shows the current one.
            </>
          )}
        </div>
      ) : (
        <div className="callout" style={{ marginBottom: 12 }}>
          Fetched through the gateway and decrypted by the SDK with the CEK. The
          plaintext below never left the backend unencrypted.
        </div>
      )}

      {isImage ? (
        <img
          className="preview-img"
          src={`data:${entry.mimeType};base64,${base64UrlToStandard(contentB64Url)}`}
          alt={entry.name}
        />
      ) : (
        <div className="preview-box">{text || "(empty)"}</div>
      )}

      {/* ---- is this the newest version? ---- */}
      {synced && cid && (
        <div
          className={`callout sync-status ${sync.kind === "behind" ? "warn" : ""}`}
          data-sync={sync.kind}
          style={{ marginTop: 12, display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}
        >
          <span className={`badge sync ${syncBadgeClass}`}>
            {sync.kind === "checking" ? <span className="spinner xs" /> : <Network size={11} />} {syncText.label}
          </span>
          <span style={{ flex: 1, minWidth: 200 }}>
            {sync.kind === "current" && (
              <>
                The text above <b>is</b> the newest version on the Content Network (checked{" "}
                {new Date(sync.head.checkedAt).toLocaleTimeString()}).
              </>
            )}
            {sync.kind === "behind" && (
              <>
                The Content Network has a <b>newer version</b> than the text above
                {received
                  ? " — this preview is the original shared version, not the current network head"
                  : " — a recipient with write access has edited since your last save"}
                . <i>Read from state-node</i> shows it
                {canWrite ? (received ? "; Edit contents starts from it." : "; Pull & edit adopts it into your copy.") : "."}
              </>
            )}
            {sync.kind === "unchecked" && <>Not compared with the Content Network yet.</>}
            {sync.kind === "checking" && <>Reading the Content Network head…</>}
            {sync.kind === "unreachable" && (
              <>
                Could not read the Content Network head: <span className="mono">{sync.error}</span>
                {sync.head ? ` (last seen ${new Date(sync.head.checkedAt).toLocaleTimeString()})` : ""}.
              </>
            )}
          </span>
          {sync.kind !== "checking" && (
            <button className="btn ghost sm" onClick={runRead} title="Verified read of the head">
              <Refresh size={13} /> Check now
            </button>
          )}
          {sync.kind === "behind" && canWrite && (
            <button className="btn sm" onClick={() => onEdit(entry)}>
              <Pencil size={13} /> {received ? "Edit contents" : "Pull & edit"}
            </button>
          )}
        </div>
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

      {received && token && !tokenExpired && (
        <div className="muted" style={{ fontSize: 11.5, marginBottom: 8 }}>
          Reading as a recipient with the delegated token from the share package
          (jti {short(token.jti, 6, 4)}, valid until{" "}
          {new Date(token.expires_at * 1000).toLocaleTimeString()}). The gateway
          signs the request with your account key — the token's audience — and
          the state node checks both.
        </div>
      )}
      {received && !token ? (
        <div className="callout warn">
          The share package carried no delegated token, so this device cannot
          read the owner's Content Network. Ask the owner to share again.
        </div>
      ) : received && tokenExpired ? (
        <div className="callout warn">
          The delegated token in the share package expired at{" "}
          {new Date(token!.expires_at * 1000).toLocaleString()}. Ask the owner for
          a fresh package to read from the state node again; the version they
          shared still opens from the envelope.
        </div>
      ) : !synced || !cid ? (
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

          {/* Integrity compares the gateway's own ciphertext with the state
              node's; a recipient's gateway holds no ciphertext for this file. */}
          {!received && (
          <div className="field" style={{ marginTop: 10 }}>
            <label>integrity</label>
            <div className="muted" style={{ fontSize: 11.5, marginBottom: 8 }}>
              Byte-compares the ciphertext this device stored with the newest version
              the state node holds. Equal means your copy is the head; different
              usually means someone else wrote a newer version, not that anything
              was tampered with.
            </div>
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
                (() => {
                  switch (classifyVerify(verify.data)) {
                    case "valid":
                      return (
                        <span className="badge synced">
                          <Check size={11} /> valid — your copy is the head
                        </span>
                      );
                    case "behind":
                      return (
                        <span className="badge behind">
                          <Network size={11} /> not the head — newer version on the network
                        </span>
                      );
                    case "no-local":
                      return (
                        <span className="badge invalid">
                          <X size={11} /> no local ciphertext
                        </span>
                      );
                    default:
                      return (
                        <span className="badge invalid">
                          <X size={11} /> invalid — does not match
                        </span>
                      );
                  }
                })()}
            </div>
            {verify.status === "ok" && !verify.data.valid && (
              <div
                className={`callout ${classifyVerify(verify.data) === "behind" ? "warn" : ""}`}
                style={{ marginTop: 8 }}
              >
                {classifyVerify(verify.data) === "behind" ? (
                  <>
                    Not a corruption: the state node's newest version is not the one this
                    device holds — a recipient with write access wrote after your last save.
                    <i> Read from state-node</i> shows it; <i>Pull &amp; edit</i> adopts it into
                    your copy.
                  </>
                ) : classifyVerify(verify.data) === "no-local" ? (
                  <>
                    This device's gateway no longer holds ciphertext for this file (its store
                    was reset or points elsewhere), so there is nothing to compare the network
                    against. The row in the list is stale — delete it and start over.
                  </>
                ) : (
                  <>The state node's copy does not match what this device holds.</>
                )}
                <div className="mono" style={{ fontSize: 10.5, marginTop: 6, opacity: 0.8 }}>
                  {verify.data.reason}
                </div>
              </div>
            )}
            {verify.status === "ok" && (
              <div className="kv" style={{ marginTop: 8 }}>
                <span>computed_hash</span>
                <b className="mono">{short(verify.data.computed_hash)}</b>
              </div>
            )}
            {verify.status === "error" && (
              <div className="inline-err" style={{ marginTop: 6 }}>
                {verify.message}
              </div>
            )}
          </div>
          )}

          {/* ---- verified read straight off the state node ---- */}
          <div className="field" style={{ marginTop: 10 }}>
            <label>verified read</label>
            <div className="muted" style={{ fontSize: 11.5, marginBottom: 8 }}>
              The preview above came from the gateway's own store. This reads the
              newest version back from the state node — relayed to a member node
              if the one we contacted isn't one — and only shows plaintext after
              the Node CID is recomputed and the CEK decrypts it (AES-GCM). The
              plaintext is then re-addressed, and if the id differs from the
              local copy the rows below say who wrote it. A relay cannot forge
              this.
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
                {read.data.local_content_id === held ? (
                  received && entry.receivedShare?.writtenVersionId === held ? (
                    <div className="kv">
                      <span>your edit</span>
                      <b className="mono">
                        plaintext addresses {short(read.data.local_content_id)} — the version
                        this device wrote with the delegated token
                      </b>
                    </div>
                  ) : (
                    <div className="kv">
                      <span>up to date</span>
                      <b className="mono">
                        plaintext addresses {short(read.data.local_content_id)} — the same
                        version this device holds
                      </b>
                    </div>
                  )
                ) : received ? (
                  <div className="kv">
                    <span>newer than shared</span>
                    <b className="mono">
                      plaintext now addresses {short(read.data.local_content_id)} — the owner
                      has edited since sharing
                    </b>
                  </div>
                ) : (
                  <div className="kv">
                    <span>newer than your copy</span>
                    <b className="mono">
                      plaintext now addresses {short(read.data.local_content_id)} — a recipient
                      with write access has edited since your last save. “Edit contents” pulls
                      it into your copy first.
                    </b>
                  </div>
                )}
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
