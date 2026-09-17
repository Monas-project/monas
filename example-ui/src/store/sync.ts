// Where this device's copy stands against the Content Network head.
//
// The Drive keeps two facts per synced file: what this device holds (for the
// owner, the plain id of its local ciphertext; for a recipient, the version it
// last wrote, or failing that the one the envelope carried) and what the
// network's head addressed to the last time we did a verified read
// (`entry.networkHead`). The comparison is deliberately by plain content id,
// not by Node CID: a verified read re-derives the plaintext and its id, so
// the id is the one fact that cannot be spoofed by a relay (issue #59 — the
// version metadata itself has no trust anchor yet).
import type { Entry, NetworkHead } from "../types";
import * as stateApi from "../api/stateNode";
import { ApiError } from "../api/http";
import { noteEntry, allEntries } from "./registry";

export type SyncStatus =
  | { kind: "local" } // never registered on a state node
  | { kind: "unchecked" } // synced, but the head has not been read yet
  | { kind: "checking" }
  | { kind: "current"; head: NetworkHead } // network head == this device's copy
  | { kind: "behind"; head: NetworkHead } // network has a version this device hasn't adopted
  | { kind: "unreachable"; error: string; head?: NetworkHead };

/** The plain content id this device considers "its" version of the file. */
export function heldVersionId(entry: Entry): string | undefined {
  if (entry.receivedShare) {
    return entry.receivedShare.writtenVersionId ?? entry.localContentId;
  }
  return entry.localContentId;
}

const checking = new Set<string>();

export function syncStatusOf(entry: Entry, comparedVersionId = heldVersionId(entry)): SyncStatus {
  if (entry.kind !== "file" || !entry.syncedToStateNode || !entry.remoteContentId) {
    return { kind: "local" };
  }
  if (checking.has(entry.id)) return { kind: "checking" };
  if (entry.networkCheckError) {
    return { kind: "unreachable", error: entry.networkCheckError, head: entry.networkHead };
  }
  if (!entry.networkHead) return { kind: "unchecked" };
  return entry.networkHead.localId === comparedVersionId
    ? { kind: "current", head: entry.networkHead }
    : { kind: "behind", head: entry.networkHead };
}

/** Short human label for a status, used by badges and the preview header. */
export function describeSync(s: SyncStatus): { label: string; title: string; tone: "ok" | "warn" | "err" | "muted" } {
  switch (s.kind) {
    case "local":
      return { label: "local", title: "Stored & encrypted, not on the state-node", tone: "warn" };
    case "unchecked":
      return { label: "synced", title: "On a Content Network — head not checked yet", tone: "muted" };
    case "checking":
      return { label: "checking…", title: "Reading the Content Network head", tone: "muted" };
    case "current":
      return {
        label: "up to date",
        title: `Your copy is the network head (checked ${new Date(s.head.checkedAt).toLocaleTimeString()})`,
        tone: "ok",
      };
    case "behind":
      return {
        label: "newer on network",
        title: `The Content Network has a version you have not adopted (checked ${new Date(s.head.checkedAt).toLocaleTimeString()})`,
        tone: "warn",
      };
    case "unreachable":
      return { label: "can't reach network", title: s.error, tone: "err" };
  }
}

/**
 * Verified read of the head and record what it addressed to. Resolves to the
 * read result so callers that also want the plaintext (the preview) don't
 * have to read twice. Errors are recorded on the entry, not thrown — a
 * status check must never take an action down with it.
 */
export async function checkNetworkHead(
  entry: Entry,
): Promise<stateApi.ReadFromStateNodeOutput | null> {
  if (!entry.syncedToStateNode || !entry.remoteContentId || !entry.localContentId) return null;
  const token = entry.receivedShare?.delegatedAccess;
  if (entry.receivedShare && !token) return null;
  checking.add(entry.id);
  // Nudge subscribers so rows flip to "checking…" (the flag lives outside the
  // persisted store — it must not survive a reload).
  noteEntry(entry.id, {});
  try {
    const r = await stateApi.readFromStateNode({
      contentId: entry.remoteContentId,
      localContentId: entry.localContentId,
      acceptAnyVersion: true,
      auth: token ? { delegatedToken: token.delegated_token } : undefined,
    });
    checking.delete(entry.id);
    // The entry may have moved on while we were reading (an edit landed);
    // only record against the live record.
    if (allEntries().some((e) => e.id === entry.id)) {
      noteEntry(entry.id, {
        networkHead: { version: r.version, localId: r.local_content_id, checkedAt: Date.now() },
        networkCheckError: undefined,
      });
    }
    return r;
  } catch (e) {
    checking.delete(entry.id);
    const msg =
      e instanceof ApiError ? `${e.message}${e.status ? ` (HTTP ${e.status})` : ""}` : (e as Error).message;
    if (allEntries().some((x) => x.id === entry.id)) {
      noteEntry(entry.id, { networkCheckError: msg });
    }
    return null;
  }
}

/** Check every synced file once, sequentially — the state node rate-limits. */
export async function checkAllNetworkHeads(): Promise<void> {
  for (const e of allEntries()) {
    if (e.kind === "file" && e.syncedToStateNode && e.remoteContentId) {
      await checkNetworkHead(e);
    }
  }
}
