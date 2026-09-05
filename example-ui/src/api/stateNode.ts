// State / version operations via the gateway (monas-sdk state controller).
import { gateway } from "./http";

export interface GetLatestVersionOutput {
  content_id: string;
  latest_version: string;
  updated_at?: string;
}

export function getLatestVersion(contentId: string) {
  return gateway<GetLatestVersionOutput>("/state/latest-version", {
    method: "POST",
    timestamp: true,
    body: { content_id: contentId },
  });
}

export interface GetHistoryOutput {
  content_id: string;
  versions: string[];
}

export function getHistory(contentId: string, limit = 100) {
  return gateway<GetHistoryOutput>("/state/history", {
    method: "POST",
    timestamp: true,
    body: { content_id: contentId, limit },
  });
}

export interface ReadFromStateNodeOutput {
  content_id: string;
  local_content_id: string;
  /** The version actually read, already verified by CID recomputation. */
  version: string;
  /** Decrypted plaintext, base64url. */
  content: string;
}

/**
 * Verified read: fetches the crsl-lib Node from the state node, recomputes its
 * CID, decrypts with the CEK (AES-256-GCM) and re-checks the plaintext CID.
 *
 * This is the only read path that proves the returned bytes really are the
 * requested version — `getContent` reads the gateway's own local store and so
 * never exercises the relay at all.
 *
 * What it does *not* prove: that the version is the latest, or that a
 * legitimate writer produced it. Version metadata has no trust anchor yet
 * (issue #59).
 *
 * Both ids are required and are not interchangeable: `contentId` is the
 * state-node series id (also what the read signature binds to), while
 * `localContentId` selects the CEK and is re-derived from the plaintext.
 */
export function readFromStateNode(input: {
  contentId: string;
  localContentId: string;
  /** Omit to read whatever the state node reports as the newest version. */
  version?: string;
}) {
  return gateway<ReadFromStateNodeOutput>("/state/read", {
    method: "POST",
    timestamp: true,
    body: {
      content_id: input.contentId,
      local_content_id: input.localContentId,
      version: input.version,
    },
  });
}

export interface VerifyIntegrityOutput {
  valid: boolean;
  computed_hash: string;
  reason?: string;
}

export function verifyIntegrity(input: {
  contentId: string;
  contentBase64Url: string;
  expectedVersion?: string;
  /** SDK-local version id — lets the SDK compare the state-node ciphertext
   *  against its locally stored ciphertext (the state node never sees
   *  plaintext, so a plaintext comparison can never match). */
  localContentId?: string;
}) {
  return gateway<VerifyIntegrityOutput>("/state/verify-integrity", {
    method: "POST",
    timestamp: true,
    body: {
      content_id: input.contentId,
      content: input.contentBase64Url,
      expected_version: input.expectedVersion,
      local_content_id: input.localContentId,
    },
  });
}
