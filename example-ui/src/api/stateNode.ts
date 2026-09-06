// State / version operations via the gateway (monas-sdk state controller).
import { gateway } from "./http";

/**
 * How a state-node call is authorised. By default the gateway signs as this
 * device's account and the state node treats the caller as the content's
 * owner. A share recipient instead presents the delegated token from the
 * share package; the gateway still signs with the account key (the token's
 * audience), so the identity that received the share must be this device's
 * signing account.
 */
export interface StateAuth {
  delegatedToken?: string;
}

function authHeaders(auth?: StateAuth): Record<string, string> {
  return auth?.delegatedToken ? { Authorization: `Bearer ${auth.delegatedToken}` } : {};
}

export interface GetLatestVersionOutput {
  content_id: string;
  latest_version: string;
  updated_at?: string;
}

export function getLatestVersion(contentId: string, auth?: StateAuth) {
  return gateway<GetLatestVersionOutput>("/state/latest-version", {
    method: "POST",
    timestamp: true,
    headers: authHeaders(auth),
    body: { content_id: contentId },
  });
}

export interface GetHistoryOutput {
  content_id: string;
  versions: string[];
}

export function getHistory(contentId: string, limit = 100, auth?: StateAuth) {
  return gateway<GetHistoryOutput>("/state/history", {
    method: "POST",
    timestamp: true,
    headers: authHeaders(auth),
    body: { content_id: contentId, limit },
  });
}

export interface ReadFromStateNodeOutput {
  content_id: string;
  /** The id the decrypted plaintext addresses to. Equals the requested
   *  `localContentId` unless `acceptAnyVersion` let a newer version through. */
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
  /** For a share recipient: `localContentId` only selects the CEK (the id the
   *  share came in as) and the plaintext is not required to re-address to
   *  it, since the owner may have written newer versions since. */
  acceptAnyVersion?: boolean;
  auth?: StateAuth;
}) {
  return gateway<ReadFromStateNodeOutput>("/state/read", {
    method: "POST",
    timestamp: true,
    headers: authHeaders(input.auth),
    body: {
      content_id: input.contentId,
      local_content_id: input.localContentId,
      version: input.version,
      accept_any_version: input.acceptAnyVersion ?? false,
    },
  });
}

export interface PullFromStateNodeOutput {
  content_id: string;
  /** The local id after the pull — the head's plain id if it was adopted. */
  local_content_id: string;
  version: string;
  /** True when the head was someone else's version and the local record
   *  moved to it. */
  adopted: boolean;
  content: string; // head plaintext, base64url
}

/**
 * Owner-side pull: adopt the Content Network's newest version into the
 * gateway's local record. Needed once a recipient with write access has
 * edited — the local copy is then behind the head, and any owner-side
 * re-publish (an edit, a revoke's re-encryption) would overwrite the
 * recipient's version with stale plaintext. The SDK's revoke pulls by
 * itself; the editor calls this before opening.
 */
export function pullFromStateNode(input: { contentId: string; localContentId: string }) {
  return gateway<PullFromStateNodeOutput>("/state/pull", {
    method: "POST",
    timestamp: true,
    body: { content_id: input.contentId, local_content_id: input.localContentId },
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
