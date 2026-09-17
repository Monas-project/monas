// Share operations via the gateway (monas-sdk share controller).
//
// The CEK is wrapped with HPKE in **Auth mode**: the sender's private key is
// mixed into the wrap, so the recipient can only unwrap against the sender's
// public key (TOFU-pinned on first use). That is why every call here carries
// sender key material, and why decrypt takes a sender *public key* rather than
// the old self-asserted sender_key_id.
import { gateway } from "./http";
import type { KeyEnvelopeData } from "../types";

export type Permission = "read" | "write";

export type KeyEnvelope = KeyEnvelopeData;

export interface DelegatedAccessToken {
  delegated_token: string;
  issued_at: number;
  expires_at: number;
  jti: string;
}

export interface ShareContentOutput {
  content_id: string;
  recipient_public_key: string;
  /** The recipient TOFU-pins this on its first envelope for the content. */
  sender_public_key: string;
  sender_key_id: string;
  recipient_key_id: string;
  key_envelope: KeyEnvelope;
  delegated_access?: DelegatedAccessToken;
  shared_at?: string;
}

export function shareContent(input: {
  contentId: string; // local content id
  /** State-node series id. The delegated token is issued for this — the
   *  state node matches capabilities by series id, so a token for the
   *  local id would never authorise the recipient. */
  remoteContentId?: string;
  senderPublicKeyB64Url: string;
  /** Required: HPKE Auth-mode wrap mixes the sender's private key in. The SDK
   *  does not persist it. */
  senderPrivateKeyB64Url: string;
  recipientPublicKeyB64Url: string;
  permissions: Permission[];
}) {
  return gateway<ShareContentOutput>("/share", {
    method: "POST",
    body: {
      content_id: input.contentId,
      remote_content_id: input.remoteContentId,
      sender_public_key: input.senderPublicKeyB64Url,
      sender_private_key: input.senderPrivateKeyB64Url,
      recipient_public_key: input.recipientPublicKeyB64Url,
      permissions: input.permissions,
    },
  });
}

/** An envelope reissued to a *surviving* recipient after a revoke rotated the
 *  CEK. Without processing this, that recipient can no longer decrypt. */
export interface ReissuedKeyEnvelope {
  recipient_key_id: string;
  key_envelope: KeyEnvelope;
  /** A fresh token: the revoke voided every token issued before it,
   *  the survivors' included. Absent only if issuance failed. */
  delegated_access?: DelegatedAccessToken;
}

export interface RevokeShareOutput {
  content_id: string;
  recipient_public_key: string;
  revoked: boolean;
  revoked_at?: string;
  reissued_envelopes?: ReissuedKeyEnvelope[];
  /** New state-node `min_valid_issued_at` (Unix seconds). Every delegated
   *  token issued at or before this is void — including ones held by the
   *  recipients that were *not* revoked. */
  token_invalidated_at?: number;
  /** The revoke pulls the Content Network head into the local record before
   *  re-encrypting (so a write-share recipient's version is rotated, not
   *  overwritten). If that pull failed, the revoke still went through on the
   *  local copy — revocation must not be blockable by a writer — and this
   *  says why, so the caller knows the head may have been lost. */
  head_pull_error?: string;
  /** How far the token cutoff got. A state-node member authorizes against
   *  its own copy of the policy, so a member the cutoff has not reached
   *  keeps accepting writes under the voided tokens until its next sync.
   *  The revoke does not wait for that (a writer must not be able to block
   *  it); this is how the UI tells "revoked everywhere" from "revoked, N
   *  members still to hear". Also absent with legacy nodes (unknown reach);
   *  absence alone does not mean no state node was involved. */
  token_invalidation_reach?: TokenInvalidationReach;
}

export interface TokenInvalidationReach {
  /** Members that took the new cutoff during the call. */
  notified_members: string[];
  /** Members the push did not reach, with the last error. Empty = every
   *  known member has it (unless `relayed`). */
  unreached_members: { node_id: string; error: string }[];
  /** The contacted node relayed the request; the two lists are unknown. */
  relayed: boolean;
}

export function revokeShare(input: {
  contentId: string;
  /** State-node series id — the state node only knows this, not the SDK-local
   *  version id, so the post-revoke re-encryption sync must address it. */
  remoteContentId?: string;
  senderPublicKeyB64Url: string;
  /** Required: surviving recipients get their envelopes re-wrapped under the
   *  rotated CEK, again in HPKE Auth mode. */
  senderPrivateKeyB64Url: string;
  recipientPublicKeyB64Url: string;
}) {
  return gateway<RevokeShareOutput>("/share/revoke", {
    method: "POST",
    timestamp: true,
    body: {
      content_id: input.contentId,
      remote_content_id: input.remoteContentId,
      sender_public_key: input.senderPublicKeyB64Url,
      sender_private_key: input.senderPrivateKeyB64Url,
      recipient_public_key: input.recipientPublicKeyB64Url,
    },
  });
}

export interface UpdateSharedContentOutput {
  remote_content_id: string;
  /** Plain content id of the version this device wrote — the id the
   *  plaintext addresses to, derived the same way the owner derives theirs. */
  version_id: string;
  updated_at?: string;
}

/**
 * Write a new version of someone else's file, as a share recipient.
 *
 * This device has no content record for the file — only the CEK the SDK
 * pinned when the share package was imported — so the gateway encrypts the
 * new plaintext with that CEK and PUTs it to the owner's Content Network
 * with the delegated token from the package. The state node accepts it only
 * if the token carries `write` and has not been voided by a revoke; the
 * gateway signs the request with this device's account key (the token's
 * audience) like every other write.
 */
export function updateSharedContent(input: {
  remoteContentId: string;
  contentBase64Url: string;
  delegatedToken: string;
}) {
  return gateway<UpdateSharedContentOutput>(
    `/share/content/${encodeURIComponent(input.remoteContentId)}`,
    {
      method: "PUT",
      timestamp: true,
      headers: { Authorization: `Bearer ${input.delegatedToken}` },
      body: { content: input.contentBase64Url },
    },
  );
}

export interface DecryptSharedContentOutput {
  content_id: string;
  content: string; // decrypted, base64url
  version: string;
  metadata?: { name?: string; content_type?: string };
}

export function decryptSharedContent(input: {
  contentId: string;
  /** Series id: the sender pin (TOFU key + key_epoch + CEK) is kept under
   *  it, so a stale envelope is caught even after the owner's edits have
   *  changed the content id. */
  remoteContentId?: string;
  privateKeyB64Url: string;
  /** Sender public key for the HPKE Auth unwrap. On the first envelope for
   *  this content the SDK pins it (TOFU); later envelopes must match. */
  senderPublicKeyB64Url: string;
  recipientKeyId: string;
  keyEnvelope: KeyEnvelope;
  version?: string;
}) {
  return gateway<DecryptSharedContentOutput>("/share/decrypt", {
    method: "POST",
    body: {
      content_id: input.contentId,
      remote_content_id: input.remoteContentId,
      private_key: input.privateKeyB64Url,
      sender_public_key: input.senderPublicKeyB64Url,
      recipient_key_id: input.recipientKeyId,
      key_envelope: input.keyEnvelope,
      version: input.version,
    },
  });
}
