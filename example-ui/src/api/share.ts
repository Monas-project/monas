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

export interface DecryptSharedContentOutput {
  content_id: string;
  content: string; // decrypted, base64url
  version: string;
  metadata?: { name?: string; content_type?: string };
}

export function decryptSharedContent(input: {
  contentId: string;
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
      private_key: input.privateKeyB64Url,
      sender_public_key: input.senderPublicKeyB64Url,
      recipient_key_id: input.recipientKeyId,
      key_envelope: input.keyEnvelope,
      version: input.version,
    },
  });
}
