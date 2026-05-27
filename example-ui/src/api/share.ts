// Share operations via the gateway (monas-sdk share controller).
import { gateway } from "./http";

export type Permission = "read" | "write";

export interface KeyEnvelope {
  enc: string; // base64url
  wrapped_cek: string; // base64url
  ciphertext: string; // base64url
}

export interface DelegatedAccessToken {
  delegated_token: string;
  issued_at: number;
  expires_at: number;
  jti: string;
}

export interface ShareContentOutput {
  content_id: string;
  recipient_public_key: string;
  sender_key_id: string;
  recipient_key_id: string;
  key_envelope: KeyEnvelope;
  delegated_access?: DelegatedAccessToken;
  shared_at?: string;
}

export function shareContent(input: {
  contentId: string; // local content id
  senderPublicKeyB64Url: string;
  recipientPublicKeyB64Url: string;
  permissions: Permission[];
}) {
  return gateway<ShareContentOutput>("/share", {
    method: "POST",
    body: {
      content_id: input.contentId,
      sender_public_key: input.senderPublicKeyB64Url,
      recipient_public_key: input.recipientPublicKeyB64Url,
      permissions: input.permissions,
    },
  });
}

export interface RevokeShareOutput {
  content_id: string;
  recipient_public_key: string;
  revoked: boolean;
  revoked_at?: string;
}

export function revokeShare(input: {
  contentId: string;
  senderPublicKeyB64Url: string;
  recipientPublicKeyB64Url: string;
}) {
  return gateway<RevokeShareOutput>("/share/revoke", {
    method: "POST",
    timestamp: true,
    body: {
      content_id: input.contentId,
      sender_public_key: input.senderPublicKeyB64Url,
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
  senderKeyId: string;
  recipientKeyId: string;
  keyEnvelope: KeyEnvelope;
  version?: string;
}) {
  return gateway<DecryptSharedContentOutput>("/share/decrypt", {
    method: "POST",
    body: {
      content_id: input.contentId,
      private_key: input.privateKeyB64Url,
      sender_key_id: input.senderKeyId,
      recipient_key_id: input.recipientKeyId,
      key_envelope: input.keyEnvelope,
      version: input.version,
    },
  });
}
