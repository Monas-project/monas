use serde::{Deserialize, Serialize};

use super::content::ContentMetadata;

/// Permission kind
///
/// Because of `#[non_exhaustive]`, always include a `_ =>` fallthrough so downstream `match`
/// does not break when a variant is added in the future.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Permission {
    Read,
    Write,
}

/// KeyEnvelope (encrypted CEK + associated data)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEnvelope {
    /// HPKE encapsulated public key (base64url)
    pub enc: String,
    /// Encrypted CEK (base64url)
    pub wrapped_cek: String,
    /// Encrypted content (base64url)
    pub ciphertext: String,
    /// Key epoch of the CEK. Incremented by 1 on every rotation (revoke). It is bound into the
    /// wrap AAD, so tampering with it makes decryption itself fail. The recipient rejects
    /// envelopes older than the recorded epoch (prevents replay rolling back to an old CEK).
    #[serde(default)]
    pub key_epoch: u64,
}

// ============================================
// share_content
// ============================================

/// Content share request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareContentInput {
    /// Key of the target file (`CreateContentOutput::file_id`). The wrapped CEK, ciphertext,
    /// and envelope content_id (plainCid) are those of this file's current version.
    pub file_id: String,
    /// Series ID registered with the State Node (same distinction as `UpdateContentInput` /
    /// `RevokeShareInput`). The delegated token's resource is issued with this: the State Node
    /// matches capabilities against `monas://content/<series ID>`. If unset (local-only content
    /// not registered with a State Node), no token is issued.
    /// The file key never leaves the device, so it is never used in its place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_content_id: Option<String>,
    /// Sender's public key (base64url) - used to compute sender_key_id
    pub sender_public_key: String,
    /// Sender's private key (base64url). Used for the KeyEnvelope HPKE Auth mode wrap
    /// (sender authentication). Not stored by the SDK.
    pub sender_private_key: String,
    /// Public key of the share target (base64url)
    pub recipient_public_key: String,
    #[serde(default = "default_permissions")]
    pub permissions: Vec<Permission>,
}

fn default_permissions() -> Vec<Permission> {
    vec![Permission::Read]
}

/// Content share response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareContentOutput {
    /// plainCid of the version the envelope points to (the current version).
    pub content_id: String,
    pub recipient_public_key: String,
    /// Sender's public key (base64url). The recipient passes this to `decrypt_shared_content`
    /// and pins it via TOFU on first processing (it becomes the root of later envelope
    /// verification).
    pub sender_public_key: String,
    pub sender_key_id: String,
    pub recipient_key_id: String,
    pub key_envelope: KeyEnvelope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_access: Option<DelegatedAccessToken>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_at: Option<String>,
}

/// Result of issuing a delegated token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedAccessToken {
    pub delegated_token: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub jti: String,
}

// ============================================
// revoke_share
// ============================================

/// Share revocation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeShareInput {
    /// Key of the target file (`CreateContentOutput::file_id`)
    pub file_id: String,
    /// Series ID sent to the State Node. If unset, the content is treated as local-only, and no
    /// revocation on the State Node, post-re-encryption write, or token reissue is performed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_content_id: Option<String>,
    /// Sender's public key (base64url) - used to compute sender_key_id
    pub sender_public_key: String,
    /// Sender's private key (base64url). Used for the HPKE Auth mode wrap when reissuing
    /// KeyEnvelopes for remaining recipients. Not stored by the SDK.
    pub sender_private_key: String,
    pub recipient_public_key: String,
}

/// Share revocation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeShareOutput {
    /// plainCid of the current version after re-encryption (the version reissued envelopes
    /// point to).
    pub content_id: String,
    pub recipient_public_key: String,
    pub revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    /// KeyEnvelopes reissued with the rotated CEK for recipients whose share remains after the
    /// revocation. The caller (owner) distributes these to each recipient; by processing them
    /// with `decrypt_shared_content`, the recipient's locally stored CEK is updated to the new
    /// one (reads via the state node can still be decrypted).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reissued_envelopes: Vec<ReissuedKeyEnvelope>,
    /// New `min_valid_issued_at` (Unix seconds) set by the state node.
    /// All delegated tokens issued before this are revoked.
    /// `None` when run without state node integration.
    ///
    /// Unlike CEK rotation, this decides "whether the revoked party can still write". Remaining
    /// recipients must be redistributed tokens issued after this time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_invalidated_at: Option<u64>,
    /// Before re-encrypting, revoke pulls the State Node head into the local record (so as not
    /// to roll back versions written by recipients delegated write). This is the reason that
    /// pull failed. The revoke itself proceeds with the local version — a revocation must not
    /// be blockable by a writer — so the caller should treat this as "the head may have been
    /// lost".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_pull_error: Option<String>,
    /// How far the revocation boundary (`token_invalidated_at`) reached.
    ///
    /// State Node authorization is a local decision per member, so members that have not
    /// received the boundary **accept writes with revoked tokens** until the next sync.
    /// The revoke itself does not wait for that (a writer must not block a revocation), so the
    /// caller distinguishes "reached everyone" from "not yet reached N nodes" here.
    /// `None` without state node integration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_invalidation_reach: Option<TokenInvalidationReach>,
}

/// How far a revoke's revocation boundary propagated to members.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenInvalidationReach {
    /// Members that received the boundary and authorize with it from now on.
    pub notified_members: Vec<String>,
    /// Members that were not reached, with the last error. Empty = reached all known members
    /// (unless `relayed`).
    pub unreached_members: Vec<UnreachedMember>,
    /// The State Node relayed instead of committing. The two fields above are unknown.
    pub relayed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnreachedMember {
    pub node_id: String,
    pub error: String,
}

/// KeyEnvelope reissued for a remaining recipient after a revoke.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReissuedKeyEnvelope {
    /// Key id of the recipient the envelope was reissued to (base64url)
    pub recipient_key_id: String,
    pub key_envelope: KeyEnvelope,
    /// Reissued delegated token. A revoke advances the State Node's `min_valid_issued_at`, so
    /// the tokens held by remaining recipients are revoked as well. Unless delivered together
    /// with the new envelope, that recipient can decrypt but cannot read from the State Node.
    /// `None` if issuing failed (the envelope reissue itself still succeeded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_access: Option<DelegatedAccessToken>,
}

// ============================================
// update_share_permission
// ============================================

/// Request to change the permission of an existing share target.
///
/// Re-sharing (`share_content`) fails with `AlreadyShared` for the same recipient, so switching
/// read ⇄ write is done here. The CEK is not rotated (permissions live only in the delegated
/// token).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSharePermissionInput {
    /// Key of the target file (`CreateContentOutput::file_id`)
    pub file_id: String,
    /// State Node series ID. Used as the token's resource and as the target of token revocation
    /// on downgrade. Required because permissions live only in the token (unset is a
    /// Validation error).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_content_id: Option<String>,
    pub recipient_public_key: String,
    pub permissions: Vec<Permission>,
}

/// Permission change response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSharePermissionOutput {
    /// plainCid of the current version.
    pub content_id: String,
    pub recipient_public_key: String,
    pub recipient_key_id: String,
    /// Permissions after the change (`read` / `write`)
    pub permissions: Vec<Permission>,
    /// Delegated token for this recipient, reissued with the changed permissions.
    pub delegated_access: DelegatedAccessToken,
    /// A downgrade (write → read) advances the State Node's `min_valid_issued_at` to stop the
    /// old write token. These are the reissued tokens of other recipients revoked by that. A
    /// request that does not change permissions (e.g. a retry after losing a downgrade's
    /// response) also returns the other recipients' tokens, without revoking. Empty on upgrade.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reissued_tokens: Vec<ReissuedDelegatedToken>,
    /// `min_valid_issued_at` advanced by the downgrade. `None` if nothing was revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_invalidated_at: Option<u64>,
    /// How far the revocation boundary reached members (same meaning as `RevokeShareOutput`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_invalidation_reach: Option<TokenInvalidationReach>,
}

/// Delegated token reissued for another recipient after a revocation caused by a permission
/// change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReissuedDelegatedToken {
    /// Recipient key id (base64url)
    pub recipient_key_id: String,
    /// Always `Some` in responses from the current SDK (a failure to issue fails the whole
    /// request). `Option` is kept only for wire compatibility: deserializes to `None` if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_access: Option<DelegatedAccessToken>,
}

// ============================================
// decrypt_shared_content
// ============================================

/// Shared content decryption request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptSharedContentInput {
    pub content_id: String,
    /// State Node series ID. The sender pin (TOFU sender key, key epoch, CEK) is stored keyed by
    /// this. `content_id` is the owner-side version ID and changes on every edit, so pinning by
    /// version ID would put "an old pre-edit envelope" in a different place from the new epoch's
    /// record and slip past replay detection. If unset, `content_id` is used (for local-only
    /// content not registered with a State Node).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_content_id: Option<String>,
    pub private_key: String,
    /// Sender's public key (base64url). Used for the HPKE Auth mode unwrap.
    /// If this is the first envelope processed for this content it is pinned via TOFU, and
    /// afterwards it is rejected if it does not match the pinned key.
    pub sender_public_key: String,
    pub recipient_key_id: String,
    pub key_envelope: KeyEnvelope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Shared content decryption response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptSharedContentOutput {
    pub content_id: String,
    /// Decrypted content (base64url)
    pub content: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ContentMetadata>,
}

/// Request for the share recipient to update the content.
///
/// The recipient has no local content record (it only has the CEK extracted from the envelope
/// and the sender pin). The new plaintext is encrypted with that CEK and PUT to the owner's
/// Content Network (`remote_content_id`) with a write delegated token. The State Node verifies
/// the signature with the token's `aud` key (this device's account key) and permits the write
/// via the token's capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSharedContentInput {
    /// State Node series ID (`remote_content_id` of the owner's share package).
    pub remote_content_id: String,
    /// New plaintext (base64url).
    pub content: String,
}

/// Update response for the share recipient
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSharedContentOutput {
    pub remote_content_id: String,
    /// Content id (plain CID) of the new plaintext. Derived by the same rule as the owner-side
    /// version ID, so it becomes the `local_content_id` when reading this version later.
    pub version_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_serialization() {
        let read = Permission::Read;
        assert_eq!(serde_json::to_string(&read).unwrap(), "\"read\"");

        let write = Permission::Write;
        assert_eq!(serde_json::to_string(&write).unwrap(), "\"write\"");
    }

    #[test]
    fn test_key_envelope() {
        let envelope = KeyEnvelope {
            enc: "enc_data".into(),
            wrapped_cek: "wrapped_cek_data".into(),
            ciphertext: "ciphertext_data".into(),
            key_epoch: 0,
        };
        let json = serde_json::to_string(&envelope).unwrap();
        assert!(json.contains("\"enc\":\"enc_data\""));
        assert!(json.contains("\"wrapped_cek\":\"wrapped_cek_data\""));
        assert!(json.contains("\"ciphertext\":\"ciphertext_data\""));
    }

    #[test]
    fn test_share_content_input_default_permissions() {
        let json = r#"{
            "file_id": "test_id",
            "sender_public_key": "sender_pub",
            "sender_private_key": "sender_priv",
            "recipient_public_key": "recipient_key"
        }"#;
        let input: ShareContentInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.permissions, vec![Permission::Read]);
    }

    #[test]
    fn test_share_content_input_with_permissions() {
        let json = r#"{
            "file_id": "test_id",
            "sender_public_key": "sender_pub",
            "sender_private_key": "sender_priv",
            "recipient_public_key": "recipient_key",
            "permissions": ["read", "write"]
        }"#;
        let input: ShareContentInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.permissions, vec![Permission::Read, Permission::Write]);
    }

    #[test]
    fn test_share_content_output() {
        let output = ShareContentOutput {
            content_id: "test_id".into(),
            recipient_public_key: "recipient_key".into(),
            sender_public_key: "sender_public_key".into(),
            sender_key_id: "sender_key_id".into(),
            recipient_key_id: "recipient_key_id".into(),
            key_envelope: KeyEnvelope {
                enc: "enc".into(),
                wrapped_cek: "cek".into(),
                ciphertext: "ct".into(),
                key_epoch: 0,
            },
            delegated_access: Some(DelegatedAccessToken {
                delegated_token: "jwt".into(),
                issued_at: 1,
                expires_at: 2,
                jti: "jti".into(),
            }),
            shared_at: Some("2025-12-05T12:34:56Z".into()),
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"content_id\":\"test_id\""));
        assert!(json.contains("\"key_envelope\""));
    }

    #[test]
    fn test_revoke_share_output() {
        let output = RevokeShareOutput {
            content_id: "test_id".into(),
            recipient_public_key: "recipient_key".into(),
            revoked: true,
            revoked_at: Some("2025-12-05T12:34:56Z".into()),
            reissued_envelopes: vec![],
            token_invalidated_at: None,
            head_pull_error: None,
            token_invalidation_reach: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"revoked\":true"));
        assert!(!json.contains("head_pull_error"));
        // An empty envelope list is not serialized (backward compatible)
        assert!(!json.contains("reissued_envelopes"));
        // Without state node integration, the revocation time is not emitted either
        assert!(!json.contains("token_invalidated_at"));
    }

    #[test]
    fn test_revoke_share_output_reports_token_invalidation() {
        let output = RevokeShareOutput {
            content_id: "test_id".into(),
            recipient_public_key: "recipient_key".into(),
            revoked: true,
            revoked_at: None,
            reissued_envelopes: vec![],
            token_invalidated_at: Some(1_700_000_000),
            head_pull_error: None,
            token_invalidation_reach: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"token_invalidated_at\":1700000000"));
    }

    #[test]
    fn test_revoke_share_output_with_reissued_envelopes() {
        let output = RevokeShareOutput {
            content_id: "test_id".into(),
            recipient_public_key: "recipient_key".into(),
            revoked: true,
            revoked_at: None,
            reissued_envelopes: vec![ReissuedKeyEnvelope {
                recipient_key_id: "surviving-recipient".into(),
                key_envelope: KeyEnvelope {
                    enc: "enc".into(),
                    wrapped_cek: "wrapped".into(),
                    ciphertext: "cipher".into(),
                    key_epoch: 1,
                },

                delegated_access: None,
            }],
            token_invalidated_at: None,
            head_pull_error: None,
            token_invalidation_reach: None,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains("\"reissued_envelopes\""));
        assert!(json.contains("\"recipient_key_id\":\"surviving-recipient\""));
    }

    #[test]
    fn test_decrypt_shared_content_input() {
        let input = DecryptSharedContentInput {
            content_id: "test_id".into(),
            remote_content_id: None,
            private_key: "test_key".into(),
            sender_public_key: "sender_public_key".into(),
            recipient_key_id: "recipient_key_id".into(),
            key_envelope: KeyEnvelope {
                enc: "enc".into(),
                wrapped_cek: "cek".into(),
                ciphertext: "ct".into(),
                key_epoch: 0,
            },
            version: None,
        };
        let json = serde_json::to_string(&input).unwrap();
        assert!(json.contains("\"content_id\":\"test_id\""));
        assert!(json.contains("\"key_envelope\""));
        assert!(!json.contains("version"));
    }
}
