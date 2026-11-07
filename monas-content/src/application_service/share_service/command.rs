use crate::domain::content_id::ContentId;
use crate::domain::share::{KeyEnvelope, KeyId, Permission};

/// Input for the use case that shares content with a single recipient.
///
/// - The client only passes the recipient's public key bytes; the application generates and stores
///   the KeyId.
#[derive(Debug)]
pub struct GrantShareCommand {
    pub content_id: ContentId,
    pub sender_key_id: KeyId,
    /// Sender's secret key bytes. Used for the HPKE Auth mode wrap (sender authentication).
    /// Not stored; used only for the duration of this call.
    pub sender_private_key: Vec<u8>,
    pub recipient_public_key: Vec<u8>,
    pub permission: Permission,
}

/// Output of the share-grant use case.
#[derive(Debug)]
pub struct GrantShareResult {
    pub envelope: KeyEnvelope,
    pub recipient_key_id: KeyId,
}

/// Input for the use case that revokes a share.
#[derive(Debug)]
pub struct RevokeShareCommand {
    pub content_id: ContentId,
    pub sender_key_id: KeyId,
    /// Sender's secret key bytes. Used for the HPKE Auth mode wrap (sender authentication) when
    /// reissuing KeyEnvelopes for the remaining recipients.
    pub sender_private_key: Vec<u8>,
    pub recipient_key_id: KeyId,
}

/// Output of the share-revoke use case.
#[derive(Debug)]
pub struct RevokeShareResult {
    pub content_id: ContentId,
    pub recipient_key_id: KeyId,
    pub envelopes: Vec<KeyEnvelope>,
}

/// Input for the use case that changes an existing recipient's permission.
///
/// The CEK and ciphertext are unchanged (the permission lives only in the delegated token, so the
/// KeyEnvelope stays valid).
#[derive(Debug)]
pub struct UpdateSharePermissionCommand {
    pub content_id: ContentId,
    pub recipient_key_id: KeyId,
    pub permission: Permission,
}

/// Output of the permission-change use case.
#[derive(Debug)]
pub struct UpdateSharePermissionResult {
    pub content_id: ContentId,
    pub recipient_key_id: KeyId,
    /// Permission before the change.
    pub previous: Vec<Permission>,
    /// Permission after the change.
    pub current: Vec<Permission>,
}
