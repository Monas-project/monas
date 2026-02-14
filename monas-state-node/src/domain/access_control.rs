//! ContentAccessControl - Version-based access control for shared content.
//!
//! This module provides the domain model for managing access control on State Nodes.
//! It uses `min_valid_issued_at` to invalidate tokens issued before a certain timestamp.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Access control state for a single content.
///
/// State Nodes maintain this for each content they manage.
/// When verifying a AuthToken, the token's `iat` must be >= `min_valid_issued_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentAccessControl {
    /// The content ID this access control applies to.
    content_id: String,
    /// Minimum valid issued_at timestamp.
    /// Tokens with iat < min_valid_issued_at are considered invalidated.
    min_valid_issued_at: u64,
    /// Version number for CRDT conflict resolution.
    /// Higher version wins in case of concurrent updates.
    version: u64,
    /// Last updated timestamp.
    updated_at: u64,
}

impl ContentAccessControl {
    /// Create a new access control with default values.
    ///
    /// Initially, min_valid_issued_at is 0, meaning all tokens are valid.
    pub fn new(content_id: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        Self {
            content_id,
            min_valid_issued_at: 0,
            version: 1,
            updated_at: now,
        }
    }

    /// Create an access control with specific values (for deserialization).
    pub fn with_values(
        content_id: String,
        min_valid_issued_at: u64,
        version: u64,
        updated_at: u64,
    ) -> Self {
        Self {
            content_id,
            min_valid_issued_at,
            version,
            updated_at,
        }
    }

    /// Get the content ID.
    pub fn content_id(&self) -> &str {
        &self.content_id
    }

    /// Get the minimum valid issued_at timestamp.
    pub fn min_valid_issued_at(&self) -> u64 {
        self.min_valid_issued_at
    }

    /// Get the version number.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Get the last updated timestamp.
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }

    /// Check if a token with the given issued_at is valid.
    pub fn is_token_valid(&self, issued_at: u64) -> bool {
        issued_at >= self.min_valid_issued_at
    }

    /// Invalidate all tokens issued before the given timestamp.
    ///
    /// Returns an error if the new timestamp is less than the current min_valid_issued_at.
    pub fn invalidate_before(
        &mut self,
        new_min_valid_issued_at: u64,
    ) -> Result<AccessControlEvent, AccessControlError> {
        if new_min_valid_issued_at < self.min_valid_issued_at {
            return Err(AccessControlError::InvalidTimestamp {
                current: self.min_valid_issued_at,
                requested: new_min_valid_issued_at,
            });
        }

        let old_min = self.min_valid_issued_at;
        self.min_valid_issued_at = new_min_valid_issued_at;
        self.version += 1;
        self.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        Ok(AccessControlEvent::TokensInvalidated {
            content_id: self.content_id.clone(),
            old_min_valid_issued_at: old_min,
            new_min_valid_issued_at,
            version: self.version,
        })
    }

    /// Merge with another access control state (for CRDT).
    ///
    /// Uses Last-Writer-Wins with version as the tie-breaker.
    /// Higher version wins. If versions are equal, higher min_valid_issued_at wins.
    pub fn merge(&mut self, other: &ContentAccessControl) -> bool {
        if other.content_id != self.content_id {
            return false;
        }

        // Higher version wins
        if other.version > self.version {
            self.min_valid_issued_at = other.min_valid_issued_at;
            self.version = other.version;
            self.updated_at = other.updated_at;
            return true;
        }

        // Same version: higher min_valid_issued_at wins (more restrictive)
        if other.version == self.version && other.min_valid_issued_at > self.min_valid_issued_at {
            self.min_valid_issued_at = other.min_valid_issued_at;
            self.updated_at = other.updated_at;
            return true;
        }

        false
    }
}

/// Events emitted by access control operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessControlEvent {
    /// Tokens issued before a certain timestamp have been invalidated.
    TokensInvalidated {
        content_id: String,
        old_min_valid_issued_at: u64,
        new_min_valid_issued_at: u64,
        version: u64,
    },
}

/// Errors that can occur during access control operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessControlError {
    /// The requested timestamp is less than the current min_valid_issued_at.
    InvalidTimestamp { current: u64, requested: u64 },
    /// The content was not found.
    ContentNotFound,
    /// Signature verification failed.
    InvalidSignature,
    /// The signer is not authorized to update access control.
    NotAuthorized,
}

impl std::fmt::Display for AccessControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessControlError::InvalidTimestamp { current, requested } => {
                write!(
                    f,
                    "Invalid timestamp: requested {} is less than current {}",
                    requested, current
                )
            }
            AccessControlError::ContentNotFound => write!(f, "Content not found"),
            AccessControlError::InvalidSignature => write!(f, "Invalid signature"),
            AccessControlError::NotAuthorized => write!(f, "Not authorized"),
        }
    }
}

impl std::error::Error for AccessControlError {}

/// Signed update request for access control.
///
/// This is sent by content owners to State Nodes to update access control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlUpdate {
    /// The content ID to update.
    pub content_id: String,
    /// The new min_valid_issued_at value.
    pub new_min_valid_issued_at: u64,
    /// The signer's public key (owner).
    pub signer_public_key: Vec<u8>,
    /// Signature over (content_id || new_min_valid_issued_at).
    pub signature: Vec<u8>,
}

impl AccessControlUpdate {
    /// Create a new unsigned update request.
    pub fn new(content_id: String, new_min_valid_issued_at: u64) -> Self {
        Self {
            content_id,
            new_min_valid_issued_at,
            signer_public_key: Vec::new(),
            signature: Vec::new(),
        }
    }

    /// Get the message to sign.
    ///
    /// The caller should use `monas-account` to sign these bytes.
    pub fn signing_message(&self) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(self.content_id.as_bytes());
        msg.extend_from_slice(&self.new_min_valid_issued_at.to_be_bytes());
        msg
    }

    /// Set the signature and signer's public key.
    ///
    /// Use this after signing `signing_message()` with `monas-account`.
    pub fn with_signature(mut self, signature: Vec<u8>, signer_public_key: Vec<u8>) -> Self {
        self.signature = signature;
        self.signer_public_key = signer_public_key;
        self
    }

    /// Get the signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Get the signer's public key bytes.
    pub fn signer_public_key(&self) -> &[u8] {
        &self.signer_public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_access_control_has_zero_min_valid_issued_at() {
        let ac = ContentAccessControl::new("content-1".to_string());
        assert_eq!(ac.content_id(), "content-1");
        assert_eq!(ac.min_valid_issued_at(), 0);
        assert_eq!(ac.version(), 1);
    }

    #[test]
    fn is_token_valid_returns_true_for_valid_tokens() {
        let ac = ContentAccessControl::new("content-1".to_string());
        assert!(ac.is_token_valid(0));
        assert!(ac.is_token_valid(1000));
        assert!(ac.is_token_valid(u64::MAX));
    }

    #[test]
    fn invalidate_before_updates_min_valid_issued_at() {
        let mut ac = ContentAccessControl::new("content-1".to_string());
        let event = ac.invalidate_before(1000).expect("Should succeed");

        assert_eq!(ac.min_valid_issued_at(), 1000);
        assert_eq!(ac.version(), 2);
        assert!(matches!(
            event,
            AccessControlEvent::TokensInvalidated {
                new_min_valid_issued_at: 1000,
                ..
            }
        ));
    }

    #[test]
    fn invalidate_before_rejects_lower_timestamp() {
        let mut ac = ContentAccessControl::new("content-1".to_string());
        ac.invalidate_before(1000).expect("Should succeed");

        let err = ac
            .invalidate_before(500)
            .expect_err("Should fail with lower timestamp");
        assert!(matches!(
            err,
            AccessControlError::InvalidTimestamp {
                current: 1000,
                requested: 500
            }
        ));
    }

    #[test]
    fn is_token_valid_after_invalidation() {
        let mut ac = ContentAccessControl::new("content-1".to_string());
        ac.invalidate_before(1000).expect("Should succeed");

        assert!(!ac.is_token_valid(0));
        assert!(!ac.is_token_valid(999));
        assert!(ac.is_token_valid(1000));
        assert!(ac.is_token_valid(1001));
    }

    #[test]
    fn merge_higher_version_wins() {
        let mut ac1 = ContentAccessControl::with_values("content-1".to_string(), 100, 1, 1000);
        let ac2 = ContentAccessControl::with_values("content-1".to_string(), 200, 2, 2000);

        let changed = ac1.merge(&ac2);
        assert!(changed);
        assert_eq!(ac1.min_valid_issued_at(), 200);
        assert_eq!(ac1.version(), 2);
    }

    #[test]
    fn merge_same_version_higher_min_wins() {
        let mut ac1 = ContentAccessControl::with_values("content-1".to_string(), 100, 1, 1000);
        let ac2 = ContentAccessControl::with_values("content-1".to_string(), 200, 1, 2000);

        let changed = ac1.merge(&ac2);
        assert!(changed);
        assert_eq!(ac1.min_valid_issued_at(), 200);
    }

    #[test]
    fn merge_lower_version_does_not_change() {
        let mut ac1 = ContentAccessControl::with_values("content-1".to_string(), 200, 2, 2000);
        let ac2 = ContentAccessControl::with_values("content-1".to_string(), 100, 1, 1000);

        let changed = ac1.merge(&ac2);
        assert!(!changed);
        assert_eq!(ac1.min_valid_issued_at(), 200);
        assert_eq!(ac1.version(), 2);
    }

    #[test]
    fn merge_different_content_id_does_not_change() {
        let mut ac1 = ContentAccessControl::with_values("content-1".to_string(), 100, 1, 1000);
        let ac2 = ContentAccessControl::with_values("content-2".to_string(), 200, 2, 2000);

        let changed = ac1.merge(&ac2);
        assert!(!changed);
        assert_eq!(ac1.min_valid_issued_at(), 100);
    }

    #[test]
    fn access_control_update_signing_message_is_consistent() {
        let update = AccessControlUpdate::new("content-1".to_string(), 1000);
        let msg1 = update.signing_message();
        let msg2 = update.signing_message();

        assert_eq!(msg1, msg2);
        assert!(!msg1.is_empty());
    }

    #[test]
    fn access_control_update_with_signature_sets_values() {
        let update = AccessControlUpdate::new("content-1".to_string(), 1000);
        assert!(update.signature().is_empty());
        assert!(update.signer_public_key().is_empty());

        let signature = vec![0x01, 0x02, 0x03];
        let public_key = vec![0x04, 0x05, 0x06];
        let signed_update = update.with_signature(signature.clone(), public_key.clone());

        assert_eq!(signed_update.signature(), &signature);
        assert_eq!(signed_update.signer_public_key(), &public_key);
    }
}
