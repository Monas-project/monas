//! Access policy for content authorization.
//!
//! This module defines access control policies for content.
//! The node stores only owner identity and min_valid_issued_at for token invalidation.
//! Non-owner access is determined entirely by AuthToken (JWT) verification.

use super::identity::Identity;
use super::value_objects::ContentId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Access policy for content
///
/// This represents the access control rules for a specific piece of content.
/// The node only stores the owner and a min_valid_issued_at timestamp.
/// Non-owner access is determined by AuthToken signature verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessPolicy {
    content_id: ContentId,
    owner: Identity,
    /// Legacy grants field - kept for backward compatibility with existing serialized data.
    /// Always empty in new policies. Will be ignored during authorization.
    #[serde(default)]
    grants: HashMap<String, serde_json::Value>,
    created_at: u64,
    updated_at: u64,
    /// Minimum valid issued_at timestamp for AuthTokens.
    /// Tokens with iat < min_valid_issued_at are considered invalidated.
    #[serde(default)]
    min_valid_issued_at: u64,
}

impl AccessPolicy {
    /// Create a new access policy for content
    pub fn new(content_id: ContentId, owner: Identity) -> Self {
        let now = current_timestamp();

        Self {
            content_id,
            owner,
            grants: HashMap::new(),
            created_at: now,
            updated_at: now,
            min_valid_issued_at: 0,
        }
    }

    /// Check if an identity is the owner
    pub fn is_owner(&self, identity: &Identity) -> bool {
        &self.owner == identity
    }

    /// Get the content ID
    pub fn content_id(&self) -> &ContentId {
        &self.content_id
    }

    /// Get the owner
    pub fn owner(&self) -> &Identity {
        &self.owner
    }

    /// Get created timestamp
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get updated timestamp
    pub fn updated_at(&self) -> u64 {
        self.updated_at
    }

    /// Get the minimum valid issued_at timestamp
    pub fn min_valid_issued_at(&self) -> u64 {
        self.min_valid_issued_at
    }

    /// Check if a token with the given issued_at is valid
    pub fn is_token_valid(&self, issued_at: u64) -> bool {
        issued_at >= self.min_valid_issued_at
    }

    /// Invalidate all tokens issued before the current time.
    /// Sets min_valid_issued_at to the current timestamp and returns the new value.
    pub fn invalidate_tokens(&mut self) -> u64 {
        let now = current_timestamp();
        self.min_valid_issued_at = now;
        self.updated_at = now;
        now
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccessPolicyError {
    #[error("Access policy error: {0}")]
    Internal(String),
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_content_id() -> ContentId {
        ContentId::new("test-content".to_string()).unwrap()
    }

    fn test_owner() -> Identity {
        Identity::user("alice".to_string()).unwrap()
    }

    fn test_user(name: &str) -> Identity {
        Identity::user(name.to_string()).unwrap()
    }

    #[test]
    fn test_access_policy_creation() {
        let content_id = test_content_id();
        let owner = test_owner();
        let policy = AccessPolicy::new(content_id.clone(), owner.clone());

        assert_eq!(policy.content_id(), &content_id);
        assert_eq!(policy.owner(), &owner);
        assert!(policy.is_owner(&owner));
        assert_eq!(policy.min_valid_issued_at(), 0);
    }

    #[test]
    fn test_non_owner_is_not_owner() {
        let policy = AccessPolicy::new(test_content_id(), test_owner());
        let bob = test_user("bob");
        assert!(!policy.is_owner(&bob));
    }

    #[test]
    fn test_token_valid_with_zero_min() {
        let policy = AccessPolicy::new(test_content_id(), test_owner());
        assert!(policy.is_token_valid(0));
        assert!(policy.is_token_valid(1000));
        assert!(policy.is_token_valid(u64::MAX));
    }

    #[test]
    fn test_invalidate_tokens() {
        let mut policy = AccessPolicy::new(test_content_id(), test_owner());
        let before = current_timestamp();
        let new_min = policy.invalidate_tokens();
        assert!(new_min >= before);
        assert_eq!(policy.min_valid_issued_at(), new_min);

        // Tokens issued before invalidation are now invalid
        assert!(!policy.is_token_valid(before - 1));
        // Tokens issued at or after invalidation are valid
        assert!(policy.is_token_valid(new_min));
        assert!(policy.is_token_valid(new_min + 1));
    }

    #[test]
    fn test_backward_compatibility_deserialization() {
        // Simulate old format with grants
        let json = serde_json::json!({
            "content_id": "test-content",
            "owner": {"id": "alice", "identity_type": "User"},
            "grants": {
                "alice": {
                    "identity": {"id": "alice", "identity_type": "User"},
                    "capabilities": ["ReadContent"]
                }
            },
            "created_at": 1000,
            "updated_at": 1000
        });

        // Should deserialize without error, ignoring grants content
        let policy: AccessPolicy = serde_json::from_value(json).unwrap();
        assert_eq!(policy.content_id().as_str(), "test-content");
        assert_eq!(policy.min_valid_issued_at(), 0); // default
    }

    #[test]
    fn test_new_format_deserialization() {
        let json = serde_json::json!({
            "content_id": "test-content",
            "owner": {"id": "alice", "identity_type": "User"},
            "grants": {},
            "created_at": 1000,
            "updated_at": 1000,
            "min_valid_issued_at": 500
        });

        let policy: AccessPolicy = serde_json::from_value(json).unwrap();
        assert_eq!(policy.min_valid_issued_at(), 500);
        assert!(!policy.is_token_valid(499));
        assert!(policy.is_token_valid(500));
    }
}
