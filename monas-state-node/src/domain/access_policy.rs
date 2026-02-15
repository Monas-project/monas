//! Access policy for content authorization.
//!
//! This module defines access control policies for content.
//! It is independent of the underlying authorization mechanism (UCAN, RBAC, etc.).

use super::auth_capability::AuthCapability;
use super::identity::Identity;
use super::value_objects::ContentId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Grant entry for an identity
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Grant {
    identity: Identity,
    capabilities: Vec<AuthCapability>,
}

/// Access policy for content
///
/// This represents the access control rules for a specific piece of content.
/// It is independent of the underlying authorization mechanism.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessPolicy {
    content_id: ContentId,
    owner: Identity,
    /// Grants stored as a map from identity ID (string) to Grant for JSON serialization
    grants: HashMap<String, Grant>,
    created_at: u64,
    updated_at: u64,
}

impl AccessPolicy {
    /// Create a new access policy for content
    pub fn new(content_id: ContentId, owner: Identity) -> Self {
        let now = current_timestamp();
        let mut grants = HashMap::new();

        // Owner has all capabilities
        grants.insert(
            owner.id().to_string(),
            Grant {
                identity: owner.clone(),
                capabilities: AuthCapability::owner_capabilities(),
            },
        );

        Self {
            content_id,
            owner,
            grants,
            created_at: now,
            updated_at: now,
        }
    }

    /// Grant capabilities to an identity
    pub fn grant(
        &mut self,
        identity: Identity,
        capabilities: Vec<AuthCapability>,
    ) -> Result<(), AccessPolicyError> {
        if capabilities.is_empty() {
            return Err(AccessPolicyError::EmptyCapabilities);
        }

        self.grants.insert(
            identity.id().to_string(),
            Grant {
                identity,
                capabilities,
            },
        );
        self.updated_at = current_timestamp();
        Ok(())
    }

    /// Revoke all capabilities from an identity
    pub fn revoke(&mut self, identity: &Identity) -> Result<(), AccessPolicyError> {
        if identity == &self.owner {
            return Err(AccessPolicyError::CannotRevokeOwner);
        }

        self.grants.remove(identity.id());
        self.updated_at = current_timestamp();
        Ok(())
    }

    /// Check if an identity has a specific capability
    ///
    /// This checks both direct capabilities and implied capabilities.
    pub fn has_capability(&self, identity: &Identity, capability: &AuthCapability) -> bool {
        self.grants
            .get(identity.id())
            .map(|grant| {
                // Check direct capability or implied capabilities
                grant
                    .capabilities
                    .iter()
                    .any(|c| c == capability || c.implies(capability))
            })
            .unwrap_or(false)
    }

    /// Check if an identity is the owner
    pub fn is_owner(&self, identity: &Identity) -> bool {
        &self.owner == identity
    }

    /// Get all capabilities for an identity
    pub fn capabilities_for(&self, identity: &Identity) -> Vec<AuthCapability> {
        self.grants
            .get(identity.id())
            .map(|grant| grant.capabilities.clone())
            .unwrap_or_default()
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

    /// Transfer ownership
    pub fn transfer_ownership(&mut self, new_owner: Identity) -> Result<(), AccessPolicyError> {
        // Remove old owner from grants (they'll be re-added as new owner)
        self.grants.remove(self.owner.id());

        // Set new owner
        self.owner = new_owner.clone();

        // Grant all capabilities to new owner
        self.grants.insert(
            new_owner.id().to_string(),
            Grant {
                identity: new_owner,
                capabilities: AuthCapability::owner_capabilities(),
            },
        );

        self.updated_at = current_timestamp();
        Ok(())
    }

    /// Get all identities with grants
    pub fn granted_identities(&self) -> Vec<&Identity> {
        self.grants.values().map(|grant| &grant.identity).collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AccessPolicyError {
    #[error("Cannot grant empty capabilities")]
    EmptyCapabilities,

    #[error("Cannot revoke capabilities from the owner")]
    CannotRevokeOwner,
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
    }

    #[test]
    fn test_owner_has_all_capabilities() {
        let policy = AccessPolicy::new(test_content_id(), test_owner());
        let owner = test_owner();

        assert!(policy.has_capability(&owner, &AuthCapability::ReadContent));
        assert!(policy.has_capability(&owner, &AuthCapability::WriteContent));
        assert!(policy.has_capability(&owner, &AuthCapability::DeleteContent));
        assert!(policy.has_capability(&owner, &AuthCapability::ManageMembers));
        assert!(policy.has_capability(&owner, &AuthCapability::ShareContent));
        assert!(policy.has_capability(&owner, &AuthCapability::RevokeAccess));
        assert!(policy.has_capability(&owner, &AuthCapability::ReadMetadata));
    }

    #[test]
    fn test_grant_capabilities() {
        let mut policy = AccessPolicy::new(test_content_id(), test_owner());
        let bob = test_user("bob");

        policy
            .grant(bob.clone(), vec![AuthCapability::ReadContent])
            .unwrap();

        assert!(policy.has_capability(&bob, &AuthCapability::ReadContent));
        assert!(!policy.has_capability(&bob, &AuthCapability::WriteContent));
    }

    #[test]
    fn test_grant_empty_capabilities_error() {
        let mut policy = AccessPolicy::new(test_content_id(), test_owner());
        let bob = test_user("bob");

        let result = policy.grant(bob, vec![]);
        assert!(matches!(result, Err(AccessPolicyError::EmptyCapabilities)));
    }

    #[test]
    fn test_revoke_capabilities() {
        let mut policy = AccessPolicy::new(test_content_id(), test_owner());
        let bob = test_user("bob");

        policy
            .grant(bob.clone(), vec![AuthCapability::ReadContent])
            .unwrap();
        assert!(policy.has_capability(&bob, &AuthCapability::ReadContent));

        policy.revoke(&bob).unwrap();
        assert!(!policy.has_capability(&bob, &AuthCapability::ReadContent));
    }

    #[test]
    fn test_cannot_revoke_owner() {
        let mut policy = AccessPolicy::new(test_content_id(), test_owner());
        let owner = test_owner();

        let result = policy.revoke(&owner);
        assert!(matches!(result, Err(AccessPolicyError::CannotRevokeOwner)));
    }

    #[test]
    fn test_capability_implication() {
        let mut policy = AccessPolicy::new(test_content_id(), test_owner());
        let bob = test_user("bob");

        // Grant WriteContent, which implies ReadContent
        policy
            .grant(bob.clone(), vec![AuthCapability::WriteContent])
            .unwrap();

        assert!(policy.has_capability(&bob, &AuthCapability::WriteContent));
        assert!(policy.has_capability(&bob, &AuthCapability::ReadContent)); // implied
        assert!(!policy.has_capability(&bob, &AuthCapability::DeleteContent));
    }

    #[test]
    fn test_transfer_ownership() {
        let mut policy = AccessPolicy::new(test_content_id(), test_owner());
        let alice = test_owner();
        let bob = test_user("bob");

        policy.transfer_ownership(bob.clone()).unwrap();

        assert_eq!(policy.owner(), &bob);
        assert!(policy.is_owner(&bob));
        assert!(!policy.is_owner(&alice));

        // New owner has all capabilities
        assert!(policy.has_capability(&bob, &AuthCapability::DeleteContent));

        // Old owner no longer has capabilities
        assert!(!policy.has_capability(&alice, &AuthCapability::ReadContent));
    }

    #[test]
    fn test_capabilities_for() {
        let mut policy = AccessPolicy::new(test_content_id(), test_owner());
        let bob = test_user("bob");

        policy
            .grant(
                bob.clone(),
                vec![AuthCapability::ReadContent, AuthCapability::WriteContent],
            )
            .unwrap();

        let caps = policy.capabilities_for(&bob);
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&AuthCapability::ReadContent));
        assert!(caps.contains(&AuthCapability::WriteContent));
    }

    #[test]
    fn test_granted_identities() {
        let mut policy = AccessPolicy::new(test_content_id(), test_owner());
        let bob = test_user("bob");
        let charlie = test_user("charlie");

        policy
            .grant(bob.clone(), vec![AuthCapability::ReadContent])
            .unwrap();
        policy
            .grant(charlie.clone(), vec![AuthCapability::WriteContent])
            .unwrap();

        let identities = policy.granted_identities();
        assert_eq!(identities.len(), 3); // owner + bob + charlie
        assert!(identities.contains(&&test_owner()));
        assert!(identities.contains(&&bob));
        assert!(identities.contains(&&charlie));
    }
}
