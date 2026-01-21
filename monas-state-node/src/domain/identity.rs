//! Identity types for State Node domain.
//!
//! This module defines identity concepts that are independent of external
//! authentication systems. The actual authentication mechanism (DID, OAuth, etc.)
//! is handled by the infrastructure layer through adapters.

use serde::{Deserialize, Serialize};

/// State Node domain's identity concept
///
/// This is independent from external authentication systems.
/// The actual authentication mechanism (DID, OAuth, etc.) is handled
/// by the infrastructure layer through adapters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Identity {
    id: String,
    identity_type: IdentityType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdentityType {
    /// End user
    User,
    /// State node
    Node,
    /// System service
    Service,
}

impl Identity {
    pub fn new(id: String, identity_type: IdentityType) -> Result<Self, IdentityError> {
        if id.is_empty() {
            return Err(IdentityError::EmptyIdentifier);
        }
        Ok(Self { id, identity_type })
    }

    pub fn user(id: String) -> Result<Self, IdentityError> {
        Self::new(id, IdentityType::User)
    }

    pub fn node(id: String) -> Result<Self, IdentityError> {
        Self::new(id, IdentityType::Node)
    }

    pub fn service(id: String) -> Result<Self, IdentityError> {
        Self::new(id, IdentityType::Service)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn identity_type(&self) -> &IdentityType {
        &self.identity_type
    }

    pub fn is_user(&self) -> bool {
        matches!(self.identity_type, IdentityType::User)
    }

    pub fn is_node(&self) -> bool {
        matches!(self.identity_type, IdentityType::Node)
    }

    pub fn is_service(&self) -> bool {
        matches!(self.identity_type, IdentityType::Service)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Identity identifier cannot be empty")]
    EmptyIdentifier,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_creation() {
        let identity = Identity::user("alice".to_string()).unwrap();
        assert_eq!(identity.id(), "alice");
        assert!(identity.is_user());
        assert!(!identity.is_node());
    }

    #[test]
    fn test_node_identity() {
        let identity = Identity::node("node123".to_string()).unwrap();
        assert_eq!(identity.id(), "node123");
        assert!(identity.is_node());
        assert!(!identity.is_user());
    }

    #[test]
    fn test_empty_identifier_error() {
        let result = Identity::user("".to_string());
        assert!(matches!(result, Err(IdentityError::EmptyIdentifier)));
    }

    #[test]
    fn test_identity_equality() {
        let id1 = Identity::user("alice".to_string()).unwrap();
        let id2 = Identity::user("alice".to_string()).unwrap();
        let id3 = Identity::user("bob".to_string()).unwrap();

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_service_identity() {
        let identity = Identity::service("indexer".to_string()).unwrap();
        assert_eq!(identity.id(), "indexer");
        assert!(identity.is_service());
        assert!(!identity.is_user());
        assert!(!identity.is_node());
    }
}
