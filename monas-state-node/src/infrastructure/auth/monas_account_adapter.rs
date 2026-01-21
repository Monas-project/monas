//! Monas Account authentication adapter.
//!
//! This adapter implements the Anti-Corruption Layer pattern.
//! It translates between State Node's domain concepts and monas-account's DID concepts.

use crate::domain::identity::{Identity, IdentityType};
use crate::port::auth_token::AuthToken;
use crate::port::authentication_service::AuthenticationService;
use anyhow::{Context, Result};
use async_trait::async_trait;

/// Adapter for monas-account authentication
///
/// This adapter implements Anti-Corruption Layer pattern.
/// It translates between State Node's domain concepts and monas-account's DID concepts.
///
/// # Architecture
///
/// ```text
/// State Node Domain (Identity)
///          ↕
/// MonasAccountAdapter (translation)
///          ↕
/// monas-account (DID)
/// ```
pub struct MonasAccountAdapter {
    /// DID prefix (e.g., "did:monas:")
    did_prefix: String,
}

impl MonasAccountAdapter {
    /// Create a new adapter with default DID prefix
    pub fn new() -> Self {
        Self {
            did_prefix: "did:monas:".to_string(),
        }
    }

    /// Create a new adapter with custom DID prefix
    pub fn with_prefix(did_prefix: String) -> Self {
        Self { did_prefix }
    }

    /// Parse DID from token string
    fn parse_did(&self, token: &str) -> Result<String> {
        if token.starts_with(&self.did_prefix) {
            Ok(token.to_string())
        } else {
            Err(anyhow::anyhow!(
                "Invalid DID format: expected prefix '{}'",
                self.did_prefix
            ))
        }
    }

    /// Validate DID format
    fn validate_did(&self, did: &str) -> Result<()> {
        if !did.starts_with(&self.did_prefix) {
            return Err(anyhow::anyhow!("Invalid DID format: missing prefix"));
        }

        // Check minimum length: "did:monas:type:id"
        let parts: Vec<&str> = did.split(':').collect();
        if parts.len() < 4 {
            return Err(anyhow::anyhow!("Invalid DID structure: too few parts"));
        }

        // Additional validation logic could go here:
        // - Check DID method
        // - Validate identifier format
        // - Check against revocation list

        Ok(())
    }

    /// Convert DID to Identity (domain concept)
    fn did_to_identity(&self, did: &str) -> Result<Identity> {
        // Parse DID and determine identity type
        // Example: "did:monas:user:alice" -> User identity
        //          "did:monas:node:node123" -> Node identity

        let parts: Vec<&str> = did.split(':').collect();

        if parts.len() < 4 {
            return Err(anyhow::anyhow!("Invalid DID structure"));
        }

        let identity_type = match parts[2] {
            "user" => IdentityType::User,
            "node" => IdentityType::Node,
            "service" => IdentityType::Service,
            _ => return Err(anyhow::anyhow!("Unknown identity type: {}", parts[2])),
        };

        Identity::new(did.to_string(), identity_type).context("Failed to create Identity from DID")
    }
}

impl Default for MonasAccountAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthenticationService for MonasAccountAdapter {
    async fn authenticate(&self, token: &AuthToken) -> Result<Identity> {
        // 1. Parse token as DID
        let did = self
            .parse_did(token.as_str())
            .context("Failed to parse DID from token")?;

        // 2. Validate DID format
        self.validate_did(&did).context("DID validation failed")?;

        // 3. Here you would integrate with monas-account for actual verification:
        // - Verify signature if the token includes a signature
        // - Check if the DID is registered
        // - Verify that the DID hasn't been revoked
        //
        // For now, simplified implementation for demonstration:
        // let verified = monas_account::verify_did(&did).await?;

        // 4. Convert DID to domain Identity
        let identity = self.did_to_identity(&did)?;

        Ok(identity)
    }

    async fn is_valid(&self, token: &AuthToken) -> Result<bool> {
        // Validate token format
        match self.parse_did(token.as_str()) {
            Ok(did) => Ok(self.validate_did(&did).is_ok()),
            Err(_) => Ok(false),
        }
    }

    async fn get_issuer(&self, token: &AuthToken) -> Result<Option<Identity>> {
        // For DID-based authentication, the issuer is the DID itself
        let identity = self.authenticate(token).await?;
        Ok(Some(identity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_authenticate_valid_user_did() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("did:monas:user:alice".to_string());

        let identity = adapter.authenticate(&token).await.unwrap();

        assert_eq!(identity.id(), "did:monas:user:alice");
        assert!(identity.is_user());
    }

    #[tokio::test]
    async fn test_authenticate_valid_node_did() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("did:monas:node:node123".to_string());

        let identity = adapter.authenticate(&token).await.unwrap();

        assert_eq!(identity.id(), "did:monas:node:node123");
        assert!(identity.is_node());
    }

    #[tokio::test]
    async fn test_authenticate_valid_service_did() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("did:monas:service:indexer".to_string());

        let identity = adapter.authenticate(&token).await.unwrap();

        assert_eq!(identity.id(), "did:monas:service:indexer");
        assert!(identity.is_service());
    }

    #[tokio::test]
    async fn test_authenticate_invalid_did_format() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("invalid:did:format".to_string());

        let result = adapter.authenticate(&token).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_missing_prefix() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("user:alice".to_string());

        let result = adapter.authenticate(&token).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_invalid_structure() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("did:monas:alice".to_string()); // Missing type

        let result = adapter.authenticate(&token).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_valid() {
        let adapter = MonasAccountAdapter::new();

        // Valid DID
        let valid_token = AuthToken::new("did:monas:user:alice".to_string());
        assert!(adapter.is_valid(&valid_token).await.unwrap());

        // Invalid DID
        let invalid_token = AuthToken::new("invalid".to_string());
        assert!(!adapter.is_valid(&invalid_token).await.unwrap());
    }

    #[tokio::test]
    async fn test_get_issuer() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("did:monas:user:alice".to_string());

        let issuer = adapter.get_issuer(&token).await.unwrap();

        assert!(issuer.is_some());
        assert_eq!(issuer.unwrap().id(), "did:monas:user:alice");
    }

    #[tokio::test]
    async fn test_custom_prefix() {
        let adapter = MonasAccountAdapter::with_prefix("did:custom:".to_string());
        let token = AuthToken::new("did:custom:user:bob".to_string());

        let identity = adapter.authenticate(&token).await.unwrap();

        assert_eq!(identity.id(), "did:custom:user:bob");
        assert!(identity.is_user());
    }

    #[tokio::test]
    async fn test_unknown_identity_type() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("did:monas:unknown:test".to_string());

        let result = adapter.authenticate(&token).await;

        assert!(result.is_err());
    }
}
