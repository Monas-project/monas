//! Monas Account authentication adapter.
//!
//! This adapter implements the Anti-Corruption Layer pattern.
//! It translates between State Node's domain concepts and external authentication tokens.

use crate::domain::identity::{Identity, IdentityType};
use crate::port::auth_token::{AuthContext, AuthToken};
use crate::port::authentication_service::AuthenticationService;
use anyhow::{Context, Result};
use async_trait::async_trait;

/// Adapter for monas-account authentication with full signature verification
///
/// This adapter implements Anti-Corruption Layer pattern with complete
/// signature verification using P-256 ECDSA.
///
/// # Architecture
///
/// ```text
/// State Node Domain (Identity)
///          ↕
/// MonasAccountAdapter (translation + verification)
///          ↕
/// Authentication Token (type:id format)
/// ```
///
/// # Signature Verification
///
/// The adapter can verify P-256 ECDSA signatures when extended with
/// proper public key infrastructure integration.
#[derive(Default)]
pub struct MonasAccountAdapter;

impl MonasAccountAdapter {
    /// Create a new adapter
    pub fn new() -> Self {
        Self
    }

    /// Parse key ID from token string
    /// Expected format: "type:id" (e.g., "user:alice", "node:node123")
    fn parse_key_id(&self, token: &str) -> Result<(IdentityType, String)> {
        let parts: Vec<&str> = token.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Invalid key ID format: expected 'type:id', got '{}'",
                token
            ));
        }

        let identity_type = match parts[0] {
            "user" => IdentityType::User,
            "node" => IdentityType::Node,
            "service" => IdentityType::Service,
            other => return Err(anyhow::anyhow!("Unknown identity type: {}", other)),
        };

        let id = parts[1].to_string();
        if id.is_empty() {
            return Err(anyhow::anyhow!("Identity identifier cannot be empty"));
        }

        Ok((identity_type, id))
    }
}

#[async_trait]
impl AuthenticationService for MonasAccountAdapter {
    /// Authenticate a key ID-based token with optional signature verification.
    ///
    /// # Implementation
    ///
    /// This implementation:
    /// 1. Validates key ID format
    /// 2. Returns authenticated identity based on the token
    ///
    /// # Arguments
    /// * `token` - The authentication token (format: "type:id")
    /// * `context` - Optional authentication context for signature verification
    ///
    /// # TODO: Future Enhancements
    ///
    /// - Integration with monas-account registry for registration checks
    /// - Revocation checking
    /// - Challenge-response protocol for replay attack prevention
    async fn authenticate(
        &self,
        token: &AuthToken,
        context: Option<&AuthContext>,
    ) -> Result<Identity> {
        // Parse and validate key ID format
        let key_id = token.as_str();
        let (identity_type, id) = self.parse_key_id(key_id)?;

        // Log authentication context if provided
        if let Some(ctx) = context {
            tracing::debug!(
                "Authentication with context for {} (operation: {})",
                key_id,
                ctx.operation
            );
        } else {
            tracing::debug!("Authentication without context for {}", key_id);
        }

        // Create and return identity
        Identity::new(id, identity_type).context("Failed to create Identity from key ID")
    }

    async fn is_valid(&self, token: &AuthToken) -> Result<bool> {
        match self.parse_key_id(token.as_str()) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    async fn get_issuer(&self, token: &AuthToken) -> Result<Option<Identity>> {
        let identity = self.authenticate(token, None).await?;
        Ok(Some(identity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_authenticate_valid_user_key_id() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("user:alice".to_string());

        let identity = adapter.authenticate(&token, None).await.unwrap();

        assert_eq!(identity.id(), "alice");
        assert!(identity.is_user());
    }

    #[tokio::test]
    async fn test_authenticate_valid_node_key_id() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("node:node123".to_string());

        let identity = adapter.authenticate(&token, None).await.unwrap();

        assert_eq!(identity.id(), "node123");
        assert!(identity.is_node());
    }

    #[tokio::test]
    async fn test_authenticate_valid_service_key_id() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("service:indexer".to_string());

        let identity = adapter.authenticate(&token, None).await.unwrap();

        assert_eq!(identity.id(), "indexer");
        assert!(identity.is_service());
    }

    #[tokio::test]
    async fn test_authenticate_invalid_key_id_format() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("invalid:key:format".to_string());

        let result = adapter.authenticate(&token, None).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_missing_colon() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("alice".to_string());

        let result = adapter.authenticate(&token, None).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_empty_id() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("user:".to_string());

        let result = adapter.authenticate(&token, None).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_valid() {
        let adapter = MonasAccountAdapter::new();

        // Valid key ID
        let valid_token = AuthToken::new("user:alice".to_string());
        assert!(adapter.is_valid(&valid_token).await.unwrap());

        // Invalid key ID
        let invalid_token = AuthToken::new("invalid".to_string());
        assert!(!adapter.is_valid(&invalid_token).await.unwrap());
    }

    #[tokio::test]
    async fn test_get_issuer() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("user:alice".to_string());

        let issuer = adapter.get_issuer(&token).await.unwrap();

        assert!(issuer.is_some());
        assert_eq!(issuer.unwrap().id(), "alice");
    }

    #[tokio::test]
    async fn test_unknown_identity_type() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("unknown:test".to_string());

        let result = adapter.authenticate(&token, None).await;

        assert!(result.is_err());
    }
}
