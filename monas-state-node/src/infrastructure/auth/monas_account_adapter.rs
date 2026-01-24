//! Monas Account authentication adapter.
//!
//! This adapter implements the Anti-Corruption Layer pattern.
//! It translates between State Node's domain concepts and external authentication tokens.

use crate::domain::identity::{Identity, IdentityType};
use crate::port::auth_token::AuthToken;
use crate::port::authentication_service::AuthenticationService;
use anyhow::{Context, Result};
use async_trait::async_trait;

/// Adapter for monas-account authentication
///
/// This adapter implements Anti-Corruption Layer pattern.
/// It translates between State Node's domain concepts and authentication tokens.
///
/// # Architecture
///
/// ```text
/// State Node Domain (Identity)
///          ↕
/// MonasAccountAdapter (translation)
///          ↕
/// Authentication Token (type:id format)
/// ```
pub struct MonasAccountAdapter {
    // No prefix needed for simple "type:id" format
}

impl MonasAccountAdapter {
    /// Create a new adapter
    pub fn new() -> Self {
        Self {}
    }

    /// Parse key ID from token string
    /// Expected format: "type:id" (e.g., "user:alice", "node:node123")
    fn parse_key_id(&self, token: &str) -> Result<String> {
        // Validate format: "type:id"
        let parts: Vec<&str> = token.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Invalid key ID format: expected 'type:id', got '{}'",
                token
            ));
        }
        Ok(token.to_string())
    }

    /// Validate key ID format.
    ///
    /// # Implementation Status
    ///
    /// Currently performs basic format validation.
    ///
    /// # TODO: Full Validation
    ///
    /// When monas-account crate becomes available, implement:
    ///
    /// 1. **Registration Check**
    ///    - Query monas-account registry to verify key ID is registered
    ///
    /// 2. **Revocation Check**
    ///    - Check if key ID has been revoked
    ///    - Verify key ID is still active/valid
    ///
    /// 3. **Identifier Format Validation**
    ///    - Validate identifier portion follows spec
    ///    - Check for valid characters and length
    fn validate_key_id(&self, key_id: &str) -> Result<()> {
        // Check format: "type:id"
        let parts: Vec<&str> = key_id.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!(
                "Invalid key ID structure: expected 'type:id', got '{}'",
                key_id
            ));
        }

        // Validate identity type (user, node, service)
        match parts[0] {
            "user" | "node" | "service" => {}
            other => {
                return Err(anyhow::anyhow!("Unknown identity type: {}", other));
            }
        }

        // Validate identifier is not empty
        if parts[1].is_empty() {
            return Err(anyhow::anyhow!("Identity identifier cannot be empty"));
        }

        // TODO: Additional validation with monas-account crate:
        // - Check registration status
        // - Verify hasn't been revoked
        // - Validate identifier format

        Ok(())
    }

    /// Convert key ID to Identity (domain concept)
    fn key_id_to_identity(&self, key_id: &str) -> Result<Identity> {
        // Parse key ID and determine identity type
        // Example: "user:alice" -> User identity with id="alice"
        //          "node:node123" -> Node identity with id="node123"

        let parts: Vec<&str> = key_id.split(':').collect();

        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid key ID structure"));
        }

        let identity_type = match parts[0] {
            "user" => IdentityType::User,
            "node" => IdentityType::Node,
            "service" => IdentityType::Service,
            _ => return Err(anyhow::anyhow!("Unknown identity type: {}", parts[0])),
        };

        // Store only the ID part (e.g., "alice") in Identity, not the full key ID
        Identity::new(parts[1].to_string(), identity_type)
            .context("Failed to create Identity from key ID")
    }
}

impl Default for MonasAccountAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthenticationService for MonasAccountAdapter {
    /// Authenticate a key ID-based token.
    ///
    /// # Implementation Status
    ///
    /// Currently performs basic key ID format validation and conversion.
    /// **WARNING**: Does not verify signatures or registration status.
    ///
    /// # TODO: Full Authentication
    ///
    /// When monas-account crate becomes available, implement:
    ///
    /// 1. **Signature Verification**
    ///    - Extract signature from token if present
    ///    - Fetch public key from registry
    ///    - Verify signature matches message + key ID
    ///
    /// 2. **Registration Verification**
    ///    - Query monas-account registry
    ///    - Verify key ID is registered and active
    ///
    /// 3. **Revocation Check**
    ///    - Check revocation status in registry
    ///    - Verify key ID hasn't been deactivated
    ///
    /// 4. **Challenge-Response (Optional)**
    ///    - Implement challenge-response protocol
    ///    - Verify client possesses private key
    async fn authenticate(&self, token: &AuthToken) -> Result<Identity> {
        // 1. Parse token as key ID
        let key_id = self
            .parse_key_id(token.as_str())
            .context("Failed to parse key ID from token")?;

        // 2. Validate key ID format
        self.validate_key_id(&key_id)
            .context("Key ID validation failed")?;

        // 3. TODO: Integrate with monas-account for actual verification
        //
        // Example integration:
        // ```
        // use monas_account::AccountRegistry;
        // let registry = AccountRegistry::new()?;
        //
        // // Verify key ID is registered
        // let account = registry.resolve_key_id(&key_id).await?;
        //
        // // Verify signature if token includes one
        // if let Some(signature) = extract_signature(token) {
        //     let public_key = account.get_public_key()?;
        //     verify_signature(public_key, signature, &key_id)?;
        // }
        //
        // // Check revocation status
        // if registry.is_revoked(&key_id).await? {
        //     return Err(anyhow::anyhow!("Key ID has been revoked"));
        // }
        // ```
        //
        // For now, log warning and proceed

        tracing::warn!(
            "Key ID authentication for {} is not fully implemented - accepting without verification (INSECURE)",
            key_id
        );

        // 4. Convert key ID to domain Identity
        let identity = self.key_id_to_identity(&key_id)?;

        Ok(identity)
    }

    async fn is_valid(&self, token: &AuthToken) -> Result<bool> {
        // Validate token format
        match self.parse_key_id(token.as_str()) {
            Ok(key_id) => Ok(self.validate_key_id(&key_id).is_ok()),
            Err(_) => Ok(false),
        }
    }

    async fn get_issuer(&self, token: &AuthToken) -> Result<Option<Identity>> {
        // For key ID-based authentication, the issuer is the key ID itself
        let identity = self.authenticate(token).await?;
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

        let identity = adapter.authenticate(&token).await.unwrap();

        assert_eq!(identity.id(), "alice");
        assert!(identity.is_user());
    }

    #[tokio::test]
    async fn test_authenticate_valid_node_key_id() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("node:node123".to_string());

        let identity = adapter.authenticate(&token).await.unwrap();

        assert_eq!(identity.id(), "node123");
        assert!(identity.is_node());
    }

    #[tokio::test]
    async fn test_authenticate_valid_service_key_id() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("service:indexer".to_string());

        let identity = adapter.authenticate(&token).await.unwrap();

        assert_eq!(identity.id(), "indexer");
        assert!(identity.is_service());
    }

    #[tokio::test]
    async fn test_authenticate_invalid_key_id_format() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("invalid:key:format".to_string());

        let result = adapter.authenticate(&token).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_missing_colon() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("alice".to_string());

        let result = adapter.authenticate(&token).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_empty_id() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("user:".to_string());

        let result = adapter.authenticate(&token).await;

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

        let result = adapter.authenticate(&token).await;

        assert!(result.is_err());
    }
}
