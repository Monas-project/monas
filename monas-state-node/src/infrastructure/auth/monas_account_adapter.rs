//! Monas Account authentication adapter.
//!
//! This adapter implements the Anti-Corruption Layer pattern.
//! It translates between State Node's domain concepts and external authentication tokens.

use crate::domain::identity::{Identity, IdentityType};
use crate::infrastructure::auth::auth_token::AuthToken as InfraAuthToken;
use crate::infrastructure::auth::signature_verifier::SignatureVerifier;
use crate::port::auth_token::{AuthContext, AuthToken};
use crate::port::authentication_service::AuthenticationService;
use crate::port::extended_public_key_registry::{ExtendedPublicKeyRegistry, SignatureContext};
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::Arc;

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
/// The adapter verifies P-256 ECDSA signatures when AuthContext is provided.
pub struct MonasAccountAdapter {
    /// Extended public key registry for signature verification
    public_key_registry: Option<Arc<dyn ExtendedPublicKeyRegistry>>,
}

impl MonasAccountAdapter {
    /// Create a new adapter without public key registry
    pub fn new() -> Self {
        Self {
            public_key_registry: None,
        }
    }

    /// Create a new adapter with extended public key registry for signature verification
    pub fn with_registry(registry: Arc<dyn ExtendedPublicKeyRegistry>) -> Self {
        Self {
            public_key_registry: Some(registry),
        }
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

    /// Verify signature if context is provided
    async fn verify_signature(&self, key_id: &str, context: &SignatureContext) -> Result<()> {
        // Get public key from registry
        let registry = self
            .public_key_registry
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Public key registry not configured"))?;

        let public_key = registry
            .get_public_key_by_key_id(key_id)
            .await
            .context("Failed to get public key")?
            .ok_or_else(|| anyhow::anyhow!("Public key not found for key ID: {}", key_id))?;

        // Verify signature
        SignatureVerifier::verify_request_signature(
            context.message.as_bytes(),
            &context.signature,
            &public_key,
        )
        .context("Signature verification failed")?;

        // Check timestamp to prevent replay attacks
        if let Some(timestamp) = context.timestamp {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Reject if timestamp is older than 5 minutes
            const MAX_AGE_SECS: u64 = 300;
            if now > timestamp + MAX_AGE_SECS {
                return Err(anyhow::anyhow!(
                    "Authentication request expired (timestamp too old)"
                ));
            }

            // Reject if timestamp is in the future (allow 30 seconds clock skew)
            const MAX_CLOCK_SKEW_SECS: u64 = 30;
            if timestamp > now + MAX_CLOCK_SKEW_SECS {
                return Err(anyhow::anyhow!("Invalid timestamp (too far in the future)"));
            }
        }

        Ok(())
    }
}

impl MonasAccountAdapter {
    /// Verify signature with SignatureContext
    ///
    /// This method is public so it can be called directly when signature
    /// verification is needed, separate from the authenticate method.
    pub async fn verify_signature_with_context(
        &self,
        key_id: &str,
        context: &SignatureContext,
    ) -> Result<()> {
        self.verify_signature(key_id, context).await
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
    /// # Security
    ///
    /// Without a public key registry, authentication is rejected because there is
    /// no way to verify the caller's identity. A registry must be configured via
    /// `MonasAccountAdapter::with_registry()` for authentication to succeed.
    ///
    /// # Arguments
    /// * `token` - The authentication token (format: "type:id")
    /// * `context` - Optional authentication context (currently unused)
    async fn authenticate(
        &self,
        token: &AuthToken,
        context: Option<&AuthContext>,
    ) -> Result<Identity> {
        // Parse and validate key ID format
        let key_id = token.as_str();
        let (identity_type, id) = self.parse_key_id(key_id)?;

        if let Some(ctx) = context {
            tracing::debug!(
                "Authentication for {} (operation: {}, content_id: {})",
                key_id,
                ctx.operation,
                ctx.content_id
            );
        } else {
            tracing::debug!("Authentication for {}", key_id);
        }

        // Reject authentication when no public key registry is configured.
        // Without a registry, we cannot verify identity ownership.
        if self.public_key_registry.is_none() {
            return Err(anyhow::anyhow!(
                "Authentication rejected: no public key registry configured for identity verification"
            ));
        }

        // Create and return identity
        Identity::new(id, identity_type).context("Failed to create Identity from key ID")
    }

    async fn verify_jwt_signature(&self, token: &AuthToken) -> Result<()> {
        let jwt_str = token.as_str();

        // Parse JWT
        let parsed = InfraAuthToken::from_jwt(jwt_str).context("Failed to parse JWT token")?;

        // Check expiration
        if parsed.is_expired() {
            anyhow::bail!("JWT token has expired");
        }

        // Get issuer's public key from registry
        let registry = self
            .public_key_registry
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Public key registry not configured"))?;

        let issuer_key_id = &parsed.payload.iss;
        let public_key = registry
            .get_public_key_by_key_id(issuer_key_id)
            .await
            .context("Failed to get issuer public key")?
            .ok_or_else(|| {
                anyhow::anyhow!("Public key not found for JWT issuer: {}", issuer_key_id)
            })?;

        // Verify P-256 signature
        SignatureVerifier::verify_auth_token_signature(&parsed, &public_key)
            .context("JWT signature verification failed")
    }

    async fn verify_request_signature(
        &self,
        token: &AuthToken,
        signature: &[u8],
        message: &str,
        timestamp: Option<u64>,
    ) -> Result<()> {
        let key_id = token.as_str();
        let context = SignatureContext::new(
            "request".to_string(),
            message.to_string(),
            signature.to_vec(),
        );
        let context = if let Some(ts) = timestamp {
            context.with_timestamp(ts)
        } else {
            context
        };
        self.verify_signature(key_id, &context).await
    }

    async fn is_valid(&self, token: &AuthToken) -> Result<bool> {
        if self.public_key_registry.is_none() {
            return Ok(false);
        }
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
    use crate::infrastructure::persistence::sled_public_key_repository::SledPublicKeyRepository;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    async fn create_test_adapter_with_registry(
    ) -> (MonasAccountAdapter, SigningKey, String, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let registry = Arc::new(SledPublicKeyRepository::open(temp_dir.path()).unwrap());

        // Generate test key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let key_id = "user:alice".to_string();

        // Register public key using ExtendedPublicKeyRegistry trait
        use crate::port::extended_public_key_registry::ExtendedPublicKeyRegistry;
        registry
            .register_public_key_for_key_id(key_id.clone(), public_key)
            .await
            .unwrap();

        let adapter = MonasAccountAdapter::with_registry(registry);
        (adapter, signing_key, key_id, temp_dir)
    }

    #[tokio::test]
    async fn test_authenticate_rejected_without_registry() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("user:alice".to_string());

        let result = adapter.authenticate(&token, None).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no public key registry configured"));
    }

    #[tokio::test]
    async fn test_authenticate_valid_user_key_id_with_registry() {
        let (adapter, _, _, _temp_dir) = create_test_adapter_with_registry().await;
        let token = AuthToken::new("user:alice".to_string());

        let identity = adapter.authenticate(&token, None).await.unwrap();

        assert_eq!(identity.id(), "alice");
        assert!(identity.is_user());
    }

    #[tokio::test]
    async fn test_authenticate_valid_node_key_id_with_registry() {
        let (adapter, _, _, _temp_dir) = create_test_adapter_with_registry().await;
        let token = AuthToken::new("node:node123".to_string());

        // node:node123 is not registered, but format is valid and registry exists
        let identity = adapter.authenticate(&token, None).await.unwrap();

        assert_eq!(identity.id(), "node123");
        assert!(identity.is_node());
    }

    #[tokio::test]
    async fn test_authenticate_valid_service_key_id_with_registry() {
        let (adapter, _, _, _temp_dir) = create_test_adapter_with_registry().await;
        let token = AuthToken::new("service:indexer".to_string());

        let identity = adapter.authenticate(&token, None).await.unwrap();

        assert_eq!(identity.id(), "indexer");
        assert!(identity.is_service());
    }

    #[tokio::test]
    async fn test_verify_signature_with_valid_signature() {
        let (adapter, signing_key, key_id, _temp_dir) = create_test_adapter_with_registry().await;

        let message = "test message";
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = signing_key.sign(message.as_bytes());
        let signature = signature.to_vec();

        let context = SignatureContext::new("test".to_string(), message.to_string(), signature)
            .with_timestamp(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );

        // Test signature verification directly
        adapter
            .verify_signature_with_context(&key_id, &context)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_verify_signature_with_invalid_signature() {
        let (adapter, _, key_id, _temp_dir) = create_test_adapter_with_registry().await;

        let message = "test message";
        let invalid_signature = vec![0u8; 64];

        let context =
            SignatureContext::new("test".to_string(), message.to_string(), invalid_signature)
                .with_timestamp(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                );

        let result = adapter
            .verify_signature_with_context(&key_id, &context)
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Signature verification failed"));
    }

    #[tokio::test]
    async fn test_verify_signature_with_expired_timestamp() {
        let (adapter, signing_key, key_id, _temp_dir) = create_test_adapter_with_registry().await;

        let message = "test message";
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = signing_key.sign(message.as_bytes());
        let signature = signature.to_vec();

        // Use timestamp from 10 minutes ago (exceeds MAX_AGE_SECS)
        let old_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600;

        let context = SignatureContext::new("test".to_string(), message.to_string(), signature)
            .with_timestamp(old_timestamp);

        let result = adapter
            .verify_signature_with_context(&key_id, &context)
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("timestamp too old"));
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
    async fn test_is_valid_without_registry() {
        let adapter = MonasAccountAdapter::new();

        // Without registry, is_valid should always return false
        let valid_token = AuthToken::new("user:alice".to_string());
        assert!(!adapter.is_valid(&valid_token).await.unwrap());

        let invalid_token = AuthToken::new("invalid".to_string());
        assert!(!adapter.is_valid(&invalid_token).await.unwrap());
    }

    #[tokio::test]
    async fn test_is_valid_with_registry() {
        let (adapter, _signing_key, _key_id, _temp_dir) = create_test_adapter_with_registry().await;

        // With registry, valid key ID should return true
        let valid_token = AuthToken::new("user:alice".to_string());
        assert!(adapter.is_valid(&valid_token).await.unwrap());

        // Invalid key ID should still return false
        let invalid_token = AuthToken::new("invalid".to_string());
        assert!(!adapter.is_valid(&invalid_token).await.unwrap());
    }

    #[tokio::test]
    async fn test_get_issuer_rejected_without_registry() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("user:alice".to_string());

        let result = adapter.get_issuer(&token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_issuer_with_registry() {
        let (adapter, _, _, _temp_dir) = create_test_adapter_with_registry().await;
        let token = AuthToken::new("user:alice".to_string());

        let issuer = adapter.get_issuer(&token).await.unwrap();

        assert!(issuer.is_some());
        assert_eq!(issuer.unwrap().id(), "alice");
    }

    #[tokio::test]
    async fn test_unknown_identity_type() {
        let (adapter, _, _, _temp_dir) = create_test_adapter_with_registry().await;
        let token = AuthToken::new("unknown:test".to_string());

        let result = adapter.authenticate(&token, None).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_request_signature_valid() {
        let (adapter, signing_key, _, _temp_dir) = create_test_adapter_with_registry().await;
        let token = AuthToken::new("user:alice".to_string());

        let message = "update:content-1:1234567890:abc123";
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = signing_key.sign(message.as_bytes());
        let signature_bytes = signature.to_vec();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let result = adapter
            .verify_request_signature(&token, &signature_bytes, message, Some(timestamp))
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_request_signature_invalid() {
        let (adapter, _, _, _temp_dir) = create_test_adapter_with_registry().await;
        let token = AuthToken::new("user:alice".to_string());

        let message = "update:content-1:1234567890:abc123";
        let invalid_signature = vec![0u8; 64];

        let result = adapter
            .verify_request_signature(&token, &invalid_signature, message, Some(0))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_request_signature_expired_timestamp() {
        let (adapter, signing_key, _, _temp_dir) = create_test_adapter_with_registry().await;
        let token = AuthToken::new("user:alice".to_string());

        let message = "update:content-1:1234567890:abc123";
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = signing_key.sign(message.as_bytes());
        let signature_bytes = signature.to_vec();

        // 10 minutes ago
        let old_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 600;

        let result = adapter
            .verify_request_signature(&token, &signature_bytes, message, Some(old_timestamp))
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("timestamp too old"));
    }
}
