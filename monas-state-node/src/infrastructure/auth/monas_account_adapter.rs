//! Monas Account authentication adapter.
//!
//! This adapter implements the Anti-Corruption Layer pattern.
//! It translates between State Node's domain concepts and external authentication tokens.

use crate::domain::identity::{Identity, IdentityType};
use crate::infrastructure::auth::auth_token::AuthToken as InfraAuthToken;
use crate::infrastructure::auth::signature_verifier::SignatureVerifier;
use crate::port::auth_token::{AuthContext, AuthToken};
use crate::port::authentication_service::AuthenticationService;
use anyhow::{Context, Result};
use async_trait::async_trait;

/// Signature verification context for authentication.
///
/// This structure contains all the information needed to verify
/// a request signature, including the message, signature, and
/// metadata for replay attack prevention.
#[derive(Debug, Clone)]
pub struct SignatureContext {
    /// The message that was signed
    pub message: String,
    /// The signature bytes
    pub signature: Vec<u8>,
    /// Unix timestamp (for replay attack prevention)
    pub timestamp: Option<u64>,
}

impl SignatureContext {
    /// Create a new signature context
    pub fn new(message: String, signature: Vec<u8>) -> Self {
        Self {
            message,
            signature,
            timestamp: None,
        }
    }

    /// Set the timestamp
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }
}

/// Adapter for monas-account authentication with full signature verification
///
/// This adapter implements Anti-Corruption Layer pattern with complete
/// signature verification using P-256 ECDSA.
///
/// All key IDs must be self-contained: "type:{public_key_hex}"
/// where public_key_hex is 130 hex chars (65 bytes uncompressed P256, starting with "04").
pub struct MonasAccountAdapter;

impl MonasAccountAdapter {
    /// Create a new adapter
    pub fn new() -> Self {
        Self
    }

    /// Parse key ID from token string
    ///
    /// Self-contained format: "type:{public_key_hex}" (e.g., "user:04abcd...")
    /// The public key hex is 130 characters (65 bytes uncompressed P256).
    fn parse_key_id(&self, token: &str) -> Result<(IdentityType, String)> {
        let parts: Vec<&str> = token.splitn(2, ':').collect();
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

    /// Extract public key bytes from a self-contained key ID.
    ///
    /// Key ID format: "type:{public_key_hex}" where public_key_hex is 130 hex chars
    /// (65 bytes uncompressed P256, starting with "04").
    fn extract_public_key_from_key_id(key_id: &str) -> Result<Vec<u8>> {
        let id_part = key_id
            .splitn(2, ':')
            .nth(1)
            .ok_or_else(|| anyhow::anyhow!("Invalid key ID format: missing ':'"))?;

        // Uncompressed P256 public key = 65 bytes = 130 hex chars, starts with "04"
        if id_part.len() == 130 && id_part.starts_with("04") {
            hex::decode(id_part).context("Invalid hex in key ID")
        } else {
            Err(anyhow::anyhow!(
                "Key ID is not self-contained: expected 130-char hex starting with '04', got {} chars",
                id_part.len()
            ))
        }
    }

    /// Verify signature using public key extracted from self-contained key ID.
    async fn verify_signature(&self, key_id: &str, context: &SignatureContext) -> Result<()> {
        let public_key = Self::extract_public_key_from_key_id(key_id)?;

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
    /// Authenticate a self-contained key ID token.
    ///
    /// The public key is extracted directly from the key ID.
    /// Format: "type:{public_key_hex}" (e.g., "user:04abcd...")
    async fn authenticate(
        &self,
        token: &AuthToken,
        context: Option<&AuthContext>,
    ) -> Result<Identity> {
        let key_id = token.as_str();
        let (identity_type, id) = self.parse_key_id(key_id)?;

        if let Some(ctx) = context {
            tracing::debug!(
                "Authentication for {} (operation: {}, content_id: {})",
                key_id,
                ctx.operation,
                ctx.content_id
            );
        }

        // Validate the embedded public key format
        Self::extract_public_key_from_key_id(key_id)?;

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

        // Extract issuer's public key from self-contained key ID
        let issuer_key_id = &parsed.payload.iss;
        let public_key = Self::extract_public_key_from_key_id(issuer_key_id)?;

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
        let context = SignatureContext::new(message.to_string(), signature.to_vec());
        let context = if let Some(ts) = timestamp {
            context.with_timestamp(ts)
        } else {
            context
        };
        self.verify_signature(key_id, &context).await
    }

    async fn is_valid(&self, token: &AuthToken) -> Result<bool> {
        let key_id = token.as_str();
        match Self::extract_public_key_from_key_id(key_id) {
            Ok(_) => Ok(self.parse_key_id(key_id).is_ok()),
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
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    /// Create a test adapter with a self-contained key ID
    fn create_test_adapter() -> (MonasAccountAdapter, SigningKey, String) {
        let signing_key = SigningKey::random(&mut OsRng);
        let public_key = signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let key_id = format!("user:{}", hex::encode(&public_key));
        let adapter = MonasAccountAdapter::new();
        (adapter, signing_key, key_id)
    }

    #[tokio::test]
    async fn test_authenticate_self_contained_key_id() {
        let (adapter, _, key_id) = create_test_adapter();
        let token = AuthToken::new(key_id.clone());

        let identity = adapter.authenticate(&token, None).await.unwrap();

        assert!(identity.id().starts_with("04"));
        assert_eq!(identity.id().len(), 130);
        assert!(identity.is_user());
    }

    #[tokio::test]
    async fn test_authenticate_legacy_rejected() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("user:alice".to_string());

        let result = adapter.authenticate(&token, None).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not self-contained"));
    }

    #[tokio::test]
    async fn test_verify_signature_with_valid_signature() {
        let (adapter, signing_key, key_id) = create_test_adapter();

        let message = "test message";
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = signing_key.sign(message.as_bytes());
        let signature = signature.to_vec();

        let context = SignatureContext::new(message.to_string(), signature).with_timestamp(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

        adapter
            .verify_signature_with_context(&key_id, &context)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_verify_signature_with_invalid_signature() {
        let (adapter, _, key_id) = create_test_adapter();

        let message = "test message";
        let invalid_signature = vec![0u8; 64];

        let context = SignatureContext::new(message.to_string(), invalid_signature).with_timestamp(
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
        let (adapter, signing_key, key_id) = create_test_adapter();

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

        let context =
            SignatureContext::new(message.to_string(), signature).with_timestamp(old_timestamp);

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

        // "invalid" is not a valid identity type
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
    async fn test_is_valid_self_contained() {
        let (adapter, _, key_id) = create_test_adapter();

        let valid_token = AuthToken::new(key_id);
        assert!(adapter.is_valid(&valid_token).await.unwrap());

        let invalid_token = AuthToken::new("invalid".to_string());
        assert!(!adapter.is_valid(&invalid_token).await.unwrap());
    }

    #[tokio::test]
    async fn test_get_issuer_self_contained() {
        let (adapter, _, key_id) = create_test_adapter();
        let token = AuthToken::new(key_id);

        let issuer = adapter.get_issuer(&token).await.unwrap();

        assert!(issuer.is_some());
        assert!(issuer.unwrap().id().starts_with("04"));
    }

    #[tokio::test]
    async fn test_unknown_identity_type() {
        let adapter = MonasAccountAdapter::new();
        let token = AuthToken::new("unknown:test".to_string());

        let result = adapter.authenticate(&token, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_request_signature_valid() {
        let (adapter, signing_key, key_id) = create_test_adapter();
        let token = AuthToken::new(key_id);

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
        let (adapter, _, key_id) = create_test_adapter();
        let token = AuthToken::new(key_id);

        let message = "update:content-1:1234567890:abc123";
        let invalid_signature = vec![0u8; 64];

        let result = adapter
            .verify_request_signature(&token, &invalid_signature, message, Some(0))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_request_signature_expired_timestamp() {
        let (adapter, signing_key, key_id) = create_test_adapter();
        let token = AuthToken::new(key_id);

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
