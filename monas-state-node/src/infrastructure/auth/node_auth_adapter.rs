//! Node authentication adapter with P-256 key verification.
//!
//! This adapter provides cryptographic authentication for nodes using
//! P-256 ECDSA signatures and verifies NodeId against public key hashes.

use crate::domain::identity::{Identity, IdentityType};
use crate::domain::value_objects::NodeId;
use crate::port::auth_token::{AuthContext, AuthToken};
use crate::port::authentication_service::AuthenticationService;
use crate::port::public_key_registry::PublicKeyRegistry;
use anyhow::{Context, Result};
use async_trait::async_trait;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use std::sync::Arc;

/// Node authentication adapter with P-256 signature verification.
///
/// This adapter:
/// 1. Verifies NodeId matches the public key hash
/// 2. Validates P-256 ECDSA signatures
/// 3. Integrates with PublicKeyRegistry for key lookup
///
/// # Token Format
///
/// Expected token format: `node:<node_id>:<signature_hex>`
/// - `node_id`: Base58-encoded multihash of public key
/// - `signature_hex`: Hex-encoded P-256 ECDSA signature (optional)
///
/// # Example
///
/// ```text
/// node:QmTHLptDhvFhfFTjft911WC9wQuL1bfeyBNrYqstAxEqW1
/// node:QmTHLptDhvFhfFTjft911WC9wQuL1bfeyBNrYqstAxEqW1:3045022100...
/// ```
pub struct NodeAuthAdapter {
    public_key_registry: Arc<dyn PublicKeyRegistry>,
}

impl NodeAuthAdapter {
    /// Create a new node authentication adapter.
    pub fn new(public_key_registry: Arc<dyn PublicKeyRegistry>) -> Self {
        Self {
            public_key_registry,
        }
    }

    /// Parse node authentication token.
    ///
    /// Returns (node_id, optional_signature)
    fn parse_node_token(&self, token: &str) -> Result<(String, Option<Vec<u8>>)> {
        let parts: Vec<&str> = token.split(':').collect();

        if parts.len() < 2 || parts[0] != "node" {
            return Err(anyhow::anyhow!(
                "Invalid node token format: expected 'node:id[:signature]', got '{}'",
                token
            ));
        }

        let node_id = parts[1].to_string();
        if node_id.is_empty() {
            return Err(anyhow::anyhow!("Node ID cannot be empty"));
        }

        let signature = if parts.len() >= 3 && !parts[2].is_empty() {
            Some(hex::decode(parts[2]).context("Failed to decode signature from hex")?)
        } else {
            None
        };

        Ok((node_id, signature))
    }

    /// Verify NodeId matches the public key hash.
    async fn verify_node_id(&self, node_id_str: &str) -> Result<Vec<u8>> {
        // Parse NodeId
        let node_id =
            NodeId::from_string(node_id_str.to_string()).context("Failed to parse NodeId")?;

        // Get public key from registry
        let public_key = self
            .public_key_registry
            .get_public_key(&node_id)
            .await
            .context("Failed to get public key from registry")?
            .ok_or_else(|| anyhow::anyhow!("Public key not found for node: {}", node_id_str))?;

        // Verify NodeId matches public key hash
        let expected_node_id = NodeId::from_public_key(&public_key)
            .context("Failed to derive NodeId from public key")?;

        if expected_node_id.as_str() != node_id_str {
            return Err(anyhow::anyhow!(
                "NodeId mismatch: expected {}, got {}",
                expected_node_id.as_str(),
                node_id_str
            ));
        }

        Ok(public_key)
    }

    /// Verify P-256 ECDSA signature.
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        // Parse P-256 public key
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .context("Failed to parse P-256 public key")?;

        // Parse signature
        let sig = Signature::from_der(signature).context("Failed to parse P-256 signature")?;

        // Verify signature
        verifying_key
            .verify(message, &sig)
            .context("Signature verification failed")?;

        Ok(())
    }
}

#[async_trait]
impl AuthenticationService for NodeAuthAdapter {
    /// Authenticate a node with optional signature verification.
    ///
    /// # Process
    ///
    /// 1. Parse node token to extract NodeId and optional signature
    /// 2. Verify NodeId matches public key hash in registry
    /// 3. If signature provided and context available, verify signature
    /// 4. Return authenticated node identity
    async fn authenticate(
        &self,
        token: &AuthToken,
        context: Option<&AuthContext>,
    ) -> Result<Identity> {
        // Parse token
        let (node_id, signature) = self.parse_node_token(token.as_str())?;

        // Verify NodeId and get public key
        let public_key = self.verify_node_id(&node_id).await?;

        // If signature and context provided, verify signature
        if let (Some(sig), Some(ctx)) = (signature, context) {
            // Create message to verify (content_id:operation)
            let message = format!("{}:{}", ctx.content_id, ctx.operation);

            self.verify_signature(&public_key, message.as_bytes(), &sig)?;

            tracing::debug!(
                "Node {} authenticated with signature verification (operation: {}, content: {})",
                node_id,
                ctx.operation,
                ctx.content_id
            );
        } else {
            tracing::debug!(
                "Node {} authenticated without signature verification",
                node_id
            );
        }

        // Create and return node identity
        Identity::new(node_id, IdentityType::Node).context("Failed to create node Identity")
    }

    async fn verify_request_signature(
        &self,
        _token: &AuthToken,
        _signature: &[u8],
        _message: &str,
        _timestamp: Option<u64>,
    ) -> Result<()> {
        Err(anyhow::anyhow!(
            "NodeAuthAdapter does not support request signature verification; use authenticate() with AuthContext instead"
        ))
    }

    async fn verify_jwt_signature(&self, _token: &AuthToken) -> Result<()> {
        Err(anyhow::anyhow!(
            "NodeAuthAdapter does not support JWT signature verification"
        ))
    }

    async fn is_valid(&self, token: &AuthToken) -> Result<bool> {
        // Check if token can be parsed and NodeId exists in registry
        match self.parse_node_token(token.as_str()) {
            Ok((node_id_str, _)) => {
                // Parse NodeId
                match NodeId::from_string(node_id_str.clone()) {
                    Ok(node_id) => {
                        let has_key = self
                            .public_key_registry
                            .get_public_key(&node_id)
                            .await?
                            .is_some();
                        Ok(has_key)
                    }
                    Err(_) => Ok(false),
                }
            }
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
    use crate::port::public_key_registry::InMemoryPublicKeyRegistry;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    fn generate_test_key_pair() -> (Vec<u8>, SigningKey) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        (public_key, signing_key)
    }

    #[tokio::test]
    async fn test_authenticate_valid_node() {
        let registry = Arc::new(InMemoryPublicKeyRegistry::new());
        let adapter = NodeAuthAdapter::new(registry.clone());

        // Generate test key and NodeId
        let (public_key, _) = generate_test_key_pair();
        let node_id = NodeId::from_public_key(&public_key).unwrap();

        // Register public key
        registry
            .register_public_key(public_key.clone())
            .await
            .unwrap();

        // Create token
        let token = AuthToken::new(format!("node:{}", node_id.as_str()));

        // Authenticate
        let identity = adapter.authenticate(&token, None).await.unwrap();
        assert_eq!(identity.id(), node_id.as_str());
        assert!(identity.is_node());
    }

    #[tokio::test]
    async fn test_authenticate_with_signature() {
        use p256::ecdsa::signature::Signer;

        let registry = Arc::new(InMemoryPublicKeyRegistry::new());
        let adapter = NodeAuthAdapter::new(registry.clone());

        // Generate test key and NodeId
        let (public_key, signing_key) = generate_test_key_pair();
        let node_id = NodeId::from_public_key(&public_key).unwrap();

        // Register public key
        registry
            .register_public_key(public_key.clone())
            .await
            .unwrap();

        // Create context
        let context = AuthContext {
            content_id: "test-content-123".to_string(),
            operation: "read".to_string(),
        };

        // Create signature with matching message format
        let message = format!("{}:{}", context.content_id, context.operation);
        let signature: Signature = signing_key.sign(message.as_bytes());
        let sig_hex = hex::encode(signature.to_der());

        // Create token with signature
        let token = AuthToken::new(format!("node:{}:{}", node_id.as_str(), sig_hex));

        // Authenticate with signature verification
        let identity = adapter.authenticate(&token, Some(&context)).await.unwrap();
        assert_eq!(identity.id(), node_id.as_str());
    }

    #[tokio::test]
    async fn test_authenticate_node_not_registered() {
        let registry = Arc::new(InMemoryPublicKeyRegistry::new());
        let adapter = NodeAuthAdapter::new(registry);

        // Create token for unregistered node
        let token = AuthToken::new("node:QmUnregisteredNode123".to_string());

        // Should fail authentication
        let result = adapter.authenticate(&token, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_authenticate_invalid_signature() {
        use p256::ecdsa::signature::Signer;

        let registry = Arc::new(InMemoryPublicKeyRegistry::new());
        let adapter = NodeAuthAdapter::new(registry.clone());

        // Generate test key and NodeId
        let (public_key, signing_key) = generate_test_key_pair();
        let node_id = NodeId::from_public_key(&public_key).unwrap();

        // Register public key
        registry
            .register_public_key(public_key.clone())
            .await
            .unwrap();

        // Create context with expected message
        let context = AuthContext {
            content_id: "test-content-123".to_string(),
            operation: "read".to_string(),
        };

        // Create signature for wrong message
        let wrong_message = b"wrong-message";
        let signature: Signature = signing_key.sign(wrong_message);
        let sig_hex = hex::encode(signature.to_der());

        // Create token with signature
        let token = AuthToken::new(format!("node:{}:{}", node_id.as_str(), sig_hex));

        // Should fail signature verification
        let result = adapter.authenticate(&token, Some(&context)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_is_valid() {
        let registry = Arc::new(InMemoryPublicKeyRegistry::new());
        let adapter = NodeAuthAdapter::new(registry.clone());

        // Generate and register test key
        let (public_key, _) = generate_test_key_pair();
        let node_id = NodeId::from_public_key(&public_key).unwrap();
        registry.register_public_key(public_key).await.unwrap();

        // Valid registered node
        let valid_token = AuthToken::new(format!("node:{}", node_id.as_str()));
        assert!(adapter.is_valid(&valid_token).await.unwrap());

        // Unregistered node
        let unregistered_token = AuthToken::new("node:QmUnregistered".to_string());
        assert!(!adapter.is_valid(&unregistered_token).await.unwrap());

        // Invalid format
        let invalid_token = AuthToken::new("invalid:token".to_string());
        assert!(!adapter.is_valid(&invalid_token).await.unwrap());
    }
}
