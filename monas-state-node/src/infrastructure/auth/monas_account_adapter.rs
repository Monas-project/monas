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
            .split_once(':')
            .map(|x| x.1)
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

        // Bound how long a signature stays usable.
        //
        // This is a freshness check, NOT replay protection: inside the window
        // the same signature can be presented any number of times. RFC 9449
        // (DPoP) §11.1 makes the same split — it requires servers to accept a
        // proof only "for a relatively brief period on the order of seconds or
        // minutes", and separately recommends storing the proof's identifier
        // for that window so a proof cannot be used twice, noting that a
        // single-use check "provides a very strong protection against DPoP
        // proof replay". Monas does the same: mutations are consumed by
        // `verify_and_consume_mutation_signature`, keyed on the signed message
        // and signer. Reads are idempotent and rely on freshness alone.
        //
        // https://www.rfc-editor.org/rfc/rfc9449.html#section-11.1
        if let Some(timestamp) = context.timestamp {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // 300s matches the ceiling AWS SigV4 uses for the same job ("a
            // request must reach AWS within five minutes of the time stamp"),
            // and sits inside RFC 9449's "seconds or minutes".
            //
            // The floor is set by how long a request legitimately takes to
            // arrive: gateway hop, then a state-node relay whose per-peer
            // budget is `PEER_NETWORK_TIMEOUT` (30s), possibly preceded by DHT
            // discovery, with failover retrying across candidates. Tens of
            // seconds is realistic; 300s leaves generous headroom.
            //
            // The window is therefore loose rather than tuned. It could be
            // tightened once real request latency is measured, which is worth
            // doing because it directly bounds how long a captured read
            // signature stays replayable — but it must not be cut below the
            // relay failover budget or legitimate reads start failing.
            const MAX_AGE_SECS: u64 = 300;
            if now > timestamp + MAX_AGE_SECS {
                return Err(anyhow::anyhow!(
                    "Authentication request expired (timestamp too old)"
                ));
            }

            // Future-dated timestamps are a clock-sync problem, not a latency
            // one, so they get their own much smaller allowance.
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

    /// Parse a delegated JWT and extract requester identity from `aud`.
    fn parse_jwt_identity(&self, jwt: &str) -> Result<Identity> {
        let parsed = InfraAuthToken::from_jwt(jwt).context("Failed to parse JWT token")?;
        let (identity_type, id) = self.parse_key_id(&parsed.payload.aud)?;
        Self::extract_public_key_from_key_id(&parsed.payload.aud)?;
        Identity::new(id, identity_type).context("Failed to create Identity from JWT audience")
    }

    fn redact_token_for_log(token: &str) -> String {
        if !token.contains('.') {
            return token.to_string();
        }
        let prefix: String = token.chars().take(12).collect();
        format!("jwt:{}...(len={})", prefix, token.len())
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
        let raw = token.as_str();

        if let Some(ctx) = context {
            tracing::debug!(
                "Authentication for {} (operation: {}, content_id: {})",
                Self::redact_token_for_log(raw),
                ctx.operation,
                ctx.content_id
            );
        }

        if raw.contains('.') {
            // Delegated access path: token is JWT, caller identity is the audience.
            return self.parse_jwt_identity(raw);
        }

        let (identity_type, id) = self.parse_key_id(raw)?;
        // Validate the embedded public key format
        Self::extract_public_key_from_key_id(raw)?;
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

        // Verify P-256 signature over the received wire bytes (never over a
        // re-serialized form, which would reject tokens whose issuer used a
        // different JSON field order).
        SignatureVerifier::verify_jwt_signature_wire(jwt_str, &public_key)
            .context("JWT signature verification failed")
    }

    async fn verify_request_signature(
        &self,
        token: &AuthToken,
        signature: &[u8],
        message: &str,
        timestamp: Option<u64>,
    ) -> Result<()> {
        let key_id = if token.as_str().contains('.') {
            let parsed =
                InfraAuthToken::from_jwt(token.as_str()).context("Failed to parse JWT token")?;
            parsed.payload.aud
        } else {
            token.as_str().to_string()
        };
        let context = SignatureContext::new(message.to_string(), signature.to_vec());
        let context = if let Some(ts) = timestamp {
            context.with_timestamp(ts)
        } else {
            context
        };
        self.verify_signature(&key_id, &context).await
    }

    async fn is_valid(&self, token: &AuthToken) -> Result<bool> {
        if token.as_str().contains('.') {
            return Ok(self.verify_jwt_signature(token).await.is_ok());
        }

        let key_id = token.as_str();
        match Self::extract_public_key_from_key_id(key_id) {
            Ok(_) => Ok(self.parse_key_id(key_id).is_ok()),
            Err(_) => Ok(false),
        }
    }

    async fn get_issuer(&self, token: &AuthToken) -> Result<Option<Identity>> {
        if token.as_str().contains('.') {
            let parsed = InfraAuthToken::from_jwt(token.as_str()).context("Failed to parse JWT")?;
            let (identity_type, id) = self.parse_key_id(&parsed.payload.iss)?;
            Self::extract_public_key_from_key_id(&parsed.payload.iss)?;
            let identity =
                Identity::new(id, identity_type).context("Failed to create issuer identity")?;
            return Ok(Some(identity));
        }
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

    /// issue #61: the PoP of a delegated JWT is also verified against the key of the recipient
    /// (aud), in the same `{op}:{resource}:{timestamp}` format as non-JWT. The same token can be
    /// reused for a different request (new timestamp, new signature).
    #[tokio::test]
    async fn test_verify_request_signature_jwt_unified_message() {
        use crate::infrastructure::auth::test_helpers::TestKeyPair;

        let owner = TestKeyPair::generate("user", "owner");
        let recipient = TestKeyPair::generate("user", "recipient");
        let auth_token = owner.create_auth_token(
            &recipient,
            "monas://content/content-1",
            vec![crate::infrastructure::auth::auth_token::CapabilityAction::Read],
            Some(3600),
        );
        let token = AuthToken::new(auth_token.to_jwt().unwrap());
        let adapter = MonasAccountAdapter::new();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Two requests with the same token (simulating history fetch → data fetch).
        // Each puts a new timestamp inside the signature.
        for i in 0..2u64 {
            let ts = now + i;
            let message = format!("read:content-1:{ts}");
            let sig = recipient.sign(message.as_bytes());
            let result = adapter
                .verify_request_signature(&token, &sig, &message, Some(ts))
                .await;
            assert!(result.is_ok(), "request {i} should verify: {result:?}");
        }

        // A signature made with a key other than the recipient's (aud) is rejected
        let ts = now;
        let message = format!("read:content-1:{ts}");
        let forged = owner.sign(message.as_bytes());
        assert!(adapter
            .verify_request_signature(&token, &forged, &message, Some(ts))
            .await
            .is_err());
    }

    /// Regression test for cross-resource / cross-operation replay.
    /// A body+signature obtained for an update of one content must not be reusable for another
    /// content or for create (verification fails because the signed message is bound to
    /// operation / resource).
    #[tokio::test]
    async fn test_body_signature_cannot_be_replayed_across_resource_or_operation() {
        use crate::port::auth_token::RequestMetadata;
        use p256::ecdsa::signature::Signer;
        use sha2::Digest;

        let (adapter, signing_key, key_id) = create_test_adapter();
        let token = AuthToken::new(key_id);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = b"payload-bytes";
        let body_digest = hex::encode(sha2::Sha256::digest(body));

        let captured = RequestMetadata {
            timestamp: ts,
            operation: "update".to_string(),
            resource: "content-1".to_string(),
        };
        let captured_message = captured.signing_message_with_body_digest(&body_digest);
        let signature: p256::ecdsa::Signature = signing_key.sign(captured_message.as_bytes());
        let signature_bytes = signature.to_vec();

        // The legitimate combination passes
        assert!(adapter
            .verify_request_signature(&token, &signature_bytes, &captured_message, Some(ts))
            .await
            .is_ok());

        // Reuse the same body and signature for another content → rejected
        let other_resource = RequestMetadata {
            resource: "content-2".to_string(),
            ..captured.clone()
        };
        assert!(adapter
            .verify_request_signature(
                &token,
                &signature_bytes,
                &other_resource.signing_message_with_body_digest(&body_digest),
                Some(ts),
            )
            .await
            .is_err());

        // Reuse the same body and signature for create → rejected
        let other_operation = RequestMetadata {
            operation: "create".to_string(),
            ..captured.clone()
        };
        assert!(adapter
            .verify_request_signature(
                &token,
                &signature_bytes,
                &other_operation.signing_message_with_body_digest(&body_digest),
                Some(ts),
            )
            .await
            .is_err());

        // Swapping the body is also rejected
        assert!(adapter
            .verify_request_signature(
                &token,
                &signature_bytes,
                &captured.signing_message_with_body_digest(&hex::encode(sha2::Sha256::digest(
                    b"tampered"
                ))),
                Some(ts),
            )
            .await
            .is_err());
    }

    /// The add-members `count` comes from the HTTP body and determines how many members are
    /// actually added. If it were not in the signed message, count alone could be swapped while
    /// keeping the same token, signature, and timestamp (it is clamped to the cap, but tampering
    /// 1 → cap still succeeds). Verify that the canonically encoded body is bound to the
    /// signature.
    #[tokio::test]
    async fn test_add_members_count_cannot_be_substituted() {
        use crate::port::auth_token::{add_members_signing_body, RequestMetadata};
        use p256::ecdsa::signature::Signer;
        use sha2::Digest;

        let (adapter, signing_key, key_id) = create_test_adapter();
        let token = AuthToken::new(key_id);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let metadata = RequestMetadata {
            timestamp: ts,
            operation: "manage".to_string(),
            resource: "content-1".to_string(),
        };
        let digest_for =
            |count: usize| hex::encode(sha2::Sha256::digest(add_members_signing_body(count)));

        // The caller signs for count=1
        let signed_message = metadata.signing_message_with_body_digest(&digest_for(1));
        let signature: p256::ecdsa::Signature = signing_key.sign(signed_message.as_bytes());
        let signature_bytes = signature.to_vec();

        assert!(adapter
            .verify_request_signature(&token, &signature_bytes, &signed_message, Some(ts))
            .await
            .is_ok());

        // A request with the body's count swapped fails verification
        for tampered in [0usize, 2, 8, 1000] {
            assert!(
                adapter
                    .verify_request_signature(
                        &token,
                        &signature_bytes,
                        &metadata.signing_message_with_body_digest(&digest_for(tampered)),
                        Some(ts),
                    )
                    .await
                    .is_err(),
                "swapping to count={tampered} was accepted"
            );
        }

        // It also cannot be reused as a body-less manage signature
        assert!(adapter
            .verify_request_signature(
                &token,
                &signature_bytes,
                &metadata.signing_message(),
                Some(ts)
            )
            .await
            .is_err());
    }

    /// revoke's `new_min_valid_issued_at` determines "up to which Tokens are revoked", so
    /// it must be in the signed message. Otherwise, the revocation time alone could be swapped
    /// while keeping the same token, signature, and timestamp
    /// (the same kind of omission as add-members' `count`).
    #[tokio::test]
    async fn test_revoke_cutoff_cannot_be_substituted() {
        use crate::domain::access_control::AccessControlUpdate;
        use crate::port::auth_token::RequestMetadata;
        use p256::ecdsa::signature::Signer;
        use sha2::Digest;

        let (adapter, signing_key, key_id) = create_test_adapter();
        let token = AuthToken::new(key_id);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let metadata = RequestMetadata {
            timestamp: ts,
            operation: "revoke".to_string(),
            resource: "content-1".to_string(),
        };
        let digest_for = |cutoff: u64| {
            let update = AccessControlUpdate::new("content-1".to_string(), cutoff);
            hex::encode(sha2::Sha256::digest(update.signing_message()))
        };

        // The caller signs for cutoff=2000
        let signed_message = metadata.signing_message_with_body_digest(&digest_for(2000));
        let signature: p256::ecdsa::Signature = signing_key.sign(signed_message.as_bytes());
        let signature_bytes = signature.to_vec();

        assert!(adapter
            .verify_request_signature(&token, &signature_bytes, &signed_message, Some(ts))
            .await
            .is_ok());

        // A request with the cutoff swapped fails verification
        for tampered in [0u64, 1, 1999, 2001, u64::MAX] {
            assert!(
                adapter
                    .verify_request_signature(
                        &token,
                        &signature_bytes,
                        &metadata.signing_message_with_body_digest(&digest_for(tampered)),
                        Some(ts),
                    )
                    .await
                    .is_err(),
                "swapping to cutoff={tampered} was accepted"
            );
        }
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
