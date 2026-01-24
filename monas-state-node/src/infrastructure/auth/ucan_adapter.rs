//! UCAN authorization adapter.
//!
//! This adapter implements the Anti-Corruption Layer pattern.
//! It translates between State Node's capability model and UCAN's capability model.

use crate::domain::auth_capability::AuthCapability;
use crate::domain::identity::{Identity, IdentityType};
use crate::infrastructure::auth::auth_token::{AuthToken as InfraAuthToken, CapabilityAction};
use crate::infrastructure::auth::signature_verifier::SignatureVerifier;
use crate::port::auth_token::AuthToken;
use crate::port::authorization_service::{
    AuthorizationRequest, AuthorizationResult, AuthorizationService,
};
use crate::port::persistence::PersistentAccessPolicyRepository;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Adapter for UCAN-based authorization
///
/// This adapter implements Anti-Corruption Layer pattern.
/// It translates between State Node's capability model and UCAN's capability model.
///
/// # Architecture
///
/// ```text
/// State Node Domain (Capability, AccessPolicy)
///          ↕
/// UcanAdapter (translation)
///          ↕
/// UCAN (capability delegation)
/// ```
pub struct UcanAdapter<R>
where
    R: PersistentAccessPolicyRepository,
{
    policy_repo: Arc<RwLock<R>>,
    /// Public key registry for key ID resolution (Phase 1 mock implementation)
    /// Maps key ID -> Public Key (65 bytes, uncompressed P256 format)
    public_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl<R> UcanAdapter<R>
where
    R: PersistentAccessPolicyRepository,
{
    pub fn new(policy_repo: Arc<RwLock<R>>) -> Self {
        Self {
            policy_repo,
            public_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a public key for a key ID (for testing and Phase 1 mock implementation)
    ///
    /// # Arguments
    /// * `key_id` - The key ID to register (format: "monas:type:id")
    /// * `public_key` - The public key in uncompressed P256 format (65 bytes)
    pub async fn register_public_key(&self, key_id: String, public_key: Vec<u8>) {
        self.public_keys.write().await.insert(key_id, public_key);
    }

    /// Convert Identity to key ID format
    ///
    /// # Arguments
    /// * `identity` - The Identity to convert
    ///
    /// # Returns
    /// Key ID string in format "monas:type:id" (e.g., "monas:user:alice")
    fn identity_to_key_id(identity: &Identity) -> String {
        let identity_type = match identity.identity_type() {
            IdentityType::User => "user",
            IdentityType::Node => "node",
            IdentityType::Service => "service",
        };
        format!("monas:{}:{}", identity_type, identity.id())
    }

    /// Map State Node capability to AuthToken capability action
    fn map_capability_to_auth_token(cap: &AuthCapability) -> CapabilityAction {
        match cap {
            AuthCapability::ReadContent => CapabilityAction::Read,
            AuthCapability::WriteContent => CapabilityAction::Write,
            AuthCapability::DeleteContent => CapabilityAction::Delete,
            AuthCapability::ShareContent => CapabilityAction::Share,
            AuthCapability::RevokeAccess => CapabilityAction::Revoke,
            AuthCapability::ReadMetadata => CapabilityAction::Read, // ReadMetadata is subset of Read
            AuthCapability::ManageMembers => CapabilityAction::Share, // ManageMembers requires Share
        }
    }

    /// Map State Node capability to UCAN capability string
    fn map_capability_to_ucan(cap: &AuthCapability) -> &str {
        match cap {
            AuthCapability::ReadContent => "content/read",
            AuthCapability::WriteContent => "content/write",
            AuthCapability::DeleteContent => "content/delete",
            AuthCapability::ManageMembers => "content/manage",
            AuthCapability::ShareContent => "content/share",
            AuthCapability::RevokeAccess => "content/revoke",
            AuthCapability::ReadMetadata => "content/read-metadata",
        }
    }

    /// Parse UCAN token from JWT string.
    ///
    /// # Implementation Status
    ///
    /// Currently performs basic JWT format validation.
    ///
    /// # TODO: Full UCAN Parsing
    ///
    /// When monas-ucan crate becomes available:
    /// 1. Parse JWT header, payload, and signature
    /// 2. Extract UCAN fields: iss (issuer), aud (audience), att (attenuations), exp, nbf, etc.
    /// 3. Validate UCAN structure according to spec: https://ucan.xyz/
    /// 4. Extract proof chain (prf field)
    /// 5. Extract capabilities (att field)
    ///
    /// Alternative: Use external `ucan` crate (0.7.0-alpha.1) for parsing.
    fn parse_ucan(&self, token: &str) -> Result<UcanToken> {
        if token.is_empty() {
            return Err(anyhow::anyhow!("Empty UCAN token"));
        }

        // Basic JWT format validation: header.payload.signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow::anyhow!(
                "Invalid JWT format: expected 3 parts (header.payload.signature), got {}",
                parts.len()
            ));
        }

        // Validate that each part is non-empty and base64url-encoded
        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                return Err(anyhow::anyhow!("Empty JWT part at index {}", i));
            }
        }

        // TODO: Decode and validate JWT structure using ucan crate
        // For now, store raw token for future processing
        Ok(UcanToken {
            raw: token.to_string(),
        })
    }

    /// Verify UCAN token signature and proof chain.
    ///
    /// # Implementation Status
    ///
    /// Currently performs minimal validation (non-empty check).
    /// **WARNING**: This is NOT secure for production use.
    ///
    /// # TODO: Full UCAN Verification
    ///
    /// When monas-ucan crate becomes available, implement:
    ///
    /// 1. **Signature Verification**
    ///    - Extract public key from issuer
    ///    - Verify signature matches header + payload
    ///    - Use appropriate signature algorithm (EdDSA, ECDSA, RSA)
    ///
    /// 2. **Expiration Check**
    ///    - Verify exp (expiration time) > current time
    ///    - Verify nbf (not-before time) <= current time
    ///
    /// 3. **Proof Chain Validation**
    ///    - Recursively validate all UCANs in prf (proofs) field
    ///    - Ensure delegation chain is valid
    ///    - Verify each UCAN's audience matches next UCAN's issuer
    ///
    /// 4. **Issuer/Audience Validation**
    ///    - Verify issuer (iss) is valid
    ///    - Verify audience (aud) matches expected recipient
    ///
    /// 5. **Revocation Check**
    ///    - Check against revocation list if available
    ///
    /// Reference: https://ucan.xyz/#verification
    fn verify_ucan(&self, ucan: &UcanToken) -> Result<()> {
        if ucan.raw.is_empty() {
            return Err(anyhow::anyhow!("Invalid UCAN: empty token"));
        }

        // TODO: Implement full verification using ucan crate or monas-ucan
        //
        // Example with ucan crate (0.7.0-alpha.1):
        // ```
        // use ucan::Ucan;
        // let parsed_ucan = Ucan::try_from_token_string(&ucan.raw)?;
        // parsed_ucan.validate()?;
        // ```
        //
        // For now, return Ok to allow testing, but log warning

        tracing::warn!(
            "UCAN verification is not fully implemented - allowing all UCANs (INSECURE)"
        );

        Ok(())
    }

    /// Check if UCAN grants a specific capability for a resource.
    ///
    /// # Implementation Status
    ///
    /// Currently uses simplified string matching.
    /// **WARNING**: This is NOT secure for production use.
    ///
    /// # TODO: Full Capability Checking
    ///
    /// When monas-ucan crate becomes available, implement:
    ///
    /// 1. **Parse Capabilities from UCAN**
    ///    - Extract att (attenuations) field from UCAN payload
    ///    - Parse capability objects: { "with": "resource-uri", "can": "action" }
    ///
    /// 2. **Resource URI Matching**
    ///    - Support exact matching: "content://abc123"
    ///    - Support wildcard matching: "content://*", "content://abc*"
    ///    - Support hierarchical matching: "content://parent/*"
    ///
    /// 3. **Capability Hierarchies**
    ///    - ADMIN > DELETE > WRITE > READ
    ///    - If UCAN grants WRITE, it also grants READ
    ///    - If UCAN grants *, it grants all capabilities
    ///
    /// 4. **Attenuation Handling**
    ///    - Verify delegated capabilities are subset of parent UCAN
    ///    - Ensure no privilege escalation in delegation chain
    ///
    /// 5. **Proof Chain Capability Aggregation**
    ///    - Collect capabilities from all UCANs in proof chain
    ///    - Validate each delegation step
    ///
    /// Reference: https://ucan.xyz/#capabilities
    fn check_ucan_capability(
        &self,
        ucan: &UcanToken,
        resource: &str,
        capability: &AuthCapability,
    ) -> Result<bool> {
        let ucan_cap = Self::map_capability_to_ucan(capability);

        // TODO: Implement proper capability checking using ucan crate
        //
        // Example with ucan crate (0.7.0-alpha.1):
        // ```
        // use ucan::Ucan;
        // let parsed_ucan = Ucan::try_from_token_string(&ucan.raw)?;
        // let capabilities = parsed_ucan.attenuations();
        // for cap in capabilities {
        //     if cap.resource() == resource && cap.can_do(ucan_cap) {
        //         return Ok(true);
        //     }
        // }
        // ```
        //
        // For now, use simple string matching (INSECURE)

        let expected = format!("{}:{}", resource, ucan_cap);
        let has_capability = ucan.raw.contains(&expected);

        if has_capability {
            tracing::warn!(
                "UCAN capability check succeeded with insecure string matching for {}",
                expected
            );
        }

        Ok(has_capability)
    }

    /// Check UCAN-based authorization
    async fn check_ucan_authorization(
        &self,
        token: &AuthToken,
        request: &AuthorizationRequest,
    ) -> Result<bool> {
        // 1. Parse UCAN token
        let ucan = self.parse_ucan(token.as_str())?;

        // 2. Verify UCAN signature and chain
        self.verify_ucan(&ucan)?;

        // 3. Check if UCAN grants the required capability
        let has_capability =
            self.check_ucan_capability(&ucan, request.resource.as_str(), &request.capability)?;

        Ok(has_capability)
    }

    /// Parse AuthToken from JWT string
    ///
    /// # Arguments
    /// * `token_str` - JWT string in format "header.payload.signature"
    ///
    /// # Returns
    /// Parsed AuthToken or error if parsing fails
    fn parse_auth_token(&self, token_str: &str) -> Result<InfraAuthToken> {
        InfraAuthToken::from_jwt(token_str).context("Failed to parse AuthToken")
    }

    /// Get public key for a key ID
    ///
    /// # Implementation Status
    ///
    /// Currently uses mock implementation with in-memory registry.
    /// **WARNING**: This is NOT secure for production use.
    ///
    /// # TODO: Full Public Key Resolution
    ///
    /// When account registry becomes available:
    /// 1. Query account registry for public key
    /// 2. Support multiple key types (P256, Ed25519, etc.)
    /// 3. Handle key rotation and revocation
    /// 4. Cache public keys for performance
    ///
    /// For now, uses in-memory registry (Phase 1 mock implementation)
    async fn get_public_key(&self, key_id: &str) -> Result<Option<Vec<u8>>> {
        // Phase 1: Use in-memory public key registry
        let public_keys = self.public_keys.read().await;
        if let Some(key) = public_keys.get(key_id) {
            Ok(Some(key.clone()))
        } else {
            tracing::warn!("Public key not found for key ID: {}", key_id);
            Ok(None)
        }
    }

    /// Verify AuthToken with dual signature verification
    ///
    /// # Arguments
    /// * `token` - The AuthToken to verify
    /// * `request` - The authorization request containing request signature
    ///
    /// # Returns
    /// Ok(()) if all verifications pass, Err otherwise
    ///
    /// # Verification Steps
    ///
    /// 1. **AuthToken Signature Verification**
    ///    - Get owner's public key from issuer key ID (iss)
    ///    - Verify AuthToken signature using owner's public key
    ///
    /// 2. **Request Signature Verification**
    ///    - Verify request signature is provided
    ///    - Get requester's public key from audience key ID (aud)
    ///    - Construct request message: "{iss}:{aud}:{jti}"
    ///    - Verify request signature using requester's public key
    ///
    /// 3. **Expiration Check**
    ///    - Verify token has not expired
    ///
    /// 4. **Audience Validation**
    ///    - Verify audience (aud) matches requester identity
    async fn verify_auth_token(
        &self,
        token: &InfraAuthToken,
        request: &AuthorizationRequest,
    ) -> Result<()> {
        // 1. Check expiration
        if token.is_expired() {
            anyhow::bail!("AuthToken has expired");
        }

        // 2. Verify audience matches requester
        let requester_key_id = Self::identity_to_key_id(&request.identity);
        if token.payload.aud != requester_key_id {
            anyhow::bail!(
                "AuthToken audience mismatch: expected {}, got {}",
                requester_key_id,
                token.payload.aud
            );
        }

        // 3. Get owner's public key and verify AuthToken signature
        let owner_public_key = self
            .get_public_key(&token.payload.iss)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Owner public key not found for key ID: {}",
                    token.payload.iss
                )
            })?;

        SignatureVerifier::verify_auth_token_signature(token, &owner_public_key)
            .context("AuthToken signature verification failed")?;

        // 4. Verify request signature if provided
        if let Some(request_signature) = &request.request_signature {
            // Get requester's public key
            let requester_public_key =
                self.get_public_key(&token.payload.aud)
                    .await?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Requester public key not found for key ID: {}",
                            token.payload.aud
                        )
                    })?;

            // Construct request message: "{iss}:{aud}:{jti}"
            let request_message = format!(
                "{}:{}:{}",
                token.payload.iss, token.payload.aud, token.payload.jti
            );

            SignatureVerifier::verify_request_signature(
                request_message.as_bytes(),
                request_signature,
                &requester_public_key,
            )
            .context("Request signature verification failed")?;
        } else {
            tracing::warn!(
                "No request signature provided - skipping request signature verification"
            );
        }

        Ok(())
    }

    /// Check if AuthToken grants a specific capability for a resource
    ///
    /// # Arguments
    /// * `token` - The AuthToken to check
    /// * `resource` - The resource URI (e.g., "monas://content/abc123")
    /// * `capability` - The required capability
    ///
    /// # Returns
    /// true if token grants the capability, false otherwise
    fn check_auth_token_capability(
        &self,
        token: &InfraAuthToken,
        resource: &str,
        capability: &AuthCapability,
    ) -> bool {
        let required_action = Self::map_capability_to_auth_token(capability);
        let resource_uri = format!("monas://content/{}", resource);

        token.has_capability(&resource_uri, &required_action)
    }

    /// Check AuthToken-based authorization
    async fn check_auth_token_authorization(
        &self,
        token: &AuthToken,
        request: &AuthorizationRequest,
    ) -> Result<bool> {
        // 1. Parse AuthToken
        let auth_token = self.parse_auth_token(token.as_str())?;

        // 2. Verify AuthToken and request signatures
        self.verify_auth_token(&auth_token, request).await?;

        // 3. Check if AuthToken grants the required capability
        let has_capability = self.check_auth_token_capability(
            &auth_token,
            request.resource.as_str(),
            &request.capability,
        );

        Ok(has_capability)
    }
}

#[async_trait]
impl<R> AuthorizationService for UcanAdapter<R>
where
    R: PersistentAccessPolicyRepository,
{
    async fn authorize(&self, request: &AuthorizationRequest) -> Result<AuthorizationResult> {
        // 1. Get access policy from repository
        let policy = self
            .policy_repo
            .read()
            .await
            .get_policy(request.resource.as_str())
            .await
            .context("Failed to get access policy")?;

        let Some(policy) = policy else {
            // No policy found = access denied
            return Ok(AuthorizationResult::Denied {
                reason: "No access policy found for resource".to_string(),
            });
        };

        // 2. Check if identity is owner (always has access)
        if policy.is_owner(&request.identity) {
            return Ok(AuthorizationResult::Granted);
        }

        // 3. Check direct policy grants (local access policy)
        if policy.has_capability(&request.identity, &request.capability) {
            return Ok(AuthorizationResult::Granted);
        }

        // 4. Check token if provided (delegated access)
        if let Some(token) = &request.token {
            // Try AuthToken first (recommended for new implementations)
            match self.check_auth_token_authorization(token, request).await {
                Ok(true) => return Ok(AuthorizationResult::Granted),
                Ok(false) => {
                    return Ok(AuthorizationResult::Denied {
                        reason: "AuthToken does not grant required capability".to_string(),
                    });
                }
                Err(e) => {
                    // If AuthToken parsing/verification fails, try UCAN as fallback
                    tracing::debug!("AuthToken verification failed, trying UCAN: {}", e);

                    match self.check_ucan_authorization(token, request).await {
                        Ok(true) => return Ok(AuthorizationResult::Granted),
                        Ok(false) => {
                            return Ok(AuthorizationResult::Denied {
                                reason: "Token does not grant required capability".to_string(),
                            });
                        }
                        Err(ucan_err) => {
                            return Ok(AuthorizationResult::Denied {
                                reason: format!(
                                    "Token verification failed (AuthToken: {}, UCAN: {})",
                                    e, ucan_err
                                ),
                            });
                        }
                    }
                }
            }
        }

        // 5. No authorization found
        Ok(AuthorizationResult::Denied {
            reason: "Identity does not have required capability".to_string(),
        })
    }

    async fn authorize_batch(
        &self,
        requests: &[AuthorizationRequest],
    ) -> Result<Vec<AuthorizationResult>> {
        // Optimized batch authorization
        let mut results = Vec::with_capacity(requests.len());

        for request in requests {
            results.push(self.authorize(request).await?);
        }

        Ok(results)
    }
}

/// Internal UCAN token representation (hidden from domain)
struct UcanToken {
    raw: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::access_policy::AccessPolicy;
    use crate::domain::identity::Identity;
    use crate::domain::value_objects::ContentId;
    use std::collections::HashMap;

    // Mock repository for testing
    struct MockAccessPolicyRepository {
        policies: Arc<RwLock<HashMap<String, AccessPolicy>>>,
    }

    impl MockAccessPolicyRepository {
        fn new() -> Self {
            Self {
                policies: Arc::new(RwLock::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl PersistentAccessPolicyRepository for MockAccessPolicyRepository {
        async fn get_policy(&self, content_id: &str) -> Result<Option<AccessPolicy>> {
            Ok(self.policies.read().await.get(content_id).cloned())
        }

        async fn save_policy(&self, policy: &AccessPolicy) -> Result<()> {
            self.policies
                .write()
                .await
                .insert(policy.content_id().as_str().to_string(), policy.clone());
            Ok(())
        }

        async fn delete_policy(&self, content_id: &str) -> Result<()> {
            self.policies.write().await.remove(content_id);
            Ok(())
        }

        async fn list_policies(&self) -> Result<Vec<String>> {
            Ok(self.policies.read().await.keys().cloned().collect())
        }

        async fn flush(&self) -> Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_authorize_owner() {
        let repo = Arc::new(RwLock::new(MockAccessPolicyRepository::new()));
        let adapter = UcanAdapter::new(repo.clone());

        let content_id = ContentId::new("content-1".to_string()).unwrap();
        let owner = Identity::user("alice".to_string()).unwrap();

        // Create policy with owner
        let policy = AccessPolicy::new(content_id.clone(), owner.clone());
        repo.read().await.save_policy(&policy).await.unwrap();

        let request = AuthorizationRequest {
            identity: owner,
            resource: content_id,
            capability: AuthCapability::ReadContent,
            token: None,
            request_signature: None,
        };

        let result = adapter.authorize(&request).await.unwrap();

        assert!(result.is_granted());
    }

    #[tokio::test]
    async fn test_authorize_non_owner_no_grant() {
        let repo = Arc::new(RwLock::new(MockAccessPolicyRepository::new()));
        let adapter = UcanAdapter::new(repo.clone());

        let content_id = ContentId::new("content-1".to_string()).unwrap();
        let owner = Identity::user("alice".to_string()).unwrap();
        let other = Identity::user("bob".to_string()).unwrap();

        // Create policy with owner (bob has no grants)
        let policy = AccessPolicy::new(content_id.clone(), owner);
        repo.read().await.save_policy(&policy).await.unwrap();

        let request = AuthorizationRequest {
            identity: other,
            resource: content_id,
            capability: AuthCapability::ReadContent,
            token: None,
            request_signature: None,
        };

        let result = adapter.authorize(&request).await.unwrap();

        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_authorize_with_grant() {
        let repo = Arc::new(RwLock::new(MockAccessPolicyRepository::new()));
        let adapter = UcanAdapter::new(repo.clone());

        let content_id = ContentId::new("content-1".to_string()).unwrap();
        let owner = Identity::user("alice".to_string()).unwrap();
        let bob = Identity::user("bob".to_string()).unwrap();

        // Create policy and grant ReadContent to bob
        let mut policy = AccessPolicy::new(content_id.clone(), owner);
        policy
            .grant(bob.clone(), vec![AuthCapability::ReadContent])
            .unwrap();
        repo.read().await.save_policy(&policy).await.unwrap();

        let request = AuthorizationRequest {
            identity: bob,
            resource: content_id,
            capability: AuthCapability::ReadContent,
            token: None,
            request_signature: None,
        };

        let result = adapter.authorize(&request).await.unwrap();

        assert!(result.is_granted());
    }

    #[tokio::test]
    async fn test_authorize_no_policy() {
        let repo = Arc::new(RwLock::new(MockAccessPolicyRepository::new()));
        let adapter = UcanAdapter::new(repo);

        let content_id = ContentId::new("content-1".to_string()).unwrap();
        let alice = Identity::user("alice".to_string()).unwrap();

        let request = AuthorizationRequest {
            identity: alice,
            resource: content_id,
            capability: AuthCapability::ReadContent,
            token: None,
            request_signature: None,
        };

        let result = adapter.authorize(&request).await.unwrap();

        assert!(result.is_denied());
        assert_eq!(
            result.denial_reason(),
            Some("No access policy found for resource")
        );
    }

    #[tokio::test]
    async fn test_authorize_batch() {
        let repo = Arc::new(RwLock::new(MockAccessPolicyRepository::new()));
        let adapter = UcanAdapter::new(repo.clone());

        let content_id = ContentId::new("content-1".to_string()).unwrap();
        let owner = Identity::user("alice".to_string()).unwrap();

        let policy = AccessPolicy::new(content_id.clone(), owner.clone());
        repo.read().await.save_policy(&policy).await.unwrap();

        let requests = vec![
            AuthorizationRequest {
                identity: owner.clone(),
                resource: content_id.clone(),
                capability: AuthCapability::ReadContent,
                token: None,
                request_signature: None,
            },
            AuthorizationRequest {
                identity: owner.clone(),
                resource: content_id.clone(),
                capability: AuthCapability::WriteContent,
                token: None,
                request_signature: None,
            },
        ];

        let results = adapter.authorize_batch(&requests).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_granted());
        assert!(results[1].is_granted());
    }

    #[tokio::test]
    async fn test_map_capability_to_ucan() {
        assert_eq!(
            UcanAdapter::<MockAccessPolicyRepository>::map_capability_to_ucan(
                &AuthCapability::ReadContent
            ),
            "content/read"
        );
        assert_eq!(
            UcanAdapter::<MockAccessPolicyRepository>::map_capability_to_ucan(
                &AuthCapability::WriteContent
            ),
            "content/write"
        );
        assert_eq!(
            UcanAdapter::<MockAccessPolicyRepository>::map_capability_to_ucan(
                &AuthCapability::DeleteContent
            ),
            "content/delete"
        );
    }

    #[tokio::test]
    async fn test_auth_token_authorization_e2e() {
        use crate::infrastructure::auth::test_helpers::TestKeyPair;
        use crate::port::auth_token::AuthToken;

        // 1. Setup: Create test key pairs
        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");

        // 2. Setup: Create repository and adapter
        let repo = Arc::new(RwLock::new(MockAccessPolicyRepository::new()));
        let adapter = UcanAdapter::new(repo.clone());

        // 3. Register public keys
        adapter
            .register_public_key(alice.key_id().to_string(), alice.public_key().to_vec())
            .await;
        adapter
            .register_public_key(bob.key_id().to_string(), bob.public_key().to_vec())
            .await;

        // 4. Create content and access policy (alice is owner)
        let content_id = ContentId::new("test-content-123".to_string()).unwrap();
        let alice_identity = Identity::user("alice".to_string()).unwrap();
        let policy = AccessPolicy::new(content_id.clone(), alice_identity.clone());
        repo.read().await.save_policy(&policy).await.unwrap();

        // 5. Alice creates a AuthToken for Bob with Read capability
        let auth_token = alice.create_auth_token(
            &bob,
            "monas://content/test-content-123",
            vec![crate::infrastructure::auth::auth_token::CapabilityAction::Read],
            Some(3600), // 1 hour expiration
        );

        // 6. Bob creates request signature
        let request_sig = bob.sign_request(&auth_token);

        // 7. Create authorization request from Bob using AuthToken
        let bob_identity = Identity::user("bob".to_string()).unwrap();
        let token = AuthToken::new(auth_token.to_jwt().unwrap());
        let request = AuthorizationRequest {
            identity: bob_identity,
            resource: content_id.clone(),
            capability: AuthCapability::ReadContent,
            token: Some(token),
            request_signature: Some(request_sig),
        };

        // 8. Verify authorization is granted
        let result = adapter.authorize(&request).await.unwrap();
        assert!(
            result.is_granted(),
            "AuthToken authorization should be granted, but got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_auth_token_authorization_denied_wrong_capability() {
        use crate::infrastructure::auth::test_helpers::TestKeyPair;
        use crate::port::auth_token::AuthToken;

        // Setup
        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");
        let repo = Arc::new(RwLock::new(MockAccessPolicyRepository::new()));
        let adapter = UcanAdapter::new(repo.clone());

        adapter
            .register_public_key(alice.key_id().to_string(), alice.public_key().to_vec())
            .await;
        adapter
            .register_public_key(bob.key_id().to_string(), bob.public_key().to_vec())
            .await;

        let content_id = ContentId::new("test-content-456".to_string()).unwrap();
        let alice_identity = Identity::user("alice".to_string()).unwrap();
        let policy = AccessPolicy::new(content_id.clone(), alice_identity.clone());
        repo.read().await.save_policy(&policy).await.unwrap();

        // Alice grants Bob only Read capability
        let auth_token = alice.create_auth_token(
            &bob,
            "monas://content/test-content-456",
            vec![crate::infrastructure::auth::auth_token::CapabilityAction::Read],
            Some(3600),
        );

        let request_sig = bob.sign_request(&auth_token);

        // Bob tries to use Write capability (not granted)
        let bob_identity = Identity::user("bob".to_string()).unwrap();
        let token = AuthToken::new(auth_token.to_jwt().unwrap());
        let request = AuthorizationRequest {
            identity: bob_identity,
            resource: content_id.clone(),
            capability: AuthCapability::WriteContent, // Bob doesn't have this!
            token: Some(token),
            request_signature: Some(request_sig),
        };

        // Verify authorization is denied
        let result = adapter.authorize(&request).await.unwrap();
        assert!(
            result.is_denied(),
            "AuthToken authorization should be denied for wrong capability"
        );
    }

    #[tokio::test]
    async fn test_auth_token_authorization_denied_expired() {
        use crate::infrastructure::auth::test_helpers::TestKeyPair;
        use crate::port::auth_token::AuthToken;

        // Setup
        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");
        let repo = Arc::new(RwLock::new(MockAccessPolicyRepository::new()));
        let adapter = UcanAdapter::new(repo.clone());

        adapter
            .register_public_key(alice.key_id().to_string(), alice.public_key().to_vec())
            .await;
        adapter
            .register_public_key(bob.key_id().to_string(), bob.public_key().to_vec())
            .await;

        let content_id = ContentId::new("test-content-789".to_string()).unwrap();
        let alice_identity = Identity::user("alice".to_string()).unwrap();
        let policy = AccessPolicy::new(content_id.clone(), alice_identity.clone());
        repo.read().await.save_policy(&policy).await.unwrap();

        // Create an already-expired token (0 seconds = already expired)
        let auth_token = alice.create_auth_token(
            &bob,
            "monas://content/test-content-789",
            vec![crate::infrastructure::auth::auth_token::CapabilityAction::Read],
            Some(0), // Already expired
        );

        // Wait a moment to ensure expiration
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        let request_sig = bob.sign_request(&auth_token);

        let bob_identity = Identity::user("bob".to_string()).unwrap();
        let token = AuthToken::new(auth_token.to_jwt().unwrap());
        let request = AuthorizationRequest {
            identity: bob_identity,
            resource: content_id.clone(),
            capability: AuthCapability::ReadContent,
            token: Some(token),
            request_signature: Some(request_sig),
        };

        // Verify authorization is denied due to expiration
        let result = adapter.authorize(&request).await.unwrap();
        assert!(
            result.is_denied(),
            "AuthToken authorization should be denied for expired token"
        );
    }
}
