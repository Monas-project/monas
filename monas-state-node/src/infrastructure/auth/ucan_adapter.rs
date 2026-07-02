//! UCAN authorization adapter.
//!
//! This adapter implements the Anti-Corruption Layer pattern.
//! It translates between State Node's capability model and UCAN's capability model.
//!
//! Authorization flow:
//! 1. Owner check: if the identity is the owner, access is granted immediately
//! 2. AuthToken check: non-owners must provide a valid AuthToken (JWT)
//!    - Token signature is verified against the owner's public key
//!    - Token's iat must be >= policy's min_valid_issued_at
//!    - Token must grant the required capability

use crate::domain::auth_capability::AuthCapability;
use crate::domain::identity::{Identity, IdentityType};
use crate::infrastructure::auth::auth_token::AuthToken as InfraAuthToken;
use crate::infrastructure::auth::signature_verifier::SignatureVerifier;
use crate::infrastructure::persistence::SledPublicKeyRepository;
use crate::port::auth_token::AuthToken;
use crate::port::authorization_service::{
    AuthorizationRequest, AuthorizationResult, AuthorizationService,
};
use crate::port::content_repository::ContentRepository;
use anyhow::{Context, Result};
use async_trait::async_trait;
use std::sync::Arc;

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
pub struct UcanAdapter {
    content_repo: Arc<dyn ContentRepository>,
    /// Nonce store for replay attack prevention (JTI uniqueness check)
    nonce_store: Option<Arc<SledPublicKeyRepository>>,
}

impl UcanAdapter {
    /// Create a new UcanAdapter with a ContentRepository
    pub fn new(content_repo: Arc<dyn ContentRepository>) -> Self {
        Self {
            content_repo,
            nonce_store: None,
        }
    }

    /// Set the nonce store for replay attack prevention (builder pattern)
    pub fn with_nonce_store(mut self, nonce_store: Arc<SledPublicKeyRepository>) -> Self {
        self.nonce_store = Some(nonce_store);
        self
    }

    /// Convert Identity to key ID format
    ///
    /// # Arguments
    /// * `identity` - The Identity to convert
    ///
    /// # Returns
    /// Key ID string in format "monas:type:id"
    /// For self-contained key IDs, id is the hex-encoded public key,
    /// e.g., "monas:user:04abcd..."
    fn identity_to_key_id(identity: &Identity) -> String {
        let identity_type = match identity.identity_type() {
            IdentityType::User => "user",
            IdentityType::Node => "node",
            IdentityType::Service => "service",
        };
        format!("monas:{}:{}", identity_type, identity.id())
    }

    /// Extract public key bytes from a self-contained key ID.
    ///
    /// Key ID format: "monas:type:{public_key_hex}" or "type:{public_key_hex}"
    /// The public key hex is 130 characters (65 bytes uncompressed P256, starting with 04).
    ///
    /// Returns None if the key ID does not contain a valid embedded public key.
    fn extract_public_key_from_key_id(key_id: &str) -> Option<Vec<u8>> {
        // Extract the last segment (the id part)
        let id_part = if key_id.starts_with("monas:") {
            // "monas:user:04abcd..." -> split into ["monas", "user", "04abcd..."]
            key_id.splitn(3, ':').nth(2)?
        } else {
            // "user:04abcd..." -> split into ["user", "04abcd..."]
            key_id.split_once(':')?.1
        };

        // Uncompressed P256 public key = 65 bytes = 130 hex chars, starts with "04"
        if id_part.len() == 130 && id_part.starts_with("04") {
            hex::decode(id_part).ok()
        } else {
            None
        }
    }

    // ---- UCAN methods below are disabled until proper verification is implemented ----
    // They are retained for future Phase implementation of UCAN delegation chain support.

    /// Map State Node capability to UCAN capability string
    #[allow(dead_code)]
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
    #[allow(dead_code)]
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

        Ok(UcanToken {
            raw: token.to_string(),
        })
    }

    /// Verify UCAN token signature and proof chain.
    ///
    /// SECURITY: UCAN verification is not yet implemented. All tokens are rejected
    /// until proper signature verification, expiration checks, and delegation chain
    /// validation are implemented.
    #[allow(dead_code)]
    fn verify_ucan(&self, _ucan: &UcanToken) -> Result<()> {
        Err(anyhow::anyhow!(
            "UCAN verification is not implemented - all UCAN tokens are rejected"
        ))
    }

    /// Check if UCAN grants a specific capability for a resource.
    #[allow(dead_code)]
    fn check_ucan_capability(
        &self,
        ucan: &UcanToken,
        resource: &str,
        capability: &AuthCapability,
    ) -> Result<bool> {
        let ucan_cap = Self::map_capability_to_ucan(capability);

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
    #[allow(dead_code)]
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
    fn parse_auth_token(&self, token_str: &str) -> Result<InfraAuthToken> {
        InfraAuthToken::from_jwt(token_str).context("Failed to parse AuthToken")
    }

    /// Get public key for a key ID by extracting it from the self-contained key ID.
    ///
    /// The key ID embeds the full public key hex (e.g., "monas:user:04abcd..."),
    /// so no external registry lookup is needed.
    fn get_public_key_from_key_id(key_id: &str) -> Result<Vec<u8>> {
        Self::extract_public_key_from_key_id(key_id).ok_or_else(|| {
            anyhow::anyhow!(
                "Cannot extract public key from key ID '{}': expected format 'type:{{130-hex-char-public-key}}'",
                key_id
            )
        })
    }

    /// Verify AuthToken with domain-level checks delegated to domain verifier components,
    /// plus adapter-specific checks (JTI uniqueness, request signature).
    ///
    /// Domain-level verification (signature, expiration, TTL, access control, audience,
    /// capability) uses the same logic as domain::auth_token_verifier::AuthTokenVerifier.
    /// Adapter-level checks (JTI nonce, request signature) remain here as they depend
    /// on infrastructure concerns (nonce store, request context).
    ///
    /// Note: We cannot directly call AuthTokenVerifier::verify() because the infra and
    /// domain AuthToken use different JWT serialization formats for iss/aud fields
    /// (string key IDs vs byte-array KeyId). Instead, we use the domain's
    /// ContentAccessControl for access control checks and delegate signature verification
    /// to the shared crypto layer.
    async fn verify_auth_token(
        &self,
        token: &InfraAuthToken,
        request: &AuthorizationRequest,
        min_valid_issued_at: u64,
    ) -> Result<()> {
        // 1. Check expiration
        if token.is_expired() {
            anyhow::bail!("AuthToken has expired");
        }

        // 1.5. Check max TTL (reject abnormally long-lived tokens)
        const MAX_TOKEN_TTL_SECS: u64 = 24 * 60 * 60; // 24 hours
        if let Some(exp) = token.payload.exp {
            let lifetime = exp.saturating_sub(token.payload.iat);
            if lifetime > MAX_TOKEN_TTL_SECS {
                anyhow::bail!(
                    "AuthToken TTL too long: {} secs (max {})",
                    lifetime,
                    MAX_TOKEN_TTL_SECS
                );
            }
        }

        // 2. Check access control (min_valid_issued_at) using domain ContentAccessControl
        let access_control = crate::domain::access_control::ContentAccessControl::with_values(
            request.resource.as_str().to_string(),
            min_valid_issued_at,
            1,
            0,
        );
        if !access_control.is_token_valid(token.payload.iat) {
            anyhow::bail!(
                "AuthToken invalidated: iat {} < min_valid_issued_at {}",
                token.payload.iat,
                min_valid_issued_at
            );
        }

        // 3. Verify audience matches requester
        let requester_key_id = Self::identity_to_key_id(&request.identity);
        if token.payload.aud != requester_key_id {
            anyhow::bail!(
                "AuthToken audience mismatch: expected {}, got {}",
                requester_key_id,
                token.payload.aud
            );
        }

        // 4. Check JTI uniqueness (adapter layer - replay attack prevention)
        if let Some(nonce_store) = &self.nonce_store {
            if !nonce_store
                .check_and_record_nonce(&token.payload.jti)
                .await?
            {
                anyhow::bail!("AuthToken JTI already used (replay attack prevented)");
            }
        }

        // 5. Extract owner's public key from key ID and verify AuthToken signature
        let owner_public_key = Self::get_public_key_from_key_id(&token.payload.iss)?;

        SignatureVerifier::verify_auth_token_signature(token, &owner_public_key)
            .context("AuthToken signature verification failed")?;

        // 6. Verify request signature (adapter layer - mandatory)
        let request_signature = request.request_signature.as_ref().ok_or_else(|| {
            anyhow::anyhow!("Request signature is required for AuthToken-based authorization")
        })?;

        // Extract requester's public key from key ID
        let requester_public_key = Self::get_public_key_from_key_id(&token.payload.aud)?;

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

        // 7. Check capability (domain-level check, using infra token's capability format)
        let required_action =
            crate::infrastructure::auth::auth_token::CapabilityAction::from_auth_capability(
                &request.capability,
            );
        let resource_uri = format!("monas://content/{}", request.resource.as_str());
        if !token.has_capability(&resource_uri, &required_action) {
            anyhow::bail!(
                "AuthToken does not grant required capability {:?} for {}",
                request.capability,
                resource_uri
            );
        }

        Ok(())
    }

    /// Check AuthToken-based authorization
    async fn check_auth_token_authorization(
        &self,
        token: &AuthToken,
        request: &AuthorizationRequest,
        min_valid_issued_at: u64,
    ) -> Result<bool> {
        // 1. Parse AuthToken
        let auth_token = self.parse_auth_token(token.as_str())?;

        // 2. Verify AuthToken (domain verifier checks signature, expiration, audience,
        //    capability, and access control; adapter checks JTI and request signature)
        self.verify_auth_token(&auth_token, request, min_valid_issued_at)
            .await?;

        Ok(true)
    }
}

#[async_trait]
impl AuthorizationService for UcanAdapter {
    async fn authorize(&self, request: &AuthorizationRequest) -> Result<AuthorizationResult> {
        // 1. Get access policy from CRDT repository
        let policy = self
            .content_repo
            .get_access_policy(request.resource.as_str())
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

        // 3. Non-owners must provide a token
        let Some(token) = &request.token else {
            return Ok(AuthorizationResult::Denied {
                reason: "Non-owner access requires an AuthToken".to_string(),
            });
        };

        // 4. Check AuthToken (delegated access) with min_valid_issued_at
        match self
            .check_auth_token_authorization(token, request, policy.min_valid_issued_at())
            .await
        {
            Ok(true) => Ok(AuthorizationResult::Granted),
            Ok(false) => Ok(AuthorizationResult::Denied {
                reason: "AuthToken does not grant required capability".to_string(),
            }),
            Err(e) => Ok(AuthorizationResult::Denied {
                reason: format!("AuthToken verification failed: {}", e),
            }),
        }
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
#[allow(dead_code)]
struct UcanToken {
    raw: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::access_policy::AccessPolicy;
    use crate::domain::identity::Identity;
    use crate::domain::value_objects::ContentId;
    use crate::port::content_repository::{CommitResult, SerializedOperation};
    use std::collections::HashMap;
    use tokio::sync::RwLock;

    // Mock content repository for testing
    struct MockContentRepo {
        policies: Arc<RwLock<HashMap<String, AccessPolicy>>>,
    }

    impl MockContentRepo {
        fn new() -> Self {
            Self {
                policies: Arc::new(RwLock::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl ContentRepository for MockContentRepo {
        async fn create_content(
            &self,
            _data: &[u8],
            _author: &str,
            _access_policy: Option<AccessPolicy>,
        ) -> Result<CommitResult> {
            unimplemented!()
        }
        async fn update_content(
            &self,
            _genesis_cid: &str,
            _data: &[u8],
            _author: &str,
            _access_policy: Option<AccessPolicy>,
        ) -> Result<CommitResult> {
            unimplemented!()
        }
        async fn get_latest(&self, _genesis_cid: &str) -> Result<Option<Vec<u8>>> {
            unimplemented!()
        }
        async fn get_latest_with_version(
            &self,
            _genesis_cid: &str,
        ) -> Result<Option<(Vec<u8>, String)>> {
            unimplemented!()
        }
        async fn get_version(&self, _version_cid: &str) -> Result<Option<Vec<u8>>> {
            unimplemented!()
        }
        async fn get_history(&self, _genesis_cid: &str) -> Result<Vec<String>> {
            unimplemented!()
        }
        async fn get_operations(
            &self,
            _genesis_cid: &str,
            _since_version: Option<&str>,
        ) -> Result<Vec<SerializedOperation>> {
            unimplemented!()
        }
        async fn apply_operations(&self, _operations: &[SerializedOperation]) -> Result<usize> {
            unimplemented!()
        }
        async fn exists(&self, _genesis_cid: &str) -> Result<bool> {
            unimplemented!()
        }
        async fn has_genesis(&self, _genesis_cid: &str) -> Result<bool> {
            unimplemented!()
        }
        async fn list_contents(&self) -> Result<Vec<String>> {
            unimplemented!()
        }
        async fn get_access_policy(&self, genesis_cid: &str) -> Result<Option<AccessPolicy>> {
            Ok(self.policies.read().await.get(genesis_cid).cloned())
        }
        async fn update_access_policy(
            &self,
            genesis_cid: &str,
            access_policy: AccessPolicy,
            _author: &str,
        ) -> Result<CommitResult> {
            self.policies
                .write()
                .await
                .insert(genesis_cid.to_string(), access_policy);
            Ok(CommitResult {
                genesis_cid: genesis_cid.to_string(),
                version_cid: "mock-version".to_string(),
                is_new: false,
            })
        }
        async fn prepare_create_operations(
            &self,
            _data: &[u8],
            _author: &str,
            _owner_identity: Option<crate::domain::identity::Identity>,
        ) -> Result<crate::port::content_repository::PreparedCreate> {
            unimplemented!()
        }
    }

    /// Helper to create an owner Identity from a TestKeyPair's public key
    fn identity_from_key(
        key_pair: &crate::infrastructure::auth::test_helpers::TestKeyPair,
    ) -> Identity {
        let pubkey_hex = hex::encode(key_pair.public_key());
        Identity::user(pubkey_hex).unwrap()
    }

    #[tokio::test]
    async fn test_authorize_owner() {
        use crate::infrastructure::auth::test_helpers::TestKeyPair;

        let repo = Arc::new(MockContentRepo::new());
        let adapter = UcanAdapter::new(repo.clone());

        let alice = TestKeyPair::generate("user", "alice");
        let content_id = ContentId::new("content-1".to_string()).unwrap();
        let owner = identity_from_key(&alice);

        // Create policy with owner
        let policy = AccessPolicy::new(content_id.clone(), owner.clone());
        repo.policies
            .write()
            .await
            .insert("content-1".to_string(), policy);

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
    async fn test_authorize_non_owner_no_token() {
        use crate::infrastructure::auth::test_helpers::TestKeyPair;

        let repo = Arc::new(MockContentRepo::new());
        let adapter = UcanAdapter::new(repo.clone());

        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");
        let content_id = ContentId::new("content-1".to_string()).unwrap();
        let owner = identity_from_key(&alice);
        let other = identity_from_key(&bob);

        // Create policy with owner (bob has no token)
        let policy = AccessPolicy::new(content_id.clone(), owner);
        repo.policies
            .write()
            .await
            .insert("content-1".to_string(), policy);

        let request = AuthorizationRequest {
            identity: other,
            resource: content_id,
            capability: AuthCapability::ReadContent,
            token: None,
            request_signature: None,
        };

        let result = adapter.authorize(&request).await.unwrap();

        assert!(result.is_denied());
        assert_eq!(
            result.denial_reason(),
            Some("Non-owner access requires an AuthToken")
        );
    }

    #[tokio::test]
    async fn test_authorize_no_policy() {
        use crate::infrastructure::auth::test_helpers::TestKeyPair;

        let repo = Arc::new(MockContentRepo::new());
        let adapter = UcanAdapter::new(repo);

        let alice = TestKeyPair::generate("user", "alice");
        let content_id = ContentId::new("content-1".to_string()).unwrap();
        let alice_identity = identity_from_key(&alice);

        let request = AuthorizationRequest {
            identity: alice_identity,
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
        use crate::infrastructure::auth::test_helpers::TestKeyPair;

        let repo = Arc::new(MockContentRepo::new());
        let adapter = UcanAdapter::new(repo.clone());

        let alice = TestKeyPair::generate("user", "alice");
        let content_id = ContentId::new("content-1".to_string()).unwrap();
        let owner = identity_from_key(&alice);

        let policy = AccessPolicy::new(content_id.clone(), owner.clone());
        repo.policies
            .write()
            .await
            .insert("content-1".to_string(), policy);

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
            UcanAdapter::map_capability_to_ucan(&AuthCapability::ReadContent),
            "content/read"
        );
        assert_eq!(
            UcanAdapter::map_capability_to_ucan(&AuthCapability::WriteContent),
            "content/write"
        );
        assert_eq!(
            UcanAdapter::map_capability_to_ucan(&AuthCapability::DeleteContent),
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
        let repo = Arc::new(MockContentRepo::new());
        let adapter = UcanAdapter::new(repo.clone());

        // 3. No public key registration needed — key IDs are self-contained

        // 4. Create content and access policy (alice is owner)
        let content_id = ContentId::new("test-content-123".to_string()).unwrap();
        let alice_identity = identity_from_key(&alice);
        let policy = AccessPolicy::new(content_id.clone(), alice_identity.clone());
        repo.policies
            .write()
            .await
            .insert("test-content-123".to_string(), policy);

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
        let bob_identity = identity_from_key(&bob);
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
        let repo = Arc::new(MockContentRepo::new());
        let adapter = UcanAdapter::new(repo.clone());

        let content_id = ContentId::new("test-content-456".to_string()).unwrap();
        let alice_identity = identity_from_key(&alice);
        let policy = AccessPolicy::new(content_id.clone(), alice_identity.clone());
        repo.policies
            .write()
            .await
            .insert("test-content-456".to_string(), policy);

        // Alice grants Bob only Read capability
        let auth_token = alice.create_auth_token(
            &bob,
            "monas://content/test-content-456",
            vec![crate::infrastructure::auth::auth_token::CapabilityAction::Read],
            Some(3600),
        );

        let request_sig = bob.sign_request(&auth_token);

        // Bob tries to use Write capability (not granted)
        let bob_identity = identity_from_key(&bob);
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
    async fn test_auth_token_authorization_denied_replay() {
        use crate::infrastructure::auth::test_helpers::TestKeyPair;
        use crate::infrastructure::persistence::SledPublicKeyRepository;
        use crate::port::auth_token::AuthToken;

        // Setup
        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");
        let repo = Arc::new(MockContentRepo::new());
        let temp_dir = tempfile::TempDir::new().unwrap();
        let nonce_store = Arc::new(SledPublicKeyRepository::open(temp_dir.path()).unwrap());
        let adapter = UcanAdapter::new(repo.clone()).with_nonce_store(nonce_store);

        let content_id = ContentId::new("test-content-replay".to_string()).unwrap();
        let alice_identity = identity_from_key(&alice);
        let policy = AccessPolicy::new(content_id.clone(), alice_identity.clone());
        repo.policies
            .write()
            .await
            .insert("test-content-replay".to_string(), policy);

        // Create a valid token
        let auth_token = alice.create_auth_token(
            &bob,
            "monas://content/test-content-replay",
            vec![crate::infrastructure::auth::auth_token::CapabilityAction::Read],
            Some(3600),
        );

        let request_sig = bob.sign_request(&auth_token);
        let bob_identity = identity_from_key(&bob);
        let token = AuthToken::new(auth_token.to_jwt().unwrap());

        // First request should succeed
        let request = AuthorizationRequest {
            identity: bob_identity.clone(),
            resource: content_id.clone(),
            capability: AuthCapability::ReadContent,
            token: Some(token.clone()),
            request_signature: Some(request_sig.clone()),
        };
        let result = adapter.authorize(&request).await.unwrap();
        assert!(result.is_granted(), "First use should be granted");

        // Second request with same token (same JTI) should be denied (replay)
        let request2 = AuthorizationRequest {
            identity: bob_identity,
            resource: content_id,
            capability: AuthCapability::ReadContent,
            token: Some(token),
            request_signature: Some(request_sig),
        };
        let result2 = adapter.authorize(&request2).await.unwrap();
        assert!(
            result2.is_denied(),
            "Replay should be denied, but got: {:?}",
            result2
        );
    }

    #[tokio::test]
    async fn test_auth_token_authorization_denied_expired() {
        use crate::infrastructure::auth::test_helpers::TestKeyPair;
        use crate::port::auth_token::AuthToken;

        // Setup
        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");
        let repo = Arc::new(MockContentRepo::new());
        let adapter = UcanAdapter::new(repo.clone());

        let content_id = ContentId::new("test-content-789".to_string()).unwrap();
        let alice_identity = identity_from_key(&alice);
        let policy = AccessPolicy::new(content_id.clone(), alice_identity.clone());
        repo.policies
            .write()
            .await
            .insert("test-content-789".to_string(), policy);

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

        let bob_identity = identity_from_key(&bob);
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

    #[tokio::test]
    async fn test_auth_token_authorization_denied_invalidated() {
        use crate::infrastructure::auth::test_helpers::TestKeyPair;
        use crate::port::auth_token::AuthToken;

        // Setup
        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");
        let repo = Arc::new(MockContentRepo::new());
        let adapter = UcanAdapter::new(repo.clone());

        let content_id = ContentId::new("test-content-inv".to_string()).unwrap();
        let alice_identity = identity_from_key(&alice);

        // First create the token, then invalidate
        let auth_token = alice.create_auth_token(
            &bob,
            "monas://content/test-content-inv",
            vec![crate::infrastructure::auth::auth_token::CapabilityAction::Read],
            Some(3600),
        );

        // Wait to ensure invalidation timestamp is after token's iat
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Now invalidate tokens (min_valid_issued_at will be > token's iat)
        let mut policy = AccessPolicy::new(content_id.clone(), alice_identity.clone());
        policy.invalidate_tokens();
        repo.policies
            .write()
            .await
            .insert("test-content-inv".to_string(), policy);

        let request_sig = bob.sign_request(&auth_token);
        let bob_identity = identity_from_key(&bob);
        let token = AuthToken::new(auth_token.to_jwt().unwrap());
        let request = AuthorizationRequest {
            identity: bob_identity,
            resource: content_id.clone(),
            capability: AuthCapability::ReadContent,
            token: Some(token),
            request_signature: Some(request_sig),
        };

        // Verify authorization is denied due to token invalidation
        let result = adapter.authorize(&request).await.unwrap();
        assert!(
            result.is_denied(),
            "AuthToken authorization should be denied for invalidated token, but got: {:?}",
            result
        );
    }
}
