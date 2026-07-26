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
}

impl UcanAdapter {
    /// Create a new UcanAdapter with a ContentRepository
    pub fn new(content_repo: Arc<dyn ContentRepository>) -> Self {
        Self { content_repo }
    }

    /// Convert Identity to key ID format
    ///
    /// # Arguments
    /// * `identity` - The Identity to convert
    ///
    /// # Returns
    /// Key ID string in format "type:id".
    fn identity_to_key_id(identity: &Identity) -> String {
        let identity_type = match identity.identity_type() {
            IdentityType::User => "user",
            IdentityType::Node => "node",
            IdentityType::Service => "service",
        };
        format!("{}:{}", identity_type, identity.id())
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

    /// Verify AuthToken with domain-level checks delegated to domain verifier components.
    ///
    /// Domain-level verification (signature, expiration, TTL, access control, audience,
    /// capability) uses the same logic as domain::auth_token_verifier::AuthTokenVerifier.
    ///
    /// Request proof-of-possession(リクエスト署名の中身)の検証はここでは行わない。
    /// 全経路が authorize より前に通る認証層(`verify_caller_signature`)が、
    /// トークン種別によらず `{operation}:{resource}:{timestamp}` 形式で検証する。
    /// リプレイ防御は署名内 timestamp の鮮度チェック(5 分窓)に一本化されている。
    ///
    /// Note: We cannot directly call AuthTokenVerifier::verify() because the infra and
    /// domain AuthToken use different JWT serialization formats for iss/aud fields
    /// (string key IDs vs byte-array KeyId). Instead, we use the domain's
    /// ContentAccessControl for access control checks and delegate signature verification
    /// to the shared crypto layer.
    ///
    /// `token_str` は受信したままの JWT 文字列。署名検証はワイヤ上のバイト列に
    /// 対して行う(再シリアライズ形とフィールド順序が異なっても正しく検証できる)。
    async fn verify_auth_token(
        &self,
        token_str: &str,
        token: &InfraAuthToken,
        request: &AuthorizationRequest,
        min_valid_issued_at: u64,
        owner_identity: &Identity,
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

        // 4. Ensure issuer is the content owner.
        let owner_key_id = Self::identity_to_key_id(owner_identity);
        if token.payload.iss != owner_key_id {
            anyhow::bail!(
                "AuthToken issuer mismatch: expected owner {}, got {}",
                owner_key_id,
                token.payload.iss
            );
        }

        // 5. Extract owner's public key from key ID and verify AuthToken signature
        //    over the received wire bytes (issue #60: re-serialization must not
        //    participate in signature verification).
        let owner_public_key = Self::get_public_key_from_key_id(&token.payload.iss)?;

        SignatureVerifier::verify_jwt_signature_wire(token_str, &owner_public_key)
            .context("AuthToken signature verification failed")?;

        // 6. Require a request signature to be present.
        //
        // Proof-of-possession 自体は認証層(`verify_caller_signature`)が
        // `{operation}:{resource}:{timestamp}` 形式で検証済みである(全経路が
        // authorize より前に必ず通る)。リプレイ防御は署名内 timestamp の
        // 鮮度チェックに一本化されており、旧実装の jti 単回消費
        // (ノードごとに独立で、SDK の「委譲トークンを 1 個渡して TTL 内で
        // 再利用する」設計と矛盾していた)は廃止した(issue #61)。
        // ここでは「署名なしで authorize が呼ばれる」経路の混入を防ぐ
        // 存在チェックのみを行う。
        if request.request_signature.is_none() {
            anyhow::bail!("Request signature is required for AuthToken-based authorization");
        }

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
        owner_identity: &Identity,
    ) -> Result<bool> {
        // 1. Parse AuthToken
        let auth_token = self.parse_auth_token(token.as_str())?;

        // 2. Verify AuthToken (domain verifier checks signature, expiration, audience,
        //    capability, and access control; request PoP is enforced upstream in
        //    the authentication layer)
        self.verify_auth_token(
            token.as_str(),
            &auth_token,
            request,
            min_valid_issued_at,
            owner_identity,
        )
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
            .check_auth_token_authorization(
                token,
                request,
                policy.min_valid_issued_at(),
                policy.owner(),
            )
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
        async fn get_version(
            &self,
            _genesis_cid: &str,
            _version_cid: &str,
        ) -> Result<Option<Vec<u8>>> {
            unimplemented!()
        }
        async fn get_latest_node_bytes_with_version(
            &self,
            _genesis_cid: &str,
        ) -> Result<Option<(Vec<u8>, String)>> {
            unimplemented!()
        }
        async fn get_version_node_bytes(
            &self,
            _genesis_cid: &str,
            _version_cid: &str,
        ) -> Result<Option<Vec<u8>>> {
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
        let request_sig = bob.sign_request(
            "read",
            content_id.as_str(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

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

        let request_sig = bob.sign_request(
            "read",
            content_id.as_str(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

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
    async fn test_auth_token_authorization_denied_when_issuer_is_not_owner() {
        use crate::infrastructure::auth::test_helpers::TestKeyPair;
        use crate::port::auth_token::AuthToken;

        // Setup
        let alice_owner = TestKeyPair::generate("user", "alice");
        let mallory_attacker = TestKeyPair::generate("user", "mallory");
        let bob_recipient = TestKeyPair::generate("user", "bob");
        let repo = Arc::new(MockContentRepo::new());
        let adapter = UcanAdapter::new(repo.clone());

        let content_id = ContentId::new("test-content-owner-bound".to_string()).unwrap();
        let owner_identity = identity_from_key(&alice_owner);
        let policy = AccessPolicy::new(content_id.clone(), owner_identity);
        repo.policies
            .write()
            .await
            .insert("test-content-owner-bound".to_string(), policy);

        // Mallory (non-owner) self-issues a token for Bob.
        let forged_token = mallory_attacker.create_auth_token(
            &bob_recipient,
            "monas://content/test-content-owner-bound",
            vec![crate::infrastructure::auth::auth_token::CapabilityAction::Write],
            Some(3600),
        );
        let request_sig = bob_recipient.sign_request(
            "write",
            content_id.as_str(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        let token = AuthToken::new(forged_token.to_jwt().unwrap());

        let request = AuthorizationRequest {
            identity: identity_from_key(&bob_recipient),
            resource: content_id,
            capability: AuthCapability::WriteContent,
            token: Some(token),
            request_signature: Some(request_sig),
        };

        let result = adapter.authorize(&request).await.unwrap();
        assert!(
            result.is_denied(),
            "Authorization must be denied when token issuer is not owner"
        );
        assert!(
            result
                .denial_reason()
                .unwrap_or_default()
                .contains("issuer mismatch"),
            "Expected issuer mismatch denial, got: {:?}",
            result
        );
    }

    /// 委譲トークンは TTL 内で何度でも使える(issue #61)。
    /// リプレイ防御は認証層の署名内 timestamp(鮮度窓)が担い、
    /// 旧 jti 単回消費(1 トークン 1 リクエストになり、履歴取得 → データ取得
    /// という通常の read すら成立しなかった)は廃止された。
    #[tokio::test]
    async fn test_auth_token_reusable_across_requests() {
        use crate::infrastructure::auth::test_helpers::TestKeyPair;
        use crate::port::auth_token::AuthToken;

        // Setup
        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");
        let repo = Arc::new(MockContentRepo::new());
        let adapter = UcanAdapter::new(repo.clone());

        let content_id = ContentId::new("test-content-reuse".to_string()).unwrap();
        let alice_identity = identity_from_key(&alice);
        let policy = AccessPolicy::new(content_id.clone(), alice_identity.clone());
        repo.policies
            .write()
            .await
            .insert("test-content-reuse".to_string(), policy);

        // Create a valid token
        let auth_token = alice.create_auth_token(
            &bob,
            "monas://content/test-content-reuse",
            vec![crate::infrastructure::auth::auth_token::CapabilityAction::Read],
            Some(3600),
        );

        let request_sig = bob.sign_request(
            "read",
            content_id.as_str(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        let bob_identity = identity_from_key(&bob);
        let token = AuthToken::new(auth_token.to_jwt().unwrap());

        // 同じトークンで複数リクエスト(履歴取得 → データ取得を模す)が全部通る
        for i in 0..3 {
            let request = AuthorizationRequest {
                identity: bob_identity.clone(),
                resource: content_id.clone(),
                capability: AuthCapability::ReadContent,
                token: Some(token.clone()),
                request_signature: Some(request_sig.clone()),
            };
            let result = adapter.authorize(&request).await.unwrap();
            assert!(
                result.is_granted(),
                "request {} with the same token should be granted, got: {:?}",
                i,
                result
            );
        }
    }

    /// authorize は request_signature の存在を要求する(検証自体は認証層で
    /// 済んでいる前提だが、署名なしで authorize が呼ばれる経路の混入を防ぐ)。
    #[tokio::test]
    async fn test_auth_token_authorization_requires_request_signature() {
        use crate::infrastructure::auth::test_helpers::TestKeyPair;
        use crate::port::auth_token::AuthToken;

        let alice = TestKeyPair::generate("user", "alice");
        let bob = TestKeyPair::generate("user", "bob");
        let repo = Arc::new(MockContentRepo::new());
        let adapter = UcanAdapter::new(repo.clone());

        let content_id = ContentId::new("test-content-no-sig".to_string()).unwrap();
        let alice_identity = identity_from_key(&alice);
        let policy = AccessPolicy::new(content_id.clone(), alice_identity.clone());
        repo.policies
            .write()
            .await
            .insert("test-content-no-sig".to_string(), policy);

        let auth_token = alice.create_auth_token(
            &bob,
            "monas://content/test-content-no-sig",
            vec![crate::infrastructure::auth::auth_token::CapabilityAction::Read],
            Some(3600),
        );

        let request = AuthorizationRequest {
            identity: identity_from_key(&bob),
            resource: content_id,
            capability: AuthCapability::ReadContent,
            token: Some(AuthToken::new(auth_token.to_jwt().unwrap())),
            request_signature: None,
        };
        let result = adapter.authorize(&request).await.unwrap();
        assert!(
            result.is_denied(),
            "authorize without a request signature must be denied"
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

        let request_sig = bob.sign_request(
            "read",
            content_id.as_str(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );

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

        let request_sig = bob.sign_request(
            "read",
            content_id.as_str(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
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
