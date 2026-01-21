//! UCAN authorization adapter.
//!
//! This adapter implements the Anti-Corruption Layer pattern.
//! It translates between State Node's capability model and UCAN's capability model.

use crate::domain::auth_capability::AuthCapability;
use crate::port::auth_token::AuthToken;
use crate::port::authorization_service::{
    AuthorizationRequest, AuthorizationResult, AuthorizationService,
};
use crate::port::persistence::PersistentAccessPolicyRepository;
use anyhow::{Context, Result};
use async_trait::async_trait;
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
}

impl<R> UcanAdapter<R>
where
    R: PersistentAccessPolicyRepository,
{
    pub fn new(policy_repo: Arc<RwLock<R>>) -> Self {
        Self { policy_repo }
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

    /// Parse UCAN token (simplified - would use ucan-rs in production)
    fn parse_ucan(&self, token: &str) -> Result<UcanToken> {
        // In production, use proper UCAN parsing library
        // For now, simplified structure

        if token.is_empty() {
            return Err(anyhow::anyhow!("Empty UCAN token"));
        }

        // TODO: Integrate with monas-ucan crate for proper parsing
        Ok(UcanToken {
            raw: token.to_string(),
        })
    }

    /// Verify UCAN token signature and proof chain
    fn verify_ucan(&self, ucan: &UcanToken) -> Result<()> {
        // In production:
        // 1. Verify signature
        // 2. Verify proof chain
        // 3. Check expiration
        // 4. Verify issuer/audience

        // TODO: Integrate with monas-ucan crate for proper verification

        if ucan.raw.is_empty() {
            return Err(anyhow::anyhow!("Invalid UCAN"));
        }

        Ok(())
    }

    /// Check if UCAN grants a specific capability for a resource
    fn check_ucan_capability(
        &self,
        ucan: &UcanToken,
        resource: &str,
        capability: &AuthCapability,
    ) -> Result<bool> {
        let ucan_cap = Self::map_capability_to_ucan(capability);

        // In production, properly parse UCAN capabilities
        // For now, simplified string matching

        // TODO: Integrate with monas-ucan crate for proper capability checking

        Ok(ucan.raw.contains(&format!("{}:{}", resource, ucan_cap)))
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

        // 4. Check UCAN token if provided (delegated access)
        if let Some(token) = &request.token {
            match self.check_ucan_authorization(token, request).await {
                Ok(true) => return Ok(AuthorizationResult::Granted),
                Ok(false) => {
                    return Ok(AuthorizationResult::Denied {
                        reason: "UCAN token does not grant required capability".to_string(),
                    });
                }
                Err(e) => {
                    return Ok(AuthorizationResult::Denied {
                        reason: format!("UCAN verification failed: {}", e),
                    });
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
            },
            AuthorizationRequest {
                identity: owner.clone(),
                resource: content_id.clone(),
                capability: AuthCapability::WriteContent,
                token: None,
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
}
