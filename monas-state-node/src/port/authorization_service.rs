//! Authorization service abstraction.
//!
//! This trait abstracts away the actual authorization mechanism.
//! Infrastructure layer provides concrete implementations (UCAN, RBAC, etc.).

use crate::domain::auth_capability::AuthCapability;
use crate::domain::identity::Identity;
use crate::domain::value_objects::ContentId;
use crate::port::auth_token::AuthToken;
use anyhow::Result;
use async_trait::async_trait;

/// Authorization request
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// The identity requesting access
    pub identity: Identity,

    /// The resource being accessed
    pub resource: ContentId,

    /// The capability being requested
    pub capability: AuthCapability,

    /// Optional authorization token (e.g., delegated UCAN)
    pub token: Option<AuthToken>,

    /// Optional request signature for verifying the request sender
    /// This is used to verify that the requester possesses the private key
    /// corresponding to the audience (aud) in the ShareToken
    pub request_signature: Option<Vec<u8>>,
}

/// Authorization result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationResult {
    /// Access is granted
    Granted,

    /// Access is denied
    Denied { reason: String },

    /// Authorization cannot be determined (e.g., resource not found)
    Unknown,
}

impl AuthorizationResult {
    /// Check if access is granted
    pub fn is_granted(&self) -> bool {
        matches!(self, AuthorizationResult::Granted)
    }

    /// Check if access is denied
    pub fn is_denied(&self) -> bool {
        matches!(self, AuthorizationResult::Denied { .. })
    }

    /// Check if authorization is unknown
    pub fn is_unknown(&self) -> bool {
        matches!(self, AuthorizationResult::Unknown)
    }

    /// Get the denial reason if denied
    pub fn denial_reason(&self) -> Option<&str> {
        match self {
            AuthorizationResult::Denied { reason } => Some(reason),
            _ => None,
        }
    }
}

/// Authorization service abstraction
///
/// This trait abstracts away the actual authorization mechanism.
/// Infrastructure layer provides concrete implementations (UCAN, RBAC, etc.).
#[async_trait]
pub trait AuthorizationService: Send + Sync {
    /// Check if an identity is authorized to perform a capability on a resource
    ///
    /// # Errors
    ///
    /// Returns an error if the authorization check cannot be performed
    /// (e.g., repository failure, network error).
    /// Access denial is NOT an error - it returns Ok(AuthorizationResult::Denied).
    async fn authorize(&self, request: &AuthorizationRequest) -> Result<AuthorizationResult>;

    /// Batch authorization check for multiple capabilities
    ///
    /// This is useful for checking multiple permissions at once.
    /// The default implementation checks each request individually.
    ///
    /// # Errors
    ///
    /// Returns an error if any authorization check cannot be performed.
    async fn authorize_batch(
        &self,
        requests: &[AuthorizationRequest],
    ) -> Result<Vec<AuthorizationResult>> {
        // Default implementation: check each request individually
        let mut results = Vec::new();
        for request in requests {
            results.push(self.authorize(request).await?);
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::access_policy::AccessPolicy;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Mock authorization service for testing
    struct MockAuthorizationService {
        policies: Arc<RwLock<HashMap<String, AccessPolicy>>>,
    }

    impl MockAuthorizationService {
        fn new() -> Self {
            Self {
                policies: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        async fn add_policy(&self, policy: AccessPolicy) {
            self.policies
                .write()
                .await
                .insert(policy.content_id().as_str().to_string(), policy);
        }
    }

    #[async_trait]
    impl AuthorizationService for MockAuthorizationService {
        async fn authorize(&self, request: &AuthorizationRequest) -> Result<AuthorizationResult> {
            let policies = self.policies.read().await;
            let policy = policies.get(request.resource.as_str());

            match policy {
                Some(policy) => {
                    if policy.has_capability(&request.identity, &request.capability) {
                        Ok(AuthorizationResult::Granted)
                    } else {
                        Ok(AuthorizationResult::Denied {
                            reason: "Identity does not have required capability".to_string(),
                        })
                    }
                }
                None => Ok(AuthorizationResult::Unknown),
            }
        }
    }

    #[tokio::test]
    async fn test_authorization_result_is_granted() {
        assert!(AuthorizationResult::Granted.is_granted());
        assert!(!AuthorizationResult::Denied {
            reason: "test".to_string()
        }
        .is_granted());
        assert!(!AuthorizationResult::Unknown.is_granted());
    }

    #[tokio::test]
    async fn test_authorization_result_is_denied() {
        assert!(AuthorizationResult::Denied {
            reason: "test".to_string()
        }
        .is_denied());
        assert!(!AuthorizationResult::Granted.is_denied());
        assert!(!AuthorizationResult::Unknown.is_denied());
    }

    #[tokio::test]
    async fn test_authorization_result_denial_reason() {
        let result = AuthorizationResult::Denied {
            reason: "Access denied".to_string(),
        };
        assert_eq!(result.denial_reason(), Some("Access denied"));

        assert_eq!(AuthorizationResult::Granted.denial_reason(), None);
    }

    #[tokio::test]
    async fn test_mock_authorization_service() {
        let service = MockAuthorizationService::new();
        let content_id = ContentId::new("test-content".to_string()).unwrap();
        let alice = Identity::user("alice".to_string()).unwrap();
        let bob = Identity::user("bob".to_string()).unwrap();

        // Create policy with alice as owner
        let policy = AccessPolicy::new(content_id.clone(), alice.clone());
        service.add_policy(policy).await;

        // Alice (owner) should have access
        let request = AuthorizationRequest {
            identity: alice.clone(),
            resource: content_id.clone(),
            capability: AuthCapability::ReadContent,
            token: None,
            request_signature: None,
        };
        let result = service.authorize(&request).await.unwrap();
        assert!(result.is_granted());

        // Bob should not have access
        let request = AuthorizationRequest {
            identity: bob,
            resource: content_id,
            capability: AuthCapability::ReadContent,
            token: None,
            request_signature: None,
        };
        let result = service.authorize(&request).await.unwrap();
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_authorize_batch() {
        let service = MockAuthorizationService::new();
        let content_id = ContentId::new("test-content".to_string()).unwrap();
        let alice = Identity::user("alice".to_string()).unwrap();

        let policy = AccessPolicy::new(content_id.clone(), alice.clone());
        service.add_policy(policy).await;

        let requests = vec![
            AuthorizationRequest {
                identity: alice.clone(),
                resource: content_id.clone(),
                capability: AuthCapability::ReadContent,
                token: None,
                request_signature: None,
            },
            AuthorizationRequest {
                identity: alice.clone(),
                resource: content_id.clone(),
                capability: AuthCapability::WriteContent,
                token: None,
                request_signature: None,
            },
        ];

        let results = service.authorize_batch(&requests).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_granted());
        assert!(results[1].is_granted());
    }
}
