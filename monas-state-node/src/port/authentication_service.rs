//! Authentication service abstraction.
//!
//! This trait abstracts away the actual authentication mechanism.
//! Infrastructure layer provides concrete implementations.

use crate::domain::identity::Identity;
use crate::port::auth_token::{AuthContext, AuthToken};
use anyhow::Result;
use async_trait::async_trait;

/// Authentication service abstraction
///
/// This trait abstracts away the actual authentication mechanism.
/// Infrastructure layer provides concrete implementations.
#[async_trait]
pub trait AuthenticationService: Send + Sync {
    /// Verify an authentication token and return the identity
    ///
    /// # Arguments
    /// * `token` - The authentication token to verify
    /// * `context` - Optional authentication context (e.g., content_id for signature verification)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The token is invalid or malformed
    /// - The token has expired
    /// - The token signature is invalid
    /// - The identity cannot be resolved
    async fn authenticate(
        &self,
        token: &AuthToken,
        context: Option<&AuthContext>,
    ) -> Result<Identity>;

    /// Check if a token is still valid (not expired)
    ///
    /// # Errors
    ///
    /// Returns an error if the token cannot be parsed or validated.
    async fn is_valid(&self, token: &AuthToken) -> Result<bool>;

    /// Get the issuer of a token (if applicable)
    ///
    /// This is optional and may not be supported by all implementations.
    /// Returns None if the implementation doesn't support issuer identification
    /// or if the token doesn't have an issuer.
    ///
    /// # Errors
    ///
    /// Returns an error if the token cannot be parsed.
    async fn get_issuer(&self, token: &AuthToken) -> Result<Option<Identity>> {
        // Default implementation returns None
        let _ = token;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock implementation for testing
    struct MockAuthService;

    #[async_trait]
    impl AuthenticationService for MockAuthService {
        async fn authenticate(
            &self,
            token: &AuthToken,
            _context: Option<&AuthContext>,
        ) -> Result<Identity> {
            // Simple mock: treat token as identity ID
            Identity::user(token.as_str().to_string())
                .map_err(|e| anyhow::anyhow!("Failed to create identity: {}", e))
        }

        async fn is_valid(&self, token: &AuthToken) -> Result<bool> {
            Ok(!token.is_empty())
        }
    }

    #[tokio::test]
    async fn test_mock_authentication_service() {
        let service = MockAuthService;
        let token = AuthToken::new("alice".to_string());

        let identity = service.authenticate(&token, None).await.unwrap();
        assert_eq!(identity.id(), "alice");
        assert!(identity.is_user());
    }

    #[tokio::test]
    async fn test_mock_is_valid() {
        let service = MockAuthService;

        let valid_token = AuthToken::new("alice".to_string());
        assert!(service.is_valid(&valid_token).await.unwrap());

        let invalid_token = AuthToken::new("".to_string());
        assert!(!service.is_valid(&invalid_token).await.unwrap());
    }

    #[tokio::test]
    async fn test_default_get_issuer() {
        let service = MockAuthService;
        let token = AuthToken::new("alice".to_string());

        let issuer = service.get_issuer(&token).await.unwrap();
        assert!(issuer.is_none());
    }
}
