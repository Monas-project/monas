//! Authentication token types.
//!
//! This module provides an opaque authentication token type for the State Node domain.
//! The actual token format (JWT, UCAN, etc.) is hidden from the domain layer.

use serde::{Deserialize, Serialize};

/// Authentication token (opaque type in domain)
///
/// The actual format (JWT, UCAN, etc.) is hidden from the domain.
/// This is just an opaque handle that the domain can pass around.
///
/// The infrastructure layer is responsible for parsing and validating
/// the actual token format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthToken {
    raw: String,
}

/// Authentication context for signature verification
///
/// Contains the context information needed to verify signatures and
/// look up public keys from the content network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthContext {
    /// Content ID being accessed
    pub content_id: String,
    /// Operation being performed
    pub operation: String,
}

impl AuthContext {
    /// Create a new authentication context
    pub fn new(content_id: String, operation: String) -> Self {
        Self {
            content_id,
            operation,
        }
    }
}

/// Request metadata for replay attack prevention
///
/// This structure contains timestamp information to prevent replay attacks.
/// It is used in conjunction with request signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    /// Unix timestamp (seconds since epoch)
    pub timestamp: u64,
    /// Operation being performed
    pub operation: String,
    /// Resource being accessed
    pub resource: String,
}

impl RequestMetadata {
    /// Create signing message for request signature
    /// Format: "{operation}:{resource}:{timestamp}"
    pub fn signing_message(&self) -> String {
        format!("{}:{}:{}", self.operation, self.resource, self.timestamp)
    }
}

impl AuthToken {
    /// Create a new authentication token
    pub fn new(raw: String) -> Self {
        Self { raw }
    }

    /// Get the raw token string
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Check if the token is empty
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

impl From<String> for AuthToken {
    fn from(raw: String) -> Self {
        Self { raw }
    }
}

impl From<&str> for AuthToken {
    fn from(raw: &str) -> Self {
        Self {
            raw: raw.to_string(),
        }
    }
}

impl AsRef<str> for AuthToken {
    fn as_ref(&self) -> &str {
        &self.raw
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_token_creation() {
        let token = AuthToken::new("test-token".to_string());
        assert_eq!(token.as_str(), "test-token");
        assert!(!token.is_empty());
    }

    #[test]
    fn test_auth_token_from_string() {
        let token: AuthToken = "test-token".to_string().into();
        assert_eq!(token.as_str(), "test-token");
    }

    #[test]
    fn test_auth_token_from_str() {
        let token: AuthToken = "test-token".into();
        assert_eq!(token.as_str(), "test-token");
    }

    #[test]
    fn test_auth_token_empty() {
        let token = AuthToken::new("".to_string());
        assert!(token.is_empty());
    }

    #[test]
    fn test_auth_token_equality() {
        let token1 = AuthToken::new("token1".to_string());
        let token2 = AuthToken::new("token1".to_string());
        let token3 = AuthToken::new("token2".to_string());

        assert_eq!(token1, token2);
        assert_ne!(token1, token3);
    }
}
