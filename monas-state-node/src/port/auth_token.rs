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

/// Domain separation tag for request signatures. Bumping this invalidates
/// every previously produced signature, which is what we want if the message
/// structure ever changes.
pub const REQUEST_SIGNATURE_DOMAIN: &str = "monas-request-v1";

impl RequestMetadata {
    /// Create the signing message for a request signature.
    ///
    /// Every request signature — with or without a body, JWT or not — commits
    /// to the same fields, so a signature captured for one request cannot be
    /// replayed against a different operation or resource (issue: review
    /// finding "body signature lacks operation/resource").
    ///
    /// Format (length-prefixed to keep the concatenation unambiguous):
    ///
    /// ```text
    /// monas-request-v1:<len>:<operation>:<len>:<resource>:<timestamp>:<len>:<body_digest_hex>
    /// ```
    ///
    /// `body_digest_hex` is `sha256(body)` for requests that carry a body, and
    /// the empty string otherwise. Lengths prevent a crafted operation or
    /// resource containing `:` from shifting the field boundaries.
    pub fn signing_message(&self) -> String {
        self.signing_message_with_body_digest("")
    }

    /// Same as [`Self::signing_message`], but committing to a body digest.
    pub fn signing_message_with_body_digest(&self, body_digest_hex: &str) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            REQUEST_SIGNATURE_DOMAIN,
            self.operation.len(),
            self.operation,
            self.resource.len(),
            self.resource,
            self.timestamp,
            body_digest_hex.len(),
            body_digest_hex,
        )
    }
}

/// Canonical byte encoding of the `add-members` request body for signing.
///
/// `count` controls how many nodes get added to a content network, so it must
/// be covered by the request signature — otherwise the same token, signature
/// and timestamp can be replayed with a different `count` (it is clamped to
/// `max_add_member_count`, but raising `1` to the clamp is still a mutation the
/// caller never authorized).
///
/// The HTTP body itself is not signable as-is: it is JSON, so whitespace and
/// key order vary between clients producing different digests for the same
/// request. Instead both sides derive the same canonical bytes from the parsed
/// value. Keep the tag so a future field cannot collide with this encoding.
pub fn add_members_signing_body(count: usize) -> Vec<u8> {
    format!("add-members:count={count}").into_bytes()
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

    /// 署名対象が operation / resource / timestamp / body digest すべてに
    /// 束縛されることの回帰テスト。ここが緩むと、ある content 向けに
    /// 取得した署名を別 content や別 operation へ転用できてしまう。
    #[test]
    fn signing_message_binds_operation_resource_and_timestamp() {
        let base = RequestMetadata {
            timestamp: 42,
            operation: "update".to_string(),
            resource: "content-1".to_string(),
        };
        let msg = base.signing_message();
        assert!(msg.starts_with("monas-request-v1:"), "msg={msg}");

        let other_op = RequestMetadata {
            operation: "create".to_string(),
            ..base.clone()
        };
        let other_resource = RequestMetadata {
            resource: "content-2".to_string(),
            ..base.clone()
        };
        let other_ts = RequestMetadata {
            timestamp: 43,
            ..base.clone()
        };
        assert_ne!(msg, other_op.signing_message());
        assert_ne!(msg, other_resource.signing_message());
        assert_ne!(msg, other_ts.signing_message());
    }

    #[test]
    fn signing_message_with_body_digest_stays_bound_to_operation_and_resource() {
        let update_c1 = RequestMetadata {
            timestamp: 42,
            operation: "update".to_string(),
            resource: "content-1".to_string(),
        };
        let digest = "aa".repeat(32);
        let signed = update_c1.signing_message_with_body_digest(&digest);

        // 同じ body でも別 resource / 別 operation なら署名対象が変わる
        let update_c2 = RequestMetadata {
            resource: "content-2".to_string(),
            ..update_c1.clone()
        };
        let create_c1 = RequestMetadata {
            operation: "create".to_string(),
            ..update_c1.clone()
        };
        assert_ne!(signed, update_c2.signing_message_with_body_digest(&digest));
        assert_ne!(signed, create_c1.signing_message_with_body_digest(&digest));

        // body が変われば署名対象も変わる / body 有無も区別される
        assert_ne!(
            signed,
            update_c1.signing_message_with_body_digest(&"bb".repeat(32))
        );
        assert_ne!(signed, update_c1.signing_message());
    }

    /// count ごとに異なるバイト列になること。ここが衝突すると、
    /// ある count 用の署名を別の count へ転用できてしまう。
    #[test]
    fn add_members_signing_body_is_distinct_per_count() {
        let bodies: Vec<Vec<u8>> = [0usize, 1, 2, 10, 100]
            .iter()
            .map(|c| add_members_signing_body(*c))
            .collect();
        for (i, a) in bodies.iter().enumerate() {
            for b in bodies.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
        assert_eq!(add_members_signing_body(3), b"add-members:count=3".to_vec());
    }

    /// 長さ前置により、区切り文字を含む値でもフィールド境界がずれない。
    #[test]
    fn signing_message_is_unambiguous_with_colons() {
        let a = RequestMetadata {
            timestamp: 1,
            operation: "a".to_string(),
            resource: "b:c".to_string(),
        };
        let b = RequestMetadata {
            timestamp: 1,
            operation: "a:b".to_string(),
            resource: "c".to_string(),
        };
        assert_ne!(a.signing_message(), b.signing_message());
    }
}
