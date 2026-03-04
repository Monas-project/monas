//! AuthToken implementation for content sharing authorization.
//!
//! This module implements AuthToken, a JWT-based token for delegating
//! content access capabilities. AuthTokens follow the UCAN-inspired design
//! with P256 (ES256) signature verification.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

/// AuthToken のヘッダー
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthTokenHeader {
    /// Algorithm: "ES256" (P256 only)
    pub alg: String,
    /// Type: "JWT"
    #[serde(rename = "typ")]
    pub token_type: String,
    /// Version: "1.0"
    pub ver: String,
}

impl Default for AuthTokenHeader {
    fn default() -> Self {
        Self {
            alg: "ES256".to_string(),
            token_type: "JWT".to_string(),
            ver: "1.0".to_string(),
        }
    }
}

/// AuthToken のペイロード
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthTokenPayload {
    /// Issuer: 発行者のKeyId（"monas:type:id" 形式、例: "monas:user:alice"）
    pub iss: String,
    /// Audience: 受信者のKeyId（"monas:type:id" 形式、例: "monas:user:bob"）
    pub aud: String,
    /// Expiration: 有効期限（Unix timestamp）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Issued At: 発行日時（Unix timestamp）
    pub iat: u64,
    /// JWT ID: 一意識別子（UUID v4）
    pub jti: String,
    /// Attenuations: 権限リスト
    pub att: Vec<Capability>,
    /// Facts: 事実情報（オプション）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fct: Option<serde_json::Value>,
}

/// 単一の権限定義
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    /// Resource: リソース "monas://content/{id}"
    pub with: String,
    /// Action: アクション
    pub can: CapabilityAction,
}

/// アクション種別（AuthToken用）
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CapabilityAction {
    Read,
    Write,
    Delete,
    Share,
    Revoke,
    Reencrypt,
}

impl CapabilityAction {
    /// Convert from AuthCapability to CapabilityAction
    pub fn from_auth_capability(cap: &crate::domain::auth_capability::AuthCapability) -> Self {
        use crate::domain::auth_capability::AuthCapability;
        match cap {
            AuthCapability::ReadContent | AuthCapability::ReadMetadata => Self::Read,
            AuthCapability::WriteContent => Self::Write,
            AuthCapability::DeleteContent => Self::Delete,
            AuthCapability::ShareContent => Self::Share,
            AuthCapability::RevokeAccess => Self::Revoke,
            AuthCapability::ManageMembers => Self::Share, // ManageMembersはShareに相当
        }
    }

    /// Convert from CapabilityAction to AuthCapability
    pub fn to_auth_capability(&self) -> crate::domain::auth_capability::AuthCapability {
        use crate::domain::auth_capability::AuthCapability;
        match self {
            Self::Read => AuthCapability::ReadContent,
            Self::Write => AuthCapability::WriteContent,
            Self::Delete => AuthCapability::DeleteContent,
            Self::Share => AuthCapability::ShareContent,
            Self::Revoke => AuthCapability::RevokeAccess,
            Self::Reencrypt => AuthCapability::ManageMembers, // 暫定マッピング
        }
    }

    /// Check if this action satisfies the required action.
    ///
    /// Capability hierarchy:
    /// - Delete → Write, Read
    /// - Write → Read
    /// - Share → Read
    /// - Revoke → Share, Read
    pub fn satisfies(&self, required: &CapabilityAction) -> bool {
        match (self, required) {
            (CapabilityAction::Write, CapabilityAction::Read) => true,
            (CapabilityAction::Delete, CapabilityAction::Write) => true,
            (CapabilityAction::Delete, CapabilityAction::Read) => true,
            (CapabilityAction::Share, CapabilityAction::Read) => true,
            (CapabilityAction::Revoke, CapabilityAction::Share) => true,
            (CapabilityAction::Revoke, CapabilityAction::Read) => true,
            (a, b) if a == b => true,
            _ => false,
        }
    }
}

/// AuthToken 本体
#[derive(Debug, Clone)]
pub struct AuthToken {
    pub header: AuthTokenHeader,
    pub payload: AuthTokenPayload,
    pub signature: Vec<u8>, // 署名（バイナリ形式）
}

impl AuthToken {
    /// Create a new AuthToken with default header
    pub fn new(payload: AuthTokenPayload, signature: Vec<u8>) -> Self {
        Self {
            header: AuthTokenHeader::default(),
            payload,
            signature,
        }
    }

    /// JWT文字列からパース
    ///
    /// # Format
    /// `<base64url(header)>.<base64url(payload)>.<base64url(signature)>`
    pub fn from_jwt(jwt: &str) -> Result<Self> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            anyhow::bail!("Invalid JWT format: expected 3 parts, got {}", parts.len());
        }

        // Base64url decode
        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .context("Failed to decode header")?;
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .context("Failed to decode payload")?;
        let signature = URL_SAFE_NO_PAD
            .decode(parts[2])
            .context("Failed to decode signature")?;

        // JSON parse
        let header: AuthTokenHeader =
            serde_json::from_slice(&header_bytes).context("Failed to parse header JSON")?;
        let payload: AuthTokenPayload =
            serde_json::from_slice(&payload_bytes).context("Failed to parse payload JSON")?;

        // Validate algorithm
        if header.alg != "ES256" {
            anyhow::bail!("Unsupported algorithm: {}", header.alg);
        }

        Ok(Self {
            header,
            payload,
            signature,
        })
    }

    /// JWT文字列にエンコード
    pub fn to_jwt(&self) -> Result<String> {
        // JSON serialize
        let header_json = serde_json::to_string(&self.header)?;
        let payload_json = serde_json::to_string(&self.payload)?;

        // Base64url encode
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signature_b64 = URL_SAFE_NO_PAD.encode(&self.signature);

        Ok(format!("{}.{}.{}", header_b64, payload_b64, signature_b64))
    }

    /// 署名対象メッセージ（header.payload）を取得
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        let header_json = serde_json::to_string(&self.header)?;
        let payload_json = serde_json::to_string(&self.payload)?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        Ok(format!("{}.{}", header_b64, payload_b64).into_bytes())
    }

    /// Check if the token has expired
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.payload.exp {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now >= exp
        } else {
            false
        }
    }

    /// Check if the token is invalidated by version
    pub fn is_invalidated(&self, min_valid_issued_at: Option<u64>) -> bool {
        if let Some(min) = min_valid_issued_at {
            self.payload.iat < min
        } else {
            false
        }
    }

    /// Check if the token grants a specific capability for a resource
    pub fn has_capability(&self, resource: &str, capability: &CapabilityAction) -> bool {
        self.payload
            .att
            .iter()
            .any(|cap| cap.with == resource && cap.can.satisfies(capability))
    }
}

/// AuthToken エラー型
#[derive(Debug, thiserror::Error)]
pub enum AuthTokenError {
    #[error("Invalid JWT format: {0}")]
    InvalidFormat(String),

    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Token expired (exp: {exp}, now: {now})")]
    Expired { exp: u64, now: u64 },

    #[error("Token invalidated (iat: {iat}, min_valid: {min_valid})")]
    Invalidated { iat: u64, min_valid: u64 },

    #[error("Audience mismatch (expected: {expected}, got: {got})")]
    AudienceMismatch { expected: String, got: String },

    #[error("Insufficient capability (required: {required:?}, granted: {granted:?})")]
    InsufficientCapability {
        required: CapabilityAction,
        granted: Vec<CapabilityAction>,
    },

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_token_header_default() {
        let header = AuthTokenHeader::default();
        assert_eq!(header.alg, "ES256");
        assert_eq!(header.token_type, "JWT");
        assert_eq!(header.ver, "1.0");
    }

    #[test]
    fn test_capability_action_conversion() {
        use crate::domain::auth_capability::AuthCapability;

        let auth_cap = AuthCapability::ReadContent;
        let share_cap = CapabilityAction::from_auth_capability(&auth_cap);
        assert_eq!(share_cap, CapabilityAction::Read);

        let converted_back = share_cap.to_auth_capability();
        assert_eq!(converted_back, AuthCapability::ReadContent);
    }

    #[test]
    fn test_auth_token_jwt_roundtrip() {
        let payload = AuthTokenPayload {
            iss: "monas:user:alice".to_string(),
            aud: "monas:user:bob".to_string(),
            exp: Some(1706744400),
            iat: 1706740800,
            jti: "550e61f7-98e0-45c3-b28c-1f8d72a6e6c4".to_string(),
            att: vec![Capability {
                with: "monas://content/abc123".to_string(),
                can: CapabilityAction::Read,
            }],
            fct: None,
        };

        let token = AuthToken::new(payload.clone(), vec![1, 2, 3, 4]);
        let jwt = token.to_jwt().unwrap();

        let parsed = AuthToken::from_jwt(&jwt).unwrap();
        assert_eq!(parsed.header.alg, "ES256");
        assert_eq!(parsed.payload.iss, payload.iss);
        assert_eq!(parsed.payload.aud, payload.aud);
        assert_eq!(parsed.signature, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_auth_token_invalid_jwt_format() {
        let result = AuthToken::from_jwt("invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expected 3 parts"));
    }

    #[test]
    fn test_auth_token_signing_message() {
        let payload = AuthTokenPayload {
            iss: "monas:user:alice".to_string(),
            aud: "monas:user:bob".to_string(),
            exp: None,
            iat: 1706740800,
            jti: "test-id".to_string(),
            att: vec![],
            fct: None,
        };

        let token = AuthToken::new(payload, vec![]);
        let message = token.signing_message().unwrap();
        assert!(!message.is_empty());
    }

    #[test]
    fn test_auth_token_has_capability() {
        let payload = AuthTokenPayload {
            iss: "monas:user:alice".to_string(),
            aud: "monas:user:bob".to_string(),
            exp: None,
            iat: 1706740800,
            jti: "test-id".to_string(),
            att: vec![
                Capability {
                    with: "monas://content/abc123".to_string(),
                    can: CapabilityAction::Read,
                },
                Capability {
                    with: "monas://content/def456".to_string(),
                    can: CapabilityAction::Write,
                },
            ],
            fct: None,
        };

        let token = AuthToken::new(payload, vec![]);
        assert!(token.has_capability("monas://content/abc123", &CapabilityAction::Read));
        assert!(token.has_capability("monas://content/def456", &CapabilityAction::Write));
        assert!(!token.has_capability("monas://content/abc123", &CapabilityAction::Write));
        assert!(!token.has_capability("monas://content/xyz789", &CapabilityAction::Read));
    }
}
