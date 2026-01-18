//! ShareToken types for State Node verification.
//!
//! This module defines ShareToken types specifically for State Node's verification needs.
//! These types are independent of monas-content to avoid domain coupling.
//!
//! State Node only needs to:
//! 1. Parse JWT format
//! 2. Verify signatures
//! 3. Check capabilities and expiration
//!
//! It does NOT need to create or sign tokens (that's the client's responsibility).

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// ShareToken header containing algorithm and type information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareTokenHeader {
    /// Signing algorithm: "ES256" for P256
    pub alg: String,
    /// Token type: always "JWT"
    pub typ: String,
    /// Version: "1.0"
    pub ver: String,
}

/// Key identifier for issuers and audiences.
///
/// This is typically derived from a public key (e.g., hash of the key bytes).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(Vec<u8>);

impl KeyId {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

/// ShareToken payload containing authorization claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareTokenPayload {
    /// Issuer's KeyId
    pub iss: KeyId,
    /// Audience (recipient's) KeyId
    pub aud: KeyId,
    /// Expiration time (Unix timestamp). None means no expiration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    /// Issued at time (Unix timestamp)
    pub iat: u64,
    /// JWT ID - unique identifier for this token
    pub jti: String,
    /// Capabilities (permissions) granted by this token
    pub att: Vec<Capability>,
    /// Optional facts/metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fct: Option<serde_json::Value>,
}

impl ShareTokenPayload {
    /// Check if the token has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.exp {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();
            now > exp
        } else {
            false
        }
    }

    /// Check if the token has a specific capability action for a resource.
    pub fn has_capability(&self, resource: &str, action: CapabilityAction) -> bool {
        self.att
            .iter()
            .any(|cap| cap.with == resource && cap.can.satisfies(&action))
    }
}

/// A single capability (permission) definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Resource identifier (e.g., "monas://content/{content_id}")
    pub with: String,
    /// Permitted action
    pub can: CapabilityAction,
}

impl Capability {
    /// Extract content_id from the resource URI if it's a content resource.
    pub fn content_id(&self) -> Option<&str> {
        self.with.strip_prefix("monas://content/")
    }
}

/// Action types for capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityAction {
    /// Read permission - can view content
    Read,
    /// Write permission - can modify content (implies Read)
    Write,
    /// Delete permission - can delete content
    Delete,
    /// Share permission - can grant permissions to others
    Share,
    /// Revoke permission - can revoke permissions from others
    Revoke,
    /// Reencrypt permission - can re-encrypt content with new CEK
    Reencrypt,
}

impl CapabilityAction {
    /// Get all actions for the Owner role.
    pub fn owner_actions() -> Vec<Self> {
        vec![
            Self::Read,
            Self::Write,
            Self::Delete,
            Self::Share,
            Self::Revoke,
            Self::Reencrypt,
        ]
    }

    /// Get all actions for the Editor role.
    pub fn editor_actions() -> Vec<Self> {
        vec![Self::Read, Self::Write]
    }

    /// Get all actions for the Viewer role.
    pub fn viewer_actions() -> Vec<Self> {
        vec![Self::Read]
    }

    /// Check if this action satisfies the required action.
    /// Write satisfies Read.
    pub fn satisfies(&self, required: &CapabilityAction) -> bool {
        match (self, required) {
            // Write satisfies Read and Write
            (CapabilityAction::Write, CapabilityAction::Read) => true,
            // Same action satisfies itself
            (a, b) if a == b => true,
            // Everything else is not satisfied
            _ => false,
        }
    }
}

/// Errors that can occur during ShareToken parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareTokenParseError {
    /// Invalid JWT format
    InvalidFormat(String),
    /// Base64 decoding error
    Base64DecodeError(String),
    /// JSON parsing error
    JsonError(String),
}

impl std::fmt::Display for ShareTokenParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShareTokenParseError::InvalidFormat(msg) => write!(f, "Invalid token format: {}", msg),
            ShareTokenParseError::Base64DecodeError(msg) => {
                write!(f, "Base64 decode error: {}", msg)
            }
            ShareTokenParseError::JsonError(msg) => write!(f, "JSON error: {}", msg),
        }
    }
}

impl std::error::Error for ShareTokenParseError {}

/// Parsed ShareToken for verification.
///
/// This struct represents a parsed JWT token. State Node uses this for verification only.
#[derive(Debug, Clone)]
pub struct ShareToken {
    /// Token header
    pub header: ShareTokenHeader,
    /// Token payload
    pub payload: ShareTokenPayload,
    /// Raw signature bytes
    pub signature: Vec<u8>,
    /// The signing input (header.payload in base64) - cached for verification
    signing_input: Vec<u8>,
}

impl ShareToken {
    /// Parse a token from JWT format.
    pub fn from_jwt(jwt: &str) -> Result<Self, ShareTokenParseError> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(ShareTokenParseError::InvalidFormat(
                "JWT must have 3 parts separated by '.'".to_string(),
            ));
        }

        let header_bytes = base64_url_decode(parts[0])?;
        let payload_bytes = base64_url_decode(parts[1])?;
        let signature = base64_url_decode(parts[2])?;

        let header: ShareTokenHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| ShareTokenParseError::JsonError(e.to_string()))?;
        let payload: ShareTokenPayload = serde_json::from_slice(&payload_bytes)
            .map_err(|e| ShareTokenParseError::JsonError(e.to_string()))?;

        // Cache the signing input for verification
        let signing_input = format!("{}.{}", parts[0], parts[1]).into_bytes();

        Ok(Self {
            header,
            payload,
            signature,
            signing_input,
        })
    }

    /// Get the signing input bytes for signature verification.
    pub fn signing_input_bytes(&self) -> &[u8] {
        &self.signing_input
    }

    /// Get the signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// Base64 URL-safe decoding.
fn base64_url_decode(data: &str) -> Result<Vec<u8>, ShareTokenParseError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| ShareTokenParseError::Base64DecodeError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_action_satisfies() {
        assert!(CapabilityAction::Read.satisfies(&CapabilityAction::Read));
        assert!(CapabilityAction::Write.satisfies(&CapabilityAction::Write));
        assert!(CapabilityAction::Write.satisfies(&CapabilityAction::Read));
        assert!(!CapabilityAction::Read.satisfies(&CapabilityAction::Write));
        assert!(!CapabilityAction::Delete.satisfies(&CapabilityAction::Read));
    }

    #[test]
    fn capability_action_roles() {
        let owner = CapabilityAction::owner_actions();
        assert_eq!(owner.len(), 6);
        assert!(owner.contains(&CapabilityAction::Read));
        assert!(owner.contains(&CapabilityAction::Write));
        assert!(owner.contains(&CapabilityAction::Delete));
        assert!(owner.contains(&CapabilityAction::Share));
        assert!(owner.contains(&CapabilityAction::Revoke));
        assert!(owner.contains(&CapabilityAction::Reencrypt));

        let editor = CapabilityAction::editor_actions();
        assert_eq!(editor.len(), 2);
        assert!(editor.contains(&CapabilityAction::Read));
        assert!(editor.contains(&CapabilityAction::Write));

        let viewer = CapabilityAction::viewer_actions();
        assert_eq!(viewer.len(), 1);
        assert!(viewer.contains(&CapabilityAction::Read));
    }

    #[test]
    fn key_id_display() {
        let key_id = KeyId::new(vec![0x01, 0x02, 0x03]);
        assert_eq!(format!("{}", key_id), "010203");
    }

    #[test]
    fn parse_invalid_jwt_format() {
        let result = ShareToken::from_jwt("invalid");
        assert!(matches!(
            result,
            Err(ShareTokenParseError::InvalidFormat(_))
        ));

        let result = ShareToken::from_jwt("a.b");
        assert!(matches!(
            result,
            Err(ShareTokenParseError::InvalidFormat(_))
        ));
    }
}
