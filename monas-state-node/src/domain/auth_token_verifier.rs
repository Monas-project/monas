//! AuthToken verification service for State Nodes.
//!
//! This module provides verification logic for AuthTokens (UCAN-based authorization).
//! State Nodes use this to validate incoming requests and ensure proper authorization.

use crate::domain::access_control::ContentAccessControl;
use crate::domain::auth_token::{
    AuthToken, AuthTokenParseError, AuthTokenPayload, CapabilityAction, KeyId,
};
use crate::infrastructure::crypto::{verify_p256_signature, SignatureVerifyError};
use thiserror::Error;

/// Errors that can occur during AuthToken verification.
#[derive(Debug, Error)]
pub enum AuthTokenVerifyError {
    #[error("Token parsing error: {0}")]
    ParseError(#[from] AuthTokenParseError),

    #[error("Signature verification failed: {0}")]
    SignatureError(#[from] SignatureVerifyError),

    #[error("Token has expired")]
    Expired,

    #[error("Token is missing required expiration (exp) claim")]
    MissingExpiration,

    #[error("Token expiration is too far in the future (max 24 hours)")]
    ExpirationTooFar,

    #[error("Token has been invalidated (issued_at < min_valid_issued_at)")]
    Invalidated,

    #[error("Audience mismatch: expected {expected}, got {actual}")]
    AudienceMismatch { expected: String, actual: String },

    #[error("Insufficient capability: required {required:?} for resource {resource}")]
    InsufficientCapability {
        required: CapabilityAction,
        resource: String,
    },

    #[error("Content ID mismatch: expected {expected}, got {actual}")]
    ContentIdMismatch { expected: String, actual: String },

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Issuer public key not found")]
    IssuerPublicKeyNotFound,
}

/// Result of AuthToken verification.
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    /// The verified token's payload
    pub payload: AuthTokenPayload,
    /// The issuer's KeyId
    pub issuer: KeyId,
    /// The audience's KeyId
    pub audience: KeyId,
    /// The content ID from the capability
    pub content_id: String,
    /// The granted action
    pub action: CapabilityAction,
}

/// AuthToken verifier for State Nodes.
///
/// This verifier performs the following checks:
/// 1. JWT format and structure validation
/// 2. Signature verification (P256 ECDSA)
/// 3. Expiration check
/// 4. Access control validation (min_valid_issued_at)
/// 5. Capability matching
pub struct AuthTokenVerifier;

impl AuthTokenVerifier {
    /// Verify a AuthToken for accessing a specific content with a required action.
    ///
    /// # Arguments
    /// * `jwt` - The JWT string to verify
    /// * `issuer_public_key` - The issuer's P256 public key (65 bytes, SEC1 uncompressed)
    /// * `expected_audience` - The expected audience KeyId (usually this State Node or the requester)
    /// * `content_id` - The content ID being accessed
    /// * `required_action` - The required capability action
    /// * `access_control` - Optional access control state for invalidation check
    ///
    /// # Returns
    /// * `Ok(VerifiedToken)` if verification succeeds
    /// * `Err(AuthTokenVerifyError)` if verification fails
    pub fn verify(
        jwt: &str,
        issuer_public_key: &[u8],
        expected_audience: &KeyId,
        content_id: &str,
        required_action: CapabilityAction,
        access_control: Option<&ContentAccessControl>,
    ) -> Result<VerifiedToken, AuthTokenVerifyError> {
        // 1. Parse the JWT
        let token = AuthToken::from_jwt(jwt)?;

        // 2. Check algorithm (only P256/ES256 is supported)
        if token.header.alg != "ES256" {
            return Err(AuthTokenVerifyError::UnsupportedAlgorithm(
                token.header.alg.clone(),
            ));
        }

        // 3. Verify signature
        verify_p256_signature(
            token.signing_input_bytes(),
            token.signature(),
            issuer_public_key,
        )?;

        // 4. Check expiration: exp is required
        let exp = token
            .payload
            .exp
            .ok_or(AuthTokenVerifyError::MissingExpiration)?;

        // Check max TTL (24 hours from iat)
        const MAX_TTL_SECS: u64 = 24 * 60 * 60;
        if exp > token.payload.iat + MAX_TTL_SECS {
            return Err(AuthTokenVerifyError::ExpirationTooFar);
        }

        if token.payload.is_expired() {
            return Err(AuthTokenVerifyError::Expired);
        }

        // 5. Check access control (min_valid_issued_at)
        if let Some(ac) = access_control {
            if !ac.is_token_valid(token.payload.iat) {
                return Err(AuthTokenVerifyError::Invalidated);
            }
        }

        // 6. Check audience (mandatory)
        if &token.payload.aud != expected_audience {
            return Err(AuthTokenVerifyError::AudienceMismatch {
                expected: expected_audience.to_string(),
                actual: token.payload.aud.to_string(),
            });
        }

        // 7. Check capability
        let resource = format!("monas://content/{}", content_id);
        if !token.payload.has_capability(&resource, required_action) {
            return Err(AuthTokenVerifyError::InsufficientCapability {
                required: required_action,
                resource,
            });
        }

        // 8. Extract content_id from capability and verify it matches
        let cap_content_id = token
            .payload
            .att
            .iter()
            .find_map(|cap| cap.content_id())
            .ok_or_else(|| AuthTokenVerifyError::ContentIdMismatch {
                expected: content_id.to_string(),
                actual: "none".to_string(),
            })?;

        if cap_content_id != content_id {
            return Err(AuthTokenVerifyError::ContentIdMismatch {
                expected: content_id.to_string(),
                actual: cap_content_id.to_string(),
            });
        }

        Ok(VerifiedToken {
            payload: token.payload.clone(),
            issuer: token.payload.iss.clone(),
            audience: token.payload.aud.clone(),
            content_id: content_id.to_string(),
            action: required_action,
        })
    }

    /// Verify only the signature of a AuthToken.
    ///
    /// This is a lightweight verification that only checks the signature,
    /// without checking expiration, access control, or capabilities.
    ///
    /// # Arguments
    /// * `jwt` - The JWT string to verify
    /// * `issuer_public_key` - The issuer's P256 public key
    ///
    /// # Returns
    /// * `Ok(AuthToken)` if signature verification succeeds
    /// * `Err(AuthTokenVerifyError)` if verification fails
    pub fn verify_signature_only(
        jwt: &str,
        issuer_public_key: &[u8],
    ) -> Result<AuthToken, AuthTokenVerifyError> {
        let token = AuthToken::from_jwt(jwt)?;

        if token.header.alg != "ES256" {
            return Err(AuthTokenVerifyError::UnsupportedAlgorithm(
                token.header.alg.clone(),
            ));
        }

        verify_p256_signature(
            token.signing_input_bytes(),
            token.signature(),
            issuer_public_key,
        )?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::DigestSigner;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p256::elliptic_curve::rand_core::OsRng;
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn generate_test_keypair() -> (SigningKey, Vec<u8>) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        (signing_key, public_key_bytes)
    }

    fn create_and_sign_token(
        signing_key: &SigningKey,
        issuer_pk: &[u8],
        audience_pk: &[u8],
        content_id: &str,
        action: CapabilityAction,
        exp: Option<u64>,
    ) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "ver": "1.0"
        });

        let payload = serde_json::json!({
            "iss": issuer_pk,
            "aud": audience_pk,
            "exp": exp,
            "iat": now,
            "jti": format!("test-{}", now),
            "att": [{
                "with": format!("monas://content/{}", content_id),
                "can": action
            }]
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let (signature, _): (Signature, _) =
            signing_key.sign_digest(Sha256::new_with_prefix(signing_input.as_bytes()));
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_vec());

        format!("{}.{}", signing_input, sig_b64)
    }

    fn create_multi_capability_token(
        signing_key: &SigningKey,
        issuer_pk: &[u8],
        audience_pk: &[u8],
        content_id: &str,
        actions: Vec<CapabilityAction>,
        exp: Option<u64>,
    ) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let header = serde_json::json!({
            "alg": "ES256",
            "typ": "JWT",
            "ver": "1.0"
        });

        let capabilities: Vec<serde_json::Value> = actions
            .into_iter()
            .map(|action| {
                serde_json::json!({
                    "with": format!("monas://content/{}", content_id),
                    "can": action
                })
            })
            .collect();

        let payload = serde_json::json!({
            "iss": issuer_pk,
            "aud": audience_pk,
            "exp": exp,
            "iat": now,
            "jti": format!("test-{}", now),
            "att": capabilities
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.to_string().as_bytes());
        let signing_input = format!("{}.{}", header_b64, payload_b64);

        let (signature, _): (Signature, _) =
            signing_key.sign_digest(Sha256::new_with_prefix(signing_input.as_bytes()));
        let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_vec());

        format!("{}.{}", signing_input, sig_b64)
    }

    #[test]
    fn verify_valid_token() {
        let (signing_key, issuer_pk) = generate_test_keypair();
        let (_, audience_pk) = generate_test_keypair();
        let content_id = "test-content-123";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let jwt = create_and_sign_token(
            &signing_key,
            &issuer_pk,
            &audience_pk,
            content_id,
            CapabilityAction::Read,
            Some(now + 3600),
        );

        let aud_key = KeyId::new(audience_pk.clone());
        let result = AuthTokenVerifier::verify(
            &jwt,
            &issuer_pk,
            &aud_key,
            content_id,
            CapabilityAction::Read,
            None,
        );

        assert!(result.is_ok());
        let verified = result.unwrap();
        assert_eq!(verified.content_id, content_id);
        assert_eq!(verified.action, CapabilityAction::Read);
    }

    #[test]
    fn verify_fails_with_wrong_signature() {
        let (signing_key, _issuer_pk) = generate_test_keypair();
        let (_, wrong_pk) = generate_test_keypair();
        let (_, audience_pk) = generate_test_keypair();
        let content_id = "test-content-123";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let jwt = create_and_sign_token(
            &signing_key,
            &wrong_pk,
            &audience_pk,
            content_id,
            CapabilityAction::Read,
            Some(now + 3600),
        );

        let aud_key = KeyId::new(audience_pk.clone());
        let result = AuthTokenVerifier::verify(
            &jwt,
            &wrong_pk,
            &aud_key,
            content_id,
            CapabilityAction::Read,
            None,
        );

        assert!(matches!(
            result,
            Err(AuthTokenVerifyError::SignatureError(_))
        ));
    }

    #[test]
    fn verify_fails_with_expired_token() {
        let (signing_key, issuer_pk) = generate_test_keypair();
        let (_, audience_pk) = generate_test_keypair();
        let content_id = "test-content-123";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Use iat close to exp so it passes ExpirationTooFar check
        let jwt = create_and_sign_token(
            &signing_key,
            &issuer_pk,
            &audience_pk,
            content_id,
            CapabilityAction::Read,
            Some(now - 1), // Already expired
        );

        let aud_key = KeyId::new(audience_pk.clone());
        let result = AuthTokenVerifier::verify(
            &jwt,
            &issuer_pk,
            &aud_key,
            content_id,
            CapabilityAction::Read,
            None,
        );

        assert!(matches!(result, Err(AuthTokenVerifyError::Expired)));
    }

    #[test]
    fn verify_fails_with_invalidated_token() {
        let (signing_key, issuer_pk) = generate_test_keypair();
        let (_, audience_pk) = generate_test_keypair();
        let content_id = "test-content-123";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let jwt = create_and_sign_token(
            &signing_key,
            &issuer_pk,
            &audience_pk,
            content_id,
            CapabilityAction::Read,
            Some(now + 3600),
        );

        // Create access control that invalidates all tokens issued before now + 1 hour
        let mut access_control = ContentAccessControl::new(content_id.to_string());
        access_control.invalidate_before(now + 3600).unwrap();

        let aud_key = KeyId::new(audience_pk.clone());
        let result = AuthTokenVerifier::verify(
            &jwt,
            &issuer_pk,
            &aud_key,
            content_id,
            CapabilityAction::Read,
            Some(&access_control),
        );

        assert!(matches!(result, Err(AuthTokenVerifyError::Invalidated)));
    }

    #[test]
    fn verify_fails_with_insufficient_capability() {
        let (signing_key, issuer_pk) = generate_test_keypair();
        let (_, audience_pk) = generate_test_keypair();
        let content_id = "test-content-123";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Token only grants Read
        let jwt = create_and_sign_token(
            &signing_key,
            &issuer_pk,
            &audience_pk,
            content_id,
            CapabilityAction::Read,
            Some(now + 3600),
        );

        // But we require Write
        let aud_key = KeyId::new(audience_pk.clone());
        let result = AuthTokenVerifier::verify(
            &jwt,
            &issuer_pk,
            &aud_key,
            content_id,
            CapabilityAction::Write,
            None,
        );

        assert!(matches!(
            result,
            Err(AuthTokenVerifyError::InsufficientCapability { .. })
        ));
    }

    #[test]
    fn verify_write_satisfies_read() {
        let (signing_key, issuer_pk) = generate_test_keypair();
        let (_, audience_pk) = generate_test_keypair();
        let content_id = "test-content-123";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Token grants Write
        let jwt = create_and_sign_token(
            &signing_key,
            &issuer_pk,
            &audience_pk,
            content_id,
            CapabilityAction::Write,
            Some(now + 3600),
        );

        // Require Read - should succeed because Write satisfies Read
        let aud_key = KeyId::new(audience_pk.clone());
        let result = AuthTokenVerifier::verify(
            &jwt,
            &issuer_pk,
            &aud_key,
            content_id,
            CapabilityAction::Read,
            None,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn verify_fails_with_audience_mismatch() {
        let (signing_key, issuer_pk) = generate_test_keypair();
        let (_, audience_pk) = generate_test_keypair();
        let (_, wrong_audience_pk) = generate_test_keypair();
        let content_id = "test-content-123";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let jwt = create_and_sign_token(
            &signing_key,
            &issuer_pk,
            &audience_pk,
            content_id,
            CapabilityAction::Read,
            Some(now + 3600),
        );

        let wrong_aud_key = KeyId::new(wrong_audience_pk);
        let result = AuthTokenVerifier::verify(
            &jwt,
            &issuer_pk,
            &wrong_aud_key,
            content_id,
            CapabilityAction::Read,
            None,
        );

        assert!(matches!(
            result,
            Err(AuthTokenVerifyError::AudienceMismatch { .. })
        ));
    }

    #[test]
    fn verify_fails_with_content_id_mismatch() {
        let (signing_key, issuer_pk) = generate_test_keypair();
        let (_, audience_pk) = generate_test_keypair();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let jwt = create_and_sign_token(
            &signing_key,
            &issuer_pk,
            &audience_pk,
            "content-A",
            CapabilityAction::Read,
            Some(now + 3600),
        );

        // Try to use token for different content
        let aud_key = KeyId::new(audience_pk.clone());
        let result = AuthTokenVerifier::verify(
            &jwt,
            &issuer_pk,
            &aud_key,
            "content-B",
            CapabilityAction::Read,
            None,
        );

        assert!(matches!(
            result,
            Err(AuthTokenVerifyError::InsufficientCapability { .. })
        ));
    }

    #[test]
    fn verify_fails_with_missing_expiration() {
        let (signing_key, issuer_pk) = generate_test_keypair();
        let (_, audience_pk) = generate_test_keypair();
        let content_id = "test-content-123";

        let jwt = create_and_sign_token(
            &signing_key,
            &issuer_pk,
            &audience_pk,
            content_id,
            CapabilityAction::Read,
            None, // No expiration
        );

        let aud_key = KeyId::new(audience_pk.clone());
        let result = AuthTokenVerifier::verify(
            &jwt,
            &issuer_pk,
            &aud_key,
            content_id,
            CapabilityAction::Read,
            None,
        );

        assert!(matches!(
            result,
            Err(AuthTokenVerifyError::MissingExpiration)
        ));
    }

    #[test]
    fn verify_fails_with_expiration_too_far() {
        let (signing_key, issuer_pk) = generate_test_keypair();
        let (_, audience_pk) = generate_test_keypair();
        let content_id = "test-content-123";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Token expires in 48 hours (> 24h max)
        let jwt = create_and_sign_token(
            &signing_key,
            &issuer_pk,
            &audience_pk,
            content_id,
            CapabilityAction::Read,
            Some(now + 48 * 3600),
        );

        let aud_key = KeyId::new(audience_pk.clone());
        let result = AuthTokenVerifier::verify(
            &jwt,
            &issuer_pk,
            &aud_key,
            content_id,
            CapabilityAction::Read,
            None,
        );

        assert!(matches!(
            result,
            Err(AuthTokenVerifyError::ExpirationTooFar)
        ));
    }

    #[test]
    fn verify_signature_only_succeeds() {
        let (signing_key, issuer_pk) = generate_test_keypair();
        let (_, audience_pk) = generate_test_keypair();
        let content_id = "test-content-123";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let jwt = create_and_sign_token(
            &signing_key,
            &issuer_pk,
            &audience_pk,
            content_id,
            CapabilityAction::Read,
            Some(now + 3600),
        );

        let result = AuthTokenVerifier::verify_signature_only(&jwt, &issuer_pk);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_owner_role_capabilities() {
        let (signing_key, issuer_pk) = generate_test_keypair();
        let (_, audience_pk) = generate_test_keypair();
        let content_id = "test-content-owner";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let jwt = create_multi_capability_token(
            &signing_key,
            &issuer_pk,
            &audience_pk,
            content_id,
            CapabilityAction::owner_actions(),
            Some(now + 3600),
        );

        // Verify all owner actions are granted
        let aud_key = KeyId::new(audience_pk.clone());
        for action in CapabilityAction::owner_actions() {
            let result =
                AuthTokenVerifier::verify(&jwt, &issuer_pk, &aud_key, content_id, action, None);
            assert!(result.is_ok(), "Owner should have {:?} capability", action);
        }
    }

    #[test]
    fn verify_editor_role_capabilities() {
        let (signing_key, issuer_pk) = generate_test_keypair();
        let (_, audience_pk) = generate_test_keypair();
        let content_id = "test-content-editor";

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let jwt = create_multi_capability_token(
            &signing_key,
            &issuer_pk,
            &audience_pk,
            content_id,
            CapabilityAction::editor_actions(),
            Some(now + 3600),
        );

        let aud_key = KeyId::new(audience_pk.clone());

        // Editor should have Read and Write
        let read_result = AuthTokenVerifier::verify(
            &jwt,
            &issuer_pk,
            &aud_key,
            content_id,
            CapabilityAction::Read,
            None,
        );
        assert!(read_result.is_ok());

        let write_result = AuthTokenVerifier::verify(
            &jwt,
            &issuer_pk,
            &aud_key,
            content_id,
            CapabilityAction::Write,
            None,
        );
        assert!(write_result.is_ok());

        // Editor should NOT have Delete
        let delete_result = AuthTokenVerifier::verify(
            &jwt,
            &issuer_pk,
            &aud_key,
            content_id,
            CapabilityAction::Delete,
            None,
        );
        assert!(matches!(
            delete_result,
            Err(AuthTokenVerifyError::InsufficientCapability { .. })
        ));
    }
}
