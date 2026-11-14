//! Signature verification for AuthToken and request signatures.
//!
//! This module provides signature verification functionality using P256 (ES256).

use super::auth_token::{AuthToken, AuthTokenError};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

/// Signature verifier for P256/ES256 signatures
pub struct SignatureVerifier;

impl SignatureVerifier {
    /// Verify AuthToken signature using owner's public key
    ///
    /// # Arguments
    /// * `token` - The AuthToken to verify
    /// * `owner_public_key` - Owner's public key in uncompressed format (65 bytes)
    ///
    /// # Returns
    /// Ok(()) if signature is valid, Err otherwise
    pub fn verify_auth_token_signature(token: &AuthToken, owner_public_key: &[u8]) -> Result<()> {
        let message = token.signing_message()?;

        Self::verify_p256(&message, &token.signature, owner_public_key)
    }

    /// Verify a JWT's signature over the exact wire bytes it was signed with.
    ///
    /// The JWS signing input is "the received `<header_b64>.<payload_b64>` itself"; it must
    /// not be rebuilt by re-serializing the parsed struct (there is no guarantee that JSON field
    /// order and whitespace match the issuer's, so legitimate tokens would be rejected).
    /// This function verifies the wire segments as-is, so it verifies correctly regardless of
    /// the issuer's serialization.
    pub fn verify_jwt_signature_wire(jwt: &str, issuer_public_key: &[u8]) -> Result<()> {
        let parts: Vec<&str> = jwt.split('.').collect();
        if parts.len() != 3 {
            anyhow::bail!("Invalid JWT format: expected 3 parts, got {}", parts.len());
        }

        let message = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD
            .decode(parts[2])
            .context("Failed to decode JWT signature segment")?;

        Self::verify_p256(message.as_bytes(), &signature, issuer_public_key)
    }

    fn verify_p256(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<()> {
        // Parse P256 public key from SEC1 uncompressed format
        let verifying_key =
            VerifyingKey::from_sec1_bytes(public_key).context("Invalid P256 public key format")?;

        // Parse signature from DER or raw format
        let signature =
            Signature::from_slice(signature).context("Invalid P256 signature format")?;

        // Verify signature
        verifying_key
            .verify(message, &signature)
            .map_err(|e| AuthTokenError::SignatureVerificationFailed(e.to_string()))?;

        Ok(())
    }

    /// Verify request signature using requester's public key
    ///
    /// # Arguments
    /// * `message` - The message that was signed
    /// * `signature` - The signature bytes (DER or raw format)
    /// * `requester_public_key` - Requester's public key in uncompressed format (65 bytes)
    ///
    /// # Returns
    /// Ok(()) if signature is valid, Err otherwise
    pub fn verify_request_signature(
        message: &[u8],
        signature: &[u8],
        requester_public_key: &[u8],
    ) -> Result<()> {
        // Parse P256 public key from SEC1 uncompressed format
        let verifying_key = VerifyingKey::from_sec1_bytes(requester_public_key)
            .context("Invalid P256 public key format")?;

        // Parse signature from DER or raw format
        let sig = Signature::from_slice(signature).context("Invalid P256 signature format")?;

        // NOTE on ECDSA malleability.
        //
        // For any valid `(r, s)` the value `(r, n - s)` verifies against the
        // same message and key, so one authorized request has two distinct
        // signature encodings. Both are accepted here *on purpose*: rejecting
        // high-S would break every existing caller, because none of the signers
        // in this repo (nor monas-account, which real clients use) normalize
        // before sending, and S is high about half the time.
        //
        // Nothing security-relevant depends on the encoding being unique. The
        // single-use record for mutations is keyed on the signed *message* and
        // the signer — see `StateNodeService::mutation_request_id` — precisely
        // so that a re-encoded signature cannot masquerade as a second request.
        // Deriving that identity from the signature bytes would have made this
        // malleability a replay bypass.
        //
        // Normalizing at the signing side and then requiring low-S here is the
        // stricter end state, but it is a wire-compatibility break that has to
        // land in the signers first.

        // Verify signature
        verifying_key
            .verify(message, &sig)
            .map_err(|e| AuthTokenError::SignatureVerificationFailed(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn test_verify_auth_token_signature() {
        // Generate a test key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        // Create a test AuthToken
        let payload = super::super::auth_token::AuthTokenPayload {
            iss: "user:04aaaa".to_string(),
            aud: "user:04bbbb".to_string(),
            exp: None,
            iat: 1706740800,
            jti: "test-id".to_string(),
            att: vec![],
            fct: None,
        };

        let mut token = AuthToken::new(payload, vec![]);
        let message = token.signing_message().unwrap();

        // Sign the message
        let signature: p256::ecdsa::Signature = signing_key.sign(&message);
        token.signature = signature.to_vec();

        // Verify the signature
        let result = SignatureVerifier::verify_auth_token_signature(&token, &public_key_bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_auth_token_signature_invalid() {
        // Generate a test key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        // Create a test AuthToken with invalid signature
        let payload = super::super::auth_token::AuthTokenPayload {
            iss: "user:04aaaa".to_string(),
            aud: "user:04bbbb".to_string(),
            exp: None,
            iat: 1706740800,
            jti: "test-id".to_string(),
            att: vec![],
            fct: None,
        };

        let token = AuthToken::new(payload, vec![0u8; 64]); // Invalid signature

        // Verify should fail
        let result = SignatureVerifier::verify_auth_token_signature(&token, &public_key_bytes);
        assert!(result.is_err());
    }

    /// Explicitly document ECDSA malleability.
    ///
    /// For a valid `(r, s)`, `(r, n - s)` also verifies with the same message and key, yet the
    /// bytes differ. This verifier **accepts both** (so as not to break existing clients'
    /// signatures). Therefore, do not assume that "signature bytes are unique per request".
    /// Mutation replay prevention does not rely on this assumption and derives the ID from the
    /// signed message.
    #[test]
    fn both_signature_encodings_verify_so_bytes_are_not_a_request_identity() {
        use p256::ecdsa::Signature;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        let message = b"monas-request-v1:6:update:9:content-1:1700000000:0:";
        let signature: Signature = signing_key.sign(message);
        let flipped = Signature::from_scalars(*signature.r(), -*signature.s()).unwrap();

        assert_ne!(
            signature.to_vec(),
            flipped.to_vec(),
            "the two encodings must differ in bytes"
        );
        for encoding in [signature.to_vec(), flipped.to_vec()] {
            assert!(
                SignatureVerifier::verify_request_signature(message, &encoding, &public_key_bytes,)
                    .is_ok(),
                "both encodings authenticate the same request"
            );
        }
    }

    #[test]
    fn test_verify_request_signature() {
        // Generate a test key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        // Create a test message
        let message = b"test message";

        // Sign the message
        let signature: p256::ecdsa::Signature = signing_key.sign(message);

        // Verify the signature
        let result = SignatureVerifier::verify_request_signature(
            message,
            &signature.to_vec(),
            &public_key_bytes,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_request_signature_invalid() {
        // Generate a test key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        // Create a test message
        let message = b"test message";

        // Invalid signature
        let invalid_signature = vec![0u8; 64];

        // Verify should fail
        let result = SignatureVerifier::verify_request_signature(
            message,
            &invalid_signature,
            &public_key_bytes,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_request_signature_wrong_message() {
        // Generate a test key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        // Sign one message
        let original_message = b"original message";
        let signature: p256::ecdsa::Signature = signing_key.sign(original_message);

        // Try to verify with a different message
        let different_message = b"different message";
        let result = SignatureVerifier::verify_request_signature(
            different_message,
            &signature.to_vec(),
            &public_key_bytes,
        );
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod wire_verification_tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use rand::rngs::OsRng;

    fn sign_jwt(header_json: &str, payload_json: &str, key: &SigningKey) -> String {
        let h = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let p = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{h}.{p}");
        let sig: p256::ecdsa::Signature = key.sign(signing_input.as_bytes());
        format!("{h}.{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    /// Regression test for issue #60: signature verification is performed on the wire bytes,
    /// so it verifies correctly even if the issuer built the JSON with a field order and
    /// whitespace different from the struct's re-serialized form.
    #[test]
    fn wire_verification_is_independent_of_field_order() {
        let key = SigningKey::random(&mut OsRng);
        let public_key = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        // JSON with deliberately shuffled order and mixed whitespace (a form that serde
        // re-serialization does not reproduce)
        let header = r#"{ "typ":"JWT" , "alg":"ES256" }"#;
        let payload = r#"{ "jti":"j-1", "iss":"user:04aa", "iat":1, "aud":"user:04bb", "att":[] }"#;
        let jwt = sign_jwt(header, payload, &key);

        assert!(SignatureVerifier::verify_jwt_signature_wire(&jwt, &public_key).is_ok());
    }

    #[test]
    fn wire_verification_rejects_tampered_payload() {
        let key = SigningKey::random(&mut OsRng);
        let public_key = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let jwt = sign_jwt(
            r#"{"alg":"ES256","typ":"JWT"}"#,
            r#"{"iss":"user:04aa","aud":"user:04bb","iat":1,"jti":"j-1","att":[]}"#,
            &key,
        );

        // Swap the payload segment
        let parts: Vec<&str> = jwt.split('.').collect();
        let forged_payload = URL_SAFE_NO_PAD
            .encode(r#"{"iss":"user:04aa","aud":"user:04EVIL","iat":1,"jti":"j-1","att":[]}"#);
        let forged = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);

        assert!(SignatureVerifier::verify_jwt_signature_wire(&forged, &public_key).is_err());
    }

    #[test]
    fn wire_verification_rejects_wrong_key() {
        let key = SigningKey::random(&mut OsRng);
        let other = SigningKey::random(&mut OsRng);
        let other_pub = other
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let jwt = sign_jwt(
            r#"{"alg":"ES256","typ":"JWT"}"#,
            r#"{"iss":"user:04aa","aud":"user:04bb","iat":1,"jti":"j-1","att":[]}"#,
            &key,
        );
        assert!(SignatureVerifier::verify_jwt_signature_wire(&jwt, &other_pub).is_err());
    }
}
