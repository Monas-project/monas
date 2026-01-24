//! Signature verification for ShareToken and request signatures.
//!
//! This module provides signature verification functionality using P256 (ES256).

use super::share_token::{ShareToken, ShareTokenError};
use anyhow::{Context, Result};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

/// Signature verifier for P256/ES256 signatures
pub struct SignatureVerifier;

impl SignatureVerifier {
    /// Verify ShareToken signature using owner's public key
    ///
    /// # Arguments
    /// * `token` - The ShareToken to verify
    /// * `owner_public_key` - Owner's public key in uncompressed format (65 bytes)
    ///
    /// # Returns
    /// Ok(()) if signature is valid, Err otherwise
    pub fn verify_share_token_signature(token: &ShareToken, owner_public_key: &[u8]) -> Result<()> {
        let message = token.signing_message()?;

        // Parse P256 public key from SEC1 uncompressed format
        let verifying_key = VerifyingKey::from_sec1_bytes(owner_public_key)
            .context("Invalid P256 public key format")?;

        // Parse signature from DER or raw format
        let signature =
            Signature::from_slice(&token.signature).context("Invalid P256 signature format")?;

        // Verify signature
        verifying_key
            .verify(&message, &signature)
            .map_err(|e| ShareTokenError::SignatureVerificationFailed(e.to_string()))?;

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

        // Verify signature
        verifying_key
            .verify(message, &sig)
            .map_err(|e| ShareTokenError::SignatureVerificationFailed(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn test_verify_share_token_signature() {
        // Generate a test key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        // Create a test ShareToken
        let payload = super::super::share_token::ShareTokenPayload {
            iss: "user:alice".to_string(),
            aud: "user:bob".to_string(),
            exp: None,
            iat: 1706740800,
            jti: "test-id".to_string(),
            att: vec![],
            fct: None,
        };

        let mut token = ShareToken::new(payload, vec![]);
        let message = token.signing_message().unwrap();

        // Sign the message
        let signature: p256::ecdsa::Signature = signing_key.sign(&message);
        token.signature = signature.to_vec();

        // Verify the signature
        let result = SignatureVerifier::verify_share_token_signature(&token, &public_key_bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_share_token_signature_invalid() {
        // Generate a test key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();

        // Create a test ShareToken with invalid signature
        let payload = super::super::share_token::ShareTokenPayload {
            iss: "user:alice".to_string(),
            aud: "user:bob".to_string(),
            exp: None,
            iat: 1706740800,
            jti: "test-id".to_string(),
            att: vec![],
            fct: None,
        };

        let token = ShareToken::new(payload, vec![0u8; 64]); // Invalid signature

        // Verify should fail
        let result = SignatureVerifier::verify_share_token_signature(&token, &public_key_bytes);
        assert!(result.is_err());
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
