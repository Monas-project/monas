//! Cryptographic utilities for signature verification.
//!
//! This module provides P-256 ECDSA signature verification for AuthToken validation.
//! The signing is done by clients using monas-account, and State Nodes verify the signatures.

use p256::ecdsa::signature::DigestVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Error type for signature verification failures.
#[derive(Debug, Error)]
pub enum SignatureVerifyError {
    #[error("Invalid public key format: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid signature format: {0}")]
    InvalidSignature(String),

    #[error("Signature verification failed")]
    VerificationFailed,
}

/// Verify a P-256 ECDSA signature.
///
/// # Arguments
/// * `message` - The message that was signed
/// * `signature` - The signature bytes (DER or raw format, 64 bytes for raw)
/// * `public_key` - The P-256 public key in SEC1 uncompressed format (65 bytes, starting with 0x04)
///
/// # Returns
/// * `Ok(())` if the signature is valid
/// * `Err(SignatureVerifyError)` if verification fails
pub fn verify_p256_signature(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), SignatureVerifyError> {
    // Parse the public key from SEC1 uncompressed format
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
        .map_err(|e| SignatureVerifyError::InvalidPublicKey(e.to_string()))?;

    // Parse the signature
    let sig = Signature::from_slice(signature)
        .map_err(|e| SignatureVerifyError::InvalidSignature(e.to_string()))?;

    // Verify using SHA-256 digest (matching monas-account's P256KeyPair implementation)
    verifying_key
        .verify_digest(Sha256::new_with_prefix(message), &sig)
        .map_err(|_| SignatureVerifyError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::DigestSigner;
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;

    fn generate_test_keypair() -> (SigningKey, Vec<u8>) {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let public_key_bytes = verifying_key.to_encoded_point(false).as_bytes().to_vec();
        (signing_key, public_key_bytes)
    }

    fn sign_message(signing_key: &SigningKey, message: &[u8]) -> Vec<u8> {
        let (signature, _): (Signature, _) =
            signing_key.sign_digest(Sha256::new_with_prefix(message));
        signature.to_vec()
    }

    #[test]
    fn verify_valid_signature() {
        let (signing_key, public_key) = generate_test_keypair();
        let message = b"test message for verification";
        let signature = sign_message(&signing_key, message);

        let result = verify_p256_signature(message, &signature, &public_key);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_fails_with_wrong_message() {
        let (signing_key, public_key) = generate_test_keypair();
        let message = b"original message";
        let signature = sign_message(&signing_key, message);

        let wrong_message = b"different message";
        let result = verify_p256_signature(wrong_message, &signature, &public_key);
        assert!(matches!(
            result,
            Err(SignatureVerifyError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_fails_with_wrong_public_key() {
        let (signing_key, _public_key) = generate_test_keypair();
        let (_, wrong_public_key) = generate_test_keypair();
        let message = b"test message";
        let signature = sign_message(&signing_key, message);

        let result = verify_p256_signature(message, &signature, &wrong_public_key);
        assert!(matches!(
            result,
            Err(SignatureVerifyError::VerificationFailed)
        ));
    }

    #[test]
    fn verify_fails_with_invalid_public_key() {
        let message = b"test message";
        let signature = vec![0u8; 64];
        let invalid_public_key = vec![0u8; 10]; // Invalid length

        let result = verify_p256_signature(message, &signature, &invalid_public_key);
        assert!(matches!(
            result,
            Err(SignatureVerifyError::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn verify_fails_with_invalid_signature() {
        let (_signing_key, public_key) = generate_test_keypair();
        let message = b"test message";
        let invalid_signature = vec![0u8; 10]; // Invalid length

        let result = verify_p256_signature(message, &invalid_signature, &public_key);
        assert!(matches!(
            result,
            Err(SignatureVerifyError::InvalidSignature(_))
        ));
    }
}
