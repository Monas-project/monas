use crate::domain::content::encryption::{
    ContentEncryption, ContentEncryptionKey, ContentEncryptionKeyGenerator,
};
use crate::domain::content::ContentError;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand_core::{OsRng, RngCore};

/// Implementation for generating a CEK suitable for AES-256.
///
/// Produces a 32-byte random key using an OS-backed cryptographically secure RNG.
pub struct OsRngContentEncryptionKeyGenerator;

impl ContentEncryptionKeyGenerator for OsRngContentEncryptionKeyGenerator {
    fn generate(&self) -> ContentEncryptionKey {
        let mut key_bytes = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut key_bytes);
        ContentEncryptionKey(key_bytes.to_vec())
    }
}

/// Content encryption/decryption implementation using AES-256-GCM (AEAD).
///
/// - Encryption: generates a 12-byte random nonce and returns a byte sequence
///   in the form `[nonce || ciphertext || tag]` (the 16-byte authentication
///   tag is appended by AES-GCM).
/// - Decryption: splits the first 12 bytes as the nonce and authenticates the
///   remaining bytes before returning the plaintext. Any tampering with the
///   ciphertext (including a forged payload substituted by an untrusted node)
///   fails authentication and returns a `DecryptionError` instead of silently
///   yielding corrupted plaintext.
pub struct Aes256GcmContentEncryption;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;

impl ContentEncryption for Aes256GcmContentEncryption {
    fn encrypt(
        &self,
        key: &ContentEncryptionKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentError> {
        if key.0.len() != KEY_LEN {
            return Err(ContentError::EncryptionError(format!(
                "Invalid content encryption key length; expected {} bytes, got {} bytes",
                KEY_LEN,
                key.0.len()
            )));
        }
        let cipher = Aes256Gcm::new_from_slice(key.0.as_slice()).map_err(|_| {
            ContentError::EncryptionError(
                "Invalid key length for AES-256-GCM (expected 32-byte key)".into(),
            )
        })?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| ContentError::EncryptionError("AES-256-GCM encryption failed".into()))?;

        let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, key: &ContentEncryptionKey, data: &[u8]) -> Result<Vec<u8>, ContentError> {
        if key.0.len() != KEY_LEN {
            return Err(ContentError::DecryptionError(format!(
                "Invalid content encryption key length; expected {} bytes, got {} bytes",
                KEY_LEN,
                key.0.len()
            )));
        }

        if data.len() < NONCE_LEN + TAG_LEN {
            return Err(ContentError::DecryptionError(
                "Ciphertext is too short to contain nonce and authentication tag".into(),
            ));
        }

        let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(key.0.as_slice()).map_err(|_| {
            ContentError::DecryptionError(
                "Invalid key length for AES-256-GCM (expected 32-byte key)".into(),
            )
        })?;

        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| {
                ContentError::DecryptionError(
                    "AES-256-GCM authentication failed: ciphertext is corrupted or tampered".into(),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trip() {
        let key = ContentEncryptionKey(vec![42u8; 32]); // fixed key only for testing
        let encryptor = Aes256GcmContentEncryption;
        let plaintext = b"Monas content encryption test".to_vec();

        let ciphertext = encryptor
            .encrypt(&key, &plaintext)
            .expect("encryption should succeed");

        assert_ne!(ciphertext, plaintext);
        assert_eq!(ciphertext.len(), NONCE_LEN + plaintext.len() + TAG_LEN);

        let decrypted = encryptor
            .decrypt(&key, &ciphertext)
            .expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_fails_with_invalid_key_length() {
        let key = ContentEncryptionKey(vec![1u8; 16]);
        let encryptor = Aes256GcmContentEncryption;
        let plaintext = b"test".to_vec();

        let result = encryptor.encrypt(&key, &plaintext);
        assert!(matches!(result, Err(ContentError::EncryptionError(_))));
    }

    #[test]
    fn decrypt_fails_with_invalid_key_length() {
        let key = ContentEncryptionKey(vec![1u8; 16]);
        let encryptor = Aes256GcmContentEncryption;

        let dummy_ciphertext = vec![0u8; NONCE_LEN + TAG_LEN + 4];

        let result = encryptor.decrypt(&key, &dummy_ciphertext);
        assert!(matches!(result, Err(ContentError::DecryptionError(_))));
    }

    #[test]
    fn decrypt_fails_when_data_too_short() {
        let key = ContentEncryptionKey(vec![2u8; 32]);
        let encryptor = Aes256GcmContentEncryption;

        // nonce + tag だけの長さ未満は即エラー
        let too_short = vec![0u8; NONCE_LEN + TAG_LEN - 1];
        let result = encryptor.decrypt(&key, &too_short);
        assert!(matches!(result, Err(ContentError::DecryptionError(_))));

        let even_shorter = vec![0u8; NONCE_LEN];
        let result2 = encryptor.decrypt(&key, &even_shorter);
        assert!(matches!(result2, Err(ContentError::DecryptionError(_))));
    }

    #[test]
    fn encrypt_produces_different_ciphertexts_due_to_random_nonce() {
        let key = ContentEncryptionKey(vec![99u8; 32]);
        let encryptor = Aes256GcmContentEncryption;
        let plaintext = b"same plaintext".to_vec();

        let c1 = encryptor
            .encrypt(&key, &plaintext)
            .expect("encryption should succeed");
        let c2 = encryptor
            .encrypt(&key, &plaintext)
            .expect("encryption should succeed");

        assert_ne!(c1, c2);
    }

    #[test]
    fn encrypt_then_decrypt_round_trip_large_plaintext() {
        let key = ContentEncryptionKey(vec![7u8; 32]);
        let encryptor = Aes256GcmContentEncryption;
        let size = 1024 * 1024;
        let mut plaintext = Vec::with_capacity(size);
        for i in 0..size {
            plaintext.push((i % 256) as u8);
        }

        let ciphertext = encryptor
            .encrypt(&key, &plaintext)
            .expect("encryption should succeed for large plaintext");

        assert_eq!(ciphertext.len(), NONCE_LEN + plaintext.len() + TAG_LEN);

        let decrypted = encryptor
            .decrypt(&key, &ciphertext)
            .expect("decryption should succeed for large plaintext");

        assert_eq!(decrypted, plaintext);
    }

    /// **Integrity test**: AES-GCM detects any tampering of the ciphertext.
    ///
    /// This is the counterpart of the old AES-CTR "vulnerability demo" test:
    /// with CTR, a bit-flipped ciphertext decrypted "successfully" into
    /// attacker-controlled plaintext. With GCM the authentication tag no
    /// longer matches, so decryption MUST fail. This is what protects the SDK
    /// from forged payloads returned by untrusted state nodes (PR #54 review).
    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let key = ContentEncryptionKey(vec![42u8; 32]);
        let encryptor = Aes256GcmContentEncryption;
        let plaintext = b"Secret message that should not be tampered with!";

        let mut ciphertext = encryptor
            .encrypt(&key, plaintext)
            .expect("encryption should succeed");

        // Flip one bit in the encrypted payload (right after the nonce)
        ciphertext[NONCE_LEN] ^= 0x11;

        let result = encryptor.decrypt(&key, &ciphertext);
        assert!(
            matches!(result, Err(ContentError::DecryptionError(_))),
            "tampered ciphertext must fail GCM authentication"
        );

        // Restoring the original byte makes decryption succeed again,
        // proving the failure above was caused by the tampering.
        ciphertext[NONCE_LEN] ^= 0x11;
        let restored = encryptor
            .decrypt(&key, &ciphertext)
            .expect("untampered ciphertext should decrypt");
        assert_eq!(&restored[..], &plaintext[..]);
    }

    /// Tampering with the nonce is also detected (the tag authenticates the
    /// nonce implicitly via the keystream).
    #[test]
    fn tampered_nonce_fails_authentication() {
        let key = ContentEncryptionKey(vec![42u8; 32]);
        let encryptor = Aes256GcmContentEncryption;
        let plaintext = b"nonce integrity";

        let mut ciphertext = encryptor
            .encrypt(&key, plaintext)
            .expect("encryption should succeed");
        ciphertext[0] ^= 0x01;

        let result = encryptor.decrypt(&key, &ciphertext);
        assert!(matches!(result, Err(ContentError::DecryptionError(_))));
    }

    /// Tampering with the authentication tag itself is detected.
    #[test]
    fn tampered_tag_fails_authentication() {
        let key = ContentEncryptionKey(vec![42u8; 32]);
        let encryptor = Aes256GcmContentEncryption;
        let plaintext = b"tag integrity";

        let mut ciphertext = encryptor
            .encrypt(&key, plaintext)
            .expect("encryption should succeed");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x80;

        let result = encryptor.decrypt(&key, &ciphertext);
        assert!(matches!(result, Err(ContentError::DecryptionError(_))));
    }

    /// Decrypting with a wrong key fails instead of returning garbage.
    #[test]
    fn wrong_key_fails_authentication() {
        let key = ContentEncryptionKey(vec![42u8; 32]);
        let wrong_key = ContentEncryptionKey(vec![43u8; 32]);
        let encryptor = Aes256GcmContentEncryption;
        let plaintext = b"key binding";

        let ciphertext = encryptor
            .encrypt(&key, plaintext)
            .expect("encryption should succeed");

        let result = encryptor.decrypt(&wrong_key, &ciphertext);
        assert!(matches!(result, Err(ContentError::DecryptionError(_))));
    }
}
