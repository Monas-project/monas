use crate::domain::content::encryption::{
    ContentEncryption, ContentEncryptionKey, ContentEncryptionKeyGenerator,
};
use crate::domain::content::ContentError;

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use rand_core::{OsRng, RngCore};

type Aes256Ctr = Ctr128BE<Aes256>;

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

/// Content encryption/decryption implementation using AES-256-CTR.
///
/// - Encryption: generates a 16-byte random IV and returns a byte sequence in the form `[iv || ciphertext]`.
/// - Decryption: splits the first 16 bytes as the IV and uses the remaining bytes as the ciphertext for AES-CTR.
/// - Provides confidentiality only; no integrity/authentication (no MAC or AEAD).
///   In the future this may be replaced with an AEAD scheme such as AES-GCM to add integrity protection.
pub struct Aes256CtrContentEncryption;

const IV_LEN: usize = 16;
const KEY_LEN: usize = 32;

impl ContentEncryption for Aes256CtrContentEncryption {
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
        let mut iv = [0u8; IV_LEN];
        let mut rng = OsRng;
        rng.fill_bytes(&mut iv);

        let mut buffer = plaintext.to_vec();
        let mut cipher = Aes256Ctr::new_from_slices(key.0.as_slice(), &iv).map_err(|_| {
            ContentError::EncryptionError(
                "Invalid key or IV length for AES-256-CTR (expected 32-byte key, 16-byte IV)"
                    .into(),
            )
        })?;
        cipher.apply_keystream(&mut buffer);
        let mut result = Vec::with_capacity(IV_LEN + buffer.len());
        result.extend_from_slice(&iv);
        result.extend_from_slice(&buffer);
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

        if data.len() <= IV_LEN {
            return Err(ContentError::DecryptionError(
                "Ciphertext is too short to contain IV and data (must be longer than IV only)"
                    .into(),
            ));
        }

        let (iv_bytes, ciphertext) = data.split_at(IV_LEN);

        let mut buffer = ciphertext.to_vec();

        let mut cipher = Aes256Ctr::new_from_slices(key.0.as_slice(), iv_bytes).map_err(|_| {
            ContentError::DecryptionError(
                "Invalid key or IV length for AES-256-CTR (expected 32-byte key, 16-byte IV)"
                    .into(),
            )
        })?;
        cipher.apply_keystream(&mut buffer);

        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trip() {
        let key = ContentEncryptionKey(vec![42u8; 32]); // fixed key only for testing
        let encryptor = Aes256CtrContentEncryption;
        let plaintext = b"Monas content encryption test".to_vec();

        let ciphertext = encryptor
            .encrypt(&key, &plaintext)
            .expect("encryption should succeed");

        assert_ne!(ciphertext, plaintext);
        assert!(ciphertext.len() > plaintext.len());
        assert!(ciphertext.len() >= IV_LEN);

        let decrypted = encryptor
            .decrypt(&key, &ciphertext)
            .expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_fails_with_invalid_key_length() {
        let key = ContentEncryptionKey(vec![1u8; 16]);
        let encryptor = Aes256CtrContentEncryption;
        let plaintext = b"test".to_vec();

        let result = encryptor.encrypt(&key, &plaintext);
        assert!(matches!(result, Err(ContentError::EncryptionError(_))));
    }

    #[test]
    fn decrypt_fails_with_invalid_key_length() {
        let key = ContentEncryptionKey(vec![1u8; 16]);
        let encryptor = Aes256CtrContentEncryption;

        let dummy_ciphertext = vec![0u8; IV_LEN + 4];

        let result = encryptor.decrypt(&key, &dummy_ciphertext);
        assert!(matches!(result, Err(ContentError::DecryptionError(_))));
    }

    #[test]
    fn decrypt_fails_when_data_too_short() {
        let key = ContentEncryptionKey(vec![2u8; 32]);
        let encryptor = Aes256CtrContentEncryption;

        let too_short = vec![0u8; IV_LEN]; // exactly IV length (no payload data)
        let result = encryptor.decrypt(&key, &too_short);
        assert!(matches!(result, Err(ContentError::DecryptionError(_))));

        let even_shorter = vec![0u8; IV_LEN - 1];
        let result2 = encryptor.decrypt(&key, &even_shorter);
        assert!(matches!(result2, Err(ContentError::DecryptionError(_))));
    }

    #[test]
    fn encrypt_produces_different_ciphertexts_due_to_random_iv() {
        let key = ContentEncryptionKey(vec![99u8; 32]);
        let encryptor = Aes256CtrContentEncryption;
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
        let encryptor = Aes256CtrContentEncryption;
        let size = 1024 * 1024;
        let mut plaintext = Vec::with_capacity(size);
        for i in 0..size {
            plaintext.push((i % 256) as u8);
        }

        let ciphertext = encryptor
            .encrypt(&key, &plaintext)
            .expect("encryption should succeed for large plaintext");

        assert!(ciphertext.len() > plaintext.len());
        assert!(ciphertext.len() >= IV_LEN);

        let decrypted = encryptor
            .decrypt(&key, &ciphertext)
            .expect("decryption should succeed for large plaintext");

        assert_eq!(decrypted, plaintext);
    }

    /// **Security vulnerability test**: This test passing demonstrates lack of integrity verification
    ///
    /// In AES-CTR mode, decryption succeeds even when ciphertext is tampered with.
    /// Tampering goes undetected and incorrect data is returned.
    ///
    /// **Expected behavior (ideal)**: Tampered ciphertext should be detected and decryption should fail
    /// **Current behavior (problem)**: Test passes = tampering undetected = security vulnerability
    #[test]
    fn tampered_ciphertext_decrypts_successfully_but_returns_wrong_data() {
        let key = ContentEncryptionKey(vec![42u8; 32]);
        let encryptor = Aes256CtrContentEncryption;
        let plaintext = b"Secret message that should not be tampered with!";

        println!("\n========== TEST 1: Tampered Ciphertext ==========");
        println!(
            "Original Plaintext: {:?}",
            String::from_utf8_lossy(plaintext)
        );
        println!("Plaintext (hex):    {}", hex::encode(plaintext));
        println!("Plaintext length:   {} bytes", plaintext.len());

        // Encrypt normally
        let mut ciphertext = encryptor
            .encrypt(&key, plaintext)
            .expect("encryption should succeed");

        println!("\n--- After Encryption ---");
        println!(
            "Ciphertext length:  {} bytes (IV: {} + data: {})",
            ciphertext.len(),
            IV_LEN,
            ciphertext.len() - IV_LEN
        );
        println!(
            "IV (first 16 bytes):       {}",
            hex::encode(&ciphertext[0..IV_LEN])
        );
        println!(
            "Encrypted data (hex):      {}",
            hex::encode(&ciphertext[IV_LEN..])
        );

        // Tamper with part of the ciphertext (modify the first byte after IV)
        let original_byte = ciphertext[IV_LEN];
        println!("\n--- Before Tampering ---");
        println!("Byte at position [IV_LEN=16]: 0x{original_byte:02x} ({original_byte})");

        ciphertext[IV_LEN] ^= 0x11; // Tampering by bit flipping
        println!("\n--- After Tampering ---");
        let tampered_byte = ciphertext[IV_LEN];
        println!(
            "Byte at position [IV_LEN=16]: 0x{tampered_byte:02x} ({tampered_byte}) ← TAMPERED!"
        );
        println!(
            "Modified ciphertext (hex):     {}",
            hex::encode(&ciphertext[IV_LEN..])
        );

        // Problem: Decryption "succeeds" even with tampered ciphertext
        let decrypted = encryptor
            .decrypt(&key, &ciphertext)
            .expect("decryption 'succeeds' even with tampered data - THIS IS THE PROBLEM!");

        println!("\n--- Decryption of Tampered Data ---");
        println!("WARNING: Decryption SUCCEEDED (this is the problem!)");
        println!("Decrypted text:  {:?}", String::from_utf8_lossy(&decrypted));
        println!("Decrypted (hex): {}", hex::encode(&decrypted));

        // Due to tampering, the decrypted result differs from the original first byte
        println!("\n--- Verification ---");
        println!(
            "Original 1st byte:  0x{:02x} ({})",
            plaintext[0], plaintext[0] as char
        );
        println!(
            "Decrypted 1st byte: 0x{:02x} ({})",
            decrypted[0], decrypted[0] as char
        );
        assert_ne!(decrypted[0], plaintext[0]);
        assert_ne!(&decrypted[..], &plaintext[..]);
        println!("OK: Decrypted data DIFFERS from original (as expected from tampering)");

        // Restoring the original byte allows correct decryption (proof that tampering was the cause)
        println!("\n--- Restoring Original Ciphertext ---");
        ciphertext[IV_LEN] = original_byte;
        let restored = encryptor
            .decrypt(&key, &ciphertext)
            .expect("should decrypt");
        println!("Restored text: {:?}", String::from_utf8_lossy(&restored));
        assert_eq!(&restored[..], &plaintext[..]);
        println!("OK: After restoring byte, plaintext matches original");
        println!("========== END TEST 1 ==========\n");
    }
}
