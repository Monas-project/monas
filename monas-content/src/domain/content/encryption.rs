use crate::domain::content::ContentError;

/// Value object representing the symmetric key used for content encryption (CEK: Content
/// Encryption Key).
///
/// The concrete key material generation algorithm and length (e.g. AES-256) are left to the infra
/// implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentEncryptionKey(pub Vec<u8>);

/// Port for generating CEKs.
pub trait ContentEncryptionKeyGenerator {
    fn generate(&self) -> ContentEncryptionKey;
}

/// Port for encrypting/decrypting content with a CEK.
///
/// Implementations are expected to live in the infra layer, using an AEAD such as AES-GCM.
pub trait ContentEncryption {
    fn encrypt(
        &self,
        key: &ContentEncryptionKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentError>;

    fn decrypt(
        &self,
        key: &ContentEncryptionKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ContentError>;
}
