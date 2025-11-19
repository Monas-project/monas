use crate::domain::content::ContentError;
use crate::domain::encryption::{
    ContentEncryption, ContentEncryptionKey, ContentEncryptionKeyGenerator,
};

/// v1 用の簡易的な CEK 生成器。
/// TODO: 将来的に安全な乱数生成に置き換える。
pub struct SimpleContentEncryptionKeyGenerator;

impl ContentEncryptionKeyGenerator for SimpleContentEncryptionKeyGenerator {
    fn generate(&self) -> ContentEncryptionKey {
        // とりあえず固定長のダミーキーを返す。
        // AES-GCM などに発展させる場合は、rand や KMS を利用する。
        ContentEncryptionKey(vec![0u8; 32])
    }
}

/// v1 用の簡易暗号化実装。
/// encrypt: 各バイトに +1, decrypt: 各バイトに -1。
/// TODO: AES-GCM などの本番向け実装に差し替える。
pub struct SimpleContentEncryption;

impl ContentEncryption for SimpleContentEncryption {
    fn encrypt(
        &self,
        _key: &ContentEncryptionKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ContentError> {
        Ok(plaintext.iter().map(|b| b.wrapping_add(1)).collect())
    }

    fn decrypt(
        &self,
        _key: &ContentEncryptionKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, ContentError> {
        Ok(ciphertext.iter().map(|b| b.wrapping_sub(1)).collect())
    }
}
