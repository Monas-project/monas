use crate::domain::content::ContentError;

/// コンテンツ暗号化に用いる共有鍵 (CEK: Content Encryption Key) を表す値オブジェクト。
///
/// 具体的な鍵素材の生成アルゴリズムや長さ（AES-256 など）は infra 側の実装に委ねる。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentEncryptionKey(pub Vec<u8>);

/// CEK を生成するためのポート。
pub trait ContentEncryptionKeyGenerator {
    fn generate(&self) -> ContentEncryptionKey;
}

/// CEK を用いてコンテンツを暗号化/復号するためのポート。
///
/// 実装は AES-CTR などの暗号アルゴリズムを用いる infra 層に置く想定。
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
