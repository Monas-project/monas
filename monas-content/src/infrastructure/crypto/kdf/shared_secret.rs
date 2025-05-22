use crate::infrastructure::crypto::kdf::hkdf::{HkdfError, HkdfKeyDerivation};
use p256::ecdsa::{SigningKey, VerifyingKey};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SharedSecretError {
    #[error("Failed to generate shared secret: {0}")]
    GenerationFailed(String),
    #[error("Invalid shared secret: {0}")]
    Invalid(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(#[from] HkdfError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedSecret {
    data: Vec<u8>,
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl SharedSecret {
    pub fn new(
        _account_private_key: &SigningKey,
        _content_public_key: &VerifyingKey,
    ) -> Result<Self, SharedSecretError> {
        // TODO: monas-account/で実装された共有秘密生成ロジックを使用する
        let test_shared_secret = b"test_shared_secret";
        if test_shared_secret.is_empty() {
            return Err(SharedSecretError::Invalid(
                "Shared secret cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            data: test_shared_secret.to_vec(),
        })
    }

    /// 共有秘密から指定された長さの鍵を導出する
    ///
    /// # 引数
    /// * `salt` - Extractフェーズで使用するソルト．指定しない場合は0で埋められた32バイトの配列を使用
    /// * `info` - Expandフェーズで使用するコンテキスト情報．指定しない場合は空の配列を使用
    /// * `length` - 導出する鍵の長さ（バイト）
    pub fn derive_key(
        &self,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        length: usize,
    ) -> Result<Vec<u8>, SharedSecretError> {
        HkdfKeyDerivation::derive_key(&self.data, salt, info, length)
            .map_err(SharedSecretError::KeyDerivationFailed)
    }

    /// 共有秘密からAES-256用の32バイト鍵を導出する
    pub fn derive_aes_256_key(
        &self,
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> Result<[u8; 32], SharedSecretError> {
        HkdfKeyDerivation::derive_aes_256_key(&self.data, salt, info)
            .map_err(SharedSecretError::KeyDerivationFailed)
    }
}
