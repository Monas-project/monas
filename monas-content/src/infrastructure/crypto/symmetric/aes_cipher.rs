use crate::infrastructure::crypto::symmetric::nonce::{NonceError, NonceGenerator};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

pub trait SymmetricEncryption {
    // TODO: 改ざん攻撃に対する保護のために，認証付きデータ（AAD）をパラメータとして追加することを検討する
    /// データを暗号化する
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// 暗号化されたデータを復号する
    fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

#[derive(Debug)]
pub enum CryptoError {
    // TODO: サイドチャネル攻撃対策のために，内部エラーの詳細を隠しつつ，ログには十分な情報を残す設計を検討する
    EncryptingError,
    DecryptingError,
    InvalidKey,
    InvalidFormat,
    NonceGenerationError(NonceError),
}

#[derive(Debug)]
pub struct AesCipher {
    key: [u8; 32],
    nonce_generator: NonceGenerator,
}

impl AesCipher {
    /// AES-256 GCM 暗号化鍵を生成する
    ///
    /// # 引数
    /// * `key` - HKDFで導出したAES-256用の32バイト鍵
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            nonce_generator: NonceGenerator::new(),
        }
    }

    #[cfg(test)]
    fn key_for_test(&self) -> &[u8; 32] {
        &self.key
    }
}

impl SymmetricEncryption for AesCipher {
    /// AES-256-GCMでデータを暗号化する
    fn encrypt(&self, target: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| CryptoError::InvalidKey)?;

        let nonce_bytes = self
            .nonce_generator
            .generate()
            .map_err(CryptoError::NonceGenerationError)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        // TODO: タイミング攻撃対策のために定数時間処理の確保を検討する
        let encrypted_data = cipher
            .encrypt(nonce, target)
            .map_err(|_| CryptoError::EncryptingError)?;
        let mut result = Vec::with_capacity(nonce_bytes.len() + encrypted_data.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&encrypted_data);
        Ok(result)
    }

    /// AES-256 GCMで暗号化されたデータを復号する
    ///
    /// # 引数
    /// * `encrypted_target` - 復号対象の暗号化データ（ノンス + 暗号文）
    fn decrypt(&self, encrypted_target: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if encrypted_target.len() <= 12 {
            return Err(CryptoError::InvalidFormat);
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| CryptoError::InvalidKey)?;
        let nonce = Nonce::from_slice(&encrypted_target[..12]);
        // TODO: タイミング攻撃対策のために定数時間処理の確保を検討する
        cipher
            .decrypt(nonce, &encrypted_target[12..])
            .map_err(|_| CryptoError::DecryptingError)
    }
}

impl Drop for AesCipher {
    fn drop(&mut self) {
        for byte in self.key.iter_mut() {
            *byte = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_encrypt_and_decrypt() {
        let key = [0u8; 32];
        let cipher = AesCipher::new(key);
        let data = b"Hello, World!";

        let encrypted = cipher.encrypt(data).unwrap();
        assert_ne!(&encrypted[12..], data);

        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_drop_key() {
        let key = [0x12; 32];
        let boxed_cipher = Box::new(AesCipher::new(key));
        assert_eq!(*boxed_cipher.key_for_test(), key);

        let ptr = &*boxed_cipher as *const AesCipher;
        mem::drop(boxed_cipher);

        unsafe {
            // ドロップ後のメモリを直接操作するのは避けるべき
            let dropped_cipher = &*ptr;
            for byte in dropped_cipher.key.iter() {
                assert_eq!(*byte, 0);
            }
        }
    }
}
