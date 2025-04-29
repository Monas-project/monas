use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::rng;
use rand::RngCore;

pub trait SymmetricEncryption {
    // TODO: 改ざん攻撃に対する保護のために，認証付きデータ（AAD）をパラメータとして追加することを検討する
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

#[derive(Debug)]
pub enum CryptoError {
    // TODO: サイドチャネル攻撃対策のために，内部エラーの詳細を隠しつつ，ログには十分な情報を残す設計を検討する
    EncryptingError,
    DecryptingError,
    InvalidKey,
    InvalidFormat,
}

#[derive(Debug)]
pub struct AesCipher {
    key: [u8; 32],
}

impl AesCipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    #[cfg(test)]
    fn key_for_test(&self) -> &[u8; 32] {
        &self.key
    }
}

impl SymmetricEncryption for AesCipher {
    fn encrypt(&self, target: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| CryptoError::InvalidKey)?;
        let mut nonce_bytes = [0u8; 12];
        rng().fill_bytes(&mut nonce_bytes);
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
