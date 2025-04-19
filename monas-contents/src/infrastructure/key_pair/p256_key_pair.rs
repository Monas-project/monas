use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use sha3::{Digest, Keccak256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P256KeyPair {
    secret_key: SigningKey,
    public_key: VerifyingKey,
}

impl P256KeyPair {
    pub fn generate() -> Self {
        let secret_key = SigningKey::random(&mut OsRng);
        let public_key = VerifyingKey::from(&secret_key);
        P256KeyPair {
            secret_key,
            public_key,
        }
    }

    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }

    pub fn secret_key(&self) -> &SigningKey {
        &self.secret_key
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        // 入力データのハッシュを計算
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        // TODO: v1では適切な暗号化アルゴリズムに変更する
        let mut result = Vec::with_capacity(hash.len() + data.len());
        result.extend_from_slice(&hash);
        result.extend_from_slice(data);
        result
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        // TODO: v1では適切な暗号化アルゴリズムに変更する
        if data.len() <= 32 {
            return Vec::new();
        }
        data[32..].to_vec()
    }

    pub fn public_key_string(&self) -> String {
        let encoded_point = self.public_key.to_encoded_point(false);
        let bytes = encoded_point.as_bytes();
        format!("p256_{}", hex::encode(bytes))
    }

}

#[cfg(test)]
mod p256_key_pair_tests {
    use super::*;

    #[test]
    fn test_key_pair_generate() {
        let key_pair = P256KeyPair::generate();
        assert!(!key_pair.public_key_string().is_empty());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key_pair = P256KeyPair::generate();
        let original_data = b"This is a test message";

        let encrypted = key_pair.encrypt(original_data);
        let decrypted = key_pair.decrypt(&encrypted);

        assert_eq!(decrypted, original_data);
    }
}