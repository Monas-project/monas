use rand::Rng;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesKeyPair {
    // ダミーフィールド
    key: Vec<u8>,
}

impl AesKeyPair {
    pub fn generate() -> Self {
        // ランダムな鍵を生成
        let mut rng = rand::thread_rng();
        let key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        Self { key }
    }

    pub fn key(&self) -> &[u8] {
        &self.key
    }

    // KeyPairトレイトの実装に必要互換性のために残している．
    pub fn key_string(&self) -> String {
        format!("aes_dummy_pub_{}", hex::encode(&self.key[..4]))
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        // ダミー暗号化: XORのみ
        data.iter().zip(self.key.iter().cycle()).map(|(d, k)| d ^ k).collect::<Vec<u8>>()
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        // ダミー復号化: XORのみ
        // 対称鍵なので encrypt() と同じ操作をして，元のデータに戻す．
        self.encrypt(data)
    }
}

#[cfg(test)]
mod aes_key_pair_tests {
    use super::*;

    #[test]
    fn test_key_pair_generate() {
        let key_pair = AesKeyPair::generate();
        // キーが正しい長さであることを確認
        assert_eq!(key_pair.key().len(), 32);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key_pair = AesKeyPair::generate();
        let original_data = b"This is a test message for AES encryption";

        let encrypted = key_pair.encrypt(original_data);
        let decrypted = key_pair.decrypt(&encrypted);

        assert_eq!(decrypted, original_data);
        // 暗号化されたデータは元のデータと異なることを確認
        assert_ne!(encrypted, original_data);
    }

    #[test]
    fn test_key_uniqueness() {
        let key_pair1 = AesKeyPair::generate();
        let key_pair2 = AesKeyPair::generate();
        // 違う鍵が生成されることを確認
        assert_ne!(key_pair1.key(), key_pair2.key());
    }
}
