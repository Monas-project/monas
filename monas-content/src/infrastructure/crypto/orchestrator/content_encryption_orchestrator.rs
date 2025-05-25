use crate::infrastructure::crypto::kdf::shared_secret::SharedSecret;
use crate::infrastructure::crypto::symmetric::aes_cipher::{AesCipher, SymmetricEncryption};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;

#[derive(Debug, Clone, PartialEq)]
pub struct ContentKeyPair {
    private_key: SigningKey,
    public_key: VerifyingKey,
}

impl ContentKeyPair {
    pub fn private_key(&self) -> &SigningKey {
        &self.private_key
    }

    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }

    // 公開鍵暗号（p256）を生成
    pub fn generate() -> Self {
        let private_key = SigningKey::random(&mut OsRng);
        let public_key = VerifyingKey::from(&private_key);
        ContentKeyPair {
            private_key,
            public_key,
        }
    }

    // 公開鍵をContent IDとして使用する
    // TODO: 将来的にCIDの生成ロジックはDASLで実装する
    // Ref: https://github.com/Monas-project/crsl-lib/blob/main/src/dasl/node.rs
    pub fn to_content_id(&self) -> String {
        let encoded_point = self.public_key.to_encoded_point(false);
        format!("0xPub{}", hex::encode(encoded_point.as_bytes()))
    }
}

pub struct ContentEncryptionOrchestrator;

impl ContentEncryptionOrchestrator {
    /// 共有秘密からAES-256鍵を導出する
    fn derive_encryption_key(
        shared_secret: &SharedSecret,
        context_info: Option<&[u8]>,
    ) -> Result<[u8; 32], String> {
        shared_secret
            .derive_aes_256_key(
                None, // salt
                context_info.or(Some(b"content_encryption")),
            )
            .map_err(|e| format!("Deriving encryption key failed: {:?}", e))
    }

    fn encrypt_with_aes_key(aes_key: [u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = AesCipher::new(aes_key);
        cipher
            .encrypt(data)
            .map_err(|e| format!("Encrypting data failed: {:?}", e))
    }

    pub fn encrypt_content(
        account_private_key: &SigningKey,
        content_public_key: &VerifyingKey,
        data: &[u8],
    ) -> Result<Vec<u8>, String> {
        // 1: 共有秘密を生成する
        let shared_secret = SharedSecret::new(account_private_key, content_public_key)
            .map_err(|e| format!("Failed to generate shared secret: {}", e))?;

        // 2: SharedSecretオブジェクトから直接AES鍵を導出
        let aes_key = Self::derive_encryption_key(&shared_secret, Some(b"content_encryption"))?;

        // 3: AES鍵でContentデータを暗号化する
        Self::encrypt_with_aes_key(aes_key, data)
    }

    fn decrypt_with_aes_key(aes_key: [u8; 32], encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = AesCipher::new(aes_key);
        cipher
            .decrypt(encrypted_data)
            .map_err(|e| format!("Decrypting data failed: {:?}", e))
    }

    pub fn decrypt_content(
        account_private_key: &SigningKey,
        content_public_key: &VerifyingKey,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, String> {
        // 1: 共有秘密を生成する
        let shared_secret = SharedSecret::new(account_private_key, content_public_key)
            .map_err(|e| format!("Failed to generate shared secret: {}", e))?;

        // 2: SharedSecretオブジェクトから直接AES鍵を導出
        let aes_key = Self::derive_encryption_key(&shared_secret, Some(b"content_encryption"))?;

        // 3: AES鍵でデータを復号する
        Self::decrypt_with_aes_key(aes_key, encrypted_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl ContentEncryptionOrchestrator {
        pub fn test_encrypt_with_aes_key(
            aes_key: [u8; 32],
            data: &[u8],
        ) -> Result<Vec<u8>, String> {
            Self::encrypt_with_aes_key(aes_key, data)
        }

        pub fn test_decrypt_with_aes_key(
            aes_key: [u8; 32],
            encrypted_data: &[u8],
        ) -> Result<Vec<u8>, String> {
            Self::decrypt_with_aes_key(aes_key, encrypted_data)
        }

        pub fn test_derive_encryption_key(
            shared_secret: &SharedSecret,
            context_info: Option<&[u8]>,
        ) -> Result<[u8; 32], String> {
            Self::derive_encryption_key(shared_secret, context_info)
        }
    }

    fn generate_test_account_key_pair() -> (SigningKey, VerifyingKey) {
        let private_key = SigningKey::random(&mut OsRng);
        let public_key = VerifyingKey::from(&private_key);
        (private_key, public_key)
    }

    #[test]
    fn test_generate_content_id_from_key() {
        let key_pair = ContentKeyPair::generate();
        let content_id = key_pair.to_content_id();
        assert!(!content_id.is_empty());

        // プレフィックスを除いた部分が16進数であることを確認
        assert!(content_id.starts_with("0xPub"));
        assert!(content_id[5..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_key_derivation() {
        let (account_private_key, _account_public_key) = generate_test_account_key_pair();
        let content_key_pair = ContentKeyPair::generate();

        // SharedSecretオブジェクトを生成
        let shared_secret = SharedSecret::new(&account_private_key, content_key_pair.public_key())
            .map_err(|e| format!("Failed to generate shared secret: {}", e))
            .unwrap();

        // SharedSecretから直接AES鍵を導出
        let aes_key1 = ContentEncryptionOrchestrator::test_derive_encryption_key(
            &shared_secret,
            Some(b"test context"), // コンテキスト情報
        )
        .unwrap();

        let aes_key2 = ContentEncryptionOrchestrator::test_derive_encryption_key(
            &shared_secret,
            Some(b"test context"),
        )
        .unwrap();

        assert_eq!(aes_key1.len(), 32);
        assert_eq!(aes_key2.len(), 32);

        // 同じコンテキスト情報で導出した鍵は同一になることを確認する
        assert_eq!(aes_key1, aes_key2);
    }

    #[test]
    fn test_aes_encryption() {
        let key = [1u8; 32];
        let data = b"Test data for AES encryption";
        let encrypted =
            ContentEncryptionOrchestrator::test_encrypt_with_aes_key(key, data).unwrap();
        let encrypted_data = &encrypted[12..encrypted.len() - 16];

        assert_ne!(encrypted_data, data);

        let decrypted =
            ContentEncryptionOrchestrator::test_decrypt_with_aes_key(key, &encrypted).unwrap();

        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_content_encryption_lifecycle() {
        let (account_private_key, _account_public_key) = generate_test_account_key_pair();
        let content_key_pair = ContentKeyPair::generate();
        let data = b"This is a secret content";

        let encrypted = ContentEncryptionOrchestrator::encrypt_content(
            &account_private_key,
            content_key_pair.public_key(),
            data,
        )
        .unwrap();

        assert_ne!(encrypted, data);

        let decrypted = ContentEncryptionOrchestrator::decrypt_content(
            &account_private_key,
            content_key_pair.public_key(),
            &encrypted,
        )
        .unwrap();

        assert_eq!(decrypted, data);
    }
}
