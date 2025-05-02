use crate::infrastructure::crypto::kdf::hkdf::HkdfKeyDerivation;
use crate::infrastructure::crypto::symmetric::aes_cipher::{AesCipher, SymmetricEncryption};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;

#[derive(Debug, Clone)]
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
    pub fn to_content_id(&self) -> String {
        let encoded_point = self.public_key.to_encoded_point(false);
        format!("0xPub{}", hex::encode(encoded_point.as_bytes()))
    }

    /// アカウントの秘密鍵とコンテンツの公開鍵から共有秘密を生成する
    pub fn generate_shared_secret(
        _account_private_key: &SigningKey,
        _content_public_key: &VerifyingKey,
    ) -> Result<Vec<u8>, String> {
        // TODO: monas-account/で実装された共有秘密生成ロジックを使用する
        let test_shared_secret = b"test_shared_secret_for_content_encryption";
        Ok(test_shared_secret.to_vec())
    }

    pub fn derive_encryption_key(
        shared_secret: &[u8],
        context_info: Option<&[u8]>,
    ) -> Result<[u8; 32], String> {
        HkdfKeyDerivation::derive_aes_256_key(
            shared_secret,
            None,
            context_info.or(Some(b"content_encryption")),
        )
        .map_err(|e| format!("Deriving encryption key failed: {:?}", e))
    }

    pub fn encrypt_with_aes_key(aes_key: [u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
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
        let shared_secret = Self::generate_shared_secret(account_private_key, content_public_key)?;

        // 2: HKDFで共有秘密からAES鍵を導出する
        let aes_key = Self::derive_encryption_key(
            &shared_secret,
            Some(b"content_encryption"), // コンテキスト情報
        )?;

        // 3: AES鍵でContentデータを暗号化する
        Self::encrypt_with_aes_key(aes_key, data)
    }

    pub fn decrypt_with_aes_key(
        aes_key: [u8; 32],
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>, String> {
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
        let shared_secret = Self::generate_shared_secret(account_private_key, content_public_key)?;

        // 2: HKDFで共有秘密からAES鍵を導出する
        let aes_key = Self::derive_encryption_key(
            &shared_secret,
            Some(b"content_encryption"), // コンテキスト情報
        )?;

        // 3: AES鍵でデータを復号する
        Self::decrypt_with_aes_key(aes_key, encrypted_data)
    }
}

impl PartialEq for ContentKeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.private_key == other.private_key
    }
}
