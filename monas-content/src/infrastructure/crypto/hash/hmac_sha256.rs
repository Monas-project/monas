use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HmacError {
    #[error("HMAC verification failed: {0}")]
    VerificationError(String),
}

pub struct HmacSha256;

impl HmacSha256 {
    /// HMAC-SHA256を使用してメッセージ認証コードを計算する
    ///
    /// # 引数
    /// * `key` - 認証に使用する鍵．HKDFのExtractフェーズではsalt，Expandフェーズでは擬似乱数鍵として使用
    /// * `data` - 認証対象のデータ．HKDFのExtractフェーズでは共有秘密，ExpandフェーズではHMAC入力として使用
    pub fn compute(key: &[u8], data: &[u8]) -> Result<Vec<u8>, HmacError> {
        let mut mac =
            <Hmac<Sha256>>::new_from_slice(key).expect("HMAC key initialization should never fail");
        mac.update(data);
        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    }

    /// HMAC-SHA256を使用してメッセージ認証コードを検証する
    pub fn verify(key: &[u8], data: &[u8], expected_hash: &[u8]) -> Result<(), HmacError> {
        let computed = Self::compute(key, data)?;

        if computed.len() != expected_hash.len() {
            return Err(HmacError::VerificationError(format!(
                "Length mismatch: computed={}, expected={}",
                computed.len(),
                expected_hash.len()
            )));
        }

        let mut result = 0;
        for (a, b) in computed.iter().zip(expected_hash.iter()) {
            result |= a ^ b;
        }

        if result == 0 {
            Ok(())
        } else {
            Err(HmacError::VerificationError(
                "Hash values do not match".to_string(),
            ))
        }
    }

    /// HmacSha256::verify()の検証結果をboolで返す
    pub fn is_verified(key: &[u8], data: &[u8], expected_hash: &[u8]) -> bool {
        Self::verify(key, data, expected_hash).is_ok()
    }
}

pub struct HmacSha256Key {
    key: Vec<u8>,
}

impl HmacSha256Key {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }

    pub fn compute(&self, data: &[u8]) -> Result<Vec<u8>, HmacError> {
        HmacSha256::compute(&self.key, data)
    }

    pub fn verify(&self, data: &[u8], expected_hash: &[u8]) -> Result<(), HmacError> {
        HmacSha256::verify(&self.key, data, expected_hash)
    }

    pub fn is_verified(&self, data: &[u8], expected_hash: &[u8]) -> bool {
        HmacSha256::is_verified(&self.key, data, expected_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_compute_and_verify() {
        let key_bytes = b"test key";
        let data = b"test data";

        let key = HmacSha256Key::new(key_bytes);
        let hmac = key.compute(data).unwrap();
        let hmac2 = key.compute(data).unwrap();
        assert_eq!(hmac, hmac2);

        assert!(key.verify(data, &hmac).is_ok());
        assert!(key.is_verified(data, &hmac));
    }

    #[test]
    fn test_different_data_causes_verification_failure() {
        let key_bytes = b"test key";
        let data = b"test data";
        let key = HmacSha256Key::new(key_bytes);
        let hmac = key.compute(data).unwrap();

        let different_data = b"different data";
        let incorrect_hmac = key.compute(different_data).unwrap();
        assert_ne!(hmac, incorrect_hmac);

        assert!(key.verify(data, &incorrect_hmac).is_err());
        assert!(!key.is_verified(data, &incorrect_hmac));
    }

    #[test]
    fn test_hmac_output_correct_bytes_length_with_various_keys() {
        let data = b"test data";
        let key_lengths = vec![0, 1, 32, 64, 100];

        for length in key_lengths {
            let key_bytes = vec![0u8; length];
            let key = HmacSha256Key::new(&key_bytes);
            let result = key.compute(data).unwrap();
            assert_eq!(
                result.len(),
                32,
                "HMAC output should be 32 bytes for key length {}",
                length
            );
        }
    }
}
