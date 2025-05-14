use crate::infrastructure::crypto::hash::hmac_sha256::HmacSha256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HkdfError {
    ExpansionError,
    OutputTooLong,
    InvalidParameter(&'static str),
    HmacError,
}

/// RFC 5869[1]に準拠したHKDF（HMACベースの鍵導出関数）を使用
/// HKDFの定義については以下の文献[2]が参考になります．
///
/// [1] RFC 5869, https://datatracker.ietf.org/doc/html/rfc5869
/// [2] 鍵導出アルゴリズム, https://hazm.at/mox/security/kdf/index.html
pub struct HkdfKeyDerivation;

impl HkdfKeyDerivation {
    /// 共有秘密から指定された長さの鍵を導出する
    ///
    /// # 引数
    /// * `shared_secret` - 鍵導出の元となる共有秘密
    /// * `salt` - Extractフェーズで使用するソルト．指定しない場合は0で埋められた32バイトの配列を使用
    /// * `info` - Expandフェーズで使用するコンテキスト情報．指定しない場合は空の配列を使用
    /// * `length` - 導出する鍵の長さ（バイト）
    pub fn derive_key(
        shared_secret: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
        length: usize,
    ) -> Result<Vec<u8>, HkdfError> {
        if shared_secret.is_empty() {
            return Err(HkdfError::InvalidParameter("shared_secret cannot be empty"));
        }
        if length == 0 {
            return Err(HkdfError::InvalidParameter("length must be larger than 0"));
        }

        // Extractフェーズ
        let pseudo_random_key = HmacSha256::compute(salt.unwrap_or(&[0u8; 32]), shared_secret)
            .map_err(|_| HkdfError::HmacError)?;

        // Expandフェーズ
        let mut output_keying_material = vec![0u8; length];
        let mut previous_hmac_result = Vec::new();
        let mut counter = 1u8;
        let mut output_length = 0;

        while output_length < length {
            if counter == 0 {
                return Err(HkdfError::OutputTooLong);
            }

            let mut hmac_input = previous_hmac_result.clone();
            hmac_input.extend_from_slice(info.unwrap_or(&[]));
            hmac_input.push(counter);

            previous_hmac_result = HmacSha256::compute(&pseudo_random_key, &hmac_input)
                .map_err(|_| HkdfError::HmacError)?;

            let remaining = length - output_length;
            let copy_length = std::cmp::min(previous_hmac_result.len(), remaining);
            output_keying_material[output_length..output_length + copy_length]
                .copy_from_slice(&previous_hmac_result[..copy_length]);

            output_length += copy_length;
            counter = counter.checked_add(1).ok_or(HkdfError::OutputTooLong)?;
        }

        Ok(output_keying_material)
    }

    /// 共有秘密からAES-256用の32バイト鍵を導出する
    pub fn derive_aes_256_key(
        shared_secret: &[u8],
        salt: Option<&[u8]>,
        info: Option<&[u8]>,
    ) -> Result<[u8; 32], HkdfError> {
        let derived = Self::derive_key(shared_secret, salt, info, 32)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&derived);
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_aes_256_key_consistency() {
        let shared_secret = b"this is a shared secret for testing";
        let salt = b"salt value";
        let info = b"test context info";

        let aes_key =
            HkdfKeyDerivation::derive_aes_256_key(shared_secret, Some(salt), Some(info)).unwrap();
        let aes_key2 =
            HkdfKeyDerivation::derive_aes_256_key(shared_secret, Some(salt), Some(info)).unwrap();
        assert_eq!(aes_key, aes_key2);
    }

    #[test]
    fn test_different_salt_causes_different_key() {
        let shared_secret = b"this is a shared secret for testing";
        let salt = b"salt value";
        let info = b"test context info";
        let aes_key =
            HkdfKeyDerivation::derive_aes_256_key(shared_secret, Some(salt), Some(info)).unwrap();

        let different_salt = b"different salt";
        let different_aes_key =
            HkdfKeyDerivation::derive_aes_256_key(shared_secret, Some(different_salt), Some(info))
                .unwrap();
        assert_ne!(aes_key, different_aes_key);
    }
}
